// SPDX-License-Identifier: GPL-2.0-or-later
//! Real isolated loopback sockets with synthetic keys, clocks and atomic
//! downward guards. Not enrollment, native authentication or remote approval.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};

use framed_transport::{
    CancellationToken, ConnectionBudget, FRAME_TIMEOUT, OutboundFrameGuard, PeerTransport,
    SocketClock, SocketClockUnavailable, SocketDriver, SocketError, SocketEvent, SocketLimits,
    TransportError,
};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, ChannelError, EndpointRole,
    PlatformTlsSigner, SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{MAX_PC_EVENT_BYTES, encode_frame};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

const TEST_DEADLINE: Duration = Duration::from_secs(2);
const SETUP: &[u8] = b"synthetic guarded-send setup";

struct SyntheticClock {
    origin: Instant,
    nanos: AtomicU64,
}
impl SyntheticClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            nanos: AtomicU64::new(0),
        })
    }
    fn set(&self, elapsed: Duration) {
        self.nanos
            .store(u64::try_from(elapsed.as_nanos()).unwrap(), Ordering::SeqCst);
    }
    fn at(&self, elapsed: Duration) -> Instant {
        self.origin.checked_add(elapsed).unwrap()
    }
}
impl SocketClock for SyntheticClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        self.origin
            .checked_add(Duration::from_nanos(self.nanos.load(Ordering::SeqCst)))
            .ok_or(SocketClockUnavailable)
    }
}

#[derive(Default)]
struct AtomicGuard(AtomicBool);
impl AtomicGuard {
    fn revoke(&self) {
        self.0.store(true, Ordering::Release);
    }
}
impl OutboundFrameGuard for AtomicGuard {
    fn is_revoked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct SyntheticSigner(SigningKey);
impl SyntheticSigner {
    fn new(seed: u8) -> Arc<Self> {
        Arc::new(Self(SigningKey::from_slice(&[seed; 32]).unwrap()))
    }
}
impl PlatformTlsSigner for SyntheticSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        let key =
            PublicKey::from_sec1_bytes(self.0.verifying_key().to_encoded_point(false).as_bytes())
                .unwrap();
        TlsPublicKey::from_spki_der(key.to_public_key_der().unwrap().as_bytes())
            .map_err(|_| SignerError::Unavailable)
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let signature: Signature = self.0.sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}

async fn sockets(tiny: bool) -> (TcpStream, TcpStream) {
    if tiny {
        // Test-local buffers create actual backpressure, not a timeout change.
        let listening = TcpSocket::new_v4().unwrap();
        listening.set_recv_buffer_size(1024).unwrap();
        listening.set_send_buffer_size(1024).unwrap();
        listening.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listening.listen(2).unwrap();
        let connecting = TcpSocket::new_v4().unwrap();
        connecting.set_send_buffer_size(1024).unwrap();
        connecting.set_recv_buffer_size(1024).unwrap();
        let (client, accepted) = tokio::join!(
            connecting.connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        (client.unwrap(), accepted.unwrap().0)
    } else {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        (client.unwrap(), accepted.unwrap().0)
    }
}

struct Pair {
    phone: SocketDriver,
    pc: SocketDriver,
    clock: Arc<SyntheticClock>,
    budget: Arc<ConnectionBudget>,
}
async fn pair(tiny: bool, quantum: usize) -> Pair {
    let (phone_socket, pc_socket) = sockets(tiny).await;
    let clock = SyntheticClock::new();
    let budget = Arc::new(ConnectionBudget::new(2).unwrap());
    let phone_signer = SyntheticSigner::new(21);
    let pc_signer = SyntheticSigner::new(22);
    let phone_transport = PeerTransport::client(
        budget.clone(),
        TlsIdentity::from_trusted_host(EndpointRole::Client, phone_signer.clone()).unwrap(),
        pc_signer.public_key().unwrap(),
        clock.now().unwrap(),
    )
    .unwrap();
    let pc_transport = PeerTransport::server(
        budget.clone(),
        TlsIdentity::from_trusted_host(EndpointRole::Server, pc_signer).unwrap(),
        phone_signer.public_key().unwrap(),
        clock.now().unwrap(),
    )
    .unwrap();
    let limits = SocketLimits::default()
        .with_io_chunk_bytes(quantum)
        .unwrap();
    Pair {
        phone: SocketDriver::new(
            phone_socket,
            phone_transport,
            clock.clone(),
            limits,
            CancellationToken::new(),
        )
        .unwrap(),
        pc: SocketDriver::new(
            pc_socket,
            pc_transport,
            clock.clone(),
            limits,
            CancellationToken::new(),
        )
        .unwrap(),
        clock,
        budget,
    }
}
async fn setup(driver: &mut SocketDriver) {
    let event = driver.next_event().await.unwrap();
    assert!(
        matches!(event, SocketEvent::Ready),
        "setup readiness: {event:?}"
    );
    driver.queue_frame(encode_frame(SETUP).unwrap()).unwrap();
    let mut received = false;
    let mut drained = false;
    for _ in 0..2 {
        match driver.next_event().await.unwrap() {
            SocketEvent::Frame(frame) => {
                assert!(!received);
                assert_eq!(frame.into_bytes(), SETUP);
                received = true;
            }
            SocketEvent::OutboundDrained => {
                assert!(!drained);
                drained = true;
            }
            event => panic!("unexpected setup event: {event:?}"),
        }
    }
    assert!(received && drained);
}
async fn ready_pair(tiny: bool, quantum: usize) -> Pair {
    let mut pair = pair(tiny, quantum).await;
    tokio::join!(setup(&mut pair.phone), setup(&mut pair.pc));
    pair
}
async fn receive_queued(pair: &mut Pair) -> Vec<u8> {
    let (sent, received) = tokio::join!(pair.phone.next_event(), pair.pc.next_event());
    assert!(
        matches!(sent, Ok(SocketEvent::OutboundDrained)),
        "local drain: {sent:?}"
    );
    match received.unwrap() {
        SocketEvent::Frame(frame) => frame.into_bytes(),
        event => panic!("expected one complete synthetic frame: {event:?}"),
    }
}

// Poll only the public future; dropping this future must retain its partial IO.
async fn poll_once(driver: &mut SocketDriver) -> Option<SocketEvent> {
    let mut future = pin!(driver.next_event());
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(None),
        Poll::Ready(result) => Poll::Ready(Some(result.expect("live guarded socket"))),
    })
    .await
}
async fn partial_write(driver: &mut SocketDriver) {
    let mut initial = None;
    for _ in 0..128 {
        assert!(
            poll_once(driver).await.is_none(),
            "frame must remain partial"
        );
        let pending = driver.pending_counts();
        if let Some(initial) = initial {
            if pending.socket_write_bytes > 0 && pending.socket_write_bytes < initial {
                assert!(pending.outbound_frame);
                assert!(
                    !pending.transport.outbound_frame,
                    "guard must survive inner encryption completion"
                );
                return;
            }
        } else if pending.socket_write_bytes > 0 {
            initial = Some(pending.socket_write_bytes);
        }
    }
    panic!("bounded driver polls did not produce a partial TCP write");
}
fn assert_discarded(driver: &SocketDriver, failure: SocketError) {
    let pending = driver.pending_counts();
    assert_eq!(driver.failure_reason(), Some(failure));
    assert!(!pending.outbound_frame);
    assert_eq!(pending.socket_write_bytes, 0);
    assert_eq!(pending.transport.outbound_plaintext_bytes, 0);
    assert_eq!(pending.transport.outbound_tls_bytes, 0);
}

#[tokio::test]
async fn pre_revoked_and_already_expired_restrictions_are_not_admitted() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 64).await;
        let guard = Arc::new(AtomicGuard::default());
        guard.revoke();
        assert_eq!(
            pair.phone.queue_guarded_frame(
                encode_frame(b"not admitted").unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                guard.clone()
            ),
            Err(SocketError::OutboundRevoked)
        );
        assert_eq!(Arc::strong_count(&guard), 1);
        let guard = Arc::new(AtomicGuard::default());
        assert_eq!(
            pair.phone.queue_guarded_frame(
                encode_frame(b"already expired").unwrap(),
                pair.clock.at(Duration::ZERO),
                guard.clone()
            ),
            Err(SocketError::SendDeadline)
        );
        assert_eq!(Arc::strong_count(&guard), 1);
        assert!(!pair.phone.pending_counts().outbound_frame);
        assert_eq!(pair.phone.failure_reason(), None);
        pair.phone
            .queue_frame(encode_frame(b"ordinary frame still works").unwrap())
            .unwrap();
        assert_eq!(
            receive_queued(&mut pair).await,
            b"ordinary frame still works"
        );
    })
    .await
    .expect("bounded rejection before guarded frame admission");
}

#[tokio::test]
async fn not_ready_does_not_install_the_rejected_guard() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = pair(false, 64).await;
        let guard = Arc::new(AtomicGuard::default());
        assert_eq!(
            pair.phone.queue_guarded_frame(
                encode_frame(b"not ready").unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                guard.clone()
            ),
            Err(SocketError::Transport(TransportError::NotReady))
        );
        assert_eq!(Arc::strong_count(&guard), 1);
        guard.revoke();
        tokio::join!(setup(&mut pair.phone), setup(&mut pair.pc));
        assert_eq!(pair.phone.failure_reason(), None);
    })
    .await
    .expect("bounded NotReady guard rejection");
}

#[tokio::test]
async fn shorter_absolute_deadline_survives_encryption_and_partial_tcp_writes() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 17).await;
        pair.phone
            .queue_guarded_frame(
                encode_frame(&vec![0x31; 4096]).unwrap(),
                pair.clock.at(Duration::from_millis(250)),
                Arc::new(AtomicGuard::default()),
            )
            .unwrap();
        partial_write(&mut pair.phone).await;
        pair.clock.set(Duration::from_millis(250));
        let result = pair.phone.next_event().await;
        assert!(
            matches!(result, Err(SocketError::SendDeadline)),
            "short deadline: {result:?}"
        );
        assert_discarded(&pair.phone, SocketError::SendDeadline);
        assert!(matches!(
            pair.phone.next_event().await,
            Err(SocketError::Failed)
        ));
    })
    .await
    .expect("bounded restricted original frame deadline");
}

#[tokio::test]
async fn later_supplied_deadline_cannot_extend_the_original_ten_seconds() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 17).await;
        pair.phone
            .queue_guarded_frame(
                encode_frame(&vec![0x32; 4096]).unwrap(),
                pair.clock.at(Duration::from_secs(60)),
                Arc::new(AtomicGuard::default()),
            )
            .unwrap();
        partial_write(&mut pair.phone).await;
        pair.clock.set(FRAME_TIMEOUT);
        let result = pair.phone.next_event().await;
        assert!(
            matches!(result, Err(SocketError::SendDeadline)),
            "original deadline: {result:?}"
        );
        assert_discarded(&pair.phone, SocketError::SendDeadline);
    })
    .await
    .expect("bounded non-extension of ten-second send deadline");
}

#[tokio::test]
async fn admitted_guard_revoked_before_first_write_cannot_deliver_a_complete_peer_frame() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 17).await;
        let guard = Arc::new(AtomicGuard::default());
        pair.phone
            .queue_guarded_frame(
                encode_frame(&vec![0x33; 4096]).unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                guard.clone(),
            )
            .unwrap();
        assert!(pair.phone.pending_counts().outbound_frame);
        guard.revoke();
        let result = pair.phone.next_event().await;
        assert!(
            matches!(result, Err(SocketError::OutboundRevoked)),
            "revoked frame: {result:?}"
        );
        assert_discarded(&pair.phone, SocketError::OutboundRevoked);
        assert_eq!(Arc::strong_count(&guard), 1);
        let peer = pair.pc.next_event().await;
        assert!(
            matches!(
                peer,
                Err(SocketError::Transport(TransportError::Channel(
                    ChannelError::Truncated
                ))) | Err(SocketError::Io)
            ),
            "no complete frame or authenticated close: {peer:?}"
        );
        assert_eq!(
            pair.budget.active(),
            2,
            "failure retains reservation until owner drop"
        );
        drop(pair.phone);
        drop(pair.pc);
        assert_eq!(pair.budget.active(), 0);
    })
    .await
    .expect("bounded guarded rejection before application TCP write");
}

#[tokio::test]
async fn busy_replacement_cannot_replace_the_original_guard_during_partial_writes() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 17).await;
        let original = Arc::new(AtomicGuard::default());
        pair.phone
            .queue_guarded_frame(
                encode_frame(&vec![0x34; 4096]).unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                original.clone(),
            )
            .unwrap();
        partial_write(&mut pair.phone).await;
        let replacement = Arc::new(AtomicGuard::default());
        assert_eq!(
            pair.phone.queue_guarded_frame(
                encode_frame(b"must not replace").unwrap(),
                pair.clock.at(Duration::from_secs(60)),
                replacement.clone()
            ),
            Err(SocketError::Transport(TransportError::Busy))
        );
        assert_eq!(Arc::strong_count(&replacement), 1);
        replacement.revoke();
        assert!(poll_once(&mut pair.phone).await.is_none());
        assert_eq!(pair.phone.failure_reason(), None);
        original.revoke();
        let result = pair.phone.next_event().await;
        assert!(
            matches!(result, Err(SocketError::OutboundRevoked)),
            "original guard: {result:?}"
        );
        assert_discarded(&pair.phone, SocketError::OutboundRevoked);
    })
    .await
    .expect("bounded preservation of admitted guard after Busy");
}

#[tokio::test]
async fn local_drain_releases_only_that_guard_and_unrestricted_next_frame_is_unchanged() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(false, 64).await;
        let guard = Arc::new(AtomicGuard::default());
        pair.phone
            .queue_guarded_frame(
                encode_frame(b"first guarded frame").unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                guard.clone(),
            )
            .unwrap();
        assert_eq!(receive_queued(&mut pair).await, b"first guarded frame");
        assert_eq!(Arc::strong_count(&guard), 1);
        guard.revoke();
        pair.clock.set(Duration::from_secs(1));
        pair.phone
            .queue_frame(encode_frame(b"next ordinary frame").unwrap())
            .unwrap();
        assert_eq!(receive_queued(&mut pair).await, b"next ordinary frame");
        assert_eq!(pair.phone.failure_reason(), None);
    })
    .await
    .expect("bounded guard retirement at actual local socket drain");
}

#[tokio::test]
async fn atomic_revocation_wakes_a_real_backpressured_guarded_write() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut pair = ready_pair(true, 16 * 1024).await;
        let guard = Arc::new(AtomicGuard::default());
        pair.phone
            .queue_guarded_frame(
                encode_frame(&vec![0x35; MAX_PC_EVENT_BYTES]).unwrap(),
                pair.clock.at(Duration::from_secs(1)),
                guard.clone(),
            )
            .unwrap();
        let mut previous = None;
        let mut blocked = false;
        for _ in 0..256 {
            assert!(poll_once(&mut pair.phone).await.is_none());
            let pending = pair.phone.pending_counts();
            if pending.socket_write_bytes > 0 && previous == Some(pending) {
                blocked = true;
                break;
            }
            previous = Some(pending);
        }
        assert!(
            blocked,
            "bounded small-buffer fixture must retain a blocked write"
        );
        let (result, ()) = tokio::join!(pair.phone.next_event(), async {
            tokio::task::yield_now().await;
            guard.revoke();
        });
        assert!(
            matches!(result, Err(SocketError::OutboundRevoked)),
            "blocked revocation: {result:?}"
        );
        assert_discarded(&pair.phone, SocketError::OutboundRevoked);
    })
    .await
    .expect("bounded wake for revoked output without guard-owned task");
}
