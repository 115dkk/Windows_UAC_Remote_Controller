// SPDX-License-Identifier: GPL-2.0-or-later
//! Real isolated localhost sockets; synthetic clock/keys only. No native
//! TPM/Keystore, enrollment, notification or Windows approval is exercised.

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
    CancellationToken, ConnectionBudget, ConnectionBudgetError, FRAME_TIMEOUT,
    MAX_QUEUED_FRAME_BYTES, MAX_SOCKET_IDLE_TIMEOUT, MAX_SOCKET_LIFETIME, PeerTransport,
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
    HANDSHAKE_TIMEOUT, PlatformTlsSigner, SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{MAX_PC_EVENT_BYTES, encode_frame};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

const TEST_DEADLINE: Duration = Duration::from_secs(2);
const SETUP_FRAME: &[u8] = b"synthetic socket setup; not authority";

struct SyntheticClock {
    origin: Instant,
    nanos: AtomicU64,
    unavailable: AtomicBool,
}

impl SyntheticClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            nanos: AtomicU64::new(0),
            unavailable: AtomicBool::new(false),
        })
    }

    fn set(&self, time: Duration) {
        self.nanos
            .store(u64::try_from(time.as_nanos()).unwrap(), Ordering::SeqCst);
    }
}

impl SocketClock for SyntheticClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(SocketClockUnavailable);
        }
        self.origin
            .checked_add(Duration::from_nanos(self.nanos.load(Ordering::SeqCst)))
            .ok_or(SocketClockUnavailable)
    }
}

enum SignAction {
    None,
    Advance(Arc<SyntheticClock>),
    Cancel(CancellationToken),
}

struct SyntheticSigner {
    key: SigningKey,
    action: SignAction,
}

impl SyntheticSigner {
    fn new(seed: u8, action: SignAction) -> Arc<Self> {
        Arc::new(Self {
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
            action,
        })
    }
}

impl PlatformTlsSigner for SyntheticSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        let point =
            PublicKey::from_sec1_bytes(self.key.verifying_key().to_encoded_point(false).as_bytes())
                .unwrap();
        TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes())
            .map_err(|_| SignerError::Unavailable)
    }

    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let signature: Signature = self.key.sign(input.as_bytes());
        // Models a native observation/cancellation that changes during a
        // synchronous signing call, not a real hardware or biometric operation.
        match &self.action {
            SignAction::None => (),
            SignAction::Advance(clock) => clock.set(HANDSHAKE_TIMEOUT),
            SignAction::Cancel(stop) => stop.cancel(),
        }
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}

async fn sockets(tiny_buffers: bool) -> (TcpStream, TcpStream) {
    if tiny_buffers {
        // Only these two test sockets are configured. This is not a global OS
        // setting or a timeout workaround; it produces real write backpressure.
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
    phone_stop: CancellationToken,
}

async fn pair(tiny_buffers: bool, quantum: usize, action: SignAction) -> Pair {
    let (phone_socket, pc_socket) = sockets(tiny_buffers).await;
    let clock = SyntheticClock::new();
    let budget = Arc::new(ConnectionBudget::new(2).unwrap());
    let phone_signer = SyntheticSigner::new(3, action);
    let pc_signer = SyntheticSigner::new(4, SignAction::None);
    let now = clock.now().unwrap();
    let phone = PeerTransport::client(
        Arc::clone(&budget),
        TlsIdentity::from_trusted_host(EndpointRole::Client, phone_signer.clone()).unwrap(),
        pc_signer.public_key().unwrap(),
        now,
    )
    .unwrap();
    let pc = PeerTransport::server(
        Arc::clone(&budget),
        TlsIdentity::from_trusted_host(EndpointRole::Server, pc_signer).unwrap(),
        phone_signer.public_key().unwrap(),
        now,
    )
    .unwrap();
    let limits = SocketLimits::default()
        .with_io_chunk_bytes(quantum)
        .unwrap();
    let phone_stop = CancellationToken::new();
    let phone = SocketDriver::new(
        phone_socket,
        phone,
        clock.clone(),
        limits,
        phone_stop.clone(),
    )
    .unwrap();
    let pc = SocketDriver::new(
        pc_socket,
        pc,
        clock.clone(),
        limits,
        CancellationToken::new(),
    )
    .unwrap();
    Pair {
        phone,
        pc,
        clock,
        budget,
        phone_stop,
    }
}

async fn setup(driver: &mut SocketDriver) {
    assert!(matches!(
        driver.next_event().await.unwrap(),
        SocketEvent::Ready
    ));
    driver
        .queue_frame(encode_frame(SETUP_FRAME).unwrap())
        .unwrap();
    let bytes = collect_exchange(driver).await;
    assert_eq!(bytes, SETUP_FRAME);
}

async fn ready_pair(tiny_buffers: bool, quantum: usize) -> Pair {
    let mut fixture = pair(tiny_buffers, quantum, SignAction::None).await;
    tokio::join!(setup(&mut fixture.phone), setup(&mut fixture.pc));
    fixture
}

async fn collect_exchange(driver: &mut SocketDriver) -> Vec<u8> {
    let mut frame = None;
    let mut drained = false;
    for _ in 0..2 {
        match driver.next_event().await.unwrap() {
            SocketEvent::Frame(received) => {
                assert!(frame.is_none());
                frame = Some(received.into_bytes());
            }
            SocketEvent::OutboundDrained => {
                assert!(!drained);
                drained = true;
            }
            _ => panic!("unexpected event in bounded synthetic exchange"),
        }
    }
    assert!(drained);
    frame.expect("one complete frame")
}

// One public future poll, followed by cancellation of only that future. The
// production owner must preserve its partial I/O without a background task.
async fn pending_poll(driver: &mut SocketDriver) {
    assert!(
        poll_once(driver).await.is_none(),
        "expected retained partial I/O"
    );
}

async fn poll_once(driver: &mut SocketDriver) -> Option<SocketEvent> {
    let mut future = pin!(driver.next_event());
    poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(None),
        Poll::Ready(result) => Poll::Ready(Some(result.expect("live synthetic socket"))),
    })
    .await
}

async fn retain_backpressured_write(driver: &mut SocketDriver) {
    driver
        .queue_frame(encode_frame(&vec![0x5A; MAX_PC_EVENT_BYTES]).unwrap())
        .unwrap();
    let mut previous = None;
    for _ in 0..256 {
        pending_poll(driver).await;
        let current = driver.pending_counts();
        if current.socket_write_bytes > 0 && previous == Some(current) {
            return;
        }
        previous = Some(current);
    }
    panic!("bounded real small-buffer socket did not retain a blocked write");
}

async fn lonely(
    limits: SocketLimits,
) -> (
    SocketDriver,
    TcpStream,
    Arc<SyntheticClock>,
    Arc<ConnectionBudget>,
    CancellationToken,
) {
    let (socket, raw_peer) = sockets(false).await;
    let clock = SyntheticClock::new();
    let budget = Arc::new(ConnectionBudget::new(1).unwrap());
    let signer = SyntheticSigner::new(6, SignAction::None);
    let peer = SyntheticSigner::new(7, SignAction::None);
    let transport = PeerTransport::client(
        Arc::clone(&budget),
        TlsIdentity::from_trusted_host(EndpointRole::Client, signer).unwrap(),
        peer.public_key().unwrap(),
        clock.now().unwrap(),
    )
    .unwrap();
    let stop = CancellationToken::new();
    let driver = SocketDriver::new(socket, transport, clock.clone(), limits, stop.clone()).unwrap();
    (driver, raw_peer, clock, budget, stop)
}

#[test]
fn socket_limits_cannot_disable_or_enlarge_fixed_deadlines_and_buffers() {
    assert!(SocketLimits::new(Duration::ZERO, MAX_SOCKET_LIFETIME).is_err());
    assert!(SocketLimits::new(MAX_SOCKET_IDLE_TIMEOUT, Duration::ZERO).is_err());
    assert!(
        SocketLimits::new(
            MAX_SOCKET_IDLE_TIMEOUT + Duration::from_nanos(1),
            MAX_SOCKET_LIFETIME
        )
        .is_err()
    );
    assert!(
        SocketLimits::new(
            MAX_SOCKET_IDLE_TIMEOUT,
            MAX_SOCKET_LIFETIME + Duration::from_nanos(1)
        )
        .is_err()
    );
    assert!(SocketLimits::default().with_io_chunk_bytes(0).is_err());
    assert!(
        SocketLimits::default()
            .with_io_chunk_bytes(16 * 1024 + 1)
            .is_err()
    );
    assert!(SocketLimits::default().with_io_chunk_bytes(1).is_ok());
}

#[tokio::test]
async fn early_constructor_error_closes_the_socket_and_releases_its_reservation() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (socket, mut raw_peer) = sockets(false).await;
        let clock = SyntheticClock::new();
        let budget = Arc::new(ConnectionBudget::new(1).unwrap());
        let transport = PeerTransport::client(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(
                EndpointRole::Client,
                SyntheticSigner::new(14, SignAction::None),
            )
            .unwrap(),
            SyntheticSigner::new(15, SignAction::None)
                .public_key()
                .unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        assert_eq!(budget.active(), 1);
        clock.unavailable.store(true, Ordering::SeqCst);
        let result = SocketDriver::new(
            socket,
            transport,
            clock,
            SocketLimits::default(),
            CancellationToken::new(),
        );
        assert!(
            matches!(&result, Err(SocketError::ClockUnavailable)),
            "unexpected constructor result: {result:?}"
        );
        assert_eq!(budget.active(), 0);
        let mut byte = [0];
        match raw_peer.read(&mut byte).await {
            Ok(0) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                ) => {}
            _ => panic!("constructor failure must not leave an open socket or application bytes"),
        }
    })
    .await
    .expect("bounded early-constructor resource cleanup");
}

#[tokio::test]
async fn already_used_transport_cannot_import_unknown_socket_send_state() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (socket, _raw_peer) = sockets(false).await;
        let clock = SyntheticClock::new();
        let budget = Arc::new(ConnectionBudget::new(1).unwrap());
        let mut transport = PeerTransport::client(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(
                EndpointRole::Client,
                SyntheticSigner::new(16, SignAction::None),
            )
            .unwrap(),
            SyntheticSigner::new(17, SignAction::None)
                .public_key()
                .unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        let mut external_output = [0_u8; 512];
        assert!(
            transport
                .drain_tls(&mut external_output, clock.now().unwrap())
                .unwrap()
                > 0
        );
        let result = SocketDriver::new(
            socket,
            transport,
            clock,
            SocketLimits::default(),
            CancellationToken::new(),
        );
        assert!(
            matches!(&result, Err(SocketError::InvalidTransportState)),
            "reused transport result: {result:?}"
        );
        assert_eq!(budget.active(), 0);
    })
    .await
    .expect("bounded rejection of already-used transport adoption");
}

#[tokio::test]
async fn fragmented_duplex_bytes_and_cancelled_drive_future_are_lossless_and_bounded() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(false, 17).await;
        let phone_body = vec![0xA3; 4096];
        let pc_body = vec![0x4B; 3113];
        fixture
            .phone
            .queue_frame(encode_frame(&phone_body).unwrap())
            .unwrap();
        pending_poll(&mut fixture.phone).await;
        let pending = fixture.phone.pending_counts();
        assert!(pending.socket_write_bytes > 0);
        assert!(pending.socket_write_bytes <= 16 * 1024);
        assert!(pending.socket_read_bytes <= 16 * 1024);
        assert!(
            !pending.transport.outbound_frame,
            "inner TLS drain is not socket completion"
        );
        assert!(pending.outbound_frame);
        assert_eq!(
            fixture
                .phone
                .queue_frame(encode_frame(b"must not replace pending bytes").unwrap()),
            Err(SocketError::Transport(TransportError::Busy))
        );
        fixture
            .pc
            .queue_frame(encode_frame(&pc_body).unwrap())
            .unwrap();
        let (phone_received, pc_received) = tokio::join!(
            collect_exchange(&mut fixture.phone),
            collect_exchange(&mut fixture.pc)
        );
        assert_eq!(phone_received, pc_body);
        assert_eq!(pc_received, phone_body);
        assert_eq!(fixture.budget.active(), 2);
        drop(fixture.phone);
        assert_eq!(fixture.budget.active(), 1);
        drop(fixture.pc);
        assert_eq!(fixture.budget.active(), 0);
    })
    .await
    .expect("bounded real fragmented exchange");
}

#[tokio::test]
async fn cancellation_interrupts_a_real_backpressured_write_and_keeps_budget_until_drop() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(true, 16 * 1024).await;
        retain_backpressured_write(&mut fixture.phone).await;
        fixture.phone_stop.cancel();
        assert!(matches!(
            fixture.phone.next_event().await,
            Err(SocketError::Cancelled)
        ));
        assert_eq!(fixture.phone.pending_counts().socket_write_bytes, 0);
        assert_eq!(fixture.budget.active(), 2);
        let another = SyntheticSigner::new(8, SignAction::None);
        assert!(matches!(
            PeerTransport::client(
                Arc::clone(&fixture.budget),
                TlsIdentity::from_trusted_host(EndpointRole::Client, another.clone()).unwrap(),
                SyntheticSigner::new(9, SignAction::None)
                    .public_key()
                    .unwrap(),
                fixture.clock.now().unwrap()
            ),
            Err(TransportError::Budget(ConnectionBudgetError::Exhausted))
        ));
        drop(fixture.phone);
        assert_eq!(fixture.budget.active(), 1);
    })
    .await
    .expect("bounded cancellation with real retained output");
}

#[tokio::test]
async fn original_send_deadline_covers_real_socket_backpressure() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(true, 16 * 1024).await;
        retain_backpressured_write(&mut fixture.phone).await;
        fixture.clock.set(FRAME_TIMEOUT);
        assert!(matches!(
            fixture.phone.next_event().await,
            Err(SocketError::SendDeadline)
        ));
        assert_eq!(fixture.phone.pending_counts().socket_write_bytes, 0);
        assert!(matches!(
            fixture.phone.next_event().await,
            Err(SocketError::Failed)
        ));
    })
    .await
    .expect("bounded original socket send deadline");
}

#[tokio::test]
async fn authenticated_partial_frame_cannot_survive_its_original_deadline() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(false, 16 * 1024).await;
        fixture
            .phone
            .queue_frame(encode_frame(&vec![0x71; MAX_PC_EVENT_BYTES]).unwrap())
            .unwrap();
        let mut sender_drained = false;
        // The outer real-time deadline bounds this public-future driving. Stop
        // at the first authenticated partial frame, not after receiving it all.
        loop {
            if !sender_drained && let Some(event) = poll_once(&mut fixture.phone).await {
                assert!(matches!(event, SocketEvent::OutboundDrained));
                sender_drained = true;
            }
            assert!(poll_once(&mut fixture.pc).await.is_none());
            if fixture.pc.pending_counts().transport.incoming_frame_bytes > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        fixture.clock.set(FRAME_TIMEOUT);
        assert!(matches!(
            fixture.pc.next_event().await,
            Err(SocketError::InputDeadline)
                | Err(SocketError::Transport(TransportError::ReceiveDeadline))
        ));
        assert_eq!(
            fixture.pc.pending_counts().transport.incoming_frame_bytes,
            0
        );
        assert!(matches!(
            fixture.pc.next_event().await,
            Err(SocketError::Failed)
        ));
    })
    .await
    .expect("bounded authenticated partial-frame expiry");
}

#[tokio::test]
async fn cancellation_and_absolute_deadline_wake_an_idle_handshake() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (mut driver, _raw, _clock, _budget, stop) = lonely(SocketLimits::default()).await;
        let (result, ()) = tokio::join!(driver.next_event(), async {
            tokio::task::yield_now().await;
            stop.cancel();
        });
        assert!(matches!(result, Err(SocketError::Cancelled)));

        let limits = SocketLimits::new(Duration::from_secs(60), Duration::from_secs(1)).unwrap();
        let (mut driver, _raw, clock, _budget, _stop) = lonely(limits).await;
        let (result, ()) = tokio::join!(driver.next_event(), async {
            tokio::task::yield_now().await;
            clock.set(Duration::from_secs(1));
        });
        assert!(matches!(result, Err(SocketError::AbsoluteDeadline)));
    })
    .await
    .expect("bounded handshake cancellation/lifetime");
}

#[tokio::test]
async fn idle_and_existing_tls_handshake_deadlines_are_enforced_without_incoming_bytes() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let limits = SocketLimits::new(Duration::from_secs(1), Duration::from_secs(60)).unwrap();
        let (mut driver, _raw, clock, _budget, _stop) = lonely(limits).await;
        clock.set(Duration::from_secs(1));
        assert!(matches!(
            driver.next_event().await,
            Err(SocketError::IdleDeadline)
        ));

        let (mut driver, _raw, clock, _budget, _stop) = lonely(SocketLimits::default()).await;
        // Isolate the original TLS deadline: first hand the ClientHello to the
        // actual socket. Otherwise its equally early ten-second wire budget
        // correctly wins before PeerTransport's handshake check.
        loop {
            pending_poll(&mut driver).await;
            let pending = driver.pending_counts();
            if pending.socket_write_bytes == 0 && pending.transport.outbound_tls_bytes == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let (result, ()) = tokio::join!(driver.next_event(), async {
            tokio::task::yield_now().await;
            clock.set(HANDSHAKE_TIMEOUT);
        });
        assert!(
            matches!(
                &result,
                Err(SocketError::Transport(TransportError::Channel(
                    ChannelError::HandshakeExpired
                )))
            ),
            "expected the original TLS handshake deadline, got {result:?}"
        );
    })
    .await
    .expect("bounded idle/handshake timers");
}

#[tokio::test]
async fn unavailable_or_regressing_native_clock_is_terminal_without_fallback() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (mut driver, _raw, clock, _budget, _stop) = lonely(SocketLimits::default()).await;
        clock.unavailable.store(true, Ordering::SeqCst);
        assert!(matches!(
            driver.next_event().await,
            Err(SocketError::ClockUnavailable)
        ));
        clock.unavailable.store(false, Ordering::SeqCst);
        assert!(matches!(
            driver.next_event().await,
            Err(SocketError::Failed)
        ));

        let (mut driver, _raw, clock, _budget, _stop) = lonely(SocketLimits::default()).await;
        clock.set(Duration::from_millis(1));
        assert_eq!(
            driver.queue_frame(encode_frame(b"no application before readiness").unwrap()),
            Err(SocketError::Transport(TransportError::NotReady))
        );
        clock.set(Duration::ZERO);
        assert!(matches!(
            driver.next_event().await,
            Err(SocketError::ClockRegressed)
        ));
    })
    .await
    .expect("bounded native clock failures");
}

#[tokio::test]
async fn malformed_tls_and_abrupt_eof_never_become_authenticated_close_or_ready() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (mut driver, mut raw, _clock, _budget, _stop) = lonely(SocketLimits::default()).await;
        raw.write_all(b"not a TLS record").await.unwrap();
        assert!(matches!(
            driver.next_event().await,
            Err(SocketError::Transport(TransportError::Channel(
                ChannelError::TlsRejected
            )))
        ));

        let mut fixture = ready_pair(false, 16 * 1024).await;
        fixture.pc.abort();
        assert!(matches!(
            fixture.phone.next_event().await,
            Err(SocketError::Transport(TransportError::Channel(
                ChannelError::Truncated
            ))) | Err(SocketError::Io)
        ));
    })
    .await
    .expect("bounded malformed/abrupt socket closure");
}

#[tokio::test]
async fn graceful_close_notify_and_local_close_are_distinct_and_release_no_authority() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(false, 23).await;
        fixture.phone.begin_close().unwrap();
        assert_eq!(
            fixture
                .phone
                .queue_frame(encode_frame(b"no writes during local close").unwrap()),
            Err(SocketError::Closing)
        );
        let (local, remote) = tokio::join!(fixture.phone.next_event(), fixture.pc.next_event());
        assert!(matches!(local, Ok(SocketEvent::LocallyClosed)));
        assert!(matches!(remote, Ok(SocketEvent::PeerClosed)));
        assert_eq!(fixture.phone.failure_reason(), None);
        assert_eq!(fixture.pc.failure_reason(), None);
        assert!(matches!(
            fixture.pc.next_event().await,
            Err(SocketError::Closed)
        ));
        assert_eq!(fixture.budget.active(), 2);
        drop((fixture.phone, fixture.pc));
        assert_eq!(fixture.budget.active(), 0);
    })
    .await
    .expect("bounded authenticated/local closure distinction");
}

#[tokio::test]
async fn invalid_or_overallocated_frame_is_rejected_by_the_existing_core() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(false, 16 * 1024).await;
        let mut frame = Vec::with_capacity(MAX_QUEUED_FRAME_BYTES + 1);
        frame.extend_from_slice(&encode_frame(b"synthetic overallocated frame").unwrap());
        assert_eq!(
            fixture.phone.queue_frame(frame),
            Err(SocketError::Transport(TransportError::InvalidOutboundFrame))
        );
        assert_eq!(fixture.phone.pending_counts().socket_write_bytes, 0);

        let mut fixture = ready_pair(false, 16 * 1024).await;
        assert_eq!(
            fixture.pc.queue_frame(vec![0, 0, 0, 0]),
            Err(SocketError::Transport(TransportError::InvalidOutboundFrame))
        );
        assert!(matches!(
            fixture.pc.next_event().await,
            Err(SocketError::Failed)
        ));
    })
    .await
    .expect("bounded existing frame admission rules");
}

#[tokio::test]
async fn protocol_rejection_and_debug_do_not_expose_payload_or_report_success() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut fixture = ready_pair(false, 16 * 1024).await;
        fixture
            .phone
            .queue_frame(encode_frame(b"SYNTHETIC_PRIVATE_PAYLOAD").unwrap())
            .unwrap();
        assert!(!format!("{:?}", fixture.phone).contains("SYNTHETIC_PRIVATE_PAYLOAD"));
        assert_eq!(
            fixture.phone.reject_protocol_message(),
            Err(SocketError::Transport(TransportError::ProtocolRejected))
        );
        assert_eq!(
            fixture
                .phone
                .pending_counts()
                .transport
                .outbound_plaintext_bytes,
            0
        );
        assert_eq!(
            fixture.phone.failure_reason(),
            Some(SocketError::Transport(TransportError::ProtocolRejected))
        );
    })
    .await
    .expect("bounded explicit protocol rejection");
}

#[tokio::test]
async fn cancellation_during_synchronous_signer_is_observed_before_ready() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let stop = CancellationToken::new();
        let (phone_socket, pc_socket) = sockets(false).await;
        let clock = SyntheticClock::new();
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let phone_signer = SyntheticSigner::new(10, SignAction::Cancel(stop.clone()));
        let pc_signer = SyntheticSigner::new(11, SignAction::None);
        let phone_transport = PeerTransport::client(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(EndpointRole::Client, phone_signer.clone()).unwrap(),
            pc_signer.public_key().unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        let pc_transport = PeerTransport::server(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(EndpointRole::Server, pc_signer).unwrap(),
            phone_signer.public_key().unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        let mut phone = SocketDriver::new(
            phone_socket,
            phone_transport,
            clock.clone(),
            SocketLimits::default(),
            stop,
        )
        .unwrap();
        let pc_stop = CancellationToken::new();
        let mut pc = SocketDriver::new(
            pc_socket,
            pc_transport,
            clock,
            SocketLimits::default(),
            pc_stop.clone(),
        )
        .unwrap();
        let (phone_result, pc_result) = tokio::join!(
            async {
                let result = phone.next_event().await;
                // This case isolates cancellation across the signer boundary; the
                // separate abrupt-EOF test owns observation of the raw TCP close.
                pc_stop.cancel();
                result
            },
            pc.next_event()
        );
        assert!(matches!(phone_result, Err(SocketError::Cancelled)));
        assert!(
            pc_result.is_err(),
            "peer must not become ready before the cancelled client completes"
        );
    })
    .await
    .expect("bounded cancellation across synchronous signing");
}

#[tokio::test]
async fn native_time_advancing_during_signer_cannot_evade_handshake_expiry() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let (phone_socket, pc_socket) = sockets(false).await;
        let clock = SyntheticClock::new();
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let phone_signer = SyntheticSigner::new(12, SignAction::Advance(clock.clone()));
        let pc_signer = SyntheticSigner::new(13, SignAction::None);
        let phone_transport = PeerTransport::client(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(EndpointRole::Client, phone_signer.clone()).unwrap(),
            pc_signer.public_key().unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        let pc_transport = PeerTransport::server(
            budget,
            TlsIdentity::from_trusted_host(EndpointRole::Server, pc_signer).unwrap(),
            phone_signer.public_key().unwrap(),
            clock.now().unwrap(),
        )
        .unwrap();
        let mut phone = SocketDriver::new(
            phone_socket,
            phone_transport,
            clock.clone(),
            SocketLimits::default(),
            CancellationToken::new(),
        )
        .unwrap();
        let mut pc = SocketDriver::new(
            pc_socket,
            pc_transport,
            clock.clone(),
            SocketLimits::default(),
            CancellationToken::new(),
        )
        .unwrap();
        // Transports were created at zero (TLS expiry ten seconds). Start I/O
        // at one second, making the independent RX/TX budgets eleven seconds.
        // A signer jump to ten now isolates the unchanged original TLS expiry.
        clock.set(Duration::from_secs(1));
        let (phone_result, pc_result) = tokio::join!(phone.next_event(), pc.next_event());
        assert!(
            matches!(
                &phone_result,
                Err(SocketError::Transport(TransportError::Channel(
                    ChannelError::HandshakeExpired
                )))
            ),
            "expected post-signer TLS handshake expiry, got {phone_result:?}"
        );
        assert!(
            pc_result.is_err(),
            "peer must not return readiness/frame after expiry: {pc_result:?}"
        );
    })
    .await
    .expect("bounded post-signer fresh-time expiry");
}
