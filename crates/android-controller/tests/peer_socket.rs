// SPDX-License-Identifier: GPL-2.0-or-later
//! Real localhost TCP/TLS and real isolated host files; all identities, clocks,
//! enrollment calls and PC signatures are explicitly synthetic test fixtures.
//! No Android authentication/notification, native key, UAC or deployed relay proof.
#![cfg(any(windows, target_os = "linux"))]

#[path = "peer_socket/approval_send.rs"]
mod approval_send;
#[path = "peer_socket/denial_send.rs"]
mod denial_send;
#[path = "peer_socket/request_cancellation.rs"]
mod request_cancellation;
#[path = "peer_socket/request_sources.rs"]
mod request_sources;

use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use android_controller::{
    AssociatedPcSocket, AssociatedUpdate, DurableInbox, InboxCounts, LocalAttestationChallenge,
    LocalKeyHandle, LocalKeyObservation, LocalKeySetDescriptor, PcSocketEvent, PcSocketInputs,
    PeerAssociationDescriptor, PeerAssociationMutation, PeerAssociationRef, PeerAssociationRemoval,
    PeerSocketError, ReceivedPcEvent,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DeviceId, ExpiryTick, OsSession, PcIdentity, RequestBinding,
    RequestContent, RequestId,
};
use framed_transport::{
    CancellationToken, ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable,
    SocketDriver, SocketError, SocketEvent, SocketLimits,
};
use notification_policy::{
    CapacityLimits, ClockReading, Effect, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId, request_key};
use phone_state_store::{
    INTENT_FILE_NAME, NativePrivateDirectory, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME,
};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{
    CLOCK_REQUEST_BYTES, ClockProbeRequest, PcEvent, PcEventError, PcPublicKey, ServiceTick,
    UnsignedPcEvent, encode_frame,
};
use tokio::net::{TcpListener, TcpStream};

const TEST_DEADLINE: Duration = Duration::from_secs(10);
const MILLI: u64 = 1_000_000;
const PC_SIGNING_KEY: u8 = 20;
const PC_TRANSPORT_KEY: u8 = 21;
const PHONE_TRANSPORT_KEY: u8 = 5;
const CANARY: &[u8] = b"synthetic pre-intent staging canary";

/// One continuous HOST clock for socket Instants and coherent inbox units. This
/// is not an Android elapsedRealtimeNanos implementation or suspend-time proof.
struct HostClock {
    origin: Instant,
}
impl HostClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
        })
    }
    fn inbox(&self) -> InboxClock {
        let elapsed = Instant::now()
            .checked_duration_since(self.origin)
            .expect("host fixture monotonic clock");
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap();
        InboxClock::new(
            ClockReading::new(
                MonotonicTime::from_millis(nanos / MILLI),
                LocalTime::new(Weekday::Monday, 600).unwrap(),
            ),
            nanos,
        )
        .unwrap()
    }
}
impl SocketClock for HostClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}

struct SyntheticTransportSigner {
    key: SigningKey,
    calls: AtomicUsize,
}
impl SyntheticTransportSigner {
    fn new(seed: u8) -> Arc<Self> {
        Arc::new(Self {
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
            calls: AtomicUsize::new(0),
        })
    }
}
impl PlatformTlsSigner for SyntheticTransportSigner {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        let signature: Signature = self.key.sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}
fn public(seed: u8) -> TlsPublicKey {
    SyntheticTransportSigner::new(seed).public_key().unwrap()
}
fn identity(seed: u8, role: EndpointRole) -> TlsIdentity {
    TlsIdentity::from_trusted_host(role, SyntheticTransportSigner::new(seed)).unwrap()
}
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([7; 32]).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(5).unwrap()
}
fn handle() -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([1; 32]).unwrap()
}
fn directory(temp: &tempfile::TempDir) -> NativePrivateDirectory {
    NativePrivateDirectory::from_native_app_data(temp.path()).unwrap()
}
fn association() -> PeerAssociationDescriptor {
    PeerAssociationDescriptor::new(
        pc(),
        DeviceId::from_bytes([9; 16]).unwrap(),
        7,
        handle(),
        public(PC_SIGNING_KEY),
        public(PC_TRANSPORT_KEY),
    )
    .unwrap()
}
fn reference(mutation: PeerAssociationMutation) -> PeerAssociationRef {
    match mutation {
        PeerAssociationMutation::Recorded(reference)
        | PeerAssociationMutation::AlreadyRecorded(reference) => reference,
    }
}
fn owner(temp: &tempfile::TempDir, clock: &HostClock) -> (DurableInbox, PeerAssociationRef) {
    let (mut owner, initialized) = DurableInbox::create_fresh_host_model(
        directory(temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock.inbox(),
    )
    .unwrap();
    assert!(initialized.update().effects().is_empty());
    assert!(initialized.update().fault().is_none());
    let challenge = LocalAttestationChallenge::from_bytes([65; 32]).unwrap();
    let prepared = owner.begin_local_key_creation(handle(), challenge).unwrap();
    assert!(prepared.changed());
    let (created, observed) = owner
        .record_local_key_creation(
            LocalKeySetDescriptor::new(
                handle(),
                challenge,
                public(3),
                public(4),
                public(PHONE_TRANSPORT_KEY),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(created.changed());
    assert_eq!(observed, LocalKeyObservation::RecordedUnverified);
    // Trusted-host fixture only, NOT evidence of the unimplemented real ceremony.
    let (committed, recorded) = owner
        .record_peer_association_from_trusted_host(association())
        .unwrap();
    assert!(committed.changed());
    (owner, reference(recorded))
}

async fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (phone, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    (phone.unwrap(), accepted.unwrap().0)
}
struct Pair {
    phone: AssociatedPcSocket,
    pc: SocketDriver,
}
async fn pair(
    owner: &DurableInbox,
    reference: PeerAssociationRef,
    clock: Arc<HostClock>,
    stop: CancellationToken,
    budget: Arc<ConnectionBudget>,
) -> Pair {
    let (phone_socket, pc_socket) = sockets().await;
    let phone = AssociatedPcSocket::new(
        owner,
        reference,
        PcSocketInputs {
            socket: phone_socket,
            identity: identity(PHONE_TRANSPORT_KEY, EndpointRole::Client),
            budget: budget.clone(),
            clock: clock.clone(),
            limits: SocketLimits::default(),
            stop,
        },
    )
    .unwrap();
    let transport = PeerTransport::server(
        budget,
        identity(PC_TRANSPORT_KEY, EndpointRole::Server),
        public(PHONE_TRANSPORT_KEY),
        clock.now().unwrap(),
    )
    .unwrap();
    let pc = SocketDriver::new(
        pc_socket,
        transport,
        clock,
        SocketLimits::default(),
        CancellationToken::new(),
    )
    .unwrap();
    Pair { phone, pc }
}

fn signed_frame(event: PcEvent, seed: u8) -> Vec<u8> {
    let expected_pc = event.pc();
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    let signed = unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap();
    // A wrong-key test still sends a well-formed mathematically valid signature,
    // not corrupt DER. Only the enrolled application key differs on the phone.
    let fixture_key = PcPublicKey::from_spki_der(public(seed).as_spki_der()).unwrap();
    assert_eq!(
        signed
            .verify(expected_pc, &fixture_key)
            .unwrap()
            .verification_key(),
        &fixture_key
    );
    encode_frame(&signed.to_wire()).unwrap()
}
fn opened(id: u8) -> (PcEvent, RequestBinding) {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic receiver app",
            "C:\\Synthetic\\receiver.exe",
            "synthetic socket body, not native request evidence",
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(1, 3),
        RequestId::from_bytes([id; 32]).unwrap(),
        ChallengeNonce::from_bytes([44; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(60_000 * MILLI).unwrap(),
    );
    (
        PcEvent::Opened {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            content,
        },
        binding,
    )
}

// These helpers orchestrate public events only. TLS, framing, partial I/O,
// timeouts and connection provenance are exercised in the production owners.
async fn phone_initial_clock(
    phone: &mut AssociatedPcSocket,
    owner: &DurableInbox,
    clock: &HostClock,
) -> Result<ReceivedPcEvent, PeerSocketError> {
    let mut ready = false;
    let mut drained = false;
    let mut message = None;
    for _ in 0..4 {
        match phone.next_event().await? {
            PcSocketEvent::Ready => {
                assert!(!ready);
                ready = true;
                phone.queue_clock_probe(owner, clock.inbox())?;
            }
            PcSocketEvent::OutboundDrained => {
                assert!(!drained);
                drained = true;
            }
            PcSocketEvent::Message(received) => {
                assert!(message.is_none());
                message = Some(*received);
            }
            other => panic!("unexpected initial phone event: {other:?}"),
        }
        if drained && let Some(message) = message.take() {
            assert!(ready);
            return Ok(message);
        }
    }
    panic!("bounded initial phone event count exhausted")
}
async fn pc_initial_clock(pc_socket: &mut SocketDriver, seed: u8) -> ClockProbeRequest {
    let mut ready = false;
    let mut request = None;
    for _ in 0..4 {
        match pc_socket.next_event().await.unwrap() {
            SocketEvent::Ready => {
                assert!(!ready);
                ready = true;
            }
            SocketEvent::Frame(frame) => {
                assert!(ready && request.is_none());
                let bytes = frame.into_bytes();
                assert_eq!(bytes.len(), CLOCK_REQUEST_BYTES);
                let probe = ClockProbeRequest::from_wire(&bytes).unwrap();
                assert_eq!(probe.pc(), pc());
                pc_socket
                    .queue_frame(signed_frame(
                        PcEvent::Clock {
                            pc: probe.pc(),
                            epoch: epoch(),
                            probe: probe.nonce(),
                            sampled_at: ServiceTick::from_nanos_since_epoch(0),
                        },
                        seed,
                    ))
                    .unwrap();
                request = Some(probe);
            }
            SocketEvent::OutboundDrained => {
                return request.expect("fixed clock request preceded its reply");
            }
            other => panic!("unexpected initial PC event: {other:?}"),
        }
        // Do not stop at Ready: the server must keep driving its encrypted
        // readiness preface until the phone can issue the clock request.
    }
    panic!("bounded initial PC event count exhausted")
}
async fn initial_clock(
    pair: &mut Pair,
    owner: &DurableInbox,
    clock: &HostClock,
    seed: u8,
) -> Result<ReceivedPcEvent, PeerSocketError> {
    let (message, request) = tokio::join!(
        phone_initial_clock(&mut pair.phone, owner, clock),
        pc_initial_clock(&mut pair.pc, seed)
    );
    assert_eq!(request.pc(), pc());
    message
}
async fn phone_message(phone: &mut AssociatedPcSocket) -> Result<ReceivedPcEvent, PeerSocketError> {
    for _ in 0..2 {
        match phone.next_event().await? {
            PcSocketEvent::Message(received) => return Ok(*received),
            PcSocketEvent::OutboundDrained => (),
            other => panic!("unexpected phone message event: {other:?}"),
        }
    }
    panic!("bounded phone receive event count exhausted")
}
async fn send(pair: &mut Pair, event: PcEvent) -> ReceivedPcEvent {
    pair.pc
        .queue_frame(signed_frame(event, PC_SIGNING_KEY))
        .unwrap();
    let (message, drained) = tokio::join!(phone_message(&mut pair.phone), pair.pc.next_event());
    assert!(matches!(drained.unwrap(), SocketEvent::OutboundDrained));
    message.unwrap()
}
fn assert_clock_update(
    update: &AssociatedUpdate,
    owner: &DurableInbox,
    reference: PeerAssociationRef,
) {
    assert_eq!(update.association().reference(), reference);
    assert_eq!(update.local_keys().handle(), handle());
    update.check_current(owner).unwrap();
    assert!(update.committed().update().effects().is_empty());
    assert!(update.committed().update().issue().is_none());
    assert!(update.committed().update().fault().is_none());
    assert_eq!(owner.counts().unwrap().sources(), 1);
}

struct OwnerWitness {
    snapshot: Vec<u8>,
    counts: InboxCounts,
    history: usize,
    outcomes: usize,
}
fn witness(temp: &tempfile::TempDir, owner: &DurableInbox) -> OwnerWitness {
    OwnerWitness {
        snapshot: fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap(),
        counts: owner.counts().unwrap(),
        history: owner.history().unwrap().len(),
        outcomes: owner.pending_outcomes().unwrap().len(),
    }
}
fn stage_canary(temp: &tempfile::TempDir) {
    assert!(!temp.path().join(STAGING_FILE_NAME).exists());
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    fs::write(temp.path().join(STAGING_FILE_NAME), CANARY).unwrap();
}
fn assert_preintent_unchanged(
    temp: &tempfile::TempDir,
    owner: &DurableInbox,
    before: &OwnerWitness,
) {
    assert!(fs::read(temp.path().join(SNAPSHOT_FILE_NAME)).unwrap() == before.snapshot);
    assert!(fs::read(temp.path().join(STAGING_FILE_NAME)).unwrap() == CANARY);
    assert!(!temp.path().join(INTENT_FILE_NAME).exists());
    assert!(owner.fault().is_none());
    assert!(owner.inbox_fault().unwrap().is_none());
    assert_eq!(owner.counts().unwrap(), before.counts);
    assert_eq!(owner.history().unwrap().len(), before.history);
    assert_eq!(owner.pending_outcomes().unwrap().len(), before.outcomes);
}
fn remove_own_canary(temp: &tempfile::TempDir) {
    // Remove only the exact test-created obstacle after its expected rejection.
    // This is not product recovery, nor retrying an invalid event until success.
    assert!(fs::read(temp.path().join(STAGING_FILE_NAME)).unwrap() == CANARY);
    fs::remove_file(temp.path().join(STAGING_FILE_NAME)).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls_fixed_clock_exchange_and_opened_event_keep_current_association_context() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            budget.clone(),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        assert_eq!(pair.phone.correlation_received_nanos(), None);
        let accepted_clock = clock.inbox();
        let accepted_nanos = accepted_clock.phone_monotonic_nanos();
        let clock_update = pair
            .phone
            .apply_event(&mut owner, reply, accepted_clock)
            .unwrap();
        assert_eq!(
            pair.phone.correlation_received_nanos(),
            Some(accepted_nanos)
        );
        assert_clock_update(&clock_update, &owner, reference);
        let (event, binding) = opened(1);
        let message = send(&mut pair, event).await;
        let opened_update = pair
            .phone
            .apply_event(&mut owner, message, clock.inbox())
            .unwrap();
        assert_eq!(opened_update.association().reference(), reference);
        opened_update.check_current(&owner).unwrap();
        assert_eq!(
            pair.phone.correlation_received_nanos(),
            Some(accepted_nanos)
        );
        pair.phone.queue_clock_probe(&owner, clock.inbox()).unwrap();
        assert_eq!(
            pair.phone.correlation_received_nanos(),
            Some(accepted_nanos)
        );
        assert!(
            opened_update
                .committed()
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        let checked = owner
            .check_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(checked.check().update().effects().is_empty());
        let pending = checked
            .check()
            .request()
            .expect("current body after committed ingress");
        assert_eq!(pending.binding(), binding);
        assert_eq!(
            pending.original_window().service_issued_at(),
            ServiceTick::from_nanos_since_epoch(0)
        );
        assert_eq!(pending.content().program_name(), "Synthetic receiver app");
        assert!(owner.history().unwrap().is_empty());
        // Explicit abort invalidates retained context, not the shared parent token.
        pair.phone.abort();
        assert_eq!(pair.phone.correlation_received_nanos(), None);
        assert_eq!(
            clock_update.check_current(&owner),
            Err(PeerSocketError::ConnectionClosed)
        );
        assert_eq!(
            opened_update.check_current(&owner),
            Err(PeerSocketError::ConnectionClosed)
        );
        assert!(!stop.is_cancelled());
        drop(checked);
        drop(pair);
        assert_eq!(budget.active(), 0);
    })
    .await
    .expect("bounded real peer socket happy-path deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_tls_with_wrong_application_signing_key_closes_connection_without_owner_intent() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            Arc::new(ConnectionBudget::new(2).unwrap()),
        )
        .await;
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        let error = initial_clock(&mut pair, &owner, &clock, 22)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            PeerSocketError::Protocol(PcEventError::InvalidSignature)
        );
        assert_eq!(
            pair.phone.next_event().await.unwrap_err(),
            PeerSocketError::ConnectionClosed
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        assert!(!stop.is_cancelled());
    })
    .await
    .expect("bounded wrong application key deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_client_transport_identity_rejects_before_tls_allocation_or_signing() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (owner, reference) = owner(&temp, &clock);
        let (phone_socket, _server_socket) = sockets().await;
        let signer = SyntheticTransportSigner::new(4); // Local denial key, not transport.
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let stop = CancellationToken::new();
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        let result = AssociatedPcSocket::new(
            &owner,
            reference,
            PcSocketInputs {
                socket: phone_socket,
                identity: TlsIdentity::from_trusted_host(EndpointRole::Client, signer.clone())
                    .unwrap(),
                budget: budget.clone(),
                clock,
                limits: SocketLimits::default(),
                stop: stop.clone(),
            },
        );
        assert_eq!(
            result.unwrap_err(),
            PeerSocketError::TransportIdentityMismatch
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.active(), 0);
        assert_preintent_unchanged(&temp, &owner, &before);
        assert!(!stop.is_cancelled());
        // No dependence on the separately unresolved platform half-close probes.
    })
    .await
    .expect("bounded constructor identity rejection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_opened_after_remove_and_readd_is_rejected_before_intent() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            Arc::new(ConnectionBudget::new(2).unwrap()),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let update = pair
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&update, &owner, reference);
        let message = send(&mut pair, opened(2).0).await;
        let (removed, outcome) = owner
            .revoke_peer_association_from_trusted_host(reference)
            .unwrap();
        assert!(removed.changed());
        assert_eq!(outcome, PeerAssociationRemoval::Removed);
        let (added, mutation) = owner
            .record_peer_association_from_trusted_host(association())
            .unwrap();
        assert!(added.changed());
        let replacement = match mutation {
            PeerAssociationMutation::Recorded(value) => value,
            _ => panic!("new generation required"),
        };
        assert!(replacement.generation() > reference.generation());
        assert_eq!(
            update.check_current(&owner),
            Err(PeerSocketError::AssociationChanged)
        );
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        assert_eq!(
            pair.phone
                .apply_event(&mut owner, message, clock.inbox())
                .unwrap_err(),
            PeerSocketError::AssociationChanged
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        assert!(!stop.is_cancelled());
    })
    .await
    .expect("bounded stale association deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_opened_after_owner_reopen_rejects_even_with_same_saved_association() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            CancellationToken::new(),
            Arc::new(ConnectionBudget::new(2).unwrap()),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let update = pair
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&update, &owner, reference);
        let message = send(&mut pair, opened(3).0).await;
        drop(owner);
        let (mut reopened, initial) =
            DurableInbox::open_existing_host_model(directory(&temp), boot(), clock.inbox())
                .unwrap();
        assert!(initial.update().effects().is_empty());
        assert!(
            reopened
                .peer_associations()
                .unwrap()
                .resolve(reference)
                .is_some()
        );
        assert_eq!(
            update.check_current(&reopened),
            Err(PeerSocketError::DifferentOwner)
        );
        let before = witness(&temp, &reopened);
        stage_canary(&temp);
        assert_eq!(
            pair.phone
                .apply_event(&mut reopened, message, clock.inbox())
                .unwrap_err(),
            PeerSocketError::DifferentOwner
        );
        assert_preintent_unchanged(&temp, &reopened, &before);
    })
    .await
    .expect("bounded reopened owner deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_connection_messages_preserve_the_other_probe_and_established_correlation() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let budget = Arc::new(ConnectionBudget::new(4).unwrap());
        let mut first = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            budget.clone(),
        )
        .await;
        let mut second = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            budget.clone(),
        )
        .await;
        let first_clock = initial_clock(&mut first, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let second_clock = initial_clock(&mut second, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        assert_eq!(
            second
                .phone
                .apply_event(&mut owner, first_clock, clock.inbox())
                .unwrap_err(),
            PeerSocketError::DifferentConnection
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        assert_eq!(
            second.phone.queue_clock_probe(&owner, clock.inbox()),
            Err(PeerSocketError::ProbePending)
        );
        remove_own_canary(&temp);
        let update = second
            .phone
            .apply_event(&mut owner, second_clock, clock.inbox())
            .unwrap();
        assert_clock_update(&update, &owner, reference);

        let foreign_open = send(&mut first, opened(4).0).await;
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        assert_eq!(
            second
                .phone
                .apply_event(&mut owner, foreign_open, clock.inbox())
                .unwrap_err(),
            PeerSocketError::DifferentConnection
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        remove_own_canary(&temp);
        first.phone.abort();
        assert!(!stop.is_cancelled());
        update.check_current(&owner).unwrap();
        let (event, binding) = opened(5);
        let own_open = send(&mut second, event).await;
        let received = second
            .phone
            .apply_event(&mut owner, own_open, clock.inbox())
            .unwrap();
        received.check_current(&owner).unwrap();
        assert!(
            received
                .committed()
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        let checked = owner
            .check_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(checked.check().request().is_some());
        drop(checked);
        drop(first);
        drop(second);
        assert_eq!(budget.active(), 0);
    })
    .await
    .expect("bounded foreign connection isolation deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_cancellation_invalidates_received_opened_and_updates_before_owner_intent() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            Arc::new(ConnectionBudget::new(2).unwrap()),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let update = pair
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&update, &owner, reference);
        let queued = send(&mut pair, opened(6).0).await;
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        stop.cancel();
        assert_eq!(
            pair.phone.next_event().await.unwrap_err(),
            PeerSocketError::Socket(SocketError::Cancelled)
        );
        assert_eq!(
            update.check_current(&owner),
            Err(PeerSocketError::ConnectionClosed)
        );
        assert_eq!(
            pair.phone
                .apply_event(&mut owner, queued, clock.inbox())
                .unwrap_err(),
            PeerSocketError::ConnectionClosed
        );
        assert_preintent_unchanged(&temp, &owner, &before);
    })
    .await
    .expect("bounded terminal cancellation regression deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_connection_invalidates_retained_update_without_cancelling_shared_parent() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            budget.clone(),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let update = pair
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&update, &owner, reference);
        drop(pair.phone);
        assert_eq!(
            update.check_current(&owner),
            Err(PeerSocketError::ConnectionClosed)
        );
        assert!(!stop.is_cancelled());
        assert_eq!(budget.active(), 1);
        pair.pc.abort();
        drop(pair.pc);
        assert_eq!(budget.active(), 0);
        assert!(owner.fault().is_none());
    })
    .await
    .expect("bounded dropped connection context deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parked_liveness_preserves_then_invalidates_received_context_without_an_inbox_commit() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let stop = CancellationToken::new();
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let mut pair = pair(
            &owner,
            reference,
            clock.clone(),
            stop.clone(),
            budget.clone(),
        )
        .await;
        let reply = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let update = pair
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        let queued = send(&mut pair, opened(6).0).await;
        let before = witness(&temp, &owner);
        let pending = pair.phone.pending_counts();
        stage_canary(&temp);
        pair.phone.observe_liveness().unwrap();
        assert_eq!(pair.phone.pending_counts(), pending);
        assert_preintent_unchanged(&temp, &owner, &before);
        stop.cancel();
        assert_eq!(
            pair.phone.observe_liveness().unwrap_err(),
            PeerSocketError::Socket(SocketError::Cancelled)
        );
        assert_eq!(
            update.check_current(&owner),
            Err(PeerSocketError::ConnectionClosed)
        );
        assert_eq!(
            pair.phone
                .apply_event(&mut owner, queued, clock.inbox())
                .unwrap_err(),
            PeerSocketError::ConnectionClosed
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        drop(pair.phone);
        assert_eq!(budget.active(), 1);
        pair.pc.abort();
        drop(pair.pc);
        assert_eq!(budget.active(), 0);
    })
    .await
    .expect("bounded parked associated-context maintenance");
}
