// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TCP/rustls/framing and existing Android owner/socket composition.
//! Identity/registry fixtures are SOFTWARE ONLY, not TPM, native ACL or OS proof.
#![cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]

use android_controller::{
    AssociatedPcSocket, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeySetDescriptor, PcSocketEvent, PcSocketInputs, PeerAssociationDescriptor,
    PeerAssociationMutation,
};
use approval_core::{DeviceKeys, RegistryCheckpointEntry, RequestTtl};
use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, OsSession, RequestContent, UnsignedDecision,
};
use windows_prompt_probe::{
    LabelKind, ProbeCounts, ProbeReport, PromptAction, PromptContentObservation, PromptLabel,
    supervision::{ApplyOutcome, GoneReason, RefusalReason, TargetIdentity},
};

use notification_policy::{
    CapacityLimits, ClockReading, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId};
use phone_state_store::NativePrivateDirectory;
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, OwnedCertificateVerifyInput, SignerError,
};
use service_protocol::{ClockProbe, VerifiedPcEvent, verify_parked_prompts_notice};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    marker::PhantomData,
    net::TcpListener,
    rc::Rc,
    sync::{Mutex, atomic::AtomicU64, mpsc},
};

use super::*;
use crate::ProbeSupervisorError;

mod direct;

const TEST_LIMIT: Duration = Duration::from_secs(15);
fn public(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_sec1_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn decision_key(seed: u8) -> DecisionPublicKey {
    DecisionPublicKey::from_sec1_bytes(&public(seed).as_spki_der()[26..]).unwrap()
}
fn device(value: u8) -> DeviceId {
    DeviceId::from_bytes([value; 16]).unwrap()
}

pub(super) struct Identity {
    pub(super) public: TlsPublicKey,
    key: SigningKey,
    last_clock: RefCell<Option<Vec<u8>>>,
    after_clock: RefCell<Option<Box<dyn FnMut()>>>,
    after_protocol: RefCell<Option<Box<dyn FnMut()>>>,
}
impl Identity {
    pub(super) fn new() -> Self {
        Self {
            public: public(20),
            key: SigningKey::from_slice(&[20; 32]).unwrap(),
            last_clock: RefCell::new(None),
            after_clock: RefCell::new(None),
            after_protocol: RefCell::new(None),
        }
    }
    pub(super) fn sign_protocol(&self, bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = self.key.sign(bytes);
        if let Some(hook) = self.after_protocol.borrow_mut().as_mut() {
            hook();
        }
        signature.to_der().as_bytes().to_vec()
    }
    pub(super) fn sign_event(
        &self,
        value: UnsignedPcEvent,
    ) -> Result<SignedPcEvent, PeerRuntimeError> {
        let signature: Signature = self.key.sign(&value.signing_bytes());
        let result = value
            .with_der_signature(signature.to_der().as_bytes())
            .map_err(|_| PeerRuntimeError::Identity)?;
        *self.last_clock.borrow_mut() = Some(result.to_wire());
        if let Some(hook) = self.after_clock.borrow_mut().as_mut() {
            hook();
        }
        Ok(result)
    }
}
impl crate::tls_signer::tests::SyntheticKey for Identity {
    fn public_key(&self) -> Result<TlsPublicKey, TlsSigningBridgeError> {
        Ok(self.public.clone())
    }
    fn sign(
        &self,
        input: &OwnedCertificateVerifyInput,
    ) -> Result<CertificateVerifySignature, TlsSigningBridgeError> {
        let signature: Signature = self.key.sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| TlsSigningBridgeError::InvalidSignature)
    }
}

pub(super) struct RegistryFixture {
    pub(super) checkpoint: RegistryCheckpoint,
    pub(super) transport: BTreeMap<DeviceId, TlsPublicKey>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) relay: Option<std::net::SocketAddr>,
    pub(super) routes: BTreeMap<DeviceId, (std::net::SocketAddr, relay_service::RouteId)>,
    after_checkpoint: RefCell<Option<Box<dyn FnMut()>>>,
    identity_checks: Cell<usize>,
}
impl RegistryFixture {
    // Mirrors the native registry's healthy() check at each read boundary.
    pub(super) fn verify_identity(&self) {
        self.identity_checks.set(self.identity_checks.get() + 1);
    }

    pub(super) fn read_transport(&self, device: DeviceId) -> Option<TlsPublicKey> {
        self.verify_identity();
        self.transport.get(&device).cloned()
    }

    pub(super) fn read_checkpoint(&self) -> RegistryCheckpoint {
        self.verify_identity();
        let checkpoint = self.checkpoint.clone();
        // Test-only time advancement after the actual typed snapshot read. The
        // hook must not borrow this registry again or manufacture peer evidence.
        if let Some(hook) = self.after_checkpoint.borrow_mut().as_mut() {
            hook();
        }
        checkpoint
    }
}
fn registry() -> Rc<RefCell<RegistryFixture>> {
    let entries = [
        RegistryCheckpointEntry::new(
            device(1),
            1,
            DeviceKeys::new(decision_key(3), decision_key(4)).unwrap(),
        )
        .unwrap(),
        RegistryCheckpointEntry::new(
            device(2),
            2,
            DeviceKeys::new(decision_key(6), decision_key(7)).unwrap(),
        )
        .unwrap(),
    ];
    Rc::new(RefCell::new(RegistryFixture {
        checkpoint: RegistryCheckpoint::new(32, 3, entries).unwrap(),
        transport: [(device(1), public(5)), (device(2), public(8))].into(),
        #[cfg(all(windows, target_pointer_width = "64"))]
        relay: None,
        routes: BTreeMap::new(),
        after_checkpoint: RefCell::new(None),
        identity_checks: Cell::new(0),
    }))
}
fn replace_first(registry: &Rc<RefCell<RegistryFixture>>) {
    let mut current = registry.borrow_mut();
    let next = current.checkpoint.next_revision();
    let entries: Vec<_> = current
        .checkpoint
        .entries()
        .iter()
        .map(|entry| {
            if entry.device_id() == device(1) {
                RegistryCheckpointEntry::new(device(1), next, entry.keys().clone()).unwrap()
            } else {
                entry.clone()
            }
        })
        .collect();
    current.checkpoint = RegistryCheckpoint::new(32, next + 1, entries).unwrap();
}

struct PhoneSigner {
    key: SigningKey,
    public: TlsPublicKey,
}
impl PhoneSigner {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[seed; 32]).unwrap(),
            public: public(seed),
        }
    }
}
impl PlatformTlsSigner for PhoneSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(self.public.clone())
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let signature: Signature = self.key.sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::Rejected)
    }
}

enum Notice {
    Ready,
    Frame(Vec<u8>),
    ClockApplied,
    Closed,
}
struct Client {
    notices: mpsc::Receiver<Notice>,
    thread: Option<JoinHandle<()>>,
}
fn target(sequence: u32) -> TargetIdentity {
    TargetIdentity {
        hwnd: u64::from(sequence),
        pid: 40 + sequence,
        created: 80 + u64::from(sequence),
        sequence,
    }
}

fn prompt_report(caption: &str, path: &str) -> ProbeReport {
    prompt_report_with_labels(
        caption,
        vec![
            (LabelKind::Text, "Publisher".into()),
            (LabelKind::Hyperlink, path.into()),
            (LabelKind::Button, "Yes".into()),
            (LabelKind::Button, "No".into()),
        ],
    )
}

fn prompt_report_with_labels(caption: &str, values: Vec<(LabelKind, String)>) -> ProbeReport {
    let labels = values
        .into_iter()
        .enumerate()
        .map(|(ordinal, (kind, text))| {
            PromptLabel::new(u16::try_from(ordinal).unwrap(), 1, kind, true, text).unwrap()
        })
        .collect::<Vec<_>>();
    let element_count = u16::try_from(labels.len()).unwrap();
    let button_count = u16::try_from(
        labels
            .iter()
            .filter(|label| label.kind() == LabelKind::Button)
            .count(),
    )
    .unwrap();
    let content = PromptContentObservation::from_parts(vec![1], caption.into(), labels).unwrap();
    ProbeReport::from_observation(
        ProbeCounts {
            top_level_windows: 1,
            qualified_candidates: 1,
            elements: element_count,
            enabled_elements: element_count,
            button_elements: button_count,
            maximum_depth: 1,
            ..ProbeCounts::default()
        },
        content,
    )
    .unwrap()
}

#[derive(Default)]
struct FakePromptApply {
    calls: Vec<(TargetIdentity, PromptAction, [u8; 32])>,
}

impl prompt::PromptApply for FakePromptApply {
    fn apply_prompt(
        &mut self,
        target: TargetIdentity,
        action: PromptAction,
        content_digest: [u8; 32],
    ) -> Result<(), ProbeSupervisorError> {
        self.calls.push((target, action, content_digest));
        Ok(())
    }
}

fn streams() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    (server, client)
}
fn raw_client(
    client: TcpStream,
    server_key: TlsPublicKey,
    key_seed: u8,
    payloads: Vec<Vec<u8>>,
) -> Client {
    let (send, notices) = mpsc::sync_channel(16);
    let thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(async {
            tokio::time::timeout(TEST_LIMIT, async {
                client.set_nonblocking(true).unwrap();
                let identity = TlsIdentity::from_trusted_host(
                    EndpointRole::Client,
                    Arc::new(PhoneSigner::new(key_seed)),
                )
                .unwrap();
                let transport = PeerTransport::client(
                    Arc::new(ConnectionBudget::new(1).unwrap()),
                    identity,
                    server_key,
                    Instant::now(),
                )
                .unwrap();
                let mut driver = SocketDriver::new(
                    tokio::net::TcpStream::from_std(client).unwrap(),
                    transport,
                    Arc::new(ServiceClock),
                    SocketLimits::default(),
                    CancellationToken::new(),
                )
                .unwrap();
                let mut payloads = payloads.into_iter();
                loop {
                    match driver.next_event().await {
                        Ok(SocketEvent::Ready) => {
                            send.send(Notice::Ready).unwrap();
                            if let Some(payload) = payloads.next() {
                                driver.queue_frame(encode_frame(&payload).unwrap()).unwrap();
                            }
                        }
                        Ok(SocketEvent::OutboundDrained) => {
                            if let Some(payload) = payloads.next() {
                                driver.queue_frame(encode_frame(&payload).unwrap()).unwrap();
                            }
                        }
                        Ok(SocketEvent::Frame(frame)) => {
                            send.send(Notice::Frame(frame.into_bytes())).unwrap();
                        }
                        Ok(SocketEvent::PeerClosed | SocketEvent::LocallyClosed) | Err(_) => break,
                    }
                }
            })
            .await
        });
        let _ = send.send(Notice::Closed);
    });
    Client {
        notices,
        thread: Some(thread),
    }
}
fn phone_clock(base: Instant) -> InboxClock {
    let nanos = u64::try_from(base.elapsed().as_nanos()).unwrap();
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(nanos / 1_000_000),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        nanos,
    )
    .unwrap()
}
fn android_client(client: TcpStream, pc: PcIdentity, server_key: TlsPublicKey) -> Client {
    let (send, notices) = mpsc::sync_channel(16);
    let thread = thread::spawn(move || {
        let temp = tempfile::tempdir().unwrap();
        let base = Instant::now();
        // Android uses its actual directory-synced factory; the non-Android
        // fixture explicitly permits host filesystem durability. This is a
        // compile-time target choice, never a runtime fallback after failure.
        #[cfg(target_os = "android")]
        let create_owner = DurableInbox::create_fresh;
        #[cfg(not(target_os = "android"))]
        let create_owner = DurableInbox::create_fresh_host_model;
        let (mut owner, _) = create_owner(
            NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            PhoneBootId::from_native_boot_count(1).unwrap(),
            phone_clock(base),
        )
        .unwrap();
        let handle = LocalKeyHandle::from_bytes([1; 32]).unwrap();
        let challenge = LocalAttestationChallenge::from_bytes([65; 32]).unwrap();
        let _ = owner.begin_local_key_creation(handle, challenge).unwrap();
        let _ = owner
            .record_local_key_creation(
                LocalKeySetDescriptor::new(handle, challenge, public(3), public(4), public(5))
                    .unwrap(),
            )
            .unwrap();
        let (_, mutation) = owner
            .record_peer_association_from_trusted_host(
                PeerAssociationDescriptor::new(
                    pc,
                    device(1),
                    1,
                    handle,
                    server_key.clone(),
                    server_key,
                )
                .unwrap(),
            )
            .unwrap();
        let reference = match mutation {
            PeerAssociationMutation::Recorded(reference)
            | PeerAssociationMutation::AlreadyRecorded(reference) => reference,
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(TEST_LIMIT, async {
                client.set_nonblocking(true).unwrap();
                let mut socket = AssociatedPcSocket::new(
                    &owner,
                    reference,
                    PcSocketInputs {
                        socket: tokio::net::TcpStream::from_std(client).unwrap(),
                        identity: TlsIdentity::from_trusted_host(
                            EndpointRole::Client,
                            Arc::new(PhoneSigner::new(5)),
                        )
                        .unwrap(),
                        budget: Arc::new(ConnectionBudget::new(1).unwrap()),
                        clock: Arc::new(ServiceClock),
                        limits: SocketLimits::default(),
                        stop: CancellationToken::new(),
                    },
                )
                .unwrap();
                loop {
                    match socket.next_event().await.unwrap() {
                        PcSocketEvent::Ready => {
                            send.send(Notice::Ready).unwrap();
                            socket.queue_clock_probe(&owner, phone_clock(base)).unwrap();
                        }
                        PcSocketEvent::Message(message) => {
                            let update = socket
                                .apply_event(&mut owner, *message, phone_clock(base))
                                .unwrap();
                            update.check_current(&owner).unwrap();
                            assert!(socket.correlation_received_nanos().is_some());
                            send.send(Notice::ClockApplied).unwrap();
                            socket.abort();
                            break;
                        }
                        PcSocketEvent::OutboundDrained => (),
                        other => panic!("unexpected Android fixture event {other:?}"),
                    }
                }
            })
            .await
            .unwrap();
        });
    });
    Client {
        notices,
        thread: Some(thread),
    }
}

fn ready_peer(
    session: &mut ServiceSession<'_>,
    key: &Identity,
    device_id: DeviceId,
    key_seed: u8,
    clients: &mut Vec<Client>,
) {
    // Prompt events reach only connections whose clock exchange is complete,
    // exactly as the phone requires, so the fixture peer probes the clock first.
    let pc = session.engine.pc_identity();
    let probe = ClockProbe::start(pc, 0).unwrap();
    let (server, client) = streams();
    session
        .attach_carrier(ServicePeerCarrier {
            stream: server,
            device: device_id,
        })
        .unwrap();
    clients.push(raw_client(
        client,
        key.public.clone(),
        key_seed,
        vec![probe.request().to_wire().to_vec()],
    ));
    drive_until(session, |progress| {
        progress == SessionProgress::ClockDrained
    });
    let client = clients.last().unwrap();
    let end = Instant::now() + TEST_LIMIT;
    loop {
        if let Some(PcEvent::Clock { .. }) = try_verified_event(client, pc, key) {
            break;
        }
        assert!(Instant::now() < end, "clock response was not delivered");
        let _ = session.process_one();
        thread::yield_now();
    }
}

#[test]
fn ready_connection_without_a_clock_exchange_receives_no_prompt_event() {
    exercise(|session, key, _, clients| {
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 5, Vec::new()));
        drive_until(session, |progress| progress == SessionProgress::PeerReady);
        let now = session.now().unwrap();
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(1),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 7,
                },
                now,
            )
            .unwrap();
        assert_eq!(progress.queued_opened(), 0);
        assert_eq!(session.engine.pending_count(), 1);
        for _ in 0..16 {
            let _ = session.process_one();
            thread::yield_now();
        }
        assert!(try_verified_event(&clients[0], session.engine.pc_identity(), key).is_none());
    });
}

#[test]
fn connection_completing_its_clock_exchange_during_a_live_prompt_receives_the_same_opened() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        let now = session.now().unwrap();
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(1),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 7,
                },
                now,
            )
            .unwrap();
        assert_eq!(progress.queued_opened(), 1);
        let first = next_verified_event(&clients[0], session, key);
        assert!(matches!(first, PcEvent::Opened { .. }));

        // A second phone connects while the prompt is live: nothing before its
        // clock exchange, the identical signed request right after it.
        ready_peer(session, key, device(2), 8, clients);
        let second = next_verified_event(&clients[1], session, key);
        assert_eq!(first, second);
        for _ in 0..16 {
            let _ = session.process_one();
            thread::yield_now();
        }
        let pc = session.engine.pc_identity();
        assert!(try_verified_event(&clients[0], pc, key).is_none());
        assert!(try_verified_event(&clients[1], pc, key).is_none());
        assert_eq!(session.engine.pending_count(), 1);
    });
}

fn next_verified_event(
    client: &Client,
    session: &mut ServiceSession<'_>,
    key: &Identity,
) -> PcEvent {
    let pc = session.engine.pc_identity();
    let end = Instant::now() + TEST_LIMIT;
    loop {
        let _ = session.process_one();
        if let Some(event) = try_verified_event(client, pc, key) {
            return event;
        }
        assert!(Instant::now() < end, "signed PC event was not delivered");
        thread::yield_now();
    }
}

fn next_verified_event_without_processing(
    client: &Client,
    pc: PcIdentity,
    key: &Identity,
) -> PcEvent {
    let end = Instant::now() + TEST_LIMIT;
    loop {
        if let Some(event) = try_verified_event(client, pc, key) {
            return event;
        }
        assert!(Instant::now() < end, "signed PC event was not delivered");
        thread::yield_now();
    }
}

fn try_verified_event(client: &Client, pc: PcIdentity, key: &Identity) -> Option<PcEvent> {
    match client.notices.try_recv() {
        Ok(Notice::Frame(bytes)) => Some(
            VerifiedPcEvent::from_wire(
                &bytes,
                pc,
                &PcPublicKey::from_spki_der(key.public.as_spki_der()).unwrap(),
            )
            .unwrap()
            .event()
            .clone(),
        ),
        Ok(_) | Err(mpsc::TryRecvError::Empty) => None,
        Err(mpsc::TryRecvError::Disconnected) => panic!("peer closed before PC event"),
    }
}

fn next_parked_notice(
    client: &Client,
    session: &mut ServiceSession<'_>,
    key: &Identity,
) -> ParkedPromptsNotice {
    let end = Instant::now() + TEST_LIMIT;
    loop {
        let _ = session.process_one();
        match client.notices.try_recv() {
            Ok(Notice::Frame(bytes)) => {
                return verify_parked_prompts_notice(
                    &bytes,
                    &session.engine.pc_identity(),
                    &PcPublicKey::from_spki_der(key.public.as_spki_der()).unwrap(),
                )
                .unwrap();
            }
            Ok(_) | Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                panic!("peer closed before parked prompt notice")
            }
        }
        assert!(
            Instant::now() < end,
            "parked prompt notice was not delivered"
        );
        thread::yield_now();
    }
}

fn drive_until(
    session: &mut ServiceSession<'_>,
    mut accepted: impl FnMut(SessionProgress) -> bool,
) {
    let end = Instant::now() + TEST_LIMIT;
    while Instant::now() < end {
        let progress = session.process_one().unwrap();
        if accepted(progress) {
            return;
        }
        thread::yield_now();
    }
    panic!("bounded service fixture made no required progress");
}
fn drain(session: &mut ServiceSession<'_>) {
    for peer in &session.peers {
        peer.state.hold_exit.store(false, Ordering::Release);
        peer.state.hold_response.store(false, Ordering::Release);
    }
    session.begin_shutdown();
    let end = Instant::now() + TEST_LIMIT;
    while !matches!(session.poll_shutdown(), SessionCleanup::Quiescent { .. }) {
        assert!(Instant::now() < end, "actual I/O owners did not finish");
        thread::yield_now();
    }
    assert_eq!(session.budget.active(), 0);
    session.finish_shutdown().unwrap();
}
fn exercise(
    test: impl FnOnce(
        &mut ServiceSession<'_>,
        &Identity,
        Rc<RefCell<RegistryFixture>>,
        &mut Vec<Client>,
    ),
) {
    let key = Identity::new();
    let registry = registry();
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(Rc::clone(&registry), PhantomData),
        SessionKey::Fixture(&key),
        Instant::now(),
        Arc::new(ServiceClock),
    )
    .unwrap();
    let mut clients = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        test(&mut session, &key, registry, &mut clients)
    }));
    drain(&mut session);
    drop(session);
    for mut client in clients {
        let thread = client.thread.take().unwrap();
        let end = Instant::now() + TEST_LIMIT;
        while !thread.is_finished() {
            assert!(Instant::now() < end);
            thread::yield_now();
        }
        thread.join().unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn network_shutdown_records_exits_but_session_drop_does_not_write_diagnostics() {
    for drop_only in [false, true] {
        let key = Identity::new();
        let mut session = ServiceSession::new(
            RegistryOwner::Fixture(registry(), PhantomData),
            SessionKey::Fixture(&key),
            Instant::now(),
            Arc::new(ServiceClock),
        )
        .unwrap();
        session.network.embed_fixture(
            "192.168.1.50:7443".parse().unwrap(),
            network::GatewayReading {
                access: direct_network::ExternalAccess::Automatic,
                state: direct_network::DirectGatewayState::Discovering,
                candidates: Vec::new(),
                validity_seconds: 0,
                external: None,
                source: None,
                failure: None,
            },
        );
        let rows = session.network.record_fixture();
        let peer_rows = Rc::new(RefCell::new(Vec::new()));
        session.peer_worker_exit_fixture = Some(peer_rows.clone());
        session.peer_worker_exit_pending[PeerExitCause::Timeout as usize] = 2;
        session.peer_worker_exits[PeerExitCause::Timeout as usize] = 3;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if drop_only {
                let end = Instant::now() + TEST_LIMIT;
                while !session.network.finish_relay_fixture() {
                    assert!(Instant::now() < end, "relay did not finish before Drop");
                    thread::yield_now();
                }
                assert!(rows.borrow().is_empty());
            } else {
                drain(&mut session);
                session.poll_shutdown();
                assert_eq!(rows.borrow().len(), 1);
            }
        }));
        if result.is_err() {
            drain(&mut session);
        }
        drop(session);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        let rows = rows.borrow();
        let expected = usize::from(!drop_only);
        assert_eq!(
            (rows.len(), peer_rows.borrow().len()),
            (expected, expected),
            "drop_only={drop_only}"
        );
        if !drop_only {
            let row = serde_json::to_value(&rows[0]).unwrap();
            assert_eq!(
                row,
                serde_json::json!({
                    "kind": "relay_worker_stopped",
                    "outcome": {
                        "status": "clean",
                        "report": {
                            "accepted": 0,
                            "accept_failures": 0,
                            "rejected_capacity": 0,
                            "rejected_waiting_rooms": 0,
                            "paired": 0,
                            "invalid_registrations": 0,
                            "header_timeouts": 0,
                            "waiting_timeouts": 0,
                            "rendezvous_timeouts": 0,
                            "idle_timeouts": 0,
                            "absolute_timeouts": 0,
                            "disconnected": 0,
                            "io_failures": 0,
                            "cancelled": 0,
                            "task_failures": 0,
                            "peak_connections": 0,
                            "peak_waiting_rooms": 0,
                            "remaining_connections": 0
                        }
                    }
                })
            );
            assert_eq!(
                serde_json::to_value(&peer_rows.borrow()[0]).unwrap()["count"],
                5
            );
        }
    }
}

fn finished_peer_worker(
    session: &mut ServiceSession<'_>,
    task: impl FnOnce() -> Result<PeerExitCause, PeerExitCause> + Send + 'static,
) {
    let state = Arc::new(PeerState {
        owner: Arc::clone(&session.identity),
        epoch: session.engine.boot_epoch(),
        binding: session.binding(device(1)).unwrap(),
        active: AtomicBool::new(true),
        stop: CancellationToken::new(),
        hold_response: AtomicBool::new(false),
        hold_exit: AtomicBool::new(false),
    });
    let (_, events) = async_mpsc::channel(RESPONSE_QUEUE_CAPACITY);
    let (responses, _) = async_mpsc::channel(RESPONSE_QUEUE_CAPACITY);
    let worker = thread::spawn(task);
    let end = Instant::now() + TEST_LIMIT;
    while !worker.is_finished() {
        assert!(Instant::now() < end);
        thread::yield_now();
    }
    session.peers.push(PeerSlot {
        state,
        events,
        responses,
        thread: Some(worker),
        ready: false,
        protocol: None,
        clock_served: false,
        opened_sent: None,
        responses_in_flight: VecDeque::new(),
        address_query_after: None,
        clock_since: None,
        advertised: None,
        query_lapsed: false,
        deferred_query: None,
    });
}

// These peers have no transport or decision provenance. Only the idle registry
// pass is exercised; real decision tests continue to use TCP/TLS frames.
fn idle_revalidation_fixture(
    count: u8,
    test: impl FnOnce(&mut ServiceSession<'_>, &Rc<RefCell<RegistryFixture>>),
) {
    let key = Identity::new();
    let registry = registry();
    {
        let mut fixture = registry.borrow_mut();
        let entries = (1..=count)
            .map(|id| {
                let seed = 40 + id * 3;
                fixture.transport.insert(device(id), public(seed + 2));
                RegistryCheckpointEntry::new(
                    device(id),
                    u64::from(id),
                    DeviceKeys::new(decision_key(seed), decision_key(seed + 1)).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        fixture.checkpoint = RegistryCheckpoint::new(32, u64::from(count) + 1, entries).unwrap();
    }
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(Rc::clone(&registry), PhantomData),
        SessionKey::Fixture(&key),
        Instant::now(),
        Arc::new(ServiceClock),
    )
    .unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for id in 1..=count {
            finished_peer_worker(&mut session, || Ok(PeerExitCause::LocallyClosed));
            let binding = session.binding(device(id)).unwrap();
            Arc::get_mut(&mut session.peers.last_mut().unwrap().state)
                .unwrap()
                .binding = binding;
        }
        registry.borrow().identity_checks.set(0);
        test(&mut session, &registry);
    }));
    drain(&mut session);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn idle_revalidation_checks_identity_once_for_zero_one_and_thirty_two_peers() {
    let mut checks = Vec::new();
    for count in [0, 1, 32] {
        idle_revalidation_fixture(count, |session, registry| {
            session.revalidate_peers().unwrap();
            checks.push(registry.borrow().identity_checks.get());
            assert!(session.peers.iter().all(|peer| peer.state.live()));
        });
    }
    assert_eq!(checks, [1, 1, 1], "identity checks for 0, 1, 32 peers");
}

#[test]
fn idle_revalidation_reads_registry_changes_on_the_next_pass() {
    idle_revalidation_fixture(2, |session, registry| {
        session.revalidate_peers().unwrap();
        replace_first(registry);
        assert_eq!(session.revalidate_peers(), Err(PeerRuntimeError::Registry));
    });
}

#[test]
fn idle_revalidation_retires_only_the_peer_with_a_changed_transport_key() {
    idle_revalidation_fixture(2, |session, registry| {
        session.revalidate_peers().unwrap();
        registry
            .borrow_mut()
            .transport
            .insert(device(1), public(150));
        session.revalidate_peers().unwrap();
        assert!(!session.peers[0].state.live());
        assert!(session.peers[1].state.live());
        assert!(!session.closing);
    });
}

#[test]
fn reap_records_each_closed_cause_once_and_only_panic_marks_cleanup_failed() {
    use framed_transport::{SocketError, TransportError};
    use secure_channel::ChannelError;

    exercise(|session, _, _, _| {
        let errors = [
            (
                SocketError::Transport(TransportError::Channel(ChannelError::TlsRejected)),
                PeerExitCause::TlsFailure,
            ),
            (
                SocketError::Transport(TransportError::Channel(ChannelError::HandshakeExpired)),
                PeerExitCause::Timeout,
            ),
            (SocketError::IdleDeadline, PeerExitCause::Timeout),
            (
                SocketError::Transport(TransportError::ProtocolRejected),
                PeerExitCause::ProtocolViolation,
            ),
            (SocketError::ClockRegressed, PeerExitCause::ClockFailure),
            (SocketError::Io, PeerExitCause::IoFailure),
        ];
        for (error, expected) in errors {
            finished_peer_worker(session, move || Err(error.into()));
            assert_eq!(session.reap_finished(), 1);
            assert_eq!(session.reap_finished(), 0);
            let exits = session.take_peer_worker_exits();
            assert_eq!(
                exits.iter().find(|(cause, _)| *cause == expected),
                Some(&(expected, 1))
            );
            assert_eq!(exits.iter().map(|(_, count)| count).sum::<u64>(), 1);
            assert!(!session.io_failed);
            assert!(!session.closing);
        }
        for cause in [PeerExitCause::LocallyClosed, PeerExitCause::PeerClosed] {
            finished_peer_worker(session, move || Ok(cause));
        }
        finished_peer_worker(session, || panic!("synthetic peer worker panic"));
        assert_eq!(session.reap_finished(), 3);
        let exits = session.take_peer_worker_exits();
        for expected in [
            PeerExitCause::LocallyClosed,
            PeerExitCause::PeerClosed,
            PeerExitCause::Panic,
        ] {
            assert_eq!(
                exits.iter().find(|(cause, _)| *cause == expected),
                Some(&(expected, 1))
            );
        }
        assert_eq!(exits.iter().map(|(_, count)| count).sum::<u64>(), 3);
        assert!(session.io_failed);
        assert!(!session.closing);
        assert!(
            session
                .take_peer_worker_exits()
                .iter()
                .all(|(_, count)| *count == 0)
        );
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn reap_preserves_tls_failure_without_closing_the_session() {
    exercise(|session, key, _, clients| {
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 8, Vec::new()));
        let end = Instant::now() + TEST_LIMIT;
        while !session.peers.is_empty() {
            session.process_one().unwrap();
            assert!(Instant::now() < end, "peer worker did not finish");
            thread::yield_now();
        }
        assert!(
            session.peer_worker_exit_reported_at[PeerExitCause::TlsFailure as usize].is_some(),
            "the poll seam did not report the peer worker's TLS failure"
        );
        assert_eq!(
            session.peer_worker_exit_pending[PeerExitCause::TlsFailure as usize],
            0
        );
        assert!(!session.closing);
        assert!(!session.io_failed);
        assert!(
            session
                .take_peer_worker_exits()
                .iter()
                .all(|(_, count)| *count == 0)
        );
    });
}

#[test]
fn parked_notice_is_v3_only_edge_triggered_and_sent_to_a_new_ready_peer() {
    exercise(|session, key, _, clients| {
        let now = session.now().unwrap();
        session.set_parked_prompts(2, now).unwrap();
        assert_eq!(session.notice_sequence, 1);

        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 5, Vec::new()));
        drive_until(session, |progress| progress == SessionProgress::PeerReady);
        let first = next_parked_notice(&clients[0], session, key);
        assert_eq!(first.count, 2);
        assert_eq!(first.sequence, 1);
        assert_eq!(first.boot_epoch, session.engine.boot_epoch());

        let now = session.now().unwrap();
        session.set_parked_prompts(2, now).unwrap();
        assert_eq!(session.notice_sequence, 1);

        let now = session.now().unwrap();
        session.set_parked_prompts(0, now).unwrap();
        let cleared = next_parked_notice(&clients[0], session, key);
        assert_eq!(cleared.count, 0);
        assert_eq!(cleared.sequence, 2);

        session.peers[0].protocol = Some(secure_channel::ControlProtocol::V2);
        let now = session.now().unwrap();
        session.set_parked_prompts(1, now).unwrap();
        assert_eq!(session.notice_sequence, 3);
        for _ in 0..16 {
            let _ = session.process_one();
            thread::yield_now();
        }
        assert!(!matches!(
            clients[0].notices.try_recv(),
            Ok(Notice::Frame(_))
        ));
    });
}

#[test]
fn service_session_watcher_health_starts_and_updates_without_native_owners() {
    use crate::management_protocol::{WatcherHealth, WatcherRefusal};

    exercise(|session, _, _, _| {
        assert_eq!(session.watcher_health, WatcherHealth::Starting);
        session.set_watcher_health(WatcherHealth::Unavailable(WatcherRefusal::HelperFailed));
        assert_eq!(
            session.watcher_health,
            WatcherHealth::Unavailable(WatcherRefusal::HelperFailed)
        );
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn management_query_reads_the_current_software_registry_snapshot() {
    exercise(|session, _, registry, _| {
        registry.borrow_mut().routes.insert(
            device(1),
            (
                "192.0.2.10:443".parse().unwrap(),
                relay_service::RouteId::new([9; 32]).unwrap(),
            ),
        );

        let response = session
            .handle_management(
                crate::ffi::ManagementClientClass::GuiMedium,
                crate::management_protocol::ManagementRequest::Query,
            )
            .unwrap()
            .expect("query replies synchronously");
        let crate::management_protocol::ManagementResponse::Snapshot {
            relay,
            identity_provider,
            android_signer_digests,
            devices,
            ..
        } = response
        else {
            panic!("query must return a snapshot");
        };

        assert_eq!(relay, None);
        assert_eq!(
            identity_provider,
            crate::contract::IDENTITY_PROVIDER_PROFILE
        );
        assert_eq!(
            android_signer_digests.as_slice(),
            crate::ANDROID_SIGNER_SHA256
        );
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].device, device(1));
        assert_eq!(devices[0].revision, 1);
        assert!(devices[0].route_present);
        assert!(!devices[0].connected);
        assert_eq!(devices[0].enrolled_unix_secs, None);
        assert_eq!(devices[1].device, device(2));
        assert_eq!(devices[1].revision, 2);
        assert!(!devices[1].route_present);
        assert!(!devices[1].connected);
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn management_remove_updates_registry_and_engine_on_the_session_thread() {
    exercise(|session, _, registry, _| {
        registry.borrow_mut().routes.insert(
            device(1),
            (
                "192.0.2.10:443".parse().unwrap(),
                relay_service::RouteId::new([9; 32]).unwrap(),
            ),
        );

        let response = session
            .handle_management(
                crate::ffi::ManagementClientClass::CliElevated,
                crate::management_protocol::ManagementRequest::RemoveDevice { device: device(1) },
            )
            .unwrap();
        assert_eq!(
            response,
            Some(crate::management_protocol::ManagementResponse::Done)
        );

        let fixture = registry.borrow();
        assert!(
            fixture
                .checkpoint
                .entries()
                .iter()
                .all(|entry| entry.device_id() != device(1))
        );
        assert!(!fixture.transport.contains_key(&device(1)));
        assert!(!fixture.routes.contains_key(&device(1)));
        drop(fixture);
        assert!(
            session
                .engine
                .registry_checkpoint_for_privileged_host()
                .entries()
                .iter()
                .all(|entry| entry.device_id() != device(1))
        );
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn management_remove_unknown_device_is_refused_without_closing_session() {
    exercise(|session, _, _, _| {
        let response = session
            .handle_management(
                crate::ffi::ManagementClientClass::CliElevated,
                crate::management_protocol::ManagementRequest::RemoveDevice { device: device(99) },
            )
            .unwrap();
        assert!(matches!(
            response,
            Some(crate::management_protocol::ManagementResponse::Refused(_))
        ));
        assert!(!session.closing);
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn stale_proof_enrollment_commit_is_pairing_failed_without_closing_session() {
    exercise(|session, _, registry, _| {
        let candidate = android_attestation::SyntheticRkp::new();
        let chains = candidate
            .chains
            .each_ref()
            .map(|chain| chain.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let evidence =
            android_attestation::CandidateEvidence::new(&chains[0], &chains[1], &chains[2])
                .unwrap();
        let verified_status =
            android_attestation::TrustedStatusSnapshot::from_test_response(br#"{"entries":{}}"#)
                .unwrap();
        let proof = android_attestation::verify_key_bundle_with_test_anchors(
            &evidence,
            &candidate.expected,
            &candidate.policy,
            &verified_status,
            std::slice::from_ref(&candidate.anchor),
        )
        .unwrap();
        // Equal content from a new status fetch is deliberately not the status
        // snapshot against which this proof was verified.
        let current_status =
            android_attestation::TrustedStatusSnapshot::from_test_response(br#"{"entries":{}}"#)
                .unwrap();
        let enrollment = session.registry.as_mut().unwrap().enroll(
            device(99),
            proof,
            &candidate.policy,
            &current_status,
            relay_service::RouteId::new([99; 32]).unwrap(),
            "192.0.2.99:7443".parse().unwrap(),
        );
        assert!(matches!(&enrollment, Err(PeerRuntimeError::Registry)));
        let result = session.enrollment_step(enrollment.map_err(|_| pairing::Failure::Enrollment));
        assert!(matches!(result, Err(SessionProgress::PairingFailed)));
        assert!(
            registry
                .borrow()
                .checkpoint
                .entries()
                .iter()
                .all(|entry| entry.device_id() != device(99))
        );
        assert!(!session.closing);
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn frozen_candidate_closed_channel_is_pairing_failed_without_closing_session() {
    exercise(|session, _, _, _| {
        let result = session.enrollment_step::<()>(Err(pairing::Failure::Enrollment));
        assert!(matches!(result, Err(SessionProgress::PairingFailed)));
        assert!(!session.closing);
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn acceptance_delivery_failure_revokes_committed_device_before_pairing_failed() {
    exercise(|session, _, registry, _| {
        assert_eq!(
            session.reject_committed_enrollment(device(1), pairing::Failure::Enrollment),
            Ok(Some(SessionProgress::PairingFailed))
        );
        let fixture = registry.borrow();
        assert!(
            fixture
                .checkpoint
                .entries()
                .iter()
                .all(|entry| entry.device_id() != device(1))
        );
        assert!(!fixture.transport.contains_key(&device(1)));
        assert!(!fixture.routes.contains_key(&device(1)));
        drop(fixture);
        assert!(
            session
                .engine
                .registry_checkpoint_for_privileged_host()
                .entries()
                .iter()
                .all(|entry| entry.device_id() != device(1))
        );
        assert!(!session.closing);
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
struct EnrollmentLoopback {
    carrier: enrollment::EnrollmentCarrier,
    phone: JoinHandle<enrollment::tests::PhoneResult>,
    close: Arc<std::sync::Barrier>,
    device: DeviceId,
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn enrollment_loopback(session: &mut ServiceSession<'_>, confirm: bool) -> EnrollmentLoopback {
    use enrollment::{EnrollmentCarrier, EnrollmentProgress, TestVerification};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut candidate = android_attestation::SyntheticRkp::new();
    let checkpoint = session.current_registry_checkpoint().unwrap();
    let mut inputs = session.pairing.prepare_enrollment_fixture(
        session.engine.boot_epoch(),
        session.engine.pc_identity(),
        session.pc_key.clone(),
        &checkpoint,
        listener.local_addr().unwrap(),
        Arc::clone(&session.signer),
        candidate.policy.clone(),
    );
    candidate
        .reissue_for_challenge(*inputs.expected.challenge.as_bytes())
        .unwrap();
    inputs.verification = Some(TestVerification {
        status: android_attestation::TrustedStatusSnapshot::from_test_response(
            br#"{"entries":{}}"#,
        )
        .unwrap(),
        anchors: vec![candidate.anchor.clone()],
    });
    let device = inputs.expected.recipient;
    let close = Arc::new(std::sync::Barrier::new(2));
    let phone = enrollment::tests::spawn_phone(
        listener,
        inputs.invitation.clone(),
        inputs.route,
        candidate,
        true,
        Arc::clone(&close),
    );
    let mut carrier = EnrollmentCarrier::start(inputs).unwrap();
    // Keep the carrier waiting independently of the acceptance receive timeout.
    // The caller releases this test-only worker gate or cancels the real carrier.
    carrier
        .delivery_control
        .before
        .store(true, Ordering::Release);
    enrollment::tests::wait_progress(&mut carrier, &mut session.signing_worker, |_, carrier| {
        carrier.ready_for_frozen()
    });
    if confirm {
        let frozen = session
            .key
            .sign_frozen(carrier.unsigned_frozen().unwrap())
            .unwrap();
        carrier.send_frozen(frozen).unwrap();
        enrollment::tests::wait_progress(
            &mut carrier,
            &mut session.signing_worker,
            |progress, _| matches!(progress, EnrollmentProgress::PhoneConfirmed),
        );
        carrier.pc_decision(true).unwrap();
        enrollment::tests::wait_progress(
            &mut carrier,
            &mut session.signing_worker,
            |_, carrier| carrier.ready_to_commit(),
        );
    }
    EnrollmentLoopback {
        carrier,
        phone,
        close,
        device,
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn assert_enrollment_present(
    session: &ServiceSession<'_>,
    registry: &Rc<RefCell<RegistryFixture>>,
    device: DeviceId,
    present: bool,
) {
    let registry = registry.borrow();
    assert_eq!(
        registry
            .checkpoint
            .entries()
            .iter()
            .any(|entry| entry.device_id() == device),
        present
    );
    assert_eq!(registry.transport.contains_key(&device), present);
    assert_eq!(registry.routes.contains_key(&device), present);
    assert_eq!(
        session
            .engine
            .registry_checkpoint_for_privileged_host()
            .entries()
            .iter()
            .any(|entry| entry.device_id() == device),
        present
    );
    assert!(!session.closing);
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn enrollment_terminal(session: &mut ServiceSession<'_>) -> SessionProgress {
    let until = Instant::now() + TEST_LIMIT;
    loop {
        if let Some(progress) = session.process_enrollment(Instant::now()).unwrap() {
            return progress;
        }
        assert!(Instant::now() < until);
        thread::yield_now();
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn process_enrollment_rejects_actually_expired_proof_at_commit() {
    let _serial = enrollment::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    exercise(|session, _, registry, _| {
        let fixture = enrollment_loopback(session, true);
        // VerifiedKeyBundle has a real 30-second lifetime. Do not substitute a
        // different status snapshot or a manufactured registry error for expiry.
        thread::sleep(Duration::from_secs(31));
        session.pairing.install_enrollment_fixture(fixture.carrier);
        assert_eq!(
            session.process_enrollment(Instant::now()).unwrap(),
            Some(SessionProgress::PairingFailed)
        );
        assert_enrollment_present(session, &registry, fixture.device, false);
        fixture.phone.join().unwrap();
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn process_enrollment_frozen_receiver_drops_during_signing() {
    let _serial = enrollment::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    exercise(|session, key, registry, _| {
        let fixture = enrollment_loopback(session, false);
        *key.after_protocol.borrow_mut() = Some(fixture.carrier.close_command_receiver());
        session.pairing.install_enrollment_fixture(fixture.carrier);
        assert_eq!(
            session.process_enrollment(Instant::now()).unwrap(),
            Some(SessionProgress::PairingFailed)
        );
        key.after_protocol.borrow_mut().take();
        assert_enrollment_present(session, &registry, fixture.device, false);
        fixture.phone.join().unwrap();
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn process_enrollment_acceptance_queue_failure_rolls_back_both_owners() {
    let _serial = enrollment::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    exercise(|session, key, registry, _| {
        let fixture = enrollment_loopback(session, true);
        *key.after_protocol.borrow_mut() = Some(fixture.carrier.close_command_receiver());
        session.pairing.install_enrollment_fixture(fixture.carrier);
        assert_eq!(
            session.process_enrollment(Instant::now()).unwrap(),
            Some(SessionProgress::PairingFailed)
        );
        key.after_protocol.borrow_mut().take();
        assert_enrollment_present(session, &registry, fixture.device, false);
        fixture.phone.join().unwrap();
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn process_enrollment_cancel_at_delivery(after_drain: bool) {
    let _serial = enrollment::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    exercise(|session, _, registry, _| {
        let fixture = enrollment_loopback(session, true);
        let control = Arc::clone(&fixture.carrier.delivery_control);
        let mut cancel = fixture.carrier.close_command_receiver();
        let (pause, reached) = if after_drain {
            (&control.after, &control.reached_after)
        } else {
            (&control.before, &control.reached_before)
        };
        pause.store(true, Ordering::Release);
        if after_drain {
            control.before.store(false, Ordering::Release);
        }
        session.pairing.install_enrollment_fixture(fixture.carrier);
        // This call commits, signs, and queues Acceptance successfully.
        assert_eq!(session.process_enrollment(Instant::now()).unwrap(), None);
        assert_enrollment_present(session, &registry, fixture.device, true);
        let until = Instant::now() + TEST_LIMIT;
        while !reached.load(Ordering::Acquire) {
            assert!(Instant::now() < until);
            thread::yield_now();
        }
        cancel(); // The real carrier exits and releases its command receiver.
        if after_drain {
            fixture.close.wait();
        }
        let expected = if after_drain {
            SessionProgress::Enrolled(fixture.device)
        } else {
            SessionProgress::PairingFailed
        };
        assert_eq!(enrollment_terminal(session), expected);
        assert_enrollment_present(session, &registry, fixture.device, after_drain);
        fixture.phone.join().unwrap();
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn process_enrollment_carrier_failure_after_queue_before_drain_rolls_back() {
    process_enrollment_cancel_at_delivery(false);
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn process_enrollment_failure_after_drain_keeps_enrolled_outcome() {
    process_enrollment_cancel_at_delivery(true);
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn shutdown_at_acceptance_delivery(after_drain: bool) {
    let _serial = enrollment::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    exercise(|session, _, registry, _| {
        let fixture = enrollment_loopback(session, true);
        let control = Arc::clone(&fixture.carrier.delivery_control);
        let reached = if after_drain {
            control.after.store(true, Ordering::Release);
            control.before.store(false, Ordering::Release);
            &control.reached_after
        } else {
            &control.reached_before
        };
        session.pairing.install_enrollment_fixture(fixture.carrier);
        // Commit both owners and queue Acceptance while its delivery gate is held.
        assert_eq!(session.process_enrollment(Instant::now()).unwrap(), None);
        assert_enrollment_present(session, &registry, fixture.device, true);
        let until = Instant::now() + TEST_LIMIT;
        while !reached.load(Ordering::Acquire) {
            assert!(Instant::now() < until);
            thread::yield_now();
        }
        if after_drain {
            fixture.close.wait();
        }

        session.begin_shutdown();
        let cleanup = loop {
            let cleanup = session.poll_shutdown();
            if matches!(cleanup, SessionCleanup::Quiescent { .. }) {
                break cleanup;
            }
            assert!(
                Instant::now() < until,
                "service shutdown did not reach quiescence"
            );
            thread::yield_now();
        };
        assert_eq!(cleanup, SessionCleanup::Quiescent { io_failed: false });

        let registry = registry.borrow();
        assert_eq!(
            registry
                .checkpoint
                .entries()
                .iter()
                .any(|entry| entry.device_id() == fixture.device),
            after_drain
        );
        assert_eq!(
            registry.transport.contains_key(&fixture.device),
            after_drain
        );
        assert_eq!(registry.routes.contains_key(&fixture.device), after_drain);
        drop(registry);
        assert_eq!(
            session
                .engine
                .registry_checkpoint_for_privileged_host()
                .entries()
                .iter()
                .any(|entry| entry.device_id() == fixture.device),
            after_drain
        );
        fixture.phone.join().unwrap();
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn shutdown_before_acceptance_delivery_rolls_back_the_committed_device() {
    shutdown_at_acceptance_delivery(false);
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn shutdown_after_acceptance_delivery_keeps_the_device() {
    shutdown_at_acceptance_delivery(true);
}

#[test]
fn real_android_clock_probe_roundtrips_through_worker_key_and_same_engine_epoch() {
    exercise(|session, key, _, clients| {
        let pc = session.engine.pc_identity();
        let epoch = session.engine.boot_epoch();
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(android_client(client, pc, key.public.clone()));
        let mut applied = false;
        drive_until(session, |_| {
            while let Ok(notice) = clients[0].notices.try_recv() {
                applied |= matches!(notice, Notice::ClockApplied);
            }
            applied
        });
        let signed = key.last_clock.borrow().clone().unwrap();
        let verified = VerifiedPcEvent::from_wire(
            &signed,
            pc,
            &PcPublicKey::from_spki_der(key.public.as_spki_der()).unwrap(),
        )
        .unwrap();
        assert!(
            matches!(verified.event(), PcEvent::Clock { epoch: current, .. } if *current == epoch)
        );
        assert_eq!(session.engine.pending_count(), 0);
    });
}

#[test]
fn wrong_transport_key_never_produces_an_authenticated_frame() {
    exercise(|session, key, _, clients| {
        let probe = ClockProbe::start(session.engine.pc_identity(), 0).unwrap();
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(
            client,
            key.public.clone(),
            8,
            vec![probe.request().to_wire().to_vec()],
        ));
        drive_until(session, |progress| {
            assert_ne!(progress, SessionProgress::PeerReady);
            progress == SessionProgress::PeerRetired
        });
        assert!(key.last_clock.borrow().is_none());
    });
}

fn open_fixture_request(session: &mut ServiceSession<'_>) -> approval_core::PendingChallenge {
    // Private test-only OS-shaped input. Production exposes no request producer.
    session
        .engine
        .open_from_privileged_host(
            OsSession::new(1, 1),
            RequestContent::new(
                "Synthetic service request",
                "C:\\Synthetic\\fixture.exe",
                "synthetic test input",
            )
            .unwrap(),
            RequestTtl::from_millis(30_000).unwrap(),
            Instant::now(),
        )
        .unwrap()
}
fn decision_for(
    binding: approval_protocol::RequestBinding,
    device: DeviceId,
    purpose: DecisionPurpose,
    seed: u8,
) -> Vec<u8> {
    let unsigned = UnsignedDecision::new(binding, device, purpose);
    let signature: Signature = SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign(&unsigned.signing_bytes());
    SignedDecision::from_der(unsigned, signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
}

fn decision(challenge: &approval_core::PendingChallenge, device: DeviceId, seed: u8) -> Vec<u8> {
    let unsigned = UnsignedDecision::new(challenge.binding(), device, DecisionPurpose::Deny);
    let signature: Signature = SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign(&unsigned.signing_bytes());
    SignedDecision::from_der(unsigned, signature.to_der().as_bytes())
        .unwrap()
        .to_wire()
}

#[test]
fn content_mapping_preserves_order_paths_and_allowed_newlines_and_enforces_byte_bounds() {
    let report = prompt_report_with_labels(
        "Caption\t",
        vec![
            (LabelKind::Text, "First\rline\ncontinued".into()),
            (LabelKind::Hyperlink, "\\\\server\\first.exe".into()),
            (LabelKind::Text, "C:\\later.exe".into()),
            (LabelKind::Button, "Yes\u{7}".into()),
        ],
    );
    let mapped = prompt::map_content(&report).unwrap();
    assert_eq!(mapped.program_name(), "Caption ");
    assert_eq!(mapped.path(), "");
    assert_eq!(
        mapped.details(),
        "First line\ncontinued\n\\\\server\\first.exe\nC:\\later.exe\nYes "
    );

    let exact = prompt_report_with_labels(
        &"a".repeat(512),
        vec![(LabelKind::Hyperlink, "C:\\x".into())],
    );
    assert_eq!(
        prompt::map_content(&exact).unwrap().program_name().len(),
        512
    );
    let over = prompt_report_with_labels(
        &"a".repeat(513),
        vec![(LabelKind::Hyperlink, "C:\\x".into())],
    );
    assert_eq!(
        prompt::map_content(&over),
        Err(prompt::PromptContentMappingError::FieldTooLong)
    );

    let path = "C:\\x";
    let exact_details = prompt_report_with_labels(
        "caption",
        vec![
            (LabelKind::Hyperlink, path.into()),
            (LabelKind::Button, "d".repeat(8_192 - path.len() - 1)),
        ],
    );
    assert_eq!(
        prompt::map_content(&exact_details).unwrap().details().len(),
        8_192
    );
    let over_details = prompt_report_with_labels(
        "caption",
        vec![
            (LabelKind::Hyperlink, path.into()),
            (LabelKind::Button, "d".repeat(8_192 - path.len())),
        ],
    );
    assert_eq!(
        prompt::map_content(&over_details),
        Err(prompt::PromptContentMappingError::FieldTooLong)
    );

    let no_path = prompt_report_with_labels("caption", vec![(LabelKind::Text, "Publisher".into())]);
    assert_eq!(prompt::map_content(&no_path).unwrap().path(), "");
}

#[test]
fn appeared_opens_once_and_publishes_the_same_signed_request_to_two_live_peers() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        ready_peer(session, key, device(2), 8, clients);
        let now = session.now().unwrap();
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(1),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 7,
                },
                now,
            )
            .unwrap();
        assert_eq!(progress.queued_opened(), 2);
        assert_eq!(session.engine.pending_count(), 1);
        let first = next_verified_event(&clients[0], session, key);
        let second = next_verified_event(&clients[1], session, key);
        assert_eq!(first, second);
        let PcEvent::Opened { binding, .. } = first else {
            panic!("opened event expected");
        };
        assert_eq!(binding.session().session_id(), 7);
    });
}

#[test]
fn matching_phone_decision_applies_once_to_the_exact_target_and_observation_digest() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(2), 8, clients);
        let observed = prompt_report("Consent", "C:\\App\\tool.exe");
        let expected_digest = observed.content().digest();
        let expected_target = target(2);
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: expected_target,
                    report: observed,
                    session: 9,
                },
                now,
            )
            .unwrap();
        let binding = session.prompt.live().unwrap().binding();
        let wire = decision_for(binding, device(1), DecisionPurpose::Approve, 3);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 5, vec![wire]));
        let mut apply = FakePromptApply::default();
        let end = Instant::now() + TEST_LIMIT;
        let pc = session.engine.pc_identity();
        loop {
            let progress = session.process_one_with_watch(&mut apply).unwrap();
            let _ = try_verified_event(&clients[0], pc, key);
            if progress
                == (SessionProgress::ApplyRequested {
                    device: device(1),
                    purpose: DecisionPurpose::Approve,
                })
            {
                break;
            }
            assert!(Instant::now() < end, "decision was not applied");
            thread::yield_now();
        }
        assert_eq!(
            apply.calls,
            vec![(expected_target, PromptAction::Approve, expected_digest)]
        );
        for _ in 0..8 {
            let _ = session.process_one_with_watch(&mut apply).unwrap();
        }
        assert_eq!(apply.calls.len(), 1);
    });
}

#[test]
fn gone_cancels_and_publishes_cancelled_and_late_signed_decision_has_no_live_target() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        let prompt_target = target(3);
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: prompt_target,
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 11,
                },
                now,
            )
            .unwrap();
        let event = next_verified_event(&clients[0], session, key);
        let PcEvent::Opened { binding, .. } = event else {
            panic!("opened event expected");
        };
        let gone_now = session.now().unwrap();
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Gone {
                    target: prompt_target,
                    reason: GoneReason::Closed,
                },
                gone_now,
            )
            .unwrap();
        assert_eq!(progress.result(), Some(prompt::PromptResult::Cancelled));
        assert_eq!(session.engine.pending_count(), 0);
        let pc = session.engine.pc_identity();
        assert!(matches!(
            next_verified_event_without_processing(&clients[0], pc, key),
            PcEvent::Resolved {
                binding: resolved,
                outcome: service_protocol::RequestResolution::Cancelled,
                ..
            } if resolved == binding
        ));
        let late = decision_for(binding, device(2), DecisionPurpose::Deny, 7);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(2),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 8, vec![late]));
        let mut apply = FakePromptApply::default();
        let end = Instant::now() + TEST_LIMIT;
        loop {
            let progress = session.process_one_with_watch(&mut apply).unwrap();
            if progress == SessionProgress::AuthorizedButNotApplied(NotAppliedReason::NoLiveTarget)
            {
                break;
            }
            assert!(Instant::now() < end, "late decision was not rejected");
            thread::yield_now();
        }
        assert!(apply.calls.is_empty());
    });
}

#[test]
fn live_prompt_interface_keeps_publication_and_resolution_on_one_coherent_lease() {
    exercise(|session, _, _, _| {
        let now = session.now().unwrap();
        let content = Arc::new(RequestContent::new("Fixture", "", "Synthetic details").unwrap());
        let first = session
            .engine
            .open_from_privileged_host(
                OsSession::new(12, 0),
                (*content).clone(),
                prompt::request_ttl(),
                now,
            )
            .unwrap();
        let first_tick = session.tick(now).unwrap();
        let mut live = prompt::LivePrompt::opened(
            target(44),
            &first,
            Arc::clone(&content),
            [9; 32],
            first_tick,
            now + prompt::request_ttl().as_duration(),
        );
        assert!(
            matches!(live.publication(), PcEvent::Opened { binding, issued_at, content: published }
            if binding == first.binding() && issued_at == first_tick && Arc::ptr_eq(&published, &content))
        );
        assert!(!live.can_renew(target(44), now + Duration::from_secs(79)));
        assert!(!live.can_renew(target(45), now + Duration::from_secs(80)));
        assert!(!live.can_renew(target(44), live.deadline()));

        let mut previous_binding = first.binding();
        let mut previous_tick = first_tick;
        for seconds in [80, 160] {
            let renewal_time = now + Duration::from_secs(seconds);
            assert!(live.can_renew(target(44), renewal_time));
            let challenge = session
                .engine
                .renew_from_privileged_host(&previous_binding, prompt::request_ttl(), renewal_time)
                .unwrap();
            let issued_at = session.tick(renewal_time).unwrap();
            let deadline = renewal_time + prompt::request_ttl().as_duration();
            live.renew(&challenge, issued_at, deadline);
            assert_eq!(live.binding(), challenge.binding());
            assert_eq!(live.request_id(), first.binding().request_id());
            assert_eq!(live.deadline(), deadline);
            assert_eq!(live.target, target(44));
            assert_eq!(live.content_digest, [9; 32]);
            assert_eq!(live.applying_purpose(), None);
            // Repeated reconnect reads preserve the immediate signed predecessor.
            for _ in 0..2 {
                assert!(matches!(live.publication(), PcEvent::Renewed {
                    previous_binding: old, previous_issued_at: old_tick,
                    binding, issued_at: current_tick, content: published,
                } if old == previous_binding && old_tick == previous_tick
                    && binding == challenge.binding() && current_tick == issued_at
                    && Arc::ptr_eq(&published, &content)));
            }
            assert!(
                matches!(live.resolution(prompt::PromptResult::Cancelled), PcEvent::Resolved {
                binding, issued_at: current_tick, outcome: service_protocol::RequestResolution::Cancelled,
            } if binding == challenge.binding() && current_tick == issued_at)
            );
            previous_binding = challenge.binding();
            previous_tick = issued_at;
        }
    });
}

#[test]
fn live_prompt_interface_fences_exact_dispatched_action_without_rebinding() {
    exercise(|session, _, _, _| {
        let now = session.now().unwrap();
        let content = Arc::new(RequestContent::new("Fixture", "", "Synthetic details").unwrap());
        let first = session
            .engine
            .open_from_privileged_host(
                OsSession::new(12, 0),
                (*content).clone(),
                prompt::request_ttl(),
                now,
            )
            .unwrap();
        let mut live = prompt::LivePrompt::opened(
            target(44),
            &first,
            content,
            [9; 32],
            session.tick(now).unwrap(),
            now + prompt::request_ttl().as_duration(),
        );
        assert!(!live.mark_applying(
            target(45),
            first.binding(),
            device(1),
            DecisionPurpose::Approve
        ));
        assert!(!live.is_applying());
        assert!(live.mark_applying(
            target(44),
            first.binding(),
            device(1),
            DecisionPurpose::Deny
        ));
        assert!(live.is_applying());
        assert_eq!(live.applying_purpose(), Some(DecisionPurpose::Deny));
        assert!(!live.can_renew(target(44), now + Duration::from_secs(80)));
        assert!(!live.mark_applying(
            target(44),
            first.binding(),
            device(1),
            DecisionPurpose::Approve
        ));
        assert_eq!(live.applying_purpose(), Some(DecisionPurpose::Deny));
        assert_eq!(live.binding(), first.binding());
    });
}

#[test]
fn fresh_same_prompt_witness_renews_before_expiry_without_resolving_the_prompt() {
    exercise(|session, _, _, _| {
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(44),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 12,
                },
                now,
            )
            .unwrap();
        let original = session.prompt.live().unwrap().binding();
        let original_deadline = session.prompt.live().unwrap().deadline();
        let digest = session.prompt.live().unwrap().content_digest;
        let early = now + Duration::from_secs(79);
        session
            .handle_watch_event(
                crate::WatchEvent::StillPresent { target: target(44) },
                early,
            )
            .unwrap();
        assert_eq!(session.prompt.live().unwrap().binding(), original);
        let renew_at = now + Duration::from_secs(80);
        session
            .handle_watch_event(
                crate::WatchEvent::StillPresent { target: target(45) },
                renew_at,
            )
            .unwrap();
        assert_eq!(session.prompt.live().unwrap().binding(), original);
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::StillPresent { target: target(44) },
                renew_at,
            )
            .unwrap();
        assert_eq!(progress, prompt::PromptProgress::default());
        let renewed = session.prompt.live().unwrap();
        assert_ne!(renewed.binding(), original);
        assert_eq!(renewed.request_id(), original.request_id());
        assert_eq!(renewed.content_digest, digest);
        assert!(renewed.deadline() > original_deadline);
        assert!(matches!(
            renewed.publication(),
            PcEvent::Renewed { previous_binding, binding, .. }
                if previous_binding == original && binding == renewed.binding()
        ));
        assert_eq!(session.engine.pending_count(), 1);
        assert!(
            session
                .prompt_deadline_step(original_deadline)
                .unwrap()
                .is_none()
        );
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Gone {
                    target: target(44),
                    reason: crate::GoneReason::Closed,
                },
                original_deadline,
            )
            .unwrap();
        assert_eq!(progress.result(), Some(prompt::PromptResult::Cancelled));
        assert!(!session.prompt.is_live());
        assert_eq!(session.engine.pending_count(), 0);
    });
}

#[test]
fn deadline_expiry_publishes_expired_and_clears_engine_and_live_target() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(4),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 12,
                },
                now,
            )
            .unwrap();
        let _ = next_verified_event(&clients[0], session, key);
        let deadline = session.prompt.live().unwrap().deadline();
        let progress = session.prompt_deadline_step(deadline).unwrap().unwrap();
        assert_eq!(progress.result(), Some(prompt::PromptResult::Expired));
        assert_eq!(session.engine.pending_count(), 0);
        assert!(!session.prompt.is_live());
        let pc = session.engine.pc_identity();
        assert!(matches!(
            next_verified_event_without_processing(&clients[0], pc, key),
            PcEvent::Resolved {
                outcome: service_protocol::RequestResolution::Expired,
                ..
            }
        ));
    });
}

#[test]
fn applying_prompt_expires_at_its_prompt_deadline_and_publishes_expired() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(8),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 16,
                },
                now,
            )
            .unwrap();
        let opened = next_verified_event(&clients[0], session, key);
        let PcEvent::Opened { binding, .. } = opened else {
            panic!("opened event expected");
        };
        let _ = mark_applying(session, DecisionPurpose::Approve);
        assert_eq!(session.engine.pending_count(), 0);
        let deadline = session.prompt.live().unwrap().deadline();
        let progress = session.prompt_deadline_step(deadline).unwrap().unwrap();
        assert_eq!(progress.result(), Some(prompt::PromptResult::Expired));
        assert!(!session.prompt.is_live());
        let pc = session.engine.pc_identity();
        assert!(matches!(
            next_verified_event_without_processing(&clients[0], pc, key),
            PcEvent::Resolved {
                binding: resolved,
                outcome: service_protocol::RequestResolution::Expired,
                ..
            } if resolved == binding
        ));
    });
}

#[test]
fn replacement_withdraws_the_first_request_before_opening_the_second() {
    exercise(|session, key, _, clients| {
        ready_peer(session, key, device(1), 5, clients);
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(5),
                    report: prompt_report("First", "C:\\first.exe"),
                    session: 13,
                },
                now,
            )
            .unwrap();
        let first = next_verified_event(&clients[0], session, key);
        let PcEvent::Opened {
            binding: first_binding,
            ..
        } = first
        else {
            panic!("first opened event expected");
        };
        let replacement_now = session.now().unwrap();
        let progress = session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(6),
                    report: prompt_report("Second", "C:\\second.exe"),
                    session: 14,
                },
                replacement_now,
            )
            .unwrap();
        assert_eq!(progress.result(), Some(prompt::PromptResult::Cancelled));
        assert_eq!(progress.queued_opened(), 1);
        let pc = session.engine.pc_identity();
        assert!(matches!(
            next_verified_event_without_processing(&clients[0], pc, key),
            PcEvent::Resolved {
                binding,
                outcome: service_protocol::RequestResolution::Cancelled,
                ..
            } if binding == first_binding
        ));
        assert!(matches!(
            next_verified_event_without_processing(&clients[0], pc, key),
            PcEvent::Opened { binding, .. } if binding != first_binding
        ));
        assert_eq!(session.engine.pending_count(), 1);
    });
}

fn mark_applying(session: &mut ServiceSession<'_>, purpose: DecisionPurpose) -> TargetIdentity {
    let target = session.prompt.live().unwrap().target;
    let binding = session.prompt.live().unwrap().binding();
    let unsigned = UnsignedDecision::new(binding, device(1), purpose);
    let seed = if purpose == DecisionPurpose::Approve {
        3
    } else {
        4
    };
    let signature: Signature = SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign(&unsigned.signing_bytes());
    let decision = SignedDecision::from_der(unsigned, signature.to_der().as_bytes()).unwrap();
    let decision_now = session.now().unwrap();
    // The fake applies nothing here: the authorization is consumed on purpose.
    drop(
        session
            .engine
            .submit_decision(&decision, decision_now)
            .unwrap(),
    );
    assert!(
        session
            .prompt
            .live_mut()
            .unwrap()
            .mark_applying(target, binding, device(1), purpose)
    );
    target
}

#[test]
fn ordinary_gone_cancels_while_applied_outcomes_map_to_approved_denied_and_failed() {
    for (purpose, event, expected) in [
        (
            DecisionPurpose::Approve,
            None,
            prompt::PromptResult::Cancelled,
        ),
        (DecisionPurpose::Deny, None, prompt::PromptResult::Cancelled),
        (
            DecisionPurpose::Approve,
            Some(ApplyOutcome::Gone),
            prompt::PromptResult::Approved,
        ),
        (
            DecisionPurpose::Deny,
            Some(ApplyOutcome::Gone),
            prompt::PromptResult::Denied,
        ),
        (
            DecisionPurpose::Approve,
            Some(ApplyOutcome::StillPresent),
            prompt::PromptResult::FailedUnknown,
        ),
        (
            DecisionPurpose::Approve,
            Some(ApplyOutcome::Refused(RefusalReason::ContentChanged)),
            prompt::PromptResult::FailedRejected,
        ),
    ] {
        exercise(|session, key, _, clients| {
            ready_peer(session, key, device(1), 5, clients);
            let now = session.now().unwrap();
            session
                .handle_watch_event(
                    crate::WatchEvent::Appeared {
                        target: target(7),
                        report: prompt_report("Consent", "C:\\App\\tool.exe"),
                        session: 15,
                    },
                    now,
                )
                .unwrap();
            let opened = next_verified_event(&clients[0], session, key);
            let PcEvent::Opened { binding, .. } = opened else {
                panic!("opened event expected");
            };
            let applying_target = mark_applying(session, purpose);
            let applied_now = session.now().unwrap();
            let watch_event = event.map_or(
                crate::WatchEvent::Gone {
                    target: applying_target,
                    reason: GoneReason::Closed,
                },
                |outcome| crate::WatchEvent::Applied {
                    target: applying_target,
                    outcome,
                },
            );
            let progress = session
                .handle_watch_event(watch_event, applied_now)
                .unwrap();
            assert_eq!(progress.result(), Some(expected));
            assert!(!session.prompt.is_live());
            let pc = session.engine.pc_identity();
            let expected_resolution = match expected {
                prompt::PromptResult::Approved => service_protocol::RequestResolution::Approved,
                prompt::PromptResult::Denied => service_protocol::RequestResolution::Denied,
                prompt::PromptResult::Cancelled => service_protocol::RequestResolution::Cancelled,
                prompt::PromptResult::FailedRejected | prompt::PromptResult::FailedUnknown => {
                    service_protocol::RequestResolution::Failed
                }
                prompt::PromptResult::Expired => service_protocol::RequestResolution::Expired,
            };
            assert!(matches!(
                next_verified_event_without_processing(&clients[0], pc, key),
                PcEvent::Resolved {
                    binding: resolved,
                    outcome,
                    ..
                } if resolved == binding && outcome == expected_resolution
            ));
        });
    }
}

#[test]
fn genuine_decision_is_consumed_in_same_engine_but_never_applied_or_resolved_as_os_success() {
    exercise(|session, key, _, clients| {
        let challenge = open_fixture_request(session);
        let wire = decision(&challenge, device(1), 4);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(
            client,
            key.public.clone(),
            5,
            vec![wire.clone(), wire],
        ));
        let mut consumed = false;
        let mut replay = false;
        drive_until(session, |progress| {
            consumed |= progress
                == SessionProgress::AuthorizedButNotApplied(NotAppliedReason::PlatformUnavailable);
            replay |= matches!(
                progress,
                SessionProgress::DecisionRejected(DecisionError::UnknownOrCompleted)
            );
            consumed && replay
        });
        assert_eq!(session.engine.pending_count(), 0);
        assert!(key.last_clock.borrow().is_none());
        while let Ok(notice) = clients[0].notices.try_recv() {
            if let Notice::Frame(bytes) = notice {
                panic!("unexpected OS-result frame of {} bytes", bytes.len());
            }
        }
    });
}

#[test]
fn connection_end_after_verified_decision_settles_failed_without_closing_session() {
    exercise(|session, key, _, clients| {
        let now = session.now().unwrap();
        session
            .handle_watch_event(
                crate::WatchEvent::Appeared {
                    target: target(21),
                    report: prompt_report("Consent", "C:\\App\\tool.exe"),
                    session: 21,
                },
                now,
            )
            .unwrap();
        let binding = session.prompt.live().unwrap().binding();
        let wire = decision_for(binding, device(1), DecisionPurpose::Deny, 4);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        let state = Arc::clone(&session.peers[0].state);
        session.retire_peer_after_decision_verified = true;
        clients.push(raw_client(client, key.public.clone(), 5, vec![wire]));

        drive_until(session, |progress| {
            progress
                == SessionProgress::AuthorizedButNotApplied(
                    NotAppliedReason::PeerChangedAfterVerification,
                )
        });
        assert!(!state.live());
        assert_eq!(session.engine.pending_count(), 0);
        assert!(session.prompt.live().is_none());
        assert!(!session.closing);
    });
}

#[test]
fn different_enrolled_device_signature_cannot_be_transplanted_onto_this_transport() {
    exercise(|session, key, _, clients| {
        let challenge = open_fixture_request(session);
        let wire = decision(&challenge, device(2), 7);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 5, vec![wire]));
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
        assert_eq!(session.engine.pending_count(), 1);
    });
}

#[test]
fn peer_retired_during_clock_signature_is_rejected_without_closing_session() {
    exercise(|session, key, _, clients| {
        let probe = ClockProbe::start(session.engine.pc_identity(), 0).unwrap();
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        let state = Arc::clone(&session.peers[0].state);
        let retire_during_signature = Arc::clone(&state);
        *key.after_clock.borrow_mut() = Some(Box::new(move || {
            retire_during_signature.retire();
        }));
        clients.push(raw_client(
            client,
            key.public.clone(),
            5,
            vec![probe.request().to_wire().to_vec()],
        ));

        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
        assert!(!state.live());
        assert!(!session.closing);
        assert!(session.peers[0].responses_in_flight.is_empty());
    });
}

#[test]
fn revision_change_after_clock_signature_retires_source_before_response_queue() {
    exercise(|session, key, registry, clients| {
        *key.after_clock.borrow_mut() = Some(Box::new(move || replace_first(&registry)));
        let probe = ClockProbe::start(session.engine.pc_identity(), 0).unwrap();
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(
            client,
            key.public.clone(),
            5,
            vec![probe.request().to_wire().to_vec()],
        ));
        let end = Instant::now() + TEST_LIMIT;
        let error = loop {
            match session.process_one() {
                Err(error) => break error,
                Ok(progress) => assert_ne!(progress, SessionProgress::ClockQueued),
            }
            assert!(Instant::now() < end);
            thread::yield_now();
        };
        assert_eq!(error, PeerRuntimeError::Registry);
        assert!(session.closing);
        assert!(session.peers.iter().all(|peer| !peer.state.live()));
    });
}

#[test]
fn queued_signed_response_is_not_drained_after_registry_generation_retirement() {
    exercise(|session, key, registry, clients| {
        let probe = ClockProbe::start(session.engine.pc_identity(), 0).unwrap();
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        session.peers[0]
            .state
            .hold_response
            .store(true, Ordering::Release);
        clients.push(raw_client(
            client,
            key.public.clone(),
            5,
            vec![probe.request().to_wire().to_vec()],
        ));
        drive_until(session, |progress| progress == SessionProgress::ClockQueued);
        replace_first(&registry);
        assert_eq!(session.process_one(), Err(PeerRuntimeError::Registry));
        assert!(session.peers.iter().all(|peer| !peer.state.live()));
        drain(session);
        while let Ok(notice) = clients[0].notices.try_recv() {
            if let Notice::Frame(bytes) = notice {
                panic!("retired response drained {} bytes", bytes.len());
            }
        }
    });
}

#[test]
fn duplicate_peer_admission_is_bounded_and_shutdown_retains_actual_unfinished_owner() {
    exercise(|session, _, _, _| {
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        session.peers[0]
            .state
            .hold_exit
            .store(true, Ordering::Release);
        let (other, other_client) = streams();
        assert_eq!(
            session.attach_carrier(ServicePeerCarrier {
                stream: other,
                device: device(1)
            }),
            Err(PeerRuntimeError::Capacity)
        );
        drop(other_client);
        drop(client);
        session.begin_shutdown();
        assert!(matches!(
            session.poll_shutdown(),
            SessionCleanup::CleanupPending { owners: 1 }
        ));
        assert_eq!(
            session.finish_shutdown(),
            Err(PeerRuntimeError::CleanupPending)
        );
        assert!(session.registry.is_some());
    });
}

struct ControlledClock {
    origin: Instant,
    offset: Mutex<Duration>,
    calls: AtomicU64,
}
impl SocketClock for ControlledClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(self.origin + *self.offset.lock().unwrap())
    }
}

#[test]
fn real_queued_decision_expiring_during_peer_validation_does_not_consume_authorization() {
    let key = Identity::new();
    let registry = registry();
    let origin = Instant::now();
    let clock = Arc::new(ControlledClock {
        origin,
        offset: Mutex::new(Duration::ZERO),
        calls: AtomicU64::new(0),
    });
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(Rc::clone(&registry), PhantomData),
        SessionKey::Fixture(&key),
        origin,
        clock.clone(),
    )
    .unwrap();
    let mut clients = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Synthetic trusted-host request only. The RECEIVING frame below must
        // come from the unchanged actual TCP/TLS/Ready/framing path.
        let challenge = session
            .engine
            .open_from_privileged_host(
                OsSession::new(1, 1),
                RequestContent::new(
                    "Synthetic residence-bound request",
                    "C:\\Synthetic\\fixture.exe",
                    "synthetic test input",
                )
                .unwrap(),
                RequestTtl::from_millis(30_000).unwrap(),
                origin,
            )
            .unwrap();
        let wire = decision(&challenge, device(1), 4);
        let (server, client) = streams();
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(client, key.public.clone(), 5, vec![wire]));
        drive_until(&mut session, |progress| {
            progress == SessionProgress::PeerReady
        });

        // Drain only the real mailbox; never construct PeerFrame/ReceivedFrame
        // or replace its received timestamp/source/epoch. No wall-clock sleep.
        let end = Instant::now() + TEST_LIMIT;
        let event = loop {
            match session.peers[0].events.try_recv() {
                Ok(event @ PeerEvent::Frame(_)) => break event,
                Ok(_) => panic!("unexpected event before the original decision"),
                Err(async_mpsc::error::TryRecvError::Empty) => {
                    assert!(Instant::now() < end, "actual TLS decision was not queued");
                    thread::yield_now();
                }
                Err(async_mpsc::error::TryRecvError::Disconnected) => {
                    panic!("actual TLS owner closed before its decision frame");
                }
            }
        };
        let PeerEvent::Frame(frame) = &event else {
            unreachable!();
        };
        assert!(session.peers[0].ready);
        assert!(Arc::ptr_eq(&frame.source, &session.peers[0].state));
        assert_eq!(frame.received, origin);
        let deadline = frame.received.checked_add(EVENT_LIFETIME).unwrap();
        let elapsed_deadline = deadline.duration_since(origin);
        assert!(elapsed_deadline < Duration::from_secs(30));
        // Whole seconds avoid depending on the host Instant's sub-tick rounding.
        *clock.offset.lock().unwrap() = elapsed_deadline - Duration::from_secs(1);
        assert!(clock.now().unwrap() < deadline);

        let reads = Rc::new(Cell::new(0));
        let observed_reads = Rc::clone(&reads);
        let validation_clock = Arc::clone(&clock);
        *registry.borrow().after_checkpoint.borrow_mut() = Some(Box::new(move || {
            let count = observed_reads.get() + 1;
            observed_reads.set(count);
            // Dispatch's initial peer check reads twice; the THIRD read is
            // the decision's later peer validation, after initial residence
            // acceptance. Advance only this original clock to its exact deadline.
            if count == 3 {
                *validation_clock.offset.lock().unwrap() = elapsed_deadline;
            }
        }));

        assert_eq!(
            session.dispatch(0, event, None),
            Ok(SessionProgress::PeerRejected)
        );
        assert_eq!(
            reads.get(),
            4,
            "the later peer validation completed before rejection"
        );
        assert_eq!(*clock.offset.lock().unwrap(), elapsed_deadline);
        assert_eq!(
            session.engine.pending_count(),
            1,
            "the valid decision must not consume its still-live original request"
        );
        assert!(!session.peers[0].state.live());
        assert!(key.last_clock.borrow().is_none());
    }));
    // Preserve real ownership on assertion failure; ServiceSession Drop is not
    // a substitute for cancellation/joining of an actual live I/O owner.
    registry.borrow().after_checkpoint.borrow_mut().take();
    drain(&mut session);
    drop(session);
    for mut client in clients {
        let thread = client.thread.take().unwrap();
        let end = Instant::now() + TEST_LIMIT;
        while !thread.is_finished() {
            assert!(Instant::now() < end, "actual client owner did not finish");
            thread::yield_now();
        }
        thread.join().unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn native_clock_regression_closes_session_without_resetting_engine_epoch() {
    let key = Identity::new();
    let registry = registry();
    let origin = Instant::now();
    let clock = Arc::new(ControlledClock {
        origin,
        offset: Mutex::new(Duration::from_secs(2)),
        calls: AtomicU64::new(0),
    });
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(registry, PhantomData),
        SessionKey::Fixture(&key),
        origin,
        clock.clone(),
    )
    .unwrap();
    let epoch = session.engine.boot_epoch();
    session.process_one().unwrap();
    *clock.offset.lock().unwrap() = Duration::from_secs(1);
    assert_eq!(session.process_one(), Err(PeerRuntimeError::Clock));
    assert_eq!(session.engine.boot_epoch(), epoch);
    drain(&mut session);
}

#[test]
fn drop_live_owner_child() {
    if std::env::var_os("WUAC_TEST_ABORT_LIVE_IO").is_none() {
        return;
    }
    let key = Identity::new();
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(registry(), PhantomData),
        SessionKey::Fixture(&key),
        Instant::now(),
        Arc::new(ServiceClock),
    )
    .unwrap();
    let (server, _client) = streams();
    session
        .attach_carrier(ServicePeerCarrier {
            stream: server,
            device: device(1),
        })
        .unwrap();
    session.peers[0]
        .state
        .hold_exit
        .store(true, Ordering::Release);
    drop(session); // Deliberate invariant violation in THIS child process only.
    panic!("a live owner was silently detached");
}
#[test]
fn live_owner_drop_fallback_is_fail_fast_not_successful_quiescence() {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "peer_runtime::tests::drop_live_owner_child",
            "--nocapture",
        ])
        .env("WUAC_TEST_ABORT_LIVE_IO", "1")
        .status()
        .unwrap();
    assert!(!result.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(result.signal(), Some(6));
    }
    #[cfg(windows)]
    assert_ne!(
        result.code(),
        Some(101),
        "ordinary harness panic is not the abort fallback"
    );
}
