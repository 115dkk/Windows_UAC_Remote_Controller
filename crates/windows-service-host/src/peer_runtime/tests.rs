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
use service_protocol::{ClockProbe, VerifiedPcEvent};
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

const TEST_LIMIT: Duration = Duration::from_secs(15);
fn public(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
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
}
impl Identity {
    pub(super) fn new() -> Self {
        Self {
            public: public(20),
            key: SigningKey::from_slice(&[20; 32]).unwrap(),
            last_clock: RefCell::new(None),
            after_clock: RefCell::new(None),
        }
    }
    pub(super) fn sign_protocol(&self, bytes: &[u8]) -> Vec<u8> {
        let signature: Signature = self.key.sign(bytes);
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
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) routes: BTreeMap<DeviceId, (std::net::SocketAddr, relay_service::RouteId)>,
    after_checkpoint: RefCell<Option<Box<dyn FnMut()>>>,
}
impl RegistryFixture {
    pub(super) fn read_checkpoint(&self) -> RegistryCheckpoint {
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
        #[cfg(all(windows, target_pointer_width = "64"))]
        routes: BTreeMap::new(),
        after_checkpoint: RefCell::new(None),
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
    assert_eq!(
        mapped.program_name(),
        "Caption  · First line\ncontinued · C:\\later.exe"
    );
    assert_eq!(mapped.path(), "\\\\server\\first.exe");
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
        let binding = session.prompt.live().unwrap().binding;
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
        let deadline = session.prompt.live().unwrap().deadline;
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
        let deadline = session.prompt.live().unwrap().deadline;
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
    let binding = session.prompt.live().unwrap().binding;
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
    session.prompt.live_mut().unwrap().applying = Some((device(1), purpose));
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
