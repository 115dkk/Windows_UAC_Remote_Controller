// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TCP/rustls/framing and existing Android owner/socket composition.
//! Identity/registry fixtures are SOFTWARE ONLY, not TPM, native ACL or OS proof.

use android_controller::{
    AssociatedPcSocket, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeySetDescriptor, PcSocketEvent, PcSocketInputs, PeerAssociationDescriptor,
    PeerAssociationMutation,
};
use approval_core::{DeviceKeys, RegistryCheckpointEntry, RequestTtl};
use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, OsSession, RequestContent, UnsignedDecision,
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
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    net::TcpListener,
    rc::Rc,
    sync::{Mutex, atomic::AtomicU64, mpsc},
};

use super::*;

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
    fn new() -> Self {
        Self {
            public: public(20),
            key: SigningKey::from_slice(&[20; 32]).unwrap(),
            last_clock: RefCell::new(None),
            after_clock: RefCell::new(None),
        }
    }
    pub(super) fn sign_clock(
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
        let (mut owner, _) = DurableInbox::create_fresh_host_model(
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
