// SPDX-License-Identifier: GPL-2.0-or-later
//! Real owned std-carrier adoption, pinned TCP/TLS, signed service frames and
//! actual isolated host stores. Native keys/clock/sink are synthetic fixtures,
//! never Android hardware/auth/notification or Windows action evidence.
use crate::*;
use android_controller::{
    LocalAttestationChallenge, LocalKeyHandle, LocalKeySetDescriptor, PeerAssociationDescriptor,
    PeerAssociationMutation, PeerAssociationRef,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DecisionPublicKey, DecisionPurpose, DeviceId, ExpiryTick, OsSession,
    PcIdentity, RequestBinding, RequestContent, RequestId, SignedDecision,
};
use framed_transport::{
    ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable, SocketDriver,
    SocketEvent, SocketLimits,
};
use notification_policy::{AlertMode, NotificationPolicy, Schedule};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{
    ClockProbeRequest, PcEvent, RequestResolution, ServiceTick, UnsignedPcEvent, encode_frame,
};
use std::{
    sync::{Weak, atomic::AtomicUsize, mpsc as sync_mpsc},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const LIMIT: Duration = Duration::from_secs(10);
const APP_PC_KEY: u8 = 20;
const TRANSPORT_PC_KEY: u8 = 21;
const TRANSPORT_PHONE_KEY: u8 = 5;
fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn public(seed: u8) -> TlsPublicKey {
    let point =
        PublicKey::from_sec1_bytes(key(seed).verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([7; 32]).unwrap()
}
fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}
fn frame(event: PcEvent, seed: u8) -> Vec<u8> {
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key(seed).sign(&unsigned.signing_bytes());
    encode_frame(
        &unsigned
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap()
            .to_wire(),
    )
    .unwrap()
}
fn opened(id: u8) -> (PcEvent, RequestBinding) {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic intake application",
            "C:\\Synthetic\\intake.exe",
            "synthetic review details, not native prompt evidence",
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
        ExpiryTick::from_nanos_since_epoch(60_000_000_000).unwrap(),
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

enum Notice {
    Progress,
    Projection(Arc<NativePendingRequest>, NativeRequestPresentation),
    Withdraw,
    Clear,
}
struct Platform {
    origin: Instant,
    offset: AtomicU64,
    time_epoch: AtomicU64,
    binding: Mutex<Option<Arc<NativeTransportBinding>>>,
    controller: Mutex<Weak<MobileController>>,
    notice: sync_mpsc::SyncSender<Notice>,
    sign_calls: AtomicUsize,
    releases: AtomicUsize,
    published: AtomicUsize,
    fail_publish: AtomicBool,
    path: String,
    panic_presentation: AtomicBool,
    fail_clear: AtomicBool,
    clear_calls: AtomicUsize,
    refresh_presentation: AtomicBool,
}
impl Platform {
    fn nanos(&self) -> u64 {
        100_000_000
            + u64::try_from(self.origin.elapsed().as_nanos()).unwrap()
            + self.offset.load(Ordering::Acquire)
    }
    fn sample(&self) -> NativeClock {
        NativeClock {
            boot_count: 5,
            monotonic_nanos: self.nanos(),
            weekday: 0,
            minute: 600,
        }
    }
    fn callback(&self) {
        if let Some(controller) = self.controller.lock().unwrap().upgrade() {
            assert_eq!(
                controller.notification_policy_json(),
                Err(BridgeError::Busy),
                "native callback never reenters owner"
            );
        }
    }
    fn notify(&self, notice: Notice) {
        self.notice
            .try_send(notice)
            .unwrap_or_else(|_| panic!("bounded fixture notice capacity"));
    }
    fn observed(&self) -> NativePresentationClock {
        crate::native_clock::native_callback(|| self.presentation_clock()).unwrap()
    }
}
impl NativePlatform for Platform {
    fn create_local_key_set(
        &self,
        _request: std::sync::Arc<crate::NativeKeyCreationRequest>,
    ) -> Result<crate::NativeCreatedKeyEvidence, BridgeError> {
        Err(BridgeError::LifecycleIntegrationRequired)
    }

    fn presentation_clock(&self) -> Result<NativePresentationClock, BridgeError> {
        assert!(
            !self.panic_presentation.swap(false, Ordering::AcqRel),
            "synthetic outside-admission native clock panic"
        );
        if self.refresh_presentation.load(Ordering::Acquire) {
            return Err(BridgeError::PresentationRefreshRequired);
        }
        self.callback();
        let clock = self.sample();
        let wall = 1_700_000_000_000 + clock.monotonic_nanos / 1_000_000;
        Ok(NativePresentationClock {
            boot_count: 5,
            elapsed_before_nanos: clock.monotonic_nanos,
            elapsed_after_nanos: clock.monotonic_nanos,
            wall_before_millis: wall,
            wall_after_millis: wall,
            weekday: 0,
            minute: 600,
            millis_within_minute: (clock.monotonic_nanos / 1_000_000 % 60_000) as u16,
            time_epoch: self.time_epoch.load(Ordering::Acquire),
        })
    }
    fn publish_pending_request(
        &self,
        request: Arc<NativePendingRequest>,
        intent: NativeRequestPresentation,
        _: NativeRequestAlert,
    ) -> Result<NativeRequestSinkOutcome, BridgeError> {
        self.callback();
        self.published.fetch_add(1, Ordering::SeqCst);
        if self.fail_publish.load(Ordering::Acquire) {
            return Err(BridgeError::NativeUnavailable);
        }
        self.notify(Notice::Projection(request, intent));
        Ok(NativeRequestSinkOutcome::RetainedAndPostRequested)
    }
    fn intake_progress(&self) -> Result<(), BridgeError> {
        self.callback();
        self.notify(Notice::Progress);
        Ok(())
    }
    fn prepare_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError> {
        self.callback();
        assert_eq!(
            binding.local_keys()?.transport_spki,
            public(TRANSPORT_PHONE_KEY).as_spki_der()
        );
        *self.binding.lock().unwrap() = Some(binding);
        Ok(())
    }
    fn sign_client_certificate_verify(
        &self,
        input: Arc<NativeCertificateVerify>,
    ) -> Result<Vec<u8>, BridgeError> {
        self.callback();
        let binding = self.binding.lock().unwrap().as_ref().unwrap().clone();
        assert!(input.belongs_to(binding));
        let bytes = input.take_bytes()?;
        assert!(matches!(bytes.len(), 130 | 146));
        assert!(input.take_bytes().is_err());
        let signature: Signature = key(TRANSPORT_PHONE_KEY).sign(&bytes);
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        Ok(signature.to_der().as_bytes().to_vec())
    }
    fn release_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError> {
        self.callback();
        assert!(binding.is_closed());
        self.binding.lock().unwrap().take();
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn state_directory(&self) -> Result<String, BridgeError> {
        Ok(self.path.clone())
    }
    fn clock(&self) -> Result<NativeClock, BridgeError> {
        self.callback();
        Ok(self.sample())
    }
    fn unix_millis(&self) -> Result<u64, BridgeError> {
        self.callback();
        Ok(1_700_000_000_000)
    }
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
        Ok(None)
    }
    fn has_device_keys(&self) -> Result<bool, BridgeError> {
        Ok(true)
    }
    fn reopen_local_key_sets(&self, keys: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].transport_spki,
            public(TRANSPORT_PHONE_KEY).as_spki_der()
        );
        Ok(())
    }
    fn release_local_key_references(&self) -> Result<(), BridgeError> {
        self.callback();
        assert!(self.binding.lock().unwrap().is_none());
        Ok(())
    }
    fn clear_request_notifications(&self) -> Result<(), BridgeError> {
        self.callback();
        self.clear_calls.fetch_add(1, Ordering::SeqCst);
        self.notify(Notice::Clear);
        if self.fail_clear.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            Ok(())
        }
    }
    fn withdraw_requests(&self, _: Vec<NativeRequestSelection>) -> Result<(), BridgeError> {
        self.callback();
        self.notify(Notice::Withdraw);
        Ok(())
    }
    fn advance_approval_drain_for_denial(
        &self,
        _: Arc<NativeDenialScope>,
    ) -> Result<NativeApprovalDrainState, BridgeError> {
        self.callback();
        Ok(NativeApprovalDrainState::NoMatchingSession)
    }
    fn observe_denial_operation(
        &self,
        _: Arc<NativeDenialAttempt>,
    ) -> Result<NativeDenialOperationState, BridgeError> {
        self.callback();
        Ok(NativeDenialOperationState::Quiescent)
    }
    fn release_denial_scope(&self, _: Arc<NativeDenialScope>) -> Result<(), BridgeError> {
        self.callback();
        Ok(())
    }
}
struct PcSigner;
impl PlatformTlsSigner for PcSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(public(TRANSPORT_PC_KEY))
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let signature: Signature = key(TRANSPORT_PC_KEY).sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}
struct PcClock;
impl SocketClock for PcClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}
enum PcNotice {
    ClockDrained,
    EventDrained,
    Decision(Vec<u8>),
    Closed,
}
struct PcPeer {
    commands: mpsc::Sender<(PcEvent, u8)>,
    notices: sync_mpsc::Receiver<PcNotice>,
    stop: CancellationToken,
    service_tick: Arc<AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl PcPeer {
    fn start(socket: std::net::TcpStream) -> Self {
        let (commands, mut receiver) = mpsc::channel(4);
        let (notice, notices) = sync_mpsc::sync_channel(32);
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let service_tick = Arc::new(AtomicU64::new(0));
        let sampled = Arc::clone(&service_tick);
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                socket.set_nonblocking(true).unwrap();
                let socket = tokio::net::TcpStream::from_std(socket).unwrap();
                let transport = PeerTransport::server(Arc::new(ConnectionBudget::new(1).unwrap()),
                    TlsIdentity::from_trusted_host(EndpointRole::Server, Arc::new(PcSigner)).unwrap(), public(TRANSPORT_PHONE_KEY), Instant::now()).unwrap();
                let mut driver = SocketDriver::new(socket, transport, Arc::new(PcClock), SocketLimits::default(), stopped.clone()).unwrap();
                let mut clock_write = false;
                loop {
                    tokio::select! {
                        biased;
                        _ = stopped.cancelled() => break,
                        command = receiver.recv() => {
                            let Some((event, seed)) = command else { break; };
                            driver.queue_frame(frame(event, seed)).unwrap();
                        }
                        event = driver.next_event() => match event {
                            Ok(SocketEvent::Ready) => (),
                            Ok(SocketEvent::Frame(bytes)) => {
                                let bytes = bytes.into_bytes();
                                if let Ok(probe) = ClockProbeRequest::from_wire(&bytes) {
                                    driver.queue_frame(frame(PcEvent::Clock { pc: pc(), epoch: epoch(), probe: probe.nonce(), sampled_at: ServiceTick::from_nanos_since_epoch(sampled.load(Ordering::Acquire)) }, APP_PC_KEY)).unwrap();
                                    clock_write = true;
                                } else { notice.try_send(PcNotice::Decision(bytes)).unwrap_or_else(|_| panic!("bounded PC notice")); }
                            }
                            Ok(SocketEvent::OutboundDrained) => {
                                notice.try_send(if clock_write { PcNotice::ClockDrained } else { PcNotice::EventDrained }).unwrap_or_else(|_| panic!("bounded PC notice")); clock_write = false;
                            }
                            _ => { let _ = notice.try_send(PcNotice::Closed); break; }
                        }
                    }
                }
            });
        });
        Self {
            commands,
            notices,
            stop,
            service_tick,
            thread: Some(thread),
        }
    }
    fn send(&self, event: PcEvent) {
        self.commands
            .try_send((event, APP_PC_KEY))
            .unwrap_or_else(|_| panic!("bounded PC command"));
    }
    fn wait(&self, want_decision: bool) -> Option<SignedDecision> {
        let end = Instant::now() + LIMIT;
        for _ in 0..32 {
            let event = self
                .notices
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .expect("bounded PC progress");
            match event {
                PcNotice::ClockDrained if !want_decision => return None,
                PcNotice::Decision(wire) if want_decision => {
                    return Some(SignedDecision::from_wire(&wire).unwrap());
                }
                PcNotice::Closed => panic!("peer closed before expected synthetic exchange"),
                _ => (),
            }
        }
        panic!("bounded PC progress count")
    }
}
impl Drop for PcPeer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn carriers() -> (std::net::TcpStream, std::net::TcpStream) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(LIMIT, async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, accepted) = tokio::join!(
                tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            (
                client.unwrap().into_std().unwrap(),
                accepted.unwrap().0.into_std().unwrap(),
            )
        })
        .await
        .unwrap()
    })
}
struct Fixture {
    controller: Arc<MobileController>,
    platform: Arc<Platform>,
    notices: sync_mpsc::Receiver<Notice>,
    reference: PeerAssociationRef,
    _temp: tempfile::TempDir,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let (notice, notices) = sync_mpsc::sync_channel(128);
    let platform = Arc::new(Platform {
        origin: Instant::now(),
        offset: AtomicU64::new(0),
        time_epoch: AtomicU64::new(1),
        binding: Mutex::new(None),
        controller: Mutex::new(Weak::new()),
        notice,
        sign_calls: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        published: AtomicUsize::new(0),
        fail_publish: AtomicBool::new(false),
        path: temp.path().to_str().unwrap().into(),
        panic_presentation: AtomicBool::new(false),
        fail_clear: AtomicBool::new(false),
        clear_calls: AtomicUsize::new(0),
        refresh_presentation: AtomicBool::new(false),
    });
    let (boot, clock) = map_clock(platform.sample()).unwrap();
    let (mut owner, initial) = DurableInbox::create_fresh_host_model(
        NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot,
        clock,
    )
    .unwrap();
    let handle = LocalKeyHandle::from_bytes([1; 32]).unwrap();
    let challenge = LocalAttestationChallenge::from_bytes([65; 32]).unwrap();
    let _ = owner.begin_local_key_creation(handle, challenge).unwrap();
    let _ = owner
        .record_local_key_creation(
            LocalKeySetDescriptor::new(
                handle,
                challenge,
                public(3),
                public(4),
                public(TRANSPORT_PHONE_KEY),
            )
            .unwrap(),
        )
        .unwrap();
    let (_, association) = owner
        .record_peer_association_from_trusted_host(
            PeerAssociationDescriptor::new(
                pc(),
                DeviceId::from_bytes([9; 16]).unwrap(),
                7,
                handle,
                public(APP_PC_KEY),
                public(TRANSPORT_PC_KEY),
            )
            .unwrap(),
        )
        .unwrap();
    let reference = match association {
        PeerAssociationMutation::Recorded(reference) => reference,
        _ => panic!("new synthetic association"),
    };
    let controller = Arc::new(MobileController {
        platform: platform.clone(),
        boot,
        approval_owner: Mutex::new(Some(
            android_controller::ApprovalPlanOwner::new(&owner, boot).unwrap(),
        )),
        approval_native_plan: Mutex::new(None),
        denial_state: Mutex::new(crate::denial::DenialState::new(&owner, boot).unwrap()),
        projections: Mutex::new(crate::request_projection::ProjectionRegistry::default()),
        intake: Arc::new(crate::intake::IntakeOwner::default()),
        state: Mutex::new(Some(owner)),
        creation_slot: Mutex::new(std::sync::Weak::new()),
        approval_alive: Arc::new(AtomicBool::new(true)),
        active: AtomicBool::new(false),
        cleanup_pending: AtomicBool::new(false),
        notification_cleanup_failed: AtomicBool::new(false),
        key_cleanup_pending: AtomicBool::new(true),
        key_cleanup_failed: AtomicBool::new(false),
        native_floor_nanos: AtomicU64::new(clock.phone_monotonic_nanos()),
        _owner_lease: Arc::new(OwnerLease::acquire().unwrap()),
    });
    *platform.controller.lock().unwrap() = Arc::downgrade(&controller);
    {
        let _admission = controller.enter().unwrap();
        controller.initialize_effects(initial).unwrap();
        controller.start_intake_reactor().unwrap();
    }
    Fixture {
        controller,
        platform,
        notices,
        reference,
        _temp: temp,
    }
}
impl Fixture {
    fn connect(&self) -> PcPeer {
        let (client, server) = carriers();
        let peer = PcPeer::start(server);
        let _ = self
            .controller
            .attach_provisioned_stream(self.reference, client)
            .unwrap();
        peer.wait(false);
        let _ = self.accepted_correlation_after(None);
        peer
    }
    fn accepted_correlation_after(&self, previous: Option<u64>) -> u64 {
        let end = Instant::now() + LIMIT;
        for _ in 0..128 {
            if let Some(received) = self
                .controller
                .intake
                .accepted_correlation_for_tests(self.reference)
                && previous.is_none_or(|old| received > old)
            {
                return received;
            }
            // Actual native progress wakes the fixture; neither PC-local drain
            // nor a count of unrelated notifications proves phone acceptance.
            let _ = self
                .notices
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .expect("bounded actual accepted correlation");
        }
        panic!("bounded accepted-correlation notice count")
    }
    fn projection(&self) -> Arc<NativePendingRequest> {
        let end = Instant::now() + LIMIT;
        let mut projection = None;
        for _ in 0..128 {
            match self
                .notices
                .recv_timeout(end.saturating_duration_since(Instant::now()))
                .expect("bounded native projection")
            {
                Notice::Projection(value, intent) => {
                    assert_eq!(intent, NativeRequestPresentation::Fresh);
                    projection = Some(value);
                }
                Notice::Progress if projection.is_some() => return projection.unwrap(),
                _ => (),
            }
        }
        panic!("bounded projection notice count")
    }
    fn cleanup(&self) {
        self.controller.stop_intake();
        let end = Instant::now() + LIMIT;
        for _ in 0..128 {
            match self.controller.continue_native_cleanup() {
                Ok(()) => {
                    self.controller.intake.join_completed_for_tests();
                    return;
                }
                Err(BridgeError::Busy | BridgeError::NativeUnavailable) => {
                    let _ = self
                        .notices
                        .recv_timeout(end.saturating_duration_since(Instant::now()))
                        .expect("bounded actual cleanup progress");
                }
                Err(error) => panic!("unexpected cleanup {error:?}"),
            }
        }
        panic!("bounded cleanup notification count")
    }
}

#[test]
fn owned_carrier_signed_open_projection_approval_and_pc_terminal_history_use_one_owner() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let peer = fixture.connect();
    let (event, binding) = opened(1);
    peer.send(event);
    let view = fixture.projection();
    let selection = fixture
        .controller
        .check_pending_request(view.clone())
        .unwrap();
    let preview = view.preview(fixture.platform.observed()).unwrap();
    assert!(preview.has_details);
    assert_eq!(preview.pc_identity_hint, "070707070707");
    let plan = fixture.controller.begin_approval(selection).unwrap();
    let attempt = fixture.controller.claim_approval(plan.clone()).unwrap();
    let signature: Signature = key(3).sign(&attempt.signing_bytes().unwrap());
    let submission = fixture
        .controller
        .finish_approval(attempt, signature.to_der().as_bytes().to_vec())
        .unwrap();
    fixture.controller.retire_approval(plan).unwrap();
    let _ = fixture
        .controller
        .request_approval_delivery(submission.clone())
        .unwrap();
    let received = peer.wait(true).unwrap();
    assert_eq!(received.statement().binding(), binding);
    assert_eq!(received.statement().purpose(), DecisionPurpose::Approve);
    received
        .verify(
            &DecisionPublicKey::from_sec1_bytes(
                key(3).verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .history()
            .unwrap()
            .is_empty()
    );
    peer.send(PcEvent::Resolved {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        outcome: RequestResolution::Denied,
    });
    let end = Instant::now() + LIMIT;
    for _ in 0..64 {
        let notice = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .unwrap();
        if matches!(notice, Notice::Progress) && view.is_revoked() {
            break;
        }
    }
    assert!(view.is_revoked());
    assert_eq!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .history()
            .unwrap()
            .len(),
        1
    );
    assert!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending_outcomes()
            .unwrap()
            .is_empty()
    );
    fixture.cleanup();
    drop(peer);
}

#[test]
fn denial_reaches_same_peer_and_keeps_fence_until_committed_terminal_evidence() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let peer = fixture.connect();
    let (event, binding) = opened(2);
    peer.send(event);
    let view = fixture.projection();
    let scope = fixture.controller.reserve_denial(view.selection()).unwrap();
    let attempt = match fixture.controller.advance_denial(scope.clone()).unwrap() {
        NativeDenialAdvance::Ready { attempt } => attempt,
        other => panic!("ready {other:?}"),
    };
    let signature: Signature = key(4).sign(&attempt.take_signing_bytes().unwrap());
    assert!(matches!(
        fixture
            .controller
            .finish_denial(attempt, signature.to_der().as_bytes().to_vec())
            .unwrap(),
        NativeDenialAdvance::Prepared
    ));
    assert!(matches!(
        fixture
            .controller
            .retire_denial_native(scope.clone())
            .unwrap(),
        NativeDenialAdvance::Prepared
    ));
    let _ = fixture.controller.advance_denial(scope.clone()).unwrap();
    let received = peer.wait(true).unwrap();
    assert_eq!(received.statement().purpose(), DecisionPurpose::Deny);
    received
        .verify(
            &DecisionPublicKey::from_sec1_bytes(
                key(4).verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(matches!(
        fixture.controller.settle_denial(scope.clone()).unwrap(),
        NativeDenialAdvance::AwaitingOutcome
    ));
    assert!(fixture.controller.begin_approval(view.selection()).is_err());
    peer.send(PcEvent::Resolved {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        outcome: RequestResolution::Denied,
    });
    let end = Instant::now() + LIMIT;
    for _ in 0..64 {
        let notice = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .unwrap();
        if matches!(notice, Notice::Progress) && view.is_revoked() {
            break;
        }
    }
    assert!(matches!(
        fixture.controller.settle_denial(scope).unwrap(),
        NativeDenialAdvance::Released
    ));
    fixture.cleanup();
    drop(peer);
}

#[test]
fn no_peers_is_truthfully_unprovisioned_transport_and_policy_withdraw_clears_body() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let status = fixture.controller.request_catalog_status().unwrap();
    assert_eq!(status.attached_peers, 0);
    assert_eq!(status.connected_peers, 0);
    assert_eq!(status.configured_peers, 1); // Synthetic persisted metadata, not a live connection.
    let peer = fixture.connect();
    peer.send(opened(3).0);
    let view = fixture.projection();
    let policy = serde_json::to_string(&NotificationPolicy::new(
        Some(Schedule::Never),
        AlertMode::Silent,
    ))
    .unwrap();
    fixture.controller.save_notification_policy(policy).unwrap();
    assert!(view.is_revoked());
    assert!(view.details(fixture.platform.observed()).is_err());
    assert!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .history()
            .unwrap()
            .is_empty()
    );
    fixture.cleanup();
    drop(peer);
}

#[test]
fn callback_panic_outside_admission_closes_live_owner_before_any_later_cleanup_join() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let peer = fixture.connect();
    peer.send(opened(4).0);
    let view = fixture.projection();
    fixture
        .platform
        .panic_presentation
        .store(true, Ordering::Release);
    let end = Instant::now() + LIMIT;
    for _ in 0..64 {
        let _ = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .expect("bounded abnormal exit notification");
        if !fixture.controller.approval_alive.load(Ordering::Acquire) {
            break;
        }
    }
    assert!(!fixture.controller.approval_alive.load(Ordering::Acquire));
    assert!(view.is_revoked());
    assert!(fixture.controller.cleanup_pending.load(Ordering::Acquire));
    assert!(fixture.controller.request_catalog_status().is_err());
    fixture.cleanup();
    drop(peer);
}

#[test]
fn continuously_ready_wakes_do_not_starve_original_maintenance_deadline() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let peer = fixture.connect();
    peer.send(opened(5).0);
    let view = fixture.projection();
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&stop);
    let intake = Arc::clone(&fixture.controller.intake);
    let flood = std::thread::spawn(move || {
        let end = Instant::now() + LIMIT;
        while !done.load(Ordering::Acquire) && Instant::now() < end {
            intake.wake();
            std::thread::yield_now();
        }
    });
    fixture
        .platform
        .offset
        .store(70_000_000_000, Ordering::Release);
    let end = Instant::now() + LIMIT;
    let mut withdrawn = false;
    for _ in 0..128 {
        let notice = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .expect("deadline despite continuously ready notification");
        if matches!(notice, Notice::Withdraw) {
            withdrawn = true;
        }
        if withdrawn && matches!(notice, Notice::Progress) {
            break;
        }
    }
    stop.store(true, Ordering::Release);
    flood.join().unwrap();
    assert!(withdrawn);
    assert!(view.is_revoked());
    assert_eq!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .counts()
            .unwrap()
            .active(),
        0
    );
    fixture.cleanup();
    drop(peer);
}

fn opened_at(id: u8, issued: u64, expiry: u64) -> (PcEvent, RequestBinding) {
    let (event, old) = opened(id);
    let PcEvent::Opened { content, .. } = event else {
        unreachable!()
    };
    let binding = RequestBinding::new(
        old.pc(),
        old.epoch(),
        old.session(),
        old.request_id(),
        old.nonce(),
        old.content_digest(),
        ExpiryTick::from_nanos_since_epoch(expiry).unwrap(),
    );
    (
        PcEvent::Opened {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(issued),
            content,
        },
        binding,
    )
}
#[test]
fn periodic_authenticated_probe_admits_later_requests_without_retiming_existing_request() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let peer = fixture.connect();
    let initial_correlation = fixture.accepted_correlation_after(None);
    fixture
        .platform
        .offset
        .store(230_000_000_000, Ordering::Release);
    let (event, _) = opened_at(6, 230_000_000_000, 350_000_000_000);
    peer.send(event);
    let original = fixture.projection();
    let original_deadline = original.deadline_nanos();
    peer.service_tick.store(241_000_000_000, Ordering::Release);
    fixture
        .platform
        .offset
        .store(241_000_000_000, Ordering::Release);
    peer.wait(false); // Actual automatic renewal request/reply, not injected correlation.
    // Observe the exact newly accepted stamp before the next native-time jump.
    let renewed_correlation = fixture.accepted_correlation_after(Some(initial_correlation));
    assert!(renewed_correlation > initial_correlation);
    // Past the OLD five-minute validity; the new correlation must be real.
    fixture
        .platform
        .offset
        .store(301_000_000_000, Ordering::Release);
    let (event, _) = opened_at(7, 301_000_000_000, 361_000_000_000);
    peer.send(event);
    let later = fixture.projection();
    assert!(!later.same_handle(original.clone()));
    assert_eq!(original.deadline_nanos(), original_deadline);
    assert!(fixture.controller.check_pending_request(original).is_ok());
    assert_eq!(
        fixture
            .controller
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .counts()
            .unwrap()
            .active(),
        2
    );
    fixture.cleanup();
    drop(peer);
}

#[cfg(target_os = "linux")]
#[test]
fn full_native_constructor_initial_clear_failure_is_not_automatically_retried() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    fixture.cleanup();
    let Fixture {
        controller,
        platform,
        notices: _,
        reference: _,
        _temp,
    } = fixture;
    drop(controller);
    let before = platform.clear_calls.load(Ordering::SeqCst);
    platform.fail_clear.store(true, Ordering::Release);
    assert!(matches!(
        MobileController::open_existing(platform.clone()),
        Err(BridgeError::NativeUnavailable)
    ));
    assert_eq!(platform.clear_calls.load(Ordering::SeqCst), before + 1);
    assert!(platform.controller.lock().unwrap().upgrade().is_none());
    drop(_temp);
}

#[test]
fn known_light_clock_invalidation_with_busy_worker_does_not_kill_empty_reactor() {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let admission = fixture.controller.enter().unwrap();
    fixture
        .platform
        .refresh_presentation
        .store(true, Ordering::Release);
    let end = Instant::now() + LIMIT;
    for _ in 0..64 {
        let _ = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .expect("known refresh notice");
        if fixture.controller.intake.awaiting_temporal_refresh() {
            break;
        }
    }
    assert!(fixture.controller.intake.awaiting_temporal_refresh());
    assert!(fixture.controller.approval_alive.load(Ordering::Acquire));
    fixture.platform.time_epoch.store(2, Ordering::Release);
    fixture
        .platform
        .refresh_presentation
        .store(false, Ordering::Release);
    drop(admission);
    for _ in 0..64 {
        let _ = fixture
            .notices
            .recv_timeout(end.saturating_duration_since(Instant::now()))
            .expect("actual rewarm progress");
        if !fixture.controller.intake.awaiting_temporal_refresh() {
            break;
        }
    }
    assert!(fixture.controller.approval_alive.load(Ordering::Acquire));
    assert!(!fixture.controller.intake.awaiting_temporal_refresh());
    let peer = fixture.connect();
    peer.send(opened(8).0);
    assert!(!fixture.projection().is_revoked());
    fixture.cleanup();
    drop(peer);
}

#[test]
fn parked_verified_message_after_original_socket_deadline_cannot_commit_or_show() {
    struct ShortClock {
        origin: Instant,
        offset: AtomicU64,
    }
    impl SocketClock for ShortClock {
        fn now(&self) -> Result<Instant, SocketClockUnavailable> {
            self.origin
                .checked_add(
                    self.origin.elapsed()
                        + Duration::from_nanos(self.offset.load(Ordering::Acquire)),
                )
                .ok_or(SocketClockUnavailable)
        }
    }
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = fixture();
    let (client, server) = carriers();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(LIMIT, async {
            client.set_nonblocking(true).unwrap();
            server.set_nonblocking(true).unwrap();
            let client = tokio::net::TcpStream::from_std(client).unwrap();
            let server = tokio::net::TcpStream::from_std(server).unwrap();
            let clock = Arc::new(ShortClock {
                origin: Instant::now(),
                offset: AtomicU64::new(0),
            });
            let budget = Arc::new(ConnectionBudget::new(2).unwrap());
            let limits =
                SocketLimits::new(Duration::from_secs(10), Duration::from_secs(10)).unwrap();
            let identity = {
                let _admission = fixture.controller.enter().unwrap();
                fixture
                    .controller
                    .with_inbox(|owner| {
                        native_client_transport_identity(
                            owner,
                            fixture.reference,
                            fixture.platform.clone(),
                        )
                    })
                    .unwrap()
            };
            let mut phone = {
                let _admission = fixture.controller.enter().unwrap();
                fixture
                    .controller
                    .with_inbox(|owner| {
                        android_controller::AssociatedPcSocket::new(
                            owner,
                            fixture.reference,
                            android_controller::PcSocketInputs {
                                socket: client,
                                identity,
                                budget: budget.clone(),
                                clock: clock.clone(),
                                limits,
                                stop: CancellationToken::new(),
                            },
                        )
                        .map_err(|_| BridgeError::NativeUnavailable)
                    })
                    .unwrap()
            };
            let transport = PeerTransport::server(
                budget.clone(),
                TlsIdentity::from_trusted_host(EndpointRole::Server, Arc::new(PcSigner)).unwrap(),
                public(TRANSPORT_PHONE_KEY),
                clock.now().unwrap(),
            )
            .unwrap();
            let mut pc_socket = SocketDriver::new(
                server,
                transport,
                clock.clone(),
                limits,
                CancellationToken::new(),
            )
            .unwrap();
            let phone_clock = async {
                let mut drained = false;
                let mut message = None;
                for _ in 0..4 {
                    match phone.next_event().await.unwrap() {
                        android_controller::PcSocketEvent::Ready => {
                            let _admission = fixture.controller.enter().unwrap();
                            let now = map_clock(fixture.platform.sample()).unwrap().1;
                            fixture
                                .controller
                                .with_inbox(|owner| {
                                    phone
                                        .queue_clock_probe(owner, now)
                                        .map_err(|_| BridgeError::NativeUnavailable)
                                })
                                .unwrap();
                        }
                        android_controller::PcSocketEvent::OutboundDrained => drained = true,
                        android_controller::PcSocketEvent::Message(value) => message = Some(*value),
                        other => panic!("initial clock {other:?}"),
                    }
                    if drained && let Some(message) = message.take() {
                        return message;
                    }
                }
                panic!("bounded initial clock flow")
            };
            let pc_clock = async {
                for _ in 0..4 {
                    match pc_socket.next_event().await.unwrap() {
                        SocketEvent::Ready => (),
                        SocketEvent::Frame(value) => {
                            let probe = ClockProbeRequest::from_wire(&value.into_bytes()).unwrap();
                            pc_socket
                                .queue_frame(frame(
                                    PcEvent::Clock {
                                        pc: pc(),
                                        epoch: epoch(),
                                        probe: probe.nonce(),
                                        sampled_at: ServiceTick::from_nanos_since_epoch(0),
                                    },
                                    APP_PC_KEY,
                                ))
                                .unwrap();
                        }
                        SocketEvent::OutboundDrained => return,
                        other => panic!("PC clock {other:?}"),
                    }
                }
                panic!("bounded PC clock flow")
            };
            let (message, ()) = tokio::join!(phone_clock, pc_clock);
            {
                let _admission = fixture.controller.enter().unwrap();
                let now = map_clock(fixture.platform.sample()).unwrap().1;
                let _ = fixture
                    .controller
                    .with_inbox(|owner| {
                        phone
                            .apply_event(owner, message, now)
                            .map_err(|_| BridgeError::NativeUnavailable)
                    })
                    .unwrap();
            }
            pc_socket
                .queue_frame(frame(opened(9).0, APP_PC_KEY))
                .unwrap();
            let (message, sent) = tokio::join!(phone.next_event(), pc_socket.next_event());
            assert!(matches!(sent.unwrap(), SocketEvent::OutboundDrained));
            let message = match message.unwrap() {
                android_controller::PcSocketEvent::Message(value) => *value,
                other => panic!("verified message {other:?}"),
            };
            // Delayed owner admission, with coherent advancement of both clocks.
            // The request's60s window still lives, but this socket's10s lifetime does not.
            clock.offset.store(11_000_000_000, Ordering::Release);
            fixture
                .platform
                .offset
                .store(11_000_000_000, Ordering::Release);
            {
                let _admission = fixture.controller.enter().unwrap();
                crate::intake::process_parked_message_for_test(
                    &fixture.controller,
                    phone,
                    message,
                    fixture.reference,
                )
                .unwrap();
            }
            assert_eq!(fixture.platform.published.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture
                    .controller
                    .state
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .counts()
                    .unwrap()
                    .active(),
                0
            );
            drop(pc_socket);
            assert_eq!(budget.active(), 0);
        })
        .await
        .unwrap();
    });
    fixture.cleanup();
}
