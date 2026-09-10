// SPDX-License-Identifier: GPL-2.0-or-later
//! One service-worker session. No listener/dialer, carrier IPC, enrollment API,
//! request-opening API or OS action. Native activation awaits a real carrier.
#![forbid(unsafe_code)]

use std::{
    fmt,
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use approval_core::{
    ApprovalEngine, DecisionError, DeviceKeys, MAX_PENDING_REQUESTS, PrivilegedDeviceRegistry,
    RegistryCheckpoint,
};
use approval_protocol::{BootEpoch, DeviceId, PcIdentity, SignedDecision};
use framed_transport::{
    CancellationToken, ConnectionBudget, OutboundFrameGuard, PeerTransport, ReceivedFrame,
    SocketClock, SocketClockUnavailable, SocketDriver, SocketEvent, SocketLimits,
};
use secure_channel::{EndpointRole, PlatformTlsSigner, TlsIdentity, TlsPublicKey};
use service_protocol::{
    CLOCK_REQUEST_BYTES, ClockProbeRequest, MAX_CLOCK_PROBE_RTT_NANOS, PcEvent, PcPublicKey,
    ServiceTick, SignedPcEvent, UnsignedPcEvent, encode_frame,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc as async_mpsc;

use crate::tls_signer::{
    ServiceTlsSigner, ServiceTlsSigningWorker, TlsSigningBridgeError, TlsSigningProgress,
};

const MAX_PEERS: usize = framed_transport::MAX_CONNECTIONS;
const POLL: Duration = Duration::from_millis(25);
const EVENT_LIFETIME: Duration = Duration::from_nanos(MAX_CLOCK_PROBE_RTT_NANOS);
const IDENTITY_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pc-identity/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeerRuntimeError {
    #[error("the service session is closed")]
    Closed,
    #[error("the service registry is unavailable or differs from the live engine")]
    Registry,
    #[error("the original enrolled peer tuple is no longer current")]
    PeerChanged,
    #[error("the service key is unavailable or changed")]
    Identity,
    #[error("native service time is unavailable, regressed or out of range")]
    Clock,
    #[error("the bounded peer capacity is occupied")]
    Capacity,
    #[error("the peer input or response is invalid or expired")]
    Protocol,
    #[error("the service peer I/O owner failed")]
    Io,
    #[error("the service owner unwound")]
    Unwind,
    #[error("actual I/O owners still need cleanup")]
    CleanupPending,
    #[error("service TLS signing failed")]
    Signing(TlsSigningBridgeError),
}

/// These are in-process observations, never Windows or remote delivery results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionProgress {
    Idle,
    TlsSigning(TlsSigningProgress),
    PeerReady,
    PeerRetired,
    PeerRejected,
    ClockQueued,
    ClockDrained,
    DecisionRejected(DecisionError),
    AuthorizedButNotApplied(NotAppliedReason),
    Expired(usize),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotAppliedReason {
    PlatformUnavailable,
    ExpiredAfterVerification,
    PeerChangedAfterVerification,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCleanup {
    CleanupPending { owners: usize },
    Quiescent { io_failed: bool },
}

/// No public constructor. A future reviewed native carrier source may construct
/// this only INSIDE the service crate. DeviceId selects a candidate TLS pin; it
/// is NOT a verified-peer assertion. No byte/IPC/handle import exists here.
pub struct ServicePeerCarrier {
    stream: TcpStream,
    device: DeviceId,
}
impl fmt::Debug for ServicePeerCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServicePeerCarrier([redacted], unauthenticated)")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PeerBinding {
    device: DeviceId,
    revision: u64,
    keys: DeviceKeys,
    transport: TlsPublicKey,
}
struct PeerState {
    owner: Arc<()>,
    epoch: BootEpoch,
    binding: PeerBinding,
    active: AtomicBool,
    stop: CancellationToken,
    #[cfg(test)]
    hold_response: AtomicBool,
    #[cfg(test)]
    hold_exit: AtomicBool,
}
impl PeerState {
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.stop.cancel();
    }
    fn live(&self) -> bool {
        self.active.load(Ordering::Acquire) && !self.stop.is_cancelled()
    }
}
impl OutboundFrameGuard for PeerState {
    fn is_revoked(&self) -> bool {
        !self.live()
    }
}

// Neither raw bytes nor a caller flag can construct this private provenance.
// Only EnrolledPeerSocket's actual Ready -> Frame path below constructs it.
struct PeerFrame {
    source: Arc<PeerState>,
    frame: ReceivedFrame,
    received: Instant,
}
enum PeerEvent {
    Ready,
    Frame(PeerFrame),
    Drained(u64),
}
struct Response {
    source: Arc<PeerState>,
    id: u64,
    bytes: Vec<u8>,
    deadline: Instant,
}
struct PeerSlot {
    state: Arc<PeerState>,
    events: async_mpsc::Receiver<PeerEvent>,
    responses: async_mpsc::Sender<Response>,
    thread: Option<JoinHandle<Result<(), PeerRuntimeError>>>,
    ready: bool,
    response: Option<(u64, Instant)>,
}

enum RegistryOwner<'key> {
    #[cfg(windows)]
    Native(crate::ServiceRegistry<'key>),
    #[cfg(test)]
    Fixture(
        std::rc::Rc<std::cell::RefCell<tests::RegistryFixture>>,
        std::marker::PhantomData<&'key ()>,
    ),
}
impl RegistryOwner<'_> {
    fn checkpoint(&mut self) -> Result<RegistryCheckpoint, PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(owner) => owner
                .checkpoint_for_engine()
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => Ok(owner.borrow().checkpoint.clone()),
        }
    }
    fn transport(&mut self, device: DeviceId) -> Result<Option<TlsPublicKey>, PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(owner) => owner
                .transport_key(device)
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => Ok(owner.borrow().transport.get(&device).cloned()),
        }
    }
    fn close(self) -> Result<(), PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(owner) => owner.close().map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(_, _) => Ok(()),
        }
    }
}

enum SessionKey<'key> {
    #[cfg(windows)]
    Native(&'key windows_identity::PcIdentityKey),
    #[cfg(test)]
    Fixture(&'key tests::Identity),
}
impl<'key> SessionKey<'key> {
    fn public(&self) -> Result<TlsPublicKey, PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                use p256::pkcs8::EncodePublicKey;
                let point = key.public_sec1().map_err(|_| PeerRuntimeError::Identity)?;
                let public = p256::PublicKey::from_sec1_bytes(point.as_sec1_bytes())
                    .map_err(|_| PeerRuntimeError::Identity)?;
                TlsPublicKey::from_spki_der(
                    public
                        .to_public_key_der()
                        .map_err(|_| PeerRuntimeError::Identity)?
                        .as_bytes(),
                )
                .map_err(|_| PeerRuntimeError::Identity)
            }
            #[cfg(test)]
            Self::Fixture(key) => Ok(key.public.clone()),
        }
    }
    fn bridge(
        &self,
    ) -> Result<(Arc<ServiceTlsSigner>, ServiceTlsSigningWorker<'key>), PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                ServiceTlsSigner::for_service_key(*key).map_err(PeerRuntimeError::Signing)
            }
            #[cfg(test)]
            Self::Fixture(key) => {
                ServiceTlsSigner::for_test_key(*key).map_err(PeerRuntimeError::Signing)
            }
        }
    }
    fn sign_clock(&self, message: UnsignedPcEvent) -> Result<SignedPcEvent, PeerRuntimeError> {
        // ONLY the coordinator's fixed Clock event reaches this method. No
        // network-supplied signing bytes/digest command exists in the dispatch.
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                let digest: [u8; 32] = Sha256::digest(message.signing_bytes()).into();
                let signature = key
                    .sign_digest_for_service(&digest)
                    .map_err(|_| PeerRuntimeError::Identity)?;
                message
                    .with_der_signature(signature.as_der_bytes())
                    .map_err(|_| PeerRuntimeError::Identity)
            }
            #[cfg(test)]
            Self::Fixture(key) => key.sign_clock(message),
        }
    }
}

struct ServiceClock;
impl SocketClock for ServiceClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}

/// Sole registry/engine/key-worker composition. Constructors and carrier
/// construction are sealed to native service code; no IPC or mutable state exit.
/// Caller MUST begin/poll/finish shutdown. The actual runtime catches errors and
/// unwind while retaining this owner. Dropping with live I/O is a fatal invariant
/// violation, not an implicit detached shutdown or successful timeout cleanup.
#[must_use = "retain the session until every actual I/O owner is joined"]
pub struct ServiceSession<'key> {
    registry: Option<RegistryOwner<'key>>,
    engine: ApprovalEngine,
    key: SessionKey<'key>,
    epoch_start: Instant,
    last_time: Instant,
    pc_key: TlsPublicKey,
    identity: Arc<()>,
    clock: Arc<dyn SocketClock>,
    signer: Arc<ServiceTlsSigner>,
    signing_worker: ServiceTlsSigningWorker<'key>,
    budget: Arc<ConnectionBudget>,
    peers: Vec<PeerSlot>,
    next_response: u64,
    cursor: usize,
    closing: bool,
    io_failed: bool,
}
impl fmt::Debug for ServiceSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceSession")
            .field("peers", &self.peers.len())
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}

impl<'key> ServiceSession<'key> {
    #[cfg(windows)]
    pub(crate) fn for_service(
        registry: crate::ServiceRegistry<'key>,
        key: &'key windows_identity::PcIdentityKey,
        epoch_start: Instant,
    ) -> Result<Self, PeerRuntimeError> {
        Self::new(
            RegistryOwner::Native(registry),
            SessionKey::Native(key),
            epoch_start,
            Arc::new(ServiceClock),
        )
    }
    fn new(
        mut registry: RegistryOwner<'key>,
        key: SessionKey<'key>,
        epoch_start: Instant,
        clock: Arc<dyn SocketClock>,
    ) -> Result<Self, PeerRuntimeError> {
        let pc_key = key.public()?;
        let mut hash = Sha256::new();
        hash.update(IDENTITY_DOMAIN);
        hash.update(pc_key.as_spki_der());
        let pc = PcIdentity::from_bytes(hash.finalize().into())
            .map_err(|_| PeerRuntimeError::Identity)?;
        let devices = PrivilegedDeviceRegistry::restore_for_privileged_host(registry.checkpoint()?)
            .map_err(|_| PeerRuntimeError::Registry)?;
        let engine = ApprovalEngine::initialize_for_privileged_host(
            pc,
            devices,
            MAX_PENDING_REQUESTS,
            epoch_start,
        )
        .map_err(|_| PeerRuntimeError::Registry)?;
        let (signer, signing_worker) = key.bridge()?;
        if signer
            .public_key()
            .map_err(|_| PeerRuntimeError::Identity)?
            != pc_key
        {
            return Err(PeerRuntimeError::Identity);
        }
        Ok(Self {
            registry: Some(registry),
            engine,
            key,
            epoch_start,
            last_time: epoch_start,
            pc_key,
            identity: Arc::new(()),
            clock,
            signer,
            signing_worker,
            budget: Arc::new(
                ConnectionBudget::new(MAX_PEERS).map_err(|_| PeerRuntimeError::Capacity)?,
            ),
            peers: Vec::new(),
            next_response: 1,
            cursor: 0,
            closing: false,
            io_failed: false,
        })
    }

    /// Only a sealed native carrier can reach this point. This is not a
    /// listener or a generic local request interface; no production source exists.
    pub fn attach_carrier(&mut self, carrier: ServicePeerCarrier) -> Result<(), PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        self.reap_finished();
        if self.peers.len() >= MAX_PEERS
            || self
                .peers
                .iter()
                .any(|peer| peer.state.binding.device == carrier.device)
        {
            return Err(PeerRuntimeError::Capacity);
        }
        let binding = self.binding(carrier.device)?;
        let state = Arc::new(PeerState {
            owner: Arc::clone(&self.identity),
            epoch: self.engine.boot_epoch(),
            binding,
            active: AtomicBool::new(true),
            stop: CancellationToken::new(),
            #[cfg(test)]
            hold_response: AtomicBool::new(false),
            #[cfg(test)]
            hold_exit: AtomicBool::new(false),
        });
        let (event_sender, events) = async_mpsc::channel(1);
        let (responses, response_receiver) = async_mpsc::channel(1);
        self.peers
            .try_reserve_exact(1)
            .map_err(|_| PeerRuntimeError::Capacity)?;
        let thread_state = Arc::clone(&state);
        let signer = Arc::clone(&self.signer);
        let clock = Arc::clone(&self.clock);
        let budget = Arc::clone(&self.budget);
        let thread = thread::Builder::new()
            .name("service-peer-io".into())
            .spawn(move || {
                let _retirement = RetireOnDrop(Arc::clone(&thread_state));
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| PeerRuntimeError::Io)?;
                #[cfg(test)]
                let exit_state = Arc::clone(&thread_state);
                let result = runtime.block_on(async move {
                    carrier
                        .stream
                        .set_nonblocking(true)
                        .map_err(|_| PeerRuntimeError::Io)?;
                    let socket = tokio::net::TcpStream::from_std(carrier.stream)
                        .map_err(|_| PeerRuntimeError::Io)?;
                    let identity = TlsIdentity::from_trusted_host(EndpointRole::Server, signer)
                        .map_err(|_| PeerRuntimeError::Identity)?;
                    let transport = PeerTransport::server(
                        budget,
                        identity,
                        thread_state.binding.transport.clone(),
                        clock.now().map_err(|_| PeerRuntimeError::Clock)?,
                    )
                    .map_err(|_| PeerRuntimeError::Io)?;
                    let driver = SocketDriver::new(
                        socket,
                        transport,
                        Arc::clone(&clock),
                        SocketLimits::default(),
                        thread_state.stop.clone(),
                    )
                    .map_err(|_| PeerRuntimeError::Io)?;
                    EnrolledPeerSocket {
                        driver,
                        state: thread_state,
                        clock,
                        events: event_sender,
                        responses: response_receiver,
                        ready: false,
                        response: None,
                    }
                    .run()
                    .await
                });
                #[cfg(test)]
                while exit_state.hold_exit.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                result
            })
            .map_err(|_| PeerRuntimeError::Io)?;
        self.peers.push(PeerSlot {
            state,
            events,
            responses,
            thread: Some(thread),
            ready: false,
            response: None,
        });
        Ok(())
    }

    /// Services at most one signing request and one peer event. Native key work
    /// can block; it is not preempted by the response/cleanup budgets.
    pub fn process_one(&mut self) -> Result<SessionProgress, PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.process_live()))
            .unwrap_or(Err(PeerRuntimeError::Unwind));
        if result.is_err() {
            self.begin_shutdown();
        }
        result
    }
    fn process_live(&mut self) -> Result<SessionProgress, PeerRuntimeError> {
        self.revalidate_peers()?;
        if self.reap_finished() != 0 {
            return Ok(SessionProgress::PeerRetired);
        }
        let signing = self
            .signing_worker
            .process_one()
            .map_err(PeerRuntimeError::Signing)?;
        self.revalidate_peers()?;
        let now = self.now()?;
        let expired = self
            .engine
            .expire_from_privileged_host(now)
            .map_err(|_| PeerRuntimeError::Clock)?;
        let count = self.peers.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            if let Ok(event) = self.peers[index].events.try_recv() {
                self.cursor = (index + 1) % count;
                return self.dispatch(index, event);
            }
        }
        if !expired.is_empty() {
            return Ok(SessionProgress::Expired(expired.len()));
        }
        Ok(if signing == TlsSigningProgress::Idle {
            SessionProgress::Idle
        } else {
            SessionProgress::TlsSigning(signing)
        })
    }
    fn dispatch(
        &mut self,
        index: usize,
        event: PeerEvent,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        let state = Arc::clone(&self.peers[index].state);
        if self.check_peer(&state).is_err() {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        match event {
            PeerEvent::Ready => {
                self.peers[index].ready = true;
                Ok(SessionProgress::PeerReady)
            }
            PeerEvent::Drained(id) => {
                let now = self.now()?;
                if self.peers[index]
                    .response
                    .take()
                    .is_none_or(|(expected, deadline)| expected != id || now >= deadline)
                {
                    state.retire();
                    return Ok(SessionProgress::PeerRejected);
                }
                self.check_peer(&state)?;
                Ok(SessionProgress::ClockDrained)
            }
            PeerEvent::Frame(frame) => {
                if !self.peers[index].ready || !Arc::ptr_eq(&state, &frame.source) {
                    state.retire();
                    return Ok(SessionProgress::PeerRejected);
                }
                let now = self.now()?;
                let Some(deadline) = frame.received.checked_add(EVENT_LIFETIME) else {
                    return Err(PeerRuntimeError::Clock);
                };
                if now < frame.received || now >= deadline {
                    state.retire();
                    return Ok(SessionProgress::PeerRejected);
                }
                let bytes = frame.frame.into_bytes();
                if bytes.len() == CLOCK_REQUEST_BYTES {
                    let request = match ClockProbeRequest::from_wire(&bytes) {
                        Ok(request) => request,
                        Err(_) => {
                            state.retire();
                            return Ok(SessionProgress::PeerRejected);
                        }
                    };
                    if request.pc() != self.engine.pc_identity()
                        || self.peers[index].response.is_some()
                    {
                        state.retire();
                        return Ok(SessionProgress::PeerRejected);
                    }
                    self.respond_clock(index, state, request, deadline)
                } else {
                    let decision = match SignedDecision::from_wire(&bytes) {
                        Ok(decision) => decision,
                        Err(_) => {
                            state.retire();
                            return Ok(SessionProgress::PeerRejected);
                        }
                    };
                    if decision.statement().device_id() != state.binding.device {
                        state.retire();
                        return Ok(SessionProgress::PeerRejected);
                    }
                    let now = self.now()?;
                    self.check_peer(&state)?;
                    match self.engine.submit_decision(&decision, now) {
                        Err(error) => {
                            state.retire();
                            Ok(SessionProgress::DecisionRejected(error))
                        }
                        Ok(authorized) => {
                            let current = self.check_peer(&state);
                            let after = self.now();
                            let reason = if current.is_err() {
                                NotAppliedReason::PeerChangedAfterVerification
                            } else if after.is_err()
                                || after.is_ok_and(|now| now >= authorized.deadline())
                            {
                                NotAppliedReason::ExpiredAfterVerification
                            } else {
                                NotAppliedReason::PlatformUnavailable
                            };
                            drop(authorized); // No OS target exists; never queue/serialize this token.
                            if current.is_err() || after.is_err() {
                                self.begin_shutdown();
                            }
                            Ok(SessionProgress::AuthorizedButNotApplied(reason))
                        }
                    }
                }
            }
        }
    }
    fn respond_clock(
        &mut self,
        index: usize,
        state: Arc<PeerState>,
        request: ClockProbeRequest,
        deadline: Instant,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        self.check_peer(&state)?;
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        let now = self.now()?;
        if now >= deadline {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        let tick = u64::try_from(
            now.checked_duration_since(self.epoch_start)
                .ok_or(PeerRuntimeError::Clock)?
                .as_nanos(),
        )
        .map_err(|_| PeerRuntimeError::Clock)?;
        let message = UnsignedPcEvent::new(PcEvent::Clock {
            pc: self.engine.pc_identity(),
            epoch: self.engine.boot_epoch(),
            probe: request.nonce(),
            sampled_at: ServiceTick::from_nanos_since_epoch(tick),
        })
        .map_err(|_| PeerRuntimeError::Protocol)?;
        let signed = self.key.sign_clock(message)?;
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        self.check_peer(&state)?;
        signed
            .verify(
                self.engine.pc_identity(),
                &PcPublicKey::from_spki_der(self.pc_key.as_spki_der())
                    .map_err(|_| PeerRuntimeError::Identity)?,
            )
            .map_err(|_| PeerRuntimeError::Identity)?;
        let bytes = encode_frame(&signed.to_wire()).map_err(|_| PeerRuntimeError::Protocol)?;
        // Last registry/revision/role-key check before response queue/drain.
        // The retained guard retires queued/partially written output on closure.
        self.check_peer(&state)?;
        if self.now()? >= deadline {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        let id = self.next_response;
        self.next_response = id.checked_add(1).ok_or(PeerRuntimeError::Capacity)?;
        self.peers[index]
            .responses
            .try_send(Response {
                source: state,
                id,
                bytes,
                deadline,
            })
            .map_err(|_| PeerRuntimeError::Protocol)?;
        self.peers[index].response = Some((id, deadline));
        Ok(SessionProgress::ClockQueued)
    }
    fn now(&mut self) -> Result<Instant, PeerRuntimeError> {
        let now = self.clock.now().map_err(|_| PeerRuntimeError::Clock)?;
        if now < self.last_time || now < self.epoch_start {
            return Err(PeerRuntimeError::Clock);
        }
        self.last_time = now;
        Ok(now)
    }
    fn check_registry(&mut self) -> Result<(), PeerRuntimeError> {
        let checkpoint = self
            .registry
            .as_mut()
            .ok_or(PeerRuntimeError::Closed)?
            .checkpoint()?;
        if checkpoint != self.engine.registry_checkpoint_for_privileged_host() {
            return Err(PeerRuntimeError::Registry);
        }
        Ok(())
    }
    fn revalidate_peers(&mut self) -> Result<(), PeerRuntimeError> {
        self.check_registry()?;
        for index in 0..self.peers.len() {
            let state = Arc::clone(&self.peers[index].state);
            if state.live() && self.binding(state.binding.device)? != state.binding {
                state.retire();
            }
        }
        Ok(())
    }
    fn binding(&mut self, device: DeviceId) -> Result<PeerBinding, PeerRuntimeError> {
        self.check_registry()?;
        let registry = self.registry.as_mut().ok_or(PeerRuntimeError::Closed)?;
        let checkpoint = registry.checkpoint()?;
        let entry = checkpoint
            .entries()
            .iter()
            .find(|entry| entry.device_id() == device)
            .ok_or(PeerRuntimeError::PeerChanged)?;
        Ok(PeerBinding {
            device,
            revision: entry.revision(),
            keys: entry.keys().clone(),
            transport: registry
                .transport(device)?
                .ok_or(PeerRuntimeError::PeerChanged)?,
        })
    }
    fn check_peer(&mut self, state: &PeerState) -> Result<(), PeerRuntimeError> {
        if self.closing
            || !state.live()
            || !Arc::ptr_eq(&state.owner, &self.identity)
            || state.epoch != self.engine.boot_epoch()
            || self.binding(state.binding.device)? != state.binding
        {
            return Err(PeerRuntimeError::PeerChanged);
        }
        Ok(())
    }
    fn reap_finished(&mut self) -> usize {
        let mut index = 0;
        let mut count = 0;
        while index < self.peers.len() {
            if self.peers[index]
                .thread
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let mut peer = self.peers.swap_remove(index);
                peer.state.retire();
                if let Some(thread) = peer.thread.take() {
                    // Peer protocol/TLS rejection is a normal retired owner;
                    // an actual thread unwind remains a cleanup failure signal.
                    if thread.join().is_err() {
                        self.io_failed = true;
                    }
                }
                count += 1;
            } else {
                index += 1;
            }
        }
        count
    }
    pub fn begin_shutdown(&mut self) {
        self.closing = true;
        for peer in &self.peers {
            peer.state.retire();
        }
        self.signer.close();
        self.signing_worker.close();
    }
    /// Never wait on a peer blocked on this same key worker. Closure wakes that
    /// bridge wait; each poll joins ONLY handles already reported finished.
    pub fn poll_shutdown(&mut self) -> SessionCleanup {
        self.begin_shutdown();
        self.reap_finished();
        if self.peers.is_empty() {
            SessionCleanup::Quiescent {
                io_failed: self.io_failed,
            }
        } else {
            SessionCleanup::CleanupPending {
                owners: self.peers.len(),
            }
        }
    }
    pub fn finish_shutdown(&mut self) -> Result<(), PeerRuntimeError> {
        if !self.closing || !self.peers.is_empty() {
            return Err(PeerRuntimeError::CleanupPending);
        }
        if let Some(registry) = self.registry.take() {
            registry.close()?;
        }
        Ok(())
    }
}
impl Drop for ServiceSession<'_> {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.reap_finished();
        if !self.peers.is_empty() {
            // Last-resort invariant failure ONLY. No detached reaper, forgotten
            // handle, blocking join, key release, or false quiescence receipt.
            // Actual runtime retains this session across catch/drain instead.
            std::process::abort();
        }
    }
}

struct RetireOnDrop(Arc<PeerState>);
impl Drop for RetireOnDrop {
    fn drop(&mut self) {
        self.0.retire();
    }
}

struct EnrolledPeerSocket {
    driver: SocketDriver,
    state: Arc<PeerState>,
    clock: Arc<dyn SocketClock>,
    events: async_mpsc::Sender<PeerEvent>,
    responses: async_mpsc::Receiver<Response>,
    ready: bool,
    response: Option<u64>,
}
impl EnrolledPeerSocket {
    async fn emit(&mut self, mut event: PeerEvent) -> Result<(), PeerRuntimeError> {
        let end = self
            .clock
            .now()
            .map_err(|_| PeerRuntimeError::Clock)?
            .checked_add(EVENT_LIFETIME)
            .ok_or(PeerRuntimeError::Clock)?;
        loop {
            if !self.state.live() {
                return Ok(());
            }
            match self.events.try_send(event) {
                Ok(()) => return Ok(()),
                Err(async_mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                Err(async_mpsc::error::TrySendError::Full(value)) => event = value,
            }
            self.driver
                .observe_liveness()
                .map_err(|_| PeerRuntimeError::Io)?;
            if self.clock.now().map_err(|_| PeerRuntimeError::Clock)? >= end {
                return Err(PeerRuntimeError::Protocol);
            }
            tokio::time::sleep(POLL).await;
        }
    }
    async fn run(mut self) -> Result<(), PeerRuntimeError> {
        loop {
            tokio::select! {
                biased;
                _ = self.state.stop.cancelled() => { self.driver.abort(); return Ok(()); }
                response = self.responses.recv() => {
                    let Some(response) = response else { self.driver.abort(); return Ok(()); };
                    #[cfg(test)] while self.state.hold_response.load(Ordering::Acquire) && self.state.live() {
                        self.driver.observe_liveness().map_err(|_| PeerRuntimeError::Io)?;
                        tokio::time::sleep(POLL).await;
                    }
                    if !self.ready || !self.state.live() || !Arc::ptr_eq(&response.source, &self.state) || self.response.is_some() { self.driver.abort(); return Err(PeerRuntimeError::Protocol); }
                    let guard: Arc<dyn OutboundFrameGuard> = self.state.clone();
                    self.driver.queue_guarded_frame(response.bytes, response.deadline, guard).map_err(|_| PeerRuntimeError::Io)?;
                    self.response = Some(response.id);
                }
                event = self.driver.next_event() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(_) if !self.state.live() => return Ok(()),
                        Err(_) => return Err(PeerRuntimeError::Io),
                    };
                    match event {
                        SocketEvent::Ready => { self.ready = true; self.emit(PeerEvent::Ready).await?; }
                        SocketEvent::Frame(frame) => {
                            if !self.ready || !self.state.live() { return Err(PeerRuntimeError::Protocol); }
                            let received = self.clock.now().map_err(|_| PeerRuntimeError::Clock)?;
                            self.emit(PeerEvent::Frame(PeerFrame { source: Arc::clone(&self.state), frame, received })).await?;
                        }
                        SocketEvent::OutboundDrained => {
                            let id = self.response.take().ok_or(PeerRuntimeError::Protocol)?;
                            self.emit(PeerEvent::Drained(id)).await?;
                        }
                        SocketEvent::PeerClosed | SocketEvent::LocallyClosed => return Ok(()),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
