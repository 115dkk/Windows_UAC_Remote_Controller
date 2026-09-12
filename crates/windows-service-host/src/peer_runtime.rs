// SPDX-License-Identifier: GPL-2.0-or-later
//! One service-worker session. Native pairing rendezvous is owned here only
//! after full SCM Ready; policy-qualified private preparation still confers no
//! consent/enrollment/grant. No network
//! listener or generic request/action API is exposed.
#![forbid(unsafe_code)]
// The ceremony and dialer orchestration only runs on 64-bit Windows; other
// targets compile this module for its shared types and host tests, so items
// that those paths alone use are not dead code there.
#![cfg_attr(
    not(all(windows, target_pointer_width = "64")),
    allow(dead_code, unused_imports, unused_variables)
)]

use std::{
    collections::VecDeque,
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
    ApprovalEngine, DecisionError, DeviceKeys, EngineError, MAX_PENDING_REQUESTS,
    PrivilegedDeviceRegistry, RegistryCheckpoint,
};
use approval_protocol::{
    BootEpoch, DecisionPublicKey, DecisionPurpose, DeviceId, OsSession, PcIdentity, RequestId,
    SignedDecision,
};
use framed_transport::{
    CancellationToken, ConnectionBudget, OutboundFrameGuard, PeerTransport, ReceivedFrame,
    SocketClock, SocketClockUnavailable, SocketDriver, SocketEvent, SocketLimits,
};
use secure_channel::{EndpointRole, PlatformTlsSigner, TlsIdentity, TlsPublicKey};
use service_protocol::{
    CLOCK_REQUEST_BYTES, ClockProbeRequest, EnrollmentAcceptanceFields, MAX_CLOCK_PROBE_RTT_NANOS,
    PcEvent, PcPublicKey, ServiceTick, SignedEnrollmentAcceptance, SignedFrozenCandidate,
    SignedPcEvent, UnsignedEnrollmentAcceptance, UnsignedFrozenCandidate, UnsignedPcEvent,
    encode_frame,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc as async_mpsc;

use crate::tls_signer::{
    ServiceTlsSigner, ServiceTlsSigningWorker, TlsSigningBridgeError, TlsSigningProgress,
};

#[cfg(all(windows, target_pointer_width = "64"))]
mod dialer;
#[cfg(all(windows, target_pointer_width = "64"))]
mod enrollment;
#[cfg(all(windows, target_pointer_width = "64"))]
mod management;
#[cfg(all(windows, target_pointer_width = "64"))]
mod pairing;
pub(crate) mod prompt;

const MAX_PEERS: usize = framed_transport::MAX_CONNECTIONS;
const RESPONSE_QUEUE_CAPACITY: usize = 4;
const POLL: Duration = Duration::from_millis(25);
const EVENT_LIFETIME: Duration = Duration::from_nanos(MAX_CLOCK_PROBE_RTT_NANOS);
const IDENTITY_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pc-identity/v1\0";
#[cfg(all(windows, target_pointer_width = "64"))]
const MIN_ANDROID_APP_VERSION: u64 = 1_000;
#[cfg(all(windows, target_pointer_width = "64"))]
const MIN_ANDROID_OS_VERSION: u32 = 110_000;
#[cfg(all(windows, target_pointer_width = "64"))]
const MIN_ANDROID_PATCH: u32 = 202_601;

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
    ApplyRequested {
        device: DeviceId,
        purpose: DecisionPurpose,
    },
    Prompt(prompt::PromptProgress),
    Enrolled(DeviceId),
    PairingFailed,
    Expired(usize),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotAppliedReason {
    PlatformUnavailable,
    NoLiveTarget,
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
    Drained { id: u64, kind: ResponseKind },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseKind {
    Clock,
    Prompt,
}
struct Response {
    source: Arc<PeerState>,
    id: u64,
    bytes: Vec<u8>,
    deadline: Instant,
    kind: ResponseKind,
}
struct PeerSlot {
    state: Arc<PeerState>,
    events: async_mpsc::Receiver<PeerEvent>,
    responses: async_mpsc::Sender<Response>,
    thread: Option<JoinHandle<Result<(), PeerRuntimeError>>>,
    ready: bool,
    /// This connection has drained at least one clock response. The phone
    /// aborts a connection that carries a prompt event before its own
    /// connection-bound clock correlation exists, so prompt events wait.
    clock_served: bool,
    /// The live request whose `Opened` this connection has already received.
    opened_sent: Option<RequestId>,
    responses_in_flight: VecDeque<(u64, Instant, ResponseKind)>,
}

#[cfg(all(windows, target_pointer_width = "64"))]
struct PendingRelayReplacement {
    address: Option<std::net::SocketAddr>,
    old_dialer: Option<dialer::DeviceDialer>,
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl fmt::Debug for PendingRelayReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRelayReplacement")
            .field("old_dialer_owned", &self.old_dialer.is_some())
            .finish_non_exhaustive()
    }
}

enum RegistryOwner<'key> {
    #[cfg(windows)]
    Native(Box<crate::ServiceRegistry<'key>>),
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
            Self::Fixture(owner, _) => Ok(owner.borrow().read_checkpoint()),
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
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn relay_endpoint(&mut self) -> Result<Option<std::net::SocketAddr>, PeerRuntimeError> {
        match self {
            Self::Native(owner) => owner
                .read_relay_endpoint()
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => Ok(owner.borrow().relay),
        }
    }
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn routes(
        &mut self,
    ) -> Result<Vec<(DeviceId, std::net::SocketAddr, relay_service::RouteId)>, PeerRuntimeError>
    {
        match self {
            Self::Native(owner) => owner
                .device_routes()
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => Ok(owner
                .borrow()
                .routes
                .iter()
                .map(|(device, (relay, route))| (*device, *relay, *route))
                .collect()),
        }
    }
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn revoke(
        &mut self,
        device: DeviceId,
    ) -> Result<crate::CommittedRegistryChange, PeerRuntimeError> {
        match self {
            Self::Native(owner) => owner
                .revoke_from_privileged_owner(device)
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => {
                let mut fixture = owner.borrow_mut();
                let mut registry = PrivilegedDeviceRegistry::restore_for_privileged_host(
                    fixture.checkpoint.clone(),
                )
                .map_err(|_| PeerRuntimeError::Registry)?;
                registry
                    .revoke_from_privileged_host(device)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                fixture.checkpoint = registry.checkpoint_for_privileged_host();
                fixture.transport.remove(&device);
                fixture.routes.remove(&device);
                Ok(crate::CommittedRegistryChange::for_test(
                    device,
                    fixture.checkpoint.next_revision() - 1,
                ))
            }
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn enroll(
        &mut self,
        device: DeviceId,
        proof: android_attestation::VerifiedKeyBundle,
        policy: &android_attestation::VerificationPolicy,
        status: &android_attestation::TrustedStatusSnapshot,
        route: relay_service::RouteId,
        relay: std::net::SocketAddr,
    ) -> Result<crate::CommittedRegistryChange, PeerRuntimeError> {
        match self {
            Self::Native(owner) => owner
                .enroll_from_privileged_owner(device, proof, policy, status, route, relay)
                .map_err(|_| PeerRuntimeError::Registry),
            #[cfg(test)]
            Self::Fixture(owner, _) => {
                let [approval, denial, transport] = proof
                    .into_current_keys(policy, status)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                let keys =
                    DeviceKeys::new(decision_from_tls(&approval)?, decision_from_tls(&denial)?)
                        .map_err(|_| PeerRuntimeError::Registry)?;
                let mut fixture = owner.borrow_mut();
                let mut registry = PrivilegedDeviceRegistry::restore_for_privileged_host(
                    fixture.checkpoint.clone(),
                )
                .map_err(|_| PeerRuntimeError::Registry)?;
                registry
                    .enroll_from_privileged_host(device, keys)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                let checkpoint = registry.checkpoint_for_privileged_host();
                let revision = checkpoint
                    .entries()
                    .iter()
                    .find(|entry| entry.device_id() == device)
                    .map(approval_core::RegistryCheckpointEntry::revision)
                    .ok_or(PeerRuntimeError::Registry)?;
                fixture.checkpoint = checkpoint;
                fixture.transport.insert(device, transport);
                fixture.routes.insert(device, (relay, route));
                Ok(crate::CommittedRegistryChange::for_test(device, revision))
            }
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
                ServiceTlsSigner::for_service_key(key).map_err(PeerRuntimeError::Signing)
            }
            #[cfg(test)]
            Self::Fixture(key) => {
                ServiceTlsSigner::for_test_key(*key).map_err(PeerRuntimeError::Signing)
            }
        }
    }
    fn sign_frozen(
        &self,
        message: UnsignedFrozenCandidate,
    ) -> Result<SignedFrozenCandidate, PeerRuntimeError> {
        let bytes = message.signing_bytes();
        let signature = self.sign_protocol(&bytes)?;
        message
            .with_der_signature(&signature)
            .map_err(|_| PeerRuntimeError::Identity)
    }
    fn sign_acceptance(
        &self,
        message: UnsignedEnrollmentAcceptance,
    ) -> Result<SignedEnrollmentAcceptance, PeerRuntimeError> {
        let bytes = message.signing_bytes();
        let signature = self.sign_protocol(&bytes)?;
        message
            .with_der_signature(&signature)
            .map_err(|_| PeerRuntimeError::Identity)
    }
    fn sign_protocol(&self, bytes: &[u8]) -> Result<Vec<u8>, PeerRuntimeError> {
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                let digest: [u8; 32] = Sha256::digest(bytes).into();
                Ok(key
                    .sign_digest_for_service(&digest)
                    .map_err(|_| PeerRuntimeError::Identity)?
                    .as_der_bytes()
                    .to_vec())
            }
            #[cfg(test)]
            Self::Fixture(key) => Ok(key.sign_protocol(bytes)),
        }
    }
    fn sign_event(&self, message: UnsignedPcEvent) -> Result<SignedPcEvent, PeerRuntimeError> {
        // Only internally constructed fixed PcEvent values reach this method. No
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
            Self::Fixture(key) => key.sign_event(message),
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
    #[cfg(all(windows, target_pointer_width = "64"))]
    pairing: pairing::ServicePairing,
    #[cfg(all(windows, target_pointer_width = "64"))]
    management: management::ServiceManagement,
    #[cfg(all(windows, target_pointer_width = "64"))]
    dialer: Option<dialer::DeviceDialer>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    embedded_relay: Option<relay_service::HostedRelay>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    embedded_mode: bool,
    #[cfg(all(windows, target_pointer_width = "64"))]
    relay_retry_at: Instant,
    #[cfg(all(windows, target_pointer_width = "64"))]
    relay: Option<std::net::SocketAddr>,
    #[cfg(all(windows, target_pointer_width = "64"))]
    pending_relay: Option<PendingRelayReplacement>,
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
    prompt: prompt::PromptState,
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
            RegistryOwner::Native(Box::new(registry)),
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
            #[cfg(all(windows, target_pointer_width = "64"))]
            pairing: pairing::ServicePairing::dormant(),
            #[cfg(all(windows, target_pointer_width = "64"))]
            management: management::ServiceManagement::dormant(),
            #[cfg(all(windows, target_pointer_width = "64"))]
            dialer: None,
            #[cfg(all(windows, target_pointer_width = "64"))]
            embedded_relay: None,
            #[cfg(all(windows, target_pointer_width = "64"))]
            embedded_mode: false,
            #[cfg(all(windows, target_pointer_width = "64"))]
            relay_retry_at: epoch_start,
            #[cfg(all(windows, target_pointer_width = "64"))]
            relay: None,
            #[cfg(all(windows, target_pointer_width = "64"))]
            pending_relay: None,
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
            prompt: prompt::PromptState::default(),
        })
    }

    /// Only the worker receiving entry's exact full-Ready acknowledgement may
    /// activate these native endpoints. Shared/test constructors remain dormant.
    #[cfg(windows)]
    /// Activates pairing and then the management pipe. The management pipe is an
    /// auxiliary surface: when it cannot be offered the service still observes
    /// prompts and serves enrolled phones, and the reason comes back as fixed
    /// text for the caller's journal and lab notes (`Ok(Some(reason))`).
    pub(crate) fn activate_pairing(
        &mut self,
        ready: crate::startup_phase::ScmReadyPermit,
    ) -> Result<Option<String>, PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        #[cfg(target_pointer_width = "64")]
        {
            self.pairing.activate(ready, self.engine.boot_epoch())?;
            Ok(self
                .management
                .activate()
                .err()
                .map(|error| error.to_string()))
        }
        #[cfg(not(target_pointer_width = "64"))]
        {
            let _ = ready;
            Err(PeerRuntimeError::Io)
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(crate) fn configure_relay_after_ready(
        &mut self,
        relay: Option<std::net::SocketAddr>,
    ) -> Result<(), PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        self.embedded_mode = relay.is_none();
        self.relay = relay;
        if self.embedded_mode {
            self.poll_embedded_relay(Instant::now())?;
        } else {
            self.dialer = relay.map(dialer::DeviceDialer::new).transpose()?;
        }
        Ok(())
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn withdraw_relay(&mut self) {
        // Readiness, the dialer and the active invitation describe one endpoint.
        // Withdraw them together; callers retain every worker until drained.
        self.relay = None;
        if let Some(dialer) = self.dialer.as_mut() {
            dialer.cancel();
        }
        if !self.pairing.enrollment_is_absent() {
            self.pairing
                .reject_enrollment_start(pairing::Failure::RelayUnconfigured);
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn poll_embedded_relay(&mut self, now: Instant) -> Result<(), PeerRuntimeError> {
        if !self.embedded_mode
            || self.pending_relay.is_some()
            || self.closing
            || now < self.relay_retry_at
        {
            return Ok(());
        }
        self.relay_retry_at = now + Duration::from_secs(5);
        if self
            .embedded_relay
            .as_ref()
            .is_some_and(|host| !host.is_running())
        {
            if !self
                .embedded_relay
                .as_mut()
                .is_none_or(relay_service::HostedRelay::drain)
            {
                return Ok(());
            }
            self.embedded_relay = None;
            self.withdraw_relay();
        }
        if self.embedded_relay.is_none() {
            // A port collision or offline network disables connection readiness,
            // not TPM/service startup. Retry is bounded and never kills an owner.
            self.embedded_relay = relay_service::HostedRelay::start(std::net::SocketAddr::from((
                [0, 0, 0, 0],
                relay_service::EMBEDDED_RELAY_PORT,
            )))
            .ok();
        }
        let endpoint = if self
            .embedded_relay
            .as_ref()
            .is_some_and(relay_service::HostedRelay::is_running)
        {
            relay_service::local_endpoint().ok()
        } else {
            None
        };
        if self.relay.is_some() && self.relay != endpoint {
            self.withdraw_relay();
        }
        if self
            .embedded_relay
            .as_ref()
            .is_some_and(relay_service::HostedRelay::is_running)
            && self.relay.is_none()
        {
            if let Some(dialer) = self.dialer.as_mut() {
                if !dialer.drain() {
                    return Ok(());
                }
                self.dialer = None;
            }
            if let Some(endpoint) = endpoint {
                self.dialer = Some(dialer::DeviceDialer::new(endpoint)?);
                self.relay = Some(endpoint);
            }
        }
        Ok(())
    }

    pub(crate) fn handle_watch_event(
        &mut self,
        event: crate::WatchEvent,
        now: Instant,
    ) -> Result<prompt::PromptProgress, PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        self.observe_external_now(now)?;
        self.prompt.clear_withdrawn_if_expired(now);
        match event {
            crate::WatchEvent::Appeared {
                target,
                report,
                session,
            } => {
                let previous = self.cancel_live_prompt(prompt::PromptResult::Cancelled, now)?;
                let content = match prompt::map_content(&report) {
                    Ok(content) => content,
                    Err(_) => {
                        return Ok(prompt::PromptProgress::opened(0, previous));
                    }
                };
                let deadline = now
                    .checked_add(prompt::request_ttl().as_duration())
                    .ok_or(PeerRuntimeError::Clock)?;
                let issued_at = self.tick(now)?;
                let observed_digest = report.content().digest();
                let challenge = match self.engine.open_from_privileged_host(
                    OsSession::new(session, 0),
                    (*content).clone(),
                    prompt::request_ttl(),
                    now,
                ) {
                    Ok(challenge) => challenge,
                    Err(EngineError::NoEligibleDevices) => {
                        return Ok(prompt::PromptProgress::opened(0, previous));
                    }
                    Err(EngineError::Clock(_)) | Err(EngineError::ClockRangeExceeded) => {
                        return Err(PeerRuntimeError::Clock);
                    }
                    Err(_) => return Err(PeerRuntimeError::Protocol),
                };
                let binding = challenge.binding();
                if challenge.binding().session().session_id() != session
                    || challenge.binding().session().logon_id() != 0
                    || binding.content_digest() != content.digest()
                    || challenge.content() != content.as_ref()
                {
                    let _ = self.engine.cancel_from_privileged_host(&binding);
                    return Err(PeerRuntimeError::Protocol);
                }
                let live = prompt::LivePrompt {
                    target,
                    session_id: session,
                    binding,
                    request_id: binding.request_id(),
                    content: Arc::clone(&content),
                    content_digest: observed_digest,
                    issued_at,
                    deadline,
                    applying: None,
                };
                self.prompt.replace(live);
                let event = PcEvent::Opened {
                    binding,
                    issued_at,
                    content,
                };
                let queued = match self.publish_event(event, deadline, now) {
                    Ok(count) => count,
                    Err(error) => {
                        let _ = self.cancel_live_prompt(prompt::PromptResult::FailedUnknown, now);
                        return Err(error);
                    }
                };
                Ok(prompt::PromptProgress::opened(queued, previous))
            }
            crate::WatchEvent::Gone { target, .. } => {
                if self
                    .prompt
                    .live()
                    .is_some_and(|prompt| prompt.target == target)
                {
                    let result = self
                        .cancel_live_prompt(prompt::PromptResult::Cancelled, now)?
                        .unwrap_or(prompt::PromptResult::Cancelled);
                    Ok(prompt::PromptProgress::resolved(result))
                } else {
                    Ok(prompt::PromptProgress::default())
                }
            }
            crate::WatchEvent::Applied { target, outcome } => {
                let Some(live) = self.prompt.live() else {
                    return Ok(prompt::PromptProgress::default());
                };
                if live.target != target || live.applying.is_none() {
                    return Ok(prompt::PromptProgress::default());
                }
                let (_, purpose) = live.applying.expect("checked applying state");
                let result = match outcome {
                    crate::ApplyOutcome::Gone => match purpose {
                        DecisionPurpose::Approve => prompt::PromptResult::Approved,
                        DecisionPurpose::Deny => prompt::PromptResult::Denied,
                    },
                    crate::ApplyOutcome::StillPresent => prompt::PromptResult::FailedUnknown,
                    crate::ApplyOutcome::Refused(_) => prompt::PromptResult::FailedRejected,
                };
                self.resolve_live_prompt(result, now)?;
                Ok(prompt::PromptProgress::resolved(result))
            }
            crate::WatchEvent::HelperRestarted { .. } | crate::WatchEvent::HelperUnavailable => {
                let result = self.cancel_live_prompt(prompt::PromptResult::Cancelled, now)?;
                Ok(
                    result.map_or_else(prompt::PromptProgress::default, |result| {
                        prompt::PromptProgress::resolved(result)
                    }),
                )
            }
        }
    }

    pub(crate) fn prompt_deadline_step(
        &mut self,
        now: Instant,
    ) -> Result<Option<prompt::PromptProgress>, PeerRuntimeError> {
        self.observe_external_now(now)?;
        self.prompt.clear_withdrawn_if_expired(now);
        let Some(live) = self.prompt.live() else {
            return Ok(None);
        };
        if now < live.deadline {
            return Ok(None);
        }
        let request_id = live.request_id;
        let applying = live.applying.is_some();
        let expired = self
            .engine
            .expire_from_privileged_host(now)
            .map_err(|_| PeerRuntimeError::Clock)?;
        let request_expired = expired.contains(&request_id);
        if self
            .prompt
            .live()
            .is_some_and(|current| current.request_id != request_id)
            || applying == request_expired
        {
            return Err(PeerRuntimeError::Protocol);
        }
        self.resolve_live_prompt(prompt::PromptResult::Expired, now)?;
        Ok(Some(prompt::PromptProgress::resolved(
            prompt::PromptResult::Expired,
        )))
    }

    fn cancel_live_prompt(
        &mut self,
        result: prompt::PromptResult,
        now: Instant,
    ) -> Result<Option<prompt::PromptResult>, PeerRuntimeError> {
        let Some(live) = self.prompt.take() else {
            return Ok(None);
        };
        match self.engine.cancel_from_privileged_host(&live.binding) {
            Ok(()) => {}
            Err(approval_core::CancelError::UnknownOrCompleted) if live.applying.is_some() => {}
            Err(_) => {
                self.prompt.replace(live);
                return Err(PeerRuntimeError::Protocol);
            }
        }
        self.prompt.remember_withdrawn(live.binding, live.deadline);
        self.publish_resolution(&live, result, now)?;
        Ok(Some(result))
    }

    fn resolve_live_prompt(
        &mut self,
        result: prompt::PromptResult,
        now: Instant,
    ) -> Result<(), PeerRuntimeError> {
        let live = self.prompt.take().ok_or(PeerRuntimeError::Protocol)?;
        if result == prompt::PromptResult::Cancelled {
            self.prompt.remember_withdrawn(live.binding, live.deadline);
        }
        self.publish_resolution(&live, result, now).map(|_| ())
    }

    fn fail_consumed_live(&mut self, now: Instant) -> Result<(), PeerRuntimeError> {
        let live = self.prompt.take().ok_or(PeerRuntimeError::Protocol)?;
        self.publish_resolution(&live, prompt::PromptResult::FailedUnknown, now)
            .map(|_| ())
    }

    fn publish_resolution(
        &mut self,
        live: &prompt::LivePrompt,
        result: prompt::PromptResult,
        now: Instant,
    ) -> Result<usize, PeerRuntimeError> {
        let event = PcEvent::Resolved {
            binding: live.binding,
            issued_at: live.issued_at,
            outcome: result.resolution(),
        };
        let deadline = now
            .checked_add(EVENT_LIFETIME)
            .ok_or(PeerRuntimeError::Clock)?;
        self.publish_event(event, deadline, now)
    }

    fn publish_event(
        &mut self,
        event: PcEvent,
        deadline: Instant,
        now: Instant,
    ) -> Result<usize, PeerRuntimeError> {
        let opened = match &event {
            PcEvent::Opened { binding, .. } => Some(binding.request_id()),
            _ => None,
        };
        let bytes = self.signed_event_bytes(event)?;
        self.revalidate_peers()?;
        let mut queued = 0;
        for index in 0..self.peers.len() {
            if !self.peers[index].clock_served {
                continue;
            }
            if self.queue_signed_event(index, &bytes, deadline, now, opened)? {
                queued += 1;
            }
        }
        Ok(queued)
    }

    /// A connection that completed its clock exchange after the live prompt
    /// opened (a phone that connected during the prompt, or whose clock probe
    /// arrived after `Appeared`) has not seen `Opened` yet: publish the same
    /// signed request to that connection alone, once.
    fn resend_live_opened(&mut self, index: usize, now: Instant) -> Result<(), PeerRuntimeError> {
        let Some(live) = self.prompt.live() else {
            return Ok(());
        };
        if live.applying.is_some()
            || now >= live.deadline
            || self.peers[index].opened_sent == Some(live.request_id)
        {
            return Ok(());
        }
        let request_id = live.request_id;
        let deadline = live.deadline;
        let event = PcEvent::Opened {
            binding: live.binding,
            issued_at: live.issued_at,
            content: Arc::clone(&live.content),
        };
        let bytes = self.signed_event_bytes(event)?;
        self.revalidate_peers()?;
        self.queue_signed_event(index, &bytes, deadline, now, Some(request_id))
            .map(|_| ())
    }

    fn signed_event_bytes(&mut self, event: PcEvent) -> Result<Vec<u8>, PeerRuntimeError> {
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        let message = UnsignedPcEvent::new(event).map_err(|_| PeerRuntimeError::Protocol)?;
        let signed = self.key.sign_event(message)?;
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        signed
            .verify(
                self.engine.pc_identity(),
                &PcPublicKey::from_spki_der(self.pc_key.as_spki_der())
                    .map_err(|_| PeerRuntimeError::Identity)?,
            )
            .map_err(|_| PeerRuntimeError::Identity)?;
        encode_frame(&signed.to_wire()).map_err(|_| PeerRuntimeError::Protocol)
    }

    /// Queues one signed prompt event on one ready connection. `false` means
    /// the connection was skipped or retired instead of served.
    fn queue_signed_event(
        &mut self,
        index: usize,
        bytes: &[u8],
        deadline: Instant,
        now: Instant,
        opened: Option<RequestId>,
    ) -> Result<bool, PeerRuntimeError> {
        let state = Arc::clone(&self.peers[index].state);
        if !self.peers[index].ready || !state.live() {
            return Ok(false);
        }
        if self.check_peer(&state).is_err()
            || self.peers[index].responses_in_flight.len() >= RESPONSE_QUEUE_CAPACITY
            || now >= deadline
        {
            state.retire();
            return Ok(false);
        }
        let id = self.next_response;
        self.next_response = id.checked_add(1).ok_or(PeerRuntimeError::Capacity)?;
        let response = Response {
            source: Arc::clone(&state),
            id,
            bytes: bytes.to_vec(),
            deadline,
            kind: ResponseKind::Prompt,
        };
        if self.peers[index].responses.try_send(response).is_err() {
            state.retire();
            return Ok(false);
        }
        self.peers[index]
            .responses_in_flight
            .push_back((id, deadline, ResponseKind::Prompt));
        if let Some(request_id) = opened {
            self.peers[index].opened_sent = Some(request_id);
        }
        Ok(true)
    }

    /// The engine consumed or dropped `request_id`: a live prompt for it that
    /// is not being applied must not outlive the engine request, or the exact
    /// deadline step would find the two out of agreement.
    fn settle_consumed(
        &mut self,
        request_id: RequestId,
        result: prompt::PromptResult,
        now: Instant,
    ) -> Result<(), PeerRuntimeError> {
        let Some(live) = self.prompt.live() else {
            return Ok(());
        };
        if live.request_id != request_id || live.applying.is_some() {
            return Ok(());
        }
        let result = if now >= live.deadline {
            prompt::PromptResult::Expired
        } else {
            result
        };
        self.resolve_live_prompt(result, now)
    }

    fn tick(&self, now: Instant) -> Result<ServiceTick, PeerRuntimeError> {
        let nanos = now
            .checked_duration_since(self.epoch_start)
            .ok_or(PeerRuntimeError::Clock)?
            .as_nanos();
        Ok(ServiceTick::from_nanos_since_epoch(
            u64::try_from(nanos).map_err(|_| PeerRuntimeError::Clock)?,
        ))
    }

    fn observe_external_now(&mut self, now: Instant) -> Result<(), PeerRuntimeError> {
        if now < self.last_time || now < self.epoch_start {
            return Err(PeerRuntimeError::Clock);
        }
        self.last_time = now;
        Ok(())
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
        let (event_sender, events) = async_mpsc::channel(RESPONSE_QUEUE_CAPACITY);
        let (responses, response_receiver) = async_mpsc::channel(RESPONSE_QUEUE_CAPACITY);
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
            clock_served: false,
            opened_sent: None,
            responses_in_flight: VecDeque::new(),
        });
        Ok(())
    }

    /// Services at most one signing request and one peer event. Native key work
    /// can block; it is not preempted by the response/cleanup budgets.
    pub fn process_one(&mut self) -> Result<SessionProgress, PeerRuntimeError> {
        self.process_one_inner(None)
    }

    pub(crate) fn process_one_with_watch(
        &mut self,
        watch: &mut dyn prompt::PromptApply,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        self.process_one_inner(Some(watch))
    }

    fn process_one_inner(
        &mut self,
        watch: Option<&mut dyn prompt::PromptApply>,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.process_live(watch)))
                .unwrap_or(Err(PeerRuntimeError::Unwind));
        if result.is_err() {
            self.begin_shutdown();
        }
        result
    }

    fn process_live(
        &mut self,
        watch: Option<&mut dyn prompt::PromptApply>,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            if let management::ManagementProgress::Request { class, request } =
                self.management.poll().map_err(|_| PeerRuntimeError::Io)?
                && let Some(response) = self.handle_management(class, request)?
            {
                self.management
                    .reply(response)
                    .map_err(|_| PeerRuntimeError::Io)?;
            }
            if self.pending_relay.is_some() {
                self.poll_pending_relay()?;
            }
            let now = self.now()?;
            self.poll_embedded_relay(now)?;
            self.pairing.poll(self.engine.boot_epoch(), now);
            if self.pairing.wants_preparation_context() {
                // One native-worker owner supplies the current registry/engine
                // checkpoint and real PC identity. No foreign context or grant.
                let checkpoint = self.current_registry_checkpoint()?;
                let key = &self.key;
                self.pairing.maintain_original(
                    self.engine.boot_epoch(),
                    self.engine.pc_identity(),
                    &self.pc_key,
                    &checkpoint,
                    || key.public(),
                );
            }
            if self
                .pairing
                .renderer()
                .is_some_and(|renderer| renderer.ready_for_invitation())
                && self.pairing.enrollment_is_absent()
            {
                let started = (|| {
                    let configured = self
                        .registry
                        .as_mut()
                        .ok_or(pairing::Failure::Enrollment)?
                        .relay_endpoint()
                        .map_err(|_| pairing::Failure::Enrollment)?;
                    let relay = self.relay.ok_or(pairing::Failure::RelayUnconfigured)?;
                    if configured.is_some_and(|configured| configured != relay)
                        || (configured.is_none()
                            && !self
                                .embedded_relay
                                .as_ref()
                                .is_some_and(relay_service::HostedRelay::is_running))
                    {
                        return Err(pairing::Failure::Protocol);
                    }
                    if crate::ANDROID_SIGNER_SHA256.is_empty() {
                        return Err(pairing::Failure::SignerPolicyUnavailable);
                    }
                    let policy = trusted_android_policy()
                        .map_err(|_| pairing::Failure::SignerPolicyUnavailable)?;
                    self.pairing.begin_enrollment(
                        relay,
                        policy,
                        Arc::clone(&self.signer),
                        self.pc_key.clone(),
                    )
                })();
                if let Err(error) = started {
                    self.pairing.reject_enrollment_start(error);
                }
            }
            if let Some(progress) = self.process_enrollment(now)? {
                return Ok(progress);
            }
            self.poll_dialer(now)?;
        }
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
        let expired = if self.prompt.is_live() {
            Vec::new()
        } else {
            self.engine
                .expire_from_privileged_host(now)
                .map_err(|_| PeerRuntimeError::Clock)?
        };
        let count = self.peers.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            if let Ok(event) = self.peers[index].events.try_recv() {
                self.cursor = (index + 1) % count;
                return self.dispatch(index, event, watch);
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
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn process_enrollment(
        &mut self,
        now: Instant,
    ) -> Result<Option<SessionProgress>, PeerRuntimeError> {
        let Some(action) = self.pairing.enrollment_action(now) else {
            return Ok(None);
        };
        match action {
            pairing::CeremonyAction::SignFrozen(unsigned) => {
                if self.key.public()? != self.pc_key {
                    return Err(PeerRuntimeError::Identity);
                }
                let signed = self.key.sign_frozen(*unsigned)?;
                if self.key.public()? != self.pc_key {
                    return Err(PeerRuntimeError::Identity);
                }
                self.pairing
                    .frozen_signed(signed)
                    .map_err(|_| PeerRuntimeError::Protocol)?;
                Ok(None)
            }
            pairing::CeremonyAction::Commit { relay, route } => {
                let ((proof, status), summary) = self
                    .pairing
                    .take_verified()
                    .map_err(|_| PeerRuntimeError::Protocol)?;
                let approval = decision_from_tls(&summary.approval_key)?;
                let denial = decision_from_tls(&summary.denial_key)?;
                let keys =
                    DeviceKeys::new(approval, denial).map_err(|_| PeerRuntimeError::Registry)?;
                let policy = trusted_android_policy()?;
                let receipt = self
                    .registry
                    .as_mut()
                    .ok_or(PeerRuntimeError::Closed)?
                    .enroll(summary.device, proof, &policy, &status, route, relay)?;
                if receipt.affected_device() != summary.device {
                    return Err(PeerRuntimeError::Registry);
                }
                self.engine
                    .enroll_device_from_privileged_host(summary.device, keys)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                self.current_registry_checkpoint()?;
                let pc_transport_key = self.pairing.original_pc_key()?;
                let unsigned = UnsignedEnrollmentAcceptance::new(EnrollmentAcceptanceFields {
                    ceremony_nonce: self.pairing.original_nonce()?,
                    attestation_challenge: self.pairing.original_challenge()?,
                    pc: self.engine.pc_identity(),
                    recipient_device: summary.device,
                    registry_revision: receipt.registry_revision(),
                    phone_keys: summary.phone_keys,
                    pc_signing_key: self.pc_key.clone(),
                    pc_transport_key,
                })
                .map_err(|_| PeerRuntimeError::Protocol)?;
                let acceptance = self.key.sign_acceptance(unsigned)?;
                self.pairing
                    .send_acceptance(acceptance)
                    .map_err(|_| PeerRuntimeError::Protocol)?;
                Ok(None)
            }
            pairing::CeremonyAction::Enrolled(device) => {
                Ok(Some(SessionProgress::Enrolled(device)))
            }
            pairing::CeremonyAction::Failed => Ok(Some(SessionProgress::PairingFailed)),
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn poll_dialer(&mut self, now: Instant) -> Result<(), PeerRuntimeError> {
        // Keep the worker owned by the session across fallible registry reads.
        // An error must leave it counted for the normal cancellation/drain path.
        let Some(dialer) = self.dialer.as_mut() else {
            return Ok(());
        };
        let routes = self
            .registry
            .as_mut()
            .ok_or(PeerRuntimeError::Closed)?
            .routes()?;
        let carriers = dialer.poll(&routes, now);
        for carrier in carriers {
            let device = carrier.device;
            if self
                .peers
                .iter()
                .any(|peer| peer.state.binding.device == device && peer.state.live())
            {
                continue;
            }
            if self.attach_carrier(carrier).is_err()
                && let Some(dialer) = self.dialer.as_mut()
            {
                dialer.release(device);
            }
        }
        Ok(())
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn poll_pending_relay(&mut self) -> Result<(), PeerRuntimeError> {
        let Some(mut pending) = self.pending_relay.take() else {
            return Ok(());
        };
        if let Some(old_dialer) = pending.old_dialer.as_mut()
            && !old_dialer.drain()
        {
            self.pending_relay = Some(pending);
            return Ok(());
        }
        pending.old_dialer = None;
        if let Some(host) = self.embedded_relay.as_mut()
            && !host.drain()
        {
            self.pending_relay = Some(pending);
            return Ok(());
        }
        self.embedded_relay = None;
        self.relay_retry_at = Instant::now();
        self.configure_relay_after_ready(pending.address)?;
        self.management
            .reply(if self.relay.is_some() { crate::management_protocol::ManagementResponse::Done }
                else { crate::management_protocol::ManagementResponse::Refused("이 PC의 중계를 준비하지 못했어요. 네트워크 연결과 7443 포트를 확인한 뒤 다시 시도해 주세요.".into()) })
            .map_err(|_| PeerRuntimeError::Io)
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn handle_management(
        &mut self,
        class: crate::ffi::ManagementClientClass,
        request: crate::management_protocol::ManagementRequest,
    ) -> Result<Option<crate::management_protocol::ManagementResponse>, PeerRuntimeError> {
        use crate::management_protocol::{DeviceRow, ManagementRequest, ManagementResponse};
        if !matches!(request, ManagementRequest::Query)
            && class != crate::ffi::ManagementClientClass::CliElevated
        {
            return Ok(Some(ManagementResponse::Refused(
                "관리자 확인을 거쳐 다시 시도해 주세요.".into(),
            )));
        }
        match request {
            ManagementRequest::Query => {
                let checkpoint = self.current_registry_checkpoint()?;
                let routes = self
                    .registry
                    .as_mut()
                    .ok_or(PeerRuntimeError::Closed)?
                    .routes()?;
                let devices = checkpoint
                    .entries()
                    .iter()
                    .map(|entry| DeviceRow {
                        device: entry.device_id(),
                        revision: entry.revision(),
                        route_present: routes
                            .iter()
                            .any(|(device, _, _)| *device == entry.device_id()),
                        connected: self.peers.iter().any(|peer| {
                            peer.state.binding.device == entry.device_id() && peer.state.live()
                        }),
                        enrolled_unix_secs: None,
                    })
                    .collect();
                Ok(Some(ManagementResponse::Snapshot {
                    relay: if self.embedded_mode
                        && !self
                            .embedded_relay
                            .as_ref()
                            .is_some_and(relay_service::HostedRelay::is_running)
                    {
                        None
                    } else {
                        self.relay
                    },
                    identity_provider: crate::contract::IDENTITY_PROVIDER_PROFILE.into(),
                    android_signer_digests: crate::ANDROID_SIGNER_SHA256.to_vec(),
                    devices,
                }))
            }
            ManagementRequest::RemoveDevice { device } => {
                let receipt = self
                    .registry
                    .as_mut()
                    .ok_or(PeerRuntimeError::Closed)?
                    .revoke(device)?;
                if receipt.affected_device() != device {
                    return Err(PeerRuntimeError::Registry);
                }
                self.engine
                    .revoke_device_from_privileged_host(device)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                self.current_registry_checkpoint()?;
                for peer in &self.peers {
                    if peer.state.binding.device == device {
                        peer.state.retire();
                    }
                }
                if let Some(dialer) = self.dialer.as_mut() {
                    dialer.release(device);
                }
                Ok(Some(ManagementResponse::Done))
            }
            ManagementRequest::SetRelay { .. } | ManagementRequest::UseEmbeddedRelay => {
                let address = match request {
                    ManagementRequest::SetRelay { address } => Some(address),
                    _ => None,
                };
                if self.pending_relay.is_some() {
                    return Err(PeerRuntimeError::Protocol);
                }
                crate::native::configure_relay_for_running_service(address)
                    .map_err(|_| PeerRuntimeError::Registry)?;
                self.withdraw_relay();
                let old_dialer = self.dialer.take();
                if let Some(host) = self.embedded_relay.as_ref() {
                    host.cancel();
                }
                self.pending_relay = Some(PendingRelayReplacement {
                    address,
                    old_dialer,
                });
                Ok(None)
            }
        }
    }

    fn dispatch(
        &mut self,
        index: usize,
        event: PeerEvent,
        watch: Option<&mut dyn prompt::PromptApply>,
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
            PeerEvent::Drained { id, kind } => {
                let now = self.now()?;
                let Some((expected, deadline, expected_kind)) =
                    self.peers[index].responses_in_flight.pop_front()
                else {
                    state.retire();
                    return Ok(SessionProgress::PeerRejected);
                };
                if expected != id || expected_kind != kind || now >= deadline {
                    state.retire();
                    return Ok(SessionProgress::PeerRejected);
                }
                self.check_peer(&state)?;
                Ok(match kind {
                    ResponseKind::Clock => {
                        self.peers[index].clock_served = true;
                        self.resend_live_opened(index, now)?;
                        SessionProgress::ClockDrained
                    }
                    ResponseKind::Prompt => SessionProgress::Idle,
                })
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
                        || self.peers[index].responses_in_flight.len() >= RESPONSE_QUEUE_CAPACITY
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
                    self.check_peer(&state)?;
                    let now = self.now()?;
                    if now < frame.received || now >= deadline {
                        state.retire();
                        return Ok(SessionProgress::PeerRejected);
                    }
                    match self.withdrawn_decision_matches(&decision, &state, now) {
                        Ok(true) => {
                            return Ok(SessionProgress::AuthorizedButNotApplied(
                                NotAppliedReason::NoLiveTarget,
                            ));
                        }
                        Ok(false) => {}
                        Err(_) => {
                            state.retire();
                            return Ok(SessionProgress::PeerRejected);
                        }
                    }
                    let request_id = decision.statement().binding().request_id();
                    match self.engine.submit_decision(&decision, now) {
                        Err(error) => {
                            state.retire();
                            if matches!(error, DecisionError::Expired) {
                                // The engine dropped the expired request on this decision.
                                self.settle_consumed(
                                    request_id,
                                    prompt::PromptResult::Expired,
                                    now,
                                )?;
                            }
                            Ok(SessionProgress::DecisionRejected(error))
                        }
                        Ok(authorized) => {
                            if self.check_peer(&state).is_err() {
                                drop(authorized);
                                self.begin_shutdown();
                                return Ok(SessionProgress::AuthorizedButNotApplied(
                                    NotAppliedReason::PeerChangedAfterVerification,
                                ));
                            }
                            let after = match self.now() {
                                Ok(now) => now,
                                Err(_) => {
                                    drop(authorized);
                                    self.begin_shutdown();
                                    return Ok(SessionProgress::AuthorizedButNotApplied(
                                        NotAppliedReason::ExpiredAfterVerification,
                                    ));
                                }
                            };
                            if after >= deadline || after >= authorized.deadline() {
                                drop(authorized);
                                self.settle_consumed(
                                    request_id,
                                    prompt::PromptResult::Expired,
                                    after,
                                )?;
                                return Ok(SessionProgress::AuthorizedButNotApplied(
                                    NotAppliedReason::ExpiredAfterVerification,
                                ));
                            }
                            let Some(watch) = watch else {
                                drop(authorized);
                                self.settle_consumed(
                                    request_id,
                                    prompt::PromptResult::FailedUnknown,
                                    after,
                                )?;
                                return Ok(SessionProgress::AuthorizedButNotApplied(
                                    NotAppliedReason::PlatformUnavailable,
                                ));
                            };
                            self.prompt.clear_withdrawn_if_expired(after);
                            let Some(live) = self.prompt.live() else {
                                drop(authorized);
                                return Ok(SessionProgress::AuthorizedButNotApplied(
                                    NotAppliedReason::NoLiveTarget,
                                ));
                            };
                            if live.binding != authorized.binding()
                                || live.session_id != authorized.binding().session().session_id()
                                || authorized.binding().session().logon_id() != 0
                                || live.content.as_ref() != authorized.content()
                                || after >= live.deadline
                                || live.applying.is_some()
                            {
                                drop(authorized);
                                self.settle_consumed(
                                    request_id,
                                    prompt::PromptResult::FailedUnknown,
                                    after,
                                )?;
                                return Ok(SessionProgress::AuthorizedButNotApplied(
                                    NotAppliedReason::NoLiveTarget,
                                ));
                            }
                            let target = live.target;
                            let digest = live.content_digest;
                            let purpose = authorized.purpose();
                            let device = authorized.device_id();
                            let action = match purpose {
                                DecisionPurpose::Approve => crate::PromptAction::Approve,
                                DecisionPurpose::Deny => crate::PromptAction::Deny,
                            };
                            if watch.apply_prompt(target, action, digest).is_err() {
                                drop(authorized);
                                self.fail_consumed_live(after)?;
                                return Ok(SessionProgress::Prompt(
                                    prompt::PromptProgress::resolved(
                                        prompt::PromptResult::FailedUnknown,
                                    ),
                                ));
                            }
                            drop(authorized);
                            let live = self.prompt.live_mut().ok_or(PeerRuntimeError::Protocol)?;
                            if live.target != target
                                || live.binding != decision.statement().binding()
                                || live.applying.is_some()
                            {
                                return Err(PeerRuntimeError::Protocol);
                            }
                            live.applying = Some((device, purpose));
                            Ok(SessionProgress::ApplyRequested { device, purpose })
                        }
                    }
                }
            }
        }
    }
    fn withdrawn_decision_matches(
        &mut self,
        decision: &SignedDecision,
        state: &PeerState,
        now: Instant,
    ) -> Result<bool, PeerRuntimeError> {
        self.prompt.clear_withdrawn_if_expired(now);
        let Some(withdrawn) = self.prompt.withdrawn() else {
            return Ok(false);
        };
        let statement = decision.statement();
        if statement.binding() != withdrawn.binding || statement.device_id() != state.binding.device
        {
            return Ok(false);
        }
        let current = self.binding(state.binding.device)?;
        if current != state.binding {
            return Ok(false);
        }
        let key = match statement.purpose() {
            DecisionPurpose::Approve => current.keys.approval(),
            DecisionPurpose::Deny => current.keys.denial(),
        };
        decision
            .verify(key)
            .map_err(|_| PeerRuntimeError::Protocol)?;
        let _ = self.prompt.take_withdrawn();
        Ok(now < withdrawn.deadline)
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
        let signed = self.key.sign_event(message)?;
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
                kind: ResponseKind::Clock,
            })
            .map_err(|_| PeerRuntimeError::Protocol)?;
        self.peers[index]
            .responses_in_flight
            .push_back((id, deadline, ResponseKind::Clock));
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
        self.current_registry_checkpoint().map(|_| ())
    }
    fn current_registry_checkpoint(&mut self) -> Result<RegistryCheckpoint, PeerRuntimeError> {
        let checkpoint = self
            .registry
            .as_mut()
            .ok_or(PeerRuntimeError::Closed)?
            .checkpoint()?;
        if checkpoint != self.engine.registry_checkpoint_for_privileged_host() {
            return Err(PeerRuntimeError::Registry);
        }
        Ok(checkpoint)
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
                let device = peer.state.binding.device;
                peer.state.retire();
                if let Some(thread) = peer.thread.take() {
                    // Peer protocol/TLS rejection is a normal retired owner;
                    // an actual thread unwind remains a cleanup failure signal.
                    if thread.join().is_err() {
                        self.io_failed = true;
                    }
                }
                #[cfg(all(windows, target_pointer_width = "64"))]
                if let Some(dialer) = self.dialer.as_mut() {
                    dialer.release(device);
                }
                count += 1;
            } else {
                index += 1;
            }
        }
        count
    }
    pub fn begin_shutdown(&mut self) {
        if let Some(live) = self.prompt.take() {
            let _ = self.engine.cancel_from_privileged_host(&live.binding);
        }
        self.closing = true;
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.pairing.shutdown();
            self.management.shutdown();
            if let Some(host) = self.embedded_relay.as_ref() {
                host.cancel();
            }
            if let Some(dialer) = self.dialer.as_mut() {
                dialer.cancel();
            }
            if let Some(dialer) = self
                .pending_relay
                .as_mut()
                .and_then(|pending| pending.old_dialer.as_mut())
            {
                dialer.cancel();
            }
        }
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
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.pairing.poll_shutdown();
            self.io_failed |= self.pairing.cleanup_failed();
            self.management.drain();
            self.io_failed |= self.management.failed();
            if let Some(host) = self.embedded_relay.as_mut() {
                host.drain();
            }
            if let Some(dialer) = self.dialer.as_mut() {
                dialer.drain();
            }
            if let Some(dialer) = self
                .pending_relay
                .as_mut()
                .and_then(|pending| pending.old_dialer.as_mut())
            {
                dialer.drain();
            }
            if self.pending_relay.as_ref().is_some_and(|pending| {
                pending
                    .old_dialer
                    .as_ref()
                    .is_none_or(|dialer| dialer.remaining_owners() == 0)
            }) {
                self.pending_relay = None;
            }
        }
        let owners = self.peers.len()
            + self.pairing_owners()
            + self.management_owners()
            + self.dialer_owners();
        if owners == 0 {
            SessionCleanup::Quiescent {
                io_failed: self.io_failed,
            }
        } else {
            SessionCleanup::CleanupPending { owners }
        }
    }
    pub fn finish_shutdown(&mut self) -> Result<(), PeerRuntimeError> {
        if !self.closing
            || !self.peers.is_empty()
            || self.pairing_owners() != 0
            || self.management_owners() != 0
            || self.dialer_owners() != 0
        {
            return Err(PeerRuntimeError::CleanupPending);
        }
        if let Some(registry) = self.registry.take() {
            registry.close()?;
        }
        Ok(())
    }
    fn pairing_owners(&self) -> usize {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.pairing.remaining_owners()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            0
        }
    }
    fn management_owners(&self) -> usize {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.management.remaining_owners()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            0
        }
    }
    fn dialer_owners(&self) -> usize {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.embedded_relay
                .as_ref()
                .map_or(0, relay_service::HostedRelay::remaining_owners)
                + self
                    .dialer
                    .as_ref()
                    .map_or(0, dialer::DeviceDialer::remaining_owners)
                + self
                    .pending_relay
                    .as_ref()
                    .and_then(|pending| pending.old_dialer.as_ref())
                    .map_or(0, dialer::DeviceDialer::remaining_owners)
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            0
        }
    }
}
impl Drop for ServiceSession<'_> {
    fn drop(&mut self) {
        self.begin_shutdown();
        self.reap_finished();
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.pairing.poll_shutdown();
            self.management.drain();
            if let Some(host) = self.embedded_relay.as_mut() {
                host.drain();
            }
            if let Some(dialer) = self.dialer.as_mut() {
                dialer.drain();
            }
            if let Some(dialer) = self
                .pending_relay
                .as_mut()
                .and_then(|pending| pending.old_dialer.as_mut())
            {
                dialer.drain();
            }
            if self.pending_relay.as_ref().is_some_and(|pending| {
                pending
                    .old_dialer
                    .as_ref()
                    .is_none_or(|dialer| dialer.remaining_owners() == 0)
            }) {
                self.pending_relay = None;
            }
        }
        if !self.peers.is_empty()
            || self.pairing_owners() != 0
            || self.management_owners() != 0
            || self.dialer_owners() != 0
        {
            // Last-resort invariant failure ONLY. No detached reaper, forgotten
            // handle, blocking join, key release, or false quiescence receipt.
            // Actual runtime retains this session across catch/drain instead.
            std::process::abort();
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn trusted_android_policy() -> Result<android_attestation::VerificationPolicy, PeerRuntimeError> {
    if crate::ANDROID_SIGNER_SHA256.is_empty() {
        return Err(PeerRuntimeError::Identity);
    }
    android_attestation::VerificationPolicy::from_trusted_host(
        crate::ANDROID_SIGNER_SHA256.to_vec(),
        MIN_ANDROID_APP_VERSION,
        android_attestation::PlatformMinimums {
            os_version: MIN_ANDROID_OS_VERSION,
            os_patch: MIN_ANDROID_PATCH,
            vendor_patch: None,
            boot_patch: None,
        },
    )
    .map_err(|_| PeerRuntimeError::Identity)
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn decision_from_tls(key: &TlsPublicKey) -> Result<DecisionPublicKey, PeerRuntimeError> {
    DecisionPublicKey::from_sec1_bytes(
        key.as_spki_der()
            .get(26..)
            .ok_or(PeerRuntimeError::Identity)?,
    )
    .map_err(|_| PeerRuntimeError::Identity)
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
    response: Option<(u64, ResponseKind)>,
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
                response = self.responses.recv(), if self.response.is_none() => {
                    let Some(response) = response else { self.driver.abort(); return Ok(()); };
                    #[cfg(test)]
                    while self.state.hold_response.load(Ordering::Acquire) && self.state.live() {
                        self.driver
                            .observe_liveness()
                            .map_err(|_| PeerRuntimeError::Io)?;
                        tokio::time::sleep(POLL).await;
                    }
                    if !self.ready
                        || !self.state.live()
                        || !Arc::ptr_eq(&response.source, &self.state)
                    {
                        self.driver.abort();
                        return Err(PeerRuntimeError::Protocol);
                    }
                    let guard: Arc<dyn OutboundFrameGuard> = self.state.clone();
                    self.driver
                        .queue_guarded_frame(response.bytes, response.deadline, guard)
                        .map_err(|_| PeerRuntimeError::Io)?;
                    self.response = Some((response.id, response.kind));
                }
                event = self.driver.next_event() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(_) if !self.state.live() => return Ok(()),
                        Err(_) => return Err(PeerRuntimeError::Io),
                    };
                    match event {
                        SocketEvent::Ready => {
                            self.ready = true;
                            self.emit(PeerEvent::Ready).await?;
                        }
                        SocketEvent::Frame(frame) => {
                            if !self.ready || !self.state.live() {
                                return Err(PeerRuntimeError::Protocol);
                            }
                            let received = self.clock.now().map_err(|_| PeerRuntimeError::Clock)?;
                            self.emit(PeerEvent::Frame(PeerFrame {
                                source: Arc::clone(&self.state),
                                frame,
                                received,
                            }))
                            .await?;
                        }
                        SocketEvent::OutboundDrained => {
                            let (id, kind) =
                                self.response.take().ok_or(PeerRuntimeError::Protocol)?;
                            self.emit(PeerEvent::Drained { id, kind }).await?;
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
