// SPDX-License-Identifier: GPL-2.0-or-later
//! Real socket/framing ownership with a frozen enrollment association. No TOFU,
//! bare-frame promotion, generic outbound payload, native UI or approval API.
#![forbid(unsafe_code)]

mod delivery;
pub use delivery::{
    ApprovalSendOutcome, ApprovalSendTransition, ApprovalWriteProgress, QueuedApproval, SendIssue,
    SendRetry,
};

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use framed_transport::{
    ConnectionBudget, PeerTransport, SocketClock, SocketDriver, SocketError, SocketEvent,
    SocketLimits, SocketPending, TransportError,
};
use phone_request_core::{InboxClock, InboxIssue, ReceivingGeneration};
use secure_channel::{EndpointRole, TlsIdentity};
use service_protocol::{
    ClockCorrelation, ClockError, ClockProbe, PcEvent, PcEventError, PcPublicKey, VerifiedPcEvent,
    encode_frame,
};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::{
    CommittedUpdate, DurableFailure, DurableFault, DurableInbox, LocalKeySetDescriptor,
    PeerAssociation, PeerAssociationRef,
};

/// Already connected carrier and native-owned signer/clock, not enrollment.
/// Socket is declared first so it closes before the remaining inputs on error.
pub struct PcSocketInputs {
    pub socket: TcpStream,
    pub identity: TlsIdentity,
    pub budget: Arc<ConnectionBudget>,
    pub clock: Arc<dyn SocketClock>,
    pub limits: SocketLimits,
    pub stop: CancellationToken,
}

impl fmt::Debug for PcSocketInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PcSocketInputs([redacted], native_inputs_required)")
    }
}

struct PeerContext {
    active: AtomicBool,
    stop: CancellationToken,
    owner_epoch: Arc<()>,
    association: PeerAssociation,
    local_keys: LocalKeySetDescriptor,
    verification_key: PcPublicKey,
}

impl PeerContext {
    fn capture(
        owner: &DurableInbox,
        reference: PeerAssociationRef,
        stop: CancellationToken,
    ) -> Result<Self, PeerSocketError> {
        let association = owner
            .peer_associations()
            .map_err(PeerSocketError::Owner)?
            .resolve(reference)
            .ok_or(PeerSocketError::AssociationChanged)?
            .clone();
        let local_keys = owner
            .local_keys()
            .map_err(PeerSocketError::Owner)?
            .get(association.descriptor().local_key_handle())
            .and_then(|phase| phase.descriptor())
            .ok_or(PeerSocketError::LocalKeysChanged)?
            .clone();
        let verification_key =
            PcPublicKey::from_spki_der(association.descriptor().pc_signing_key().as_spki_der())
                .map_err(PeerSocketError::Protocol)?;
        Ok(Self {
            active: AtomicBool::new(true),
            stop,
            owner_epoch: owner.owner_epoch(),
            association,
            local_keys,
            verification_key,
        })
    }

    fn check_current(&self, owner: &DurableInbox) -> Result<(), PeerSocketError> {
        if !self.active.load(Ordering::Acquire) || self.stop.is_cancelled() {
            return Err(PeerSocketError::ConnectionClosed);
        }
        // An Arc is identity only, not liveness. Also check the current healthy
        // owner, complete immutable association and actual local tuple below.
        if !Arc::ptr_eq(&self.owner_epoch, &owner.owner_epoch()) {
            return Err(PeerSocketError::DifferentOwner);
        }
        if owner
            .peer_associations()
            .map_err(PeerSocketError::Owner)?
            .resolve(self.association.reference())
            != Some(&self.association)
        {
            return Err(PeerSocketError::AssociationChanged);
        }
        if owner
            .local_keys()
            .map_err(PeerSocketError::Owner)?
            .get(self.local_keys.handle())
            .and_then(|phase| phase.descriptor())
            != Some(&self.local_keys)
        {
            return Err(PeerSocketError::LocalKeysChanged);
        }
        Ok(())
    }
}

/// Produced only from this wrapper's actual peer-pinned TLS socket, complete
/// frame and application signature check. Not Clone and no public constructor.
/// It is queued evidence, not current authority; apply it through its connection
/// against the current owner. Merely retaining it cannot preserve enrollment.
pub struct ReceivedPcEvent {
    context: Arc<PeerContext>,
    verified: VerifiedPcEvent,
}

impl fmt::Debug for ReceivedPcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceivedPcEvent([redacted], current_context_required)")
    }
}

#[derive(Debug)]
pub enum PcSocketEvent {
    Ready,
    Message(Box<ReceivedPcEvent>),
    OutboundDrained,
    PeerClosed,
    LocallyClosed,
}

/// Committed receiving effects with their exact originating association. This
/// is not a request/approval plan. Native dispatch must apply effects and take
/// fresh time; downward withdrawal/history effects must not be lost even if the
/// connection subsequently closes. New display requires a fresh current check.
/// Future request ownership must retain the original source tuple,
/// not infer an old pending body's key from the newest association by PC ID.
#[must_use = "apply committed effects; this is neither native delivery nor signing authority"]
pub struct AssociatedUpdate {
    context: Arc<PeerContext>,
    committed: CommittedUpdate,
}

impl AssociatedUpdate {
    pub fn association(&self) -> &PeerAssociation {
        &self.context.association
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.context.local_keys
    }
    pub fn committed(&self) -> &CommittedUpdate {
        &self.committed
    }
    pub fn check_current(&self, owner: &DurableInbox) -> Result<(), PeerSocketError> {
        self.context.check_current(owner)
    }
}

impl fmt::Debug for AssociatedUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AssociatedUpdate([redacted], effects_not_authorization)")
    }
}

/// One current association, exact client key, server transport pin, application
/// verification key, pending clock probe and correlation share this owner.
/// Do not hold a DurableInbox/actor lock while awaiting next_event. Native host
/// revocation/close must promptly abort the matching socket; no background watcher
/// is spawned here. Every later queue/apply rechecks association and owner epoch.
/// The Application policy-only gate is unchanged; no startup connection is added.
pub struct AssociatedPcSocket {
    driver: SocketDriver,
    socket_clock: Arc<dyn SocketClock>,
    context: Arc<PeerContext>,
    probe: Option<ClockProbe>,
    correlation: Option<ClockCorrelation>,
    outbound_approval: Option<delivery::WriteState>,
}

impl fmt::Debug for AssociatedPcSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssociatedPcSocket")
            .field("pending", &self.driver.pending_counts())
            .field("clock_pending", &self.probe.is_some())
            .finish_non_exhaustive()
    }
}

impl AssociatedPcSocket {
    pub fn new(
        owner: &DurableInbox,
        reference: PeerAssociationRef,
        inputs: PcSocketInputs,
    ) -> Result<Self, PeerSocketError> {
        // Cancelling this connection must not cancel a caller's shared parent
        // token or unrelated PCs. Parent cancellation still reaches this child.
        let stop = inputs.stop.child_token();
        let context = Arc::new(PeerContext::capture(owner, reference, stop.clone())?);
        if inputs.identity.role() != EndpointRole::Client
            || inputs.identity.public_key() != context.local_keys.transport_key()
        {
            return Err(PeerSocketError::TransportIdentityMismatch);
        }
        let now = inputs
            .clock
            .now()
            .map_err(|_| PeerSocketError::Socket(SocketError::ClockUnavailable))?;
        let transport = PeerTransport::client(
            inputs.budget,
            inputs.identity,
            context.association.descriptor().pc_transport_key().clone(),
            now,
        )
        .map_err(|error| PeerSocketError::Socket(SocketError::Transport(error)))?;
        let socket_clock = Arc::clone(&inputs.clock);
        let driver = SocketDriver::new(inputs.socket, transport, inputs.clock, inputs.limits, stop)
            .map_err(PeerSocketError::Socket)?;
        Ok(Self {
            driver,
            socket_clock,
            context,
            probe: None,
            correlation: None,
            outbound_approval: None,
        })
    }

    pub fn pending_counts(&self) -> SocketPending {
        self.driver.pending_counts()
    }

    /// No domain owner borrow spans network waiting. Complete frames are decoded
    /// only with the frozen PC/key, never a later key looked up solely by PC ID.
    pub async fn next_event(&mut self) -> Result<PcSocketEvent, PeerSocketError> {
        self.ensure_open()?;
        let event = match self.driver.next_event().await {
            Ok(event) => event,
            Err(error) => {
                self.abort();
                return Err(PeerSocketError::Socket(error));
            }
        };
        self.ensure_open()?;
        match event {
            SocketEvent::Ready => Ok(PcSocketEvent::Ready),
            SocketEvent::Frame(frame) => {
                let verified = match VerifiedPcEvent::from_wire(
                    &frame.into_bytes(),
                    self.context.association.descriptor().pc(),
                    &self.context.verification_key,
                ) {
                    Ok(verified) => verified,
                    Err(error) => {
                        self.abort();
                        return Err(PeerSocketError::Protocol(error));
                    }
                };
                self.ensure_open()?;
                Ok(PcSocketEvent::Message(Box::new(ReceivedPcEvent {
                    context: Arc::clone(&self.context),
                    verified,
                })))
            }
            SocketEvent::OutboundDrained => {
                if let Some(write) = self.outbound_approval.take() {
                    write.written();
                }
                Ok(PcSocketEvent::OutboundDrained)
            }
            SocketEvent::PeerClosed => {
                self.abort();
                Ok(PcSocketEvent::PeerClosed)
            }
            SocketEvent::LocallyClosed => {
                self.abort();
                Ok(PcSocketEvent::LocallyClosed)
            }
        }
    }

    /// Native processing-time observation, never UI/peer time. A failed queue
    /// drops this new probe; retry cannot reuse it. No arbitrary outbound method.
    pub fn queue_clock_probe(
        &mut self,
        owner: &DurableInbox,
        clock: InboxClock,
    ) -> Result<(), PeerSocketError> {
        self.check_current(owner)?;
        if self.probe.is_some() {
            return Err(PeerSocketError::ProbePending);
        }
        let probe = ClockProbe::start(
            self.context.association.descriptor().pc(),
            clock.phone_monotonic_nanos(),
        )
        .map_err(PeerSocketError::Clock)?;
        let frame = encode_frame(&probe.request().to_wire())
            .map_err(|_| PeerSocketError::InvalidClockFrame)?;
        if let Err(error) = self.driver.queue_frame(frame) {
            if !matches!(
                error,
                SocketError::Transport(TransportError::Busy | TransportError::NotReady)
            ) {
                self.abort();
            }
            return Err(PeerSocketError::Socket(error));
        }
        self.ensure_open()?;
        self.probe = Some(probe);
        Ok(())
    }

    /// Apply only messages from THIS socket/association to THIS healthy owner.
    /// Stale/foreign context is rejected before a domain intent or clock update.
    /// Raw clock objects never leave this wrapper or enter through its API.
    pub fn apply_event(
        &mut self,
        owner: &mut DurableInbox,
        message: ReceivedPcEvent,
        clock: InboxClock,
    ) -> Result<AssociatedUpdate, PeerSocketError> {
        if !Arc::ptr_eq(&self.context, &message.context) {
            return Err(PeerSocketError::DifferentConnection);
        }
        self.check_current(owner)?;
        if message.verified.verification_key() != &self.context.verification_key {
            self.abort();
            return Err(PeerSocketError::VerificationKeyMismatch);
        }
        let result = (|| {
            let generation =
                ReceivingGeneration::from_trusted_owner(self.context.association.generation())
                    .map_err(|_| PeerSocketError::AssociationChanged)?;
            match message.verified.event() {
                PcEvent::Clock { .. } => {
                    let probe = self.probe.take().ok_or(PeerSocketError::UnexpectedClock)?;
                    let correlation = probe
                        .complete(&message.verified, clock.phone_monotonic_nanos())
                        .map_err(PeerSocketError::Clock)?;
                    let changed_queued_epoch = self.outbound_approval.is_some()
                        && self
                            .correlation
                            .as_ref()
                            .is_some_and(|previous| previous.epoch() != correlation.epoch());
                    let update = owner
                        .observe_service_clock(&correlation, clock)
                        .map_err(PeerSocketError::Persistence)?;
                    if changed_queued_epoch {
                        // Preserve the committed clock update, but never write
                        // an old-service-epoch approval suffix after this change.
                        self.abort();
                    } else {
                        self.correlation = Some(correlation);
                    }
                    Ok(update)
                }
                PcEvent::Opened { .. } => owner
                    .receive_opened_from(
                        &message.verified,
                        generation,
                        self.correlation
                            .as_mut()
                            .ok_or(PeerSocketError::ClockRequired)?,
                        clock,
                    )
                    .map_err(receiving_error),
                PcEvent::Resolved { .. } => owner
                    .resolve_pc_from(
                        &message.verified,
                        generation,
                        self.correlation
                            .as_mut()
                            .ok_or(PeerSocketError::ClockRequired)?,
                        clock,
                    )
                    .map_err(receiving_error),
            }
        })();
        match result {
            Ok(committed) => {
                if committed.update().fault().is_some() {
                    self.abort();
                }
                Ok(AssociatedUpdate {
                    context: Arc::clone(&self.context),
                    committed,
                })
            }
            // A well-authenticated but mismatched old request is a pre-intent
            // rejection, not permission to destroy this peer's current clock
            // or other valid work. No body/effect escapes this rejected event.
            Err(error @ PeerSocketError::ReceivingSource(_)) => Err(error),
            Err(error) => {
                self.abort();
                Err(error)
            }
        }
    }

    pub fn check_current(&mut self, owner: &DurableInbox) -> Result<(), PeerSocketError> {
        self.ensure_open()?;
        if let Err(error) = self.context.check_current(owner) {
            self.abort();
            return Err(error);
        }
        Ok(())
    }

    /// Downward only; never clears replay guards, history, keys or association.
    pub fn abort(&mut self) {
        if let Some(write) = self.outbound_approval.take() {
            write.stopped();
        }
        self.context.active.store(false, Ordering::Release);
        self.context.stop.cancel();
        self.probe.take();
        self.correlation.take();
        self.driver.abort();
    }

    fn ensure_open(&mut self) -> Result<(), PeerSocketError> {
        if !self.context.active.load(Ordering::Acquire) {
            return Err(PeerSocketError::ConnectionClosed);
        }
        if self.context.stop.is_cancelled() {
            self.abort();
            return Err(PeerSocketError::Socket(SocketError::Cancelled));
        }
        Ok(())
    }
}

impl Drop for AssociatedPcSocket {
    fn drop(&mut self) {
        self.abort();
    }
}

fn receiving_error(error: crate::RequestSourceFailure) -> PeerSocketError {
    match error {
        crate::RequestSourceFailure::Rejected(issue) => PeerSocketError::ReceivingSource(issue),
        crate::RequestSourceFailure::Owner(failure) => PeerSocketError::Persistence(failure),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeerSocketError {
    #[error("the message does not match the request's original receiving source")]
    ReceivingSource(InboxIssue),
    #[error("the originating connection was cancelled, closed or failed")]
    ConnectionClosed,
    #[error("peer context belongs to another owner instance")]
    DifferentOwner,
    #[error("event belongs to another connection")]
    DifferentConnection,
    #[error("peer association is no longer current")]
    AssociationChanged,
    #[error("local key tuple no longer matches the peer association")]
    LocalKeysChanged,
    #[error("the native client transport identity does not match the local transport key")]
    TransportIdentityMismatch,
    #[error("the event verification key does not match the frozen PC key")]
    VerificationKeyMismatch,
    #[error("a clock probe is already pending")]
    ProbePending,
    #[error("clock response has no matching pending probe")]
    UnexpectedClock,
    #[error("a current connection-bound clock correlation is required")]
    ClockRequired,
    #[error("the fixed clock frame could not be encoded")]
    InvalidClockFrame,
    #[error("the durable owner is unavailable")]
    Owner(DurableFault),
    #[error("the durable transition failed")]
    Persistence(DurableFailure),
    #[error("socket operation failed")]
    Socket(SocketError),
    #[error("PC message verification failed")]
    Protocol(PcEventError),
    #[error("connection-bound clock observation failed")]
    Clock(ClockError),
}
