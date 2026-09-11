// SPDX-License-Identifier: GPL-2.0-or-later
//! Private ServiceSession-owned rendezvous producer. Bound matches original
//! native transport owners only. A fixed pre-Offer policy watch permits one
//! private preparation, NOT a consent receipt or QR/enrollment/signing grant.
#![forbid(unsafe_code)]

use super::enrollment::{
    EnrollmentCarrier, EnrollmentInputs, EnrollmentProgress, ExpectedOriginal,
};
use crate::{
    PairingPeerError, PairingPipe, PairingPipeProgress, PairingServerEndpoints, PendingElevationId,
    RendererInvocation,
    ffi::{
        AttemptWindow, ListenProgress, RendererRegistration, StarterAdmission,
        UnboundPairingListener, check_renderer_cutoff, renderer_original_cutoff,
    },
    pairing_handoff::{
        ComparisonDigits, Frame, InvitationText, RendererProcess, RendererRequest, ServiceHandoff,
        ServiceSide,
    },
    startup_phase::ScmReadyPermit,
};
use android_attestation::VerificationPolicy;
use approval_core::RegistryCheckpoint;
use approval_protocol::{BootEpoch, DeviceId, PcIdentity};
use relay_service::RouteId;
use secure_channel::TlsPublicKey;
use service_protocol::{
    PairingComparisonCode, PairingInvitation, PairingInvitationFields, SignedEnrollmentAcceptance,
    SignedFrozenCandidate,
};
use std::{
    fmt,
    time::{Duration, Instant},
};

const CLOSE_RESERVE: Duration = Duration::from_secs(30);
mod ceremony;
use ceremony::{Context as CeremonyContext, Origin, OriginalCeremony, PreparationError};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Dormant,
    Listening,
    Active,
    Draining,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Native(PairingPeerError),
    Protocol,
    Random,
    Epoch,
    Window,
    Cancelled,
    Generation,
    Preparation(PreparationError),
    Identity,
    RelayUnconfigured,
    SignerPolicyUnavailable,
    Enrollment,
}
impl From<PairingPeerError> for Failure {
    fn from(error: PairingPeerError) -> Self {
        Self::Native(error)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Io {
    Connect,
    OfferWrite,
    StarterRead,
    HelperRead,
    BoundWrite,
    CloseWrite,
    AckRead,
    Idle,
    RendererPrepareWrite,
    RendererRegisterWrite,
    RendererParentRead,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RendererParent {
    PrepareWrite,
    AwaitLaunch,
    RegisterWrite,
    Done,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum RendererIo {
    Connect,
    HelloRead,
    ObjectsRead,
    BoundWrite,
    Idle,
    InvitationWrite,
    ComparisonWrite,
    DecisionRead,
    OutcomeWrite,
    CloseWrite,
    AckRead,
    Acknowledged,
    TransportClosed,
    Drained,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentAction {
    Invitation,
    Comparison,
    Outcome,
}

pub(super) enum CeremonyAction {
    SignFrozen(Box<service_protocol::UnsignedFrozenCandidate>),
    Commit {
        relay: std::net::SocketAddr,
        route: RouteId,
    },
    Enrolled(DeviceId),
    Failed,
}
pub(super) struct RendererRun {
    request: RendererRequest,
    pipe: PairingPipe,
    registration: RendererRegistration,
    parent: RendererParent,
    io: RendererIo,
    invitation_sent: bool,
    comparison_sent: bool,
    decision_received: bool,
    decision: Option<bool>,
    outcome_sent: bool,
    cleanup_failed: bool,
}
impl RendererRun {
    fn awaiting_parent(&self) -> bool {
        matches!(
            self.parent,
            RendererParent::PrepareWrite | RendererParent::AwaitLaunch
        )
    }
    fn accept_parent(
        &mut self,
        parent: &mut PairingPipe,
        request: RendererRequest,
        process: RendererProcess,
    ) -> Result<Frame, Failure> {
        if self.parent != RendererParent::AwaitLaunch
            || request.invocation != self.request.invocation
            || request.cutoff == 0
            || request.cutoff > self.request.cutoff
        {
            return Err(Failure::Protocol);
        }
        check_renderer_cutoff(request.cutoff)?;
        self.request = request; // One conservative narrowing, never a renewed timer.
        self.registration.register(parent, process)?;
        check_renderer_cutoff(request.cutoff)?;
        self.parent = RendererParent::RegisterWrite;
        Ok(Frame::RendererRegistered(request))
    }
    fn ready_idle(&self) -> bool {
        self.parent == RendererParent::Done
            && self.io == RendererIo::Idle
            && self.registration.objects_bound()
    }
    fn content_state_allows(
        io: RendererIo,
        invitation_sent: bool,
        comparison_sent: bool,
        outcome_sent: bool,
        action: ContentAction,
    ) -> bool {
        if io != RendererIo::Idle {
            return false;
        }
        match action {
            ContentAction::Invitation => !invitation_sent,
            ContentAction::Comparison => invitation_sent && !comparison_sent,
            // A failure outcome is also legal when relay or policy setup fails
            // before an invitation can be shown. Success still follows both confirmations.
            ContentAction::Outcome => !outcome_sent,
        }
    }
    pub(super) fn ready_for_invitation(&self) -> bool {
        self.parent == RendererParent::Done
            && self.registration.objects_bound()
            && Self::content_state_allows(
                self.io,
                self.invitation_sent,
                self.comparison_sent,
                self.outcome_sent,
                ContentAction::Invitation,
            )
    }
    pub(super) fn send_invitation(&mut self, text: &InvitationText) -> Result<(), Failure> {
        if !self.ready_for_invitation() {
            return Err(Failure::Protocol);
        }
        self.begin_renderer_write(
            Frame::RendererInvitation {
                invocation: self.request.invocation,
                text: text.clone(),
            },
            RendererIo::InvitationWrite,
        )?;
        self.invitation_sent = true;
        Ok(())
    }
    pub(super) fn send_comparison(&mut self, code: &PairingComparisonCode) -> Result<(), Failure> {
        if !self.ready_idle()
            || !Self::content_state_allows(
                self.io,
                self.invitation_sent,
                self.comparison_sent,
                self.outcome_sent,
                ContentAction::Comparison,
            )
        {
            return Err(Failure::Protocol);
        }
        let code = ComparisonDigits::from_code(code).map_err(|_| Failure::Protocol)?;
        self.begin_renderer_write(
            Frame::RendererComparison {
                invocation: self.request.invocation,
                code,
            },
            RendererIo::ComparisonWrite,
        )?;
        self.comparison_sent = true;
        Ok(())
    }
    pub(super) fn take_decision(&mut self) -> Option<bool> {
        self.decision.take()
    }
    pub(super) fn send_outcome(&mut self, enrolled: bool) -> Result<(), Failure> {
        if !self.ready_idle()
            || !Self::content_state_allows(
                self.io,
                self.invitation_sent,
                self.comparison_sent,
                self.outcome_sent,
                ContentAction::Outcome,
            )
        {
            return Err(Failure::Protocol);
        }
        self.begin_renderer_write(
            Frame::RendererOutcome {
                invocation: self.request.invocation,
                enrolled,
            },
            RendererIo::OutcomeWrite,
        )?;
        self.outcome_sent = true;
        Ok(())
    }
    fn begin_renderer_write(&mut self, frame: Frame, next: RendererIo) -> Result<(), Failure> {
        if self.io != RendererIo::Idle {
            return Err(Failure::Protocol);
        }
        self.registration.check_connected(&mut self.pipe)?;
        self.pipe
            .begin_write(&frame.encode().map_err(|_| Failure::Protocol)?)?;
        self.io = next;
        Ok(())
    }
    fn begin_close(&mut self) -> Result<(), Failure> {
        if !self.ready_idle() {
            return Err(Failure::Protocol);
        }
        self.registration.check_connected(&mut self.pipe)?;
        self.pipe.begin_write(
            &Frame::Close(self.request.invocation.pending())
                .encode()
                .map_err(|_| Failure::Protocol)?,
        )?;
        self.io = RendererIo::CloseWrite;
        Ok(())
    }
    fn poll(&mut self, work_end: Instant) -> Result<(), Failure> {
        if self.io == RendererIo::Drained {
            return Ok(());
        }
        if self.io == RendererIo::TransportClosed {
            if self.registration.drain()? {
                self.io = RendererIo::Drained;
                if let Some(error) = self.registration.failure() {
                    return Err(Failure::Native(error));
                }
            }
            return Ok(());
        }
        check_renderer_cutoff(self.request.cutoff)?;
        let closing = matches!(
            self.io,
            RendererIo::CloseWrite | RendererIo::AckRead | RendererIo::Acknowledged
        );
        if !closing && Instant::now() >= work_end {
            return Err(Failure::Window);
        }
        if self.io == RendererIo::Acknowledged {
            self.registration.check_connected(&mut self.pipe)?;
            return Ok(());
        }
        let progress = self.pipe.poll()?;
        check_renderer_cutoff(self.request.cutoff)?;
        match (self.io, progress) {
            (_, PairingPipeProgress::Pending) => (),
            (RendererIo::Connect, PairingPipeProgress::Connected) => {
                self.registration.check_connected(&mut self.pipe)?;
                self.pipe.begin_read()?;
                self.io = RendererIo::HelloRead;
            }
            (RendererIo::HelloRead, PairingPipeProgress::Read(bytes)) => {
                if Frame::decode(&bytes).map_err(|_| Failure::Protocol)?
                    != Frame::RendererHello(self.request)
                {
                    return Err(Failure::Protocol);
                }
                self.registration.check_connected(&mut self.pipe)?;
                self.pipe.begin_read()?;
                self.io = RendererIo::ObjectsRead;
            }
            (RendererIo::ObjectsRead, PairingPipeProgress::Read(bytes)) => {
                let Frame::RendererObjects {
                    invocation,
                    objects,
                } = Frame::decode(&bytes).map_err(|_| Failure::Protocol)?
                else {
                    return Err(Failure::Protocol);
                };
                if invocation != self.request.invocation {
                    return Err(Failure::Protocol);
                }
                self.registration
                    .bind_objects(&mut self.pipe, invocation, objects)?;
                if Instant::now() >= work_end {
                    return Err(Failure::Window);
                }
                check_renderer_cutoff(self.request.cutoff)?;
                self.pipe.begin_write(
                    &Frame::RendererBound(self.request)
                        .encode()
                        .map_err(|_| Failure::Protocol)?,
                )?;
                self.io = RendererIo::BoundWrite;
            }
            (RendererIo::BoundWrite, PairingPipeProgress::Written) => {
                self.registration.check_connected(&mut self.pipe)?;
                if Instant::now() >= work_end {
                    return Err(Failure::Window);
                }
                self.io = RendererIo::Idle;
            }
            (RendererIo::Idle, PairingPipeProgress::Idle) => {
                self.registration.check_connected(&mut self.pipe)?;
                self.pipe.check_input_quiet()?;
            }
            (RendererIo::InvitationWrite, PairingPipeProgress::Written)
            | (RendererIo::OutcomeWrite, PairingPipeProgress::Written) => {
                self.registration.check_connected(&mut self.pipe)?;
                self.io = RendererIo::Idle;
            }
            (RendererIo::ComparisonWrite, PairingPipeProgress::Written) => {
                self.registration.check_connected(&mut self.pipe)?;
                self.pipe.begin_read()?;
                self.io = RendererIo::DecisionRead;
            }
            (RendererIo::DecisionRead, PairingPipeProgress::Read(bytes)) => {
                let Frame::RendererDecision {
                    invocation,
                    confirmed,
                } = Frame::decode(&bytes).map_err(|_| Failure::Protocol)?
                else {
                    return Err(Failure::Protocol);
                };
                if invocation != self.request.invocation || self.decision_received {
                    return Err(Failure::Protocol);
                }
                self.registration.check_connected(&mut self.pipe)?;
                self.decision_received = true;
                self.decision = Some(confirmed);
                self.io = RendererIo::Idle;
            }
            (RendererIo::CloseWrite, PairingPipeProgress::Written) => {
                self.pipe.begin_read()?;
                self.io = RendererIo::AckRead;
            }
            (RendererIo::AckRead, PairingPipeProgress::Read(bytes)) => {
                if Frame::decode(&bytes).map_err(|_| Failure::Protocol)?
                    != Frame::CloseAck(self.request.invocation.pending())
                {
                    return Err(Failure::Protocol);
                }
                self.registration.check_connected(&mut self.pipe)?;
                self.io = RendererIo::Acknowledged;
            }
            _ => return Err(Failure::Protocol),
        }
        check_renderer_cutoff(self.request.cutoff)?;
        Ok(())
    }
    fn acknowledged(&self) -> bool {
        matches!(
            self.io,
            RendererIo::Acknowledged | RendererIo::TransportClosed | RendererIo::Drained
        )
    }
    fn close_transport_after_all_acks(&mut self) -> Result<(), Failure> {
        if self.io == RendererIo::Acknowledged {
            // Normal identities were checked while all three clients remained
            // alive. This cleanup EOF allows renderer exit; parents stay owned.
            if !self.pipe.drain()? {
                return Err(Failure::Protocol);
            }
            self.io = RendererIo::TransportClosed;
        } else if !matches!(self.io, RendererIo::TransportClosed | RendererIo::Drained) {
            return Err(Failure::Protocol);
        }
        Ok(())
    }
    fn cancel(&mut self) {
        self.pipe.cancel();
    }
    fn drain(&mut self) {
        self.pipe.cancel();
        let pipe_failed = self.pipe.drain().is_err();
        let registration_failed = self.registration.drain().is_err();
        self.cleanup_failed |= pipe_failed || registration_failed;
    }
    fn remaining_owners(&self) -> usize {
        usize::from(!self.pipe.is_drained()) + usize::from(!self.registration.is_drained())
    }
}
fn all_participants_acknowledged(originals: bool, renderer: Option<bool>) -> bool {
    originals && renderer.unwrap_or(true)
}
enum Channel {
    Listener(UnboundPairingListener),
    Pipe {
        pipe: PairingPipe,
        io: Io,
    },
    #[cfg(test)]
    Fixture(FixtureChannel),
}
#[cfg(test)]
struct FixtureChannel {
    polls_left: usize,
    drained: bool,
    cancelled: bool,
    fail: bool,
    idle: bool,
}
impl Channel {
    fn listener(&mut self) -> Result<&mut UnboundPairingListener, Failure> {
        match self {
            Self::Listener(value) => Ok(value),
            _ => Err(Failure::Protocol),
        }
    }
    fn pipe(&mut self) -> Result<(&mut PairingPipe, &mut Io), Failure> {
        match self {
            Self::Pipe { pipe, io } => Ok((pipe, io)),
            _ => Err(Failure::Protocol),
        }
    }
    fn idle(&self) -> bool {
        match self {
            Self::Pipe { io: Io::Idle, .. } => true,
            #[cfg(test)]
            Self::Fixture(value) => value.idle,
            _ => false,
        }
    }
    fn cancel(&mut self) {
        match self {
            Self::Listener(value) => value.cancel(),
            Self::Pipe { pipe, .. } => pipe.cancel(),
            #[cfg(test)]
            Self::Fixture(value) => value.cancelled = true,
        }
    }
    fn drain(&mut self) -> Result<bool, PairingPeerError> {
        match self {
            Self::Listener(value) => value.drain(),
            Self::Pipe { pipe, .. } => pipe.drain(),
            #[cfg(test)]
            Self::Fixture(value) => {
                assert!(value.cancelled);
                if value.fail {
                    Err(PairingPeerError::CleanupUnconfirmed)
                } else if value.polls_left != 0 {
                    value.polls_left -= 1;
                    Ok(false)
                } else {
                    value.drained = true;
                    Ok(true)
                }
            }
        }
    }
    fn drained(&self) -> bool {
        match self {
            Self::Listener(value) => value.is_drained(),
            Self::Pipe { pipe, .. } => pipe.is_drained(),
            #[cfg(test)]
            Self::Fixture(value) => value.drained,
        }
    }
    fn cleanup_failed(&self) -> bool {
        match self {
            Self::Listener(value) => value.cleanup_failure().is_some(),
            Self::Pipe { pipe, .. } => pipe.cleanup_failure().is_some(),
            #[cfg(test)]
            Self::Fixture(value) => value.fail,
        }
    }
}

pub(super) struct ServicePairing {
    state: State,
    enabled: bool,
    epoch: Option<BootEpoch>,
    next_generation: Option<u64>,
    generation: Option<u64>,
    starter: Option<Channel>,
    helper: Option<Channel>,
    admission: Option<StarterAdmission>,
    window: Option<AttemptWindow>,
    protocol: Option<ServiceHandoff>,
    pending_id: Option<PendingElevationId>,
    preparation: Option<OriginalCeremony>,
    renderer: Option<RendererRun>,
    enrollment: Option<EnrollmentCarrier>,
    enrollment_route: Option<(std::net::SocketAddr, RouteId)>,
    enrollment_failed: bool,
    enrollment_terminal: bool,
    enrollment_reported: bool,
    commit_requested: bool,
    committed_device: Option<DeviceId>,
    renderer_attempted: bool,
    next_side: ServiceSide,
    first_failure: Option<Failure>,
    cleanup_failed: bool,
    rearm: bool,
}
impl fmt::Debug for ServicePairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServicePairing")
            .field("state", &self.state)
            .field("first_failure", &self.first_failure)
            .field("cleanup_failed", &self.cleanup_failed)
            .finish_non_exhaustive()
    }
}
impl ServicePairing {
    pub(super) fn dormant() -> Self {
        Self {
            state: State::Dormant,
            enabled: false,
            epoch: None,
            next_generation: Some(1),
            generation: None,
            starter: None,
            helper: None,
            admission: None,
            window: None,
            protocol: None,
            pending_id: None,
            preparation: None,
            renderer: None,
            enrollment: None,
            enrollment_route: None,
            enrollment_failed: false,
            enrollment_terminal: false,
            enrollment_reported: false,
            commit_requested: false,
            committed_device: None,
            renderer_attempted: false,
            next_side: ServiceSide::Starter,
            first_failure: None,
            cleanup_failed: false,
            rearm: false,
        }
    }
    pub(super) fn activate(
        &mut self,
        _ready: ScmReadyPermit,
        epoch: BootEpoch,
    ) -> Result<(), super::PeerRuntimeError> {
        if self.state != State::Dormant || self.enabled {
            return Err(super::PeerRuntimeError::Protocol);
        }
        self.enabled = true;
        self.epoch = Some(epoch);
        if crate::entry::stop_requested() {
            self.shutdown();
            return Ok(());
        }
        if let Err(error) = self.arm() {
            self.retire(Some(error), false);
        }
        if crate::entry::stop_requested() {
            self.shutdown();
        }
        Ok(())
    }
    fn arm(&mut self) -> Result<(), Failure> {
        self.ensure_running()?;
        if !self.enabled
            || crate::entry::stop_requested()
            || self.remaining_owners() != 0
            || self.cleanup_failed
        {
            return Err(Failure::Cancelled);
        }
        if !matches!(self.state, State::Dormant | State::Draining)
            || self.starter.is_some()
            || self.helper.is_some()
            || self.admission.is_some()
            || self.window.is_some()
            || self.protocol.is_some()
            || self.pending_id.is_some()
            || self.preparation.is_some()
            || self.renderer.is_some()
            || self.enrollment.is_some()
            || self.enrollment_route.is_some()
            || self.enrollment_failed
            || self.enrollment_terminal
            || self.enrollment_reported
            || self.commit_requested
            || self.committed_device.is_some()
            || self.renderer_attempted
        {
            return Err(Failure::Protocol);
        }
        let pair = PairingServerEndpoints::create_for_running_service()?;
        let (starter, helper) = pair.into_servers();
        self.starter = Some(Channel::Listener(starter.into_unbound_listener()?));
        self.helper = Some(Channel::Listener(helper.into_unbound_listener()?));
        self.ensure_running()?;
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .begin_connect()?;
        self.helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .begin_connect()?;
        self.ensure_running()?;
        self.state = State::Listening;
        self.first_failure = None;
        self.ensure_running()
    }
    pub(super) fn poll(&mut self, epoch: BootEpoch, now: Instant) {
        if matches!(self.state, State::Dormant | State::Unavailable) {
            return;
        }
        if !self.enabled || crate::entry::stop_requested() {
            self.shutdown();
        }
        if self.epoch != Some(epoch) {
            self.retire(Some(Failure::Epoch), false);
        }
        if self.state == State::Draining {
            self.drain_step();
            return;
        }
        let result = match self.state {
            State::Listening => self.listen_step(),
            State::Active => self.active_step(now),
            _ => Ok(()),
        };
        if let Err(error) = result {
            self.retire(Some(error), true);
        }
    }
    fn listen_step(&mut self) -> Result<(), Failure> {
        self.ensure_running()?;
        let starter = self
            .starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .poll_connect()?;
        if starter == ListenProgress::Pending {
            if self
                .helper
                .as_mut()
                .ok_or(Failure::Protocol)?
                .listener()?
                .poll_connect()?
                == ListenProgress::Connected
            {
                return Err(Failure::Protocol);
            }
            return Ok(());
        }
        let admission = self
            .starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .admit_starter()?;
        self.admission = Some(admission); // Retain before any fallible Helper transfer.
        self.ensure_running()?;
        let helper = self
            .helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .bind_helper(self.admission.as_mut().ok_or(Failure::Protocol)?)?;
        self.helper = Some(Channel::Pipe {
            pipe: helper,
            io: Io::Connect,
        });
        self.ensure_running()?;
        let (starter, window) = self
            .admission
            .as_mut()
            .ok_or(Failure::Protocol)?
            .take_parts()?;
        self.starter = Some(Channel::Pipe {
            pipe: starter,
            io: Io::Idle,
        });
        self.window = Some(window);
        drop(self.admission.take());
        self.ensure_running()?;
        let generation = self.next_generation.take().ok_or(Failure::Generation)?;
        self.next_generation = generation.checked_add(1);
        self.generation = Some(generation);
        // Fixed actual policy watch must be current before any Offer permits
        // the original GUI to enter its one native helper launch.
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .prepare_uac_policy()?;
        self.check_window(Instant::now())?;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Failure::Random)?;
        self.check_window(Instant::now())?;
        let id = PendingElevationId::from_bytes(bytes).map_err(|_| Failure::Random)?;
        self.pending_id = Some(id);
        self.preparation = Some(OriginalCeremony::new());
        self.protocol = Some(ServiceHandoff::new(id));
        self.state = State::Active;
        self.check_window(Instant::now())?;
        let offer = self
            .protocol
            .as_ref()
            .ok_or(Failure::Protocol)?
            .offer()
            .map_err(|_| Failure::Protocol)?;
        self.write(ServiceSide::Starter, offer, Io::OfferWrite)?;
        Ok(())
    }
    fn channel(&mut self, side: ServiceSide) -> Result<&mut Channel, Failure> {
        match side {
            ServiceSide::Starter => self.starter.as_mut(),
            ServiceSide::Helper => self.helper.as_mut(),
        }
        .ok_or(Failure::Protocol)
    }
    fn write(&mut self, side: ServiceSide, frame: Frame, operation: Io) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.check_policy()?;
        if matches!(
            frame,
            Frame::Offer(_)
                | Frame::Bound(_)
                | Frame::PrepareRenderer(_)
                | Frame::RendererRegistered(_)
        ) && Instant::now() >= self.close_at()?
        {
            return Err(Failure::Window);
        }
        let bytes = frame.encode().map_err(|_| Failure::Protocol)?;
        let (pipe, io) = self.channel(side)?.pipe()?;
        if *io != Io::Idle {
            return Err(Failure::Protocol);
        }
        pipe.begin_write(&bytes)?;
        *io = operation;
        self.check_window(Instant::now())?;
        self.check_policy()
    }
    fn read(&mut self, side: ServiceSide, operation: Io) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.check_policy()?;
        let (pipe, io) = self.channel(side)?.pipe()?;
        if *io != Io::Idle {
            return Err(Failure::Protocol);
        }
        pipe.begin_read()?;
        *io = operation;
        self.check_window(Instant::now())?;
        self.check_policy()
    }
    fn ensure_running(&self) -> Result<(), Failure> {
        self.ensure_running_with(crate::entry::stop_requested)
    }
    // Private pure observation seam for deterministic fixtures. Production
    // always uses the actual service latch above, never a caller trust flag.
    fn ensure_running_with(&self, stopped: impl FnOnce() -> bool) -> Result<(), Failure> {
        if !self.enabled || stopped() {
            Err(Failure::Cancelled)
        } else {
            Ok(())
        }
    }
    fn check_window(&self, now: Instant) -> Result<(), Failure> {
        self.ensure_running()?;
        if self.generation.is_none_or(|generation| generation == 0) {
            return Err(Failure::Generation);
        }
        let window = self.window.as_ref().ok_or(Failure::Protocol)?;
        if now < window.started() || now >= window.deadline() {
            Err(Failure::Window)
        } else {
            self.ensure_running()
        }
    }
    fn close_at(&self) -> Result<Instant, Failure> {
        self.window
            .as_ref()
            .ok_or(Failure::Protocol)?
            .deadline()
            .checked_sub(CLOSE_RESERVE)
            .ok_or(Failure::Window)
    }
    fn check_policy(&mut self) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .check_uac_policy()?;
        self.check_window(Instant::now())
    }
    fn check_pair_live(&mut self) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.check_policy()?;
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .check_live()?;
        self.helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .check_live()?;
        self.check_window(Instant::now())?;
        self.check_policy()
    }
    fn match_pair(&mut self) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.check_policy()?;
        let (pid, created) = self
            .protocol
            .as_ref()
            .and_then(ServiceHandoff::candidate)
            .ok_or(Failure::Protocol)?;
        let starter = self.starter.as_mut().ok_or(Failure::Protocol)?.pipe()?.0;
        let helper = self.helper.as_mut().ok_or(Failure::Protocol)?.pipe()?.0;
        helper.match_launched_helper(starter, pid, created)?;
        starter.check_input_quiet()?;
        // Exactly one registered-parent reply may race our observed Prepare
        // write completion. All other idle helper input stays forbidden.
        if !self
            .renderer
            .as_ref()
            .is_some_and(RendererRun::awaiting_parent)
        {
            helper.check_input_quiet()?;
        }
        self.check_window(Instant::now())?;
        self.check_policy()
    }
    fn active_step(&mut self, now: Instant) -> Result<(), Failure> {
        self.check_window(now)?;
        self.check_pair_live()?;
        if self.protocol.as_ref().is_some_and(ServiceHandoff::is_bound) {
            self.match_pair()?;
        }
        let close_at = self.close_at()?;
        if Instant::now() >= close_at
            && !self
                .protocol
                .as_ref()
                .ok_or(Failure::Protocol)?
                .is_closing()
        {
            if self.enrollment.is_some() && !self.enrollment_terminal {
                return Err(Failure::Window);
            }
            if !self.protocol.as_ref().is_some_and(ServiceHandoff::is_bound)
                || !self.both_idle()
                || self
                    .renderer
                    .as_ref()
                    .is_some_and(|renderer| !renderer.ready_idle())
            {
                return Err(Failure::Window);
            }
            self.match_pair()?;
            if let Some(preparation) = self.preparation.as_mut() {
                preparation.invalidate();
            }
            self.protocol
                .as_mut()
                .ok_or(Failure::Protocol)?
                .start_close()
                .map_err(|_| Failure::Protocol)?;
            if let Some(renderer) = self.renderer.as_mut()
                && !matches!(
                    renderer.io,
                    RendererIo::CloseWrite
                        | RendererIo::AckRead
                        | RendererIo::Acknowledged
                        | RendererIo::TransportClosed
                        | RendererIo::Drained
                )
            {
                renderer.begin_close()?;
            }
        }
        let side = self.next_side;
        self.next_side = match side {
            ServiceSide::Starter => ServiceSide::Helper,
            ServiceSide::Helper => ServiceSide::Starter,
        };
        self.poll_side(side)?;
        if let Some(renderer) = self.renderer.as_mut() {
            renderer.poll(close_at)?;
        }
        self.check_policy()?;
        self.check_window(Instant::now())?;
        let original_acks = self
            .protocol
            .as_ref()
            .is_some_and(ServiceHandoff::both_acknowledged);
        if all_participants_acknowledged(
            original_acks,
            self.renderer.as_ref().map(RendererRun::acknowledged),
        ) {
            if let Some(renderer) = self.renderer.as_mut() {
                renderer.close_transport_after_all_acks()?;
                if renderer.io != RendererIo::Drained {
                    return Ok(());
                }
            }
            // BOTH normal post-read native fences have completed while clients
            // remain live. Only now may either original pipe be closed.
            self.retire(None, true);
            return Ok(());
        }
        if self
            .protocol
            .as_ref()
            .is_some_and(ServiceHandoff::is_closing)
        {
            if self.channel(side)?.idle()
                && let Ok(close) = self
                    .protocol
                    .as_ref()
                    .ok_or(Failure::Protocol)?
                    .close_frame(side)
            {
                self.write(side, close, Io::CloseWrite)?;
            }
            return Ok(());
        }
        let ready_to_match = self
            .protocol
            .as_ref()
            .is_some_and(|model| !model.is_matched() && model.candidate().is_some());
        if ready_to_match {
            self.match_pair()?;
            self.protocol
                .as_mut()
                .ok_or(Failure::Protocol)?
                .confirm_match()
                .map_err(|_| Failure::Protocol)?;
            self.check_window(Instant::now())?;
        }
        if self.channel(side)?.idle()
            && let Ok(bound) = self
                .protocol
                .as_ref()
                .ok_or(Failure::Protocol)?
                .bound_frame(side)
        {
            self.match_pair()?;
            self.write(side, bound, Io::BoundWrite)?;
            self.match_pair()?;
        }
        Ok(())
    }
    /// Scheduling only; the private mutation below repeats every native gate.
    /// No caller-provided readiness/consent flag is accepted.
    pub(super) fn wants_preparation_context(&self) -> bool {
        self.state == State::Active
            && self.enabled
            && !crate::entry::stop_requested()
            && self.protocol.as_ref().is_some_and(ServiceHandoff::is_bound)
            && self.both_idle()
    }
    pub(super) fn maintain_original(
        &mut self,
        epoch: BootEpoch,
        pc: PcIdentity,
        pc_key: &TlsPublicKey,
        checkpoint: &RegistryCheckpoint,
        mut read_key: impl FnMut() -> Result<TlsPublicKey, super::PeerRuntimeError>,
    ) {
        let result = (|| {
            self.check_window(Instant::now())?;
            if !self.wants_preparation_context() || self.epoch != Some(epoch) {
                return Err(Failure::Protocol);
            }
            if Instant::now() >= self.close_at()? {
                return Err(Failure::Window);
            }
            self.match_pair()?;
            let window = self.window.as_ref().ok_or(Failure::Protocol)?;
            let origin = Origin {
                epoch,
                generation: self.generation.ok_or(Failure::Generation)?,
                pending_id: self.pending_id.ok_or(Failure::Protocol)?,
                started: window.started(),
                deadline: window.deadline(),
            };
            // This pure resource may be temporarily moved while its callback
            // borrows the SAME native pair. No pipe/key owner moves or escapes.
            // Unwind drops/wipes it; ordinary outcomes retain it before checks.
            let mut preparation = self.preparation.take().ok_or(Failure::Protocol)?;
            let mut validation_failure = None;
            let maintained = preparation.maintain(
                CeremonyContext {
                    origin,
                    pc,
                    pc_key,
                    checkpoint,
                },
                || {
                    let validation = (|| {
                        self.match_pair()?;
                        if Instant::now() >= self.close_at()? {
                            return Err(Failure::Window);
                        }
                        let current = read_key().map_err(|_| Failure::Identity)?;
                        self.match_pair()?;
                        if Instant::now() >= self.close_at()? {
                            return Err(Failure::Window);
                        }
                        ceremony::check_pc_pin(&current, pc_key).map_err(|_| Failure::Identity)?;
                        self.check_window(Instant::now())
                    })();
                    validation.map_err(|error| {
                        validation_failure.get_or_insert(error);
                        PreparationError::Identity
                    })
                },
            );
            self.preparation = Some(preparation);
            maintained
                .map_err(|error| validation_failure.unwrap_or(Failure::Preparation(error)))?;
            // Native checks and RNG/cloning never renew the window or convert
            // Prepared to a grant. A late failure destroys the prepared context.
            self.match_pair()?;
            if Instant::now() >= self.close_at()? {
                return Err(Failure::Window);
            }
            self.check_window(Instant::now())
        })();
        if let Err(error) = result {
            self.retire(Some(error), true);
        } else if !self.renderer_attempted {
            let begun = self.begin_renderer();
            if let Err(error) = begun {
                self.retire(Some(error), true);
            }
        }
    }
    pub(super) fn enrollment_is_absent(&self) -> bool {
        self.enrollment.is_none()
    }

    pub(super) fn begin_enrollment(
        &mut self,
        relay: std::net::SocketAddr,
        policy: VerificationPolicy,
        signer: std::sync::Arc<crate::tls_signer::ServiceTlsSigner>,
        pc_transport_key: TlsPublicKey,
    ) -> Result<(), Failure> {
        if self.enrollment.is_some() || self.enrollment_route.is_some() {
            return Err(Failure::Protocol);
        }
        let renderer = self.renderer.as_mut().ok_or(Failure::Protocol)?;
        if !renderer.ready_for_invitation() {
            return Err(Failure::Protocol);
        }
        let original = self
            .preparation
            .as_ref()
            .ok_or(Failure::Protocol)?
            .prepared()
            .map_err(Failure::Preparation)?;
        let invitation = PairingInvitation::new(PairingInvitationFields {
            ceremony_nonce: original.nonce,
            attestation_challenge: original.challenge,
            pc: original.pc,
            recipient_device: original.recipient,
            pc_signing_key: original.pc_key.clone(),
            pc_transport_key: pc_transport_key.clone(),
            relay_address: relay,
            route: *original.route.as_bytes(),
        })
        .map_err(|_| Failure::Protocol)?;
        let invitation_text =
            InvitationText::new(invitation.to_qr_text()).map_err(|_| Failure::Protocol)?;
        let expected = ExpectedOriginal {
            nonce: original.nonce,
            challenge: original.challenge,
            pc: original.pc,
            recipient: original.recipient,
            invitation_context: invitation.context_digest(),
            intended_revision: original.intended_revision,
            policy,
        };
        renderer.send_invitation(&invitation_text)?;
        let enrollment = EnrollmentCarrier::start(EnrollmentInputs {
            relay,
            route: original.route,
            invitation,
            expected,
            deadline: original
                .deadline
                .checked_sub(CLOSE_RESERVE)
                .ok_or(Failure::Window)?,
            signer,
            pc_signing_key: original.pc_key,
            pc_transport_key,
            #[cfg(test)]
            verification: None,
        })
        .map_err(|_| Failure::Enrollment)?;
        self.enrollment_route = Some((relay, original.route));
        self.enrollment = Some(enrollment);
        Ok(())
    }

    pub(super) fn enrollment_action(&mut self, now: Instant) -> Option<CeremonyAction> {
        if self.enrollment_terminal {
            if self.enrollment_failed
                && self
                    .renderer
                    .as_ref()
                    .is_some_and(|renderer| !renderer.outcome_sent && renderer.ready_idle())
            {
                if self
                    .renderer
                    .as_mut()
                    .is_none_or(|renderer| renderer.send_outcome(false).is_err())
                {
                    self.retire(Some(Failure::Enrollment), true);
                }
                return None;
            }
            let outcome_drained = self
                .renderer
                .as_ref()
                .is_some_and(|renderer| renderer.outcome_sent && renderer.ready_idle());
            if outcome_drained && !self.enrollment_reported {
                self.enrollment_reported = true;
                return if self.enrollment_failed {
                    Some(CeremonyAction::Failed)
                } else {
                    self.committed_device.map(CeremonyAction::Enrolled)
                };
            }
            if outcome_drained
                && self.enrollment_reported
                && let Err(error) = self.finish_enrollment_terminal()
            {
                self.retire(Some(error), true);
            }
            return None;
        }
        self.enrollment.as_ref()?;
        let result = (|| {
            let progress = self
                .enrollment
                .as_mut()
                .ok_or(Failure::Protocol)?
                .poll(now)
                .map_err(|_| Failure::Enrollment)?;
            match progress {
                EnrollmentProgress::Verifying => {
                    let carrier = self.enrollment.as_ref().ok_or(Failure::Protocol)?;
                    if carrier.ready_for_frozen() {
                        return Ok(Some(CeremonyAction::SignFrozen(Box::new(
                            carrier.unsigned_frozen().map_err(|_| Failure::Enrollment)?,
                        ))));
                    }
                }
                EnrollmentProgress::CandidateSent { code } => {
                    let renderer = self.renderer.as_mut().ok_or(Failure::Protocol)?;
                    if !renderer.comparison_sent {
                        renderer.send_comparison(&code)?;
                    }
                }
                EnrollmentProgress::PhoneConfirmed | EnrollmentProgress::AwaitingPcDecision => {
                    if let Some(decision) = self
                        .renderer
                        .as_mut()
                        .ok_or(Failure::Protocol)?
                        .take_decision()
                    {
                        self.enrollment
                            .as_mut()
                            .ok_or(Failure::Protocol)?
                            .pc_decision(decision)
                            .map_err(|_| Failure::Enrollment)?;
                    }
                    if !self.commit_requested
                        && self
                            .enrollment
                            .as_ref()
                            .is_some_and(EnrollmentCarrier::ready_to_commit)
                    {
                        let (relay, route) = self.enrollment_route.ok_or(Failure::Protocol)?;
                        self.commit_requested = true;
                        return Ok(Some(CeremonyAction::Commit { relay, route }));
                    }
                }
                EnrollmentProgress::Accepted => {
                    let renderer = self.renderer.as_mut().ok_or(Failure::Protocol)?;
                    if !renderer.outcome_sent {
                        renderer.send_outcome(true)?;
                    }
                }
                EnrollmentProgress::Closed => {
                    let device = self
                        .enrollment
                        .as_ref()
                        .and_then(EnrollmentCarrier::candidate_device)
                        .ok_or(Failure::Protocol)?;
                    self.committed_device = Some(device);
                    self.enrollment_terminal = true;
                }
                EnrollmentProgress::Connecting | EnrollmentProgress::AwaitingSubmission => {}
            }
            Ok(None)
        })();
        match result {
            Ok(action) => action,
            Err(error) => {
                self.fail_enrollment(error);
                None
            }
        }
    }

    pub(super) fn frozen_signed(&mut self, frozen: SignedFrozenCandidate) -> Result<(), Failure> {
        let code = self
            .enrollment
            .as_mut()
            .ok_or(Failure::Protocol)?
            .send_frozen(frozen)
            .map_err(|_| Failure::Enrollment)?;
        self.renderer
            .as_mut()
            .ok_or(Failure::Protocol)?
            .send_comparison(&code)
    }

    pub(super) fn original_nonce(
        &self,
    ) -> Result<service_protocol::PairingNonce, super::PeerRuntimeError> {
        self.preparation
            .as_ref()
            .ok_or(super::PeerRuntimeError::Protocol)?
            .prepared()
            .map(|original| original.nonce)
            .map_err(|_| super::PeerRuntimeError::Protocol)
    }

    pub(super) fn original_challenge(
        &self,
    ) -> Result<service_protocol::PairingChallenge, super::PeerRuntimeError> {
        self.preparation
            .as_ref()
            .ok_or(super::PeerRuntimeError::Protocol)?
            .prepared()
            .map(|original| original.challenge)
            .map_err(|_| super::PeerRuntimeError::Protocol)
    }

    pub(super) fn original_pc_key(&self) -> Result<TlsPublicKey, super::PeerRuntimeError> {
        self.preparation
            .as_ref()
            .ok_or(super::PeerRuntimeError::Protocol)?
            .prepared()
            .map(|original| original.pc_key)
            .map_err(|_| super::PeerRuntimeError::Protocol)
    }

    pub(super) fn take_verified(
        &mut self,
    ) -> Result<
        (
            (
                android_attestation::VerifiedKeyBundle,
                android_attestation::TrustedStatusSnapshot,
            ),
            super::enrollment::CandidateSummary,
        ),
        Failure,
    > {
        if !self.commit_requested {
            return Err(Failure::Protocol);
        }
        self.enrollment
            .as_mut()
            .ok_or(Failure::Protocol)?
            .take_verified()
            .map_err(|_| Failure::Enrollment)
    }

    pub(super) fn send_acceptance(
        &mut self,
        acceptance: SignedEnrollmentAcceptance,
    ) -> Result<(), Failure> {
        if !self.commit_requested {
            return Err(Failure::Protocol);
        }
        self.enrollment
            .as_mut()
            .ok_or(Failure::Protocol)?
            .send_acceptance(acceptance)
            .map_err(|_| Failure::Enrollment)
    }

    pub(super) fn reject_enrollment_start(&mut self, error: Failure) {
        self.fail_enrollment(error);
    }

    fn fail_enrollment(&mut self, error: Failure) {
        self.first_failure.get_or_insert(error);
        if let Some(carrier) = self.enrollment.as_mut() {
            carrier.cancel();
        }
        self.commit_requested = false;
        self.enrollment_failed = true;
        self.enrollment_terminal = true;
    }

    fn finish_enrollment_terminal(&mut self) -> Result<(), Failure> {
        if !self.enrollment_terminal || !self.enrollment_reported {
            return Err(Failure::Protocol);
        }
        if !self
            .renderer
            .as_ref()
            .is_some_and(|renderer| renderer.outcome_sent && renderer.ready_idle())
        {
            return Err(Failure::Protocol);
        }
        if let Some(preparation) = self.preparation.as_mut() {
            preparation.invalidate();
        }
        self.protocol
            .as_mut()
            .ok_or(Failure::Protocol)?
            .start_close()
            .map_err(|_| Failure::Protocol)?;
        self.renderer
            .as_mut()
            .ok_or(Failure::Protocol)?
            .begin_close()
    }

    fn begin_renderer(&mut self) -> Result<(), Failure> {
        self.renderer_attempted = true; // Burn before RNG, allocation or native creation.
        self.match_pair()?;
        if Instant::now() >= self.close_at()? {
            return Err(Failure::Window);
        }
        let pending = self.pending_id.ok_or(Failure::Protocol)?;
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Failure::Random)?;
        let display = PendingElevationId::from_bytes(bytes).map_err(|_| Failure::Random)?;
        let invocation = RendererInvocation::new(pending, display).map_err(|_| Failure::Random)?;
        let cutoff =
            renderer_original_cutoff(self.window.as_ref().ok_or(Failure::Protocol)?.deadline())?;
        let request = RendererRequest::new(invocation, cutoff).map_err(|_| Failure::Protocol)?;
        let pipe = self
            .starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .prepare_renderer_pipe()?;
        self.renderer = Some(RendererRun {
            request,
            pipe,
            registration: RendererRegistration::new(),
            parent: RendererParent::PrepareWrite,
            io: RendererIo::Connect,
            invitation_sent: false,
            comparison_sent: false,
            decision_received: false,
            decision: None,
            outcome_sent: false,
            cleanup_failed: false,
        });
        self.match_pair()?;
        self.renderer
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe
            .begin_connect()?;
        self.match_pair()?;
        self.write(
            ServiceSide::Helper,
            Frame::PrepareRenderer(request),
            Io::RendererPrepareWrite,
        )
    }
    fn both_idle(&self) -> bool {
        self.starter.as_ref().is_some_and(Channel::idle)
            && self.helper.as_ref().is_some_and(Channel::idle)
    }
    fn poll_side(&mut self, side: ServiceSide) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.check_policy()?;
        let (operation, progress) = {
            let (pipe, io) = self.channel(side)?.pipe()?;
            (*io, pipe.poll()?)
        };
        self.check_window(Instant::now())?;
        self.check_policy()?;
        let outcome = match (operation, progress) {
            (_, PairingPipeProgress::Pending) | (Io::Idle, PairingPipeProgress::Idle) => Ok(()),
            (Io::Connect, PairingPipeProgress::Connected) if side == ServiceSide::Helper => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.read(side, Io::HelperRead)
            }
            (Io::OfferWrite, PairingPipeProgress::Written) if side == ServiceSide::Starter => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .offer_written()
                    .map_err(|_| Failure::Protocol)?;
                self.read(side, Io::StarterRead)
            }
            (Io::StarterRead | Io::HelperRead | Io::AckRead, PairingPipeProgress::Read(bytes)) => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                let frame = Frame::decode(&bytes).map_err(|_| Failure::Protocol)?;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .receive(side, frame)
                    .map_err(|_| Failure::Protocol)
            }
            (Io::BoundWrite, PairingPipeProgress::Written) => {
                self.match_pair()?;
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .bound_written(side)
                    .map_err(|_| Failure::Protocol)?;
                self.match_pair()?; // Includes both-written internal Bound publication.
                Ok(())
            }
            (Io::CloseWrite, PairingPipeProgress::Written) => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .close_written(side)
                    .map_err(|_| Failure::Protocol)?;
                self.read(side, Io::AckRead)
            }
            (Io::RendererPrepareWrite, PairingPipeProgress::Written)
                if side == ServiceSide::Helper =>
            {
                let renderer = self.renderer.as_mut().ok_or(Failure::Protocol)?;
                if renderer.parent != RendererParent::PrepareWrite {
                    return Err(Failure::Protocol);
                }
                renderer.parent = RendererParent::AwaitLaunch;
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.read(side, Io::RendererParentRead)
            }
            (Io::RendererParentRead, PairingPipeProgress::Read(bytes))
                if side == ServiceSide::Helper =>
            {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                let Frame::RendererLaunched { request, process } =
                    Frame::decode(&bytes).map_err(|_| Failure::Protocol)?
                else {
                    return Err(Failure::Protocol);
                };
                let helper = self.helper.as_mut().ok_or(Failure::Protocol)?.pipe()?.0;
                let reply = self
                    .renderer
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .accept_parent(helper, request, process)?;
                self.write(ServiceSide::Helper, reply, Io::RendererRegisterWrite)
            }
            (Io::RendererRegisterWrite, PairingPipeProgress::Written)
                if side == ServiceSide::Helper =>
            {
                let renderer = self.renderer.as_mut().ok_or(Failure::Protocol)?;
                if renderer.parent != RendererParent::RegisterWrite {
                    return Err(Failure::Protocol);
                }
                renderer.parent = RendererParent::Done;
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                Ok(())
            }
            _ => Err(Failure::Protocol),
        };
        outcome?;
        self.check_window(Instant::now())?;
        self.check_policy()
    }
    fn retire(&mut self, failure: Option<Failure>, rearm: bool) {
        if let Some(error) = failure {
            self.first_failure.get_or_insert(error);
        }
        if let Some(protocol) = self.protocol.as_mut() {
            protocol.cancel();
        }
        if let Some(preparation) = self.preparation.as_mut() {
            preparation.invalidate();
        }
        if let Some(renderer) = self.renderer.as_mut() {
            renderer.cancel();
        }
        if let Some(enrollment) = self.enrollment.as_mut() {
            enrollment.cancel();
        }
        if let Some(starter) = self.starter.as_mut() {
            starter.cancel();
        }
        if let Some(helper) = self.helper.as_mut() {
            helper.cancel();
        }
        if let Some(admission) = self.admission.as_mut() {
            admission.cancel();
        }
        self.state = State::Draining;
        self.rearm = rearm && self.enabled && !crate::entry::stop_requested();
    }
    pub(super) fn shutdown(&mut self) {
        self.enabled = false;
        self.retire(Some(Failure::Cancelled), false);
    }
    fn drain_step(&mut self) {
        for channel in [&mut self.starter, &mut self.helper].into_iter().flatten() {
            if channel.drain().is_err() || channel.cleanup_failed() {
                self.cleanup_failed = true;
            }
        }
        if let Some(admission) = self.admission.as_mut()
            && admission.drain().is_err()
        {
            self.cleanup_failed = true;
        }
        if let Some(renderer) = self.renderer.as_mut() {
            renderer.drain();
            self.cleanup_failed |= renderer.cleanup_failed;
        }
        if let Some(enrollment) = self.enrollment.as_mut() {
            enrollment.drain();
        }
        if self.remaining_owners() != 0 {
            return;
        }
        drop(self.starter.take());
        drop(self.helper.take());
        drop(self.admission.take());
        self.window = None;
        self.protocol = None;
        self.pending_id = None;
        self.preparation = None;
        self.renderer = None;
        self.enrollment = None;
        self.enrollment_route = None;
        self.enrollment_failed = false;
        self.enrollment_terminal = false;
        self.enrollment_reported = false;
        self.commit_requested = false;
        self.committed_device = None;
        self.renderer_attempted = false;
        self.generation = None;
        if self.rearm
            && !self.cleanup_failed
            && self.enabled
            && !crate::entry::stop_requested()
            && self.next_generation.is_some()
        {
            self.rearm = false;
            if let Err(error) = self.arm() {
                self.retire(Some(error), false);
            }
        } else {
            self.state = State::Unavailable;
        }
    }
    pub(super) fn poll_shutdown(&mut self) {
        self.shutdown();
        self.drain_step();
    }
    pub(super) fn renderer(&self) -> Option<&RendererRun> {
        self.renderer.as_ref()
    }
    pub(super) fn remaining_owners(&self) -> usize {
        usize::from(
            self.starter
                .as_ref()
                .is_some_and(|channel| !channel.drained()),
        ) + usize::from(
            self.helper
                .as_ref()
                .is_some_and(|channel| !channel.drained()),
        ) + usize::from(
            self.admission
                .as_ref()
                .is_some_and(|admission| !admission.is_drained()),
        ) + self
            .renderer
            .as_ref()
            .map_or(0, RendererRun::remaining_owners)
            + self
                .enrollment
                .as_ref()
                .map_or(0, EnrollmentCarrier::remaining_owners)
    }
    pub(super) fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(polls_left: usize, fail: bool) -> Channel {
        Channel::Fixture(FixtureChannel {
            polls_left,
            drained: false,
            cancelled: false,
            fail,
            idle: false,
        })
    }
    #[test]
    fn renderer_content_order_rejects_comparison_first_and_duplicate_invitation() {
        assert!(!RendererRun::content_state_allows(
            RendererIo::Idle,
            false,
            false,
            false,
            ContentAction::Comparison,
        ));
        assert!(RendererRun::content_state_allows(
            RendererIo::Idle,
            false,
            false,
            false,
            ContentAction::Invitation,
        ));
        assert!(!RendererRun::content_state_allows(
            RendererIo::Idle,
            true,
            false,
            false,
            ContentAction::Invitation,
        ));
        assert!(!RendererRun::content_state_allows(
            RendererIo::DecisionRead,
            true,
            true,
            false,
            ContentAction::Outcome,
        ));
    }
    #[test]
    fn late_stop_blocks_producer_eligibility_but_not_mock_cleanup() {
        use std::cell::Cell;
        let mut owner = ServicePairing::dormant();
        owner.enabled = true;
        let stopped = Cell::new(false);
        assert_eq!(owner.ensure_running_with(|| stopped.get()), Ok(()));
        stopped.set(true); // Deterministic fixture: native checks elapsed meanwhile.
        assert_eq!(
            owner.ensure_running_with(|| stopped.get()),
            Err(Failure::Cancelled)
        );
        owner.starter = Some(fixture(1, false));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
        assert!(!owner.enabled);
    }
    #[test]
    fn constructors_are_dormant_and_shutdown_counts_all_mock_owners() {
        let mut owner = ServicePairing::dormant();
        assert_eq!(owner.state, State::Dormant);
        assert!(!owner.enabled);
        assert_eq!(owner.remaining_owners(), 0);
        owner.starter = Some(fixture(0, false));
        owner.helper = Some(fixture(2, false));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
        assert!(owner.starter.is_none() && owner.helper.is_none());
        assert_eq!(owner.state, State::Unavailable);
        assert!(!owner.enabled);
    }
    #[test]
    fn renderer_terminal_needs_all_three_acknowledgements_before_any_close() {
        assert!(!all_participants_acknowledged(false, Some(false)));
        assert!(!all_participants_acknowledged(true, Some(false)));
        assert!(!all_participants_acknowledged(false, Some(true)));
        assert!(all_participants_acknowledged(true, Some(true)));
        // A ceremony rejected before creating a renderer keeps the original
        // two-peer cleanup contract; absence is not fabricated renderer success.
        assert!(all_participants_acknowledged(true, None));
    }
    #[test]
    fn uncertain_mock_drain_retains_owner_and_never_rearms() {
        let mut owner = ServicePairing::dormant();
        owner.helper = Some(fixture(0, true));
        owner.poll_shutdown();
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        assert!(owner.cleanup_failed());
        assert!(owner.helper.is_some());
        assert!(!owner.rearm);
        // No native handle was constructed; prevent a synthetic failure fixture
        // from being mistaken for the production Session Drop invariant.
    }
    #[test]
    fn active_state_cannot_rearm_or_replace_an_existing_attempt() {
        let mut owner = ServicePairing::dormant();
        owner.state = State::Active;
        owner.enabled = true;
        assert!(owner.arm().is_err()); // Rejects before any native factory.
        assert_eq!(owner.next_generation, Some(1));
    }
    #[test]
    fn preparation_scheduling_requires_both_completed_bound_writes_and_idle_owners() {
        let id = PendingElevationId::from_bytes([1; 32]).unwrap();
        let mut protocol = ServiceHandoff::new(id);
        protocol.offer_written().unwrap();
        protocol
            .receive(ServiceSide::Helper, Frame::Hello(id))
            .unwrap();
        protocol
            .receive(
                ServiceSide::Starter,
                Frame::HelperLaunched {
                    id,
                    pid: 42,
                    created: 99,
                },
            )
            .unwrap();
        protocol.confirm_match().unwrap();
        protocol.bound_written(ServiceSide::Starter).unwrap();
        let mut owner = ServicePairing::dormant();
        owner.state = State::Active;
        owner.enabled = true;
        owner.protocol = Some(protocol);
        owner.preparation = Some(OriginalCeremony::new());
        for slot in [&mut owner.starter, &mut owner.helper] {
            let mut channel = fixture(0, false);
            if let Channel::Fixture(value) = &mut channel {
                value.idle = true;
            }
            *slot = Some(channel);
        }
        assert!(!owner.wants_preparation_context());
        owner
            .protocol
            .as_mut()
            .unwrap()
            .bound_written(ServiceSide::Helper)
            .unwrap();
        assert!(owner.wants_preparation_context()); // Scheduling only, not native authority.
        owner.protocol.as_mut().unwrap().start_close().unwrap();
        assert!(!owner.wants_preparation_context());
        owner.poll_shutdown(); // Pure fixture cleanup, no native factory or query.
        assert_eq!(owner.remaining_owners(), 0);
        assert!(owner.preparation.is_none());
    }
    #[test]
    fn ordinary_test_process_cannot_activate_native_pairing_endpoints() {
        // The fake report callbacks test ONLY the native negative factory guard:
        // this executable is not the actual fixed running SCM process. No UAC,
        // provider, endpoint creation or successful activation is expected.
        let began = Instant::now();
        let (request, gate) = crate::startup_phase::ready_handshake();
        request
            .complete_after_report(began, || false, || Ok(()), || ())
            .unwrap();
        let ready = gate.wait(began, || false).unwrap();
        let mut owner = ServicePairing::dormant();
        owner
            .activate(ready, BootEpoch::from_bytes([1; 32]).unwrap())
            .unwrap();
        assert!(!matches!(owner.state, State::Listening | State::Active));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
    }
}
