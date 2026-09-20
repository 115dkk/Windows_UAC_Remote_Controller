// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual framed TLS queueing of the two sealed prepared decision types.
//! Queue/drain are local transport facts, never PC receipt, Windows result or
//! durable outbox. No public arbitrary statement, purpose, bytes or extension.
use approval_protocol::RequestBinding;
use framed_transport::{OutboundFrameGuard, SocketError, TransportError};
use phone_request_core::{PhoneBootId, request_key};
use service_protocol::{MAX_CLOCK_CORRELATION_AGE_NANOS, MappedRequestWindow, encode_frame};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use super::{AssociatedPcSocket, PeerContext, PeerSocketError};
use crate::{
    ApprovalClock, ApprovalSubmission, ApprovalTime, AssociatedPendingRequest,
    CommittedAssociatedCheck, DurableFailure, DurableInbox, LocalKeySetDescriptor, NativePeerLease,
    PeerAssociation, PeerLeaseError, PreparedDenial,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWriteProgress {
    Queued,
    /// All frame ciphertext handed to local TCP. The PC may still reject it.
    WrittenToSocket,
    /// No complete local drain was confirmed. Some bytes may already be sent.
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialWriteProgress {
    Queued,
    /// All frame ciphertext handed to local TCP. The PC may still reject it.
    WrittenToSocket,
    /// No complete local drain was confirmed. Some bytes may already be sent.
    Stopped,
}
pub(super) struct WriteState(Arc<AtomicU8>);
impl WriteState {
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }
    pub(super) fn written(self) {
        self.0.store(1, Ordering::Release);
    }
    pub(super) fn stopped(self) {
        let _ = self
            .0
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}
struct QueuedDecision {
    binding: RequestBinding,
    state: Arc<AtomicU8>,
}
pub struct QueuedApproval {
    inner: QueuedDecision,
}
impl QueuedApproval {
    pub const fn binding(&self) -> RequestBinding {
        self.inner.binding
    }
    pub fn progress(&self) -> ApprovalWriteProgress {
        match self.inner.state.load(Ordering::Acquire) {
            0 => ApprovalWriteProgress::Queued,
            1 => ApprovalWriteProgress::WrittenToSocket,
            _ => ApprovalWriteProgress::Stopped,
        }
    }
}
pub struct QueuedDenial {
    inner: QueuedDecision,
}
impl QueuedDenial {
    pub const fn binding(&self) -> RequestBinding {
        self.inner.binding
    }
    pub fn progress(&self) -> DenialWriteProgress {
        match self.inner.state.load(Ordering::Acquire) {
            0 => DenialWriteProgress::Queued,
            1 => DenialWriteProgress::WrittenToSocket,
            _ => DenialWriteProgress::Stopped,
        }
    }
}
impl fmt::Debug for QueuedDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedDenial")
            .field("progress", &self.progress())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for QueuedApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedApproval")
            .field("progress", &self.progress())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendRetry {
    Busy,
    NotReady,
    ClockRequired,
    LeaseCapacity,
}
pub enum ApprovalSendOutcome {
    Queued(QueuedApproval),
    /// SAME signed data/original deadline, not a new auth window or signature.
    Retry {
        reason: SendRetry,
        submission: ApprovalSubmission,
    },
    Rejected(SendIssue),
}
impl fmt::Debug for ApprovalSendOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued(value) => value.fmt(f),
            Self::Retry { reason, .. } => f.debug_tuple("Retry").field(reason).finish(),
            Self::Rejected(error) => error.fmt(f),
        }
    }
}
#[must_use = "dispatch committed withdrawals even when queueing failed; queued is not delivered"]
pub struct ApprovalSendTransition {
    checks: Vec<CommittedAssociatedCheck>,
    outcome: ApprovalSendOutcome,
}
impl ApprovalSendTransition {
    pub fn checks(&self) -> &[CommittedAssociatedCheck] {
        &self.checks
    }
    pub fn outcome(&self) -> &ApprovalSendOutcome {
        &self.outcome
    }
    pub fn into_parts(self) -> (Vec<CommittedAssociatedCheck>, ApprovalSendOutcome) {
        (self.checks, self.outcome)
    }
}
impl fmt::Debug for ApprovalSendTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalSendTransition")
            .field("checks", &self.checks.len())
            .field("outcome", &self.outcome)
            .finish()
    }
}
pub enum DenialSendOutcome {
    Queued(QueuedDenial),
    /// The SAME signature/context/deadline, not another native key operation.
    Retry {
        reason: SendRetry,
        submission: PreparedDenial,
    },
    Rejected(SendIssue),
}
impl fmt::Debug for DenialSendOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued(value) => value.fmt(f),
            Self::Retry { reason, .. } => f.debug_tuple("Retry").field(reason).finish(),
            Self::Rejected(error) => error.fmt(f),
        }
    }
}
#[must_use = "dispatch committed withdrawals even when queueing failed; queued is not delivered"]
pub struct DenialSendTransition {
    checks: Vec<CommittedAssociatedCheck>,
    outcome: DenialSendOutcome,
}
impl DenialSendTransition {
    pub fn checks(&self) -> &[CommittedAssociatedCheck] {
        &self.checks
    }
    pub fn outcome(&self) -> &DenialSendOutcome {
        &self.outcome
    }
    pub fn into_parts(self) -> (Vec<CommittedAssociatedCheck>, DenialSendOutcome) {
        (self.checks, self.outcome)
    }
}
impl fmt::Debug for DenialSendTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DenialSendTransition")
            .field("checks", &self.checks.len())
            .field("outcome", &self.outcome)
            .finish()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SendIssue {
    #[error("submission belongs to another owner or original peer")]
    DifferentOrigin,
    #[error("the original request or registration no longer matches")]
    RequestChanged,
    #[error("original request is expired or no longer allowed")]
    ExpiredOrSuppressed,
    #[error("decision was cancelled or withdrawn")]
    Cancelled,
    #[error("native send clock is unavailable or inconsistent")]
    Clock,
    #[error("the connection belongs to another service epoch")]
    ServiceEpochChanged,
    #[error("the durable send check failed")]
    Persistence(DurableFailure),
    #[error("the socket could not accept this decision")]
    Socket(PeerSocketError),
    #[error("native liveness registration failed")]
    Lease(PeerLeaseError),
    #[error("the bounded decision frame could not be encoded")]
    Encoding,
}

struct SendGuard {
    decision: Arc<dyn OutboundFrameGuard>,
    lease: NativePeerLease,
    connection: Arc<PeerContext>,
}
impl OutboundFrameGuard for SendGuard {
    fn is_revoked(&self) -> bool {
        self.decision.is_revoked()
            || self.lease.is_revoked()
            || !self.connection.active.load(Ordering::Acquire)
            || self.connection.stop.is_cancelled()
    }
}

// Deliberately closed and private. These are the only two concrete sealed
// inputs; no caller can implement a trait or supply arbitrary signed bytes,
// metadata, purpose or cancellation callback to the admission pipeline.
#[derive(Clone, Copy)]
enum PreparedDecisionRef<'a> {
    Approval(&'a ApprovalSubmission),
    Denial(&'a PreparedDenial),
}
impl<'a> PreparedDecisionRef<'a> {
    fn binding(self) -> RequestBinding {
        match self {
            Self::Approval(value) => value.binding(),
            Self::Denial(value) => value.binding(),
        }
    }
    fn original_window(self) -> MappedRequestWindow {
        match self {
            Self::Approval(value) => value.original_window(),
            Self::Denial(value) => value.original_window(),
        }
    }
    fn phone_boot(self) -> PhoneBootId {
        match self {
            Self::Approval(value) => value.phone_boot(),
            Self::Denial(value) => value.phone_boot(),
        }
    }
    fn deadline_nanos(self) -> u64 {
        match self {
            Self::Approval(value) => value.deadline_nanos(),
            Self::Denial(value) => value.deadline_nanos(),
        }
    }
    fn association(self) -> &'a PeerAssociation {
        match self {
            Self::Approval(value) => value.association(),
            Self::Denial(value) => value.association(),
        }
    }
    fn local_keys(self) -> &'a LocalKeySetDescriptor {
        match self {
            Self::Approval(value) => value.local_keys(),
            Self::Denial(value) => value.local_keys(),
        }
    }
    fn belongs_to_owner(self, owner: &DurableInbox) -> bool {
        match self {
            Self::Approval(value) => value.belongs_to_owner(owner),
            Self::Denial(value) => value.belongs_to_owner(owner),
        }
    }
    fn is_cancelled(self) -> bool {
        match self {
            Self::Approval(value) => value.is_cancelled(),
            Self::Denial(value) => value.is_cancelled(),
        }
    }
    fn delivery_parts(self) -> Result<(Vec<u8>, Arc<dyn OutboundFrameGuard>), SendFailure> {
        match self {
            Self::Approval(value) => value
                .delivery_parts()
                .map_err(|_| reject(SendIssue::Cancelled)),
            Self::Denial(value) => value
                .delivery_parts()
                .map_err(|_| reject(SendIssue::Cancelled)),
        }
    }
}

impl AssociatedPcSocket {
    /// Caller keeps one bounded submission until Queued/rejected; retries cannot
    /// reset its original auth/deadline. No generic frame or caller statement.
    /// Native clock callbacks are observation-only and must not re-enter owners.
    pub fn queue_approval(
        &mut self,
        owner: &mut DurableInbox,
        submission: ApprovalSubmission,
        clock: &mut dyn ApprovalClock,
    ) -> ApprovalSendTransition {
        let mut checks = Vec::new();
        let result = self.prepare_decision_send(
            owner,
            PreparedDecisionRef::Approval(&submission),
            clock,
            &mut checks,
        );
        let outcome = match result {
            Ok(inner) => ApprovalSendOutcome::Queued(QueuedApproval { inner }),
            Err(SendFailure::Retry(reason)) => ApprovalSendOutcome::Retry { reason, submission },
            Err(SendFailure::Reject(error)) => {
                if error == SendIssue::Clock {
                    self.abort();
                }
                ApprovalSendOutcome::Rejected(error)
            }
        };
        ApprovalSendTransition { checks, outcome }
    }

    /// Queue only a sealed denial, retaining its original cancellation/lease
    /// through final writes. A retry returns the SAME signature and deadline;
    /// neither queueing nor drain is a PC receipt or Windows-denied outcome.
    pub fn queue_denial(
        &mut self,
        owner: &mut DurableInbox,
        submission: PreparedDenial,
        clock: &mut dyn ApprovalClock,
    ) -> DenialSendTransition {
        let mut checks = Vec::new();
        let result = self.prepare_decision_send(
            owner,
            PreparedDecisionRef::Denial(&submission),
            clock,
            &mut checks,
        );
        let outcome = match result {
            Ok(inner) => DenialSendOutcome::Queued(QueuedDenial { inner }),
            Err(SendFailure::Retry(reason)) => DenialSendOutcome::Retry { reason, submission },
            Err(SendFailure::Reject(error)) => {
                if error == SendIssue::Clock {
                    self.abort();
                }
                DenialSendOutcome::Rejected(error)
            }
        };
        DenialSendTransition { checks, outcome }
    }

    fn prepare_decision_send(
        &mut self,
        owner: &mut DurableInbox,
        submission: PreparedDecisionRef<'_>,
        clock: &mut dyn ApprovalClock,
        checks: &mut Vec<CommittedAssociatedCheck>,
    ) -> Result<QueuedDecision, SendFailure> {
        if !submission.belongs_to_owner(owner)
            || submission.association() != &self.context.association
            || submission.local_keys() != &self.context.local_keys
        {
            return Err(reject(SendIssue::DifferentOrigin));
        }
        self.check_current(owner)
            .map_err(|error| reject(SendIssue::Socket(error)))?;
        if submission.is_cancelled() {
            return Err(reject(SendIssue::Cancelled));
        }
        // The progress record is single-owner too: it must never be replaced
        // before next_event marks/takes its actual drain or terminal cleanup.
        if self.outbound_decision.is_some() || self.driver.pending_counts().outbound_frame {
            return Err(SendFailure::Retry(SendRetry::Busy));
        }
        let correlation = self
            .correlation
            .as_ref()
            .ok_or(SendFailure::Retry(SendRetry::ClockRequired))?;
        if correlation.epoch() != submission.binding().epoch() {
            return Err(reject(SendIssue::ServiceEpochChanged));
        }
        if correlation.is_faulted() {
            return Err(reject(SendIssue::Clock));
        }
        let before = read_time(clock, submission)?;
        let checked = owner
            .check_associated_pending(request_key(submission.binding()), before.clock())
            .map_err(|error| {
                self.abort();
                reject(SendIssue::Persistence(error))
            })?;
        checks.push(checked);
        if checks
            .last()
            .is_some_and(|checked| checked.update().fault().is_some())
        {
            self.abort();
            return Err(reject(SendIssue::RequestChanged));
        }
        let request = checks
            .last()
            .and_then(CommittedAssociatedCheck::request)
            .ok_or(reject(SendIssue::RequestChanged))?;
        match_request(submission, request)?;
        // This Instant precedes the native phone observation: adding its REMAINING
        // TTL cannot extend the original phone deadline across the callback/IO.
        // Both clocks MUST be the same suspend-inclusive native time projection.
        let socket_before = self
            .socket_clock
            .now()
            .map_err(|_| reject(SendIssue::Clock))?;
        let after = read_time(clock, submission)?;
        if after.clock().phone_monotonic_nanos() < before.clock().phone_monotonic_nanos() {
            self.abort();
            return Err(reject(SendIssue::Clock));
        }
        let now = after.clock().phone_monotonic_nanos();
        let expired = now >= submission.deadline_nanos();
        let allowed = owner
            .policy()
            .map_err(|error| reject(SendIssue::Socket(PeerSocketError::Owner(error))))?
            .allows(after.clock().reading().local);
        if expired || !allowed {
            let maintenance = owner
                .check_associated_pending(request_key(submission.binding()), after.clock())
                .map_err(|error| {
                    self.abort();
                    reject(SendIssue::Persistence(error))
                })?;
            checks.push(maintenance);
            return Err(reject(SendIssue::ExpiredOrSuppressed));
        }
        let correlation = self
            .correlation
            .as_ref()
            .ok_or(SendFailure::Retry(SendRetry::ClockRequired))?;
        let age = now
            .checked_sub(correlation.phone_anchor_nanos())
            .ok_or(reject(SendIssue::Clock))?;
        if age > MAX_CLOCK_CORRELATION_AGE_NANOS {
            return Err(SendFailure::Retry(SendRetry::ClockRequired));
        }
        self.check_current(owner)
            .map_err(|error| reject(SendIssue::Socket(error)))?;
        if submission.is_cancelled() {
            return Err(reject(SendIssue::Cancelled));
        }
        let lease = owner
            .lease_pending_request(request)
            .map_err(|error| match error {
                PeerLeaseError::Capacity => SendFailure::Retry(SendRetry::LeaseCapacity),
                error => reject(SendIssue::Lease(error)),
            })?;
        let deadline = socket_before
            .checked_add(Duration::from_nanos(submission.deadline_nanos() - now))
            .ok_or(reject(SendIssue::Clock))?;
        let (wire, decision) = submission.delivery_parts()?;
        let frame = encode_frame(&wire).map_err(|_| reject(SendIssue::Encoding))?;
        let guard = Arc::new(SendGuard {
            decision,
            lease,
            connection: Arc::clone(&self.context),
        });
        match self.driver.queue_guarded_frame(frame, deadline, guard) {
            Ok(()) => {
                let state = WriteState::new();
                let queued = QueuedDecision {
                    binding: submission.binding(),
                    state: Arc::clone(&state.0),
                };
                self.outbound_decision = Some(state);
                Ok(queued)
            }
            Err(SocketError::Transport(TransportError::Busy)) => {
                Err(SendFailure::Retry(SendRetry::Busy))
            }
            Err(SocketError::Transport(TransportError::NotReady)) => {
                Err(SendFailure::Retry(SendRetry::NotReady))
            }
            Err(error) => {
                self.abort();
                Err(reject(SendIssue::Socket(PeerSocketError::Socket(error))))
            }
        }
    }
}
enum SendFailure {
    Retry(SendRetry),
    Reject(SendIssue),
}
fn reject(issue: SendIssue) -> SendFailure {
    SendFailure::Reject(issue)
}
fn read_time(
    clock: &mut dyn ApprovalClock,
    submission: PreparedDecisionRef<'_>,
) -> Result<ApprovalTime, SendFailure> {
    let time = clock.read().map_err(|_| reject(SendIssue::Clock))?;
    if time.boot() != submission.phone_boot() {
        return Err(reject(SendIssue::Clock));
    }
    Ok(time)
}
fn match_request(
    submission: PreparedDecisionRef<'_>,
    request: &AssociatedPendingRequest,
) -> Result<(), SendFailure> {
    if request.request().original_window() != submission.original_window()
        || request.association() != submission.association()
        || request.local_keys() != submission.local_keys()
    {
        return Err(reject(SendIssue::RequestChanged));
    }
    Ok(())
}
