// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual framed TLS queueing of an already signed approval. Queue/drain are
//! local transport facts, never PC receipt, Windows approval or durable outbox.
use approval_protocol::RequestBinding;
use framed_transport::{OutboundFrameGuard, SocketError, TransportError};
use phone_request_core::request_key;
use service_protocol::{MAX_CLOCK_CORRELATION_AGE_NANOS, encode_frame};
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
    CommittedAssociatedCheck, DurableFailure, DurableInbox, NativePeerLease, PeerLeaseError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalWriteProgress {
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
pub struct QueuedApproval {
    binding: RequestBinding,
    state: Arc<AtomicU8>,
}
impl QueuedApproval {
    pub const fn binding(&self) -> RequestBinding {
        self.binding
    }
    pub fn progress(&self) -> ApprovalWriteProgress {
        match self.state.load(Ordering::Acquire) {
            0 => ApprovalWriteProgress::Queued,
            1 => ApprovalWriteProgress::WrittenToSocket,
            _ => ApprovalWriteProgress::Stopped,
        }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SendIssue {
    #[error("submission belongs to another owner or original peer")]
    DifferentOrigin,
    #[error("the original request or registration no longer matches")]
    RequestChanged,
    #[error("original request is expired or no longer allowed")]
    ExpiredOrSuppressed,
    #[error("approval was explicitly cancelled")]
    Cancelled,
    #[error("native send clock is unavailable or inconsistent")]
    Clock,
    #[error("the connection belongs to another service epoch")]
    ServiceEpochChanged,
    #[error("the durable send check failed")]
    Persistence(DurableFailure),
    #[error("the socket could not accept this approval")]
    Socket(PeerSocketError),
    #[error("native liveness registration failed")]
    Lease(PeerLeaseError),
    #[error("the bounded approval frame could not be encoded")]
    Encoding,
}

struct SendGuard {
    approval: Arc<dyn OutboundFrameGuard>,
    lease: NativePeerLease,
    connection: Arc<PeerContext>,
}
impl OutboundFrameGuard for SendGuard {
    fn is_revoked(&self) -> bool {
        self.approval.is_revoked()
            || self.lease.is_revoked()
            || !self.connection.active.load(Ordering::Acquire)
            || self.connection.stop.is_cancelled()
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
        let result = self.prepare_approval_send(owner, &submission, clock, &mut checks);
        let outcome = match result {
            Ok(queued) => ApprovalSendOutcome::Queued(queued),
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

    fn prepare_approval_send(
        &mut self,
        owner: &mut DurableInbox,
        submission: &ApprovalSubmission,
        clock: &mut dyn ApprovalClock,
        checks: &mut Vec<CommittedAssociatedCheck>,
    ) -> Result<QueuedApproval, SendFailure> {
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
        if self.driver.pending_counts().outbound_frame {
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
        let (wire, approval) = submission
            .delivery_parts()
            .map_err(|_| reject(SendIssue::Cancelled))?;
        let frame = encode_frame(&wire).map_err(|_| reject(SendIssue::Encoding))?;
        let guard = Arc::new(SendGuard {
            approval,
            lease,
            connection: Arc::clone(&self.context),
        });
        match self.driver.queue_guarded_frame(frame, deadline, guard) {
            Ok(()) => {
                let state = WriteState::new();
                let queued = QueuedApproval {
                    binding: submission.binding(),
                    state: Arc::clone(&state.0),
                };
                self.outbound_approval = Some(state);
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
    submission: &ApprovalSubmission,
) -> Result<ApprovalTime, SendFailure> {
    let time = clock.read().map_err(|_| reject(SendIssue::Clock))?;
    if time.boot() != submission.phone_boot() {
        return Err(reject(SendIssue::Clock));
    }
    Ok(time)
}
fn match_request(
    submission: &ApprovalSubmission,
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
