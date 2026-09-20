// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed typed ownership handoff to the SAME associated socket. No raw frames,
//! caller purpose or signing callback can enter this module's command queue.
use crate::{BridgeError, MobileController, NativeApprovalSubmission, NativeDenialScope};
use android_controller::{
    ApprovalSendOutcome, AssociatedPcSocket, DenialSendOutcome, QueuedApproval, QueuedDenial,
    SendRetry,
};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeDecisionProgress {
    Prepared,
    WaitingForPeer,
    Queued,
    WrittenToSocket,
    Stopped,
    Rejected,
}
pub(crate) struct DeliveryControl {
    progress: AtomicU8,
    pub queued_command: AtomicBool,
    pub retry_blocked: AtomicBool,
    pub ever_admitted: AtomicBool,
    pub sender_finished: AtomicBool,
}
impl DeliveryControl {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            progress: AtomicU8::new(0),
            queued_command: AtomicBool::new(false),
            retry_blocked: AtomicBool::new(false),
            ever_admitted: AtomicBool::new(false),
            sender_finished: AtomicBool::new(true),
        })
    }
    pub(crate) fn progress(&self) -> NativeDecisionProgress {
        match self.progress.load(Ordering::Acquire) {
            0 => NativeDecisionProgress::Prepared,
            1 => NativeDecisionProgress::WaitingForPeer,
            2 => NativeDecisionProgress::Queued,
            3 => NativeDecisionProgress::WrittenToSocket,
            4 => NativeDecisionProgress::Stopped,
            _ => NativeDecisionProgress::Rejected,
        }
    }
    pub(crate) fn set(&self, value: NativeDecisionProgress) {
        let value = match value {
            NativeDecisionProgress::Prepared => 0,
            NativeDecisionProgress::WaitingForPeer => 1,
            NativeDecisionProgress::Queued => 2,
            NativeDecisionProgress::WrittenToSocket => 3,
            NativeDecisionProgress::Stopped => 4,
            NativeDecisionProgress::Rejected => 5,
        };
        self.progress.store(value, Ordering::Release);
    }
    pub(crate) fn stop(&self) {
        if self.progress() != NativeDecisionProgress::WrittenToSocket {
            self.set(NativeDecisionProgress::Stopped);
        }
        self.sender_finished.store(true, Ordering::Release);
        self.queued_command.store(false, Ordering::Release);
    }
}
impl fmt::Debug for DeliveryControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryControl")
            .field("progress", &self.progress())
            .finish_non_exhaustive()
    }
}

pub(crate) enum DeliveryCommand {
    Approval(Arc<NativeApprovalSubmission>),
    Denial(Arc<NativeDenialScope>),
}
impl DeliveryCommand {
    pub(crate) fn control(&self) -> Arc<DeliveryControl> {
        match self {
            Self::Approval(value) => value.delivery_control(),
            Self::Denial(scope) => scope.delivery_control(),
        }
    }
    pub(crate) fn reference(&self) -> android_controller::PeerAssociationRef {
        match self {
            Self::Approval(value) => value.association_reference(),
            Self::Denial(scope) => scope.association_reference(),
        }
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        match self {
            Self::Approval(value) => value.is_cancelled(),
            Self::Denial(scope) => scope.is_cancelled(),
        }
    }
    pub(crate) fn key(&self) -> notification_policy::RequestKey {
        match self {
            Self::Approval(value) => value.request_key(),
            Self::Denial(scope) => scope.request_key(),
        }
    }
    pub(crate) fn clone_handle(&self) -> Self {
        match self {
            Self::Approval(value) => Self::Approval(Arc::clone(value)),
            Self::Denial(scope) => Self::Denial(Arc::clone(scope)),
        }
    }
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Approval(a), Self::Approval(b)) => Arc::ptr_eq(a, b),
            (Self::Denial(a), Self::Denial(b)) => a.same_scope(Arc::clone(b)),
            _ => false,
        }
    }
}
pub(crate) struct QueuedWrite {
    ticket: WriteTicket,
    control: Arc<DeliveryControl>,
}
enum WriteTicket {
    Approval(QueuedApproval),
    Denial(QueuedDenial),
}
impl QueuedWrite {
    pub(crate) fn complete(self) {
        let complete = match &self.ticket {
            WriteTicket::Approval(ticket) => {
                ticket.progress() == android_controller::ApprovalWriteProgress::WrittenToSocket
            }
            WriteTicket::Denial(ticket) => {
                ticket.progress() == android_controller::DenialWriteProgress::WrittenToSocket
            }
        };
        if complete {
            self.control.set(NativeDecisionProgress::WrittenToSocket);
        } else {
            self.control.stop();
        }
        self.control.sender_finished.store(true, Ordering::Release);
    }
}
impl Drop for QueuedWrite {
    fn drop(&mut self) {
        self.control.stop();
    }
}
pub(crate) enum DeliveryResult {
    Queued(QueuedWrite),
    Retry(DeliveryCommand, SendRetry),
    Rejected,
}

#[uniffi::export]
impl MobileController {
    pub fn request_approval_delivery(
        &self,
        submission: Arc<NativeApprovalSubmission>,
    ) -> Result<NativeDecisionProgress, BridgeError> {
        let _admission = self.enter()?;
        if !submission.belongs_to_controller(self) || submission.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        self.denial_fence(submission.request_key())?;
        let control = submission.delivery_control();
        if matches!(
            control.progress(),
            NativeDecisionProgress::Queued
                | NativeDecisionProgress::WrittenToSocket
                | NativeDecisionProgress::Stopped
                | NativeDecisionProgress::Rejected
        ) {
            return Ok(control.progress());
        }
        self.intake
            .enqueue_delivery(DeliveryCommand::Approval(submission))?;
        Ok(control.progress())
    }
}
impl MobileController {
    pub(crate) fn process_delivery(
        &self,
        socket: &mut AssociatedPcSocket,
        command: DeliveryCommand,
    ) -> Result<DeliveryResult, BridgeError> {
        let control = command.control();
        control.queued_command.store(false, Ordering::Release);
        if command.is_cancelled() {
            control.stop();
            return Ok(DeliveryResult::Rejected);
        }
        let mut clock = crate::approval::NativeApprovalClock::new(self);
        match &command {
            DeliveryCommand::Approval(value) => {
                if self.denial_fence(value.request_key()).is_err() {
                    value.cancel_context();
                    control.stop();
                    return Ok(DeliveryResult::Rejected);
                }
                let core = match value.take_core() {
                    Ok(core) => core,
                    Err(BridgeError::ApprovalRejected) => {
                        control.stop();
                        return Ok(DeliveryResult::Rejected);
                    }
                    Err(error) => return Err(error),
                };
                control.ever_admitted.store(true, Ordering::Release);
                let transition =
                    self.with_inbox(|owner| Ok(socket.queue_approval(owner, core, &mut clock)))?;
                let (checks, outcome) = transition.into_parts();
                if let Err(error) = self.dispatch_approval_checks(checks) {
                    socket.abort();
                    control.stop();
                    return Err(error);
                }
                if let Some(error) = clock.error() {
                    socket.abort();
                    control.stop();
                    return self.fail_closed(error);
                }
                match outcome {
                    ApprovalSendOutcome::Queued(ticket) => {
                        if self.denial_fence(value.request_key()).is_err() || value.is_cancelled() {
                            value.cancel_context();
                            socket.abort();
                            control.stop();
                            return Ok(DeliveryResult::Rejected);
                        }
                        control.set(NativeDecisionProgress::Queued);
                        control.sender_finished.store(false, Ordering::Release);
                        Ok(DeliveryResult::Queued(QueuedWrite {
                            ticket: WriteTicket::Approval(ticket),
                            control,
                        }))
                    }
                    ApprovalSendOutcome::Retry { reason, submission } => {
                        if let Err(error) = value.restore_retry(submission) {
                            control.stop();
                            return if error == BridgeError::ApprovalRejected {
                                Ok(DeliveryResult::Rejected)
                            } else {
                                Err(error)
                            };
                        }
                        control.ever_admitted.store(false, Ordering::Release);
                        control.set(NativeDecisionProgress::WaitingForPeer);
                        control.retry_blocked.store(true, Ordering::Release);
                        Ok(DeliveryResult::Retry(command, reason))
                    }
                    ApprovalSendOutcome::Rejected(_) => {
                        control.set(NativeDecisionProgress::Rejected);
                        control.sender_finished.store(true, Ordering::Release);
                        Ok(DeliveryResult::Rejected)
                    }
                }
            }
            DeliveryCommand::Denial(scope) => {
                let core = match self.take_denial_for_delivery(scope) {
                    Ok(core) => core,
                    Err(BridgeError::DenialRejected) => {
                        control.stop();
                        return Ok(DeliveryResult::Rejected);
                    }
                    Err(error) => return Err(error),
                };
                control.ever_admitted.store(true, Ordering::Release);
                let transition =
                    self.with_inbox(|owner| Ok(socket.queue_denial(owner, core, &mut clock)))?;
                let (checks, outcome) = transition.into_parts();
                if let Err(error) = self.dispatch_approval_checks(checks) {
                    socket.abort();
                    control.stop();
                    return Err(error);
                }
                if let Some(error) = clock.error() {
                    socket.abort();
                    control.stop();
                    return self.fail_closed(error);
                }
                match outcome {
                    DenialSendOutcome::Queued(ticket) => {
                        control.set(NativeDecisionProgress::Queued);
                        control.sender_finished.store(false, Ordering::Release);
                        Ok(DeliveryResult::Queued(QueuedWrite {
                            ticket: WriteTicket::Denial(ticket),
                            control,
                        }))
                    }
                    DenialSendOutcome::Retry { reason, submission } => {
                        if let Err(error) = self.restore_denial_retry(scope, submission) {
                            control.stop();
                            return if error == BridgeError::DenialRejected {
                                Ok(DeliveryResult::Rejected)
                            } else {
                                Err(error)
                            };
                        }
                        control.ever_admitted.store(false, Ordering::Release);
                        control.set(NativeDecisionProgress::WaitingForPeer);
                        control.retry_blocked.store(true, Ordering::Release);
                        Ok(DeliveryResult::Retry(command, reason))
                    }
                    DenialSendOutcome::Rejected(_) => {
                        control.set(NativeDecisionProgress::Rejected);
                        control.sender_finished.store(true, Ordering::Release);
                        Ok(DeliveryResult::Rejected)
                    }
                }
            }
        }
    }
}
