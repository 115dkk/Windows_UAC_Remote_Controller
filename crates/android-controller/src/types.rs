// SPDX-License-Identifier: GPL-2.0-or-later

use phone_request_core::{InboxCheck, InboxCheckpointError, InboxUpdate, OutcomeAcknowledgment};
use phone_state_store::{CommitReceipt, StoreError};
use thiserror::Error;

/// Fixed failure categories only; no paths, checkpoint bytes, bodies or OS text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DurableFault {
    #[error("request lifecycle integration is required before opening this state")]
    LifecycleIntegrationRequired,
    #[error("phone checkpoint storage failed")]
    Storage(StoreError),
    #[error("phone checkpoint validation failed")]
    Checkpoint(InboxCheckpointError),
    #[error("the native owner requires directory-synchronized storage")]
    DirectorySynchronizationRequired,
    #[error("the phone owner transition did not complete")]
    TransitionIncomplete,
}

/// A mandatory downward-only native action, never an authentication result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationCleanup {
    /// Clear all request notifications owned by this app, including recovered
    /// identifiers that an invalid checkpoint could not safely enumerate.
    ClearAllOwnedRequestNotifications,
}

/// Unaccepted failure, not a dropped/retained packet acknowledgment.
///
/// No candidate Show, Restore, history, request view or accepted disposition is
/// exposed. The native owner must stop intake, clear its request notifications
/// and discard caller-held views. A prior commit receipt does not establish the
/// current disk state after an uncertain failure. No rollback is implied.
#[must_use = "stop intake and clear all owned request notifications on failure"]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the durable inbox stopped; reconcile all owned request notifications")]
pub struct DurableFailure {
    cause: DurableFault,
}

impl DurableFailure {
    pub(crate) const fn new(cause: DurableFault) -> Self {
        Self { cause }
    }

    pub const fn cause(self) -> DurableFault {
        self.cause
    }

    pub const fn notification_cleanup(self) -> NotificationCleanup {
        NotificationCleanup::ClearAllOwnedRequestNotifications
    }
}

/// Counts of the last successfully committed in-memory domain state.
/// These are diagnostic metadata, never pending views or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxCounts {
    pub(crate) active: usize,
    pub(crate) retained: usize,
    pub(crate) retained_bodies: usize,
    pub(crate) recovering: usize,
    pub(crate) sources: usize,
}

impl InboxCounts {
    pub const fn active(self) -> usize {
        self.active
    }
    pub const fn retained(self) -> usize {
        self.retained
    }
    pub const fn retained_bodies(self) -> usize {
        self.retained_bodies
    }
    pub const fn recovering(self) -> usize {
        self.recovering
    }
    pub const fn sources(self) -> usize {
        self.sources
    }
}

/// Effects released only after an actual accepted-durability commit receipt.
///
/// This is not an OS-delivery, freshness or approval receipt. I/O may have taken
/// time: the native owner must obtain fresh suspend-inclusive native time after
/// I/O and recheck current state before posting or beginning a native action.
#[must_use = "apply committed withdrawals and recheck fresh native time before acting"]
#[derive(Debug)]
pub struct CommittedUpdate {
    pub(crate) receipt: CommitReceipt,
    pub(crate) update: InboxUpdate,
}

impl CommittedUpdate {
    pub const fn receipt(&self) -> CommitReceipt {
        self.receipt
    }
    pub fn update(&self) -> &InboxUpdate {
        &self.update
    }
    pub fn into_parts(self) -> (CommitReceipt, InboxUpdate) {
        (self.receipt, self.update)
    }
}

/// Checkpoint-backed acknowledgment, not a native journal or OS delivery receipt.
/// A crash after journal insertion but before this commit leaves the same ID
/// pending, so the recipient must durably deduplicate before acknowledging again.
#[must_use = "check the committed removal result; NotPending is not delivery proof"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommittedOutcomeAcknowledgment {
    pub(crate) receipt: CommitReceipt,
    pub(crate) acknowledgment: OutcomeAcknowledgment,
}

impl CommittedOutcomeAcknowledgment {
    pub const fn receipt(self) -> CommitReceipt {
        self.receipt
    }
    pub const fn acknowledgment(self) -> OutcomeAcknowledgment {
        self.acknowledgment
    }
}

/// A committed body view checked at the supplied pre-I/O clock, not a live permit.
///
/// Disk barriers can outlast a request. Obtain fresh native time after this call
/// and recheck the exact request/deadline and current native conditions before
/// use. That post-I/O native check is not implemented here; repeated file commits
/// are not a freshness guarantee. Later withdrawals invalidate caller-held Arc
/// snapshots; discard them.
#[must_use = "apply withdrawals and recheck fresh native time before using any body view"]
#[derive(Debug)]
pub struct CommittedCheck {
    pub(crate) receipt: CommitReceipt,
    pub(crate) check: InboxCheck,
}

impl CommittedCheck {
    pub const fn receipt(&self) -> CommitReceipt {
        self.receipt
    }
    pub fn check(&self) -> &InboxCheck {
        &self.check
    }
    pub fn into_parts(self) -> (CommitReceipt, InboxCheck) {
        (self.receipt, self.check)
    }
}
