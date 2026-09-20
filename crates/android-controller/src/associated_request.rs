// SPDX-License-Identifier: GPL-2.0-or-later
//! Native-facing body lookup with original receiving provenance. Not an auth
//! plan: blocking commit/IO can expire the request before this snapshot returns.
#![forbid(unsafe_code)]

use std::{fmt, sync::Arc};

use notification_policy::RequestKey;
use phone_request_core::{InboxClock, InboxIssue, InboxUpdate, PendingRequest};
use phone_state_store::CommitReceipt;

use crate::{DurableFailure, DurableInbox, LocalKeySetDescriptor, PeerAssociation};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RequestSourceFailure {
    #[error("the event conflicts with its original receiving source")]
    Rejected(InboxIssue),
    #[error("the durable receiving owner is unavailable")]
    Owner(DurableFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssociatedRequestIssue {
    UnassociatedRequest,
    AssociationNoLongerCurrent,
    LocalKeysUnavailable,
}

/// Immutable metadata/body snapshot tied to its original receiving generation.
/// There is deliberately no public constructor, Clone, signing method or boolean
/// authentication result. A future plan owner must recheck live pending state,
/// original deadline, current owner/association and actual native conditions.
pub struct AssociatedPendingRequest {
    request: PendingRequest,
    association: PeerAssociation,
    local_keys: LocalKeySetDescriptor,
    // Identity only; does not retain a live storage owner or a native permission.
    owner_epoch: Arc<()>,
}

impl AssociatedPendingRequest {
    pub fn request(&self) -> &PendingRequest {
        &self.request
    }
    pub fn association(&self) -> &PeerAssociation {
        &self.association
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.local_keys
    }

    /// Only an owner-instance identity comparison, NOT a liveness/action check.
    pub fn belongs_to_owner(&self, owner: &DurableInbox) -> bool {
        Arc::ptr_eq(&self.owner_epoch, &owner.owner_epoch())
    }
}

impl fmt::Debug for AssociatedPendingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AssociatedPendingRequest([redacted], snapshot_not_permission)")
    }
}

/// Always carries committed downward effects, even when the body is withheld
/// because provenance is absent or its original registration is no longer current.
#[must_use = "dispatch downward effects and recheck fresh native time before any body use"]
pub struct CommittedAssociatedCheck {
    receipt: CommitReceipt,
    update: InboxUpdate,
    request: Option<AssociatedPendingRequest>,
    issue: Option<AssociatedRequestIssue>,
}

impl CommittedAssociatedCheck {
    pub const fn receipt(&self) -> CommitReceipt {
        self.receipt
    }
    pub fn update(&self) -> &InboxUpdate {
        &self.update
    }
    pub fn request(&self) -> Option<&AssociatedPendingRequest> {
        self.request.as_ref()
    }
    pub const fn issue(&self) -> Option<AssociatedRequestIssue> {
        self.issue
    }
}

impl fmt::Debug for CommittedAssociatedCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedAssociatedCheck")
            .field("issue", &self.issue)
            .field("has_request", &self.request.is_some())
            .finish_non_exhaustive()
    }
}

impl DurableInbox {
    pub fn check_associated_pending(
        &mut self,
        key: RequestKey,
        clock: InboxClock,
    ) -> Result<CommittedAssociatedCheck, DurableFailure> {
        let checked = self.check_pending(key, clock)?;
        let (receipt, checked) = checked.into_parts();
        let (update, request) = checked.into_parts();
        let (request, issue) = match request {
            None => (None, None),
            Some(request) => match self.associate_snapshot(request) {
                Ok(request) => (Some(request), None),
                Err(issue) => (None, Some(issue)),
            },
        };
        Ok(CommittedAssociatedCheck {
            receipt,
            update,
            request,
            issue,
        })
    }

    fn associate_snapshot(
        &self,
        request: PendingRequest,
    ) -> Result<AssociatedPendingRequest, AssociatedRequestIssue> {
        let original = request
            .receiving_generation()
            .ok_or(AssociatedRequestIssue::UnassociatedRequest)?;
        let association = self
            .peer_associations()
            .map_err(|_| AssociatedRequestIssue::AssociationNoLongerCurrent)?
            .lookup_current(request.binding().pc())
            .filter(|current| current.generation() == original.get())
            .ok_or(AssociatedRequestIssue::AssociationNoLongerCurrent)?
            .clone();
        let local_keys = self
            .local_keys()
            .map_err(|_| AssociatedRequestIssue::LocalKeysUnavailable)?
            .get(association.descriptor().local_key_handle())
            .and_then(|phase| phase.descriptor())
            .ok_or(AssociatedRequestIssue::LocalKeysUnavailable)?
            .clone();
        Ok(AssociatedPendingRequest {
            request,
            association,
            local_keys,
            owner_epoch: self.owner_epoch(),
        })
    }
}
