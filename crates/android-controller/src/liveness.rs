// SPDX-License-Identifier: GPL-2.0-or-later
//! Process-local downward liveness only. No lease is enrollment, per-use
//! authentication, fresh request eligibility, or permission to sign/send/act.
#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use phone_request_core::{InboxFault, PhoneInbox, ReceivingGeneration};
use service_protocol::MappedRequestWindow;

use crate::{
    DurableFault, DurableInbox, LocalKeyLedger, LocalKeySetDescriptor, PeerAssociation,
    PeerAssociationLedger,
};

const MAX_LEASES: usize = 64;

struct LeaseState {
    owner_epoch: Arc<()>,
    association: PeerAssociation,
    local_keys: LocalKeySetDescriptor,
    request: Option<(MappedRequestWindow, ReceivingGeneration)>,
    revoked: AtomicBool,
}

/// Immutable metadata plus one irreversible process-local withdrawal bit.
/// Cloning shares that same bit; it does not allocate another registry slot or
/// retain the DurableInbox. No body, private key, raw constructor or rearm API.
/// Time passing alone does not update this value: native fresh checks and the
/// socket's original absolute deadline remain independently mandatory.
#[derive(Clone)]
pub struct NativePeerLease {
    state: Arc<LeaseState>,
}
impl NativePeerLease {
    pub fn association(&self) -> &PeerAssociation {
        &self.state.association
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.state.local_keys
    }
    pub fn is_revoked(&self) -> bool {
        self.state.revoked.load(Ordering::Acquire)
    }
    /// Owner-instance identity only, NOT a fresh liveness/action check.
    pub fn belongs_to_owner(&self, owner: &DurableInbox) -> bool {
        Arc::ptr_eq(&self.state.owner_epoch, &owner.owner_epoch())
    }
}
impl fmt::Debug for NativePeerLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePeerLease([redacted], downward_only)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeerLeaseError {
    #[error("durable peer owner is unavailable")]
    Owner(DurableFault),
    #[error("request lifecycle owner is faulted")]
    DomainFault(InboxFault),
    #[error("peer association is no longer current")]
    AssociationNotCurrent,
    #[error("exact local public key tuple is unavailable")]
    LocalKeysUnavailable,
    #[error("request snapshot belongs to another owner instance")]
    DifferentOwner,
    #[error("exact original associated request is no longer body-ready")]
    RequestNotPending,
    #[error("process-local peer lease capacity is exhausted")]
    Capacity,
    #[error("bounded peer lease allocation failed")]
    AllocationFailed,
}

#[derive(Default)]
pub(crate) struct LeaseRegistry {
    entries: Vec<Weak<LeaseState>>,
}
impl LeaseRegistry {
    pub(crate) fn register(
        &mut self,
        owner_epoch: Arc<()>,
        association: PeerAssociation,
        local_keys: LocalKeySetDescriptor,
        request: Option<(MappedRequestWindow, ReceivingGeneration)>,
    ) -> Result<NativePeerLease, PeerLeaseError> {
        // A revoked but still-held lease is deliberately NOT evicted. Only a
        // genuinely dead Weak releases capacity; clones share the same entry.
        let mut index = 0;
        while index < self.entries.len() {
            if Weak::<LeaseState>::upgrade(&self.entries[index]).is_none() {
                self.entries.swap_remove(index);
            } else {
                index += 1;
            }
        }
        if self.entries.len() >= MAX_LEASES {
            return Err(PeerLeaseError::Capacity);
        }
        self.entries
            .try_reserve_exact(1)
            .map_err(|_| PeerLeaseError::AllocationFailed)?;
        let state: Arc<LeaseState> = Arc::new(LeaseState {
            owner_epoch,
            association,
            local_keys,
            request,
            revoked: AtomicBool::new(false),
        });
        self.entries.push(Arc::downgrade(&state));
        Ok(NativePeerLease { state })
    }

    pub(crate) fn invalidate_all(&self) {
        for state in self.entries.iter().filter_map(Weak::upgrade) {
            state.revoked.store(true, Ordering::Release);
        }
    }

    pub(crate) fn reconcile(
        &mut self,
        inbox: &PhoneInbox,
        associations: &PeerAssociationLedger,
        local_keys: &LocalKeyLedger,
    ) {
        let healthy = inbox.fault().is_none();
        let mut index = 0;
        while index < self.entries.len() {
            let Some(state) = Weak::<LeaseState>::upgrade(&self.entries[index]) else {
                self.entries.swap_remove(index);
                continue;
            };
            if !healthy
                || associations.resolve(state.association.reference()) != Some(&state.association)
                || local_keys
                    .get(state.local_keys.handle())
                    .and_then(|phase| phase.descriptor())
                    != Some(&state.local_keys)
                || state.request.is_some_and(|(window, source)| {
                    !inbox.retains_exact_pending_snapshot(window, source)
                })
            {
                state.revoked.store(true, Ordering::Release);
            }
            index += 1;
        }
    }

    pub(crate) fn begin_transition(&mut self) -> LeaseTransition<'_> {
        LeaseTransition {
            registry: self,
            completed: false,
        }
    }

    /// Read-only candidate preparation may reject harmless input normally. An
    /// unwind still withdraws all already-issued leases before it propagates.
    pub(crate) fn preserve_on_return<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        let mut transition = self.begin_transition();
        let result = operation();
        transition.preserve();
        result
    }
}
impl Drop for LeaseRegistry {
    fn drop(&mut self) {
        self.invalidate_all();
    }
}

pub(crate) struct LeaseTransition<'a> {
    registry: &'a mut LeaseRegistry,
    completed: bool,
}
impl LeaseTransition<'_> {
    pub(crate) fn reconcile(
        &mut self,
        inbox: &PhoneInbox,
        associations: &PeerAssociationLedger,
        local_keys: &LocalKeyLedger,
    ) {
        self.registry.reconcile(inbox, associations, local_keys);
        self.completed = true;
    }
    pub(crate) fn preserve(&mut self) {
        self.completed = true;
    }
}
impl Drop for LeaseTransition<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.registry.invalidate_all();
        }
    }
}
