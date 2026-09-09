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
/// Exact request-specific registrations may share this same domain-wide bit;
/// per-operation cancellation is separate and cannot manually revoke a lease.
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
        // Share only an identical, still-live REQUEST restriction. The caller
        // has already repeated its current owner/body/source/key checks. This
        // is not a fresh permission, and must never revive a revoked state or
        // collapse independently registered connection-only restrictions.
        if request.is_some()
            && let Some(state) = self.entries.iter().filter_map(Weak::upgrade).find(|state| {
                !state.revoked.load(Ordering::Acquire)
                    && Arc::ptr_eq(&state.owner_epoch, &owner_epoch)
                    && state.association == association
                    && state.local_keys == local_keys
                    && state.request == request
            })
        {
            return Ok(NativePeerLease { state });
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

#[cfg(test)]
mod tests {
    use super::*;
    use approval_protocol::{
        BootEpoch, ChallengeNonce, ContentDigest, DeviceId, ExpiryTick, OsSession, PcIdentity,
        RequestBinding, RequestId,
    };
    use p256::{PublicKey, ecdsa::SigningKey, pkcs8::EncodePublicKey};
    use secure_channel::TlsPublicKey;
    use service_protocol::ServiceTick;

    use crate::{LocalAttestationChallenge, LocalKeyHandle, PeerAssociationDescriptor};

    // Pure metadata fixtures for the PRIVATE registry matcher. In particular,
    // changed tuples below may be rejected by the upstream durable owner; these
    // unit values prove no real enrollment, storage, ingress or native authority.
    #[derive(Clone)]
    struct Metadata {
        owner_epoch: Arc<()>,
        association: PeerAssociation,
        local_keys: LocalKeySetDescriptor,
        request: (MappedRequestWindow, ReceivingGeneration),
    }

    fn public(seed: u8) -> TlsPublicKey {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point =
            PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
                .unwrap();
        TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
    }

    fn local(handle: u8, challenge: u8, roles: [u8; 3]) -> LocalKeySetDescriptor {
        LocalKeySetDescriptor::new(
            LocalKeyHandle::from_bytes([handle; 32]).unwrap(),
            LocalAttestationChallenge::from_bytes([challenge; 32]).unwrap(),
            public(roles[0]),
            public(roles[1]),
            public(roles[2]),
        )
        .unwrap()
    }

    fn association(
        local: &LocalKeySetDescriptor,
        descriptor: PeerAssociationDescriptor,
        reenroll: bool,
    ) -> PeerAssociation {
        let mut keys = LocalKeyLedger::new();
        keys.begin_creation(local.handle(), local.challenge())
            .unwrap();
        keys.record_created(local.clone()).unwrap();
        let mut peers = PeerAssociationLedger::new();
        peers
            .record_from_trusted_host(descriptor.clone(), &keys)
            .unwrap();
        if reenroll {
            let reference = peers.lookup_current(descriptor.pc()).unwrap().reference();
            assert_eq!(
                peers.remove_from_trusted_host(reference),
                crate::PeerAssociationRemoval::Removed
            );
            peers
                .record_from_trusted_host(descriptor.clone(), &keys)
                .unwrap();
        }
        peers.lookup_current(descriptor.pc()).unwrap().clone()
    }

    fn mapped(
        binding: RequestBinding,
        service_issued: u64,
        phone_issued: u64,
        phone_expiry: u64,
    ) -> MappedRequestWindow {
        MappedRequestWindow::from_trusted_checkpoint(
            binding,
            ServiceTick::from_nanos_since_epoch(service_issued),
            phone_issued,
            phone_expiry,
        )
        .unwrap()
    }

    fn metadata() -> Metadata {
        let local_keys = local(42, 41, [3, 4, 5]);
        let pc = PcIdentity::from_bytes([21; 32]).unwrap();
        let descriptor = PeerAssociationDescriptor::new(
            pc,
            DeviceId::from_bytes([22; 16]).unwrap(),
            1,
            local_keys.handle(),
            public(6),
            public(7),
        )
        .unwrap();
        let association = association(&local_keys, descriptor, false);
        let binding = RequestBinding::new(
            pc,
            BootEpoch::from_bytes([2; 32]).unwrap(),
            OsSession::new(1, 3),
            RequestId::from_bytes([4; 32]).unwrap(),
            ChallengeNonce::from_bytes([5; 32]).unwrap(),
            ContentDigest::from_bytes([6; 32]),
            ExpiryTick::from_nanos_since_epoch(2_000).unwrap(),
        );
        Metadata {
            owner_epoch: Arc::new(()),
            association,
            local_keys,
            request: (
                mapped(binding, 100, 200, 1_000),
                ReceivingGeneration::from_trusted_owner(1).unwrap(),
            ),
        }
    }

    fn register_request(registry: &mut LeaseRegistry, input: &Metadata) -> NativePeerLease {
        registry
            .register(
                Arc::clone(&input.owner_epoch),
                input.association.clone(),
                input.local_keys.clone(),
                Some(input.request),
            )
            .unwrap()
    }

    fn register_connection(
        registry: &mut LeaseRegistry,
        input: &Metadata,
    ) -> Result<NativePeerLease, PeerLeaseError> {
        registry.register(
            Arc::clone(&input.owner_epoch),
            input.association.clone(),
            input.local_keys.clone(),
            None,
        )
    }

    #[test]
    fn exact_request_reuses_one_shared_downward_state() {
        let input = metadata();
        let mut registry = LeaseRegistry::default();
        let first = register_request(&mut registry, &input);
        let repeated = register_request(&mut registry, &input);
        assert!(Arc::ptr_eq(&first.state, &repeated.state));
        assert_eq!(registry.entries.len(), 1);
        assert!(!first.is_revoked());
        registry.invalidate_all();
        assert!(first.is_revoked());
        assert!(repeated.is_revoked());
    }

    #[test]
    fn owner_full_association_and_full_local_tuple_mismatches_are_not_shared() {
        let input = metadata();
        let mut candidates = Vec::new();
        let mut different_owner = input.clone();
        different_owner.owner_epoch = Arc::new(());
        candidates.push(("owner Arc identity", different_owner));

        let original = input.association.descriptor();
        for (name, pc, device, revision, signing, transport) in [
            (
                "association PC",
                PcIdentity::from_bytes([23; 32]).unwrap(),
                original.recipient_device_id(),
                1,
                public(6),
                public(7),
            ),
            (
                "recipient device",
                original.pc(),
                DeviceId::from_bytes([23; 16]).unwrap(),
                1,
                public(6),
                public(7),
            ),
            (
                "PC registry revision",
                original.pc(),
                original.recipient_device_id(),
                2,
                public(6),
                public(7),
            ),
            (
                "PC signing key",
                original.pc(),
                original.recipient_device_id(),
                1,
                public(8),
                public(7),
            ),
            (
                "PC transport key",
                original.pc(),
                original.recipient_device_id(),
                1,
                public(6),
                public(8),
            ),
        ] {
            let descriptor = PeerAssociationDescriptor::new(
                pc,
                device,
                revision,
                input.local_keys.handle(),
                signing,
                transport,
            )
            .unwrap();
            let mut changed = input.clone();
            changed.association = association(&input.local_keys, descriptor, false);
            candidates.push((name, changed));
        }
        let mut reenrolled = input.clone();
        reenrolled.association = association(&input.local_keys, original.clone(), true);
        candidates.push(("local association generation", reenrolled));
        let alternate_local = local(43, 41, [3, 4, 5]);
        let descriptor = PeerAssociationDescriptor::new(
            original.pc(),
            original.recipient_device_id(),
            1,
            alternate_local.handle(),
            public(6),
            public(7),
        )
        .unwrap();
        let mut changed_handle = input.clone();
        changed_handle.association = association(&alternate_local, descriptor, false);
        candidates.push(("association local handle", changed_handle));

        for (name, keys) in [
            ("local handle", local(43, 41, [3, 4, 5])),
            ("local challenge", local(42, 40, [3, 4, 5])),
            ("local approval key", local(42, 41, [8, 4, 5])),
            ("local denial key", local(42, 41, [3, 8, 5])),
            ("local transport key", local(42, 41, [3, 4, 8])),
        ] {
            let mut changed = input.clone();
            changed.local_keys = keys;
            candidates.push((name, changed));
        }

        let mut registry = LeaseRegistry::default();
        let first = register_request(&mut registry, &input);
        let mut held = Vec::new();
        for (name, changed) in candidates {
            let lease = register_request(&mut registry, &changed);
            assert!(!Arc::ptr_eq(&first.state, &lease.state), "{name}");
            assert!(
                held.iter()
                    .all(|previous: &NativePeerLease| !Arc::ptr_eq(&previous.state, &lease.state)),
                "{name}"
            );
            held.push(lease);
            assert_eq!(registry.entries.len(), held.len() + 1);
        }
    }

    #[test]
    fn full_original_mapping_and_receiving_generation_must_match() {
        let input = metadata();
        let mut candidates = Vec::new();
        let b = input.request.0.binding();
        for index in 0..8 {
            let changed = RequestBinding::new(
                if index == 0 {
                    PcIdentity::from_bytes([23; 32]).unwrap()
                } else {
                    b.pc()
                },
                if index == 1 {
                    BootEpoch::from_bytes([3; 32]).unwrap()
                } else {
                    b.epoch()
                },
                match index {
                    2 => OsSession::new(2, b.session().logon_id()),
                    3 => OsSession::new(b.session().session_id(), 4),
                    _ => b.session(),
                },
                if index == 4 {
                    RequestId::from_bytes([7; 32]).unwrap()
                } else {
                    b.request_id()
                },
                if index == 5 {
                    ChallengeNonce::from_bytes([7; 32]).unwrap()
                } else {
                    b.nonce()
                },
                if index == 6 {
                    ContentDigest::from_bytes([7; 32])
                } else {
                    b.content_digest()
                },
                if index == 7 {
                    ExpiryTick::from_nanos_since_epoch(2_001).unwrap()
                } else {
                    b.expiry()
                },
            );
            candidates.push((mapped(changed, 100, 200, 1_000), input.request.1));
        }
        candidates.extend([
            (mapped(b, 101, 200, 1_000), input.request.1),
            (mapped(b, 100, 201, 1_000), input.request.1),
            (mapped(b, 100, 200, 1_001), input.request.1),
            (
                input.request.0,
                ReceivingGeneration::from_trusted_owner(2).unwrap(),
            ),
        ]);
        let mut registry = LeaseRegistry::default();
        let first = register_request(&mut registry, &input);
        let mut held = Vec::new();
        for request in candidates {
            let mut changed = input.clone();
            changed.request = request;
            let lease = register_request(&mut registry, &changed);
            assert!(!Arc::ptr_eq(&first.state, &lease.state));
            assert!(
                held.iter()
                    .all(|previous: &NativePeerLease| !Arc::ptr_eq(&previous.state, &lease.state))
            );
            held.push(lease);
            assert_eq!(registry.entries.len(), held.len() + 1);
        }
    }

    #[test]
    fn exact_live_request_can_be_reused_at_capacity_without_reusing_connections() {
        let input = metadata();
        let mut registry = LeaseRegistry::default();
        let request = register_request(&mut registry, &input);
        let connections: Vec<_> = (1..MAX_LEASES)
            .map(|_| register_connection(&mut registry, &input).unwrap())
            .collect();
        let reused = register_request(&mut registry, &input);
        assert!(Arc::ptr_eq(&request.state, &reused.state));
        assert_eq!(connections.len() + 1, MAX_LEASES);
        assert_eq!(registry.entries.len(), MAX_LEASES);
        assert_eq!(
            register_connection(&mut registry, &input).unwrap_err(),
            PeerLeaseError::Capacity
        );
        assert_eq!(
            registry
                .register(
                    Arc::clone(&input.owner_epoch),
                    input.association.clone(),
                    input.local_keys.clone(),
                    Some((
                        input.request.0,
                        ReceivingGeneration::from_trusted_owner(2).unwrap()
                    )),
                )
                .unwrap_err(),
            PeerLeaseError::Capacity
        );
        registry.invalidate_all();
        assert_eq!(
            registry
                .register(
                    Arc::clone(&input.owner_epoch),
                    input.association.clone(),
                    input.local_keys.clone(),
                    Some(input.request),
                )
                .unwrap_err(),
            PeerLeaseError::Capacity
        );
        assert!(request.is_revoked() && reused.is_revoked());
        assert!(connections.iter().all(NativePeerLease::is_revoked));
    }

    #[test]
    fn connection_only_registrations_are_distinct_and_never_substitute_for_a_request() {
        let input = metadata();
        let mut registry = LeaseRegistry::default();
        let first = register_connection(&mut registry, &input).unwrap();
        let second = register_connection(&mut registry, &input).unwrap();
        let request = register_request(&mut registry, &input);
        assert!(!Arc::ptr_eq(&first.state, &second.state));
        assert!(!Arc::ptr_eq(&first.state, &request.state));
        assert!(!Arc::ptr_eq(&second.state, &request.state));
        assert_eq!(registry.entries.len(), 3);
    }

    #[test]
    fn a_revoked_request_is_retained_but_never_reused_or_rearmed() {
        let input = metadata();
        let mut registry = LeaseRegistry::default();
        let revoked = register_request(&mut registry, &input);
        registry.invalidate_all();
        let fresh = register_request(&mut registry, &input);
        assert!(!Arc::ptr_eq(&revoked.state, &fresh.state));
        assert!(revoked.is_revoked());
        assert!(!fresh.is_revoked());
        assert_eq!(registry.entries.len(), 2);
        let repeated = register_request(&mut registry, &input);
        assert!(Arc::ptr_eq(&fresh.state, &repeated.state));
        assert_eq!(registry.entries.len(), 2);
    }

    #[test]
    fn only_the_last_strong_reference_drop_recovers_a_capacity_slot() {
        let input = metadata();
        let mut registry = LeaseRegistry::default();
        let mut held: Vec<_> = (0..MAX_LEASES)
            .map(|_| register_connection(&mut registry, &input).unwrap())
            .collect();
        let last_copy = held.last().unwrap().clone();
        drop(held.pop().unwrap());
        assert_eq!(
            register_connection(&mut registry, &input).unwrap_err(),
            PeerLeaseError::Capacity
        );
        drop(last_copy);
        let replacement = register_request(&mut registry, &input);
        assert!(!replacement.is_revoked());
        assert!(held.iter().all(|lease| !lease.is_revoked()));
        assert_eq!(registry.entries.len(), MAX_LEASES);
        assert!(Arc::ptr_eq(
            &replacement.state,
            &register_request(&mut registry, &input).state
        ));
    }
}
