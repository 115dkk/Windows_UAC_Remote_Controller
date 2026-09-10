// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot PC acceptance into the existing phone checkpoint, not a ceremony.
//!
//! The external trusted native owner must independently establish original QR
//! provenance, explicit consent, a fresh unpredictable nonce, the PC pins and
//! the original monotonic deadline. A PC signature does not prove those facts,
//! Android attestation/key possession, or that the PC actually committed a row.
//! That real ceremony source and PC receipt producer are not wired here.
//!
//! No private keys, key creation/reopening, networking, renderer/UniFFI entry
//! point, paired flag, second store or recovery fallback is introduced. Pending
//! state is process-local and cannot be cloned, serialized or resumed on reopen.

use std::{
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use approval_protocol::PcIdentity;
use framed_transport::{SocketClock, SocketClockUnavailable};
use phone_request_core::InboxFault;
use phone_state_store::CommitReceipt;
use secure_channel::TlsPublicKey;
use service_protocol::{PairingError, PairingNonce, PhoneKeyDigest, SignedEnrollmentAcceptance};

use crate::{
    DurableFailure, DurableFault, DurableInbox, LocalKeyLedger, LocalKeySetDescriptor,
    PeerAssociationDescriptor, PeerAssociationLedger, PeerAssociationMutationError,
    PeerAssociationRef,
};

pub const MAX_PENDING_PAIRING_ACCEPTANCES: usize = 32;
pub const MAX_PAIRING_ACCEPTANCE_LIFETIME: Duration = Duration::from_secs(300);

/// Inputs from the ORIGINAL trusted native ceremony, not an authority witness.
///
/// Supply the exact descriptor already committed as CreatedUnverified and the
/// PC identity/pins learned through the independently approved ceremony. The
/// nonce must be unpredictable and never reused, even after cancellation or
/// rejection. `started_at` and `deadline` must be the original native monotonic
/// instants, never reception time, relay fields or a newly refreshed timeout.
/// Both instants MUST use the same immutable projection coordinate as `clock`.
/// That captured trusted-native provider supplies EVERY continuing observation,
/// including suspend-inclusive elapsed time and native boot/regression checks;
/// `Instant` is only a coordinate type, never a continuing-time fallback here.
/// Clock callbacks must only observe time, without owner mutation or reentry.
/// This DTO itself proves none of those preconditions. No real QR/consent source
/// currently constructs it, and it must never be accepted through JS or FFI.
pub struct PairingAcceptanceContext {
    pub local_keys: LocalKeySetDescriptor,
    pub pc: PcIdentity,
    pub pc_signing_key: TlsPublicKey,
    pub pc_transport_key: TlsPublicKey,
    pub ceremony_nonce: PairingNonce,
    pub clock: Arc<dyn SocketClock>,
    pub started_at: Instant,
    pub deadline: Instant,
}
impl fmt::Debug for PairingAcceptanceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingAcceptanceContext([redacted], native_preconditions_required)")
    }
}

struct PairingReservation {
    local_keys: LocalKeySetDescriptor,
    pc: PcIdentity,
    pc_signing_key: TlsPublicKey,
    pc_transport_key: TlsPublicKey,
    ceremony_nonce: PairingNonce,
    cancelled: AtomicBool,
}

/// Owner-bound, non-Clone, single-use expectation, not a paired/native grant.
/// A cancelled but still-held value keeps its bounded reservation until drop.
/// ```compile_fail
/// fn duplicate(value: android_controller::PendingPairingAcceptance) {
///     let _copy = value.clone();
/// }
/// ```
#[must_use = "consume with the same durable owner or drop to abandon this expectation"]
pub struct PendingPairingAcceptance {
    owner_epoch: Arc<()>,
    reservation: Arc<PairingReservation>,
    clock: Arc<dyn SocketClock>,
    started_at: Instant,
    deadline: Instant,
    last_observed: Instant,
}
impl PendingPairingAcceptance {
    /// Irreversible memory-only cancellation. It does not revoke a PC registry
    /// row, remove local metadata, delete keys or assert remote cancellation.
    pub fn cancel(&self) {
        self.reservation.cancelled.store(true, Ordering::Release);
    }

    fn check_current(&self, owner: &DurableInbox) -> Result<(), PairingAcceptanceError> {
        if !Arc::ptr_eq(&self.owner_epoch, &owner.owner_epoch()) {
            return Err(PairingAcceptanceError::DifferentOwner);
        }
        // Enrollment is an upward trust mutation. A durable snapshot with a
        // faulted receiving domain is not a healthy source of that authority.
        if let Some(fault) = owner.inbox_fault().map_err(owner_error)? {
            return Err(PairingAcceptanceError::DomainFault(fault));
        }
        if self.reservation.cancelled.load(Ordering::Acquire) {
            return Err(PairingAcceptanceError::Cancelled);
        }
        self.reservation.check_current(
            owner.local_keys().map_err(owner_error)?,
            owner.peer_associations().map_err(owner_error)?,
        )
    }

    fn observe(&mut self, now: Instant) -> Result<(), PairingAcceptanceError> {
        if now < self.started_at || now < self.last_observed {
            return Err(PairingAcceptanceError::ClockRollback);
        }
        if now >= self.deadline {
            return Err(PairingAcceptanceError::Expired);
        }
        self.last_observed = now;
        Ok(())
    }

    fn descriptor_from_wire(
        &self,
        wire: &[u8],
    ) -> Result<PeerAssociationDescriptor, PairingAcceptanceError> {
        // The protocol decoder bounds input before allocating/parsing. The
        // verification key is the ORIGINAL pin, never one learned from wire.
        let signed = SignedEnrollmentAcceptance::from_wire(wire)
            .map_err(PairingAcceptanceError::Protocol)?;
        let verified = signed
            .verify(&self.reservation.pc_signing_key)
            .map_err(PairingAcceptanceError::Protocol)?;
        let fields = verified.fields();
        let expected = &self.reservation;
        let digest = PhoneKeyDigest::from_keys(
            expected.local_keys.approval_key(),
            expected.local_keys.denial_key(),
            expected.local_keys.transport_key(),
        )
        .map_err(PairingAcceptanceError::Protocol)?;
        if fields.ceremony_nonce != expected.ceremony_nonce
            || fields.attestation_challenge.as_bytes() != expected.local_keys.challenge().as_bytes()
            || fields.phone_keys != digest
            || fields.pc != expected.pc
            || fields.pc_signing_key != expected.pc_signing_key
            || fields.pc_transport_key != expected.pc_transport_key
            || fields.registry_revision == 0
        {
            return Err(PairingAcceptanceError::BindingMismatch);
        }
        // Device/revision are authenticated PC assignments, not assertions of
        // observed remote persistence. Full local relationship checks follow.
        PeerAssociationDescriptor::new(
            expected.pc,
            fields.recipient_device,
            fields.registry_revision,
            expected.local_keys.handle(),
            expected.pc_signing_key.clone(),
            expected.pc_transport_key.clone(),
        )
        .map_err(|error| {
            PairingAcceptanceError::Association(PeerAssociationMutationError::Rejected(error))
        })
    }
}
impl fmt::Debug for PendingPairingAcceptance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingPairingAcceptance([redacted], one_shot_not_paired)")
    }
}

impl PairingReservation {
    fn check_current(
        &self,
        local_keys: &LocalKeyLedger,
        associations: &PeerAssociationLedger,
    ) -> Result<(), PairingAcceptanceError> {
        if local_keys
            .get(self.local_keys.handle())
            .and_then(|phase| phase.descriptor())
            != Some(&self.local_keys)
        {
            return Err(PairingAcceptanceError::LocalKeysChanged);
        }
        for existing in associations.entries() {
            let descriptor = existing.descriptor();
            if descriptor.pc() == self.pc
                || descriptor.local_key_handle() == self.local_keys.handle()
            {
                return Err(PairingAcceptanceError::AlreadyAssociated);
            }
            let current_pins = [descriptor.pc_signing_key(), descriptor.pc_transport_key()];
            if current_pins.contains(&&self.pc_signing_key)
                || current_pins.contains(&&self.pc_transport_key)
            {
                return Err(PairingAcceptanceError::PcPinConflict);
            }
        }
        for local in local_keys.entries().filter_map(|phase| phase.descriptor()) {
            let roles = [
                local.approval_key(),
                local.denial_key(),
                local.transport_key(),
            ];
            if roles.contains(&&self.pc_signing_key) || roles.contains(&&self.pc_transport_key) {
                return Err(PairingAcceptanceError::PcPinConflict);
            }
        }
        Ok(())
    }
}

/// Only the LOCAL full-checkpoint commit was observed. The acceptance contains
/// a signed PC claim; this is not a witnessed remote commit, live connection,
/// Android attestation/authentication result, or Windows UAC success.
/// Blocking flush may finish after the original deadline: freshness was checked
/// at the logical mutation point, not certified at I/O completion.
#[must_use = "a local association receipt is not native or remote pairing completion"]
#[derive(Debug)]
pub struct CommittedPairingAcceptance {
    receipt: CommitReceipt,
    association: PeerAssociationRef,
}
impl CommittedPairingAcceptance {
    pub const fn receipt(&self) -> CommitReceipt {
        self.receipt
    }
    pub const fn association(&self) -> PeerAssociationRef {
        self.association
    }
}

impl DurableInbox {
    /// Capture one original native expectation without writing storage or
    /// touching keys. All external prerequisites on PairingAcceptanceContext
    /// remain mandatory; this is a Rust seam, not the implemented QR workflow.
    pub fn begin_pairing_acceptance_from_trusted_host(
        &mut self,
        context: PairingAcceptanceContext,
    ) -> Result<PendingPairingAcceptance, PairingAcceptanceError> {
        let now = context
            .clock
            .now()
            .map_err(|_| PairingAcceptanceError::ClockUnavailable)?;
        self.begin_pairing_acceptance_at(context, now)
    }

    fn begin_pairing_acceptance_at(
        &mut self,
        context: PairingAcceptanceContext,
        now: Instant,
    ) -> Result<PendingPairingAcceptance, PairingAcceptanceError> {
        // The duration is only a bound check. It is NEVER added to reception
        // time: preserve both absolute endpoints of the original ceremony.
        if context
            .deadline
            .checked_duration_since(context.started_at)
            .is_none_or(|duration| duration.is_zero() || duration > MAX_PAIRING_ACCEPTANCE_LIFETIME)
        {
            return Err(PairingAcceptanceError::InvalidLifetime);
        }
        let mut pending = PendingPairingAcceptance {
            owner_epoch: self.owner_epoch(),
            clock: context.clock,
            reservation: Arc::new(PairingReservation {
                local_keys: context.local_keys,
                pc: context.pc,
                pc_signing_key: context.pc_signing_key,
                pc_transport_key: context.pc_transport_key,
                ceremony_nonce: context.ceremony_nonce,
                cancelled: AtomicBool::new(false),
            }),
            started_at: context.started_at,
            deadline: context.deadline,
            last_observed: context.started_at,
        };
        pending.check_current(self)?;
        pending.observe(now)?;
        self.reserve_pairing_acceptance(&pending)?;
        Ok(pending)
    }

    /// Consume one expectation and bounded signed wire, then commit through
    /// this same exclusive owner's full composite transaction. Every failure
    /// consumes the expectation; neither rejection nor retry refreshes its time.
    /// A failed/uncertain write retains the ordinary owner fault/cleanup contract
    /// and never reports a successful association or claims remote rollback.
    pub fn commit_pairing_acceptance(
        &mut self,
        pending: PendingPairingAcceptance,
        wire: &[u8],
    ) -> Result<CommittedPairingAcceptance, PairingAcceptanceError> {
        // Retain this exact original provider; the receive API accepts no
        // replacement clock, and never advances using std::Instant::now().
        let clock = Arc::clone(&pending.clock);
        self.commit_pairing_acceptance_observing(pending, wire, || clock.now())
    }

    fn commit_pairing_acceptance_observing(
        &mut self,
        mut pending: PendingPairingAcceptance,
        wire: &[u8],
        mut now: impl FnMut() -> Result<Instant, SocketClockUnavailable>,
    ) -> Result<CommittedPairingAcceptance, PairingAcceptanceError> {
        pending.check_current(self)?;
        pending.observe(now().map_err(|_| PairingAcceptanceError::ClockUnavailable)?)?;
        let descriptor = pending.descriptor_from_wire(wire)?;
        // Recheck the full original context AFTER signature/codec/composite
        // work, directly before the existing logical durable mutation point.
        let (receipt, association) = self.commit_pairing_association(descriptor, |owner| {
            pending.check_current(owner)?;
            pending.observe(now().map_err(|_| PairingAcceptanceError::ClockUnavailable)?)
        })?;
        Ok(CommittedPairingAcceptance {
            receipt,
            association,
        })
    }

    /// Existing deterministic unit cases can isolate individual observation
    /// points. Only test builds have this helper; the public path always uses
    /// the immutable provider captured from the original native context.
    #[cfg(all(test, any(windows, target_os = "linux")))]
    fn commit_pairing_acceptance_with_clock(
        &mut self,
        pending: PendingPairingAcceptance,
        wire: &[u8],
        mut now: impl FnMut() -> Instant,
    ) -> Result<CommittedPairingAcceptance, PairingAcceptanceError> {
        self.commit_pairing_acceptance_observing(pending, wire, || Ok(now()))
    }
}

#[derive(Default)]
pub(crate) struct PairingRegistry {
    entries: Vec<Weak<PairingReservation>>,
}
impl PairingRegistry {
    pub(crate) fn register(
        &mut self,
        pending: &PendingPairingAcceptance,
    ) -> Result<(), PairingAcceptanceError> {
        self.entries
            .retain(|entry: &Weak<PairingReservation>| entry.strong_count() != 0);
        let candidate = &pending.reservation;
        for existing in self.entries.iter().filter_map(Weak::upgrade) {
            if existing.pc == candidate.pc
                || existing.local_keys.handle() == candidate.local_keys.handle()
                || existing.ceremony_nonce == candidate.ceremony_nonce
            {
                return Err(PairingAcceptanceError::AlreadyPending);
            }
        }
        if self.entries.len() >= MAX_PENDING_PAIRING_ACCEPTANCES {
            return Err(PairingAcceptanceError::Capacity);
        }
        self.entries
            .try_reserve_exact(1)
            .map_err(|_| PairingAcceptanceError::AllocationFailed)?;
        self.entries.push(Arc::downgrade(candidate));
        Ok(())
    }

    pub(crate) fn reconcile(
        &self,
        local_keys: &LocalKeyLedger,
        associations: &PeerAssociationLedger,
        inbox_fault: Option<InboxFault>,
    ) {
        if inbox_fault.is_some() {
            self.invalidate_all();
            return;
        }
        for pending in self.entries.iter().filter_map(Weak::upgrade) {
            if pending.check_current(local_keys, associations).is_err() {
                // Irreversible: adding and subsequently revoking a conflicting
                // association cannot resurrect an older ceremony expectation.
                pending.cancelled.store(true, Ordering::Release);
            }
        }
    }

    pub(crate) fn invalidate_all(&self) {
        for pending in self.entries.iter().filter_map(Weak::upgrade) {
            pending.cancelled.store(true, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PairingAcceptanceError {
    #[error("the receiving domain is faulted and cannot add pairing trust")]
    DomainFault(InboxFault),
    #[error("the pairing expectation belongs to another durable owner")]
    DifferentOwner,
    #[error("the pairing expectation was cancelled or invalidated")]
    Cancelled,
    #[error("the original pairing lifetime is invalid or exceeds 300 seconds")]
    InvalidLifetime,
    #[error("the pairing monotonic clock moved backwards")]
    ClockRollback,
    #[error("the captured trusted native pairing clock is unavailable")]
    ClockUnavailable,
    #[error("the original pairing deadline elapsed")]
    Expired,
    #[error("the exact created local key tuple is unavailable")]
    LocalKeysChanged,
    #[error("the PC or local handle already has a current association")]
    AlreadyAssociated,
    #[error("the original PC pins conflict with current key relationships")]
    PcPinConflict,
    #[error("a live expectation already reserves this PC, local handle or nonce")]
    AlreadyPending,
    #[error("the bounded pairing expectation capacity is exhausted")]
    Capacity,
    #[error("bounded pairing expectation allocation failed")]
    AllocationFailed,
    #[error("the signed acceptance differs from the original ceremony context")]
    BindingMismatch,
    #[error("the PC acceptance encoding or signature was rejected")]
    Protocol(PairingError),
    #[error("the existing durable association transaction rejected or failed")]
    Association(PeerAssociationMutationError),
}

fn owner_error(fault: DurableFault) -> PairingAcceptanceError {
    PairingAcceptanceError::Association(PeerAssociationMutationError::Owner(DurableFailure::new(
        fault,
    )))
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests;
