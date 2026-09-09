// SPDX-License-Identifier: GPL-2.0-or-later
//! One request-bound native denial operation, without an authentication stage.
//!
//! The containing trusted native actor owns one DenialOwner for its exact
//! DurableInbox/native boot. It must freshly check secure-screen-lock state and
//! quiesce any concurrent approval UI before user denial. This module neither
//! invokes authentication nor supplies a generic signing/native-key interface.
//! CreatedUnverified alone is not enrollment: the original receiving generation
//! must resolve to the current immutable association and exact local key tuple.
//!
//! The existing ApprovalClock/ApprovalTime names describe observations only.
//! Callbacks must be non-reentrant, fallible native time reads outside application
//! mutexes; never perform signing, UI, owner mutation or cleanup in a callback.
//! All blocking checks are followed by a fresh read, as is signature verification.
//! No borrow of this owner or DurableInbox spans the actual native signing call.
//!
//! Every committed downward check is returned even on rejection. Preparing a
//! denial does not resolve the request or record a Windows-denied history row.
//! Native key use and Application/ABI wiring are absent. The optional typed
//! socket sender retains this operation's cancellation/liveness through writes.
#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, RequestBinding, SignedDecision, UnsignedDecision,
};
use notification_policy::RequestKey;
use phone_request_core::{InboxFault, PhoneBootId};
use service_protocol::MappedRequestWindow;

use crate::{
    ApprovalClock, ApprovalTime, AssociatedPendingRequest, AssociatedRequestIssue,
    CommittedAssociatedCheck, DurableFailure, DurableFault, DurableInbox, LocalKeySetDescriptor,
    NativePeerLease, PeerAssociation, PeerLeaseError,
};

const NANOS_PER_MILLI: u64 = 1_000_000;

/// Includes ALL committed maintenance, including when no signing data escapes.
#[must_use = "dispatch committed downward effects even when denial is rejected"]
pub struct DenialTransition<T> {
    checks: Vec<CommittedAssociatedCheck>,
    outcome: Result<T, DenialError>,
}
impl<T> DenialTransition<T> {
    pub fn checks(&self) -> &[CommittedAssociatedCheck] {
        &self.checks
    }
    pub fn outcome(&self) -> Result<&T, &DenialError> {
        self.outcome.as_ref()
    }
    pub fn into_parts(self) -> (Vec<CommittedAssociatedCheck>, Result<T, DenialError>) {
        (self.checks, self.outcome)
    }
}
impl<T> fmt::Debug for DenialTransition<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DenialTransition")
            .field("committed_checks", &self.checks.len())
            .field("rejection", &self.outcome.as_ref().err())
            .finish_non_exhaustive()
    }
}

// A clone shares the same downward-only lease; no new registry slot or body.
#[derive(Clone)]
struct BoundRequest {
    window: MappedRequestWindow,
    deadline_nanos: u64,
    boot: PhoneBootId,
    lease: NativePeerLease,
}
impl BoundRequest {
    fn capture(
        request: &AssociatedPendingRequest,
        owner: &mut DurableInbox,
        boot: PhoneBootId,
    ) -> Result<Self, DenialError> {
        Self::check_source(request, owner)?;
        let deadline_nanos = Self::deadline(request)?;
        let lease = owner
            .lease_pending_request(request)
            .map_err(DenialError::Lease)?;
        Ok(Self {
            window: request.request().original_window(),
            deadline_nanos,
            boot,
            lease,
        })
    }
    fn check_source(
        request: &AssociatedPendingRequest,
        owner: &DurableInbox,
    ) -> Result<(), DenialError> {
        if !request.belongs_to_owner(owner) {
            return Err(DenialError::DifferentOwner);
        }
        if request
            .request()
            .receiving_generation()
            .is_none_or(|generation| generation.get() != request.association().generation())
        {
            return Err(DenialError::AssociationChanged);
        }
        Ok(())
    }
    fn deadline(request: &AssociatedPendingRequest) -> Result<u64, DenialError> {
        let floor = request
            .request()
            .notification()
            .expires_at
            .as_millis()
            .checked_mul(NANOS_PER_MILLI)
            .ok_or(DenialError::InvalidRequest)?;
        Ok(request
            .request()
            .original_window()
            .phone_expiry_nanos()
            .min(floor))
    }
    fn matches(
        &self,
        request: &AssociatedPendingRequest,
        owner: &DurableInbox,
        boot: PhoneBootId,
    ) -> Result<(), DenialError> {
        Self::check_source(request, owner)?;
        if self.window != request.request().original_window()
            || self.deadline_nanos != Self::deadline(request)?
            || self.boot != boot
        {
            return Err(DenialError::RequestChanged);
        }
        if self.lease.association() != request.association() {
            return Err(DenialError::AssociationChanged);
        }
        if self.lease.local_keys() != request.local_keys() {
            return Err(DenialError::LocalKeysChanged);
        }
        Ok(())
    }
    fn key(&self) -> RequestKey {
        phone_request_core::request_key(self.window.binding())
    }
    fn statement(&self) -> UnsignedDecision {
        UnsignedDecision::new(
            self.window.binding(),
            self.lease.association().descriptor().recipient_device_id(),
            DecisionPurpose::Deny,
        )
    }
}

struct SharedAttempt {
    life: Arc<AtomicBool>,
    owner_epoch: Arc<()>,
    bound: BoundRequest,
    cancelled: AtomicBool,
    active: AtomicBool,
    retired: AtomicBool,
}
impl SharedAttempt {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || !self.life.load(Ordering::Acquire)
            || self.bound.lease.is_revoked()
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.active.store(false, Ordering::Release);
    }
}

/// Sealed exact-request signing input. No public constructor, Clone, key alias,
/// caller-selected purpose or authentication flag. Finish is one-shot even if
/// a native provider permits its Signature object to be reused.
pub struct DenialAttempt {
    shared: Arc<SharedAttempt>,
}
impl DenialAttempt {
    pub fn binding(&self) -> RequestBinding {
        self.shared.bound.window.binding()
    }
    pub fn original_window(&self) -> MappedRequestWindow {
        self.shared.bound.window
    }
    pub fn phone_boot(&self) -> PhoneBootId {
        self.shared.bound.boot
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.shared.bound.deadline_nanos
    }
    pub fn association(&self) -> &PeerAssociation {
        self.shared.bound.lease.association()
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        self.shared.bound.lease.local_keys()
    }
    /// Identity comparison only, not a live/native action permission.
    pub fn belongs_to_owner(&self, owner: &DurableInbox) -> bool {
        Arc::ptr_eq(&self.shared.owner_epoch, &owner.owner_epoch())
    }
    pub fn is_cancelled(&self) -> bool {
        self.shared.is_cancelled() || !self.shared.active.load(Ordering::Acquire)
    }
    /// Downward-only, immediate and lock-free. Also invalidates prepared data.
    pub fn cancel(&self) {
        self.shared.cancel();
    }
    /// Only canonical Deny bytes. Use the DENIAL key with SHA256withECDSA;
    /// do not prehash these bytes. This neither invokes nor requests OS auth.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, DenialError> {
        if self.is_cancelled() {
            return Err(DenialError::Cancelled);
        }
        Ok(self.shared.bound.statement().signing_bytes())
    }
}
impl fmt::Debug for DenialAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DenialAttempt([redacted], not_native_key_authority)")
    }
}

/// Bounded verified signature data, NOT PC acceptance or a Windows result.
/// Native cleanup retirement alone preserves it; explicit cancellation, either
/// owner closing, or actual request/association withdrawal invalidates it.
pub struct PreparedDenial {
    shared: Arc<SharedAttempt>,
    signed: SignedDecision,
}
impl PreparedDenial {
    /// Only the crate's closed prepared-decision sender may retain these parts.
    /// The shared guard keeps cancellation, the original request lease and owner
    /// lifetime alive through TLS buffering and every partial socket write.
    pub(crate) fn delivery_parts(
        &self,
    ) -> Result<(Vec<u8>, Arc<dyn framed_transport::OutboundFrameGuard>), DenialError> {
        if self.is_cancelled() {
            return Err(DenialError::Cancelled);
        }
        Ok((
            self.signed.to_wire(),
            Arc::new(DenialDeliveryGuard(Arc::clone(&self.shared))),
        ))
    }
    pub fn binding(&self) -> RequestBinding {
        self.shared.bound.window.binding()
    }
    pub fn original_window(&self) -> MappedRequestWindow {
        self.shared.bound.window
    }
    pub fn phone_boot(&self) -> PhoneBootId {
        self.shared.bound.boot
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.shared.bound.deadline_nanos
    }
    pub fn association(&self) -> &PeerAssociation {
        self.shared.bound.lease.association()
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        self.shared.bound.lease.local_keys()
    }
    /// Identity comparison only. Current request/time checks remain necessary.
    pub fn belongs_to_owner(&self, owner: &DurableInbox) -> bool {
        Arc::ptr_eq(&self.shared.owner_epoch, &owner.owner_epoch())
    }
    pub fn is_cancelled(&self) -> bool {
        self.shared.is_cancelled()
    }
    pub fn cancel(&self) {
        self.shared.cancel();
    }
    /// Consuming data extraction, not a delivery permit. The typed socket sender
    /// takes PreparedDenial itself instead, retaining the original context and
    /// cancellation. This extraction must not replace its fresh native checks.
    pub fn into_signed_decision(self) -> Result<SignedDecision, DenialError> {
        if self.is_cancelled() {
            return Err(DenialError::Cancelled);
        }
        Ok(self.signed)
    }
}
struct DenialDeliveryGuard(Arc<SharedAttempt>);
impl framed_transport::OutboundFrameGuard for DenialDeliveryGuard {
    fn is_revoked(&self) -> bool {
        self.0.is_cancelled()
    }
}
impl fmt::Debug for PreparedDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedDenial([redacted], not_windows_result)")
    }
}

struct Slot {
    shared: Arc<SharedAttempt>,
    terminal: bool,
}

/// Exactly one native signing slot, not an application runtime or an inbox.
/// The trusted actor must not construct competing owners for the same inbox.
pub struct DenialOwner {
    life: Arc<AtomicBool>,
    owner_epoch: Arc<()>,
    boot: PhoneBootId,
    last_clock_nanos: Option<u64>,
    slot: Option<Slot>,
}
impl fmt::Debug for DenialOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DenialOwner")
            .field("occupied", &self.slot.is_some())
            .finish_non_exhaustive()
    }
}
impl DenialOwner {
    /// Boot must be the actual native boot used to open this exact inbox.
    pub fn new(owner: &DurableInbox, boot: PhoneBootId) -> Result<Self, DenialError> {
        owner.policy().map_err(DenialError::Owner)?;
        if let Some(fault) = owner.inbox_fault().map_err(DenialError::Owner)? {
            return Err(DenialError::DomainFault(fault));
        }
        Ok(Self {
            life: Arc::new(AtomicBool::new(true)),
            owner_epoch: owner.owner_epoch(),
            boot,
            last_clock_nanos: None,
            slot: None,
        })
    }

    pub fn begin(
        &mut self,
        owner: &mut DurableInbox,
        key: RequestKey,
        clock: &mut dyn ApprovalClock,
    ) -> DenialTransition<DenialAttempt> {
        let mut unwind = OperationGuard::new(&self.life);
        let mut checks = Vec::new();
        let outcome = (|| {
            self.guard_owner(owner)?;
            if self.slot.is_some() {
                return Err(DenialError::Busy);
            }
            let bound = self.refresh(owner, key, None, clock, &mut checks)?;
            let shared = Arc::new(SharedAttempt {
                life: Arc::clone(&self.life),
                owner_epoch: Arc::clone(&self.owner_epoch),
                bound,
                cancelled: AtomicBool::new(false),
                active: AtomicBool::new(true),
                retired: AtomicBool::new(false),
            });
            if shared.is_cancelled() {
                return Err(DenialError::Cancelled);
            }
            self.slot = Some(Slot {
                shared: Arc::clone(&shared),
                terminal: false,
            });
            Ok(DenialAttempt { shared })
        })();
        self.close_on_fatal(outcome.as_ref().err());
        unwind.completed = true;
        DenialTransition { checks, outcome }
    }

    pub fn finish(
        &mut self,
        owner: &mut DurableInbox,
        attempt: &DenialAttempt,
        der: &[u8],
        clock: &mut dyn ApprovalClock,
    ) -> DenialTransition<PreparedDenial> {
        let mut unwind = OperationGuard::new(&self.life);
        let mut checks = Vec::new();
        let mut consumed = None;
        let outcome = (|| {
            // Foreign handles cannot touch the rightful slot. A matching attempt
            // is consumed BEFORE clocks, IO, parsing, crypto or stale-owner checks.
            let shared = self.consume(&attempt.shared)?;
            consumed = Some(Arc::clone(&shared));
            self.guard_owner(owner)?;
            if shared.is_cancelled() {
                return Err(DenialError::Cancelled);
            }
            self.refresh(
                owner,
                shared.bound.key(),
                Some(&shared.bound),
                clock,
                &mut checks,
            )?;
            if shared.is_cancelled() {
                return Err(DenialError::Cancelled);
            }
            let public = denial_public_key(shared.bound.lease.local_keys())?;
            let signed = SignedDecision::from_der(shared.bound.statement(), der)
                .map_err(|_| DenialError::InvalidSignature)?;
            signed
                .verify(&public)
                .map_err(|_| DenialError::InvalidSignature)?;
            let fresh = self.read_time(clock)?;
            self.seal_or_maintain(owner, &shared.bound, fresh, &mut checks)?;
            if shared.is_cancelled() {
                return Err(DenialError::Cancelled);
            }
            Ok(PreparedDenial { shared, signed })
        })();
        if outcome.is_err()
            && let Some(shared) = consumed
        {
            shared.cancel();
        }
        self.close_on_fatal(outcome.as_ref().err());
        unwind.completed = true;
        DenialTransition { checks, outcome }
    }

    /// Only after the actual native operation has quiesced. Cancellation alone
    /// never frees the slot. Idempotent retirement does not cancel prepared data.
    pub fn retire_after_native_cleanup(
        &mut self,
        attempt: &DenialAttempt,
    ) -> Result<(), DenialError> {
        if !Arc::ptr_eq(&self.life, &attempt.shared.life) {
            return Err(DenialError::ForeignHandle);
        }
        if attempt.shared.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        let slot = self
            .slot
            .as_ref()
            .filter(|slot| Arc::ptr_eq(&slot.shared, &attempt.shared))
            .ok_or(DenialError::AlreadyConsumed)?;
        if !slot.terminal && !attempt.is_cancelled() {
            return Err(DenialError::CleanupRequired);
        }
        attempt.shared.active.store(false, Ordering::Release);
        attempt.shared.retired.store(true, Ordering::Release);
        self.slot = None;
        Ok(())
    }

    /// Downward-only. Native operation cancellation/reference cleanup is still
    /// the containing actor's obligation; this changes no persistent state/key.
    pub fn close(&mut self) {
        self.life.store(false, Ordering::Release);
        if let Some(slot) = &self.slot {
            slot.shared.cancel();
        }
    }

    fn consume(&mut self, shared: &Arc<SharedAttempt>) -> Result<Arc<SharedAttempt>, DenialError> {
        if !Arc::ptr_eq(&self.life, &shared.life) {
            return Err(DenialError::ForeignHandle);
        }
        let slot = self
            .slot
            .as_mut()
            .filter(|slot| Arc::ptr_eq(&slot.shared, shared))
            .ok_or(DenialError::AlreadyConsumed)?;
        if slot.terminal {
            return Err(DenialError::AlreadyConsumed);
        }
        slot.terminal = true;
        shared.active.store(false, Ordering::Release);
        Ok(Arc::clone(shared))
    }
    fn close_on_fatal(&mut self, error: Option<&DenialError>) {
        if matches!(
            error,
            Some(
                DenialError::Closed
                    | DenialError::ClockUnavailable
                    | DenialError::ClockRegressed
                    | DenialError::BootChanged
                    | DenialError::Owner(_)
                    | DenialError::Persistence(_)
                    | DenialError::DomainFault(_)
                    | DenialError::Lease(PeerLeaseError::Owner(_) | PeerLeaseError::DomainFault(_))
            )
        ) {
            self.close();
        }
    }
    fn guard_owner(&self, owner: &DurableInbox) -> Result<(), DenialError> {
        if !self.life.load(Ordering::Acquire) {
            return Err(DenialError::Closed);
        }
        if !Arc::ptr_eq(&self.owner_epoch, &owner.owner_epoch()) {
            return Err(DenialError::DifferentOwner);
        }
        owner.policy().map_err(DenialError::Owner)?;
        if let Some(fault) = owner.inbox_fault().map_err(DenialError::Owner)? {
            return Err(DenialError::DomainFault(fault));
        }
        Ok(())
    }
    fn read_time(&mut self, clock: &mut dyn ApprovalClock) -> Result<ApprovalTime, DenialError> {
        let time = clock.read().map_err(|_| DenialError::ClockUnavailable)?;
        if time.boot() != self.boot {
            return Err(DenialError::BootChanged);
        }
        let now = time.clock().phone_monotonic_nanos();
        if self.last_clock_nanos.is_some_and(|previous| now < previous) {
            return Err(DenialError::ClockRegressed);
        }
        self.last_clock_nanos = Some(now);
        Ok(time)
    }
    fn refresh(
        &mut self,
        owner: &mut DurableInbox,
        key: RequestKey,
        expected: Option<&BoundRequest>,
        clock: &mut dyn ApprovalClock,
        checks: &mut Vec<CommittedAssociatedCheck>,
    ) -> Result<BoundRequest, DenialError> {
        self.guard_owner(owner)?;
        let before = self.read_time(clock)?;
        checks.push(
            owner
                .check_associated_pending(key, before.clock())
                .map_err(DenialError::Persistence)?,
        );
        let checked = checks.last().ok_or(DenialError::InvalidRequest)?;
        if let Some(fault) = checked.update().fault() {
            return Err(DenialError::DomainFault(fault));
        }
        let Some(request) = checked.request() else {
            if expected
                .is_some_and(|bound| before.clock().phone_monotonic_nanos() >= bound.deadline_nanos)
            {
                return Err(DenialError::Expired);
            }
            if !owner
                .policy()
                .map_err(DenialError::Owner)?
                .allows(before.clock().reading().local)
            {
                return Err(DenialError::OutsidePolicy);
            }
            return Err(checked.issue().map_or(
                DenialError::RequestUnavailable,
                DenialError::AssociationIssue,
            ));
        };
        let current = if let Some(expected) = expected {
            expected.matches(request, owner, self.boot)?;
            expected.clone()
        } else {
            BoundRequest::capture(request, owner, self.boot)?
        };
        // No positive result relies on the pre-IO sample. Exclusive ownership
        // plus the non-reentrant observation contract forbids intervening edits.
        let after = self.read_time(clock)?;
        self.seal_or_maintain(owner, &current, after, checks)?;
        Ok(current)
    }
    fn seal_or_maintain(
        &self,
        owner: &mut DurableInbox,
        bound: &BoundRequest,
        time: ApprovalTime,
        checks: &mut Vec<CommittedAssociatedCheck>,
    ) -> Result<(), DenialError> {
        let result = self.seal(owner, bound, time);
        if matches!(
            result,
            Err(DenialError::Expired | DenialError::OutsidePolicy)
        ) {
            // Rejection-only maintenance, at most once per operation. No action
            // is released from this additional blocking check's old timestamp.
            checks.push(
                owner
                    .check_associated_pending(bound.key(), time.clock())
                    .map_err(DenialError::Persistence)?,
            );
            if let Some(fault) = checks.last().and_then(|check| check.update().fault()) {
                return Err(DenialError::DomainFault(fault));
            }
        }
        result
    }
    fn seal(
        &self,
        owner: &DurableInbox,
        bound: &BoundRequest,
        time: ApprovalTime,
    ) -> Result<(), DenialError> {
        self.guard_owner(owner)?;
        if time.boot() != bound.boot {
            return Err(DenialError::BootChanged);
        }
        if owner
            .peer_associations()
            .map_err(DenialError::Owner)?
            .resolve(bound.lease.association().reference())
            != Some(bound.lease.association())
        {
            return Err(DenialError::AssociationChanged);
        }
        if owner
            .local_keys()
            .map_err(DenialError::Owner)?
            .get(bound.lease.local_keys().handle())
            .and_then(|phase| phase.descriptor())
            != Some(bound.lease.local_keys())
        {
            return Err(DenialError::LocalKeysChanged);
        }
        if time.clock().phone_monotonic_nanos() >= bound.deadline_nanos {
            return Err(DenialError::Expired);
        }
        if !owner
            .policy()
            .map_err(DenialError::Owner)?
            .allows(time.clock().reading().local)
        {
            return Err(DenialError::OutsidePolicy);
        }
        if bound.lease.is_revoked() {
            return Err(DenialError::Cancelled);
        }
        Ok(())
    }
}
impl Drop for DenialOwner {
    fn drop(&mut self) {
        self.close();
    }
}

// If a native clock callback unwinds and its caller catches that panic, earlier
// handles must not stay live. No recovery/automatic slot rearm is provided.
struct OperationGuard {
    life: Arc<AtomicBool>,
    completed: bool,
}
impl OperationGuard {
    fn new(life: &Arc<AtomicBool>) -> Self {
        Self {
            life: Arc::clone(life),
            completed: false,
        }
    }
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.life.store(false, Ordering::Release);
        }
    }
}

fn denial_public_key(local: &LocalKeySetDescriptor) -> Result<DecisionPublicKey, DenialError> {
    // These bytes came through TlsPublicKey's canonical 91-byte P-256 SPKI
    // validator. Revalidate the fixed uncompressed point as a decision key.
    let spki = local.denial_key().as_spki_der();
    if spki.len() != 91 {
        return Err(DenialError::LocalKeysChanged);
    }
    let point = spki
        .get(26..)
        .filter(|point| point.len() == 65 && point[0] == 4)
        .ok_or(DenialError::LocalKeysChanged)?;
    DecisionPublicKey::from_sec1_bytes(point).map_err(|_| DenialError::LocalKeysChanged)
}

/// Fixed categories: no payload, key, alias, signature or provider error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DenialError {
    #[error("denial slot is already occupied")]
    Busy,
    #[error("denial owner is closed")]
    Closed,
    #[error("denial belongs to another durable owner instance")]
    DifferentOwner,
    #[error("denial handle belongs to another owner or slot")]
    ForeignHandle,
    #[error("denial attempt was already consumed or retired")]
    AlreadyConsumed,
    #[error("denial was cancelled or withdrawn")]
    Cancelled,
    #[error("native operation must reach terminal cleanup before retirement")]
    CleanupRequired,
    #[error("native time is unavailable")]
    ClockUnavailable,
    #[error("native time moved backwards")]
    ClockRegressed,
    #[error("native phone boot differs from the denial owner")]
    BootChanged,
    #[error("current associated request is unavailable")]
    RequestUnavailable,
    #[error("current associated request source is unavailable")]
    AssociationIssue(AssociatedRequestIssue),
    #[error("denial request metadata is invalid")]
    InvalidRequest,
    #[error("denial request no longer matches its original window")]
    RequestChanged,
    #[error("denial association is no longer current")]
    AssociationChanged,
    #[error("denial local key tuple no longer matches")]
    LocalKeysChanged,
    #[error("denial request expired")]
    Expired,
    #[error("current notification policy no longer permits this request")]
    OutsidePolicy,
    #[error("signature did not verify for the exact denial request and key")]
    InvalidSignature,
    #[error("durable denial owner is unavailable")]
    Owner(DurableFault),
    #[error("denial maintenance commit failed")]
    Persistence(DurableFailure),
    #[error("request lifecycle is faulted")]
    DomainFault(InboxFault),
    #[error("request liveness lease is unavailable")]
    Lease(PeerLeaseError),
}
