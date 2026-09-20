// SPDX-License-Identifier: GPL-2.0-or-later
//! One process-local approval slot attached to the existing durable inbox.
//!
//! This is NOT enrollment, OS authentication, a generic signer or Windows
//! success. The trusted containing actor owns exactly one ApprovalPlanOwner per
//! DurableInbox and supplies that owner's actual native boot. Original receiving
//! provenance/current association is mandatory; CreatedUnverified alone is never
//! eligible. Native code still owns hardware policy and the exact per-use
//! CryptoObject/Signature operation. Application policy-only startup is unchanged.
//!
//! Clock callbacks run synchronously before and AFTER blocking check commits,
//! and after signature verification. They must only observe native time: no
//! owner mutation, reentry, UI/signing or fail_closed cleanup. The containing
//! actor must move its owners outside native mutexes under exclusive admission,
//! then defer callback failure cleanup until guards have been released. No
//! borrow of this owner may span waiting for a person or native signing work.
//!
//! Every committed check remains in ApprovalTransition, including rejection.
//! Dispatch downward effects even if no body/plan/submission is returned; its
//! check snapshots are not authority. No approval outcome/history is fabricated.
#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use approval_protocol::{
    DecisionPublicKey, DecisionPurpose, RequestBinding, SignedDecision, UnsignedDecision,
};
use notification_policy::RequestKey;
use phone_request_core::{InboxClock, InboxFault, PhoneBootId};
use service_protocol::MappedRequestWindow;

use crate::{
    AssociatedPendingRequest, AssociatedRequestIssue, CommittedAssociatedCheck, DurableFailure,
    DurableFault, DurableInbox, LocalKeySetDescriptor, PeerAssociation,
};

const NANOS_PER_MILLI: u64 = 1_000_000;

/// Active and retired-but-live contexts share this bound. Cancelled contexts
/// still occupy capacity until their LAST plan/attempt/submission/guard drops.
pub const MAX_LIVE_APPROVAL_CONTEXTS: usize = 64;

/// Matching existing contexts had their downward cancellation flags recorded.
/// This is NOT OS/provider quiescence, a future-action fence, or a PC outcome.
/// Repeating cancellation counts still-live matches even if already cancelled.
#[must_use = "cancellation flags do not replace native cleanup or an action fence"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalRequestCancellation {
    matched_contexts: usize,
}
impl ApprovalRequestCancellation {
    pub const fn matched_contexts(self) -> usize {
        self.matched_contexts
    }
}

/// Trusted native observations, not UI clock or authentication input.
#[derive(Clone, Copy)]
pub struct ApprovalTime {
    boot: PhoneBootId,
    clock: InboxClock,
}
impl ApprovalTime {
    pub const fn new(boot: PhoneBootId, clock: InboxClock) -> Self {
        Self { boot, clock }
    }
    pub const fn boot(self) -> PhoneBootId {
        self.boot
    }
    pub const fn clock(self) -> InboxClock {
        self.clock
    }
}
impl fmt::Debug for ApprovalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalTime(native_observation)")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalClockError {
    #[error("native approval time is unavailable")]
    Unavailable,
}
/// Non-reentrant native time observation only; see the module locking contract.
pub trait ApprovalClock {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError>;
}

/// The result and ALL committed maintenance checks travel together. A rejected
/// outcome must not cause callers to discard already-committed withdrawals.
#[must_use = "dispatch committed downward effects even when approval is rejected"]
pub struct ApprovalTransition<T> {
    checks: Vec<CommittedAssociatedCheck>,
    outcome: Result<T, ApprovalError>,
}
impl<T> ApprovalTransition<T> {
    pub fn checks(&self) -> &[CommittedAssociatedCheck] {
        &self.checks
    }
    pub fn outcome(&self) -> Result<&T, &ApprovalError> {
        self.outcome.as_ref()
    }
    pub fn into_parts(self) -> (Vec<CommittedAssociatedCheck>, Result<T, ApprovalError>) {
        (self.checks, self.outcome)
    }
}
impl<T> fmt::Debug for ApprovalTransition<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalTransition")
            .field("committed_checks", &self.checks.len())
            .field("rejection", &self.outcome.as_ref().err())
            .finish_non_exhaustive()
    }
}

struct OwnerLife {
    alive: AtomicBool,
}
struct BoundRequest {
    window: MappedRequestWindow,
    deadline_nanos: u64,
    boot: PhoneBootId,
    association: PeerAssociation,
    local_keys: LocalKeySetDescriptor,
}
impl BoundRequest {
    fn capture(
        request: &AssociatedPendingRequest,
        owner: &DurableInbox,
        boot: PhoneBootId,
    ) -> Result<Self, ApprovalError> {
        if !request.belongs_to_owner(owner) {
            return Err(ApprovalError::DifferentOwner);
        }
        let pending = request.request();
        if pending
            .receiving_generation()
            .is_none_or(|generation| generation.get() != request.association().generation())
        {
            return Err(ApprovalError::AssociationChanged);
        }
        let window = pending.original_window();
        let floor = pending
            .notification()
            .expires_at
            .as_millis()
            .checked_mul(NANOS_PER_MILLI)
            .ok_or(ApprovalError::InvalidRequest)?;
        Ok(Self {
            window,
            deadline_nanos: window.phone_expiry_nanos().min(floor),
            boot,
            association: request.association().clone(),
            local_keys: request.local_keys().clone(),
        })
    }
    fn key(&self) -> RequestKey {
        phone_request_core::request_key(self.window.binding())
    }
    fn statement(&self) -> UnsignedDecision {
        UnsignedDecision::new(
            self.window.binding(),
            self.association.descriptor().recipient_device_id(),
            DecisionPurpose::Approve,
        )
    }
    fn matches(&self, current: &Self) -> Result<(), ApprovalError> {
        if self.window != current.window
            || self.deadline_nanos != current.deadline_nanos
            || self.boot != current.boot
        {
            return Err(ApprovalError::RequestChanged);
        }
        if self.association != current.association {
            return Err(ApprovalError::AssociationChanged);
        }
        if self.local_keys != current.local_keys {
            return Err(ApprovalError::LocalKeysChanged);
        }
        Ok(())
    }
}

struct SharedPlan {
    life: Arc<OwnerLife>,
    owner_epoch: Arc<()>,
    bound: BoundRequest,
    cancelled: AtomicBool,
    attempt_active: AtomicBool,
    retired: AtomicBool,
}
impl SharedPlan {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || !self.life.alive.load(Ordering::Acquire)
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.attempt_active.store(false, Ordering::Release);
    }
}

/// Sealed after a post-commit native clock read. No public constructor, Clone,
/// serde or signing material. ABI Arc handle copies share the same one-shot slot.
pub struct ApprovalPlan {
    shared: Arc<SharedPlan>,
}
impl ApprovalPlan {
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
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.shared.bound.local_keys
    }
    pub fn association(&self) -> &PeerAssociation {
        &self.shared.bound.association
    }
    pub fn is_cancelled(&self) -> bool {
        self.shared.is_cancelled()
    }
    /// Immediate downward cancellation, with no storage/actor lock or native API.
    /// It invalidates a claimed attempt and any prepared submission too.
    pub fn cancel(&self) {
        self.shared.cancel();
    }
}
impl fmt::Debug for ApprovalPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalPlan([redacted], not_authentication)")
    }
}

/// One sealed claim. Only these fixed request-bound bytes reach the native
/// already-initialized approval-key operation; never prehash before SHA256withECDSA.
pub struct ApprovalAttempt {
    shared: Arc<SharedPlan>,
}
impl ApprovalAttempt {
    pub fn belongs_to(&self, plan: &ApprovalPlan) -> bool {
        Arc::ptr_eq(&self.shared, &plan.shared)
    }
    pub fn is_cancelled(&self) -> bool {
        self.shared.is_cancelled() || !self.shared.attempt_active.load(Ordering::Acquire)
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        if self.is_cancelled() {
            return Err(ApprovalError::Cancelled);
        }
        Ok(self.shared.bound.statement().signing_bytes())
    }
}
impl fmt::Debug for ApprovalAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalAttempt([redacted], native_per_use_operation_required)")
    }
}

/// Bounded prepared signature data, not Windows success or remote delivery.
/// Native slot retirement alone does not cancel this value. Explicit plan
/// cancellation or plan-owner close/drop does. The future typed sender must
/// recheck current pending/source/owner/native time immediately before handoff;
/// this crate intentionally implements no sender or durable approval outbox.
pub struct ApprovalSubmission {
    shared: Arc<SharedPlan>,
    signed: SignedDecision,
}
impl ApprovalSubmission {
    /// Crate-owned delivery only. The caller consumes the original submission
    /// on successful admission; temporary busy retries retain that same value.
    pub(crate) fn delivery_parts(
        &self,
    ) -> Result<(Vec<u8>, Arc<dyn framed_transport::OutboundFrameGuard>), ApprovalError> {
        if self.is_cancelled() {
            return Err(ApprovalError::Cancelled);
        }
        Ok((
            self.signed.to_wire(),
            Arc::new(ApprovalDeliveryGuard(Arc::clone(&self.shared))),
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
        &self.shared.bound.association
    }
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.shared.bound.local_keys
    }
    pub fn belongs_to_owner(&self, owner: &DurableInbox) -> bool {
        Arc::ptr_eq(&self.shared.owner_epoch, &owner.owner_epoch())
    }
    pub fn is_cancelled(&self) -> bool {
        self.shared.is_cancelled()
    }
    /// Consume prepared data only, NOT a replacement for the fresh sender check.
    pub fn into_signed_decision(self) -> Result<SignedDecision, ApprovalError> {
        if self.is_cancelled() {
            return Err(ApprovalError::Cancelled);
        }
        Ok(self.signed)
    }
}
struct ApprovalDeliveryGuard(Arc<SharedPlan>);
impl framed_transport::OutboundFrameGuard for ApprovalDeliveryGuard {
    fn is_revoked(&self) -> bool {
        self.0.is_cancelled()
    }
}
impl fmt::Debug for ApprovalSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApprovalSubmission([redacted], not_windows_success)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Plan,
    Claimed,
    Terminal,
}
struct Slot {
    shared: Arc<SharedPlan>,
    phase: Phase,
}

/// The containing native actor constructs exactly one instance for its exact
/// DurableInbox/native boot. No persistence, reset, key creation or paired setter.
pub struct ApprovalPlanOwner {
    life: Arc<OwnerLife>,
    owner_epoch: Arc<()>,
    boot: PhoneBootId,
    last_clock_nanos: Option<u64>,
    slot: Option<Slot>,
    // Weak ownership only: retirement must not hide live prepared/queued data,
    // and this registry must not itself keep any completed context alive.
    contexts: Vec<Weak<SharedPlan>>,
}
impl fmt::Debug for ApprovalPlanOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalPlanOwner")
            .field("occupied", &self.slot.is_some())
            .finish_non_exhaustive()
    }
}

impl ApprovalPlanOwner {
    /// The trusted containing owner supplies the SAME actual native boot used to
    /// open this DurableInbox. A typed boot constructor alone proves no OS fact.
    pub fn new(owner: &DurableInbox, boot: PhoneBootId) -> Result<Self, ApprovalError> {
        owner.policy().map_err(ApprovalError::Owner)?;
        Ok(Self {
            life: Arc::new(OwnerLife {
                alive: AtomicBool::new(true),
            }),
            owner_epoch: owner.owner_epoch(),
            boot,
            last_clock_nanos: None,
            slot: None,
            contexts: Vec::new(),
        })
    }

    pub fn begin(
        &mut self,
        owner: &mut DurableInbox,
        key: RequestKey,
        clock: &mut dyn ApprovalClock,
    ) -> ApprovalTransition<ApprovalPlan> {
        let mut checks = Vec::new();
        let outcome = (|| {
            self.guard_owner(owner)?;
            if self.slot.is_some() {
                return Err(ApprovalError::Busy);
            }
            // Reserve before blocking checks/commits or publishing a handle.
            // An occupied native slot retains its existing Busy precedence.
            self.reserve_context()?;
            let bound = self.refresh(owner, key, None, clock, &mut checks)?;
            let shared = Arc::new(SharedPlan {
                life: Arc::clone(&self.life),
                owner_epoch: Arc::clone(&self.owner_epoch),
                bound,
                cancelled: AtomicBool::new(false),
                attempt_active: AtomicBool::new(false),
                retired: AtomicBool::new(false),
            });
            // One entry for this Arc identity, before either public handle or
            // active slot is published. Reservation above makes push bounded.
            self.contexts.push(Arc::downgrade(&shared));
            self.slot = Some(Slot {
                shared: Arc::clone(&shared),
                phase: Phase::Plan,
            });
            Ok(ApprovalPlan { shared })
        })();
        ApprovalTransition { checks, outcome }
    }

    pub fn claim(
        &mut self,
        owner: &mut DurableInbox,
        plan: &ApprovalPlan,
        clock: &mut dyn ApprovalClock,
    ) -> ApprovalTransition<ApprovalAttempt> {
        let mut checks = Vec::new();
        let mut consumed = None;
        let outcome = (|| {
            self.guard_owner(owner)?;
            let shared = self.consume(&plan.shared, Phase::Plan)?;
            consumed = Some(Arc::clone(&shared));
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            self.refresh(
                owner,
                shared.bound.key(),
                Some(&shared.bound),
                clock,
                &mut checks,
            )?;
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            shared.attempt_active.store(true, Ordering::Release);
            self.slot
                .as_mut()
                .ok_or(ApprovalError::AlreadyConsumed)?
                .phase = Phase::Claimed;
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            Ok(ApprovalAttempt { shared })
        })();
        if outcome.is_err()
            && let Some(shared) = consumed
        {
            self.reject_consumed(&shared);
        }
        ApprovalTransition { checks, outcome }
    }

    pub fn finish(
        &mut self,
        owner: &mut DurableInbox,
        attempt: &ApprovalAttempt,
        der: &[u8],
        clock: &mut dyn ApprovalClock,
    ) -> ApprovalTransition<ApprovalSubmission> {
        let mut checks = Vec::new();
        let mut consumed = None;
        let outcome = (|| {
            self.guard_owner(owner)?;
            let shared = self.consume(&attempt.shared, Phase::Claimed)?;
            // One-shot consumption BEFORE clocks, IO, parsing or crypto. Native
            // code may not reuse its Signature merely because Java permits it.
            shared.attempt_active.store(false, Ordering::Release);
            consumed = Some(Arc::clone(&shared));
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            self.refresh(
                owner,
                shared.bound.key(),
                Some(&shared.bound),
                clock,
                &mut checks,
            )?;
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            let public = approval_public_key(&shared.bound.local_keys)?;
            let signed = SignedDecision::from_der(shared.bound.statement(), der)
                .map_err(|_| ApprovalError::InvalidSignature)?;
            signed
                .verify(&public)
                .map_err(|_| ApprovalError::InvalidSignature)?;
            // Signature verification is synchronous work: observe native time
            // again, rather than reusing the post-commit sample from refresh.
            let fresh = self.read_time(clock)?;
            self.seal_or_maintain(owner, &shared.bound, fresh, &mut checks)?;
            if shared.is_cancelled() {
                return Err(ApprovalError::Cancelled);
            }
            Ok(ApprovalSubmission { shared, signed })
        })();
        if outcome.is_err()
            && let Some(shared) = consumed
        {
            self.reject_consumed(&shared);
        }
        ApprovalTransition { checks, outcome }
    }

    /// Trusted native terminal/cleanup acknowledgment, NOT proof manufactured by
    /// this call. Caller must know the native operation has actually quiesced.
    /// Cancellation alone does NOT free the slot. Retirement is idempotent and
    /// never cancels an independent successfully prepared submission.
    pub fn retire_after_native_cleanup(
        &mut self,
        plan: &ApprovalPlan,
    ) -> Result<(), ApprovalError> {
        if !Arc::ptr_eq(&self.life, &plan.shared.life) {
            return Err(ApprovalError::ForeignHandle);
        }
        if plan.shared.retired.load(Ordering::Acquire) {
            return Ok(());
        }
        let slot = self
            .slot
            .as_ref()
            .filter(|slot| Arc::ptr_eq(&slot.shared, &plan.shared))
            .ok_or(ApprovalError::AlreadyConsumed)?;
        if slot.phase != Phase::Terminal && !plan.is_cancelled() {
            return Err(ApprovalError::CleanupRequired);
        }
        plan.shared.attempt_active.store(false, Ordering::Release);
        plan.shared.retired.store(true, Ordering::Release);
        self.slot = None;
        Ok(())
    }

    /// Whether the one native slot still belongs to this exact PC/epoch/request.
    /// Includes planned, claimed, cancelled and terminal-but-unretired slots.
    /// Closing the owner is cancellation, not retirement, so it also preserves
    /// this observation until explicit native cleanup retires the slot.
    ///
    /// False says nothing about OS/provider quiescence, live retired submissions
    /// or queued socket guards. The native actor must observe actual cleanup AND
    /// this slot independently; neither observation grants signing authority.
    pub fn has_native_slot_for(&self, key: RequestKey) -> bool {
        self.slot
            .as_ref()
            .is_some_and(|slot| slot.shared.bound.key() == key)
    }

    /// Cancel ALL currently live contexts for this exact PC/epoch/request key,
    /// including retired submissions or a context held only by a socket guard.
    /// No inbox, clock, native callback or I/O is involved. The native slot is
    /// NOT retired: actual provider/UI cleanup still has to finish separately.
    ///
    /// This cancels existing contexts only. Before invoking it for user denial,
    /// the containing native actor must reserve a same-request action fence and
    /// prevent subsequent begin/claim/send admission until that action finishes.
    /// It cannot recall bytes already written or assert a Windows/PC outcome.
    pub fn cancel_request(&mut self, key: RequestKey) -> ApprovalRequestCancellation {
        self.prune_dead_contexts();
        let mut matched_contexts = 0;
        for shared in self.contexts.iter().filter_map(Weak::upgrade) {
            if shared.bound.key() == key {
                shared.cancel();
                matched_contexts += 1;
            }
        }
        ApprovalRequestCancellation { matched_contexts }
    }

    /// Downward invalidation only; native cancellation/reference cleanup remains
    /// the containing actor's responsibility. No key or inbox state is changed.
    pub fn close(&mut self) {
        self.life.alive.store(false, Ordering::Release);
        if let Some(slot) = &self.slot {
            slot.shared.cancel();
        }
    }

    fn prune_dead_contexts(&mut self) {
        let mut index = 0;
        while index < self.contexts.len() {
            if Weak::<SharedPlan>::upgrade(&self.contexts[index]).is_none() {
                self.contexts.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    fn reserve_context(&mut self) -> Result<(), ApprovalError> {
        self.prune_dead_contexts();
        if self.contexts.len() >= MAX_LIVE_APPROVAL_CONTEXTS {
            return Err(ApprovalError::ContextCapacity);
        }
        self.contexts
            .try_reserve_exact(1)
            .map_err(|_| ApprovalError::ContextAllocationFailed)
    }

    fn consume(
        &mut self,
        shared: &Arc<SharedPlan>,
        expected: Phase,
    ) -> Result<Arc<SharedPlan>, ApprovalError> {
        if !Arc::ptr_eq(&self.life, &shared.life) {
            return Err(ApprovalError::ForeignHandle);
        }
        let slot = self
            .slot
            .as_mut()
            .filter(|slot| Arc::ptr_eq(&slot.shared, shared))
            .ok_or(ApprovalError::AlreadyConsumed)?;
        if slot.phase != expected {
            return Err(ApprovalError::AlreadyConsumed);
        }
        slot.phase = Phase::Terminal;
        Ok(Arc::clone(&slot.shared))
    }
    fn reject_consumed(&mut self, shared: &SharedPlan) {
        shared.cancel();
        if let Some(slot) = &mut self.slot {
            slot.phase = Phase::Terminal;
        }
    }
    fn guard_owner(&self, owner: &DurableInbox) -> Result<(), ApprovalError> {
        if !self.life.alive.load(Ordering::Acquire) {
            return Err(ApprovalError::Closed);
        }
        if !Arc::ptr_eq(&self.owner_epoch, &owner.owner_epoch()) {
            return Err(ApprovalError::DifferentOwner);
        }
        owner.policy().map_err(ApprovalError::Owner)?;
        Ok(())
    }
    fn read_time(&mut self, clock: &mut dyn ApprovalClock) -> Result<ApprovalTime, ApprovalError> {
        let time = clock.read().map_err(|_| ApprovalError::ClockUnavailable)?;
        if time.boot != self.boot {
            return Err(ApprovalError::BootChanged);
        }
        let now = time.clock.phone_monotonic_nanos();
        if self.last_clock_nanos.is_some_and(|previous| now < previous) {
            return Err(ApprovalError::ClockRegressed);
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
    ) -> Result<BoundRequest, ApprovalError> {
        self.guard_owner(owner)?;
        let before = self.read_time(clock)?;
        let checked = owner
            .check_associated_pending(key, before.clock)
            .map_err(ApprovalError::Persistence)?;
        checks.push(checked);
        let checked = checks.last().ok_or(ApprovalError::InvalidRequest)?;
        if let Some(fault) = checked.update().fault() {
            return Err(ApprovalError::DomainFault(fault));
        }
        let Some(request) = checked.request() else {
            if expected
                .is_some_and(|bound| before.clock.phone_monotonic_nanos() >= bound.deadline_nanos)
            {
                return Err(ApprovalError::Expired);
            }
            if !owner
                .policy()
                .map_err(ApprovalError::Owner)?
                .allows(before.clock.reading().local)
            {
                return Err(ApprovalError::OutsidePolicy);
            }
            return Err(checked.issue().map_or(
                ApprovalError::RequestUnavailable,
                ApprovalError::AssociationIssue,
            ));
        };
        let current = BoundRequest::capture(request, owner, self.boot)?;
        if let Some(expected) = expected {
            expected.matches(&current)?;
        }
        // Exclusive &mut owner and the NON-REENTRANT time callback ensure there
        // is no intervening domain mutation between this check and the seal.
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
    ) -> Result<(), ApprovalError> {
        let result = self.seal(owner, bound, time);
        if matches!(
            result,
            Err(ApprovalError::Expired | ApprovalError::OutsidePolicy)
        ) {
            // Seal rejected, so no signing material can escape. Commit the now
            // due downward maintenance once and retain it; no extra freshness
            // claim is made from this rejection-only follow-up check.
            checks.push(
                owner
                    .check_associated_pending(bound.key(), time.clock)
                    .map_err(ApprovalError::Persistence)?,
            );
        }
        result
    }
    fn seal(
        &self,
        owner: &DurableInbox,
        bound: &BoundRequest,
        time: ApprovalTime,
    ) -> Result<(), ApprovalError> {
        self.guard_owner(owner)?;
        if time.boot != bound.boot {
            return Err(ApprovalError::BootChanged);
        }
        if owner
            .peer_associations()
            .map_err(ApprovalError::Owner)?
            .resolve(bound.association.reference())
            != Some(&bound.association)
        {
            return Err(ApprovalError::AssociationChanged);
        }
        if owner
            .local_keys()
            .map_err(ApprovalError::Owner)?
            .get(bound.local_keys.handle())
            .and_then(|phase| phase.descriptor())
            != Some(&bound.local_keys)
        {
            return Err(ApprovalError::LocalKeysChanged);
        }
        if time.clock.phone_monotonic_nanos() >= bound.deadline_nanos {
            return Err(ApprovalError::Expired);
        }
        if !owner
            .policy()
            .map_err(ApprovalError::Owner)?
            .allows(time.clock.reading().local)
        {
            return Err(ApprovalError::OutsidePolicy);
        }
        Ok(())
    }
}
impl Drop for ApprovalPlanOwner {
    fn drop(&mut self) {
        self.close();
    }
}

fn approval_public_key(local: &LocalKeySetDescriptor) -> Result<DecisionPublicKey, ApprovalError> {
    // TlsPublicKey already validated the unique 91-byte id-ecPublicKey/prime256v1
    // SPKI with its 65-byte uncompressed point. Revalidate point shape as the
    // protocol's purpose-key type, never slice arbitrary callback/provider bytes.
    let spki = local.approval_key().as_spki_der();
    if spki.len() != 91 {
        return Err(ApprovalError::LocalKeysChanged);
    }
    let point = spki
        .get(26..)
        .filter(|point| point.len() == 65 && point[0] == 4)
        .ok_or(ApprovalError::LocalKeysChanged)?;
    DecisionPublicKey::from_sec1_bytes(point).map_err(|_| ApprovalError::LocalKeysChanged)
}

/// Fixed categories only; none carries text, key bytes, aliases or signatures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval slot is already occupied")]
    Busy,
    #[error("live approval context capacity is exhausted")]
    ContextCapacity,
    #[error("bounded approval context reservation failed")]
    ContextAllocationFailed,
    #[error("approval plan owner is closed")]
    Closed,
    #[error("approval belongs to another durable owner instance")]
    DifferentOwner,
    #[error("approval handle belongs to another plan owner or slot")]
    ForeignHandle,
    #[error("approval handle was already consumed or retired")]
    AlreadyConsumed,
    #[error("approval was cancelled")]
    Cancelled,
    #[error("native operation must reach terminal cleanup before slot retirement")]
    CleanupRequired,
    #[error("native approval clock is unavailable")]
    ClockUnavailable,
    #[error("native approval clock moved backwards")]
    ClockRegressed,
    #[error("native phone boot differs from the approval owner")]
    BootChanged,
    #[error("current associated request is unavailable")]
    RequestUnavailable,
    #[error("current associated request source is unavailable")]
    AssociationIssue(AssociatedRequestIssue),
    #[error("approval request metadata is invalid")]
    InvalidRequest,
    #[error("approval request no longer matches its original window")]
    RequestChanged,
    #[error("approval association is no longer current")]
    AssociationChanged,
    #[error("approval local key tuple no longer matches")]
    LocalKeysChanged,
    #[error("approval request expired")]
    Expired,
    #[error("current notification policy no longer permits this request")]
    OutsidePolicy,
    #[error("native approval signature did not verify for the exact request and key")]
    InvalidSignature,
    #[error("durable approval owner is unavailable")]
    Owner(DurableFault),
    #[error("approval maintenance commit failed")]
    Persistence(DurableFailure),
    #[error("request lifecycle is faulted")]
    DomainFault(InboxFault),
}
