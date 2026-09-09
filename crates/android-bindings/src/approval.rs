// SPDX-License-Identifier: GPL-2.0-or-later
//! Opaque native-only request plans. There is no exported constructor, caller
//! signing statement, authentication boolean, or renderer signing command.
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use android_controller::{
    ApprovalAttempt, ApprovalClock, ApprovalClockError, ApprovalError, ApprovalPlan,
    ApprovalPlanOwner, ApprovalSubmission, ApprovalTime, ApprovalTransition,
    CommittedAssociatedCheck, DurableInbox,
};
use notification_policy::RequestKey;

use crate::{BridgeError, MobileController, NativeLocalKeySet, NativePlatform, map_clock};

/// A bounded selection only, never evidence of receipt, pairing or permission.
#[derive(Clone, uniffi::Record)]
pub struct NativeRequestSelection {
    pub pc: Vec<u8>,
    pub epoch: Vec<u8>,
    pub request: Vec<u8>,
}
impl NativeRequestSelection {
    pub(crate) fn key(&self) -> Result<RequestKey, BridgeError> {
        fn part(bytes: &[u8]) -> Result<[u8; 32], BridgeError> {
            let value: [u8; 32] = bytes
                .try_into()
                .map_err(|_| BridgeError::InvalidObservation)?;
            if value == [0; 32] {
                return Err(BridgeError::InvalidObservation);
            }
            Ok(value)
        }
        Ok(RequestKey::new(
            part(&self.pc)?,
            part(&self.epoch)?,
            part(&self.request)?,
        ))
    }
    pub(crate) fn from_key(key: RequestKey) -> Self {
        Self {
            pc: key.pc().to_vec(),
            epoch: key.epoch().to_vec(),
            request: key.request().to_vec(),
        }
    }
}
impl fmt::Debug for NativeRequestSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeRequestSelection([redacted])")
    }
}

#[derive(uniffi::Object)]
pub struct NativeApprovalPlan {
    core: ApprovalPlan,
    controller_alive: Arc<AtomicBool>,
    // Closes native preparation after finish without canceling an independently
    // retained typed submission. Explicit cancel still invalidates the core.
    native_closed: AtomicBool,
}
impl fmt::Debug for NativeApprovalPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeApprovalPlan([redacted])")
    }
}
#[uniffi::export]
impl NativeApprovalPlan {
    pub fn local_keys(&self) -> Result<NativeLocalKeySet, BridgeError> {
        if self.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        Ok(NativeLocalKeySet::from_descriptor(self.core.local_keys()))
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.core.deadline_nanos()
    }
    /// Atomic-only: may run on main, even while the state owner is admitted.
    pub fn is_cancelled(&self) -> bool {
        !self.controller_alive.load(Ordering::Acquire)
            || self.native_closed.load(Ordering::Acquire)
            || self.core.is_cancelled()
    }
    /// Downward-only, no storage, callbacks, admission or OS operations.
    pub fn cancel(&self) {
        self.core.cancel();
    }
}

#[derive(uniffi::Object)]
pub struct NativeApprovalAttempt {
    core: ApprovalAttempt,
    plan: Arc<NativeApprovalPlan>,
}
impl fmt::Debug for NativeApprovalAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeApprovalAttempt([redacted])")
    }
}
#[uniffi::export]
impl NativeApprovalAttempt {
    pub fn belongs_to(&self, plan: Arc<NativeApprovalPlan>) -> bool {
        Arc::ptr_eq(&self.plan, &plan) && self.core.belongs_to(&plan.core)
    }
    pub fn is_cancelled(&self) -> bool {
        self.plan.is_cancelled() || self.core.is_cancelled()
    }
    /// Fixed canonical Approve bytes only. No raw input or alternate purpose.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        if self.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        self.core
            .signing_bytes()
            .map_err(|_| BridgeError::ApprovalRejected)
    }
}

/// Prepared only. No exported wire/DER accessor or Windows-success result.
/// Actual native transport ownership/handoff remains a separate integration.
#[derive(uniffi::Object)]
pub struct NativeApprovalSubmission {
    core: Mutex<Option<ApprovalSubmission>>,
    plan: Arc<NativeApprovalPlan>,
    delivery: Arc<crate::intake_delivery::DeliveryControl>,
    controller_alive: Arc<AtomicBool>,
}
impl fmt::Debug for NativeApprovalSubmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeApprovalSubmission([redacted], not_delivered)")
    }
}
#[uniffi::export]
impl NativeApprovalSubmission {
    pub fn is_cancelled(&self) -> bool {
        !self.controller_alive.load(Ordering::Acquire) || self.plan.core.is_cancelled()
    }
    pub fn delivery_progress(&self) -> crate::NativeDecisionProgress {
        self.delivery.progress()
    }
}
impl NativeApprovalSubmission {
    pub(crate) fn belongs_to_controller(&self, owner: &MobileController) -> bool {
        Arc::ptr_eq(&self.controller_alive, &owner.approval_alive)
    }
    pub(crate) fn request_key(&self) -> RequestKey {
        phone_request_core::request_key(self.plan.core.binding())
    }
    pub(crate) fn association_reference(&self) -> android_controller::PeerAssociationRef {
        self.plan.core.association().reference()
    }
    pub(crate) fn delivery_control(&self) -> Arc<crate::intake_delivery::DeliveryControl> {
        Arc::clone(&self.delivery)
    }
    pub(crate) fn cancel_context(&self) {
        self.plan.core.cancel();
    }
    pub(crate) fn take_core(&self) -> Result<ApprovalSubmission, BridgeError> {
        if self.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        self.core
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .take()
            .ok_or(BridgeError::ApprovalRejected)
    }
    pub(crate) fn restore_retry(&self, core: ApprovalSubmission) -> Result<(), BridgeError> {
        if self.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        let mut stored = self.core.lock().map_err(|_| BridgeError::Closed)?;
        if stored.is_some() {
            return Err(BridgeError::OwnerFaulted);
        }
        *stored = Some(core);
        Ok(())
    }
}

#[uniffi::export]
impl MobileController {
    /// No current request is invented by this API. Application startup still
    /// rejects request-bearing checkpoints until full native intake is wired.
    pub fn begin_approval(
        &self,
        request: NativeRequestSelection,
    ) -> Result<Arc<NativeApprovalPlan>, BridgeError> {
        let key = request.key()?;
        let _admission = self.enter()?;
        self.require_positive_approval(key)?;
        let plan = self.run_approval(|plans, inbox, clock| plans.begin(inbox, key, clock))?;
        if let Err(error) =
            self.seal_approval_publication(key, plan.deadline_nanos(), || plan.is_cancelled())
        {
            plan.cancel();
            // No native handle escaped. A failed clock may already have closed
            // and destroyed the owner after confirming no native obligations.
            if let Some(plans) = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .as_mut()
            {
                plans
                    .retire_after_native_cleanup(&plan)
                    .map_err(|_| BridgeError::Closed)?;
            }
            return Err(error);
        }
        let native = Arc::new(NativeApprovalPlan {
            core: plan,
            controller_alive: Arc::clone(&self.approval_alive),
            native_closed: AtomicBool::new(false),
        });
        let mut slot = self
            .approval_native_plan
            .lock()
            .map_err(|_| BridgeError::Closed)?;
        if slot.is_some() {
            native.cancel();
            return Err(BridgeError::Closed);
        }
        *slot = Some(Arc::clone(&native));
        Ok(native)
    }

    pub fn claim_approval(
        &self,
        plan: Arc<NativeApprovalPlan>,
    ) -> Result<Arc<NativeApprovalAttempt>, BridgeError> {
        let _admission = self.enter()?;
        self.require_own_plan(&plan)?;
        let key = phone_request_core::request_key(plan.core.binding());
        self.require_positive_approval(key)?;
        let attempt =
            self.run_approval(|plans, inbox, clock| plans.claim(inbox, &plan.core, clock))?;
        if let Err(error) = self
            .seal_approval_publication(key, plan.core.deadline_nanos(), || attempt.is_cancelled())
        {
            plan.cancel();
            return Err(error);
        }
        Ok(Arc::new(NativeApprovalAttempt {
            core: attempt,
            plan,
        }))
    }

    pub fn finish_approval(
        &self,
        attempt: Arc<NativeApprovalAttempt>,
        der: Vec<u8>,
    ) -> Result<Arc<NativeApprovalSubmission>, BridgeError> {
        let _admission = self.enter()?;
        self.require_own_plan(&attempt.plan)?;
        let key = phone_request_core::request_key(attempt.plan.core.binding());
        self.require_positive_approval(key)?;
        // The domain consumes its claim even on malformed/invalid DER. A caller
        // cannot retry finish with another signature or duplicate a copied Arc.
        let result = self
            .run_approval(|plans, inbox, clock| plans.finish(inbox, &attempt.core, &der, clock));
        attempt.plan.native_closed.store(true, Ordering::Release);
        match result {
            Ok(core) => {
                if let Err(error) =
                    self.seal_approval_publication(key, core.deadline_nanos(), || {
                        core.is_cancelled()
                    })
                {
                    attempt.plan.cancel();
                    return Err(error);
                }
                Ok(Arc::new(NativeApprovalSubmission {
                    core: Mutex::new(Some(core)),
                    plan: Arc::clone(&attempt.plan),
                    delivery: crate::intake_delivery::DeliveryControl::new(),
                    controller_alive: Arc::clone(&self.approval_alive),
                }))
            }
            Err(error) => {
                attempt.plan.cancel();
                Err(error)
            }
        }
    }

    /// Native actor calls only after its exact operation has become quiescent;
    /// cancellation alone or a timer is not native cleanup completion evidence.
    pub fn retire_approval(&self, plan: Arc<NativeApprovalPlan>) -> Result<(), BridgeError> {
        let _admission = self.enter()?;
        if !Arc::ptr_eq(&self.approval_alive, &plan.controller_alive) {
            return Err(BridgeError::ApprovalRejected);
        }
        let result = (|| {
            let mut plans = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?;
            let result = plans
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .retire_after_native_cleanup(&plan.core)
                .map_err(|_| BridgeError::ApprovalRejected);
            if result.is_ok() {
                let mut shadow = self
                    .approval_native_plan
                    .lock()
                    .map_err(|_| BridgeError::Closed)?;
                if shadow
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &plan))
                {
                    shadow.take();
                }
            }
            result
        })();
        if result == Err(BridgeError::Closed) {
            return self.fail_closed(BridgeError::Closed);
        }
        result
    }
}

impl MobileController {
    /// A native withdrawal/clock callback may have taken time or atomically
    /// cancelled a handle after the domain's seal. The same admission prevents
    /// replacing the inbox or changing association/key metadata during dispatch.
    /// Observe time again outside locks, with no positive retry/commit loop.
    fn seal_approval_publication(
        &self,
        key: RequestKey,
        deadline_nanos: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<(), BridgeError> {
        self.require_positive_approval(key)?;
        let clock = self.read_clock()?;
        self.require_positive_approval(key)?;
        if cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        let late = {
            let state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let owner = state.as_ref().ok_or(BridgeError::Closed)?;
            clock.phone_monotonic_nanos() >= deadline_nanos
                || !owner
                    .policy()
                    .map_err(|_| BridgeError::StorageUnavailable)?
                    .allows(clock.reading().local)
        };
        if late {
            let checked = self
                .state
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .check_associated_pending(key, clock);
            match checked {
                Ok(check) => self.dispatch_approval_checks(vec![check])?,
                Err(_) => return self.fail_closed(BridgeError::StorageUnavailable),
            }
            return Err(BridgeError::ApprovalRejected);
        }
        if cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        self.require_positive_approval(key)
    }

    fn require_positive_approval(&self, key: RequestKey) -> Result<(), BridgeError> {
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        self.denial_fence(key)
    }
    fn require_own_plan(&self, plan: &NativeApprovalPlan) -> Result<(), BridgeError> {
        if !Arc::ptr_eq(&self.approval_alive, &plan.controller_alive) || plan.is_cancelled() {
            return Err(BridgeError::ApprovalRejected);
        }
        Ok(())
    }

    fn run_approval<T>(
        &self,
        action: impl FnOnce(
            &mut ApprovalPlanOwner,
            &mut DurableInbox,
            &mut dyn ApprovalClock,
        ) -> ApprovalTransition<T>,
    ) -> Result<T, BridgeError> {
        // Move exclusive owners out while admitted. Native clock callbacks run
        // with NO state/plan mutex held; callback re-entry sees Busy. Human UI,
        // key preparation and actual signing happen after this call returns.
        let detached = (|| {
            let mut state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let mut plans = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?;
            if state.is_none() || plans.is_none() {
                return Err(BridgeError::Closed);
            }
            self.cleanup_pending.store(true, Ordering::Release);
            Ok((
                state.take().ok_or(BridgeError::Closed)?,
                plans.take().ok_or(BridgeError::Closed)?,
            ))
        })();
        let (inbox, plans) = match detached {
            Ok(value) => value,
            Err(error) => return self.fail_closed(error),
        };
        let mut detached = DetachedApprovalState {
            controller: self,
            inbox: Some(inbox),
            plans: Some(plans),
            armed: true,
        };
        let mut clock = NativeApprovalClock {
            platform: &*self.platform,
            boot: self.boot,
            floor: &self.native_floor_nanos,
            error: None,
        };
        let result = action(
            detached.plans.as_mut().ok_or(BridgeError::Closed)?,
            detached.inbox.as_mut().ok_or(BridgeError::Closed)?,
            &mut clock,
        );
        let owner_faulted = !matches!(
            detached
                .inbox
                .as_ref()
                .ok_or(BridgeError::Closed)?
                .inbox_fault(),
            Ok(None)
        );
        let clock_error = clock.error;
        // Restore before any downward callback or failure cleanup. On poisoning,
        // detached owners drop, while cleanup_pending remains available to close.
        let restored = (|| {
            let mut state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let mut stored = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?;
            if state.is_some() || stored.is_some() {
                return Err(BridgeError::Closed);
            }
            *state = detached.inbox.take();
            *stored = detached.plans.take();
            self.cleanup_pending.store(false, Ordering::Release);
            detached.armed = false;
            Ok(())
        })();
        drop(detached);
        if let Err(error) = restored {
            return self.fail_closed(error);
        }
        let (checks, outcome) = result.into_parts();
        self.dispatch_approval_checks(checks)?;
        if let Some(error) = clock_error {
            return self.fail_closed(error);
        }
        if owner_faulted {
            return self.fail_closed(BridgeError::StorageUnavailable);
        }
        match outcome {
            Ok(value) => Ok(value),
            Err(ApprovalError::Busy | ApprovalError::ContextCapacity) => Err(BridgeError::Busy),
            // Capacity/allocation reject before a new native plan is published.
            // Neither means that the request signature or its source is invalid.
            Err(ApprovalError::ContextAllocationFailed) => Err(BridgeError::NativeUnavailable),
            Err(
                ApprovalError::Owner(_)
                | ApprovalError::Persistence(_)
                | ApprovalError::DomainFault(_)
                | ApprovalError::Closed,
            ) => self.fail_closed(BridgeError::StorageUnavailable),
            Err(
                ApprovalError::ClockUnavailable
                | ApprovalError::ClockRegressed
                | ApprovalError::BootChanged,
            ) => self.fail_closed(BridgeError::InvalidObservation),
            Err(_) => Err(BridgeError::ApprovalRejected),
        }
    }

    pub(crate) fn dispatch_approval_checks(
        &self,
        checks: Vec<CommittedAssociatedCheck>,
    ) -> Result<(), BridgeError> {
        let faulted = checks.iter().any(|check| check.update().fault().is_some());
        let effects = checks
            .iter()
            .flat_map(|check| check.update().effects().iter().copied())
            .collect();
        self.dispatch_effects(effects, faulted)
    }
}

/// No foreign cleanup on unwind. Invalidate live handles immediately, release
/// detached storage/key-plan ownership, retain cleanup for the native actor.
struct DetachedApprovalState<'a> {
    controller: &'a MobileController,
    inbox: Option<DurableInbox>,
    plans: Option<ApprovalPlanOwner>,
    armed: bool,
}
impl Drop for DetachedApprovalState<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.controller
                .approval_alive
                .store(false, Ordering::Release);
            self.controller
                .cleanup_pending
                .store(true, Ordering::Release);
            // Keep exact closed native retirement ownership on unwind. The
            // uncertain inbox drops; native handles must still retire later.
            if let Some(plans) = &mut self.plans {
                plans.close();
            }
            let mut stored = self
                .controller
                .approval_owner
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if stored.is_none() {
                *stored = self.plans.take();
            }
            self.controller.close_denial_state();
        }
    }
}

pub(crate) struct NativeApprovalClock<'a> {
    platform: &'a dyn NativePlatform,
    boot: phone_request_core::PhoneBootId,
    floor: &'a std::sync::atomic::AtomicU64,
    error: Option<BridgeError>,
}
impl<'a> NativeApprovalClock<'a> {
    pub(crate) fn new(controller: &'a MobileController) -> Self {
        Self {
            platform: &*controller.platform,
            boot: controller.boot,
            floor: &controller.native_floor_nanos,
            error: None,
        }
    }
    pub(crate) fn error(&self) -> Option<BridgeError> {
        self.error
    }
}
impl ApprovalClock for NativeApprovalClock<'_> {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        let result = crate::native_clock::native_callback(|| self.platform.clock())
            .and_then(map_clock)
            .and_then(|(boot, clock)| {
                if boot != self.boot
                    || clock.phone_monotonic_nanos() < self.floor.load(Ordering::Acquire)
                {
                    return Err(BridgeError::InvalidObservation);
                }
                self.floor
                    .store(clock.phone_monotonic_nanos(), Ordering::Release);
                Ok(ApprovalTime::new(boot, clock))
            });
        result.map_err(|error| {
            self.error = Some(error);
            ApprovalClockError::Unavailable
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_selection_preserves_all_identifiers_without_truncation() {
        let selection = NativeRequestSelection {
            pc: vec![1; 32],
            epoch: vec![2; 32],
            request: vec![3; 32],
        };
        let key = selection.key().unwrap();
        assert_eq!(key.pc(), [1; 32]);
        assert_eq!(key.epoch(), [2; 32]);
        assert_eq!(key.request(), [3; 32]);
        assert_eq!(
            format!("{selection:?}"),
            "NativeRequestSelection([redacted])"
        );
        for length in [0, 31, 33, 4096] {
            let mut invalid = selection.clone();
            invalid.pc = vec![1; length];
            assert_eq!(invalid.key(), Err(BridgeError::InvalidObservation));
        }
    }
}
