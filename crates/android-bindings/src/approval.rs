// SPDX-License-Identifier: GPL-2.0-or-later
//! Opaque native-only request plans. There is no exported constructor, caller
//! signing statement, authentication boolean, or renderer signing command.
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use android_controller::{
    ApprovalAttempt, ApprovalClock, ApprovalClockError, ApprovalError, ApprovalPlan,
    ApprovalPlanOwner, ApprovalSubmission, ApprovalTime, ApprovalTransition,
    CommittedAssociatedCheck, DurableInbox,
};
use notification_policy::{Effect, RequestKey};

use crate::{BridgeError, MobileController, NativeLocalKeySet, NativePlatform, map_clock};

/// A bounded selection only, never evidence of receipt, pairing or permission.
#[derive(Clone, uniffi::Record)]
pub struct NativeRequestSelection {
    pub pc: Vec<u8>,
    pub epoch: Vec<u8>,
    pub request: Vec<u8>,
}
impl NativeRequestSelection {
    fn key(&self) -> Result<RequestKey, BridgeError> {
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
    fn from_key(key: RequestKey) -> Self {
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
    core: ApprovalSubmission,
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
        !self.controller_alive.load(Ordering::Acquire) || self.core.is_cancelled()
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
        let plan = self.run_approval(|plans, inbox, clock| plans.begin(inbox, key, clock))?;
        Ok(Arc::new(NativeApprovalPlan {
            core: plan,
            controller_alive: Arc::clone(&self.approval_alive),
            native_closed: AtomicBool::new(false),
        }))
    }

    pub fn claim_approval(
        &self,
        plan: Arc<NativeApprovalPlan>,
    ) -> Result<Arc<NativeApprovalAttempt>, BridgeError> {
        let _admission = self.enter()?;
        self.require_own_plan(&plan)?;
        let attempt =
            self.run_approval(|plans, inbox, clock| plans.claim(inbox, &plan.core, clock))?;
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
        // The domain consumes its claim even on malformed/invalid DER. A caller
        // cannot retry finish with another signature or duplicate a copied Arc.
        let result = self
            .run_approval(|plans, inbox, clock| plans.finish(inbox, &attempt.core, &der, clock));
        attempt.plan.native_closed.store(true, Ordering::Release);
        match result {
            Ok(core) => Ok(Arc::new(NativeApprovalSubmission {
                core,
                controller_alive: Arc::clone(&self.approval_alive),
            })),
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
            plans
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .retire_after_native_cleanup(&plan.core)
                .map_err(|_| BridgeError::ApprovalRejected)
        })();
        if result == Err(BridgeError::Closed) {
            return self.fail_closed(BridgeError::Closed);
        }
        result
    }
}

impl MobileController {
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

    fn dispatch_approval_checks(
        &self,
        checks: Vec<CommittedAssociatedCheck>,
    ) -> Result<(), BridgeError> {
        let mut withdrawn = std::collections::BTreeSet::new();
        let mut faulted = false;
        for checked in checks {
            faulted |= checked.update().fault().is_some();
            for effect in checked.update().effects() {
                match *effect {
                    Effect::Withdraw { key, .. } => {
                        withdrawn.insert(key);
                    }
                    // Outcome delivery remains in the durable body-free outbox.
                    Effect::RecordOutcome { .. } | Effect::Drop { .. } => {}
                    Effect::Fault(_) => faulted = true,
                    Effect::Show(_) | Effect::Restore(_) | Effect::UpdateAlert { .. } => {
                        faulted = true
                    }
                }
            }
        }
        if !withdrawn.is_empty()
            && self
                .platform
                .withdraw_requests(
                    withdrawn
                        .into_iter()
                        .map(NativeRequestSelection::from_key)
                        .collect(),
                )
                .is_err()
        {
            return self.fail_closed(BridgeError::NativeUnavailable);
        }
        if faulted {
            return self.fail_closed(BridgeError::OwnerFaulted);
        }
        Ok(())
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
        }
    }
}

struct NativeApprovalClock<'a> {
    platform: &'a dyn NativePlatform,
    boot: phone_request_core::PhoneBootId,
    floor: &'a std::sync::atomic::AtomicU64,
    error: Option<BridgeError>,
}
impl ApprovalClock for NativeApprovalClock<'_> {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        let result = self
            .platform
            .clock()
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
