// SPDX-License-Identifier: GPL-2.0-or-later
//! One committed-effect dispatcher for the existing sole inbox. No new inbox,
//! policy source, history store or renderer authorization is introduced here.
use crate::{
    BridgeError, MobileController, NativePendingRequest, NativeRequestCatalogState,
    NativeRequestCatalogStatus, NativeRequestPresentation, NativeRequestSelection,
    NativeRequestSinkOutcome,
    native_clock::{self, NativePresentationClock, PresentationTime, native_callback},
};
use android_controller::DurableInbox;
use notification_policy::{AlertMode, Effect, RequestKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, atomic::Ordering},
};

#[uniffi::export]
impl MobileController {
    pub fn request_catalog_status(&self) -> Result<NativeRequestCatalogStatus, BridgeError> {
        let _admission = self.enter()?;
        self.catalog_status_admitted()
    }
    /// Fixed native maintenance wake. No caller clock, effect, event or policy.
    pub fn maintain_native_requests(&self) -> Result<NativeRequestCatalogStatus, BridgeError> {
        let _admission = self.enter()?;
        if let Err(error) = self.maintain_requests_admitted() {
            if error == BridgeError::PresentationRefreshRequired {
                self.intake.await_temporal_refresh();
                self.pause_native_presentations()?;
            }
            return Err(error);
        }
        self.catalog_status_admitted()
    }
    /// A committed original-handle recheck, NOT approval authentication. Native
    /// actions must still call their bound approval/denial owner afterwards.
    pub fn check_pending_request(
        &self,
        request: Arc<NativePendingRequest>,
    ) -> Result<NativeRequestSelection, BridgeError> {
        let _admission = self.enter()?;
        if !self
            .projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .current(&request)
            || request.is_revoked()
        {
            return Err(BridgeError::RequestUnavailable);
        }
        let now = self.read_clock()?;
        let checked = self.with_inbox(|owner| {
            owner
                .check_associated_pending(request.key(), now)
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        let current = checked.request().is_some_and(|value| {
            value.request().original_window() == request.window()
                && value.association() == request.lease().association()
                && value.local_keys() == request.lease().local_keys()
        });
        self.dispatch_approval_checks(vec![checked])?;
        let observed = self.presentation_observation()?;
        if !current
            || !self
                .projections
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .current(&request)
        {
            return Err(BridgeError::RequestUnavailable);
        }
        request.preview(observed)?;
        Ok(request.selection())
    }
}

impl MobileController {
    pub(crate) fn presentation_observation(&self) -> Result<NativePresentationClock, BridgeError> {
        let value = native_callback(|| self.platform.presentation_clock())?;
        if native_clock::validate(value)?.boot != self.boot {
            return Err(BridgeError::InvalidObservation);
        }
        Ok(value)
    }
    pub(crate) fn catalog_status_admitted(
        &self,
    ) -> Result<NativeRequestCatalogStatus, BridgeError> {
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        let state = self.state.lock().map_err(|_| BridgeError::Closed)?;
        let owner = state.as_ref().ok_or(BridgeError::Closed)?;
        let counts = owner
            .counts()
            .map_err(|_| BridgeError::StorageUnavailable)?;
        let configured = owner
            .peer_associations()
            .map_err(|_| BridgeError::StorageUnavailable)?
            .len();
        let projections = self.projections.lock().map_err(|_| BridgeError::Closed)?;
        let state = if !projections.initialized {
            NativeRequestCatalogState::Unavailable
        } else if self.intake.awaiting_temporal_refresh()
            || counts.recovering() != 0
            || counts.active() != projections.count()
        {
            NativeRequestCatalogState::Reconciling
        } else {
            NativeRequestCatalogState::Ready
        };
        let (attached_peers, connected_peers) = self.intake.counts();
        Ok(NativeRequestCatalogStatus {
            state,
            revision: projections.revision,
            request_count: u8::try_from(projections.count())
                .map_err(|_| BridgeError::OwnerFaulted)?,
            configured_peers: u8::try_from(configured).map_err(|_| BridgeError::OwnerFaulted)?,
            attached_peers,
            connected_peers,
        })
    }
    pub(crate) fn maintain_requests_admitted(&self) -> Result<(), BridgeError> {
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        let clock = self.read_clock()?;
        let observation = self.presentation_observation()?;
        let presentation = native_clock::validate(observation)?;
        let previous_epoch = self
            .projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .time_epoch;
        if previous_epoch.is_some_and(|epoch| presentation.time_epoch < epoch) {
            return self.clock_fault();
        }
        let mut refresh = {
            let mut projections = self.projections.lock().map_err(|_| BridgeError::Closed)?;
            let keys = if projections
                .time_epoch
                .is_some_and(|epoch| epoch != presentation.time_epoch)
            {
                let keys = projections.keys();
                projections.revoke_all()?;
                keys
            } else {
                Vec::new()
            };
            projections.time_epoch = Some(presentation.time_epoch);
            keys
        };
        let update = self.with_inbox(|owner| {
            owner
                .poll(clock)
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        self.dispatch_effects(
            update.update().effects().to_vec(),
            update.update().fault().is_some(),
        )?;
        refresh.extend(
            self.projections
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .take_due_refresh(presentation.clock.phone_monotonic_nanos()),
        );
        refresh.sort_unstable();
        refresh.dedup();
        for key in refresh {
            match self.publish_request_key(key, NativeRequestPresentation::Update, None) {
                Ok(()) | Err(BridgeError::RequestUnavailable) => (),
                Err(BridgeError::PresentationRefreshRequired) => {
                    return Err(BridgeError::PresentationRefreshRequired);
                }
                Err(error) => return self.fail_closed(error),
            }
        }
        self.publish_maintenance_deadline()?;
        Ok(())
    }
    fn clock_fault<T>(&self) -> Result<T, BridgeError> {
        self.fail_closed(BridgeError::InvalidObservation)
    }
    pub(crate) fn initialize_effects(
        &self,
        update: android_controller::CommittedUpdate,
    ) -> Result<(), BridgeError> {
        // Existing owner accepted the full DirectorySynced restore BEFORE this
        // native cleanup. Stale native locators never recreate an owner.
        self.cleanup_pending.store(true, Ordering::Release);
        self.attempt_notification_cleanup()?;
        self.dispatch_effects(
            update.update().effects().to_vec(),
            update.update().fault().is_some(),
        )?;
        self.maintain_requests_admitted()?;
        self.projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .initialized = true;
        Ok(())
    }
    pub(crate) fn dispatch_effects(
        &self,
        effects: Vec<Effect>,
        faulted: bool,
    ) -> Result<(), BridgeError> {
        let mut withdrawals = BTreeSet::new();
        let mut presentations = BTreeMap::new();
        let mut failed = faulted;
        for effect in effects {
            match effect {
                Effect::Withdraw { key, .. } => {
                    withdrawals.insert(key);
                }
                Effect::Show(value) => {
                    presentations.insert(
                        value.key,
                        (NativeRequestPresentation::Fresh, Some(value.alert)),
                    );
                }
                Effect::Restore(value) => {
                    presentations.insert(
                        value.key,
                        (NativeRequestPresentation::Restore, Some(value.alert)),
                    );
                }
                Effect::UpdateAlert { key, alert } => {
                    presentations.insert(key, (NativeRequestPresentation::Update, Some(alert)));
                }
                Effect::Fault(_) => failed = true,
                Effect::Drop { .. } | Effect::RecordOutcome { .. } => (),
            }
        }
        withdrawals.extend(
            self.projections
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .prune()?,
        );
        self.dispatch_withdrawals(&withdrawals)?;
        if failed {
            return self.fail_closed(BridgeError::OwnerFaulted);
        }
        if presentations.len() > 32 {
            return self.fail_closed(BridgeError::OwnerFaulted);
        }
        self.reconcile_terminal_outcomes()?;
        for (key, (intent, alert)) in presentations {
            if withdrawals.contains(&key) {
                continue;
            }
            match self.publish_request_key(key, intent, alert) {
                Ok(()) | Err(BridgeError::RequestUnavailable) => (),
                Err(BridgeError::PresentationRefreshRequired) => {
                    return Err(BridgeError::PresentationRefreshRequired);
                }
                Err(error) => return self.fail_closed(error),
            }
        }
        self.publish_maintenance_deadline()
    }
    fn dispatch_withdrawals(&self, keys: &BTreeSet<RequestKey>) -> Result<(), BridgeError> {
        if keys.is_empty() {
            return Ok(());
        }
        for key in keys {
            self.projections
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .remove(*key)?;
            if let Some(plans) = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .as_mut()
            {
                let _ = plans.cancel_request(*key);
            }
            self.cancel_denial_request(*key);
        }
        native_callback(|| {
            self.platform.withdraw_requests(
                keys.iter()
                    .copied()
                    .map(NativeRequestSelection::from_key)
                    .collect(),
            )
        })
        .or_else(|_| self.fail_closed(BridgeError::NativeUnavailable))
    }
    pub(crate) fn pause_native_presentations(&self) -> Result<(), BridgeError> {
        let keys = {
            let mut projections = self.projections.lock().map_err(|_| BridgeError::Closed)?;
            let keys = projections.keys();
            projections.revoke_all()?;
            for key in &keys {
                projections.defer_refresh(*key, 0)?;
            }
            keys.into_iter().collect()
        };
        self.dispatch_withdrawals(&keys)
    }
    fn publish_request_key(
        &self,
        key: RequestKey,
        intent: NativeRequestPresentation,
        alert: Option<AlertMode>,
    ) -> Result<(), BridgeError> {
        self.projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .reserve(key)?;
        let before = self.read_clock()?;
        let checked = self.with_inbox(|owner| {
            owner
                .check_associated_pending(key, before)
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        // check_pending produces downward maintenance only; no recursive positive dispatch.
        let mut withdrawals = BTreeSet::new();
        let mut faulted = checked.update().fault().is_some();
        for effect in checked.update().effects() {
            match *effect {
                Effect::Withdraw { key, .. } => {
                    withdrawals.insert(key);
                }
                Effect::Drop { .. } | Effect::RecordOutcome { .. } => (),
                Effect::Fault(_)
                | Effect::Show(_)
                | Effect::Restore(_)
                | Effect::UpdateAlert { .. } => faulted = true,
            }
        }
        self.dispatch_withdrawals(&withdrawals)?;
        if faulted {
            return self.fail_closed(BridgeError::OwnerFaulted);
        }
        self.reconcile_terminal_outcomes()?;
        let Some(request) = checked.request() else {
            return Err(BridgeError::RequestUnavailable);
        };
        let observed = self.presentation_observation()?;
        let sample = native_clock::validate(observed)?;
        if sample.clock.phone_monotonic_nanos() < before.phone_monotonic_nanos() {
            return self.clock_fault();
        }
        let projection = self.with_inbox(|owner| {
            NativePendingRequest::new(owner, request, Arc::clone(&self.approval_alive), sample)
        });
        let projection = match projection {
            Ok(value) => value,
            Err(BridgeError::RequestUnavailable) => {
                self.late_request_maintenance(key, sample)?;
                return Err(BridgeError::RequestUnavailable);
            }
            Err(error) => return Err(error),
        };
        if projection.preview(observed).is_err() {
            if self.approval_alive.load(Ordering::Acquire) {
                let due = sample
                    .clock
                    .phone_monotonic_nanos()
                    .checked_add(2_000_000)
                    .ok_or(BridgeError::InvalidObservation)?;
                self.projections
                    .lock()
                    .map_err(|_| BridgeError::Closed)?
                    .defer_refresh(key, due)?;
                self.publish_maintenance_deadline()?;
            }
            return Err(BridgeError::RequestUnavailable);
        }
        let alert = alert.unwrap_or_else(|| request.request().notification().alert);
        self.projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .insert(Arc::clone(&projection))?;
        let outcome = native_callback(|| {
            self.platform
                .publish_pending_request(Arc::clone(&projection), intent, alert.into())
        })?;
        let after = self.presentation_observation()?;
        if matches!(outcome, NativeRequestSinkOutcome::DiscardedStale)
            || projection.preview(after).is_err()
        {
            projection.revoke();
            self.dispatch_withdrawals(&BTreeSet::from([key]))?;
            let time = native_clock::validate(after)?;
            self.late_request_maintenance(key, time)?;
            let due = time
                .clock
                .phone_monotonic_nanos()
                .checked_add(2_000_000)
                .ok_or(BridgeError::InvalidObservation)?;
            self.projections
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .defer_refresh(key, due)?;
            self.intake.wake();
            return Err(BridgeError::RequestUnavailable);
        }
        Ok(())
    }
    fn late_request_maintenance(
        &self,
        key: RequestKey,
        sample: PresentationTime,
    ) -> Result<(), BridgeError> {
        let checked = self.with_inbox(|owner| {
            owner
                .check_associated_pending(key, sample.clock)
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        let mut withdrawals = BTreeSet::new();
        for effect in checked.update().effects() {
            if let Effect::Withdraw { key, .. } = *effect {
                withdrawals.insert(key);
            }
        }
        self.dispatch_withdrawals(&withdrawals)?;
        if checked.update().fault().is_some() {
            return self.fail_closed(BridgeError::OwnerFaulted);
        }
        self.reconcile_terminal_outcomes()
    }
    pub(crate) fn reconcile_terminal_outcomes(&self) -> Result<(), BridgeError> {
        let pending = self.with_inbox(|owner| {
            Ok(owner
                .pending_outcomes()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .to_vec())
        })?;
        if pending.is_empty() {
            return Ok(());
        }
        // Preserve exact terminal evidence BEFORE the atomic history/producer ACK.
        for outcome in &pending {
            self.observe_denial_terminal(*outcome);
        }
        let Ok(raw) = native_callback(|| self.platform.unix_millis()) else {
            return Ok(());
        };
        let Ok(now) = activity_journal::UnixMillis::new(raw) else {
            return Ok(());
        };
        self.with_inbox(|owner| {
            owner
                .record_pending_outcomes(now)
                .map(|_| ())
                .map_err(|_| BridgeError::StorageUnavailable)
        })
    }
    pub(crate) fn publish_maintenance_deadline(&self) -> Result<(), BridgeError> {
        let deadline = self.with_inbox(|owner| {
            owner
                .next_deadline_nanos()
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        let refresh = self
            .projections
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .refresh_deadline();
        self.intake
            .set_deadline(deadline.into_iter().chain(refresh).min());
        Ok(())
    }
    pub(crate) fn with_inbox<T>(
        &self,
        action: impl FnOnce(&mut DurableInbox) -> Result<T, BridgeError>,
    ) -> Result<T, BridgeError> {
        let inbox = self
            .state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .take()
            .ok_or(BridgeError::Closed)?;
        let mut detached = DetachedInbox {
            controller: self,
            inbox: Some(inbox),
        };
        let result = action(detached.inbox.as_mut().ok_or(BridgeError::Closed)?);
        let mut state = self.state.lock().map_err(|_| BridgeError::Closed)?;
        if state.is_some() {
            return Err(BridgeError::Closed);
        }
        *state = detached.inbox.take();
        drop(state);
        match result {
            Err(
                error @ (BridgeError::StorageUnavailable
                | BridgeError::OwnerFaulted
                | BridgeError::Closed),
            ) => self.fail_closed(error),
            other => other,
        }
    }
}
struct DetachedInbox<'a> {
    controller: &'a MobileController,
    inbox: Option<DurableInbox>,
}
impl Drop for DetachedInbox<'_> {
    fn drop(&mut self) {
        if self.inbox.is_some() {
            self.controller
                .approval_alive
                .store(false, Ordering::Release);
            self.controller
                .cleanup_pending
                .store(true, Ordering::Release);
            self.controller.close_denial_state();
        }
    }
}
