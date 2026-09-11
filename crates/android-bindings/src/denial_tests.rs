// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual public associated TLS ingress + isolated host store from denial_fixture.
//! Native callbacks/time/key signing below are explicit software/system fixtures,
//! not Android hardware, secure-lock, native cleanup or Windows acceptance proof.
use crate::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use std::sync::{Weak, atomic::AtomicUsize};

struct Platform {
    time: Mutex<NativeClock>,
    drain: Mutex<NativeApprovalDrainState>,
    operation: Mutex<NativeDenialOperationState>,
    fail_release: AtomicBool,
    panic_clock: AtomicBool,
    clock_calls: AtomicUsize,
    drains: AtomicUsize,
    operations: AtomicUsize,
    releases: AtomicUsize,
    key_releases: AtomicUsize,
    notification_clears: AtomicUsize,
    fail_notifications: AtomicBool,
    fail_keys: AtomicBool,
    withdrawals: AtomicUsize,
    controller: Mutex<Weak<MobileController>>,
    callback_checks: AtomicUsize,
    cancel_scope_on_clock: Mutex<Option<Weak<NativeDenialScope>>>,
    withdraw_time: Mutex<Option<u64>>,
    cancel_plan_on_withdraw: Mutex<Option<Weak<NativeApprovalPlan>>>,
}
impl Platform {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            // All genuine fixture ingress has completed by33ms, including32 requests.
            time: Mutex::new(NativeClock {
                boot_count: 5,
                monotonic_nanos: 100_000_000,
                weekday: 0,
                minute: 600,
            }),
            drain: Mutex::new(NativeApprovalDrainState::NoMatchingSession),
            operation: Mutex::new(NativeDenialOperationState::NotStarted),
            fail_release: AtomicBool::new(false),
            panic_clock: AtomicBool::new(false),
            clock_calls: AtomicUsize::new(0),
            drains: AtomicUsize::new(0),
            operations: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            key_releases: AtomicUsize::new(0),
            notification_clears: AtomicUsize::new(0),
            fail_notifications: AtomicBool::new(false),
            fail_keys: AtomicBool::new(false),
            withdrawals: AtomicUsize::new(0),
            controller: Mutex::new(Weak::new()),
            callback_checks: AtomicUsize::new(0),
            cancel_scope_on_clock: Mutex::new(None),
            withdraw_time: Mutex::new(None),
            cancel_plan_on_withdraw: Mutex::new(None),
        })
    }
    fn callback(&self) {
        if let Some(owner) = self.controller.lock().unwrap().upgrade() {
            assert!(
                owner.state.try_lock().is_ok(),
                "no callback under inbox mutex"
            );
            assert!(
                owner.approval_owner.try_lock().is_ok(),
                "no callback under approval mutex"
            );
            assert!(
                owner.denial_state.try_lock().is_ok(),
                "no callback under denial mutex"
            );
            assert_eq!(owner.notification_policy_json(), Err(BridgeError::Busy));
            self.callback_checks.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn at(&self, nanos: u64) {
        self.time.lock().unwrap().monotonic_nanos = nanos;
    }
}
impl NativePlatform for Platform {
    fn secure_lock_configured(&self) -> Result<bool, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }

    fn create_local_key_set(
        &self,
        _request: std::sync::Arc<crate::NativeKeyCreationRequest>,
    ) -> Result<crate::NativeCreatedKeyEvidence, BridgeError> {
        Err(BridgeError::LifecycleIntegrationRequired)
    }

    fn intake_progress(&self) -> Result<(), BridgeError> {
        Ok(())
    }
    fn presentation_clock(&self) -> Result<NativePresentationClock, BridgeError> {
        let clock = self.clock()?;
        Ok(NativePresentationClock {
            boot_count: clock.boot_count,
            elapsed_before_nanos: clock.monotonic_nanos,
            elapsed_after_nanos: clock.monotonic_nanos,
            wall_before_millis: 1_700_000_000_000,
            wall_after_millis: 1_700_000_000_000,
            weekday: clock.weekday,
            minute: clock.minute,
            millis_within_minute: 0,
            time_epoch: 1,
        })
    }
    fn publish_pending_request(
        &self,
        _: Arc<NativePendingRequest>,
        _: NativeRequestPresentation,
        _: NativeRequestAlert,
    ) -> Result<NativeRequestSinkOutcome, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn advance_approval_drain_for_denial(
        &self,
        _: Arc<NativeDenialScope>,
    ) -> Result<NativeApprovalDrainState, BridgeError> {
        self.callback();
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(*self.drain.lock().unwrap())
    }
    fn observe_denial_operation(
        &self,
        _: Arc<NativeDenialAttempt>,
    ) -> Result<NativeDenialOperationState, BridgeError> {
        self.callback();
        self.operations.fetch_add(1, Ordering::SeqCst);
        Ok(*self.operation.lock().unwrap())
    }
    fn release_denial_scope(&self, _: Arc<NativeDenialScope>) -> Result<(), BridgeError> {
        self.callback();
        self.releases.fetch_add(1, Ordering::SeqCst);
        if self.fail_release.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            Ok(())
        }
    }
    fn prepare_transport_signer(&self, _: Arc<NativeTransportBinding>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn sign_client_certificate_verify(
        &self,
        _: Arc<NativeCertificateVerify>,
    ) -> Result<Vec<u8>, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_transport_signer(&self, _: Arc<NativeTransportBinding>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn state_directory(&self) -> Result<String, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn clock(&self) -> Result<NativeClock, BridgeError> {
        self.callback();
        self.clock_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(scope) = self
            .cancel_scope_on_clock
            .lock()
            .unwrap()
            .take()
            .and_then(|scope| scope.upgrade())
        {
            scope.cancel();
        }
        assert!(
            !self.panic_clock.load(Ordering::Acquire),
            "synthetic native clock panic"
        );
        Ok(*self.time.lock().unwrap())
    }
    fn unix_millis(&self) -> Result<u64, BridgeError> {
        Ok(1234567)
    }
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn has_device_keys(&self) -> Result<bool, BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn reopen_local_key_sets(&self, _: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
        Err(BridgeError::NativeUnavailable)
    }
    fn release_local_key_references(&self) -> Result<(), BridgeError> {
        self.callback();
        self.key_releases.fetch_add(1, Ordering::SeqCst);
        if self.fail_keys.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            Ok(())
        }
    }
    fn clear_request_notifications(&self) -> Result<(), BridgeError> {
        self.callback();
        self.notification_clears.fetch_add(1, Ordering::SeqCst);
        if self.fail_notifications.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            Ok(())
        }
    }
    fn withdraw_requests(&self, requests: Vec<NativeRequestSelection>) -> Result<(), BridgeError> {
        self.callback();
        self.withdrawals.fetch_add(requests.len(), Ordering::SeqCst);
        if let Some(time) = self.withdraw_time.lock().unwrap().take() {
            self.at(time);
        }
        if let Some(plan) = self
            .cancel_plan_on_withdraw
            .lock()
            .unwrap()
            .take()
            .and_then(|plan| plan.upgrade())
        {
            plan.cancel();
        }
        Ok(())
    }
}

// This is test-only Application object construction. The inbox itself has ONLY
// the fixture's public real AssociatedPcSocket-origin requests; no scope/body/
// receiving-generation or MobileController production setter is introduced.
fn with_fixture(
    count: usize,
    test: impl FnOnce(&Arc<MobileController>, &Arc<Platform>, &[NativeRequestSelection]),
) {
    with_fixture_deadlines(count, None, test);
}
fn with_fixture_deadlines(
    count: usize,
    deadlines: Option<&[u64]>,
    test: impl FnOnce(&Arc<MobileController>, &Arc<Platform>, &[NativeRequestSelection]),
) {
    let _serial = crate::tests::SERIAL
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let fixture = match deadlines {
        Some(deadlines) => crate::denial_fixture::fixture_with_deadlines(deadlines),
        None if count == 1 => crate::denial_fixture::fixture(),
        None => crate::denial_fixture::fixture_with_requests(count),
    };
    assert_eq!(fixture.binding, fixture.bindings[0]);
    assert!(
        fixture
            .owner
            .peer_associations()
            .unwrap()
            .resolve(fixture.reference)
            .is_some()
    );
    assert!(fixture.final_clock.phone_monotonic_nanos() <= 100_000_000);
    let selections: Vec<_> = fixture
        .bindings
        .iter()
        .copied()
        .map(phone_request_core::request_key)
        .map(NativeRequestSelection::from_key)
        .collect();
    let platform = Platform::new();
    let boot = crate::denial_fixture::boot();
    let owner = fixture.owner;
    let controller = Arc::new(MobileController {
        platform: platform.clone(),
        boot,
        approval_owner: Mutex::new(Some(
            android_controller::ApprovalPlanOwner::new(&owner, boot).unwrap(),
        )),
        approval_native_plan: Mutex::new(None),
        denial_state: Mutex::new(crate::denial::DenialState::new(&owner, boot).unwrap()),
        projections: Mutex::new(crate::request_projection::ProjectionRegistry::default()),
        intake: Arc::new(crate::intake::IntakeOwner::default()),
        approval_alive: Arc::new(AtomicBool::new(true)),
        state: Mutex::new(Some(owner)),
        creation_slot: Mutex::new(std::sync::Weak::<crate::pairing::CreationState>::new()),
        active: AtomicBool::new(false),
        cleanup_pending: AtomicBool::new(false),
        notification_cleanup_failed: AtomicBool::new(false),
        key_cleanup_pending: AtomicBool::new(true),
        key_cleanup_failed: AtomicBool::new(false),
        native_floor_nanos: AtomicU64::new(100_000_000),
        _owner_lease: Arc::new(OwnerLease::acquire().unwrap()),
    });
    *platform.controller.lock().unwrap() = Arc::downgrade(&controller);
    test(&controller, &platform, &selections);
    drop(controller);
    // Keep fixture-owned directory until the actual locked inbox has dropped.
    drop(fixture.temp);
}
fn ready(
    controller: &MobileController,
    scope: &Arc<NativeDenialScope>,
) -> Arc<NativeDenialAttempt> {
    match controller.advance_denial(scope.clone()).unwrap() {
        NativeDenialAdvance::Ready { attempt } => attempt,
        other => panic!("expected fixture ready attempt {other:?}"),
    }
}
fn signature(attempt: &NativeDenialAttempt, seed: u8) -> Vec<u8> {
    let bytes = attempt.take_signing_bytes().unwrap();
    let signed: Signature = SigningKey::from_slice(&[seed; 32]).unwrap().sign(&bytes);
    signed.to_der().as_bytes().to_vec()
}
fn cancel_and_release(
    controller: &MobileController,
    scope: &Arc<NativeDenialScope>,
    platform: &Platform,
) {
    scope.cancel();
    *platform.operation.lock().unwrap() = NativeDenialOperationState::Quiescent;
    assert!(matches!(
        controller.settle_denial(scope.clone()).unwrap(),
        NativeDenialAdvance::Released
    ));
}

#[test]
fn genuine_request_fence_and_one_shot_bytes_produce_only_prepared_unsent_denial() {
    with_fixture(1, |controller, platform, requests| {
        assert_eq!(bridge_version(), 10);
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        assert!(scope.same_scope(controller.reserve_denial(requests[0].clone()).unwrap()));
        assert_eq!(
            controller.begin_approval(requests[0].clone()).unwrap_err(),
            BridgeError::ApprovalRejected
        );
        let attempt = ready(controller, &scope);
        assert!(attempt.belongs_to(scope.clone()));
        assert_eq!(attempt.local_keys().unwrap().handle.len(), 32);
        let der = signature(&attempt, 4);
        assert_eq!(
            attempt.take_signing_bytes().unwrap_err(),
            BridgeError::DenialRejected
        );
        assert!(matches!(
            controller.finish_denial(attempt.clone(), der).unwrap(),
            NativeDenialAdvance::Prepared
        ));
        assert!(attempt.is_cancelled());
        assert!(!scope.is_cancelled());
        *platform.operation.lock().unwrap() = NativeDenialOperationState::Quiescent;
        assert!(matches!(
            controller.retire_denial_native(scope.clone()).unwrap(),
            NativeDenialAdvance::Prepared
        ));
        assert!(matches!(
            controller.settle_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::Prepared
        ));
        assert_eq!(
            controller.begin_approval(requests[0].clone()).unwrap_err(),
            BridgeError::ApprovalRejected
        );
        assert!(
            controller
                .state
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .history()
                .unwrap()
                .is_empty()
        );
        assert!(
            controller
                .state
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .pending_outcomes()
                .unwrap()
                .is_empty()
        );
        cancel_and_release(controller, &scope, platform);
        assert_eq!(platform.releases.load(Ordering::SeqCst), 1);
        assert!(matches!(
            controller.settle_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::Released
        ));
        assert_eq!(platform.releases.load(Ordering::SeqCst), 1);
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        plan.cancel();
        controller.retire_approval(plan).unwrap();
        assert!(platform.callback_checks.load(Ordering::SeqCst) > 0);
    });
}

#[test]
fn early_native_retirement_cannot_skip_a_later_real_attempt_cleanup() {
    with_fixture(1, |controller, platform, requests| {
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        assert!(matches!(
            controller.retire_denial_native(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupPending
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 0);
        let attempt = ready(controller, &scope);
        let der = signature(&attempt, 4);
        assert!(matches!(
            controller.retire_denial_native(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupPending
        ));
        assert!(matches!(
            controller.finish_denial(attempt, der).unwrap(),
            NativeDenialAdvance::Prepared
        ));
        *platform.operation.lock().unwrap() = NativeDenialOperationState::Running;
        assert!(matches!(
            controller.retire_denial_native(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupPending
        ));
        *platform.operation.lock().unwrap() = NativeDenialOperationState::Quiescent;
        assert!(matches!(
            controller.retire_denial_native(scope.clone()).unwrap(),
            NativeDenialAdvance::Prepared
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 2);
        cancel_and_release(controller, &scope, platform);
    });
}

#[test]
fn native_drain_and_core_slot_absence_are_independent_required_observations() {
    with_fixture(1, |controller, platform, requests| {
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        assert!(plan.is_cancelled());
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::Pending;
        assert!(matches!(
            controller.advance_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::Waiting {
                reason: NativeDenialWait::ApprovalNative
            }
        ));
        // Deliberate contradictory native fixture: it cannot erase the core slot.
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::NoMatchingSession;
        assert!(matches!(
            controller.advance_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::Waiting {
                reason: NativeDenialWait::ApprovalCore
            }
        ));
        controller.retire_approval(plan).unwrap(); // No real native operation in fixture.
        let attempt = ready(controller, &scope);
        assert!(!attempt.is_cancelled());
        cancel_and_release(controller, &scope, platform);
    });
}

#[test]
fn same_request_approval_claim_finish_are_fenced_but_other_request_remains_eligible() {
    with_fixture(2, |controller, platform, requests| {
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        let claim = controller.claim_approval(plan.clone()).unwrap();
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        assert_eq!(
            controller.claim_approval(plan.clone()).unwrap_err(),
            BridgeError::ApprovalRejected
        );
        assert_eq!(
            controller.finish_approval(claim, vec![]).unwrap_err(),
            BridgeError::ApprovalRejected
        );
        controller.retire_approval(plan).unwrap();
        let other = controller.begin_approval(requests[1].clone()).unwrap();
        assert!(!other.is_cancelled());
        let attempt = ready(controller, &scope);
        assert!(attempt.belongs_to(scope.clone()));
        assert!(!other.is_cancelled());
        cancel_and_release(controller, &scope, platform);
        other.cancel();
        controller.retire_approval(other).unwrap();
    });
}

#[test]
fn wrong_role_and_malformed_denial_finish_consume_attempt_without_release_or_history() {
    for seed in [Some(3), Some(5), None] {
        with_fixture(1, |controller, platform, requests| {
            let scope = controller.reserve_denial(requests[0].clone()).unwrap();
            let attempt = ready(controller, &scope);
            let der = match seed {
                Some(seed) => signature(&attempt, seed),
                None => {
                    let _ = attempt.take_signing_bytes().unwrap();
                    vec![0x30, 0]
                }
            };
            assert_eq!(
                controller.finish_denial(attempt.clone(), der).unwrap_err(),
                BridgeError::DenialRejected
            );
            assert!(scope.is_cancelled());
            assert_eq!(
                controller
                    .finish_denial(attempt.clone(), vec![])
                    .unwrap_err(),
                BridgeError::DenialRejected
            );
            assert_eq!(
                attempt.take_signing_bytes().unwrap_err(),
                BridgeError::DenialRejected
            );
            assert!(
                controller
                    .state
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .history()
                    .unwrap()
                    .is_empty()
            );
            cancel_and_release(controller, &scope, platform);
        });
    }
}

#[test]
fn ready_and_prepared_reobservations_cannot_publish_after_original_expiry() {
    for prepared in [false, true] {
        with_fixture(1, |controller, platform, requests| {
            let scope = controller.reserve_denial(requests[0].clone()).unwrap();
            let attempt = ready(controller, &scope);
            if prepared {
                let der = signature(&attempt, 4);
                assert!(matches!(
                    controller.finish_denial(attempt, der).unwrap(),
                    NativeDenialAdvance::Prepared
                ));
            }
            platform.at(scope.deadline_nanos());
            assert_eq!(
                controller.advance_denial(scope.clone()).unwrap_err(),
                BridgeError::DenialRejected
            );
            assert!(scope.is_cancelled());
            assert!(platform.withdrawals.load(Ordering::SeqCst) > 0);
            cancel_and_release(controller, &scope, platform);
        });
    }
}

#[test]
fn failed_native_cleanup_is_latched_until_explicit_one_step_retry() {
    with_fixture(1, |controller, platform, requests| {
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        let attempt = ready(controller, &scope);
        let _ = attempt.take_signing_bytes().unwrap();
        scope.cancel(); // Provider never started, but registered native op is terminal.
        *platform.operation.lock().unwrap() = NativeDenialOperationState::Failed;
        assert!(matches!(
            controller.settle_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 1);
        *platform.operation.lock().unwrap() = NativeDenialOperationState::Quiescent;
        assert!(matches!(
            controller.advance_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert!(matches!(
            controller.settle_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 1);
        platform.fail_release.store(true, Ordering::Release);
        assert!(matches!(
            controller.retry_denial_cleanup(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 2);
        assert_eq!(platform.releases.load(Ordering::SeqCst), 1);
        platform.fail_release.store(false, Ordering::Release);
        assert!(matches!(
            controller.settle_denial(scope.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(platform.releases.load(Ordering::SeqCst), 1);
        assert!(matches!(
            controller.retry_denial_cleanup(scope.clone()).unwrap(),
            NativeDenialAdvance::Released
        ));
        assert_eq!(platform.operations.load(Ordering::SeqCst), 2);
        assert_eq!(platform.releases.load(Ordering::SeqCst), 2);
        assert_eq!(
            attempt.take_signing_bytes().unwrap_err(),
            BridgeError::DenialRejected
        );
    });
}

#[test]
fn shutdown_keeps_exact_closed_core_owner_until_native_approval_retirement() {
    with_fixture(1, |controller, platform, requests| {
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::Pending;
        assert_eq!(
            controller.shutdown_native_owner(),
            Err(BridgeError::NativeUnavailable)
        );
        assert!(scope.is_cancelled());
        assert!(controller.state.lock().unwrap().is_none());
        assert!(controller.approval_owner.lock().unwrap().is_some());
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 0);
        assert_eq!(
            controller.begin_approval(requests[0].clone()).unwrap_err(),
            BridgeError::Closed
        );
        controller.retire_approval(plan).unwrap(); // Cleanup-only method remains callable.
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::Retired;
        assert!(matches!(
            controller.retry_denial_cleanup(scope).unwrap(),
            NativeDenialAdvance::Released
        ));
        assert_eq!(controller.shutdown_native_owner(), Ok(()));
        assert!(controller.approval_owner.lock().unwrap().is_none());
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn thirty_two_real_request_scopes_are_bounded_and_duplicate_selection_keeps_identity() {
    with_fixture(32, |controller, platform, requests| {
        let mut scopes = Vec::new();
        for request in requests {
            scopes.push(controller.reserve_denial(request.clone()).unwrap());
        }
        let duplicate = controller.reserve_denial(requests[0].clone()).unwrap();
        assert!(duplicate.same_scope(scopes[0].clone()));
        let before = platform.clock_calls.load(Ordering::SeqCst);
        let mut unavailable = requests[0].clone();
        unavailable.request = vec![99; 32];
        assert_eq!(
            controller.reserve_denial(unavailable).unwrap_err(),
            BridgeError::Busy
        );
        assert_eq!(platform.clock_calls.load(Ordering::SeqCst), before);
        let first = ready(controller, &scopes[0]);
        assert!(matches!(
            controller.advance_denial(scopes[1].clone()).unwrap(),
            NativeDenialAdvance::Waiting {
                reason: NativeDenialWait::DenialSlot
            }
        ));
        assert!(!first.is_cancelled());
        for scope in &scopes {
            cancel_and_release(controller, scope, platform);
        }
        assert_eq!(platform.releases.load(Ordering::SeqCst), 32);
    });
}

#[test]
fn malformed_or_missing_request_reservation_never_installs_a_fence() {
    with_fixture(1, |controller, platform, requests| {
        let mut invalid = requests[0].clone();
        invalid.request = vec![0; 32];
        assert_eq!(
            controller.reserve_denial(invalid).unwrap_err(),
            BridgeError::InvalidObservation
        );
        assert_eq!(platform.clock_calls.load(Ordering::SeqCst), 0);
        let mut missing = requests[0].clone();
        missing.request = vec![99; 32];
        assert_eq!(
            controller.reserve_denial(missing).unwrap_err(),
            BridgeError::DenialRejected
        );
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        plan.cancel();
        controller.retire_approval(plan).unwrap();
        assert_eq!(platform.drains.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn clock_callback_unwind_closes_admission_and_retains_scope_cleanup() {
    with_fixture(1, |controller, platform, requests| {
        let scope = controller.reserve_denial(requests[0].clone()).unwrap();
        platform.panic_clock.store(true, Ordering::Release);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = controller.advance_denial(scope.clone());
        }));
        assert!(caught.is_err());
        assert!(scope.is_cancelled());
        assert!(controller.state.lock().unwrap().is_none());
        platform.panic_clock.store(false, Ordering::Release);
        cancel_and_release(controller, &scope, platform);
        assert_eq!(controller.shutdown_native_owner(), Ok(()));
    });
}

#[test]
fn final_clock_cancellation_never_republishes_prepared_material() {
    for operation in 0..3 {
        with_fixture(1, |controller, platform, requests| {
            let scope = controller.reserve_denial(requests[0].clone()).unwrap();
            let attempt = ready(controller, &scope);
            let der = signature(&attempt, 4);
            assert!(matches!(
                controller.finish_denial(attempt, der).unwrap(),
                NativeDenialAdvance::Prepared
            ));
            *platform.operation.lock().unwrap() = NativeDenialOperationState::Quiescent;
            *platform.cancel_scope_on_clock.lock().unwrap() = Some(Arc::downgrade(&scope));
            let result = match operation {
                0 => controller.advance_denial(scope.clone()),
                1 => controller.retire_denial_native(scope.clone()),
                _ => controller.settle_denial(scope.clone()),
            };
            assert!(
                !matches!(result, Ok(NativeDenialAdvance::Prepared)),
                "cancelled final observation: {result:?}"
            );
            assert!(scope.is_cancelled());
            assert!(matches!(
                controller.settle_denial(scope).unwrap(),
                NativeDenialAdvance::Released
            ));
        });
    }
}

#[test]
fn approval_publication_after_real_withdrawal_callback_cannot_cross_original_deadline() {
    for operation in 0..3 {
        with_fixture_deadlines(
            2,
            Some(&[5_000, 60_000]),
            |controller, platform, requests| {
                let plan = if operation > 0 {
                    Some(controller.begin_approval(requests[1].clone()).unwrap())
                } else {
                    None
                };
                let attempt = if operation == 2 {
                    Some(
                        controller
                            .claim_approval(plan.as_ref().unwrap().clone())
                            .unwrap(),
                    )
                } else {
                    None
                };
                let der = attempt.as_ref().map(|attempt| {
                    let signature: Signature = SigningKey::from_slice(&[3; 32])
                        .unwrap()
                        .sign(&attempt.signing_bytes().unwrap());
                    signature.to_der().as_bytes().to_vec()
                });
                platform.at(5_000_000_000);
                *platform.withdraw_time.lock().unwrap() = Some(60_000_000_000);
                // Real first-request expiry yields a committed withdrawal callback;
                // its time advance occurs AFTER the core's seal for the second request.
                let error = match operation {
                    0 => controller.begin_approval(requests[1].clone()).unwrap_err(),
                    1 => controller
                        .claim_approval(plan.as_ref().unwrap().clone())
                        .unwrap_err(),
                    _ => controller
                        .finish_approval(attempt.unwrap(), der.unwrap())
                        .unwrap_err(),
                };
                assert_eq!(error, BridgeError::ApprovalRejected);
                assert_eq!(platform.withdrawals.load(Ordering::SeqCst), 2);
                let state = controller.state.lock().unwrap();
                assert!(
                    state
                        .as_ref()
                        .unwrap()
                        .pending_outcomes()
                        .unwrap()
                        .is_empty()
                );
                let history = state.as_ref().unwrap().history().unwrap();
                assert_eq!(history.len(), 2);
                assert!(history.iter().all(
                    |row| row.outcome() == notification_policy::RequestOutcome::ExpiredLocally
                ));
                drop(state);
                if let Some(plan) = plan {
                    assert!(plan.is_cancelled());
                    controller.retire_approval(plan).unwrap();
                } else {
                    assert!(controller.approval_native_plan.lock().unwrap().is_none());
                }
            },
        );
    }
}

#[test]
fn atomic_plan_cancellation_in_real_withdrawal_callback_prevents_claim_or_submission_publication() {
    for finish in [false, true] {
        with_fixture_deadlines(
            2,
            Some(&[5_000, 60_000]),
            |controller, platform, requests| {
                let plan = controller.begin_approval(requests[1].clone()).unwrap();
                let attempt = if finish {
                    Some(controller.claim_approval(plan.clone()).unwrap())
                } else {
                    None
                };
                let der = attempt.as_ref().map(|attempt| {
                    let signature: Signature = SigningKey::from_slice(&[3; 32])
                        .unwrap()
                        .sign(&attempt.signing_bytes().unwrap());
                    signature.to_der().as_bytes().to_vec()
                });
                platform.at(5_000_000_000);
                *platform.cancel_plan_on_withdraw.lock().unwrap() = Some(Arc::downgrade(&plan));
                let error = if finish {
                    controller
                        .finish_approval(attempt.unwrap(), der.unwrap())
                        .unwrap_err()
                } else {
                    controller.claim_approval(plan.clone()).unwrap_err()
                };
                assert_eq!(error, BridgeError::ApprovalRejected);
                assert!(plan.is_cancelled());
                assert_eq!(platform.withdrawals.load(Ordering::SeqCst), 1);
                assert_eq!(
                    controller
                        .state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .counts()
                        .unwrap()
                        .active(),
                    1
                );
                controller.retire_approval(plan).unwrap();
            },
        );
    }
}

#[test]
fn ordinary_cleanup_continuation_preserves_failed_scope_while_other_scope_progresses() {
    with_fixture(2, |controller, platform, requests| {
        let failed = controller.reserve_denial(requests[0].clone()).unwrap();
        let other = controller.reserve_denial(requests[1].clone()).unwrap();
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::Failed;
        assert!(matches!(
            controller.advance_denial(failed.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(platform.drains.load(Ordering::SeqCst), 1);
        // Native unrelated progress is not an explicit retry of the failed scope.
        *platform.drain.lock().unwrap() = NativeApprovalDrainState::NoMatchingSession;
        assert_eq!(
            controller.continue_native_cleanup(),
            Err(BridgeError::NativeUnavailable)
        );
        assert_eq!(platform.drains.load(Ordering::SeqCst), 2);
        assert!(matches!(
            controller.settle_denial(other).unwrap(),
            NativeDenialAdvance::Released
        ));
        assert!(matches!(
            controller.advance_denial(failed.clone()).unwrap(),
            NativeDenialAdvance::CleanupFailed
        ));
        assert_eq!(
            controller.continue_native_cleanup(),
            Err(BridgeError::NativeUnavailable)
        );
        assert_eq!(platform.drains.load(Ordering::SeqCst), 2);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 0);
        assert_eq!(controller.shutdown_native_owner(), Ok(()));
        assert_eq!(platform.drains.load(Ordering::SeqCst), 3);
        assert_eq!(platform.releases.load(Ordering::SeqCst), 2);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
        assert!(matches!(
            controller.settle_denial(failed).unwrap(),
            NativeDenialAdvance::Released
        ));
    });
}

#[test]
fn notification_and_key_callback_failures_need_explicit_retry_not_continue_or_fail_closed() {
    with_fixture(1, |controller, platform, _| {
        let policy = controller.notification_policy_json().unwrap();
        platform.fail_notifications.store(true, Ordering::Release);
        platform.fail_keys.store(true, Ordering::Release);
        assert_eq!(
            controller.continue_native_cleanup(),
            Err(BridgeError::NativeUnavailable)
        );
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 1);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
        platform.fail_notifications.store(false, Ordering::Release);
        platform.fail_keys.store(false, Ordering::Release);
        assert_eq!(
            controller.continue_native_cleanup(),
            Err(BridgeError::NativeUnavailable)
        );
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 1);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
        // A new automatic error path must not turn into retry permission either.
        platform.time.lock().unwrap().boot_count = 6;
        assert_eq!(
            controller.save_notification_policy(policy),
            Err(BridgeError::InvalidObservation)
        );
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 1);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
        assert_eq!(controller.shutdown_native_owner(), Ok(()));
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 2);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 2);
        assert_eq!(controller.continue_native_cleanup(), Ok(()));
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 2);
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn keys_waiting_for_approval_cleanup_are_pending_not_a_failed_callback() {
    with_fixture(1, |controller, platform, requests| {
        let plan = controller.begin_approval(requests[0].clone()).unwrap();
        assert_eq!(
            controller.continue_native_cleanup(),
            Err(BridgeError::NativeUnavailable)
        );
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 0);
        controller.retire_approval(plan).unwrap(); // Exact closed native owner retained.
        // Its first key cleanup attempt needs no new explicit retry grant.
        assert_eq!(controller.continue_native_cleanup(), Ok(()));
        assert_eq!(platform.key_releases.load(Ordering::SeqCst), 1);
        assert_eq!(platform.notification_clears.load(Ordering::SeqCst), 1);
    });
}
