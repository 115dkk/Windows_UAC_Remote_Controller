// SPDX-License-Identifier: GPL-2.0-or-later
//! Test-only synthetic native-owner adapters. Not Windows/Android end-to-end QA.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use controller_runtime::{
    AppPrivateDirectory, AppRuntime, Availability, ControlHint, DecisionIntent, MobileReadiness,
    NotificationPermission, ObservedServiceState, Platform, PlatformAdapter, PlatformError,
    ScreenLockState, ServiceAction, ServiceCommandOutcome, ServiceObservation, ServiceState,
    UnavailablePlatformAdapter,
};
use serde_json::json;

#[derive(Debug)]
struct SyntheticOwnerState {
    observation: Mutex<Result<ServiceObservation, PlatformError>>,
    outcome: Mutex<Result<ServiceCommandOutcome, PlatformError>>,
    reads: AtomicUsize,
    controls: AtomicUsize,
}

#[derive(Clone, Debug)]
struct SyntheticOwner(Arc<SyntheticOwnerState>);

impl SyntheticOwner {
    fn new(observation: Result<ServiceObservation, PlatformError>) -> Self {
        Self(Arc::new(SyntheticOwnerState {
            observation: Mutex::new(observation),
            // A test must explicitly select an outcome before requesting any
            // mutation. Even the synthetic default is not fabricated success.
            outcome: Mutex::new(Err(PlatformError::ControlFailed)),
            reads: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
        }))
    }

    fn set_observation(&self, observation: Result<ServiceObservation, PlatformError>) {
        *self
            .0
            .observation
            .lock()
            .expect("synthetic observation lock") = observation;
    }

    fn set_outcome(&self, outcome: Result<ServiceCommandOutcome, PlatformError>) {
        *self.0.outcome.lock().expect("synthetic outcome lock") = outcome;
    }
}

impl PlatformAdapter for SyntheticOwner {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        *self
            .0
            .observation
            .lock()
            .expect("synthetic observation lock")
    }

    fn control_service(
        &self,
        _action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError> {
        self.0.controls.fetch_add(1, Ordering::SeqCst);
        *self.0.outcome.lock().expect("synthetic outcome lock")
    }
}

fn absent(control: ControlHint) -> ServiceObservation {
    ServiceObservation {
        state: ObservedServiceState::NotInstalled,
        control: Ok(control),
    }
}

fn installed(state: ServiceState) -> ServiceObservation {
    ServiceObservation {
        state: ObservedServiceState::Installed(state),
        control: Ok(ControlHint::Available),
    }
}

fn windows_runtime(directory: &tempfile::TempDir, owner: SyntheticOwner) -> AppRuntime {
    AppRuntime::open(
        AppPrivateDirectory::from_native_app_data(directory.path())
            .expect("trusted synthetic directory"),
        Platform::Windows,
        Some("합성-PC"),
        Box::new(owner),
    )
    .expect("synthetic runtime")
}

#[test]
fn construction_and_snapshot_never_mutate_the_native_owner() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(absent(ControlHint::Available)));
    let mut runtime = windows_runtime(&directory, owner.clone());
    assert_eq!(owner.0.reads.load(Ordering::SeqCst), 0);
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
    for _ in 0..3 {
        assert!(
            !runtime
                .snapshot()
                .service
                .expect("observed absence")
                .installed
        );
    }
    assert_eq!(owner.0.reads.load(Ordering::SeqCst), 3);
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
}

#[test]
fn real_absence_and_first_status_read_failure_are_not_interchangeable() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Err(PlatformError::StatusUnavailable));
    let mut runtime = windows_runtime(&directory, owner.clone());
    let failed = runtime.snapshot();
    assert!(failed.service.is_none());
    assert_eq!(
        failed.issue.expect("read issue").code,
        "service_status_unavailable"
    );
    owner.set_observation(Ok(absent(ControlHint::NeedsInstaller)));
    let absent = runtime.snapshot();
    let service = absent.service.expect("actual absence observation");
    assert!(!service.installed);
    assert_eq!(service.state, None);
    assert_eq!(service.control_hint, ControlHint::NeedsInstaller);
    assert!(service.allowed_actions.is_empty());
    assert!(absent.issue.is_none());
}

#[test]
fn running_never_proves_remote_request_readiness_or_owner_availability() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Running)));
    let mut runtime = windows_runtime(&directory, owner);
    let snapshot = runtime.snapshot();
    assert_eq!(
        snapshot.service.as_ref().expect("service").state,
        Some(ServiceState::Running)
    );
    assert!(
        !snapshot
            .service
            .as_ref()
            .expect("service")
            .remote_requests_ready
    );
    assert_eq!(
        snapshot.data_availability.devices,
        Availability::Unavailable
    );
    assert_eq!(
        snapshot.data_availability.requests,
        Availability::Unavailable
    );
    assert_eq!(
        snapshot.data_availability.activity,
        Availability::Unavailable
    );
    assert!(snapshot.devices.is_empty());
    assert!(snapshot.requests.is_empty());
    assert!(snapshot.activity.is_empty());
    assert!(!snapshot.can_pair);
    assert!(!snapshot.can_unpair);
    assert!(!snapshot.can_clear_activity);
}

#[test]
fn failed_refresh_keeps_labelled_stale_state_and_disables_actions() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Running)));
    let mut runtime = windows_runtime(&directory, owner.clone());
    assert!(
        !runtime
            .snapshot()
            .service
            .expect("fresh service")
            .allowed_actions
            .is_empty()
    );
    owner.set_observation(Err(PlatformError::StatusUnavailable));
    let stale = runtime.snapshot();
    assert_eq!(
        stale.issue.expect("stale issue").code,
        "service_status_stale"
    );
    let service = stale.service.expect("previous state retained");
    assert_eq!(service.state, Some(ServiceState::Running));
    assert!(service.allowed_actions.is_empty());
    assert!(!service.remote_requests_ready);
    assert_eq!(
        runtime
            .control_service(ServiceAction::Stop)
            .expect_err("do not use stale control")
            .code,
        "service_status_stale"
    );
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
}

#[test]
fn helper_validation_failure_preserves_lifecycle_but_disables_control() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(ServiceObservation {
        state: ObservedServiceState::Installed(ServiceState::Running),
        control: Err(PlatformError::HelperUnavailable),
    }));
    let mut runtime = windows_runtime(&directory, owner.clone());
    let snapshot = runtime.snapshot();
    assert_eq!(
        snapshot.issue.expect("helper issue").code,
        "service_helper_unavailable"
    );
    let service = snapshot.service.expect("real lifecycle retained");
    assert!(service.installed);
    assert_eq!(service.state, Some(ServiceState::Running));
    assert!(service.allowed_actions.is_empty());
    assert_eq!(
        runtime
            .control_service(ServiceAction::Stop)
            .expect_err("do not launch unverified helper")
            .code,
        "service_helper_unavailable"
    );
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
}

#[test]
fn user_cancellation_returns_unchanged_observed_snapshot() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Stopped)));
    owner.set_outcome(Ok(ServiceCommandOutcome::UserCancelled));
    let mut runtime = windows_runtime(&directory, owner.clone());
    let before = runtime.snapshot();
    assert_eq!(
        runtime
            .control_service(ServiceAction::Start)
            .expect("cancellation is not completion"),
        before
    );
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_command_uses_the_owners_actual_refreshed_observation() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Stopped)));
    owner.set_outcome(Ok(ServiceCommandOutcome::Completed {
        observation: installed(ServiceState::Running),
    }));
    let mut runtime = windows_runtime(&directory, owner.clone());
    let snapshot = runtime
        .control_service(ServiceAction::Start)
        .expect("synthetic owner completion");
    let service = snapshot.service.expect("completed observation");
    assert_eq!(service.state, Some(ServiceState::Running));
    assert!(!service.remote_requests_ready);
    assert!(snapshot.issue.is_none());
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_or_unknown_completion_never_claims_success_or_allows_a_second_helper() {
    for (outcome, code) in [
        (
            ServiceCommandOutcome::StillRunning,
            "service_control_pending",
        ),
        (
            ServiceCommandOutcome::CompletionStatusUnknown,
            "service_control_completion_unknown",
        ),
    ] {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let owner = SyntheticOwner::new(Ok(installed(ServiceState::Stopped)));
        owner.set_outcome(Ok(outcome));
        let mut runtime = windows_runtime(&directory, owner.clone());
        let snapshot = runtime
            .control_service(ServiceAction::Start)
            .expect("unresolved outcome snapshot");
        assert_eq!(snapshot.issue.expect("unresolved issue").code, code);
        assert!(
            snapshot
                .service
                .expect("previous actual state")
                .allowed_actions
                .is_empty()
        );
        owner.set_observation(Ok(installed(ServiceState::Running)));
        let refreshed = runtime.snapshot();
        assert_eq!(
            refreshed.service.as_ref().expect("new actual state").state,
            Some(ServiceState::Running)
        );
        assert!(
            refreshed
                .service
                .expect("new actual state")
                .allowed_actions
                .is_empty()
        );
        assert_eq!(
            refreshed
                .issue
                .expect("SCM state does not prove helper completion")
                .code,
            code
        );
        assert_eq!(
            runtime
                .control_service(ServiceAction::Restart)
                .expect_err("second helper blocked")
                .code,
            code
        );
        assert_eq!(owner.0.controls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn helper_failure_is_a_fixed_failure_not_fabricated_service_success() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Stopped)));
    owner.set_outcome(Ok(ServiceCommandOutcome::HelperFailed));
    let mut runtime = windows_runtime(&directory, owner.clone());
    let result = runtime
        .control_service(ServiceAction::Start)
        .expect("failure snapshot");
    assert_eq!(
        result.issue.expect("fixed failure").code,
        "service_helper_failed"
    );
    let service = result.service.expect("old observed state only");
    assert_eq!(service.state, Some(ServiceState::Stopped));
    assert!(service.allowed_actions.is_empty());
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 1);
}

#[test]
fn allowed_actions_are_recomputed_and_unavailable_actions_never_launch() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(absent(ControlHint::Available)));
    let mut runtime = windows_runtime(&directory, owner.clone());
    assert_eq!(
        runtime.snapshot().service.expect("absent").allowed_actions,
        [ServiceAction::Install]
    );
    owner.set_observation(Ok(absent(ControlHint::NeedsInstaller)));
    assert_eq!(
        runtime
            .control_service(ServiceAction::Install)
            .expect_err("helper changed since UI read")
            .code,
        "service_installer_required"
    );
    for state in [
        ServiceState::StartPending,
        ServiceState::StopPending,
        ServiceState::ContinuePending,
        ServiceState::PausePending,
    ] {
        owner.set_observation(Ok(installed(state)));
        assert!(
            runtime
                .snapshot()
                .service
                .expect("pending state")
                .allowed_actions
                .is_empty()
        );
        assert_eq!(
            runtime
                .control_service(ServiceAction::Restart)
                .expect_err("do not overlap pending service")
                .code,
            "service_action_unavailable"
        );
    }
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
}

#[test]
fn android_lock_configured_missing_and_unavailable_remain_distinct() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Running)));
    let mut runtime = AppRuntime::open(
        AppPrivateDirectory::from_native_app_data(directory.path()).expect("fixture directory"),
        Platform::Android,
        Some("must-not-be-used-as-a-PC-name"),
        Box::new(owner.clone()),
    )
    .expect("android synthetic runtime");
    let initial = runtime.snapshot();
    assert_eq!(initial.mobile, Some(MobileReadiness::UNAVAILABLE));
    assert_eq!(
        initial.issue.expect("unknown is not missing").code,
        "mobile_readiness_unavailable"
    );
    assert!(initial.service.is_none());
    assert!(initial.computer_name.is_empty());
    for screen_lock in [
        ScreenLockState::Configured,
        ScreenLockState::Missing,
        ScreenLockState::Unavailable,
    ] {
        let readiness = MobileReadiness {
            screen_lock,
            notifications: NotificationPermission::Denied,
            can_open_lock_settings: true,
            can_open_notification_settings: false,
            can_open_pairing_scanner: false,
        };
        runtime
            .update_mobile_readiness_from_native(readiness)
            .expect("trusted native observation");
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mobile, Some(readiness));
        assert_eq!(
            snapshot.issue.is_some(),
            screen_lock == ScreenLockState::Unavailable
        );
        assert!(!snapshot.can_pair);
        assert!(snapshot.requests.is_empty());
    }
    assert_eq!(owner.0.reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        runtime
            .control_service(ServiceAction::Start)
            .expect_err("not a Windows command surface")
            .code,
        "service_control_unsupported"
    );
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
}

#[test]
fn unavailable_owners_return_explicit_errors_and_do_not_create_data() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::Running)));
    let mut runtime = windows_runtime(&directory, owner.clone());
    assert_eq!(
        runtime.begin_pairing().expect_err("pairing not wired").code,
        "pairing_unavailable"
    );
    assert_eq!(
        runtime
            .remove_device("synthetic-device")
            .expect_err("unpair not wired")
            .code,
        "unpair_unavailable"
    );
    for decision in [DecisionIntent::Approve, DecisionIntent::Deny] {
        assert_eq!(
            runtime
                .decide("synthetic-request", decision)
                .expect_err("decisions not wired")
                .code,
            "decisions_unavailable"
        );
    }
    assert_eq!(
        runtime
            .read_activity()
            .expect_err("read owner not wired")
            .code,
        "activity_unavailable"
    );
    assert_eq!(
        runtime
            .clear_activity()
            .expect_err("clear owner not wired")
            .code,
        "activity_unavailable"
    );
    assert_eq!(owner.0.controls.load(Ordering::SeqCst), 0);
    let snapshot = runtime.snapshot();
    assert!(
        snapshot.devices.is_empty() && snapshot.requests.is_empty() && snapshot.activity.is_empty()
    );
    assert_eq!(
        snapshot.data_availability.activity,
        Availability::Unavailable
    );
}

#[test]
fn native_mobile_readiness_input_is_rejected_on_windows() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(absent(ControlHint::NeedsInstaller)));
    let mut runtime = windows_runtime(&directory, owner);
    assert_eq!(
        runtime
            .update_mobile_readiness_from_native(MobileReadiness {
                screen_lock: ScreenLockState::Configured,
                notifications: NotificationPermission::Allowed,
                can_open_lock_settings: true,
                can_open_notification_settings: true,
                can_open_pairing_scanner: true,
            })
            .expect_err("not Android")
            .code,
        "mobile_readiness_unsupported"
    );
    assert!(runtime.snapshot().mobile.is_none());
}

#[test]
fn dto_serialization_matches_the_camel_case_snapshot_and_snake_case_policy() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let owner = SyntheticOwner::new(Ok(installed(ServiceState::StartPending)));
    let mut runtime = windows_runtime(&directory, owner);
    let json = serde_json::to_value(runtime.snapshot()).expect("snapshot JSON");
    assert_eq!(
        json,
        json!({
            "schemaVersion": 3,
            "platform": "windows",
            "computerName": "합성-PC",
            "service": {
                "installed": true, "state": "start_pending", "allowedActions": [],
                "controlHint": "available", "remoteRequestsReady": false
            },
            "phoneService": null, "mobile": null,
            "policy": {"schedule": {"mode": "always"}, "alert": "sound"},
            "devices": [], "requests": [], "activity": [],
            "requestCatalog": null, "requestReview": null,
            "dataAvailability": {"devices": "unavailable", "requests": "unavailable", "activity": "unavailable"},
            "canPair": false, "canUnpair": false, "canClearActivity": false, "issue": null
        })
    );
    let readiness = MobileReadiness {
        screen_lock: ScreenLockState::Configured,
        notifications: NotificationPermission::Allowed,
        can_open_lock_settings: true,
        can_open_notification_settings: false,
        can_open_pairing_scanner: true,
    };
    assert_eq!(
        serde_json::to_value(readiness).expect("readiness JSON"),
        json!({
            "screenLock": "configured", "notifications": "allowed", "canOpenLockSettings": true,
            "canOpenNotificationSettings": false, "canOpenPairingScanner": true
        })
    );
    assert!(
        serde_json::from_value::<MobileReadiness>(json!({
            "screenLock": "configured", "notifications": "allowed", "canOpenLockSettings": true,
            "canOpenNotificationSettings": false,
            "canOpenPairingScanner": true,
            "authenticated": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<MobileReadiness>(json!({
            "screenLock": "configured", "notifications": "denied", "canOpenLockSettings": false
        }))
        .is_err()
    );
}

#[test]
fn scanner_readiness_is_required_native_input_only_and_never_enables_pairing() {
    let record = json!({
        "screenLock": "configured", "notifications": "allowed",
        "canOpenLockSettings": false, "canOpenNotificationSettings": false,
        "canOpenPairingScanner": true
    });
    for available in [false, true] {
        let mut input = record.clone();
        input["canOpenPairingScanner"] = json!(available);
        let readiness: MobileReadiness = serde_json::from_value(input).unwrap();
        let snapshot = controller_runtime::AppSnapshot::from_android_policy(
            controller_runtime::NotificationPolicy::default(),
            readiness,
        );
        assert_eq!(snapshot.schema_version, 3);
        assert_eq!(snapshot.mobile.unwrap().can_open_pairing_scanner, available);
        assert!(!snapshot.can_pair && !snapshot.can_unpair);
        assert!(snapshot.devices.is_empty());
        assert_eq!(
            snapshot.data_availability.devices,
            controller_runtime::Availability::Unavailable
        );
    }
    let mut missing = record.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("canOpenPairingScanner");
    assert!(serde_json::from_value::<MobileReadiness>(missing).is_err());
    for invalid in [json!(null), json!("true"), json!(1), json!({})] {
        let mut input = record.clone();
        input["canOpenPairingScanner"] = invalid;
        assert!(serde_json::from_value::<MobileReadiness>(input).is_err());
    }
    let mut extra = record;
    extra["qr"] = json!("synthetic-untrusted-input");
    assert!(serde_json::from_value::<MobileReadiness>(extra).is_err());
    assert!(!MobileReadiness::UNAVAILABLE.can_open_pairing_scanner);
}

#[test]
fn display_names_are_bounded_control_free_nonidentities() {
    let invalid = [
        "a".repeat(257),
        "가".repeat(65),
        "synthetic\nPC".to_owned(),
        "synthetic\u{202e}PC".to_owned(),
        "synthetic\u{200b}PC".to_owned(),
    ];
    for name in invalid {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let mut runtime = AppRuntime::open(
            AppPrivateDirectory::from_native_app_data(directory.path()).expect("fixture directory"),
            Platform::Windows,
            Some(&name),
            Box::new(UnavailablePlatformAdapter),
        )
        .expect("synthetic runtime");
        assert!(runtime.snapshot().computer_name.is_empty());
    }
    let directory = tempfile::tempdir().expect("isolated fixture");
    let mut runtime = AppRuntime::open(
        AppPrivateDirectory::from_native_app_data(directory.path()).expect("fixture directory"),
        Platform::Unsupported,
        Some("ignored-not-a-PC"),
        Box::new(UnavailablePlatformAdapter),
    )
    .expect("unsupported runtime");
    assert!(runtime.snapshot().computer_name.is_empty());
    assert!(runtime.snapshot().service.is_none());
    assert!(runtime.snapshot().mobile.is_none());
}
