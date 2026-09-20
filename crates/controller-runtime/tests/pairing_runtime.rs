// SPDX-License-Identifier: GPL-2.0-or-later
//! Portable pairing presentation tests. No native pipe or Windows API is used.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use controller_runtime::{
    AppPrivateDirectory, AppRuntime, ControlHint, ObservedServiceState, PairingAttemptHandle,
    PairingFailure, PairingStarter, PairingUiPhase, PairingUiState, Platform, PlatformAdapter,
    PlatformError, ServiceAction, ServiceCommandOutcome, ServiceObservation, ServiceState,
};

#[derive(Clone, Debug)]
struct FakePlatform(ServiceObservation);

impl PlatformAdapter for FakePlatform {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        Ok(self.0)
    }

    fn control_service(
        &self,
        _action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError> {
        Err(PlatformError::ControlFailed)
    }
}

#[derive(Debug)]
struct FakeAttempt(Arc<Mutex<PairingUiState>>);

impl PairingAttemptHandle for FakeAttempt {
    fn state(&self) -> PairingUiState {
        *self.0.lock().expect("fake pairing state")
    }

    fn cancel(&mut self) {}

    fn join_until(&mut self, _deadline: Instant) -> bool {
        true
    }
}

#[derive(Clone, Debug)]
struct FakeStarter {
    available: bool,
    state: Arc<Mutex<PairingUiState>>,
    starts: Arc<AtomicUsize>,
}

impl FakeStarter {
    fn new(available: bool, state: PairingUiState) -> Self {
        Self {
            available,
            state: Arc::new(Mutex::new(state)),
            starts: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl PairingStarter for FakeStarter {
    fn available(&self) -> bool {
        self.available
    }

    fn start(&self) -> Result<Box<dyn PairingAttemptHandle>, PairingFailure> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(FakeAttempt(Arc::clone(&self.state))))
    }
}

fn observation(state: ServiceState, control: ControlHint) -> ServiceObservation {
    ServiceObservation {
        state: ObservedServiceState::Installed(state),
        control: Ok(control),
    }
}

fn runtime(
    directory: &tempfile::TempDir,
    service: ServiceObservation,
    starter: FakeStarter,
) -> AppRuntime {
    AppRuntime::open_with_pairing(
        AppPrivateDirectory::from_native_app_data(directory.path()).expect("fixture directory"),
        Platform::Windows,
        Some("테스트-PC"),
        Box::new(FakePlatform(service)),
        Box::new(starter),
    )
    .expect("fixture runtime")
}

#[test]
fn phase_is_projected_and_only_one_active_attempt_starts() {
    let directory = tempfile::tempdir().unwrap();
    let state = PairingUiState::running(PairingUiPhase::HelperRunning, Instant::now());
    let starter = FakeStarter::new(true, state);
    let starts = Arc::clone(&starter.starts);
    let mut runtime = runtime(
        &directory,
        observation(ServiceState::Running, ControlHint::Available),
        starter,
    );
    let started = runtime.begin_pairing().unwrap();
    assert_eq!(started.pairing.unwrap().phase, "helper_running");
    assert!(!started.can_pair);
    assert_eq!(
        runtime.begin_pairing().unwrap_err().code,
        "pairing_in_progress"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

#[test]
fn fresh_running_service_and_helper_availability_are_both_required() {
    for (state, control, available) in [
        (ServiceState::Stopped, ControlHint::Available, true),
        (ServiceState::Running, ControlHint::NeedsInstaller, true),
        (ServiceState::Running, ControlHint::Available, false),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let starter = FakeStarter::new(available, PairingUiState::connecting(Instant::now()));
        let starts = Arc::clone(&starter.starts);
        let mut runtime = runtime(&directory, observation(state, control), starter);
        assert!(!runtime.snapshot().can_pair);
        let issue = runtime.begin_pairing().unwrap_err();
        assert_eq!(issue.code, "service_not_ready");
        assert_eq!(issue.message, "먼저 PC에서 휴대폰 승인을 켜 주세요.");
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn terminal_state_is_retained_replaced_and_expires_after_sixty_seconds() {
    let directory = tempfile::tempdir().unwrap();
    let started_at = Instant::now();
    let terminal =
        PairingUiState::failure(PairingFailure::UserCancelled, started_at, Instant::now());
    let starter = FakeStarter::new(true, terminal);
    let mut runtime = runtime(
        &directory,
        observation(ServiceState::Running, ControlHint::Available),
        starter.clone(),
    );
    assert_eq!(
        runtime.begin_pairing().unwrap().pairing.unwrap().failure,
        Some("user_cancelled")
    );
    assert_eq!(
        runtime.begin_pairing().unwrap().pairing.unwrap().failure,
        Some("user_cancelled")
    );
    assert_eq!(starter.starts.load(Ordering::SeqCst), 2);
    let expired_at = Instant::now()
        .checked_sub(Duration::from_secs(61))
        .expect("fixture instant");
    *starter.state.lock().unwrap() =
        PairingUiState::failure(PairingFailure::Timeout, started_at, expired_at);
    let expired = runtime.snapshot();
    assert!(expired.pairing.is_none());
    assert!(expired.can_pair);
}

#[test]
fn schema_four_serializes_pairing_and_android_keeps_it_absent() {
    let directory = tempfile::tempdir().unwrap();
    let starter = FakeStarter::new(true, PairingUiState::connecting(Instant::now()));
    let mut runtime = runtime(
        &directory,
        observation(ServiceState::Running, ControlHint::Available),
        starter,
    );
    let value = serde_json::to_value(runtime.begin_pairing().unwrap()).unwrap();
    assert_eq!(value["schemaVersion"], 4);
    assert_eq!(value["pairing"]["phase"], "connecting");
    assert!(value["pairing"]["failure"].is_null());
    let android = controller_runtime::AppSnapshot::from_android_policy(
        controller_runtime::NotificationPolicy::default(),
        controller_runtime::MobileReadiness::UNAVAILABLE,
    );
    assert_eq!(android.schema_version, 4);
    assert!(android.pairing.is_none());
    assert!(!android.can_pair);
}
