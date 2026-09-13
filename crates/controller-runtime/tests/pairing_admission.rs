// SPDX-License-Identifier: GPL-2.0-or-later
//! Controlled worker scheduling through the real runtime interface, not native
//! Windows authorization. Management must not race a not-yet-started worker.
use controller_runtime::{
    AppPrivateDirectory, AppRuntime, Availability, ControlHint, ManagementDevice,
    ManagementObservation, ObservedServiceState, PairingAttemptHandle, PairingFailure,
    PairingStarter, PairingUiState, Platform, PlatformAdapter, PlatformError, RelayMode,
    RelayState, RelayStatusView, ServiceAction, ServiceCommandOutcome, ServiceObservation,
    ServiceState,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

struct Fixture {
    state: Mutex<PairingUiState>,
    joined: AtomicBool,
    starts: AtomicUsize,
    drops: AtomicUsize,
    reads: AtomicUsize,
    mutations: AtomicUsize,
}
struct Adapter(Arc<Fixture>);
impl PlatformAdapter for Adapter {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        Ok(ServiceObservation {
            state: ObservedServiceState::Installed(ServiceState::Running),
            control: Ok(ControlHint::Available),
        })
    }
    fn observe_management(&self) -> Result<ManagementObservation, PlatformError> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ManagementObservation {
            relay_configured: true,
            relay_status: RelayStatusView {
                mode: RelayMode::Embedded,
                state: RelayState::Listening,
            },
            devices: vec![ManagementDevice {
                id: "00000000000000000000000000000001".to_owned(),
                revision: 1,
                route_present: true,
                connected: true,
            }],
        })
    }
    fn control_service(&self, _: ServiceAction) -> Result<ServiceCommandOutcome, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn set_relay(&self, _: &str) -> Result<(), PlatformError> {
        self.0.mutations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn use_embedded_relay(&self) -> Result<(), PlatformError> {
        self.set_relay("embedded")
    }
    fn remove_device(&self, _: &str) -> Result<(), PlatformError> {
        self.set_relay("remove")
    }
}
struct Starter(Arc<Fixture>);
struct Attempt(Arc<Fixture>);
impl Drop for Attempt {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl PairingAttemptHandle for Attempt {
    fn state(&self) -> PairingUiState {
        *self.0.state.lock().unwrap()
    }
    fn cancel(&mut self) {}
    fn join_until(&mut self, _: Instant) -> bool {
        self.0.joined.load(Ordering::SeqCst)
    }
}
impl PairingStarter for Starter {
    fn available(&self) -> bool {
        true
    }
    fn start(&self) -> Result<Box<dyn PairingAttemptHandle>, PairingFailure> {
        self.0.starts.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Attempt(Arc::clone(&self.0))))
    }
}

#[test]
fn refresh_and_mutations_wait_for_the_original_worker_even_after_terminal_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = Arc::new(Fixture {
        state: Mutex::new(PairingUiState::connecting(Instant::now())),
        joined: AtomicBool::new(false),
        starts: AtomicUsize::new(0),
        drops: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        mutations: AtomicUsize::new(0),
    });
    let mut runtime = AppRuntime::open_with_pairing(
        AppPrivateDirectory::from_native_app_data(directory.path()).unwrap(),
        Platform::Windows,
        None,
        Box::new(Adapter(Arc::clone(&fixture))),
        Box::new(Starter(Arc::clone(&fixture))),
    )
    .unwrap();
    let ready = runtime.snapshot();
    assert!(ready.can_pair);
    assert!(ready.can_unpair);
    assert_eq!(ready.devices.len(), 1);
    let started = runtime.begin_pairing().unwrap();
    assert!(!started.can_pair);
    assert!(!started.can_unpair);
    assert!(started.devices.is_empty());
    assert_eq!(started.data_availability.devices, Availability::Unavailable);
    assert_eq!(started.relay_status.unwrap().state, RelayState::Unknown);
    let reads = fixture.reads.load(Ordering::SeqCst);
    // The worker is deliberately not scheduled yet; the runtime command already
    // returned. An immediate snapshot used to enter the competing native reader.
    let pending = runtime.snapshot();
    assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
    assert!(!pending.can_pair);
    assert_eq!(pending.data_availability.devices, Availability::Unavailable);
    assert_eq!(pending.relay_status.unwrap().state, RelayState::Unknown);
    assert_eq!(pending.service.unwrap().state, Some(ServiceState::Running));
    assert_eq!(
        runtime.set_relay("embedded").unwrap_err().code,
        "pairing_in_progress"
    );
    assert_eq!(
        runtime
            .remove_device("00000000000000000000000000000001")
            .unwrap_err()
            .code,
        "pairing_in_progress"
    );
    assert_eq!(fixture.mutations.load(Ordering::SeqCst), 0);
    let old = Instant::now() - Duration::from_secs(61);
    *fixture.state.lock().unwrap() = PairingUiState::failure(PairingFailure::Unavailable, old, old);
    let terminal = runtime.snapshot();
    assert!(
        terminal.pairing.is_some(),
        "UI expiry must not drop an unjoined owner"
    );
    assert!(!terminal.can_pair);
    assert_eq!(
        runtime.begin_pairing().unwrap_err().code,
        "pairing_in_progress"
    );
    assert_eq!(fixture.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.drops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
    fixture.joined.store(true, Ordering::SeqCst);
    let resumed = runtime.snapshot();
    assert_eq!(fixture.reads.load(Ordering::SeqCst), reads + 1);
    assert!(resumed.can_pair);
    assert!(resumed.can_unpair);
    assert_eq!(resumed.devices.len(), 1);
    assert!(resumed.pairing.is_none());
    assert_eq!(resumed.data_availability.devices, Availability::Available);
    assert_eq!(fixture.drops.load(Ordering::SeqCst), 1);
    runtime.begin_pairing().unwrap();
    assert_eq!(fixture.starts.load(Ordering::SeqCst), 2);
}
