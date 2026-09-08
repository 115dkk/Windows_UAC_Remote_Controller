// SPDX-License-Identifier: GPL-2.0-or-later
//! Headless generated ABI, not an approval, enrollment or arbitrary ingress API.
//! This surface currently exposes the one durable policy owner. Native lifecycle
//! wiring and peer/notification/authentication operations remain separate gates.
#![forbid(unsafe_code)]

mod bootstrap;

use android_controller::{DurableFault, DurableInbox};
use notification_policy::{CapacityLimits, LocalTime, MonotonicTime, Weekday};
use phone_request_core::{ClockReading, InboxClock, PhoneBootId};
use phone_state_store::NativePrivateDirectory;
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

uniffi::setup_scaffolding!();

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error, uniffi::Error)]
pub enum BridgeError {
    #[error("the complete native lifecycle dispatcher is required")]
    LifecycleIntegrationRequired,
    #[error("the native domain owner is faulted")]
    OwnerFaulted,
    #[error("native observation is unavailable")]
    NativeUnavailable,
    #[error("native observation is inconsistent")]
    InvalidObservation,
    #[error("the native owner is already handling another operation")]
    Busy,
    #[error("native state storage requires reconciliation")]
    StorageUnavailable,
    #[error("notification settings input is invalid")]
    InvalidPolicy,
    #[error("the native owner is closed")]
    Closed,
}
impl From<uniffi::UnexpectedUniFFICallbackError> for BridgeError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::NativeUnavailable
    }
}

/// Observations from the Application-scoped OS adapter, never renderer input.
#[derive(Clone, Copy, uniffi::Record)]
pub struct NativeClock {
    pub boot_count: u32,
    pub monotonic_nanos: u64,
    pub weekday: u8,
    pub minute: u16,
}
impl fmt::Debug for NativeClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeClock(native_observation)")
    }
}

#[uniffi::export(foreign)]
pub trait NativePlatform: Send + Sync {
    /// Fixed canonical getNoBackupFilesDir()/controller-state, never caller data.
    fn state_directory(&self) -> Result<String, BridgeError>;
    fn clock(&self) -> Result<NativeClock, BridgeError>;
    /// Read only the former fixed Tauri policy document, never a renderer path.
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError>;
    /// Existing controller aliases prevent fresh state; unavailable is an error.
    fn has_device_keys(&self) -> Result<bool, BridgeError>;
    /// Must clear only this app's request notifications and caller-held views.
    /// No Activity, permission prompt or authentication may be opened here.
    fn clear_request_notifications(&self) -> Result<(), BridgeError>;
}

struct Admission<'a>(&'a AtomicBool);
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

static OWNER_PRESENT: AtomicBool = AtomicBool::new(false);
struct OwnerLease;
impl OwnerLease {
    fn acquire() -> Result<Self, BridgeError> {
        OWNER_PRESENT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| BridgeError::Busy)
    }
}
impl Drop for OwnerLease {
    fn drop(&mut self) {
        OWNER_PRESENT.store(false, Ordering::Release);
    }
}

/// One object belongs to the Application's bounded background owner. Never
/// instantiate a second owner from a Service, receiver or Tauri Activity.
#[derive(uniffi::Object)]
pub struct MobileController {
    platform: Arc<dyn NativePlatform>,
    boot: PhoneBootId,
    state: Mutex<Option<DurableInbox>>,
    active: AtomicBool,
    cleanup_pending: AtomicBool,
    // Hold through close/cleanup and until the generated object is destroyed.
    _owner_lease: OwnerLease,
}
impl fmt::Debug for MobileController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobileController([redacted])")
    }
}

#[uniffi::export]
pub fn bridge_version() -> u32 {
    2
}

#[uniffi::export]
impl MobileController {
    #[uniffi::constructor]
    pub fn open_existing(platform: Arc<dyn NativePlatform>) -> Result<Arc<Self>, BridgeError> {
        Self::open(platform, OpenMode::Existing)
    }

    /// Application startup only: adopt existing state, or explicitly initialize
    /// one empty, unenrolled installation. Never recover by creating on error.
    #[uniffi::constructor]
    pub fn open_or_initialize(platform: Arc<dyn NativePlatform>) -> Result<Arc<Self>, BridgeError> {
        Self::open(platform, OpenMode::Application)
    }

    /// Settings only. No request bodies, keys, signing or authorization flags.
    pub fn notification_policy_json(&self) -> Result<String, BridgeError> {
        let _admission = self.enter()?;
        self.read_policy_while_admitted()
    }

    pub fn save_notification_policy(&self, policy_json: String) -> Result<String, BridgeError> {
        if policy_json.len() > 16 * 1024 {
            return Err(BridgeError::InvalidPolicy);
        }
        let policy = controller_runtime::decode_notification_policy_json(policy_json.as_bytes())
            .map_err(|_| BridgeError::InvalidPolicy)?;
        let _admission = self.enter()?;
        let clock = self.read_clock()?;
        let result = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    drop(error.into_inner());
                    return self.fail_closed(BridgeError::Closed);
                }
            };
            let owner = state.as_mut().ok_or(BridgeError::Closed)?;
            owner.update_policy(policy, clock).map(|committed| {
                // This first surface has no native effect dispatcher. Do not
                // silently throw away request effects if preexisting active
                // state is ever encountered; close and require reconciliation.
                committed.update().effects().is_empty() && committed.update().fault().is_none()
            })
        };
        match result {
            Ok(true) => self.read_policy_while_admitted(),
            Ok(false) | Err(_) => self.fail_closed(BridgeError::StorageUnavailable),
        }
    }

    /// Downward-only close; no key deletion, file recovery or service activation.
    pub fn shutdown_native_owner(&self) -> Result<(), BridgeError> {
        let _admission = self.enter()?;
        self.drop_owner();
        self.finish_cleanup()
    }
}

#[derive(Clone, Copy)]
enum OpenMode {
    Existing,
    Application,
}

impl MobileController {
    fn open(platform: Arc<dyn NativePlatform>, mode: OpenMode) -> Result<Arc<Self>, BridgeError> {
        let owner_lease = OwnerLease::acquire()?;
        let result = (|| {
            let path = platform.state_directory()?;
            if path.is_empty() || path.len() > 4096 {
                return Err(BridgeError::InvalidObservation);
            }
            let directory = NativePrivateDirectory::from_native_app_data(&path)
                .map_err(|_| BridgeError::StorageUnavailable)?;
            let (boot, clock) = map_clock(platform.clock()?)?;
            let initial = match mode {
                OpenMode::Application => {
                    bootstrap::prepare(std::path::Path::new(&path), &*platform)?
                }
                OpenMode::Existing => bootstrap::InitialState::Existing,
            };
            // This is a native constructor, never Windows's weaker host model.
            let (owner, update) = if let bootstrap::InitialState::Fresh(policy) = initial {
                DurableInbox::create_fresh(
                    directory,
                    policy,
                    CapacityLimits::default(),
                    boot,
                    clock,
                )
            } else {
                DurableInbox::open_existing_policy_only(directory, boot, clock)
            }
            .map_err(|error| {
                if error.cause() == DurableFault::LifecycleIntegrationRequired {
                    BridgeError::LifecycleIntegrationRequired
                } else {
                    BridgeError::StorageUnavailable
                }
            })?;
            if owner
                .inbox_fault()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .is_some()
            {
                return Err(BridgeError::OwnerFaulted);
            }
            if !update.update().effects().is_empty()
                || owner
                    .counts()
                    .map_err(|_| BridgeError::StorageUnavailable)?
                    .recovering()
                    != 0
            {
                return Err(BridgeError::StorageUnavailable);
            }
            if matches!(mode, OpenMode::Application) {
                // Only after taking the real store lock and accepting policy-
                // only state. Rejected/competing constructors must not clear an
                // existing owner's notifications.
                platform.clear_request_notifications()?;
            }
            Ok((boot, owner))
        })();
        match result {
            Ok((boot, owner)) => Ok(Arc::new(Self {
                platform,
                boot,
                state: Mutex::new(Some(owner)),
                active: AtomicBool::new(false),
                cleanup_pending: AtomicBool::new(false),
                _owner_lease: owner_lease,
            })),
            // A rejected constructor is not the notification owner. In
            // particular Busy/preflight failures must not clear another owner.
            Err(error) => Err(error),
        }
    }
    fn enter(&self) -> Result<Admission<'_>, BridgeError> {
        self.active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Admission(&self.active))
            .map_err(|_| BridgeError::Busy)
    }
    fn read_policy_while_admitted(&self) -> Result<String, BridgeError> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                return self.fail_closed(BridgeError::Closed);
            }
        };
        let owner = state.as_ref().ok_or(BridgeError::Closed)?;
        serde_json::to_string(
            owner
                .policy()
                .map_err(|_| BridgeError::StorageUnavailable)?,
        )
        .map_err(|_| BridgeError::StorageUnavailable)
    }
    fn read_clock(&self) -> Result<InboxClock, BridgeError> {
        // Foreign callbacks occur outside the state mutex; re-entry is Busy.
        match self.platform.clock().and_then(map_clock) {
            Ok((boot, clock)) if boot == self.boot => Ok(clock),
            Ok(_) => self.fail_closed(BridgeError::InvalidObservation),
            Err(error) => self.fail_closed(error),
        }
    }
    fn drop_owner(&self) -> bool {
        let owner = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.take()
        };
        let had_owner = owner.is_some();
        if had_owner {
            self.cleanup_pending.store(true, Ordering::Release);
        }
        drop(owner);
        had_owner
    }
    fn finish_cleanup(&self) -> Result<(), BridgeError> {
        if self.cleanup_pending.load(Ordering::Acquire) {
            self.platform
                .clear_request_notifications()
                .map_err(|_| BridgeError::NativeUnavailable)?;
            self.cleanup_pending.store(false, Ordering::Release);
        }
        Ok(())
    }
    fn fail_closed<T>(&self, error: BridgeError) -> Result<T, BridgeError> {
        self.drop_owner();
        let _ = self.finish_cleanup();
        Err(error)
    }
}

fn map_clock(observed: NativeClock) -> Result<(PhoneBootId, InboxClock), BridgeError> {
    const DAYS: [Weekday; 7] = [
        Weekday::Monday,
        Weekday::Tuesday,
        Weekday::Wednesday,
        Weekday::Thursday,
        Weekday::Friday,
        Weekday::Saturday,
        Weekday::Sunday,
    ];
    if observed.monotonic_nanos > i64::MAX as u64 {
        return Err(BridgeError::InvalidObservation);
    }
    let day = *DAYS
        .get(usize::from(observed.weekday))
        .ok_or(BridgeError::InvalidObservation)?;
    let local =
        LocalTime::new(day, observed.minute).map_err(|_| BridgeError::InvalidObservation)?;
    let boot = PhoneBootId::from_native_boot_count(observed.boot_count)
        .map_err(|_| BridgeError::InvalidObservation)?;
    let clock = InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(observed.monotonic_nanos / 1_000_000),
            local,
        ),
        observed.monotonic_nanos,
    )
    .map_err(|_| BridgeError::InvalidObservation)?;
    Ok((boot, clock))
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use notification_policy::NotificationPolicy;
    use std::sync::{Weak, atomic::AtomicUsize};
    static SERIAL: Mutex<()> = Mutex::new(());
    struct TestPlatform {
        path: String,
        clock: Mutex<NativeClock>,
        cleared: AtomicUsize,
        clear_fails: AtomicBool,
        reenter: Mutex<Option<Weak<MobileController>>>,
        saw_busy: AtomicBool,
    }
    impl NativePlatform for TestPlatform {
        fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
            Ok(None)
        }
        fn has_device_keys(&self) -> Result<bool, BridgeError> {
            Ok(false)
        }
        fn state_directory(&self) -> Result<String, BridgeError> {
            Ok(self.path.clone())
        }
        fn clock(&self) -> Result<NativeClock, BridgeError> {
            let reenter = self.reenter.lock().unwrap().clone();
            if let Some(controller) = reenter.and_then(|weak| weak.upgrade()) {
                self.saw_busy.store(
                    controller.notification_policy_json() == Err(BridgeError::Busy),
                    Ordering::Release,
                );
            }
            Ok(*self.clock.lock().unwrap())
        }
        fn clear_request_notifications(&self) -> Result<(), BridgeError> {
            self.cleared.fetch_add(1, Ordering::Relaxed);
            if self.clear_fails.load(Ordering::Acquire) {
                Err(BridgeError::NativeUnavailable)
            } else {
                Ok(())
            }
        }
    }
    fn with_model(test: impl FnOnce(&Arc<MobileController>, &Arc<TestPlatform>)) {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let directory = tempfile::tempdir().unwrap();
        let clock = NativeClock {
            boot_count: 1,
            monotonic_nanos: 100_000_000,
            weekday: 0,
            minute: 600,
        };
        let platform = Arc::new(TestPlatform {
            path: directory.path().to_str().unwrap().into(),
            clock: Mutex::new(clock),
            cleared: AtomicUsize::new(0),
            clear_fails: AtomicBool::new(false),
            reenter: Mutex::new(None),
            saw_busy: AtomicBool::new(false),
        });
        let (boot, clock) = map_clock(clock).unwrap();
        let (owner, _) = DurableInbox::create_fresh_host_model(
            NativePrivateDirectory::from_native_app_data(directory.path()).unwrap(),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
            clock,
        )
        .unwrap();
        let controller = Arc::new(MobileController {
            platform: platform.clone(),
            boot,
            state: Mutex::new(Some(owner)),
            active: AtomicBool::new(false),
            cleanup_pending: AtomicBool::new(false),
            _owner_lease: OwnerLease::acquire().unwrap(),
        });
        test(&controller, &platform);
    }

    #[test]
    fn failed_cleanup_is_retried_even_after_the_state_owner_is_gone() {
        with_model(|controller, platform| {
            platform.clear_fails.store(true, Ordering::Release);
            assert_eq!(
                controller.shutdown_native_owner(),
                Err(BridgeError::NativeUnavailable)
            );
            assert_eq!(
                controller.notification_policy_json(),
                Err(BridgeError::Closed)
            );
            assert_eq!(
                controller.shutdown_native_owner(),
                Err(BridgeError::NativeUnavailable)
            );
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 2);
            platform.clear_fails.store(false, Ordering::Release);
            controller.shutdown_native_owner().unwrap();
            controller.shutdown_native_owner().unwrap();
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 3);
        });
    }

    #[test]
    fn domain_failure_keeps_the_downward_cleanup_obligation() {
        with_model(|controller, platform| {
            platform.clear_fails.store(true, Ordering::Release);
            platform.clock.lock().unwrap().monotonic_nanos = 99_000_000;
            assert!(
                controller
                    .save_notification_policy(
                        serde_json::to_string(&NotificationPolicy::default()).unwrap()
                    )
                    .is_err()
            );
            platform.clear_fails.store(false, Ordering::Release);
            controller.shutdown_native_owner().unwrap();
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn a_domain_clock_fault_is_never_reported_as_saved_settings() {
        with_model(|controller, platform| {
            platform.clock.lock().unwrap().monotonic_nanos = 99_000_000;
            let policy = serde_json::to_string(&NotificationPolicy::default()).unwrap();
            assert!(controller.save_notification_policy(policy).is_err());
            assert_eq!(
                controller.notification_policy_json(),
                Err(BridgeError::Closed)
            );
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 1);
        });
    }
    #[test]
    fn poison_cleanup_releases_the_writer_instead_of_returning_false_success() {
        with_model(|controller, platform| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = controller.state.lock().unwrap();
                panic!("synthetic mutex poison");
            }));
            controller.shutdown_native_owner().unwrap();
            let opened = phone_state_store::SnapshotStore::open_existing(
                NativePrivateDirectory::from_native_app_data(&platform.path).unwrap(),
            );
            assert!(opened.is_ok());
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 1);
            controller.shutdown_native_owner().unwrap();
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 1);
        });
    }
    #[test]
    fn a_rejected_second_constructor_never_clears_the_existing_owners_notifications() {
        with_model(|controller, platform| {
            assert_eq!(
                MobileController::open_existing(platform.clone()).unwrap_err(),
                BridgeError::Busy
            );
            assert!(controller.notification_policy_json().is_ok());
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 0);
        });
    }
    #[test]
    fn callbacks_can_reenter_only_as_busy_without_holding_the_state_mutex() {
        with_model(|controller, platform| {
            *platform.reenter.lock().unwrap() = Some(Arc::downgrade(controller));
            let policy = NotificationPolicy::new(None, notification_policy::AlertMode::Silent);
            let json = serde_json::to_string(&policy).unwrap();
            assert_eq!(
                controller.save_notification_policy(json.clone()).unwrap(),
                json
            );
            assert!(platform.saw_busy.load(Ordering::Acquire));
        });
    }
    #[test]
    fn native_clock_mapping_is_bounded_and_never_defaults_invalid_observations() {
        let good = NativeClock {
            boot_count: 0,
            monotonic_nanos: 1_234_567,
            weekday: 0,
            minute: 600,
        };
        let (boot, clock) = map_clock(good).unwrap();
        assert_eq!(boot.as_native_boot_count(), 0);
        assert_eq!(clock.reading().monotonic.as_millis(), 1);
        for bad in [
            NativeClock {
                boot_count: u32::MAX,
                ..good
            },
            NativeClock {
                monotonic_nanos: u64::MAX,
                ..good
            },
            NativeClock { weekday: 7, ..good },
            NativeClock {
                minute: 1440,
                ..good
            },
        ] {
            assert_eq!(map_clock(bad).unwrap_err(), BridgeError::InvalidObservation);
        }
    }
}
