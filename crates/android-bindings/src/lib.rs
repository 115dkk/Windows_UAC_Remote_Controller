// SPDX-License-Identifier: GPL-2.0-or-later
//! Headless generated ABI, not an approval, enrollment or arbitrary ingress API.
//! This surface currently exposes the one durable policy owner. Native lifecycle
//! wiring and peer/notification/authentication operations remain separate gates.
#![forbid(unsafe_code)]

mod approval;
mod bootstrap;
mod denial;
#[cfg(all(test, any(windows, target_os = "linux")))]
mod denial_fixture;
#[cfg(all(test, any(windows, target_os = "linux")))]
mod denial_tests;
mod effects;
mod intake;
mod intake_delivery;
#[cfg(all(test, any(windows, target_os = "linux")))]
mod intake_tests;
mod local_keys;
mod native_clock;
mod request_projection;
mod transport;
pub use approval::{
    NativeApprovalAttempt, NativeApprovalPlan, NativeApprovalSubmission, NativeRequestSelection,
};
pub use denial::{
    NativeApprovalDrainState, NativeDenialAdvance, NativeDenialAttempt, NativeDenialOperationState,
    NativeDenialScope, NativeDenialWait,
};
pub use intake::IntakePeerId;
pub use intake_delivery::NativeDecisionProgress;
pub use local_keys::NativeLocalKeySet;
pub use native_clock::NativePresentationClock;
pub use request_projection::{
    NativePendingRequest, NativeRequestAlert, NativeRequestCatalogState,
    NativeRequestCatalogStatus, NativeRequestDetails, NativeRequestNotPosted,
    NativeRequestPresentation, NativeRequestPreview, NativeRequestSinkOutcome,
};
pub use transport::{
    NativeCertificateVerify, NativeTransportBinding, native_client_transport_identity,
};

use android_controller::{DurableFault, DurableInbox};
use notification_policy::{CapacityLimits, LocalTime, MonotonicTime, Weekday};
use phone_request_core::{ClockReading, InboxClock, PhoneBootId};
use phone_state_store::NativePrivateDirectory;
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    #[error("native history timestamp is unavailable")]
    HistoryTimeUnavailable,
    #[error("local key state requires explicit reconciliation")]
    LocalKeysReconciliationRequired,
    #[error("native local key references could not be reopened")]
    LocalKeysUnavailable,
    #[error("the approval attempt is no longer eligible")]
    ApprovalRejected,
    #[error("the denial attempt is no longer eligible")]
    DenialRejected,
    #[error("the current request projection is unavailable")]
    RequestUnavailable,
    #[error("native presentation time is awaiting a known-owner refresh")]
    PresentationRefreshRequired,
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
    /// Lightweight real temporal bookends. No storage/key/UI work or synchronous
    /// owner reentry. Each returned local field uses the same wall-after sample.
    fn presentation_clock(&self) -> Result<NativePresentationClock, BridgeError>;
    /// One owned bounded delta, not delivery/authentication evidence. Restore
    /// and Update must not re-alert. Native failures retain exact cleanup.
    fn publish_pending_request(
        &self,
        request: Arc<NativePendingRequest>,
        intent: NativeRequestPresentation,
        alert: NativeRequestAlert,
    ) -> Result<NativeRequestSinkOutcome, BridgeError>;
    /// Coalesced native-worker progress wake only; never synchronously call or
    /// wait for this controller from the callback.
    fn intake_progress(&self) -> Result<(), BridgeError>;
    /// Scope-bound actual session cancellation/progress. Never wait for or
    /// synchronously reenter the actor/controller; queue native cleanup instead.
    fn advance_approval_drain_for_denial(
        &self,
        scope: Arc<NativeDenialScope>,
    ) -> Result<NativeApprovalDrainState, BridgeError>;
    /// Observe the exact registered operation; no caller-supplied quiescent flag.
    fn observe_denial_operation(
        &self,
        attempt: Arc<NativeDenialAttempt>,
    ) -> Result<NativeDenialOperationState, BridgeError>;
    /// Scope-owned memory/generated-reference cleanup, never persistent keys.
    fn release_denial_scope(&self, scope: Arc<NativeDenialScope>) -> Result<(), BridgeError>;
    /// Same native key owner, original exact TRANSPORT reference. No key creation.
    fn prepare_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError>;
    /// Actual Client TLS input only. Never bounce synchronously to the calling
    /// actor/worker or wait for a human. Return bounded canonical DER.
    fn sign_client_certificate_verify(
        &self,
        input: Arc<NativeCertificateVerify>,
    ) -> Result<Vec<u8>, BridgeError>;
    /// One callback after Rust closes binding; failed cleanup remains owned by
    /// this same native platform until its explicit/global reference cleanup.
    fn release_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError>;
    /// Fixed canonical getNoBackupFilesDir()/controller-state, never caller data.
    fn state_directory(&self) -> Result<String, BridgeError>;
    fn clock(&self) -> Result<NativeClock, BridgeError>;
    /// Actual phone wall time for history only, never authorization or expiry.
    fn unix_millis(&self) -> Result<u64, BridgeError>;
    /// Read only the former fixed Tauri policy document, never a renderer path.
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError>;
    /// Existing controller aliases prevent fresh state; unavailable is an error.
    fn has_device_keys(&self) -> Result<bool, BridgeError>;
    /// Reopen exact recorded aliases only; verify the complete owned namespace,
    /// KeyInfo policy and all three SPKIs. No generation, signing or auth prompt.
    /// Each NativePlatform instance owns its references; it must keep a cleanup
    /// obligation before partial publication and through any callback failure.
    fn reopen_local_key_sets(&self, keys: Vec<NativeLocalKeySet>) -> Result<(), BridgeError>;
    /// Memory-only, owner-scoped and idempotent. Never delete persisted aliases,
    /// change metadata, clear another instance or retry generation. The native
    /// Application retains this adapter to retry cleanup after constructor error.
    fn release_local_key_references(&self) -> Result<(), BridgeError>;
    /// Must clear only this app's request notifications and caller-held views.
    /// No Activity, permission prompt or authentication may be opened here.
    fn clear_request_notifications(&self) -> Result<(), BridgeError>;
    /// Downward-only exact committed withdrawals, including native held views.
    fn withdraw_requests(&self, requests: Vec<NativeRequestSelection>) -> Result<(), BridgeError>;
}

struct Admission<'a>(&'a MobileController);
impl Drop for Admission<'_> {
    fn drop(&mut self) {
        // No foreign callbacks while unwinding. Retain closed retirement owners
        // and native cleanup obligations rather than reopening admission live.
        if std::thread::panicking() {
            self.0.drop_owner();
        }
        self.0.active.store(false, Ordering::Release);
        self.0.intake.admission_released();
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
    approval_owner: Mutex<Option<android_controller::ApprovalPlanOwner>>,
    approval_native_plan: Mutex<Option<Arc<NativeApprovalPlan>>>,
    denial_state: Mutex<denial::DenialState>,
    projections: Mutex<request_projection::ProjectionRegistry>,
    intake: Arc<intake::IntakeOwner>,
    approval_alive: Arc<AtomicBool>,
    active: AtomicBool,
    cleanup_pending: AtomicBool,
    notification_cleanup_failed: AtomicBool,
    key_cleanup_pending: AtomicBool,
    key_cleanup_failed: AtomicBool,
    native_floor_nanos: AtomicU64,
    // Hold through close/cleanup and until the generated object is destroyed.
    _owner_lease: Arc<OwnerLease>,
}
impl fmt::Debug for MobileController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MobileController([redacted])")
    }
}
impl Drop for MobileController {
    fn drop(&mut self) {
        // Last-resort downward invalidation only. Native actor must retain this
        // object until explicit cleanup succeeds; Drop claims no quiescence.
        self.approval_alive.store(false, Ordering::Release);
        self.intake.stop();
        let _ = self
            .projections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .revoke_all();
        self.close_denial_state();
    }
}

#[uniffi::export]
pub fn bridge_version() -> u32 {
    8
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
        let changed = self.with_inbox(|owner| {
            Ok(owner
                .policy()
                .map_err(|_| BridgeError::StorageUnavailable)?
                != &policy)
        })?;
        let refresh = if changed {
            let mut projections = self.projections.lock().map_err(|_| BridgeError::Closed)?;
            let keys = projections.keys();
            projections.revoke_all()?;
            for key in &keys {
                projections.defer_refresh(*key, clock.phone_monotonic_nanos())?;
            }
            keys
        } else {
            Vec::new()
        };
        let result = self.with_inbox(|owner| {
            owner
                .update_policy(policy, clock)
                .map_err(|_| BridgeError::StorageUnavailable)
        })?;
        self.dispatch_effects(
            result.update().effects().to_vec(),
            result.update().fault().is_some(),
        )?;
        if !refresh.is_empty() {
            self.maintain_requests_admitted()?;
        }
        self.signal_intake_maintenance();
        self.read_policy_while_admitted()
    }

    /// Fixed native history read; no path, peer body, key or result supplied by UI.
    pub fn history_json(&self) -> Result<String, BridgeError> {
        let _admission = self.enter()?;
        self.maintain_history_while_admitted()?;
        self.read_history_while_admitted()
    }

    /// Reconcile already committed pending outcomes, then clear visible history.
    /// Both phases retain source/replay state. If the clear fails, no cleared
    /// result is returned; the native owner stops rather than claiming rollback.
    pub fn clear_history_json(&self) -> Result<String, BridgeError> {
        let _admission = self.enter()?;
        self.maintain_history_while_admitted()?;
        let result = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    drop(error.into_inner());
                    return self.fail_closed(BridgeError::Closed);
                }
            };
            state.as_mut().ok_or(BridgeError::Closed)?.clear_history()
        };
        if result.is_err() {
            return self.fail_closed(BridgeError::StorageUnavailable);
        }
        self.read_history_while_admitted()
    }

    /// Downward-only close; no key deletion, file recovery or service activation.
    pub fn shutdown_native_owner(&self) -> Result<(), BridgeError> {
        let _admission = self.enter()?;
        self.drop_owner();
        self.grant_denial_shutdown_retry();
        self.notification_cleanup_failed
            .store(false, Ordering::Release);
        self.key_cleanup_failed.store(false, Ordering::Release);
        self.finish_cleanup()
    }

    /// Ordinary native progress/automatic shutdown continuation, NOT a retry
    /// grant. Previously failed callbacks remain latched until explicit stop.
    pub fn continue_native_cleanup(&self) -> Result<(), BridgeError> {
        let _admission = self.enter()?;
        self.drop_owner();
        self.finish_cleanup()
    }
    /// Atomic downward stop can be requested while a previous command/provider
    /// is in progress. Actual cleanup remains on the admitted continuation path.
    pub fn stop_intake(&self) {
        self.approval_alive.store(false, Ordering::Release);
        self.intake.stop();
        let _ = self
            .projections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .revoke_all();
    }
}

#[derive(Clone, Copy)]
enum OpenMode {
    Existing,
    Application,
}

impl MobileController {
    fn maintain_history_while_admitted(&self) -> Result<(), BridgeError> {
        // Callback/shape rejection is BEFORE any storage intent or ACK. A valid
        // backwards wall-clock observation is acceptable; monotonic request time
        // remains governed by read_clock and the inbox's independent invariants.
        let now = native_clock::native_callback(|| self.platform.unix_millis())
            .ok()
            .and_then(|value| activity_journal::UnixMillis::new(value).ok())
            .ok_or(BridgeError::HistoryTimeUnavailable)?;
        let pending = self.with_inbox(|owner| {
            Ok(owner
                .pending_outcomes()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .to_vec())
        })?;
        for outcome in pending {
            self.observe_denial_terminal(outcome);
        }
        let result = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(error) => {
                    drop(error.into_inner());
                    return self.fail_closed(BridgeError::Closed);
                }
            };
            state
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .record_pending_outcomes(now)
        };
        if result.is_err() {
            return self.fail_closed(BridgeError::StorageUnavailable);
        }
        Ok(())
    }

    fn read_history_while_admitted(&self) -> Result<String, BridgeError> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                drop(error.into_inner());
                return self.fail_closed(BridgeError::Closed);
            }
        };
        let owner = state.as_ref().ok_or(BridgeError::Closed)?;
        controller_runtime::encode_phone_history(
            owner
                .history()
                .map_err(|_| BridgeError::StorageUnavailable)?,
        )
        .map_err(|_| BridgeError::StorageUnavailable)
    }
    fn open(platform: Arc<dyn NativePlatform>, mode: OpenMode) -> Result<Arc<Self>, BridgeError> {
        let owner_lease = Arc::new(OwnerLease::acquire()?);
        let mut key_cleanup_needed = false;
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
            let mut preflight_error = None;
            let fresh = matches!(&initial, bootstrap::InitialState::Fresh(_));
            let created = if let bootstrap::InitialState::Fresh(policy) = initial {
                DurableInbox::create_fresh(
                    directory,
                    policy,
                    CapacityLimits::default(),
                    boot,
                    clock,
                )
            } else {
                DurableInbox::open_existing_with_key_preflight(
                    directory,
                    boot,
                    clock,
                    |checkpoint| {
                        local_keys::preflight(
                            checkpoint.local_keys(),
                            &*platform,
                            &mut key_cleanup_needed,
                        )
                        .map_err(|error| {
                            preflight_error = Some(error);
                            DurableFault::NativeLocalKeysUnavailable
                        })
                    },
                )
            };
            let (owner, update) = created.map_err(|error| {
                if let Some(cause) = preflight_error {
                    return cause;
                }
                if error.cause() == DurableFault::LifecycleIntegrationRequired {
                    BridgeError::LifecycleIntegrationRequired
                } else {
                    BridgeError::StorageUnavailable
                }
            })?;
            if fresh {
                // Recheck namespace absence under the new owner as well. A
                // concurrent unexpected alias never turns empty metadata ready.
                local_keys::preflight(
                    owner
                        .local_keys()
                        .map_err(|_| BridgeError::StorageUnavailable)?,
                    &*platform,
                    &mut key_cleanup_needed,
                )?;
            }
            if owner
                .inbox_fault()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .is_some()
            {
                return Err(BridgeError::OwnerFaulted);
            }
            let (finished_boot, finished_clock) = map_clock(platform.clock()?)?;
            if finished_boot != boot
                || finished_clock.phone_monotonic_nanos() < clock.phone_monotonic_nanos()
            {
                return Err(BridgeError::InvalidObservation);
            }
            let approval_owner = android_controller::ApprovalPlanOwner::new(&owner, boot)
                .map_err(|_| BridgeError::OwnerFaulted)?;
            let denial_state = denial::DenialState::new(&owner, boot)?;
            Ok((
                boot,
                finished_clock.phone_monotonic_nanos(),
                owner,
                approval_owner,
                denial_state,
                update,
            ))
        })();
        match result {
            Ok((boot, native_floor, owner, approval_owner, denial_state, update)) => {
                let controller = Arc::new(Self {
                    platform,
                    boot,
                    state: Mutex::new(Some(owner)),
                    approval_owner: Mutex::new(Some(approval_owner)),
                    approval_native_plan: Mutex::new(None),
                    denial_state: Mutex::new(denial_state),
                    projections: Mutex::new(request_projection::ProjectionRegistry::default()),
                    intake: Arc::new(intake::IntakeOwner::default()),
                    approval_alive: Arc::new(AtomicBool::new(true)),
                    active: AtomicBool::new(false),
                    cleanup_pending: AtomicBool::new(false),
                    notification_cleanup_failed: AtomicBool::new(false),
                    key_cleanup_pending: AtomicBool::new(key_cleanup_needed),
                    key_cleanup_failed: AtomicBool::new(false),
                    native_floor_nanos: AtomicU64::new(native_floor),
                    _owner_lease: owner_lease,
                });
                let initialized = (|| {
                    let _admission = controller.enter()?;
                    controller.initialize_effects(update)?;
                    controller.start_intake_reactor()
                })();
                if let Err(error) = initialized {
                    return controller.fail_closed(error);
                }
                Ok(controller)
            }
            // A rejected constructor is not the notification owner. In
            // particular Busy/preflight failures must not clear another owner.
            Err(error) => {
                if key_cleanup_needed {
                    // Preserve primary failure. The Application still retains
                    // this exact adapter and retries a failed memory cleanup.
                    let _ = platform.release_local_key_references();
                }
                Err(error)
            }
        }
    }
    fn enter(&self) -> Result<Admission<'_>, BridgeError> {
        if native_clock::callback_active() {
            return Err(BridgeError::Busy);
        }
        self.active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Admission(self))
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
        match native_clock::native_callback(|| self.platform.clock()).and_then(map_clock) {
            Ok((boot, clock)) if boot == self.boot => {
                let observed = clock.phone_monotonic_nanos();
                if observed < self.native_floor_nanos.load(Ordering::Acquire) {
                    return self.fail_closed(BridgeError::InvalidObservation);
                }
                self.native_floor_nanos.store(observed, Ordering::Release);
                Ok(clock)
            }
            Ok(_) => self.fail_closed(BridgeError::InvalidObservation),
            Err(error) => self.fail_closed(error),
        }
    }
    fn drop_owner(&self) -> bool {
        self.approval_alive.store(false, Ordering::Release);
        self.intake.stop();
        let _ = self
            .projections
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .revoke_all();
        // Logical close, not loss of the native retirement owner. Native cleanup
        // may still need retire_approval after provider return.
        if let Some(plans) = self
            .approval_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            plans.close();
        }
        self.close_denial_state();
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
        let io_clean = self.intake.cleanup_complete();
        let actions = self.finish_denial_cleanup();
        let approval_clean = self
            .approval_native_plan
            .lock()
            .map(|slot| slot.is_none())
            .unwrap_or(false);
        let notifications = self.attempt_notification_cleanup();
        let keys = if actions.is_err() || !approval_clean || !io_clean {
            // Pending action cleanup is NOT a failed key-reference callback.
            // A later continuation may make its FIRST attempt without a retry.
            Err(BridgeError::NativeUnavailable)
        } else if !self.key_cleanup_pending.load(Ordering::Acquire) {
            Ok(())
        } else if self.key_cleanup_failed.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            self.key_cleanup_failed.store(true, Ordering::Release);
            native_clock::native_callback(|| self.platform.release_local_key_references()).map(
                |()| {
                    self.key_cleanup_pending.store(false, Ordering::Release);
                    self.key_cleanup_failed.store(false, Ordering::Release);
                },
            )
        };
        // Attempt both independent downward cleanups; one failure must not skip
        // the other. Failed obligations remain for explicit shutdown retry.
        let result = notifications
            .and(actions)
            .and(keys)
            .map_err(|_| BridgeError::NativeUnavailable);
        if result.is_ok() && !self.approval_alive.load(Ordering::Acquire) {
            self.approval_owner
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            self.destroy_clean_denial_owner();
        }
        result
    }
    fn attempt_notification_cleanup(&self) -> Result<(), BridgeError> {
        if !self.cleanup_pending.load(Ordering::Acquire) {
            Ok(())
        } else if self.notification_cleanup_failed.load(Ordering::Acquire) {
            Err(BridgeError::NativeUnavailable)
        } else {
            // Set before foreign work so an unwinding callback also leaves a
            // failure latch. Only its completed success clears the obligation.
            self.notification_cleanup_failed
                .store(true, Ordering::Release);
            native_clock::native_callback(|| self.platform.clear_request_notifications()).map(
                |()| {
                    self.cleanup_pending.store(false, Ordering::Release);
                    self.notification_cleanup_failed
                        .store(false, Ordering::Release);
                },
            )
        }
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
    use std::{
        collections::VecDeque,
        sync::{Weak, atomic::AtomicUsize},
    };
    pub(crate) static SERIAL: Mutex<()> = Mutex::new(());
    struct TestPlatform {
        path: String,
        clock: Mutex<NativeClock>,
        history_time: Mutex<Result<u64, BridgeError>>,
        cleared: AtomicUsize,
        clear_fails: AtomicBool,
        reenter: Mutex<Option<Weak<MobileController>>>,
        saw_busy: AtomicBool,
        clock_samples: Mutex<VecDeque<NativeClock>>,
        keys_present: AtomicBool,
        key_callbacks: Mutex<KeyCallbacks>,
    }
    #[derive(Default)]
    struct KeyCallbacks {
        reopens: usize,
        releases: usize,
        reopen_fails: bool,
        release_fails: bool,
    }
    fn test_platform(path: String, clock: NativeClock) -> Arc<TestPlatform> {
        Arc::new(TestPlatform {
            path,
            clock: Mutex::new(clock),
            history_time: Mutex::new(Ok(1_234_567)),
            cleared: AtomicUsize::new(0),
            clear_fails: AtomicBool::new(false),
            reenter: Mutex::new(None),
            saw_busy: AtomicBool::new(false),
            clock_samples: Mutex::new(VecDeque::new()),
            keys_present: AtomicBool::new(false),
            key_callbacks: Mutex::new(KeyCallbacks::default()),
        })
    }
    impl NativePlatform for TestPlatform {
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
            Err(BridgeError::NativeUnavailable)
        }
        fn observe_denial_operation(
            &self,
            _: Arc<NativeDenialAttempt>,
        ) -> Result<NativeDenialOperationState, BridgeError> {
            Err(BridgeError::NativeUnavailable)
        }
        fn release_denial_scope(&self, _: Arc<NativeDenialScope>) -> Result<(), BridgeError> {
            Err(BridgeError::NativeUnavailable)
        }
        fn prepare_transport_signer(
            &self,
            _: Arc<NativeTransportBinding>,
        ) -> Result<(), BridgeError> {
            Err(BridgeError::LifecycleIntegrationRequired)
        }
        fn sign_client_certificate_verify(
            &self,
            _: Arc<NativeCertificateVerify>,
        ) -> Result<Vec<u8>, BridgeError> {
            Err(BridgeError::LifecycleIntegrationRequired)
        }
        fn release_transport_signer(
            &self,
            _: Arc<NativeTransportBinding>,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
        fn withdraw_requests(
            &self,
            requests: Vec<NativeRequestSelection>,
        ) -> Result<(), BridgeError> {
            if requests.is_empty() {
                Ok(())
            } else {
                Err(BridgeError::LifecycleIntegrationRequired)
            }
        }
        fn reopen_local_key_sets(&self, _: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
            let mut state = self.key_callbacks.lock().unwrap();
            state.reopens += 1;
            if state.reopen_fails {
                Err(BridgeError::LocalKeysUnavailable)
            } else {
                Ok(())
            }
        }
        fn release_local_key_references(&self) -> Result<(), BridgeError> {
            let mut state = self.key_callbacks.lock().unwrap();
            state.releases += 1;
            if state.release_fails {
                Err(BridgeError::LocalKeysUnavailable)
            } else {
                Ok(())
            }
        }
        fn unix_millis(&self) -> Result<u64, BridgeError> {
            *self.history_time.lock().unwrap()
        }
        fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
            Ok(None)
        }
        fn has_device_keys(&self) -> Result<bool, BridgeError> {
            Ok(self.keys_present.load(Ordering::Acquire))
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
            Ok(self
                .clock_samples
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(*self.clock.lock().unwrap()))
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
        let platform = test_platform(directory.path().to_str().unwrap().into(), clock);
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
            approval_owner: Mutex::new(Some(
                android_controller::ApprovalPlanOwner::new(&owner, boot).unwrap(),
            )),
            approval_alive: Arc::new(AtomicBool::new(true)),
            approval_native_plan: Mutex::new(None),
            denial_state: Mutex::new(denial::DenialState::new(&owner, boot).unwrap()),
            projections: Mutex::new(request_projection::ProjectionRegistry::default()),
            intake: Arc::new(intake::IntakeOwner::default()),
            state: Mutex::new(Some(owner)),
            active: AtomicBool::new(false),
            cleanup_pending: AtomicBool::new(false),
            notification_cleanup_failed: AtomicBool::new(false),
            key_cleanup_pending: AtomicBool::new(false),
            key_cleanup_failed: AtomicBool::new(false),
            native_floor_nanos: AtomicU64::new(clock.phone_monotonic_nanos()),
            _owner_lease: Arc::new(OwnerLease::acquire().unwrap()),
        });
        test(&controller, &platform);
    }

    fn approval_selection() -> NativeRequestSelection {
        NativeRequestSelection {
            pc: vec![1; 32],
            epoch: vec![2; 32],
            request: vec![3; 32],
        }
    }

    #[test]
    fn empty_policy_owner_never_invents_an_approval_plan_or_faults_on_normal_rejection() {
        with_model(|controller, platform| {
            assert!(matches!(
                controller.begin_approval(approval_selection()),
                Err(BridgeError::ApprovalRejected)
            ));
            assert!(controller.notification_policy_json().is_ok());
            assert!(controller.approval_alive.load(Ordering::Acquire));
            assert_eq!(platform.cleared.load(Ordering::Acquire), 0);
        });
    }

    #[test]
    fn malformed_approval_selection_is_rejected_before_clock_or_owner_transition() {
        with_model(|controller, platform| {
            platform.clock.lock().unwrap().boot_count = 2;
            let mut invalid = approval_selection();
            invalid.request = vec![0; 32];
            assert!(matches!(
                controller.begin_approval(invalid),
                Err(BridgeError::InvalidObservation)
            ));
            assert!(controller.approval_alive.load(Ordering::Acquire));
            assert!(controller.state.lock().unwrap().is_some());
        });
    }

    #[test]
    fn approval_clock_failure_closes_owner_and_preserves_downward_cleanup() {
        with_model(|controller, platform| {
            platform.clock.lock().unwrap().boot_count = 2;
            assert!(matches!(
                controller.begin_approval(approval_selection()),
                Err(BridgeError::InvalidObservation)
            ));
            assert!(!controller.approval_alive.load(Ordering::Acquire));
            assert!(controller.state.lock().unwrap().is_none());
            assert_eq!(platform.cleared.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn poisoned_approval_mutex_does_not_leave_existing_owner_or_handles_live() {
        with_model(|controller, platform| {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = controller.approval_owner.lock().unwrap();
                panic!("poison fixture");
            }));
            assert!(matches!(
                controller.begin_approval(approval_selection()),
                Err(BridgeError::Closed)
            ));
            assert!(!controller.approval_alive.load(Ordering::Acquire));
            assert!(controller.state.lock().unwrap().is_none());
            assert_eq!(platform.cleared.load(Ordering::Acquire), 1);
        });
    }

    #[test]
    fn failed_approval_check_commit_is_not_an_ordinary_rejected_request() {
        with_model(|controller, platform| {
            let blocker =
                std::path::Path::new(&platform.path).join(phone_state_store::STAGING_FILE_NAME);
            let canary = b"synthetic test-owned staging blocker";
            std::fs::write(&blocker, canary).unwrap();
            assert!(matches!(
                controller.begin_approval(approval_selection()),
                Err(BridgeError::StorageUnavailable)
            ));
            assert!(!controller.approval_alive.load(Ordering::Acquire));
            assert!(controller.state.lock().unwrap().is_none());
            assert_eq!(platform.cleared.load(Ordering::Acquire), 1);
            assert_eq!(std::fs::read(blocker).unwrap(), canary);
        });
    }

    #[test]
    fn approval_native_clock_callback_can_reenter_only_as_busy() {
        with_model(|controller, platform| {
            *platform.reenter.lock().unwrap() = Some(Arc::downgrade(controller));
            assert!(matches!(
                controller.begin_approval(approval_selection()),
                Err(BridgeError::ApprovalRejected)
            ));
            assert!(platform.saw_busy.load(Ordering::Acquire));
            assert!(controller.notification_policy_json().is_ok());
        });
    }

    #[test]
    fn both_downward_cleanup_obligations_are_attempted_and_retained_on_failure() {
        with_model(|controller, platform| {
            controller
                .key_cleanup_pending
                .store(true, Ordering::Release);
            platform.clear_fails.store(true, Ordering::Release);
            platform.key_callbacks.lock().unwrap().release_fails = true;
            assert_eq!(
                controller.shutdown_native_owner(),
                Err(BridgeError::NativeUnavailable)
            );
            assert_eq!(platform.cleared.load(Ordering::Acquire), 1);
            assert_eq!(platform.key_callbacks.lock().unwrap().releases, 1);
            assert!(controller.cleanup_pending.load(Ordering::Acquire));
            assert!(controller.key_cleanup_pending.load(Ordering::Acquire));
            platform.clear_fails.store(false, Ordering::Release);
            platform.key_callbacks.lock().unwrap().release_fails = false;
            controller.shutdown_native_owner().unwrap();
            controller.shutdown_native_owner().unwrap();
            assert_eq!(platform.cleared.load(Ordering::Acquire), 2);
            assert_eq!(platform.key_callbacks.lock().unwrap().releases, 2);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn constructor_final_clock_is_retained_as_the_next_operation_floor() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let at = |nanos| NativeClock {
            boot_count: 1,
            monotonic_nanos: nanos,
            weekday: 0,
            minute: 600,
        };
        let platform = test_platform(temp.path().to_str().unwrap().into(), at(1_500_000_000));
        platform
            .clock_samples
            .lock()
            .unwrap()
            .extend([at(1_000_000_000), at(2_000_000_000)]);
        let controller = MobileController::open_or_initialize(platform.clone()).unwrap();
        assert_eq!(
            controller.native_floor_nanos.load(Ordering::Acquire),
            2_000_000_000
        );
        let policy = serde_json::to_string(&NotificationPolicy::default()).unwrap();
        assert_eq!(
            controller.save_notification_policy(policy),
            Err(BridgeError::InvalidObservation)
        );
        assert_eq!(
            controller.notification_policy_json(),
            Err(BridgeError::Closed)
        );
    }

    #[cfg(target_os = "linux")]
    fn seed_local_keys(path: &std::path::Path, clock: NativeClock, pending: bool) {
        use android_controller::{
            LocalAttestationChallenge, LocalKeyHandle, LocalKeySetDescriptor,
        };
        use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
        use secure_channel::TlsPublicKey;
        let key = |seed| {
            let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
            let public = p256::PublicKey::from_sec1_bytes(
                signing.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap();
            TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
        };
        let (boot, clock) = map_clock(clock).unwrap();
        let (mut owner, _) = DurableInbox::create_fresh_host_model(
            NativePrivateDirectory::from_native_app_data(path).unwrap(),
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
            clock,
        )
        .unwrap();
        let handle = LocalKeyHandle::from_bytes([1; 32]).unwrap();
        let challenge = LocalAttestationChallenge::from_bytes([2; 32]).unwrap();
        let prepared = owner.begin_local_key_creation(handle, challenge).unwrap();
        assert!(prepared.changed());
        if !pending {
            let (recorded, observation) = owner
                .record_local_key_creation(
                    LocalKeySetDescriptor::new(handle, challenge, key(3), key(4), key(5)).unwrap(),
                )
                .unwrap();
            assert!(recorded.changed());
            assert_eq!(
                observation,
                android_controller::LocalKeyObservation::RecordedUnverified
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_native_reopen_failure_releases_own_refs_before_return_without_store_change() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let clock = NativeClock {
            boot_count: 1,
            monotonic_nanos: 1_000_000_000,
            weekday: 0,
            minute: 600,
        };
        seed_local_keys(temp.path(), clock, false);
        let before =
            std::fs::read(temp.path().join(phone_state_store::SNAPSHOT_FILE_NAME)).unwrap();
        let platform = test_platform(temp.path().to_str().unwrap().into(), clock);
        platform.keys_present.store(true, Ordering::Release);
        platform.key_callbacks.lock().unwrap().reopen_fails = true;
        assert_eq!(
            MobileController::open_existing(platform.clone()).unwrap_err(),
            BridgeError::LocalKeysUnavailable
        );
        let calls = platform.key_callbacks.lock().unwrap();
        assert_eq!(calls.reopens, 1);
        assert_eq!(calls.releases, 1);
        assert_eq!(platform.cleared.load(Ordering::Acquire), 0);
        assert_eq!(
            std::fs::read(temp.path().join(phone_state_store::SNAPSHOT_FILE_NAME)).unwrap(),
            before
        );
        assert!(
            !temp
                .path()
                .join(phone_state_store::INTENT_FILE_NAME)
                .exists()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn late_constructor_failure_keeps_primary_error_and_releases_reopened_refs() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        for fail_cleanup in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let at = |nanos| NativeClock {
                boot_count: 1,
                monotonic_nanos: nanos,
                weekday: 0,
                minute: 600,
            };
            seed_local_keys(temp.path(), at(1_000_000_000), false);
            let platform = test_platform(temp.path().to_str().unwrap().into(), at(900_000_000));
            platform
                .clock_samples
                .lock()
                .unwrap()
                .push_back(at(1_000_000_000));
            platform.key_callbacks.lock().unwrap().release_fails = fail_cleanup;
            assert_eq!(
                MobileController::open_existing(platform.clone()).unwrap_err(),
                BridgeError::InvalidObservation
            );
            assert_eq!(platform.key_callbacks.lock().unwrap().releases, 1);
            // Native Application retains this same adapter even with no Rust
            // handle returned. It can retry only its own pending memory cleanup.
            platform.key_callbacks.lock().unwrap().release_fails = false;
            platform.release_local_key_references().unwrap();
            assert_eq!(platform.key_callbacks.lock().unwrap().releases, 2);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preparing_or_untracked_aliases_are_rejected_before_any_reopen_or_migration() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        for pending in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let clock = NativeClock {
                boot_count: 1,
                monotonic_nanos: 1_000_000_000,
                weekday: 0,
                minute: 600,
            };
            if pending {
                seed_local_keys(temp.path(), clock, true);
            } else {
                let (boot, observed) = map_clock(clock).unwrap();
                drop(
                    DurableInbox::create_fresh_host_model(
                        NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
                        NotificationPolicy::default(),
                        CapacityLimits::default(),
                        boot,
                        observed,
                    )
                    .unwrap(),
                );
            }
            let before =
                std::fs::read(temp.path().join(phone_state_store::SNAPSHOT_FILE_NAME)).unwrap();
            let platform = test_platform(temp.path().to_str().unwrap().into(), clock);
            platform.keys_present.store(!pending, Ordering::Release);
            assert_eq!(
                MobileController::open_existing(platform.clone()).unwrap_err(),
                BridgeError::LocalKeysReconciliationRequired
            );
            assert_eq!(platform.key_callbacks.lock().unwrap().reopens, 0);
            assert_eq!(platform.key_callbacks.lock().unwrap().releases, 0);
            assert_eq!(
                std::fs::read(temp.path().join(phone_state_store::SNAPSHOT_FILE_NAME)).unwrap(),
                before
            );
        }
    }

    #[test]
    fn history_clock_failure_does_not_ack_or_stop_the_policy_owner() {
        with_model(|controller, platform| {
            *platform.history_time.lock().unwrap() = Err(BridgeError::NativeUnavailable);
            assert_eq!(
                controller.history_json(),
                Err(BridgeError::HistoryTimeUnavailable)
            );
            assert!(controller.notification_policy_json().is_ok());
            assert_eq!(platform.cleared.load(Ordering::Relaxed), 0);
            *platform.history_time.lock().unwrap() = Ok(u64::MAX);
            assert_eq!(
                controller.clear_history_json(),
                Err(BridgeError::HistoryTimeUnavailable)
            );
            assert!(controller.notification_policy_json().is_ok());
            *platform.history_time.lock().unwrap() = Ok(123);
            assert_eq!(
                controller.history_json().unwrap(),
                r#"{"schemaVersion":1,"records":[]}"#
            );
            assert_eq!(
                controller.clear_history_json().unwrap(),
                r#"{"schemaVersion":1,"records":[]}"#
            );
        });
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
