// SPDX-License-Identifier: GPL-2.0-or-later

use notification_policy::NotificationPolicy;
use serde::{Deserialize, Serialize};

/// Presentation target, selected by the native host rather than the renderer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Android,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlHint {
    NeedsInstaller,
    Available,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceView {
    pub installed: bool,
    pub state: Option<ServiceState>,
    /// Navigation hints only. Native control must revalidate at action time.
    pub allowed_actions: Vec<ServiceAction>,
    pub control_hint: ControlHint,
    pub remote_requests_ready: bool,
}

/// Phone process/service availability, never a peer or authentication claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneServiceState {
    Stopped,
    Preparing,
    WaitingForUnlock,
    LocalSettingsReady,
    CleanupPending,
    Unavailable,
}

/// Supplied by the native Application and PackageManager, not WebView input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PhoneServiceView {
    pub state: PhoneServiceState,
    #[serde(deserialize_with = "deserialize_boot_enabled")]
    pub boot_enabled: Option<bool>,
    pub can_start: bool,
    pub can_stop: bool,
    pub policy_owner_ready: bool,
}

// Require the property to be present even when its observation is null.
fn deserialize_boot_enabled<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    Option::<bool>::deserialize(deserializer)
}

impl PhoneServiceView {
    pub const UNAVAILABLE: Self = Self {
        state: PhoneServiceState::Unavailable,
        boot_enabled: None,
        can_start: false,
        can_stop: false,
        policy_owner_ready: false,
    };

    /// Reject contradictory native observations instead of inventing readiness.
    pub fn checked(self) -> Option<Self> {
        if self.can_start
            && (self.boot_enabled.is_none()
                || !matches!(
                    self.state,
                    PhoneServiceState::Stopped | PhoneServiceState::Unavailable
                ))
            || self.policy_owner_ready
                && (self.state != PhoneServiceState::LocalSettingsReady
                    || self.boot_enabled != Some(true))
            || self.state == PhoneServiceState::LocalSettingsReady && !self.policy_owner_ready
        {
            return None;
        }
        Some(self)
    }

    pub const fn allows(self, action: ServiceAction) -> bool {
        match action {
            ServiceAction::Start => self.can_start,
            ServiceAction::Stop => self.can_stop,
            ServiceAction::Install | ServiceAction::Restart | ServiceAction::Uninstall => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenLockState {
    Configured,
    Missing,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPermission {
    Allowed,
    Denied,
    Unavailable,
}

/// An observation from the Android native owner, not authentication evidence.
/// Never deserialize this from a WebView command or persist it as a preference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MobileReadiness {
    pub screen_lock: ScreenLockState,
    pub notifications: NotificationPermission,
    pub can_open_lock_settings: bool,
    pub can_open_notification_settings: bool,
    /// Native camera-input entry only, never complete pairing or permission proof.
    pub can_open_pairing_scanner: bool,
}

impl MobileReadiness {
    pub const UNAVAILABLE: Self = Self {
        screen_lock: ScreenLockState::Unavailable,
        notifications: NotificationPermission::Unavailable,
        can_open_lock_settings: false,
        can_open_notification_settings: false,
        can_open_pairing_scanner: false,
    };
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDeviceView {
    pub id: String,
    pub name: String,
    pub connected: bool,
    pub last_seen_label: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Authenticating,
    Waiting,
    Sending,
    AwaitingOutcome,
    Unavailable,
    Expired,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestView {
    pub id: String,
    pub computer_name: String,
    pub program_name: String,
    pub executable_path: String,
    pub program_elided: bool,
    pub path_elided: bool,
    pub has_details: bool,
    pub remaining_seconds: u32,
    /// Display lease only, not an authorization deadline. Subtract bridge time.
    pub refresh_after_millis: u32,
    pub state: RequestState,
    pub can_approve: bool,
    pub can_deny: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Connected,
    Disconnected,
    ServiceStarted,
    ServiceStopped,
    Expired,
    Cancelled,
    Approved,
    Denied,
    Failure,
    PcCompleted,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityView {
    pub id: String,
    pub timestamp_millis: u64,
    pub kind: ActivityKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataAvailability {
    pub devices: Availability,
    pub requests: Availability,
    pub activity: Availability,
}

impl DataAvailability {
    pub const UNAVAILABLE: Self = Self {
        devices: Availability::Unavailable,
        requests: Availability::Unavailable,
        activity: Availability::Unavailable,
    };
}

/// Fixed, reviewed copy only. No OS error, path or submitted value is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[error("{message}")]
#[serde(rename_all = "camelCase")]
pub struct AppIssue {
    pub code: &'static str,
    pub message: &'static str,
    pub next_action: Option<&'static str>,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSnapshot {
    pub schema_version: u8,
    pub platform: Platform,
    /// Bounded display text only, never a peer identity or authorization input.
    pub computer_name: String,
    pub service: Option<ServiceView>,
    pub phone_service: Option<PhoneServiceView>,
    pub mobile: Option<MobileReadiness>,
    /// None means no current policy observation; never substitute defaults.
    pub policy: Option<NotificationPolicy>,
    pub devices: Vec<PairedDeviceView>,
    pub requests: Vec<RequestView>,
    /// None is no current native observation, not an empty provisioned map.
    pub request_catalog: Option<crate::RequestCatalogView>,
    /// Native review navigation only. Never starts authentication or a decision.
    pub request_review: Option<crate::RequestReviewView>,
    pub activity: Vec<ActivityView>,
    pub data_availability: DataAvailability,
    pub can_pair: bool,
    pub can_unpair: bool,
    pub can_clear_activity: bool,
    pub issue: Option<AppIssue>,
}

impl AppSnapshot {
    /// Remains renderable while the Android policy owner is stopped/unavailable.
    pub fn from_android_service(service: PhoneServiceView, readiness: MobileReadiness) -> Self {
        Self {
            schema_version: 3,
            platform: Platform::Android,
            computer_name: String::new(),
            service: None,
            phone_service: Some(service),
            mobile: Some(readiness),
            policy: None,
            devices: Vec::new(),
            requests: Vec::new(),
            request_catalog: None,
            request_review: None,
            activity: Vec::new(),
            data_availability: DataAvailability::UNAVAILABLE,
            can_pair: false,
            can_unpair: false,
            can_clear_activity: false,
            issue: None,
        }
    }

    /// Independent native history availability; None is never an empty history.
    pub fn from_android_policy_and_history(
        policy: NotificationPolicy,
        readiness: MobileReadiness,
        history: Option<Vec<ActivityView>>,
    ) -> Self {
        let mut value = Self::from_android_policy(policy, readiness);
        if let Some(history) = history {
            value.can_clear_activity = !history.is_empty();
            value.activity = history;
            value.data_availability.activity = Availability::Available;
        }
        value
    }
    /// Present committed policy supplied by the one native Android owner.
    /// No preference store is opened, and missing request/device/history owners
    /// remain unavailable, never an apparently confirmed empty collection.
    pub fn from_android_policy(policy: NotificationPolicy, readiness: MobileReadiness) -> Self {
        Self {
            schema_version: 3,
            platform: Platform::Android,
            computer_name: String::new(),
            service: None,
            phone_service: None,
            mobile: Some(readiness),
            policy: Some(policy),
            devices: Vec::new(),
            requests: Vec::new(),
            request_catalog: None,
            request_review: None,
            activity: Vec::new(),
            data_availability: DataAvailability::UNAVAILABLE,
            can_pair: false,
            can_unpair: false,
            can_clear_activity: false,
            issue: None,
        }
    }
}

// These objects serialize to the intended local UI, but must never turn request
// details, command lines or identifiers into ambient diagnostic/log output.
impl std::fmt::Debug for RequestView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestView")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PairedDeviceView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedDeviceView")
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ActivityView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivityView")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AppSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppSnapshot")
            .field("schema_version", &self.schema_version)
            .field("platform", &self.platform)
            .field("data_availability", &self.data_availability)
            .finish_non_exhaustive()
    }
}
