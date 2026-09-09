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
}

impl MobileReadiness {
    pub const UNAVAILABLE: Self = Self {
        screen_lock: ScreenLockState::Unavailable,
        notifications: NotificationPermission::Unavailable,
        can_open_lock_settings: false,
        can_open_notification_settings: false,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Authenticating,
    Sending,
    Expired,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    pub id: String,
    pub computer_name: String,
    pub program_name: String,
    pub executable_path: String,
    pub details: String,
    pub remaining_seconds: u32,
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
    pub mobile: Option<MobileReadiness>,
    pub policy: NotificationPolicy,
    pub devices: Vec<PairedDeviceView>,
    pub requests: Vec<RequestView>,
    pub activity: Vec<ActivityView>,
    pub data_availability: DataAvailability,
    pub can_pair: bool,
    pub can_unpair: bool,
    pub can_clear_activity: bool,
    pub issue: Option<AppIssue>,
}

impl AppSnapshot {
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
            schema_version: 1,
            platform: Platform::Android,
            computer_name: String::new(),
            service: None,
            mobile: Some(readiness),
            policy,
            devices: Vec::new(),
            requests: Vec::new(),
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
