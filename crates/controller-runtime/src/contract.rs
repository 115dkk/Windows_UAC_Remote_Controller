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
    /// Last explicit operation outcome, not a capability or a stale-state gate.
    pub action_issue: Option<AppIssue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    Embedded,
    External,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayState {
    Listening,
    WaitingNetwork,
    Unavailable,
    Stopped,
    ExternalConfigured,
    Unknown,
}

/// Listener observation is distinct from selected configuration/reachability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayStatusView {
    pub mode: RelayMode,
    pub state: RelayState,
    /// A native route candidate observation, never an authenticated Internet path.
    pub internet_state: Option<DirectConnectionState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConnectionState {
    Unknown,
    Discovering,
    LanOnly,
    Candidate,
    Unavailable,
    Stopped,
}

/// How the PC learns an address that reaches its relay from outside.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAccessMode {
    Automatic,
    RouterForward,
    Fixed,
}

/// Where the published external candidate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCandidateSource {
    Pcp,
    Upnp,
    Stun,
    Fixed,
    PublicInterface,
}

/// Why no external candidate is published. Present only while there is none.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAccessFailure {
    NoMappingProtocol,
    PrivateExternalAddress,
    PublicAddressUnavailable,
}

/// The running service's configured mode and its current observation. Local
/// presentation only; the external address is a candidate, not reachability.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccessView {
    pub mode: ExternalAccessMode,
    /// router_forward only: the router port forwarded to this PC's relay port.
    pub external_port: Option<u16>,
    /// fixed only: the configured address, `ip:port` with IPv6 in brackets.
    pub fixed_address: Option<String>,
    /// The published external candidate, `ip:port`.
    pub external_address: Option<String>,
    pub source: Option<ExternalCandidateSource>,
    /// This PC's routed LAN IP without a port, for router instructions.
    pub lan_address: Option<String>,
    /// The embedded relay's port on this PC.
    pub relay_port: u16,
    pub failure: Option<ExternalAccessFailure>,
}

impl ExternalAccessView {
    /// Contradictory observations are dropped rather than presented.
    pub fn checked(self) -> Option<Self> {
        let mode_fields = match self.mode {
            ExternalAccessMode::Automatic => {
                self.external_port.is_none() && self.fixed_address.is_none()
            }
            ExternalAccessMode::RouterForward => {
                self.external_port.is_some_and(|port| port != 0) && self.fixed_address.is_none()
            }
            ExternalAccessMode::Fixed => {
                self.external_port.is_none() && self.fixed_address.is_some()
            }
        };
        let candidate = self.external_address.is_some() == self.source.is_some()
            && !(self.external_address.is_some() && self.failure.is_some());
        (mode_fields && candidate && self.relay_port != 0).then_some(self)
    }
}

impl std::fmt::Debug for ExternalAccessView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalAccessView")
            .field("mode", &self.mode)
            .field("source", &self.source)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

/// The presentation's requested mode, exactly one of three JSON shapes:
/// `{"mode":"automatic"}`, `{"mode":"router_forward","externalPort":N}` or
/// `{"mode":"fixed","fixedAddress":"ip:port"}`. Deserializing is not
/// validation; `access()` applies the service's rules before any elevation.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalAccessInput {
    // A struct variant, not a unit one: serde lets an internally tagged unit
    // variant ignore extra fields, which `deny_unknown_fields` must refuse.
    Automatic {},
    RouterForward {
        #[serde(rename = "externalPort")]
        external_port: u16,
    },
    Fixed {
        #[serde(rename = "fixedAddress")]
        fixed_address: std::net::SocketAddr,
    },
}

impl std::fmt::Debug for ExternalAccessInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Automatic {} => "ExternalAccessInput::Automatic",
            Self::RouterForward { .. } => "ExternalAccessInput::RouterForward(redacted)",
            Self::Fixed { .. } => "ExternalAccessInput::Fixed(redacted)",
        })
    }
}

impl ExternalAccessInput {
    /// The same rules as the elevated CLI and the service: port 1..=65535 and,
    /// for `fixed`, a global unicast address without scope or flow label.
    pub fn access(self) -> Result<direct_network::ExternalAccess, AppIssue> {
        let access = match self {
            Self::Automatic {} => direct_network::ExternalAccess::Automatic,
            Self::RouterForward { external_port } => {
                direct_network::ExternalAccess::RouterForward { external_port }
            }
            Self::Fixed { fixed_address } => direct_network::ExternalAccess::Fixed {
                address: fixed_address,
            },
        };
        access.validated().map_err(|error| match error {
            direct_network::InvalidExternalAccess::ZeroPort
                if matches!(self, Self::RouterForward { .. }) =>
            {
                invalid_external_port()
            }
            _ => invalid_external_address(),
        })
    }
}

/// Bound for the WebView's JSON text; the longest valid input is far shorter.
pub const MAX_EXTERNAL_ACCESS_JSON_BYTES: usize = 256;

/// Strict, bounded decoding of the WebView's `set_external_access` argument,
/// validated with the service's rules. No field outside the three shapes.
pub fn decode_external_access_json(
    bytes: &[u8],
) -> Result<direct_network::ExternalAccess, AppIssue> {
    if bytes.len() > MAX_EXTERNAL_ACCESS_JSON_BYTES {
        return Err(invalid_external_access());
    }
    let input: ExternalAccessInput =
        serde_json::from_slice(bytes).map_err(|_| invalid_external_access())?;
    input.access()
}

pub(crate) const fn invalid_external_access() -> AppIssue {
    AppIssue {
        code: "invalid_external_access",
        message: "외부 연결 설정을 읽지 못했습니다.",
        next_action: Some("연결 방법을 다시 선택한 뒤 저장하십시오."),
    }
}

pub(crate) const fn invalid_external_port() -> AppIssue {
    AppIssue {
        code: "invalid_external_port",
        message: "포트는 1에서 65535 사이의 숫자로 입력하십시오.",
        next_action: None,
    }
}

pub(crate) const fn invalid_external_address() -> AppIssue {
    AppIssue {
        code: "invalid_external_address",
        message: "이 주소로는 외부에서 연결할 수 없습니다.",
        next_action: Some("공유기 관리 페이지에 표시된 공인 IP와 포트를 입력하십시오."),
    }
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementDevice {
    pub id: String,
    pub revision: u64,
    pub route_present: bool,
    pub connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementObservation {
    pub relay_configured: bool,
    pub relay_status: RelayStatusView,
    pub devices: Vec<ManagementDevice>,
    pub activity: Option<Vec<ActivityView>>,
    /// Optional separate read; None when the service did not answer it.
    pub external_access: Option<ExternalAccessView>,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDeviceView {
    pub id: String,
    pub name: String,
    pub revision: u64,
    pub route_present: bool,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionFeedbackAction {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionFeedbackPhase {
    Authenticating,
    Preparing,
    Sending,
    AwaitingPc,
    AuthenticationCancelled,
    LocalUnconfirmed,
    Approved,
    Denied,
    Failed,
    Cancelled,
    Expired,
    PcCompleted,
}

/// Body-free native observation. Its locator is display correlation only.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecisionFeedbackView {
    pub id: String,
    pub action: DecisionFeedbackAction,
    pub phase: DecisionFeedbackPhase,
    pub elapsed_millis: u32,
    /// Eligible local interval only; does not identify which phone won on PC.
    #[serde(default)]
    pub timing_available: bool,
    pub authentication_millis: Option<u32>,
    pub after_authentication_millis: Option<u32>,
}
impl std::fmt::Debug for DecisionFeedbackView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DecisionFeedbackView([redacted], display_only)")
    }
}

/// How far the phone's last failed dial toward an unconnected PC got.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PcConnectionFailure {
    /// Every address timed out or was unreachable.
    Unreachable,
    /// Some address refused or reset the TCP connect.
    Refused,
    /// A relay accepted the TCP connect but sent no READY.
    NoAnswer,
}

/// The phone's own dialing toward its paired PCs. Display only: never a
/// reachability, authentication or action claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PcConnectionView {
    /// A dial to some paired, unconnected PC is in flight now.
    pub dialing: bool,
    /// The furthest failure among unconnected paired PCs since their last
    /// carrier, or none. The property is required even when null.
    #[serde(deserialize_with = "deserialize_connection_failure")]
    pub last_failure: Option<PcConnectionFailure>,
    /// Every paired PC has a stored global address besides its relay address.
    pub external_route: bool,
}

fn deserialize_connection_failure<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PcConnectionFailure>, D::Error> {
    Option::<PcConnectionFailure>::deserialize(deserializer)
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

/// Fixed presentation only. Native details and ceremony material never enter it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingView {
    pub phase: &'static str,
    pub message: String,
    pub failure: Option<&'static str>,
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
    DeliveryFailed,
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
    pub relay_configured: bool,
    pub relay_status: Option<RelayStatusView>,
    /// None: not Windows, service not running, or not observed.
    pub external_access: Option<ExternalAccessView>,
    pub devices: Vec<PairedDeviceView>,
    pub requests: Vec<RequestView>,
    /// None is no current native observation, not an empty provisioned map.
    pub request_catalog: Option<crate::RequestCatalogView>,
    /// Native review navigation only. Never starts authentication or a decision.
    pub request_review: Option<crate::RequestReviewView>,
    pub activity: Vec<ActivityView>,
    pub data_availability: DataAvailability,
    pub pairing: Option<PairingView>,
    pub can_pair: bool,
    pub can_unpair: bool,
    pub can_clear_activity: bool,
    pub issue: Option<AppIssue>,
}

impl AppSnapshot {
    /// Remains renderable while the Android policy owner is stopped/unavailable.
    pub fn from_android_service(service: PhoneServiceView, readiness: MobileReadiness) -> Self {
        Self {
            schema_version: 4,
            platform: Platform::Android,
            computer_name: String::new(),
            service: None,
            phone_service: Some(service),
            mobile: Some(readiness),
            policy: None,
            relay_configured: false,
            relay_status: None,
            external_access: None,
            devices: Vec::new(),
            requests: Vec::new(),
            request_catalog: None,
            request_review: None,
            activity: Vec::new(),
            data_availability: DataAvailability::UNAVAILABLE,
            pairing: None,
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
            schema_version: 4,
            platform: Platform::Android,
            computer_name: String::new(),
            service: None,
            phone_service: None,
            mobile: Some(readiness),
            policy: Some(policy),
            relay_configured: false,
            relay_status: None,
            external_access: None,
            devices: Vec::new(),
            requests: Vec::new(),
            request_catalog: None,
            request_review: None,
            activity: Vec::new(),
            data_availability: DataAvailability::UNAVAILABLE,
            pairing: None,
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
