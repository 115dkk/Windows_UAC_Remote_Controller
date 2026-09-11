// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    collections::BTreeSet,
    fmt,
    net::{SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};

use notification_policy::NotificationPolicy;
use serde::{Deserialize, Serialize};

use crate::{
    ActivityView, AppIssue, AppPrivateDirectory, AppSnapshot, ControlHint, DataAvailability,
    ManagementDevice, ManagementObservation, MobileReadiness, PairingView, Platform,
    ScreenLockState, ServiceAction, ServiceState, ServiceView, storage::PreferenceStore,
};

pub const MAX_COMPUTER_NAME_BYTES: usize = 256;
pub const MAX_COMPUTER_NAME_CHARACTERS: usize = 64;

/// Successful status reads distinguish real absence from every read failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedServiceState {
    NotInstalled,
    Installed(ServiceState),
}

/// Actual lifecycle and helper validation are independent observations. Helper
/// failure does not discard a successful SCM state read or invent nonexistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceObservation {
    pub state: ObservedServiceState,
    pub control: Result<ControlHint, PlatformError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceCommandOutcome {
    UserCancelled,
    StillRunning,
    Completed { observation: ServiceObservation },
    CompletionStatusUnknown,
    HelperFailed,
}

/// Stable categories, with no native code, path, or supplied string payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformError {
    Unsupported,
    StatusUnavailable,
    HelperUnavailable,
    ControlFailed,
}

impl From<PlatformError> for AppIssue {
    fn from(error: PlatformError) -> Self {
        match error {
            PlatformError::Unsupported => Self {
                code: "service_control_unsupported",
                message: "이 기기에서는 PC의 휴대폰 승인을 켜거나 끌 수 없습니다.",
                next_action: Some("Windows PC에서 앱을 열어 주세요."),
            },
            PlatformError::StatusUnavailable => Self {
                code: "service_status_unavailable",
                message: "PC에서 휴대폰 승인이 켜져 있는지 확인하지 못했습니다.",
                next_action: Some("PC의 설치 상태를 확인한 뒤 새로고침해 주세요."),
            },
            PlatformError::HelperUnavailable => Self {
                code: "service_helper_unavailable",
                message: "휴대폰 승인을 켜고 끄는 데 필요한 앱 파일을 확인하지 못했습니다.",
                next_action: Some("설치 프로그램으로 앱의 설치 상태를 확인해 주세요."),
            },
            PlatformError::ControlFailed => Self {
                code: "service_control_failed",
                message: "요청한 작업이 완료됐는지 확인하지 못했습니다.",
                next_action: Some("새로고침한 뒤 휴대폰 승인의 설치 상태를 확인해 주세요."),
            },
        }
    }
}

/// Native service-owner seam. Production implementations must query the real OS
/// and validate the fixed installed helper at action time. A presentation hint
/// is not permission to launch a path, sign, inject input or approve a prompt.
///
/// `control_service` can block during Windows-owned elevation and its bounded
/// helper wait. The ROOT Tauri host must run commands on a background worker and
/// serialize access to one `AppRuntime`; never block its WebView/UI thread.
pub trait PlatformAdapter: Send {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError>;
    fn observe_management(&self) -> Result<ManagementObservation, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn control_service(
        &self,
        action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError>;
    fn remove_device(&self, _device_id: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn set_relay(&self, _address: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

/// Published state and cancellation seam for one asynchronous pairing attempt.
pub trait PairingAttemptHandle: Send {
    fn state(&self) -> PairingUiState;
    fn cancel(&mut self);
    fn join_until(&mut self, deadline: Instant) -> bool;
}

/// Starts only the fixed native pairing ceremony. No path or ceremony data is accepted.
pub trait PairingStarter: Send {
    fn available(&self) -> bool;
    fn start(&self) -> Result<Box<dyn PairingAttemptHandle>, PairingFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingFailure {
    ServiceNotReady,
    UserCancelled,
    HelperFailed,
    Timeout,
    RelayUnconfigured,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingUiPhase {
    Connecting,
    WaitingForAdmin,
    HelperRunning,
    Finished,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingUiState {
    pub phase: PairingUiPhase,
    pub failure: Option<PairingFailure>,
    pub started_at: Instant,
    pub terminal_at: Option<Instant>,
}

impl PairingUiState {
    pub fn connecting(started_at: Instant) -> Self {
        Self {
            phase: PairingUiPhase::Connecting,
            failure: None,
            started_at,
            terminal_at: None,
        }
    }

    pub fn running(phase: PairingUiPhase, started_at: Instant) -> Self {
        assert!(matches!(
            phase,
            PairingUiPhase::Connecting
                | PairingUiPhase::WaitingForAdmin
                | PairingUiPhase::HelperRunning
        ));
        Self {
            phase,
            failure: None,
            started_at,
            terminal_at: None,
        }
    }

    pub fn finished(started_at: Instant, terminal_at: Instant) -> Self {
        Self {
            phase: PairingUiPhase::Finished,
            failure: None,
            started_at,
            terminal_at: Some(terminal_at),
        }
    }

    pub fn failure(failure: PairingFailure, started_at: Instant, terminal_at: Instant) -> Self {
        Self {
            phase: PairingUiPhase::Failed,
            failure: Some(failure),
            started_at,
            terminal_at: Some(terminal_at),
        }
    }

    fn view(self) -> PairingView {
        pairing_view(self.phase, self.failure)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePairingStarter;

impl PairingStarter for UnavailablePairingStarter {
    fn available(&self) -> bool {
        false
    }

    fn start(&self) -> Result<Box<dyn PairingAttemptHandle>, PairingFailure> {
        Err(PairingFailure::Unavailable)
    }
}

/// Production default for targets without a connected service owner. It never
/// invents absent services, devices, approvals or successful mutations.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailablePlatformAdapter;

impl PlatformAdapter for UnavailablePlatformAdapter {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn control_service(
        &self,
        _action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionIntent {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlProgress {
    Idle,
    StillRunning,
    CompletionUnknown,
}

/// One native runtime and exclusive notification-preference writer.
///
/// Initialization and snapshots never invoke service mutation or elevation.
/// No request, pairing registry or activity owner is connected yet; those
/// collections always carry explicit `unavailable`, not known-empty, metadata.
/// No lifecycle state is proof of authenticated remote-request readiness.
pub struct AppRuntime {
    storage: PreferenceStore,
    policy: NotificationPolicy,
    platform: Platform,
    computer_name: String,
    adapter: Box<dyn PlatformAdapter>,
    last_service: Option<ServiceView>,
    last_management: Option<ManagementObservation>,
    confirmed_relay_configured: bool,
    service_issue: Option<AppIssue>,
    mobile: MobileReadiness,
    control_progress: ControlProgress,
    pairing_starter: Box<dyn PairingStarter>,
    pairing_attempt: Option<Box<dyn PairingAttemptHandle>>,
}

impl fmt::Debug for AppRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppRuntime")
            .field("platform", &self.platform)
            .field("control_progress", &self.control_progress)
            .finish_non_exhaustive()
    }
}

impl AppRuntime {
    /// The host supplies the target, actual OS computer display name (Windows
    /// only) and native adapter. No constructor argument is a frontend setting.
    /// Opens only the local preference writer; it performs no native service
    /// query until `snapshot`, and no service mutation until `control_service`.
    pub fn open(
        directory: AppPrivateDirectory,
        platform: Platform,
        computer_name: Option<&str>,
        adapter: Box<dyn PlatformAdapter>,
    ) -> Result<Self, AppIssue> {
        let pairing_starter: Box<dyn PairingStarter> = {
            #[cfg(all(windows, target_pointer_width = "64"))]
            {
                if platform == Platform::Windows {
                    Box::new(crate::WindowsPairingStarter)
                } else {
                    Box::new(UnavailablePairingStarter)
                }
            }
            #[cfg(not(all(windows, target_pointer_width = "64")))]
            {
                Box::new(UnavailablePairingStarter)
            }
        };
        Self::open_with_pairing(directory, platform, computer_name, adapter, pairing_starter)
    }

    /// Explicit pairing seam for the Windows host and portable unit tests.
    pub fn open_with_pairing(
        directory: AppPrivateDirectory,
        platform: Platform,
        computer_name: Option<&str>,
        adapter: Box<dyn PlatformAdapter>,
        pairing_starter: Box<dyn PairingStarter>,
    ) -> Result<Self, AppIssue> {
        let (storage, policy) = PreferenceStore::open(directory).map_err(AppIssue::from)?;
        Ok(Self {
            storage,
            policy,
            platform,
            computer_name: display_computer_name(platform, computer_name),
            adapter,
            last_service: None,
            last_management: None,
            confirmed_relay_configured: false,
            service_issue: None,
            mobile: MobileReadiness::UNAVAILABLE,
            control_progress: ControlProgress::Idle,
            pairing_starter,
            pairing_attempt: None,
        })
    }

    /// Refresh read-only service observations. A failed read preserves labelled
    /// stale information with every stale service action disabled, or `None` if
    /// no successful observation exists. It never means `NotInstalled`.
    pub fn snapshot(&mut self) -> AppSnapshot {
        if self.platform == Platform::Windows {
            match self.adapter.observe_service() {
                Ok(observation) => self.accept_service_and_management(observation),
                Err(error) => {
                    let stale = self.last_service.is_some();
                    let management_was_current = self.last_management.is_some();
                    self.last_management = None;
                    if management_was_current {
                        self.confirmed_relay_configured = false;
                    }
                    if let Some(service) = &mut self.last_service {
                        service.allowed_actions.clear();
                        service.remote_requests_ready = false;
                    }
                    self.service_issue = Some(if stale {
                        AppIssue {
                            code: "service_status_stale",
                            message: "휴대폰 승인의 현재 상태를 확인하지 못했습니다. 이전 상태를 표시합니다.",
                            next_action: Some("새로고침해 현재 상태를 확인해 주세요."),
                        }
                    } else {
                        error.into()
                    });
                }
            }
        }
        self.present()
    }

    /// Policy construction/decoding is validated by notification-policy and the
    /// bounded strict decoder. In-memory saved state changes only after disk
    /// replacement succeeds; an error leaves the previous policy untouched.
    pub fn save_policy(&mut self, policy: NotificationPolicy) -> Result<AppSnapshot, AppIssue> {
        self.storage.save(&policy).map_err(AppIssue::from)?;
        self.policy = policy;
        Ok(self.snapshot())
    }

    /// Explicit user command only; ROOT must invoke it off the UI thread.
    /// Native helper validation runs independently of `allowedActions`.
    pub fn control_service(&mut self, action: ServiceAction) -> Result<AppSnapshot, AppIssue> {
        if self.platform != Platform::Windows {
            return Err(PlatformError::Unsupported.into());
        }
        if let Some(issue) = self.progress_issue() {
            return Err(issue);
        }
        let before = self.snapshot();
        if let Some(issue) = before.issue {
            return Err(issue);
        }
        let service = before
            .service
            .as_ref()
            .ok_or_else(|| AppIssue::from(PlatformError::StatusUnavailable))?;
        if service.control_hint != ControlHint::Available {
            return Err(AppIssue {
                code: "service_installer_required",
                message: "휴대폰 승인을 켜고 끄는 데 필요한 파일이 설치되지 않아 작업을 시작하지 않았습니다.",
                next_action: Some("Windows 설치 프로그램으로 앱을 설치해 주세요."),
            });
        }
        if !service.allowed_actions.contains(&action) {
            return Err(AppIssue {
                code: "service_action_unavailable",
                message: "휴대폰 승인의 현재 상태에서는 이 작업을 시작할 수 없습니다.",
                next_action: Some("새로고침해 현재 상태를 확인해 주세요."),
            });
        }
        match self
            .adapter
            .control_service(action)
            .map_err(AppIssue::from)?
        {
            // Cancellation is not failure or success. Return the exact observed
            // pre-command snapshot, without a speculative mutation or refresh.
            ServiceCommandOutcome::UserCancelled => Ok(before),
            ServiceCommandOutcome::Completed { observation } => {
                self.accept_service_and_management(observation);
                Ok(self.present())
            }
            ServiceCommandOutcome::StillRunning => {
                self.control_progress = ControlProgress::StillRunning;
                self.disable_service_actions();
                Ok(self.present())
            }
            ServiceCommandOutcome::CompletionStatusUnknown => {
                self.control_progress = ControlProgress::CompletionUnknown;
                self.disable_service_actions();
                Ok(self.present())
            }
            ServiceCommandOutcome::HelperFailed => {
                self.disable_service_actions();
                self.service_issue = Some(AppIssue {
                    code: "service_helper_failed",
                    message: "휴대폰 승인 설정을 변경하는 작업을 완료하지 못했습니다.",
                    next_action: Some("새로고침한 뒤 휴대폰 승인의 설치 상태를 확인해 주세요."),
                });
                Ok(self.present())
            }
        }
    }

    /// Trusted Rust/Kotlin lifecycle input only. Do not register this method as
    /// a Tauri command. It reports OS readiness, never authentication or approval.
    pub fn update_mobile_readiness_from_native(
        &mut self,
        readiness: MobileReadiness,
    ) -> Result<(), AppIssue> {
        if self.platform != Platform::Android {
            return Err(AppIssue {
                code: "mobile_readiness_unsupported",
                message: "이 기기에서는 휴대폰 잠금 상태를 확인할 수 없습니다.",
                next_action: Some("Android 휴대폰에서 앱을 열어 주세요."),
            });
        }
        self.mobile = readiness;
        Ok(())
    }

    pub fn begin_pairing(&mut self) -> Result<AppSnapshot, AppIssue> {
        if self.platform != Platform::Windows {
            return Err(pairing_issue(PairingFailure::Unavailable));
        }
        if self
            .pairing_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.state().terminal_at.is_none())
        {
            return Err(AppIssue {
                code: "pairing_in_progress",
                message: "휴대폰 연결이 이미 진행 중이에요.",
                next_action: Some("진행 중인 연결 절차가 끝날 때까지 기다려 주세요."),
            });
        }
        if let Some(mut retained) = self.pairing_attempt.take() {
            retained.cancel();
            let _ = retained.join_until(Instant::now() + Duration::from_millis(250));
        }
        let observation = self
            .adapter
            .observe_service()
            .map_err(|_| service_not_ready())?;
        self.accept_service_and_management(observation);
        if observation.state != ObservedServiceState::Installed(ServiceState::Running)
            || observation.control != Ok(ControlHint::Available)
            || !self.pairing_starter.available()
        {
            return Err(service_not_ready());
        }
        self.pairing_attempt = Some(self.pairing_starter.start().map_err(pairing_issue)?);
        Ok(self.present())
    }

    pub fn remove_device(&mut self, device_id: &str) -> Result<AppSnapshot, AppIssue> {
        if self.platform != Platform::Windows {
            return Err(crate::UnwiredCapability::Unpairing.issue());
        }
        let device_id = parse_device_id(device_id).ok_or_else(invalid_device_issue)?;
        let before = self.snapshot();
        if let Some(issue) = before.issue {
            return Err(issue);
        }
        let device_exists = self.last_management.as_ref().is_some_and(|management| {
            management
                .devices
                .iter()
                .any(|device| device.id == device_id)
        });
        if !before.can_unpair || !device_exists {
            return Err(AppIssue {
                code: "device_removal_unavailable",
                message: "현재 휴대폰 목록에서는 이 휴대폰을 제거할 수 없습니다.",
                next_action: Some("목록을 새로 확인한 뒤 다시 시도해 주세요."),
            });
        }
        self.adapter
            .remove_device(&device_id)
            .map_err(|_| management_mutation_issue())?;
        self.refresh_after_running_management_mutation()
    }

    pub fn set_relay(&mut self, address: &str) -> Result<AppSnapshot, AppIssue> {
        if self.platform != Platform::Windows {
            return Err(PlatformError::Unsupported.into());
        }
        let address = parse_relay_address(address).ok_or_else(invalid_relay_issue)?;
        let before = self.snapshot();
        if let Some(issue) = before.issue {
            return Err(issue);
        }
        let service = before
            .service
            .as_ref()
            .ok_or_else(|| AppIssue::from(PlatformError::StatusUnavailable))?;
        if service.control_hint != ControlHint::Available
            || !matches!(
                (service.installed, service.state),
                (false, None) | (true, Some(ServiceState::Stopped | ServiceState::Running))
            )
        {
            return Err(AppIssue {
                code: "relay_change_unavailable",
                message: "휴대폰 승인의 현재 상태에서는 중계 서버 주소를 저장할 수 없습니다.",
                next_action: Some("상태를 새로 확인한 뒤 다시 시도해 주세요."),
            });
        }
        self.adapter
            .set_relay(&address.to_string())
            .map_err(|_| management_mutation_issue())?;
        if service.state == Some(ServiceState::Running) {
            self.refresh_after_running_management_mutation()
        } else {
            self.confirmed_relay_configured = true;
            Ok(before_with_relay(before))
        }
    }

    fn refresh_after_running_management_mutation(&mut self) -> Result<AppSnapshot, AppIssue> {
        let observation = self
            .adapter
            .observe_service()
            .map_err(|_| management_query_issue())?;
        self.accept_service_and_management(observation);
        let snapshot = self.present();
        if let Some(issue) = snapshot.issue {
            Err(issue)
        } else {
            Ok(snapshot)
        }
    }

    pub fn decide(
        &mut self,
        _request_id: &str,
        _decision: DecisionIntent,
    ) -> Result<AppSnapshot, AppIssue> {
        Err(crate::UnwiredCapability::Decisions.issue())
    }

    pub fn read_activity(&self) -> Result<Vec<ActivityView>, AppIssue> {
        Err(activity_unavailable())
    }

    pub fn clear_activity(&mut self) -> Result<AppSnapshot, AppIssue> {
        Err(activity_unavailable())
    }

    fn accept_service_and_management(&mut self, observation: ServiceObservation) {
        self.accept_service_observation(observation);
        if observation.state != ObservedServiceState::Installed(ServiceState::Running) {
            self.last_management = None;
            return;
        }
        match self
            .adapter
            .observe_management()
            .and_then(validate_management)
        {
            Ok(management) => {
                self.last_management = Some(management);
            }
            Err(_) => {
                // The device list is unavailable; pairing and service control keep
                // their own paths, so this is not a service-wide issue.
                self.last_management = None;
            }
        }
    }

    fn accept_service_observation(&mut self, observation: ServiceObservation) {
        let control_hint = observation.control.unwrap_or(ControlHint::NeedsInstaller);
        self.service_issue = observation.control.err().map(Into::into);
        let (installed, state) = match observation.state {
            ObservedServiceState::NotInstalled => (false, None),
            ObservedServiceState::Installed(state) => (true, Some(state)),
        };
        self.last_service = Some(ServiceView {
            installed,
            state,
            allowed_actions: if control_hint == ControlHint::Available
                && self.control_progress == ControlProgress::Idle
            {
                allowed_actions(observation.state)
            } else {
                Vec::new()
            },
            control_hint,
            remote_requests_ready: false,
        });
    }

    fn disable_service_actions(&mut self) {
        if let Some(service) = &mut self.last_service {
            service.allowed_actions.clear();
            service.remote_requests_ready = false;
        }
    }

    fn progress_issue(&self) -> Option<AppIssue> {
        match self.control_progress {
            ControlProgress::Idle => None,
            ControlProgress::StillRunning => Some(AppIssue {
                code: "service_control_pending",
                message: "휴대폰 승인 설정 변경이 아직 진행 중일 수 있습니다. 완료 여부는 확인되지 않았습니다.",
                next_action: Some("Windows에서 작업이 끝난 것을 확인한 뒤 앱을 다시 열어 주세요."),
            }),
            ControlProgress::CompletionUnknown => Some(AppIssue {
                code: "service_control_completion_unknown",
                message: "휴대폰 승인 설정 변경이 끝났는지 확인하지 못했습니다.",
                next_action: Some("Windows에서 작업 상태를 확인한 뒤 앱을 다시 열어 주세요."),
            }),
        }
    }

    fn pairing_view(&mut self) -> Option<PairingView> {
        let state = self
            .pairing_attempt
            .as_ref()
            .map(|attempt| attempt.state())?;
        if state.terminal_at.is_some_and(|terminal| {
            Instant::now().saturating_duration_since(terminal) >= Duration::from_secs(60)
        }) {
            self.pairing_attempt = None;
            None
        } else {
            Some(state.view())
        }
    }

    fn present(&mut self) -> AppSnapshot {
        let pairing = self.pairing_view();
        let progress_issue = self.progress_issue().map(|mut issue| {
            if self.service_issue.is_some_and(|status| status.code == "service_status_stale") {
                issue.message = "휴대폰 승인의 현재 상태를 확인하지 못했습니다. 이전 상태를 표시하며 설정 변경이 끝났는지도 확인되지 않았습니다.";
            }
            issue
        });
        let issue = progress_issue.or(self.service_issue).or_else(|| {
            (self.platform == Platform::Android
                && self.mobile.screen_lock == ScreenLockState::Unavailable)
                .then_some(AppIssue {
                    code: "mobile_readiness_unavailable",
                    message: "휴대폰 잠금 상태를 아직 확인하지 못했습니다.",
                    next_action: Some("앱을 다시 열어 휴대폰 상태를 확인해 주세요."),
                })
        });
        let management_running = self.last_service.as_ref().is_some_and(|service| {
            service.state == Some(ServiceState::Running) && self.last_management.is_some()
        });
        let devices = self
            .last_management
            .as_ref()
            .filter(|_| management_running)
            .map(|management| {
                management
                    .devices
                    .iter()
                    .map(management_device_view)
                    .collect()
            })
            .unwrap_or_default();
        let mut data_availability = DataAvailability::UNAVAILABLE;
        if management_running {
            data_availability.devices = crate::Availability::Available;
        }
        AppSnapshot {
            schema_version: 4,
            platform: self.platform,
            computer_name: self.computer_name.clone(),
            service: self.last_service.clone(),
            phone_service: None,
            mobile: (self.platform == Platform::Android).then_some(self.mobile),
            policy: Some(self.policy.clone()),
            relay_configured: if self
                .last_service
                .as_ref()
                .is_some_and(|service| service.state == Some(ServiceState::Running))
            {
                self.last_management
                    .as_ref()
                    .is_some_and(|management| management.relay_configured)
            } else {
                self.confirmed_relay_configured
            },
            devices,
            requests: Vec::new(),
            request_catalog: None,
            request_review: None,
            activity: Vec::new(),
            data_availability,
            pairing,
            can_pair: self.platform == Platform::Windows
                && self.last_service.as_ref().is_some_and(|service| {
                    service.state == Some(ServiceState::Running)
                        && service.control_hint == ControlHint::Available
                })
                && self.service_issue.is_none()
                && self
                    .pairing_attempt
                    .as_ref()
                    .is_none_or(|attempt| attempt.state().terminal_at.is_some())
                && self.pairing_starter.available(),
            can_unpair: management_running
                && self.service_issue.is_none()
                && self
                    .last_service
                    .as_ref()
                    .is_some_and(|service| service.control_hint == ControlHint::Available)
                && !self
                    .last_management
                    .as_ref()
                    .is_none_or(|management| management.devices.is_empty()),
            can_clear_activity: false,
            issue,
        }
    }
}

fn validate_management(
    observation: ManagementObservation,
) -> Result<ManagementObservation, PlatformError> {
    let mut ids = BTreeSet::new();
    for device in &observation.devices {
        if device.revision == 0
            || parse_device_id(&device.id).is_none()
            || !ids.insert(device.id.as_str())
        {
            return Err(PlatformError::StatusUnavailable);
        }
    }
    Ok(observation)
}

fn parse_device_id(value: &str) -> Option<String> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || value.bytes().all(|byte| byte == b'0')
    {
        return None;
    }
    Some(value.to_owned())
}

fn parse_relay_address(value: &str) -> Option<SocketAddr> {
    if value.is_empty() || value.len() > 80 {
        return None;
    }
    let address = value.parse::<SocketAddr>().ok()?;
    if address.port() == 0 || address.ip().is_unspecified() {
        return None;
    }
    if let SocketAddr::V6(address) = address
        && invalid_ipv6_relay(address)
    {
        return None;
    }
    Some(address)
}

fn invalid_ipv6_relay(address: SocketAddrV6) -> bool {
    address.flowinfo() != 0 || address.scope_id() != 0 || address.ip().to_ipv4_mapped().is_some()
}

fn management_device_view(device: &ManagementDevice) -> crate::PairedDeviceView {
    crate::PairedDeviceView {
        id: device.id.clone(),
        name: format!("{}번 휴대폰", &device.id[..8]),
        revision: device.revision,
        route_present: device.route_present,
        connected: device.connected,
        last_seen_label: None,
    }
}

fn before_with_relay(mut snapshot: AppSnapshot) -> AppSnapshot {
    snapshot.relay_configured = true;
    snapshot
}

fn invalid_device_issue() -> AppIssue {
    AppIssue {
        code: "invalid_device_id",
        message: "휴대폰 정보를 읽지 못했습니다.",
        next_action: Some("목록을 새로 확인한 뒤 다시 시도해 주세요."),
    }
}

fn invalid_relay_issue() -> AppIssue {
    AppIssue {
        code: "invalid_relay_address",
        message: "중계 서버 주소를 숫자 IP 주소와 포트로 입력해 주세요.",
        next_action: Some("예: 192.0.2.10:443 또는 [2001:db8::10]:443"),
    }
}

fn management_query_issue() -> AppIssue {
    AppIssue {
        code: "service_management_unavailable",
        message: "연결된 휴대폰 정보를 확인하지 못했습니다.",
        next_action: Some("휴대폰 승인 상태를 확인한 뒤 새로고침해 주세요."),
    }
}

fn management_mutation_issue() -> AppIssue {
    AppIssue {
        code: "service_management_failed",
        message: "요청한 설정을 변경하지 못했습니다.",
        next_action: Some("현재 상태를 새로 확인한 뒤 다시 시도해 주세요."),
    }
}

impl Drop for AppRuntime {
    fn drop(&mut self) {
        let Some(attempt) = self.pairing_attempt.as_mut() else {
            return;
        };
        if attempt.state().terminal_at.is_none() {
            attempt.cancel();
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        let _ = attempt.join_until(deadline);
    }
}

fn service_not_ready() -> AppIssue {
    AppIssue {
        code: "service_not_ready",
        message: "먼저 PC에서 휴대폰 승인을 켜 주세요.",
        next_action: Some("휴대폰 승인을 켠 뒤 다시 시도해 주세요."),
    }
}

fn pairing_issue(failure: PairingFailure) -> AppIssue {
    match failure {
        PairingFailure::ServiceNotReady => service_not_ready(),
        PairingFailure::UserCancelled => AppIssue {
            code: "pairing_user_cancelled",
            message: "관리자 확인을 취소했어요.",
            next_action: Some("연결하려면 다시 시도해 주세요."),
        },
        PairingFailure::HelperFailed => AppIssue {
            code: "pairing_helper_failed",
            message: "연결 절차가 중단됐어요. 다시 시도해 주세요.",
            next_action: Some("잠시 뒤 다시 시도해 주세요."),
        },
        PairingFailure::Timeout => AppIssue {
            code: "pairing_timeout",
            message: "연결 시간이 지났어요. 다시 시도해 주세요.",
            next_action: Some("연결을 다시 시작해 주세요."),
        },
        PairingFailure::RelayUnconfigured => AppIssue {
            code: "pairing_relay_unconfigured",
            message: "중계 서버 주소를 먼저 설정해 주세요.",
            next_action: Some("관리자에게 중계 서버 설정을 요청해 주세요."),
        },
        PairingFailure::Unavailable => AppIssue {
            code: "pairing_unavailable",
            message: "지금은 연결을 시작할 수 없어요.",
            next_action: Some("잠시 뒤 다시 시도해 주세요."),
        },
    }
}

fn pairing_view(phase: PairingUiPhase, failure: Option<PairingFailure>) -> PairingView {
    match phase {
        PairingUiPhase::Connecting => PairingView {
            phase: "connecting",
            message: "PC의 휴대폰 승인에 연결하고 있어요.".to_owned(),
            failure: None,
        },
        PairingUiPhase::WaitingForAdmin => PairingView {
            phase: "waiting_for_admin",
            message: "관리자 확인 창에서 [예]를 눌러 주세요.".to_owned(),
            failure: None,
        },
        PairingUiPhase::HelperRunning => PairingView {
            phase: "helper_running",
            message: "PC 화면의 연결 안내를 따라 주세요. 휴대폰 승인 앱에서 QR을 읽고 여섯 자리 숫자를 비교합니다."
                .to_owned(),
            failure: None,
        },
        PairingUiPhase::Finished => PairingView {
            phase: "finished",
            message: "연결 절차가 끝났어요. 잠시 뒤 목록에서 휴대폰을 확인해 주세요."
                .to_owned(),
            failure: None,
        },
        PairingUiPhase::Failed => pairing_failure_view(failure.unwrap_or(PairingFailure::Unavailable)),
    }
}

fn pairing_failure_view(failure: PairingFailure) -> PairingView {
    let (message, code) = match failure {
        PairingFailure::ServiceNotReady => {
            ("PC의 휴대폰 승인이 준비되지 않았어요.", "service_not_ready")
        }
        PairingFailure::UserCancelled => ("관리자 확인을 취소했어요.", "user_cancelled"),
        PairingFailure::HelperFailed => (
            "연결 절차가 중단됐어요. 다시 시도해 주세요.",
            "helper_failed",
        ),
        PairingFailure::Timeout => ("연결 시간이 지났어요. 다시 시도해 주세요.", "timeout"),
        PairingFailure::RelayUnconfigured => {
            ("중계 서버 주소를 먼저 설정해 주세요.", "relay_unconfigured")
        }
        PairingFailure::Unavailable => ("지금은 연결을 시작할 수 없어요.", "unavailable"),
    };
    PairingView {
        phase: "failed",
        message: message.to_owned(),
        failure: Some(code),
    }
}

fn allowed_actions(state: ObservedServiceState) -> Vec<ServiceAction> {
    match state {
        ObservedServiceState::NotInstalled => vec![ServiceAction::Install],
        ObservedServiceState::Installed(ServiceState::Stopped) => {
            vec![ServiceAction::Start, ServiceAction::Uninstall]
        }
        ObservedServiceState::Installed(ServiceState::Running | ServiceState::Paused) => {
            vec![
                ServiceAction::Stop,
                ServiceAction::Restart,
                ServiceAction::Uninstall,
            ]
        }
        ObservedServiceState::Installed(
            ServiceState::StartPending
            | ServiceState::StopPending
            | ServiceState::ContinuePending
            | ServiceState::PausePending,
        ) => Vec::new(),
    }
}

fn activity_unavailable() -> AppIssue {
    crate::UnwiredCapability::Activity.issue()
}

fn display_computer_name(platform: Platform, supplied: Option<&str>) -> String {
    if platform != Platform::Windows {
        return String::new();
    }
    let Some(name) = supplied else {
        return String::new();
    };
    let name = name.trim();
    if name.len() > MAX_COMPUTER_NAME_BYTES || name.chars().count() > MAX_COMPUTER_NAME_CHARACTERS
        || name.chars().any(|character| character.is_control()
            || matches!(character, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}' | '\u{feff}')) {
        return String::new();
    }
    name.to_owned()
}
