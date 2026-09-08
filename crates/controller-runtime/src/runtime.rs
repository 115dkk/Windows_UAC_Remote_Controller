// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use notification_policy::NotificationPolicy;
use serde::{Deserialize, Serialize};

use crate::{
    ActivityView, AppIssue, AppPrivateDirectory, AppSnapshot, ControlHint, DataAvailability,
    MobileReadiness, Platform, ScreenLockState, ServiceAction, ServiceState, ServiceView,
    storage::PreferenceStore,
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
                message: "이 기기에서는 Windows 서비스를 관리할 수 없습니다.",
                next_action: Some("Windows PC에서 앱을 열어 주세요."),
            },
            PlatformError::StatusUnavailable => Self {
                code: "service_status_unavailable",
                message: "Windows 서비스 상태를 확인하지 못했습니다.",
                next_action: Some("PC의 설치 상태를 확인한 뒤 새로고침해 주세요."),
            },
            PlatformError::HelperUnavailable => Self {
                code: "service_helper_unavailable",
                message: "Windows 서비스 관리 도구를 확인하지 못했습니다.",
                next_action: Some("설치 프로그램으로 앱의 설치 상태를 확인해 주세요."),
            },
            PlatformError::ControlFailed => Self {
                code: "service_control_failed",
                message: "요청한 서비스 작업이 완료됐는지 확인하지 못했습니다.",
                next_action: Some("서비스 상태를 새로고침한 뒤 설치 상태를 확인해 주세요."),
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
    fn control_service(
        &self,
        action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError>;
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
    service_issue: Option<AppIssue>,
    mobile: MobileReadiness,
    control_progress: ControlProgress,
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
        let (storage, policy) = PreferenceStore::open(directory).map_err(AppIssue::from)?;
        Ok(Self {
            storage,
            policy,
            platform,
            computer_name: display_computer_name(platform, computer_name),
            adapter,
            last_service: None,
            service_issue: None,
            mobile: MobileReadiness::UNAVAILABLE,
            control_progress: ControlProgress::Idle,
        })
    }

    /// Refresh read-only service observations. A failed read preserves labelled
    /// stale information with every stale service action disabled, or `None` if
    /// no successful observation exists. It never means `NotInstalled`.
    pub fn snapshot(&mut self) -> AppSnapshot {
        if self.platform == Platform::Windows {
            match self.adapter.observe_service() {
                Ok(observation) => self.accept_service_observation(observation),
                Err(error) => {
                    let stale = self.last_service.is_some();
                    if let Some(service) = &mut self.last_service {
                        service.allowed_actions.clear();
                        service.remote_requests_ready = false;
                    }
                    self.service_issue = Some(if stale {
                        AppIssue {
                            code: "service_status_stale",
                            message: "서비스 상태를 새로 확인하지 못해 이전 상태를 표시합니다.",
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
                message: "서비스 관리 도구가 설치되어 있지 않아 작업을 시작하지 않았습니다.",
                next_action: Some("Windows 설치 프로그램으로 앱을 설치해 주세요."),
            });
        }
        if !service.allowed_actions.contains(&action) {
            return Err(AppIssue {
                code: "service_action_unavailable",
                message: "현재 서비스 상태에서는 이 작업을 시작할 수 없습니다.",
                next_action: Some("서비스 상태를 새로고침해 주세요."),
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
                self.accept_service_observation(observation);
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
                    message: "서비스 관리 도구가 작업을 완료하지 못했습니다.",
                    next_action: Some("서비스 상태를 새로고침한 뒤 설치 상태를 확인해 주세요."),
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
        Err(crate::UnwiredCapability::Pairing.issue())
    }

    pub fn remove_device(&mut self, _device_id: &str) -> Result<AppSnapshot, AppIssue> {
        Err(crate::UnwiredCapability::Unpairing.issue())
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
            // A real request/identity/transport owner is not connected. No SCM
            // lifecycle or native capability-development flag proves readiness.
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
                message: "서비스 관리 도구가 아직 실행 중일 수 있습니다. 완료 여부는 확인되지 않았습니다.",
                next_action: Some("Windows에서 작업이 끝난 것을 확인한 뒤 앱을 다시 열어 주세요."),
            }),
            ControlProgress::CompletionUnknown => Some(AppIssue {
                code: "service_control_completion_unknown",
                message: "서비스 작업의 완료 여부를 확인하지 못했습니다.",
                next_action: Some("Windows에서 작업 상태를 확인한 뒤 앱을 다시 열어 주세요."),
            }),
        }
    }

    fn present(&self) -> AppSnapshot {
        let progress_issue = self.progress_issue().map(|mut issue| {
            if self.service_issue.is_some_and(|status| status.code == "service_status_stale") {
                issue.message = "서비스 상태를 새로 확인하지 못해 이전 상태를 표시합니다. 관리 도구의 완료 여부도 확인되지 않았습니다.";
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
        AppSnapshot {
            schema_version: 1,
            platform: self.platform,
            computer_name: self.computer_name.clone(),
            service: self.last_service.clone(),
            mobile: (self.platform == Platform::Android).then_some(self.mobile),
            policy: self.policy.clone(),
            devices: Vec::new(),
            requests: Vec::new(),
            activity: Vec::new(),
            data_availability: DataAvailability::UNAVAILABLE,
            can_pair: false,
            can_unpair: false,
            can_clear_activity: false,
            issue,
        }
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
