// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]

use std::ffi::OsStr;
#[cfg(any(windows, test))]
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// CLI input has no freeform payload. Unknown arguments are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Status,
    Service,
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
    ProbeOnce,
    Help,
}

/// Presentation submits only one of these user intents. It does not supply a
/// boolean administrator claim, helper path or arbitrary command argument.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlIntent {
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
}

impl ServiceControlIntent {
    #[cfg(any(windows, test))]
    pub(crate) const fn argument(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ControlOutcome {
    UserCancelled,
    /// Windows launched the helper, but its bounded process wait expired.
    StillRunning,
    Completed {
        snapshot: ServiceSnapshot,
    },
    HelperFailed {
        exit_code: u32,
    },
    /// Helper exited successfully, but a subsequent read-only query failed.
    CompletionStatusUnknown,
}

impl Command {
    /// Input excludes argv[0]. No arguments means read-only status.
    pub fn parse<I, S>(arguments: I) -> Result<Self, ServiceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut arguments = arguments.into_iter();
        let Some(first) = arguments.next() else {
            return Ok(Self::Status);
        };
        if arguments.next().is_some() {
            return Err(ServiceError::InvalidArguments);
        }
        match first.as_ref().to_str() {
            Some("status") => Ok(Self::Status),
            Some("service") => Ok(Self::Service),
            Some("install") => Ok(Self::Install),
            Some("start") => Ok(Self::Start),
            Some("stop") => Ok(Self::Stop),
            Some("restart") => Ok(Self::Restart),
            Some("uninstall") => Ok(Self::Uninstall),
            Some("probe-once") => Ok(Self::ProbeOnce),
            Some("help" | "--help" | "-h") => Ok(Self::Help),
            _ => Err(ServiceError::InvalidArguments),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    NotInstalled,
    Installed,
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

/// These are development capability facts, never inferred from a running PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeCapabilities {
    pub windows_prompt_integration: bool,
    pub encrypted_phone_transport: bool,
    pub remote_approval: bool,
    pub credential_entry: bool,
}

impl RuntimeCapabilities {
    pub const UNIMPLEMENTED: Self = Self {
        windows_prompt_integration: false,
        encrypted_phone_transport: false,
        remote_approval: false,
        credential_entry: false,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceSnapshot {
    pub installation: InstallationState,
    pub state: Option<ServiceState>,
    pub process_id: Option<u32>,
    pub capabilities: RuntimeCapabilities,
}

impl ServiceSnapshot {
    #[cfg(any(windows, test))]
    pub(crate) const fn absent() -> Self {
        Self {
            installation: InstallationState::NotInstalled,
            state: None,
            process_id: None,
            capabilities: RuntimeCapabilities::UNIMPLEMENTED,
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn installed(state: ServiceState, process_id: Option<u32>) -> Self {
        Self {
            installation: InstallationState::Installed,
            state: Some(state),
            process_id: process_id.filter(|pid| *pid != 0 && state == ServiceState::Running),
            capabilities: RuntimeCapabilities::UNIMPLEMENTED,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    OpenManager,
    OpenService,
    QueryStatus,
    QueryConfiguration,
    QueryToken,
    KnownFolder,
    OpenProtectedPath,
    InspectProtectedPath,
    ReadSecurity,
    ResolveServiceSid,
    CreateService,
    HardenService,
    DeleteService,
    StartService,
    StopService,
    Dispatch,
    RegisterHandler,
    ReportStatus,
    LaunchElevatedHelper,
    WaitElevatedHelper,
    RequestProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupFailure {
    Windows {
        operation: ServiceOperation,
        code: u32,
    },
    UnsafePath,
    UnsafePermissions,
    Provisioning,
    Other,
}

/// Fixed categories and numeric codes only; no OS message, argument or path.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("this service operation is supported only on Windows")]
    UnsupportedPlatform,
    #[error("unsupported arguments; use uac-service help")]
    InvalidArguments,
    #[error("an elevated Windows administrator token is required")]
    ElevationRequired,
    #[error("Windows call failed at {operation:?} (code {code:#010x})")]
    WindowsCall {
        operation: ServiceOperation,
        code: u32,
    },
    #[error("Windows returned an unsupported service result at {0:?}")]
    UnsupportedResult(ServiceOperation),
    #[error("service identity or configuration does not match this product")]
    ConfigurationConflict,
    #[error("the executable is not in the required protected installation")]
    UntrustedInstallation,
    #[error("protected path validation rejected a reparse point or path alias")]
    UnsafePath,
    #[error("protected object owner or access control is unsupported or unsafe")]
    UnsafePermissions,
    #[error("the service is not installed")]
    NotInstalled,
    #[error("the service lifecycle operation exceeded its bounded deadline")]
    Timeout,
    #[error("the service stopped before the requested running state")]
    ServiceStopped,
    #[error("this service state cannot complete the requested operation")]
    UnexpectedState,
    #[error("installation preparation failed; the registration remains disabled: {reason:?}")]
    InstallationIncomplete { reason: SetupFailure },
    #[error("a pre-provisioned private activity directory is required")]
    JournalProvisioningRequired,
    #[error("activity journal operation failed; administrator recovery may be required")]
    JournalUnavailable,
    #[error("a pre-provisioned private device-registry directory is required")]
    RegistryProvisioningRequired,
    #[error("the device registry is unavailable; trusted recovery is required")]
    RegistryUnavailable,
    #[error("the device registry reached its bounded maintenance limit")]
    RegistryMaintenanceRequired,
    #[error("the service could not initialize its protected PC identity")]
    IdentityUnavailable,
    #[error("the service clock is outside the supported range")]
    InvalidClock,
    #[error("the service lifecycle worker failed")]
    WorkerFailed,
    #[error("the SCM dispatcher cannot be registered twice in one process")]
    AlreadyDispatched,
    #[error("status output could not be encoded or written")]
    OutputUnavailable,
    #[error("a read-only diagnostic probe is already pending or running")]
    ProbeBusy,
    #[error(
        "all eight fixed diagnostic slots are occupied; explicit operator recovery is required"
    )]
    ProbeSlotsFull,
    #[error("the read-only diagnostic owner or result storage is unavailable")]
    ProbeUnavailable,
}

impl ServiceError {
    /// Stable process exit classes, not raw OS text or truncated Windows codes.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArguments => 2,
            Self::ElevationRequired => 3,
            Self::UnsupportedPlatform => 4,
            Self::UnsafePath
            | Self::UnsafePermissions
            | Self::UntrustedInstallation
            | Self::ConfigurationConflict => 5,
            Self::Timeout => 6,
            Self::JournalProvisioningRequired | Self::JournalUnavailable => 7,
            Self::RegistryProvisioningRequired
            | Self::RegistryUnavailable
            | Self::RegistryMaintenanceRequired => 8,
            _ => 1,
        }
    }
}

#[cfg(windows)]
pub(crate) fn incomplete(error: ServiceError) -> ServiceError {
    let reason = match error {
        ServiceError::WindowsCall { operation, code } => SetupFailure::Windows { operation, code },
        ServiceError::UnsafePath => SetupFailure::UnsafePath,
        ServiceError::UnsafePermissions => SetupFailure::UnsafePermissions,
        ServiceError::JournalProvisioningRequired
        | ServiceError::JournalUnavailable
        | ServiceError::RegistryProvisioningRequired
        | ServiceError::RegistryUnavailable => SetupFailure::Provisioning,
        _ => SetupFailure::Other,
    };
    ServiceError::InstallationIncomplete { reason }
}

#[cfg(any(windows, test))]
pub(crate) const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(windows, test))]
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(any(windows, test))]
pub(crate) fn remaining_budget(elapsed: Duration) -> Result<Duration, ServiceError> {
    LIFECYCLE_TIMEOUT
        .checked_sub(elapsed)
        .filter(|left| !left.is_zero())
        .ok_or(ServiceError::Timeout)
}

/// Progress toward joining an already-pending worker must not grant a new
/// startup/shutdown budget. Only an unsolicited exit from Running begins one.
#[cfg(any(windows, test))]
pub(crate) fn continuing_pending_start(existing: Option<Instant>, now: Instant) -> Instant {
    existing.unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_read_only_and_mutations_are_explicit() {
        assert_eq!(Command::parse::<_, &str>([]), Ok(Command::Status));
        for (name, command) in [
            ("status", Command::Status),
            ("service", Command::Service),
            ("install", Command::Install),
            ("start", Command::Start),
            ("stop", Command::Stop),
            ("restart", Command::Restart),
            ("uninstall", Command::Uninstall),
        ] {
            assert_eq!(Command::parse([name]), Ok(command));
        }
    }

    #[test]
    fn arbitrary_payload_and_extra_arguments_are_rejected_without_retention() {
        for args in [
            vec!["approve"],
            vec!["install", "unexpected-input"],
            vec!["--program", "anything"],
            vec!["STATUS"],
            vec![""],
        ] {
            let error = Command::parse(args).unwrap_err();
            assert_eq!(error, ServiceError::InvalidArguments);
            assert!(!format!("{error:?}").contains("unexpected-input"));
        }
    }

    #[test]
    fn running_never_promises_uac_or_network_readiness() {
        let snapshot = ServiceSnapshot::installed(ServiceState::Running, Some(42));
        assert_eq!(snapshot.process_id, Some(42));
        assert_eq!(snapshot.capabilities, RuntimeCapabilities::UNIMPLEMENTED);
        let wire = serde_json::to_value(snapshot).unwrap();
        assert_eq!(wire["state"], "running");
        assert_eq!(wire["capabilities"]["remote_approval"], false);
    }

    #[test]
    fn absent_and_stopped_do_not_retain_a_pid() {
        assert_eq!(
            ServiceSnapshot::absent().installation,
            InstallationState::NotInstalled
        );
        assert_eq!(ServiceSnapshot::absent().state, None);
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::Stopped, Some(42)).process_id,
            None
        );
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::Running, Some(0)).process_id,
            None
        );
    }

    #[test]
    fn deadlines_are_strictly_bounded() {
        assert_eq!(remaining_budget(Duration::ZERO), Ok(LIFECYCLE_TIMEOUT));
        assert!(remaining_budget(LIFECYCLE_TIMEOUT - POLL_INTERVAL).is_ok());
        assert_eq!(
            remaining_budget(LIFECYCLE_TIMEOUT),
            Err(ServiceError::Timeout)
        );
        assert_eq!(remaining_budget(Duration::MAX), Err(ServiceError::Timeout));
    }

    #[test]
    fn worker_finished_progress_does_not_restart_a_pending_deadline() {
        let began = Instant::now();
        let almost_finished = began + LIFECYCLE_TIMEOUT - POLL_INTERVAL;
        let continued = continuing_pending_start(Some(began), almost_finished);
        assert_eq!(continued, began);
        assert_eq!(
            remaining_budget((began + LIFECYCLE_TIMEOUT).duration_since(continued)),
            Err(ServiceError::Timeout)
        );
        assert_eq!(
            continuing_pending_start(None, almost_finished),
            almost_finished
        );
    }

    #[test]
    fn elevation_intents_have_exactly_one_constant_cli_argument() {
        for intent in [
            ServiceControlIntent::Install,
            ServiceControlIntent::Start,
            ServiceControlIntent::Stop,
            ServiceControlIntent::Restart,
            ServiceControlIntent::Uninstall,
        ] {
            assert!(Command::parse([intent.argument()]).is_ok());
            assert!(!intent.argument().contains([' ', '\\', '/', '"']));
        }
        assert!(serde_json::from_str::<ServiceControlIntent>("\"execute\"").is_err());
        let pending = serde_json::to_value(ControlOutcome::StillRunning).unwrap();
        assert_eq!(pending["outcome"], "still_running");
        assert!(pending.get("snapshot").is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_claims_a_successful_mutation() {
        assert_eq!(
            crate::query_status(),
            Err(ServiceError::UnsupportedPlatform)
        );
        for operation in [
            crate::install,
            crate::start,
            crate::stop,
            crate::restart,
            crate::uninstall,
        ] {
            assert_eq!(operation(), Err(ServiceError::UnsupportedPlatform));
        }
        assert_eq!(
            crate::dispatch_service(),
            Err(ServiceError::UnsupportedPlatform)
        );
    }
}
