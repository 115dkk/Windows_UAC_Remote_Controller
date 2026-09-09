// SPDX-License-Identifier: GPL-2.0-or-later
//! Dormant, OS-guarded service-only supervisor. No CLI/Tauri/runtime auto hook.
#![forbid(unsafe_code)]
use std::fmt;
pub use windows_prompt_probe::supervision::ReportOutcome;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchPrivilege {
    Tcb,
    IncreaseQuota,
    AssignPrimaryToken,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorStage {
    ServiceConfiguration,
    TokenQuery,
    DuplicateOwnToken,
    SetSession,
    SessionQuery,
    CreateJob,
    CreateChild,
    AssignJob,
    CreatePipe,
    ConnectPipe,
    AuthenticatePeer,
    ChallengeWrite,
    ReportRead,
    EofRead,
    ChildWait,
    TerminateChild,
    CancelIo,
    CleanupWait,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum ProbeSupervisorError {
    UnsupportedPlatform,
    Busy,
    NotRunningService,
    ImpersonationPresent,
    ServiceConfiguration,
    RequiredPrivilegeNotEnabled(LaunchPrivilege),
    RestrictedTokenMismatch,
    UnsupportedToken,
    ProtectedHelperUnavailable,
    NoInteractiveSession,
    AmbiguousSessions,
    SessionChanged,
    SessionObservationUnsupported,
    EntropyUnavailable,
    PeerMismatch,
    InvalidReport,
    HelperFailed(u32),
    TimedOut,
    CleanupUnconfirmed,
    Quarantined,
    Native {
        stage: SupervisorStage,
        hresult: i32,
    },
}
impl fmt::Display for ProbeSupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProbeSupervisorError {}

/// One thread-affine supervisor for the actual running protected service.
/// No target/path/session/command is accepted. All launch facts are re-observed
/// per run. Unconfirmed termination/cancellation retains and quarantines owners.
pub struct ServiceProbeSupervisor {
    #[cfg(all(windows, target_pointer_width = "64"))]
    inner: crate::ffi::probe_supervisor::Supervisor,
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    _unconstructible: std::convert::Infallible,
}
impl fmt::Debug for ServiceProbeSupervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceProbeSupervisor(owned_service_only)")
    }
}
impl ServiceProbeSupervisor {
    pub fn for_running_service() -> Result<Self, ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            Ok(Self {
                inner: crate::ffi::probe_supervisor::Supervisor::new()?,
            })
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }
    pub fn probe_once(&mut self) -> Result<ReportOutcome, ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.inner.run()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }
    /// Retry only cleanup of this supervisor's existing child/I/O, never launch.
    pub fn retry_cleanup(&mut self) -> Result<(), ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.inner.retry_cleanup()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }
    pub fn is_quarantined(&self) -> bool {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.inner.is_quarantined()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            false
        }
    }
    /// Original fixed failure retained while a later cleanup failure is returned.
    /// No path, token, endpoint, challenge or process handle is exposed.
    pub fn quarantined_cause(&self) -> Option<ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.inner.quarantined_cause()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            None
        }
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) fn wait_slice(elapsed: std::time::Duration) -> Result<u32, ProbeSupervisorError> {
    let remaining =
        std::time::Duration::from_millis(windows_prompt_probe::SUPERVISOR_BUDGET_MILLIS)
            .checked_sub(elapsed)
            .ok_or(ProbeSupervisorError::TimedOut)?;
    if remaining.is_zero() {
        return Err(ProbeSupervisorError::TimedOut);
    }
    Ok(remaining.as_millis().clamp(1, 50) as u32)
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) fn quoted_image_command_line(image: &[u16]) -> Result<Vec<u16>, ProbeSupervisorError> {
    // A fixed protected filename only, never arbitrary arguments. The Windows
    // API uses an unquoted application name as command line when it is null;
    // quote argv[0] explicitly so Program Files/translated folder spaces stay
    // inside the single module token expected by the argument-free helper.
    if image.len() < 2
        || image.len() > 1024
        || image.last() != Some(&0)
        || image[..image.len() - 1]
            .iter()
            .any(|unit| *unit < 32 || *unit == u16::from(b'"'))
    {
        return Err(ProbeSupervisorError::ProtectedHelperUnavailable);
    }
    let mut command = Vec::with_capacity(image.len() + 2);
    command.push(u16::from(b'"'));
    command.extend_from_slice(&image[..image.len() - 1]);
    command.push(u16::from(b'"'));
    command.push(0);
    Ok(command)
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) fn before_deadline<T>(
    elapsed: std::time::Duration,
    operation: impl FnOnce() -> T,
) -> Result<T, ProbeSupervisorError> {
    wait_slice(elapsed)?;
    Ok(operation())
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) fn unique_session(
    entries: impl Iterator<Item = (u32, bool)>,
) -> Result<u32, ProbeSupervisorError> {
    let mut selected = None;
    for (id, active) in entries {
        if id != 0 && active {
            if selected.is_some() {
                return Err(ProbeSupervisorError::AmbiguousSessions);
            }
            selected = Some(id);
        }
    }
    selected.ok_or(ProbeSupervisorError::NoInteractiveSession)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn public_entry_has_no_launch_or_target_inputs_and_is_never_called() {
        let _constructor: fn() -> Result<ServiceProbeSupervisor, ProbeSupervisorError> =
            ServiceProbeSupervisor::for_running_service;
        let _run: fn(&mut ServiceProbeSupervisor) -> Result<ReportOutcome, ProbeSupervisorError> =
            ServiceProbeSupervisor::probe_once;
        let _cleanup: fn(&mut ServiceProbeSupervisor) -> Result<(), ProbeSupervisorError> =
            ServiceProbeSupervisor::retry_cleanup;
        let _failure: fn(&ServiceProbeSupervisor) -> Option<ProbeSupervisorError> =
            ServiceProbeSupervisor::quarantined_cause;
        assert_eq!(
            crate::SERVICE_NAME,
            windows_prompt_probe::supervision::SERVICE_NAME
        );
        assert_eq!(
            crate::INSTALLATION_FOLDER,
            windows_prompt_probe::supervision::INSTALLATION_FOLDER
        );
        assert_eq!(
            crate::SERVICE_EXECUTABLE,
            windows_prompt_probe::supervision::SERVICE_EXECUTABLE
        );
    }
    #[test]
    fn synthetic_deadline_is_absolute_and_exact_boundary_is_expired() {
        assert_eq!(wait_slice(Duration::ZERO), Ok(50));
        assert_eq!(wait_slice(Duration::from_millis(4_990)), Ok(10));
        assert_eq!(wait_slice(Duration::from_micros(4_999_999)), Ok(1));
        assert_eq!(
            wait_slice(Duration::from_secs(5)),
            Err(ProbeSupervisorError::TimedOut)
        );
        assert_eq!(
            wait_slice(Duration::MAX),
            Err(ProbeSupervisorError::TimedOut)
        );
    }
    #[test]
    fn fixed_module_with_spaces_is_exactly_one_quoted_argv_token() {
        let module = r"C:\Program Files\휴대폰 승인\uac-prompt-probe.exe";
        let input: Vec<u16> = module.encode_utf16().chain([0]).collect();
        let quoted = quoted_image_command_line(&input).unwrap();
        assert_eq!(
            String::from_utf16(&quoted[..quoted.len() - 1]).unwrap(),
            format!("\"{module}\"")
        );
        for bad in [
            vec![],
            vec![0],
            vec![b'a' as u16],
            vec![b'a' as u16, 0, b'b' as u16, 0],
            vec![b'"' as u16, 0],
        ] {
            assert!(quoted_image_command_line(&bad).is_err());
        }
    }

    #[test]
    fn expired_post_setup_gate_never_issues_an_operation() {
        let mut issued = false;
        assert_eq!(
            before_deadline(Duration::from_secs(5), || {
                issued = true;
                1
            }),
            Err(ProbeSupervisorError::TimedOut)
        );
        assert!(!issued);
        assert_eq!(
            before_deadline(Duration::from_millis(4_999), || {
                issued = true;
                1
            }),
            Ok(1)
        );
        assert!(issued);
    }

    #[test]
    fn synthetic_native_session_selection_never_chooses_ambiguity_or_session_zero() {
        assert_eq!(
            unique_session([].into_iter()),
            Err(ProbeSupervisorError::NoInteractiveSession)
        );
        assert_eq!(
            unique_session([(0, true), (9, false)].into_iter()),
            Err(ProbeSupervisorError::NoInteractiveSession)
        );
        assert_eq!(
            unique_session([(0, true), (9, false), (4, true)].into_iter()),
            Ok(4)
        );
        assert_eq!(
            unique_session([(1, true), (4, true)].into_iter()),
            Err(ProbeSupervisorError::AmbiguousSessions)
        );
        assert_eq!(
            unique_session([(1, true), (1, true)].into_iter()),
            Err(ProbeSupervisorError::AmbiguousSessions)
        );
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    #[test]
    fn unsupported_target_never_constructs_a_supervisor() {
        assert_eq!(
            ServiceProbeSupervisor::for_running_service().unwrap_err(),
            ProbeSupervisorError::UnsupportedPlatform
        );
    }
}
