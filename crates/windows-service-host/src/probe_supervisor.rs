// SPDX-License-Identifier: GPL-2.0-or-later
//! Dormant, OS-guarded service-only supervisor. No CLI/Tauri/runtime auto hook.
#![forbid(unsafe_code)]
use std::fmt;
#[cfg(all(windows, target_pointer_width = "64"))]
use windows_prompt_probe::supervision::ServiceMessage;
pub use windows_prompt_probe::{
    ProbeReport, PromptAction,
    supervision::{ApplyOutcome, GoneReason, ReportOutcome, TargetIdentity},
};

#[cfg(all(windows, target_pointer_width = "64"))]
const MAX_WATCH_MESSAGES_PER_POLL: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchPrivilege {
    Tcb,
    IncreaseQuota,
    AssignPrimaryToken,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
impl LaunchPrivilege {
    /// Attribute policy only; the native owner still proves the actual token,
    /// exact privilege LUID, service identity and unchanged restrictions.
    /// CreateProcessAsUser temporarily enables its already-held privileges;
    /// the preceding TokenSessionId change requires Tcb already enabled.
    pub(crate) const fn accepts_attributes(self, attributes: Option<u32>) -> bool {
        const ENABLED: u32 = 0x2;
        const REMOVED: u32 = 0x4;
        let Some(attributes) = attributes else {
            return false;
        };
        attributes & REMOVED == 0 && (!matches!(self, Self::Tcb) || attributes & ENABLED != 0)
    }
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
    ApplyRefused,
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

#[derive(Clone, Eq, PartialEq)]
pub enum WatchEvent {
    Appeared {
        target: TargetIdentity,
        report: ProbeReport,
        session: u32,
    },
    Gone {
        target: TargetIdentity,
        reason: GoneReason,
    },
    Applied {
        target: TargetIdentity,
        outcome: ApplyOutcome,
    },
    HelperRestarted {
        attempt: u32,
    },
    HelperUnavailable,
}
impl fmt::Debug for WatchEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Appeared {
                report, session, ..
            } => formatter
                .debug_struct("Appeared")
                .field("target", &"[redacted]")
                .field("report", report)
                .field("session", session)
                .finish(),
            Self::Gone { reason, .. } => formatter
                .debug_struct("Gone")
                .field("target", &"[redacted]")
                .field("reason", reason)
                .finish(),
            Self::Applied { outcome, .. } => formatter
                .debug_struct("Applied")
                .field("target", &"[redacted]")
                .field("outcome", outcome)
                .finish(),
            Self::HelperRestarted { attempt } => formatter
                .debug_struct("HelperRestarted")
                .field("attempt", attempt)
                .finish(),
            Self::HelperUnavailable => formatter.write_str("HelperUnavailable"),
        }
    }
}

/// Thread-affine owner for the fixed protected watch helper. The session retains
/// every native owner until shutdown confirms exit, I/O drain and job release.
pub struct WatchSession {
    state: crate::watch_session::WatchMachine,
    #[cfg(all(windows, target_pointer_width = "64"))]
    inner: crate::ffi::probe_supervisor::WatchOwner,
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    _unconstructible: std::convert::Infallible,
}
impl fmt::Debug for WatchSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WatchSession(owned_service_only)")
    }
}
impl WatchSession {
    pub fn for_running_service() -> Result<Self, ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            let inner = crate::ffi::probe_supervisor::WatchOwner::new()?;
            Ok(Self {
                state: crate::watch_session::WatchMachine::new(std::time::Instant::now()),
                inner,
            })
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    pub fn poll(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Vec<WatchEvent>, ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            if self.state.is_shutting_down() {
                let _ = self.inner.poll_shutdown();
                return Ok(self.state.drain());
            }
            if self.state.is_unavailable() {
                self.inner.begin_shutdown();
                let _ = self.inner.poll_shutdown();
                return Ok(self.state.drain());
            }
            if self.state.retry_due(now) {
                match self.inner.reap_current() {
                    Ok(true) => {}
                    Ok(false) => return Ok(self.state.drain()),
                    Err(_) => {
                        self.state.make_unavailable();
                        self.inner.begin_shutdown();
                        return Err(ProbeSupervisorError::CleanupUnconfirmed);
                    }
                }
                match self.inner.relaunch() {
                    Ok(()) => {
                        if self.state.relaunched(now).is_err() {
                            if self.inner.fail_current().is_err() {
                                self.state.make_unavailable();
                                return Err(ProbeSupervisorError::CleanupUnconfirmed);
                            }
                            self.state.make_unavailable();
                            self.inner.begin_shutdown();
                            return Ok(self.state.drain());
                        }
                    }
                    Err(_) if self.inner.is_quarantined() => {
                        self.state.make_unavailable();
                        self.inner.begin_shutdown();
                        return Err(ProbeSupervisorError::CleanupUnconfirmed);
                    }
                    Err(_) => {
                        let disposition = self.state.failed(now);
                        if matches!(
                            disposition,
                            crate::watch_session::FailureDisposition::Unavailable
                        ) {
                            self.inner.begin_shutdown();
                        }
                    }
                }
            }
            if !self.state.is_running() {
                return Ok(self.state.drain());
            }
            let heartbeat_was_expired = self.state.heartbeat_expired(now);
            let mut received_message = false;
            for _ in 0..MAX_WATCH_MESSAGES_PER_POLL {
                let polled = match self.inner.poll() {
                    Ok(polled) => polled,
                    Err(_) => {
                        if self.inner.fail_current().is_err() {
                            self.state.make_unavailable();
                            return Err(ProbeSupervisorError::CleanupUnconfirmed);
                        }
                        if self.inner.is_quarantined() {
                            self.state.make_unavailable();
                            return Err(ProbeSupervisorError::CleanupUnconfirmed);
                        }
                        let disposition = self.state.failed(now);
                        if matches!(
                            disposition,
                            crate::watch_session::FailureDisposition::Unavailable
                        ) {
                            self.inner.begin_shutdown();
                        }
                        break;
                    }
                };
                match polled {
                    crate::ffi::probe_supervisor::WatchPoll::Pending => break,
                    crate::ffi::probe_supervisor::WatchPoll::Message(message) => {
                        if let Err(message_error) =
                            self.state.ingest(message, self.inner.session(), now)
                        {
                            if self.inner.fail_current().is_err() {
                                self.state.make_unavailable();
                                return Err(ProbeSupervisorError::CleanupUnconfirmed);
                            }
                            if self.inner.is_quarantined() {
                                self.state.make_unavailable();
                                return Err(ProbeSupervisorError::CleanupUnconfirmed);
                            }
                            if matches!(message_error, crate::watch_session::MessageError::Overflow)
                            {
                                self.inner.begin_shutdown();
                                break;
                            }
                            let disposition = self.state.failed(now);
                            if matches!(
                                disposition,
                                crate::watch_session::FailureDisposition::Unavailable
                            ) {
                                self.inner.begin_shutdown();
                            }
                            break;
                        }
                        received_message = true;
                    }
                    crate::ffi::probe_supervisor::WatchPoll::Exited => {
                        if self.inner.fail_current().is_err() {
                            self.state.make_unavailable();
                            return Err(ProbeSupervisorError::CleanupUnconfirmed);
                        }
                        if self.inner.is_quarantined() {
                            self.state.make_unavailable();
                            return Err(ProbeSupervisorError::CleanupUnconfirmed);
                        }
                        let disposition = self.state.failed(now);
                        if matches!(
                            disposition,
                            crate::watch_session::FailureDisposition::Unavailable
                        ) {
                            self.inner.begin_shutdown();
                        }
                        break;
                    }
                }
            }
            if heartbeat_was_expired && !received_message && self.state.is_running() {
                if self.inner.fail_current().is_err() {
                    self.state.make_unavailable();
                    return Err(ProbeSupervisorError::CleanupUnconfirmed);
                }
                if self.inner.is_quarantined() {
                    self.state.make_unavailable();
                    return Err(ProbeSupervisorError::CleanupUnconfirmed);
                }
                let disposition = self.state.failed(now);
                if matches!(
                    disposition,
                    crate::watch_session::FailureDisposition::Unavailable
                ) {
                    self.inner.begin_shutdown();
                }
            }
            Ok(self.state.drain())
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            let _ = now;
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    pub fn apply(
        &mut self,
        target: TargetIdentity,
        action: PromptAction,
        content_digest: [u8; 32],
    ) -> Result<(), ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            if self.state.is_shutting_down() {
                return Err(ProbeSupervisorError::ApplyRefused);
            }
            self.state.reserve_apply(target)?;
            let message = ServiceMessage::Apply {
                target,
                action,
                content_digest,
            };
            if let Err(error) = self.inner.write(message) {
                if self.inner.fail_current().is_err() {
                    self.state.make_unavailable();
                    return Err(ProbeSupervisorError::CleanupUnconfirmed);
                }
                if self.inner.is_quarantined() {
                    self.state.make_unavailable();
                    return Err(ProbeSupervisorError::CleanupUnconfirmed);
                }
                let disposition = self.state.failed(std::time::Instant::now());
                if matches!(
                    disposition,
                    crate::watch_session::FailureDisposition::Unavailable
                ) {
                    self.inner.begin_shutdown();
                }
                return Err(error);
            }
            Ok(())
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            let _ = (target, action, content_digest);
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    pub fn begin_shutdown(&mut self) {
        self.state.begin_shutdown();
        #[cfg(all(windows, target_pointer_width = "64"))]
        self.inner.begin_shutdown();
    }

    pub fn poll_shutdown(&mut self) -> bool {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.begin_shutdown();
            self.inner.poll_shutdown()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            true
        }
    }
}
impl Drop for WatchSession {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

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
pub(crate) fn quoted_watch_command_line(image: &[u16]) -> Result<Vec<u16>, ProbeSupervisorError> {
    let mut command = quoted_image_command_line(image)?;
    command.pop();
    command.extend_from_slice(&[
        u16::from(b' '),
        u16::from(b'w'),
        u16::from(b'a'),
        u16::from(b't'),
        u16::from(b'c'),
        u16::from(b'h'),
        0,
    ]);
    Ok(command)
}

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
        let _watch_constructor: fn() -> Result<WatchSession, ProbeSupervisorError> =
            WatchSession::for_running_service;
        let _watch_poll: fn(
            &mut WatchSession,
            std::time::Instant,
        ) -> Result<Vec<WatchEvent>, ProbeSupervisorError> = WatchSession::poll;
        let _watch_apply: fn(
            &mut WatchSession,
            TargetIdentity,
            PromptAction,
            [u8; 32],
        ) -> Result<(), ProbeSupervisorError> = WatchSession::apply;
        let _watch_begin_shutdown: fn(&mut WatchSession) = WatchSession::begin_shutdown;
        let _watch_poll_shutdown: fn(&mut WatchSession) -> bool = WatchSession::poll_shutdown;
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
    fn documented_default_disabled_launch_privileges_are_usable_without_adjustment() {
        for privilege in [
            LaunchPrivilege::IncreaseQuota,
            LaunchPrivilege::AssignPrimaryToken,
        ] {
            assert!(privilege.accepts_attributes(Some(0)));
            assert!(privilege.accepts_attributes(Some(1))); // Enabled-by-default is not enabled now.
            assert!(privilege.accepts_attributes(Some(2)));
            assert!(privilege.accepts_attributes(Some(3)));
        }
        assert!(!LaunchPrivilege::Tcb.accepts_attributes(Some(0)));
        assert!(!LaunchPrivilege::Tcb.accepts_attributes(Some(1)));
        assert!(LaunchPrivilege::Tcb.accepts_attributes(Some(2)));
        assert!(LaunchPrivilege::Tcb.accepts_attributes(Some(3)));
    }

    #[test]
    fn removed_privileges_never_satisfy_any_launch_requirement() {
        for privilege in [
            LaunchPrivilege::Tcb,
            LaunchPrivilege::IncreaseQuota,
            LaunchPrivilege::AssignPrimaryToken,
        ] {
            for attributes in [4, 5, 6, 7, u32::MAX] {
                assert!(!privilege.accepts_attributes(Some(attributes)));
            }
        }
    }

    #[test]
    fn missing_privileges_are_not_treated_as_present_but_disabled() {
        for privilege in [
            LaunchPrivilege::Tcb,
            LaunchPrivilege::IncreaseQuota,
            LaunchPrivilege::AssignPrimaryToken,
        ] {
            assert!(!privilege.accepts_attributes(None));
        }
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
        let watch = quoted_watch_command_line(&input).unwrap();
        assert_eq!(
            String::from_utf16(&watch[..watch.len() - 1]).unwrap(),
            format!("\"{module}\" watch")
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
