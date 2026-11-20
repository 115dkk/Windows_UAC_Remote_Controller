// SPDX-License-Identifier: GPL-2.0-or-later
//! Dormant, OS-guarded service-only supervisor. No CLI/Tauri/runtime auto hook.
#![forbid(unsafe_code)]
use crate::management_protocol::WatcherHealth;
#[cfg(test)]
use crate::management_protocol::WatcherRefusal;
use std::fmt;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
use windows_prompt_probe::supervision::{HelperMessage, ServiceMessage};
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
    HelperDamaged,
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
    /// Fresh provider recapture of the same retained native identity/content.
    StillPresent {
        target: TargetIdentity,
    },
    ParkedChanged {
        count: u8,
    },
    HelperRestarted {
        attempt: u32,
    },
    HelperUnavailable,
}
impl fmt::Debug for WatchEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StillPresent { .. } => formatter.write_str("StillPresent([redacted])"),
            Self::ParkedChanged { count } => formatter
                .debug_struct("ParkedChanged")
                .field("count", count)
                .finish(),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WatchLifecycle {
    Started,
    Alive,
    Restarted,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WatchObservation {
    Event(WatchEvent),
    Health(WatcherHealth),
    StartFailed(ProbeSupervisorError),
    Lifecycle(WatchLifecycle),
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterLaunchError {
    Refused(ProbeSupervisorError),
    Retained(ProbeSupervisorError),
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
enum AdapterPoll {
    Pending,
    Message(HelperMessage),
    Exited,
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
trait WatchAdapter {
    fn launch(&mut self) -> Result<(), AdapterLaunchError>;
    fn poll(&mut self) -> Result<AdapterPoll, ProbeSupervisorError>;
    fn write(&mut self, message: ServiceMessage) -> Result<(), ProbeSupervisorError>;
    fn session(&self) -> u32;
    fn fail_current(&mut self) -> Result<(), ProbeSupervisorError>;
    fn reap_current(&mut self) -> Result<bool, ProbeSupervisorError>;
    fn is_quarantined(&self) -> bool;
    fn holds_lease(&self) -> bool;
    fn begin_shutdown(&mut self);
    fn poll_shutdown(&mut self) -> bool;
}

#[cfg(all(windows, target_pointer_width = "64"))]
struct NativeWatchAdapter {
    owner: Option<crate::ffi::probe_supervisor::WatchOwner>,
    retained_without_owner: bool,
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl NativeWatchAdapter {
    fn new() -> Self {
        Self {
            owner: None,
            retained_without_owner: false,
        }
    }

    fn launch_error(error: ProbeSupervisorError) -> AdapterLaunchError {
        if error == ProbeSupervisorError::CleanupUnconfirmed {
            AdapterLaunchError::Retained(error)
        } else {
            AdapterLaunchError::Refused(error)
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
impl WatchAdapter for NativeWatchAdapter {
    fn launch(&mut self) -> Result<(), AdapterLaunchError> {
        if self.retained_without_owner {
            return Err(AdapterLaunchError::Retained(
                ProbeSupervisorError::CleanupUnconfirmed,
            ));
        }
        if let Some(owner) = &mut self.owner {
            return owner.relaunch().map_err(Self::launch_error);
        }
        match crate::ffi::probe_supervisor::WatchOwner::new() {
            Ok(owner) => {
                self.owner = Some(owner);
                Ok(())
            }
            Err(error) => {
                if error == ProbeSupervisorError::CleanupUnconfirmed {
                    // WatchOwner retains the uncertain native run until process
                    // teardown even though its constructor cannot return the owner.
                    self.retained_without_owner = true;
                }
                Err(Self::launch_error(error))
            }
        }
    }

    fn poll(&mut self) -> Result<AdapterPoll, ProbeSupervisorError> {
        match self
            .owner
            .as_mut()
            .ok_or(ProbeSupervisorError::Quarantined)?
            .poll()?
        {
            crate::ffi::probe_supervisor::WatchPoll::Pending => Ok(AdapterPoll::Pending),
            crate::ffi::probe_supervisor::WatchPoll::Message(message) => {
                Ok(AdapterPoll::Message(message))
            }
            crate::ffi::probe_supervisor::WatchPoll::Exited => Ok(AdapterPoll::Exited),
        }
    }

    fn write(&mut self, message: ServiceMessage) -> Result<(), ProbeSupervisorError> {
        self.owner
            .as_mut()
            .ok_or(ProbeSupervisorError::ApplyRefused)?
            .write(message)
    }

    fn session(&self) -> u32 {
        self.owner.as_ref().map_or(0, |owner| owner.session())
    }

    fn fail_current(&mut self) -> Result<(), ProbeSupervisorError> {
        self.owner
            .as_mut()
            .ok_or(ProbeSupervisorError::CleanupUnconfirmed)?
            .fail_current()
    }

    fn reap_current(&mut self) -> Result<bool, ProbeSupervisorError> {
        if self.retained_without_owner {
            return Ok(false);
        }
        self.owner
            .as_mut()
            .map_or(Ok(true), |owner| owner.reap_current())
    }

    fn is_quarantined(&self) -> bool {
        self.retained_without_owner
            || self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.is_quarantined())
    }

    fn holds_lease(&self) -> bool {
        self.retained_without_owner || self.owner.is_some()
    }

    fn begin_shutdown(&mut self) {
        if let Some(owner) = &mut self.owner {
            owner.begin_shutdown();
        }
    }

    fn poll_shutdown(&mut self) -> bool {
        // A constructor-side uncertain run was deliberately retained by the FFI
        // owner for process teardown; there is no object left that can prove more.
        self.owner
            .as_mut()
            .is_none_or(|owner| owner.poll_shutdown())
    }
}

/// Thread-affine owner for the fixed protected watch helper. Creation retries,
/// restart cleanup, health and shutdown stay with this object.
pub struct WatchSession {
    state: crate::watch_session::WatchMachine,
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    inner: Box<dyn WatchAdapter>,
    #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
    _unconstructible: !,
}

impl fmt::Debug for WatchSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WatchSession(owned_service_only)")
    }
}

#[cfg(any(windows, test))]
impl crate::peer_runtime::prompt::PromptApply for WatchSession {
    fn apply_prompt(
        &mut self,
        target: TargetIdentity,
        action: PromptAction,
        content_digest: [u8; 32],
    ) -> Result<(), ProbeSupervisorError> {
        self.apply(target, action, content_digest)
    }
}

impl WatchSession {
    pub fn for_running_service() -> Result<Self, ProbeSupervisorError> {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            Ok(Self::with_adapter(
                NativeWatchAdapter::new(),
                std::time::Instant::now(),
            ))
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    fn with_adapter(adapter: impl WatchAdapter + 'static, now: std::time::Instant) -> Self {
        Self {
            state: crate::watch_session::WatchMachine::new(now),
            inner: Box::new(adapter),
        }
    }

    pub(crate) fn poll(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Vec<WatchObservation>, ProbeSupervisorError> {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
        {
            if self.state.is_shutting_down() {
                let _ = self.inner.poll_shutdown();
                return Ok(self.state.drain());
            }
            if self.state.is_unavailable() {
                self.begin_shutdown();
                let _ = self.inner.poll_shutdown();
                return Ok(self.state.drain());
            }
            if self.state.retry_due(now) {
                if self.state.cleanup_pending() {
                    let cleaned = self.inner.reap_current();
                    let quarantined = self.inner.is_quarantined();
                    if !matches!(cleaned, Ok(true)) || quarantined {
                        self.state.defer_cleanup(now);
                        return Ok(self.state.drain());
                    }
                    self.state.cleanup_confirmed();
                }
                match self.inner.launch() {
                    Ok(()) => self
                        .state
                        .launched(now)
                        .map_err(|_| ProbeSupervisorError::InvalidReport)?,
                    Err(AdapterLaunchError::Refused(error)) => {
                        self.state
                            .launch_refused(error, false, now)
                            .map_err(|_| ProbeSupervisorError::InvalidReport)?;
                    }
                    Err(AdapterLaunchError::Retained(error)) => {
                        self.state
                            .launch_refused(error, true, now)
                            .map_err(|_| ProbeSupervisorError::InvalidReport)?;
                    }
                }
            }
            if !self.state.is_running() {
                return Ok(self.state.drain());
            }
            let heartbeat_was_expired = self.state.heartbeat_expired(now);
            let mut received_message = false;
            for _ in 0..MAX_WATCH_MESSAGES_PER_POLL {
                match self.inner.poll() {
                    Ok(AdapterPoll::Pending) => break,
                    Ok(AdapterPoll::Message(message)) => {
                        if self
                            .state
                            .ingest(message, self.inner.session(), now)
                            .is_err()
                        {
                            self.finish_failed_cycle(now);
                            break;
                        }
                        received_message = true;
                    }
                    Ok(AdapterPoll::Exited) | Err(_) => {
                        self.finish_failed_cycle(now);
                        break;
                    }
                }
            }
            if heartbeat_was_expired && !received_message && self.state.is_running() {
                self.finish_failed_cycle(now);
            }
            Ok(self.state.drain())
        }
        #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
        {
            let _ = now;
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    fn finish_failed_cycle(&mut self, now: std::time::Instant) {
        // Failure cleanup, the quarantine observation and the state transition
        // form one sequence so no caller can accidentally reorder or omit one.
        let cleanup = self.inner.fail_current();
        let reaped = if cleanup.is_ok() {
            self.inner.reap_current()
        } else {
            Err(ProbeSupervisorError::CleanupUnconfirmed)
        };
        let quarantined = self.inner.is_quarantined();
        self.state
            .failed(now, !matches!(reaped, Ok(true)) || quarantined);
    }

    pub fn apply(
        &mut self,
        target: TargetIdentity,
        action: PromptAction,
        content_digest: [u8; 32],
    ) -> Result<(), ProbeSupervisorError> {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
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
                self.finish_failed_cycle(std::time::Instant::now());
                return Err(error);
            }
            Ok(())
        }
        #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
        {
            let _ = (target, action, content_digest);
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    pub(crate) fn blocks_diagnostic_probe(&self) -> bool {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
        {
            self.inner.holds_lease()
        }
        #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
        {
            false
        }
    }

    pub(crate) fn begin_shutdown(&mut self) {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
        if self.state.begin_shutdown() {
            self.inner.begin_shutdown();
        }
    }

    pub(crate) fn poll_shutdown(&mut self) -> bool {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
        {
            self.begin_shutdown();
            self.inner.poll_shutdown()
        }
        #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
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
    _unconstructible: !,
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
    use std::time::{Duration, Instant};

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
        ) -> Result<Vec<WatchObservation>, ProbeSupervisorError> = WatchSession::poll;
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
    fn damaged_helper_serializes_as_a_distinct_closed_kind() {
        assert_eq!(
            serde_json::to_value(ProbeSupervisorError::HelperDamaged).unwrap(),
            serde_json::json!({"kind": "helper_damaged"})
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
    #[derive(Default)]
    struct TestWatchState {
        launches: std::collections::VecDeque<Result<(), AdapterLaunchError>>,
        polls: std::collections::VecDeque<Result<AdapterPoll, ProbeSupervisorError>>,
        reaps: std::collections::VecDeque<Result<bool, ProbeSupervisorError>>,
        shutdown_polls: std::collections::VecDeque<bool>,
        launch_calls: usize,
        fail_calls: usize,
        reap_calls: usize,
        shutdown_calls: usize,
        held: bool,
        quarantined: bool,
        dropped: bool,
    }

    #[derive(Clone)]
    struct TestWatchAdapter(std::rc::Rc<std::cell::RefCell<TestWatchState>>);

    impl WatchAdapter for TestWatchAdapter {
        fn launch(&mut self) -> Result<(), AdapterLaunchError> {
            let mut state = self.0.borrow_mut();
            state.launch_calls += 1;
            let result = state.launches.pop_front().unwrap_or(Ok(()));
            match result {
                Ok(()) => state.held = true,
                Err(AdapterLaunchError::Retained(_)) => state.held = true,
                Err(AdapterLaunchError::Refused(_)) => {}
            }
            result
        }

        fn poll(&mut self) -> Result<AdapterPoll, ProbeSupervisorError> {
            self.0
                .borrow_mut()
                .polls
                .pop_front()
                .unwrap_or(Ok(AdapterPoll::Pending))
        }

        fn write(&mut self, _message: ServiceMessage) -> Result<(), ProbeSupervisorError> {
            Ok(())
        }

        fn session(&self) -> u32 {
            4
        }

        fn fail_current(&mut self) -> Result<(), ProbeSupervisorError> {
            self.0.borrow_mut().fail_calls += 1;
            Ok(())
        }

        fn reap_current(&mut self) -> Result<bool, ProbeSupervisorError> {
            let mut state = self.0.borrow_mut();
            state.reap_calls += 1;
            state.reaps.pop_front().unwrap_or(Ok(true))
        }

        fn is_quarantined(&self) -> bool {
            self.0.borrow().quarantined
        }

        fn holds_lease(&self) -> bool {
            self.0.borrow().held
        }

        fn begin_shutdown(&mut self) {
            self.0.borrow_mut().shutdown_calls += 1;
        }

        fn poll_shutdown(&mut self) -> bool {
            self.0
                .borrow_mut()
                .shutdown_polls
                .pop_front()
                .unwrap_or(true)
        }
    }

    impl Drop for TestWatchAdapter {
        fn drop(&mut self) {
            self.0.borrow_mut().dropped = true;
        }
    }

    fn test_watch(
        began: Instant,
        state: TestWatchState,
    ) -> (
        WatchSession,
        std::rc::Rc<std::cell::RefCell<TestWatchState>>,
    ) {
        let state = std::rc::Rc::new(std::cell::RefCell::new(state));
        let watch = WatchSession::with_adapter(TestWatchAdapter(state.clone()), began);
        (watch, state)
    }

    fn heartbeat() -> AdapterPoll {
        AdapterPoll::Message(
            windows_prompt_probe::supervision::HelperMessage::Heartbeat { sequence: 0 },
        )
    }

    #[test]
    fn watch_owner_retries_a_refused_first_start_then_waits_for_a_fresh_heartbeat() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
                Ok(()),
            ]
            .into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);

        assert_eq!(
            watch.poll(began).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Unavailable(
                    WatcherRefusal::NoSignedInUser,
                )),
                WatchObservation::StartFailed(ProbeSupervisorError::NoInteractiveSession),
                WatchObservation::Lifecycle(WatchLifecycle::Unavailable),
            ]
        );
        assert!(
            watch
                .poll(began + Duration::from_millis(999))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().launch_calls, 1);
        assert_eq!(
            watch.poll(began + Duration::from_secs(1)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Started),
            ]
        );
        assert_eq!(state.borrow().launch_calls, 2);
        assert!(
            watch
                .poll(began + Duration::from_millis(1_001))
                .unwrap()
                .is_empty()
        );

        state.borrow_mut().polls.push_back(Ok(heartbeat()));
        assert_eq!(
            watch.poll(began + Duration::from_millis(1_002)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Running),
                WatchObservation::Lifecycle(WatchLifecycle::Alive),
            ]
        );
    }

    #[test]
    fn watch_owner_does_not_reuse_an_old_heartbeat_after_helper_restart() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(()), Ok(())].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        state.borrow_mut().polls.push_back(Ok(heartbeat()));
        assert!(
            watch
                .poll(began + Duration::from_millis(1))
                .unwrap()
                .contains(&WatchObservation::Health(WatcherHealth::Running))
        );

        state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
        assert_eq!(
            watch.poll(began + Duration::from_secs(1)).unwrap(),
            vec![WatchObservation::Health(WatcherHealth::Unavailable(
                WatcherRefusal::HelperFailed,
            ))]
        );
        assert_eq!(state.borrow().fail_calls, 1);
        assert_eq!(
            watch.poll(began + Duration::from_secs(6)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Restarted),
                WatchObservation::Event(WatchEvent::HelperRestarted { attempt: 1 }),
            ]
        );
        assert!(
            watch
                .poll(began + Duration::from_millis(6_001))
                .unwrap()
                .is_empty()
        );

        state.borrow_mut().polls.push_back(Ok(heartbeat()));
        assert_eq!(
            watch.poll(began + Duration::from_millis(6_002)).unwrap(),
            vec![WatchObservation::Health(WatcherHealth::Running)]
        );
    }

    #[test]
    fn watch_owner_keeps_retrying_through_a_long_sign_out() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [
                Ok(()),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
                Ok(()),
            ]
            .into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
        watch.poll(began + Duration::from_secs(1)).unwrap();

        assert_eq!(
            watch.poll(began + Duration::from_secs(6)).unwrap(),
            vec![WatchObservation::Health(WatcherHealth::Unavailable(
                WatcherRefusal::NoSignedInUser,
            ))]
        );
        assert_eq!(state.borrow().launch_calls, 2);
        assert!(
            watch
                .poll(began + Duration::from_secs(65))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().launch_calls, 2);
        watch.poll(began + Duration::from_secs(66)).unwrap();
        assert_eq!(state.borrow().launch_calls, 3);
        assert!(
            watch
                .poll(began + Duration::from_secs(125))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().launch_calls, 3);
        assert_eq!(
            watch.poll(began + Duration::from_secs(126)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Restarted),
                WatchObservation::Event(WatchEvent::HelperRestarted { attempt: 1 }),
            ]
        );
    }

    #[test]
    fn watch_owner_retained_launch_cleanup_uses_restart_backoff_and_keeps_the_adapter() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [
                Err(AdapterLaunchError::Retained(
                    ProbeSupervisorError::CleanupUnconfirmed,
                )),
                Ok(()),
            ]
            .into(),
            reaps: [Ok(false), Ok(true)].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);

        watch.poll(began).unwrap();
        assert!(watch.blocks_diagnostic_probe());
        assert!(
            watch
                .poll(began + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().launch_calls, 1);
        assert_eq!(state.borrow().reap_calls, 0);
        assert!(!state.borrow().dropped);

        assert!(
            watch
                .poll(began + Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().reap_calls, 1);
        assert_eq!(state.borrow().launch_calls, 1);
        assert!(!state.borrow().dropped);
        assert!(
            watch
                .poll(began + Duration::from_millis(9_999))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().reap_calls, 1);
        assert_eq!(
            watch.poll(began + Duration::from_secs(10)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Started),
            ]
        );
        assert_eq!(state.borrow().reap_calls, 2);
        assert_eq!(state.borrow().launch_calls, 2);
        assert!(!state.borrow().dropped);
    }

    #[test]
    fn watch_owner_shutdown_is_idempotent_and_waits_for_the_adapter() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            shutdown_polls: [false, true].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();

        watch.begin_shutdown();
        watch.begin_shutdown();
        assert_eq!(state.borrow().shutdown_calls, 1);
        assert!(!watch.poll_shutdown());
        assert!(watch.poll_shutdown());
        assert_eq!(state.borrow().shutdown_calls, 1);
        assert_eq!(state.borrow().launch_calls, 1);
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
