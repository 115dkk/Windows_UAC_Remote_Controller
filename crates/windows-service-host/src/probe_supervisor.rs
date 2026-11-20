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

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
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
    fn launch(&mut self) -> Result<std::time::Instant, AdapterLaunchError>;
    fn poll(&mut self) -> Result<AdapterPoll, ProbeSupervisorError>;
    fn write(&mut self, message: ServiceMessage) -> Result<(), ProbeSupervisorError>;
    fn session(&self) -> u32;
    fn fail_current(&mut self) -> Result<(), ProbeSupervisorError>;
    fn reap_current(&mut self) -> Result<bool, ProbeSupervisorError>;
    fn is_quarantined(&self) -> bool;
    fn has_watch_owner(&self) -> bool;
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
    fn launch(&mut self) -> Result<std::time::Instant, AdapterLaunchError> {
        if self.retained_without_owner {
            return Err(AdapterLaunchError::Retained(
                ProbeSupervisorError::CleanupUnconfirmed,
            ));
        }
        if let Some(owner) = &mut self.owner {
            owner.relaunch().map_err(Self::launch_error)?;
            return Ok(std::time::Instant::now());
        }
        match crate::ffi::probe_supervisor::WatchOwner::new() {
            Ok(owner) => {
                self.owner = Some(owner);
                Ok(std::time::Instant::now())
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

    fn has_watch_owner(&self) -> bool {
        self.owner.is_some()
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
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
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

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
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
                    Ok(finished_at) => self
                        .state
                        .launched(now, finished_at)
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
            let _ = self.state.complete_poll();
            Ok(self.state.drain())
        }
        #[cfg(not(any(all(windows, target_pointer_width = "64"), test)))]
        {
            let _ = now;
            Err(ProbeSupervisorError::UnsupportedPlatform)
        }
    }

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    fn finish_failed_cycle(&mut self, now: std::time::Instant) -> bool {
        // Failure cleanup, the quarantine observation and the state transition
        // form one sequence so no caller can accidentally reorder or omit one.
        let cleanup = self.inner.fail_current();
        let reaped = if cleanup.is_ok() {
            self.inner.reap_current()
        } else {
            Err(ProbeSupervisorError::CleanupUnconfirmed)
        };
        let quarantined = self.inner.is_quarantined();
        let cleanup_confirmed = cleanup.is_ok() && matches!(reaped, Ok(true)) && !quarantined;
        self.state.failed(now, !cleanup_confirmed);
        cleanup_confirmed
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
                if !self.finish_failed_cycle(std::time::Instant::now()) {
                    return Err(ProbeSupervisorError::CleanupUnconfirmed);
                }
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

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    pub(crate) fn blocks_diagnostic_probe(&self) -> bool {
        #[cfg(any(all(windows, target_pointer_width = "64"), test))]
        {
            self.inner.has_watch_owner()
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

    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
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
    use windows_prompt_probe::{LabelKind, ProbeCounts, PromptContentObservation, PromptLabel};

    fn target(sequence: u32) -> TargetIdentity {
        TargetIdentity {
            hwnd: u64::from(sequence),
            pid: 2,
            created: 3,
            sequence,
        }
    }

    fn report() -> ProbeReport {
        let content = PromptContentObservation::from_parts(
            vec![1],
            "synthetic".into(),
            vec![PromptLabel::new(0, 1, LabelKind::Text, true, "label".into()).unwrap()],
        )
        .unwrap();
        ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 1,
                enabled_elements: 1,
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            content,
        )
        .unwrap()
    }

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
        launch_finished: std::collections::VecDeque<Instant>,
        polls: std::collections::VecDeque<Result<AdapterPoll, ProbeSupervisorError>>,
        writes: std::collections::VecDeque<Result<(), ProbeSupervisorError>>,
        failures: std::collections::VecDeque<Result<(), ProbeSupervisorError>>,
        reaps: std::collections::VecDeque<Result<bool, ProbeSupervisorError>>,
        quarantine_checks: std::collections::VecDeque<bool>,
        shutdown_polls: std::collections::VecDeque<bool>,
        operations: Vec<&'static str>,
        launch_calls: usize,
        poll_calls: usize,
        write_calls: usize,
        fail_calls: usize,
        reap_calls: usize,
        shutdown_calls: usize,
        has_watch_owner: bool,
        quarantined: bool,
        dropped: bool,
    }

    #[derive(Clone)]
    struct TestWatchAdapter(std::rc::Rc<std::cell::RefCell<TestWatchState>>);

    impl WatchAdapter for TestWatchAdapter {
        fn launch(&mut self) -> Result<Instant, AdapterLaunchError> {
            let mut state = self.0.borrow_mut();
            state.launch_calls += 1;
            let result = state.launches.pop_front().unwrap_or(Ok(()));
            match result {
                Ok(()) => {
                    state.has_watch_owner = true;
                    Ok(state
                        .launch_finished
                        .pop_front()
                        .unwrap_or_else(Instant::now))
                }
                Err(AdapterLaunchError::Retained(error)) => {
                    Err(AdapterLaunchError::Retained(error))
                }
                Err(AdapterLaunchError::Refused(error)) => Err(AdapterLaunchError::Refused(error)),
            }
        }

        fn poll(&mut self) -> Result<AdapterPoll, ProbeSupervisorError> {
            let mut state = self.0.borrow_mut();
            state.poll_calls += 1;
            state.polls.pop_front().unwrap_or(Ok(AdapterPoll::Pending))
        }

        fn write(&mut self, _message: ServiceMessage) -> Result<(), ProbeSupervisorError> {
            let mut state = self.0.borrow_mut();
            state.write_calls += 1;
            state.writes.pop_front().unwrap_or(Ok(()))
        }

        fn session(&self) -> u32 {
            4
        }

        fn fail_current(&mut self) -> Result<(), ProbeSupervisorError> {
            let mut state = self.0.borrow_mut();
            state.fail_calls += 1;
            state.operations.push("fail_current");
            state.failures.pop_front().unwrap_or(Ok(()))
        }

        fn reap_current(&mut self) -> Result<bool, ProbeSupervisorError> {
            let mut state = self.0.borrow_mut();
            state.reap_calls += 1;
            state.operations.push("reap_current");
            state.reaps.pop_front().unwrap_or(Ok(true))
        }

        fn is_quarantined(&self) -> bool {
            let mut state = self.0.borrow_mut();
            state.operations.push("is_quarantined");
            let fallback = state.quarantined;
            state.quarantine_checks.pop_front().unwrap_or(fallback)
        }

        fn has_watch_owner(&self) -> bool {
            self.0.borrow().has_watch_owner
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

    fn appeared(sequence: u32) -> AdapterPoll {
        AdapterPoll::Message(windows_prompt_probe::supervision::HelperMessage::Appeared {
            target: target(sequence),
            report: report(),
        })
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
    fn first_start_uses_full_backoff_and_reports_only_changed_errors() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::SessionChanged,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::SessionChanged,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::HelperDamaged,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::HelperDamaged,
                )),
                Err(AdapterLaunchError::Refused(
                    ProbeSupervisorError::NoInteractiveSession,
                )),
            ]
            .into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        let mut attempted_at = began;
        let mut reported = Vec::new();

        for (attempt, delay) in [1_u64, 2, 5, 10, 30, 60].into_iter().enumerate() {
            reported.extend(watch.poll(attempted_at).unwrap().into_iter().filter_map(
                |observation| match observation {
                    WatchObservation::StartFailed(error) => Some(error),
                    _ => None,
                },
            ));
            let next = attempted_at + Duration::from_secs(delay);
            assert!(
                watch
                    .poll(next - Duration::from_millis(1))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(state.borrow().launch_calls, attempt + 1);
            attempted_at = next;
        }

        reported.extend(
            watch.poll(attempted_at).unwrap().into_iter().filter_map(
                |observation| match observation {
                    WatchObservation::StartFailed(error) => Some(error),
                    _ => None,
                },
            ),
        );
        assert_eq!(state.borrow().launch_calls, 7);
        assert_eq!(
            reported,
            [
                ProbeSupervisorError::NoInteractiveSession,
                ProbeSupervisorError::SessionChanged,
                ProbeSupervisorError::HelperDamaged,
                ProbeSupervisorError::NoInteractiveSession,
            ]
        );
    }

    #[test]
    fn first_launch_heartbeat_baseline_is_taken_after_creation_finishes() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began + Duration::from_secs(16)].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);

        watch.poll(began).unwrap();
        assert!(
            watch
                .poll(began + Duration::from_secs(17))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().fail_calls, 0);
    }

    #[test]
    fn first_alive_observation_follows_the_complete_message_batch() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            polls: [
                Ok(heartbeat()),
                Ok(AdapterPoll::Message(
                    windows_prompt_probe::supervision::HelperMessage::Parked { count: 2 },
                )),
            ]
            .into(),
            ..TestWatchState::default()
        };
        let (mut watch, _state) = test_watch(began, state);

        assert_eq!(
            watch.poll(began).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Started),
                WatchObservation::Health(WatcherHealth::Running),
                WatchObservation::Event(WatchEvent::ParkedChanged { count: 2 }),
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
    fn failed_apply_write_reports_cleanup_failure_when_both_operations_fail() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            writes: [Err(ProbeSupervisorError::HelperFailed(7))].into(),
            failures: [Err(ProbeSupervisorError::CleanupUnconfirmed)].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        state.borrow_mut().polls.push_back(Ok(appeared(1)));
        watch.poll(began + Duration::from_millis(1)).unwrap();

        assert_eq!(
            watch.apply(target(1), PromptAction::Deny, [7; 32]),
            Err(ProbeSupervisorError::CleanupUnconfirmed)
        );
        assert_eq!(
            state.borrow().operations,
            ["fail_current", "is_quarantined"]
        );
    }

    #[test]
    fn twelve_failures_keep_retrying_at_the_cap_and_report_the_ninth_once() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        let mut failed_at = began + Duration::from_millis(1);
        let mut unavailable_lifecycles = 0;
        let mut unavailable_events = 0;

        for attempt in 1_u32..=12 {
            state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
            for observation in watch.poll(failed_at).unwrap() {
                match observation {
                    WatchObservation::Lifecycle(WatchLifecycle::Unavailable) => {
                        unavailable_lifecycles += 1;
                    }
                    WatchObservation::Event(WatchEvent::HelperUnavailable) => {
                        unavailable_events += 1;
                    }
                    _ => {}
                }
            }
            let delay = match attempt {
                1 => 5,
                2 => 10,
                3 => 20,
                4 => 40,
                _ => 60,
            };
            let retry_at = failed_at + Duration::from_secs(delay);
            assert!(
                watch
                    .poll(retry_at - Duration::from_millis(1))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                watch
                    .poll(retry_at)
                    .unwrap()
                    .contains(&WatchObservation::Event(WatchEvent::HelperRestarted {
                        attempt
                    }))
            );
            failed_at = retry_at + Duration::from_millis(1);
        }

        assert_eq!(unavailable_lifecycles, 1);
        assert_eq!(unavailable_events, 1);
        assert_eq!(state.borrow().launch_calls, 13);
    }

    #[test]
    fn valid_message_resets_the_owner_failure_backoff() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        let mut failed_at = began + Duration::from_millis(1);

        for delay in [5_u64, 10, 20] {
            state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
            watch.poll(failed_at).unwrap();
            let retry_at = failed_at + Duration::from_secs(delay);
            watch.poll(retry_at).unwrap();
            failed_at = retry_at + Duration::from_millis(1);
        }

        state.borrow_mut().polls.push_back(Ok(heartbeat()));
        watch.poll(failed_at).unwrap();
        let next_failure = failed_at + Duration::from_millis(1);
        state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
        watch.poll(next_failure).unwrap();
        assert!(
            watch
                .poll(next_failure + Duration::from_millis(4_999))
                .unwrap()
                .is_empty()
        );
        assert!(
            watch
                .poll(next_failure + Duration::from_secs(5))
                .unwrap()
                .contains(&WatchObservation::Event(WatchEvent::HelperRestarted {
                    attempt: 1,
                }))
        );
        assert_eq!(state.borrow().launch_calls, 5);
    }

    #[test]
    fn restart_forgets_target_and_accepts_reset_sequence_numbers() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        state.borrow_mut().polls.push_back(Ok(appeared(9)));
        watch.poll(began + Duration::from_millis(1)).unwrap();

        state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
        watch.poll(began + Duration::from_millis(2)).unwrap();
        assert_eq!(
            watch.apply(target(9), PromptAction::Deny, [1; 32]),
            Err(ProbeSupervisorError::ApplyRefused)
        );
        watch.poll(began + Duration::from_millis(5_002)).unwrap();

        {
            let mut adapter = state.borrow_mut();
            adapter.polls.push_back(Ok(heartbeat()));
            adapter.polls.push_back(Ok(appeared(1)));
        }
        let observations = watch.poll(began + Duration::from_millis(5_003)).unwrap();
        assert!(observations.iter().any(|observation| {
            matches!(
                observation,
                WatchObservation::Event(WatchEvent::Appeared { target: actual, .. })
                    if *actual == target(1)
            )
        }));
        assert_eq!(watch.apply(target(1), PromptAction::Deny, [2; 32]), Ok(()));
    }

    #[test]
    fn heartbeat_timeout_boundary_is_exact_at_the_owner_interface() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();

        assert!(
            watch
                .poll(began + Duration::from_millis(14_999))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().fail_calls, 0);
        assert_eq!(
            watch.poll(began + Duration::from_secs(15)).unwrap(),
            vec![WatchObservation::Health(WatcherHealth::Unavailable(
                WatcherRefusal::HelperFailed,
            ))]
        );
        assert_eq!(state.borrow().fail_calls, 1);
    }

    #[test]
    fn polling_after_shutdown_does_no_launch_message_or_heartbeat_work() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);
        watch.poll(began).unwrap();
        state.borrow_mut().polls.push_back(Ok(AdapterPoll::Exited));
        watch.begin_shutdown();
        let before = {
            let state = state.borrow();
            (state.launch_calls, state.poll_calls, state.fail_calls)
        };

        assert!(
            watch
                .poll(began + Duration::from_secs(30))
                .unwrap()
                .is_empty()
        );
        assert!(
            watch
                .poll(began + Duration::from_secs(60))
                .unwrap()
                .is_empty()
        );
        let after = {
            let state = state.borrow();
            (state.launch_calls, state.poll_calls, state.fail_calls)
        };
        assert_eq!(after, before);
        assert_eq!(state.borrow().shutdown_calls, 1);
    }

    #[test]
    fn cleanup_failure_stays_with_the_watcher_instead_of_ending_the_service() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Ok(())].into(),
            launch_finished: [began].into(),
            polls: [Ok(AdapterPoll::Exited)].into(),
            failures: [Err(ProbeSupervisorError::CleanupUnconfirmed)].into(),
            reaps: [Ok(true), Ok(true)].into(),
            quarantine_checks: [true, true, false].into(),
            ..TestWatchState::default()
        };
        let (mut watch, state) = test_watch(began, state);

        assert_eq!(
            watch.poll(began).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Started),
                WatchObservation::Health(WatcherHealth::Unavailable(WatcherRefusal::HelperFailed,)),
            ]
        );
        assert_eq!(
            state.borrow().operations,
            ["fail_current", "is_quarantined"]
        );
        assert!(watch.blocks_diagnostic_probe());

        assert!(
            watch
                .poll(began + Duration::from_secs(5))
                .unwrap()
                .is_empty()
        );
        assert_eq!(state.borrow().launch_calls, 1);
        assert_eq!(
            watch.poll(began + Duration::from_secs(10)).unwrap(),
            vec![
                WatchObservation::Health(WatcherHealth::Starting),
                WatchObservation::Lifecycle(WatchLifecycle::Restarted),
                WatchObservation::Event(WatchEvent::HelperRestarted { attempt: 1 }),
            ]
        );
        assert_eq!(
            state.borrow().operations,
            [
                "fail_current",
                "is_quarantined",
                "reap_current",
                "is_quarantined",
                "reap_current",
                "is_quarantined",
            ]
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
    fn retained_first_launch_uses_old_probe_admission_and_shutdown_result() {
        let began = Instant::now();
        let state = TestWatchState {
            launches: [Err(AdapterLaunchError::Retained(
                ProbeSupervisorError::CleanupUnconfirmed,
            ))]
            .into(),
            ..TestWatchState::default()
        };
        let (mut watch, _state) = test_watch(began, state);

        watch.poll(began).unwrap();
        assert!(!watch.blocks_diagnostic_probe());
        assert!(watch.poll_shutdown());
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
        assert!(!watch.blocks_diagnostic_probe());
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
