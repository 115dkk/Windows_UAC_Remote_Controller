// SPDX-License-Identifier: GPL-2.0-or-later
//! Trusted service worker: lifecycle, protected identity and bounded journal.
//! Pairing and the protected prompt watcher activate only after actual full SCM Ready.
//! Phone authorization remains distinct from the watcher's observed Windows outcome.
#![forbid(unsafe_code)]

use crate::peer_runtime::{PeerRuntimeError, ServiceSession, SessionCleanup, SessionProgress};
use crate::startup_phase::{
    ReadyRequest, RunningRequest, ready_handshake, run_platform_step, running_handshake,
};
use crate::{
    ProbeSupervisorError, ServiceProbeSupervisor, WatchSession,
    diagnostic::{
        CleanupObservation, HelperExitObservation, ProbeAdmission, ProbeDiagnosticRecord,
        ProbeObservation,
    },
};
use crate::{ServiceError, ServiceRegistry, ffi};
use activity_journal::{
    ActivityEvent, Decision, FailureKind, Journal, Limits, RequestOutcome, ServiceOutcome,
    UnixMillis,
};
use std::{
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_identity::{IdentityError, PcIdentityKey};

pub(crate) static PROBE_REQUESTS: ProbeAdmission = ProbeAdmission::new();

#[derive(Debug)]
pub(crate) enum WorkerEvent {
    Progress,
    ScmRunningRequired(RunningRequest),
    Ready(ReadyRequest),
    Finished(Result<(), ServiceError>),
}

/// The service-entry thread owns this handle; worker resources are constructed
/// on the worker thread and remain there. Only fixed lifecycle messages cross.
pub(crate) struct Worker {
    stop: Sender<()>,
    events: Receiver<WorkerEvent>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn spawn(startup_began: Instant) -> Result<Self, ServiceError> {
        let (stop, requests) = mpsc::channel();
        let (sender, events) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("service-lifecycle".into())
            .spawn(move || {
                // No unwind reaches SCM or disappears as a falsely successful stop.
                let outcome = std::panic::catch_unwind(|| run(&requests, &sender, startup_began))
                    .unwrap_or(Err(ServiceError::WorkerFailed));
                let _ = sender.send(WorkerEvent::Finished(outcome));
            })
            .map_err(|_| ServiceError::WorkerFailed)?;
        Ok(Self {
            stop,
            events,
            thread: Some(thread),
        })
    }

    pub(crate) fn request_stop(&self) {
        PROBE_REQUESTS.close();
        let _ = self.stop.send(());
    }

    pub(crate) fn next_event(&self) -> Result<Option<WorkerEvent>, ServiceError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ServiceError::WorkerFailed),
        }
    }

    pub(crate) fn join_finished(&mut self) -> Result<(), ServiceError> {
        // Only called after Finished was received. No unbounded join on a live
        // worker is permitted: a tiny final return is verified with is_finished.
        let Some(thread) = self.thread.take() else {
            return Err(ServiceError::WorkerFailed);
        };
        if !thread.is_finished() {
            self.thread = Some(thread);
            return Err(ServiceError::UnexpectedState);
        }
        thread.join().map_err(|_| ServiceError::WorkerFailed)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
    }
}

fn now() -> Result<UnixMillis, ServiceError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::InvalidClock)?
        .as_millis();
    UnixMillis::new(u64::try_from(millis).map_err(|_| ServiceError::InvalidClock)?)
        .map_err(|_| ServiceError::InvalidClock)
}

fn append(journal: &mut Journal, event: ActivityEvent) -> Result<(), ServiceError> {
    journal
        .append(now()?, event)
        .map_err(|_| ServiceError::JournalUnavailable)?;
    Ok(())
}

fn cancellation_requested(stop: &Receiver<()>) -> bool {
    crate::entry::stop_requested()
        || matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected))
}

fn run(
    stop: &Receiver<()>,
    events: &Sender<WorkerEvent>,
    startup_began: Instant,
) -> Result<(), ServiceError> {
    // Identity and future transport/prompt workers belong at this trusted Rust seam.
    // They must initialize genuinely before claiming any additional readiness,
    // obey cancellation, and never expose their credentials through presentation.
    if cancellation_requested(stop) {
        return Ok(());
    }
    let _installation = ffi::validate_installation(true).map_err(|error| error.at_startup(1))?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    let directory = ffi::open_activity_directory().map_err(|error| error.at_startup(2))?;
    let mut journal = Journal::open(
        directory.path(),
        Limits::default(),
        now().map_err(|error| error.at_startup(3))?,
    )
    .map_err(|_| ServiceError::JournalUnavailable.at_startup(3))?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    // Key work stays on the service worker, never the SCM entry callback or
    // a WebView/IPC thread. Only genuine absence permits initial creation.
    // Capture the fixed identity-context cause before the trust-store adapter's
    // intentionally coarse error mapping. This adds no privilege/key mutation.
    windows_identity::verify_service_context().map_err(ServiceError::from_identity)?;
    let mut trust_directory =
        ffi::TrustDirectory::open_for_service().map_err(|error| error.at_startup(4))?;
    let registry_absent = trust_directory
        .is_empty_registry_absent()
        .map_err(|error| error.at_startup(5))?;
    // Keep every protected preflight before SCM Running, but defer the first
    // platform-provider/key call until this exact entry thread has successfully
    // reported Running with NO accepted controls. This one-use in-process gate
    // retains the original startup deadline and does not advertise real Ready.
    let (request, gate) = running_handshake();
    events
        .send(WorkerEvent::ScmRunningRequired(request))
        .map_err(|_| ServiceError::WorkerFailed)?;
    gate.wait(startup_began, || cancellation_requested(stop))?;
    // This private disposition is produced only here by the actual key API,
    // never supplied by a renderer, file, phone or caller freshness boolean.
    enum IdentityOrigin {
        Existing,
        CreatedNow,
    }
    let opened = run_platform_step(
        startup_began,
        || cancellation_requested(stop),
        PcIdentityKey::open_existing_for_service,
    )?;
    let (identity, origin) = match opened {
        Ok(identity) => {
            if registry_absent {
                return Err(ServiceError::RegistryUnavailable);
            }
            (identity, IdentityOrigin::Existing)
        }
        Err(IdentityError::KeyNotFound) => {
            // Do not create a replacement key beside older trust data. Missing
            // either half of a previously initialized identity requires recovery.
            if !registry_absent {
                return Err(ServiceError::RegistryUnavailable);
            }
            // Opening may have blocked through Stop or the original deadline.
            // Absence is not permission to start a late creation attempt.
            let created = run_platform_step(
                startup_began,
                || cancellation_requested(stop),
                PcIdentityKey::create_for_service,
            )?
            .map_err(ServiceError::from_identity)?;
            (created, IdentityOrigin::CreatedNow)
        }
        Err(error) => return Err(ServiceError::from_identity(error)),
    };
    let relay = trust_directory
        .read_relay_endpoint()
        .map_err(|error| error.at_startup(6))?;
    let registry = match origin {
        IdentityOrigin::Existing => ServiceRegistry::open_existing(&identity, trust_directory),
        IdentityOrigin::CreatedNow => {
            ServiceRegistry::initialize_empty_after_key_creation(&identity, trust_directory)
        }
    }
    .map_err(registry_error)?;
    // Retain the actual registry, restored engine, original epoch coordinate and
    // borrowed native key in ONE worker-owned session. No carrier/listener is
    // activated and SCM readiness still does not mean remote approval readiness.
    let mut session =
        ServiceSession::for_service(registry, &identity, Instant::now()).map_err(session_error)?;
    let mut supervisor = None;
    let mut supervisor_initialization_failed = None;
    let mut watch = None;
    // Keep session OUTSIDE this unwind boundary: every returned error or unwind
    // takes the same staged drain before registry/key release or Finished.
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(), ServiceError> {
                if cancellation_requested(stop) {
                    return Ok(());
                }
                events
                    .send(WorkerEvent::Progress)
                    .map_err(|_| ServiceError::WorkerFailed)?;
                append(
                    &mut journal,
                    ActivityEvent::Service(ServiceOutcome::Started),
                )?;
                // Passive fixed-slot inspection only, never a startup probe. Failure/full
                // storage disables this diagnostic without bypassing identity/registry init.
                PROBE_REQUESTS.prepare(
                    crate::native::probe_control_registration_ready(_installation.executable())
                        .and_then(|()| directory.probe_slot_available()),
                );
                let (ready_request, ready_gate) = ready_handshake();
                events
                    .send(WorkerEvent::Ready(ready_request))
                    .map_err(|_| ServiceError::WorkerFailed)?;
                let ready = ready_gate.wait(startup_began, || cancellation_requested(stop))?;
                if cancellation_requested(stop) {
                    return Ok(());
                }
                session.activate_pairing(ready).map_err(session_error)?;
                session
                    .configure_relay_after_ready(relay)
                    .map_err(session_error)?;
                watch = Some(
                    WatchSession::for_running_service().map_err(|_| ServiceError::WorkerFailed)?,
                );
                if cancellation_requested(stop) {
                    return Ok(());
                }
                let mut last_purge = Instant::now();
                loop {
                    if cancellation_requested(stop) {
                        break;
                    }
                    let iteration_now = Instant::now();
                    let watcher = watch.as_mut().ok_or(ServiceError::WorkerFailed)?;
                    for event in watcher
                        .poll(iteration_now)
                        .map_err(|_| ServiceError::WorkerFailed)?
                    {
                        let progress = session
                            .handle_watch_event(event, iteration_now)
                            .map_err(session_error)?;
                        journal_prompt_progress(&mut journal, progress)?;
                    }
                    if let Some(progress) = session
                        .prompt_deadline_step(iteration_now)
                        .map_err(session_error)?
                    {
                        journal_prompt_progress(&mut journal, progress)?;
                    }
                    match session
                        .process_one_with_watch(watcher)
                        .map_err(session_error)?
                    {
                        SessionProgress::AuthorizedButNotApplied(reason) => {
                            let failure = match reason {
                            crate::peer_runtime::NotAppliedReason::PlatformUnavailable => {
                                FailureKind::PlatformUnavailable
                            }
                            crate::peer_runtime::NotAppliedReason::NoLiveTarget
                            | crate::peer_runtime::NotAppliedReason::ExpiredAfterVerification
                            | crate::peer_runtime::NotAppliedReason::PeerChangedAfterVerification =>
                            {
                                FailureKind::RequestValidationFailed
                            }
                        };
                            append(&mut journal, ActivityEvent::Failure(failure))?;
                        }
                        SessionProgress::ApplyRequested { purpose, .. } => {
                            let decision = journal_decision(purpose);
                            append(
                                &mut journal,
                                ActivityEvent::Request(RequestOutcome::PhoneDecisionVerified {
                                    decision,
                                }),
                            )?;
                            append(
                                &mut journal,
                                ActivityEvent::Request(RequestOutcome::DecisionSentToWindows {
                                    decision,
                                }),
                            )?;
                        }
                        SessionProgress::Prompt(progress) => {
                            journal_prompt_progress(&mut journal, progress)?;
                        }
                        SessionProgress::PairingFailed => append(
                            &mut journal,
                            ActivityEvent::Failure(FailureKind::TransportUnavailable),
                        )?,
                        SessionProgress::Enrolled(_device) => {
                            // The fixed journal schema has no enrollment-device event.
                        }
                        _ => {}
                    }
                    match stop.recv_timeout(Duration::from_millis(25)) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                    }
                    if let Some(request) = PROBE_REQUESTS.take() {
                        // The watch holds the shared process lease. Preserve the one-shot
                        // diagnostic path only when no watch exists.
                        let result = if watch.is_some() {
                            run_busy_probe(&directory, &request)
                        } else {
                            run_requested_probe(
                                &directory,
                                &mut supervisor,
                                &mut supervisor_initialization_failed,
                                &request,
                            )
                        };
                        match result {
                            Ok(quarantined) => {
                                request.finish(directory.probe_slot_available(), quarantined)
                            }
                            Err(ServiceError::ProbeSlotsFull) => request.finish(Ok(false), false),
                            Err(_) => request.finish(Err(ServiceError::ProbeUnavailable), true),
                        }
                    }
                    if last_purge.elapsed() >= Duration::from_secs(3_600) {
                        journal
                            .purge(now()?)
                            .map_err(|_| ServiceError::JournalUnavailable)?;
                        last_purge = Instant::now();
                    }
                }
                append(
                    &mut journal,
                    ActivityEvent::Service(ServiceOutcome::Stopping),
                )?;
                Ok(())
            },
        ))
        .unwrap_or(Err(ServiceError::WorkerFailed));
    PROBE_REQUESTS.close();
    if let Some(watch) = watch.as_mut() {
        watch.begin_shutdown();
    }
    session.begin_shutdown();
    let io_failed = loop {
        let watch_done = watch.as_mut().is_none_or(WatchSession::poll_shutdown);
        match session.poll_shutdown() {
            SessionCleanup::CleanupPending { .. } => {
                // Retain ownership even beyond an expected cleanup interval.
                // No timeout is a quiescence receipt and no live join blocks
                // this key worker. Existing SCM timeout reporting is unchanged.
                thread::park_timeout(Duration::from_millis(25));
            }
            SessionCleanup::Quiescent { io_failed } if watch_done => break io_failed,
            SessionCleanup::Quiescent { .. } => thread::park_timeout(Duration::from_millis(25)),
        }
    };
    drop(watch);
    drop(supervisor);
    let closed = session.finish_shutdown().map_err(session_error);
    drop(session);
    let identity_closed = identity.close().map_err(ServiceError::from_identity);
    // Journal drops before the directory/installation pins, never the reverse.
    drop(journal);
    drop(directory);
    outcome.and(closed).and(identity_closed).and(if io_failed {
        Err(ServiceError::WorkerFailed)
    } else {
        Ok(())
    })
}

fn session_error(error: PeerRuntimeError) -> ServiceError {
    match error {
        PeerRuntimeError::Clock => ServiceError::InvalidClock,
        PeerRuntimeError::Registry => ServiceError::RegistryUnavailable,
        _ => ServiceError::WorkerFailed,
    }
}

fn journal_decision(purpose: approval_protocol::DecisionPurpose) -> Decision {
    match purpose {
        approval_protocol::DecisionPurpose::Approve => Decision::Approve,
        approval_protocol::DecisionPurpose::Deny => Decision::Deny,
    }
}

fn journal_prompt_progress(
    journal: &mut Journal,
    progress: crate::peer_runtime::prompt::PromptProgress,
) -> Result<(), ServiceError> {
    if let Some(result) = progress.result() {
        let outcome = match result {
            crate::peer_runtime::prompt::PromptResult::Approved => RequestOutcome::WindowsApplied {
                decision: Decision::Approve,
            },
            crate::peer_runtime::prompt::PromptResult::Denied => RequestOutcome::WindowsApplied {
                decision: Decision::Deny,
            },
            crate::peer_runtime::prompt::PromptResult::Cancelled => RequestOutcome::Cancelled,
            crate::peer_runtime::prompt::PromptResult::Expired => RequestOutcome::Expired,
            crate::peer_runtime::prompt::PromptResult::FailedRejected => {
                RequestOutcome::WindowsRejected
            }
            crate::peer_runtime::prompt::PromptResult::FailedUnknown => {
                RequestOutcome::WindowsOutcomeUnknown
            }
        };
        append(journal, ActivityEvent::Request(outcome))?;
    }
    if progress.observed() {
        append(journal, ActivityEvent::Request(RequestOutcome::Observed))?;
    }
    if progress.queued_opened() != 0 {
        append(
            journal,
            ActivityEvent::Request(RequestOutcome::NotificationSent),
        )?;
    }
    Ok(())
}

fn diagnostic_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

fn run_busy_probe(
    directory: &ffi::ActivityDirectory,
    request: &crate::diagnostic::ProbeRun<'_>,
) -> Result<bool, ServiceError> {
    let file = directory.reserve_probe_slot()?;
    let record = ProbeDiagnosticRecord::new(
        file.slot(),
        std::process::id(),
        diagnostic_time(),
        diagnostic_time(),
        if request.cancelled() {
            ProbeObservation::CancelledBeforeProbe
        } else {
            ProbeObservation::SupervisorFailure {
                failure: ProbeSupervisorError::Busy,
            }
        },
        CleanupObservation::NoRetainedRun,
        HelperExitObservation::NotStarted,
    );
    file.write_record(record)?;
    Ok(false)
}

fn run_requested_probe(
    directory: &ffi::ActivityDirectory,
    supervisor: &mut Option<ServiceProbeSupervisor>,
    initialization_failure: &mut Option<ProbeSupervisorError>,
    request: &crate::diagnostic::ProbeRun<'_>,
) -> Result<bool, ServiceError> {
    let file = directory.reserve_probe_slot()?;
    let started = diagnostic_time();
    let (outcome, cleanup, helper_exit, quarantined) = if request.cancelled() {
        (
            ProbeObservation::CancelledBeforeProbe,
            CleanupObservation::NoRetainedRun,
            HelperExitObservation::NotStarted,
            false,
        )
    } else {
        if supervisor.is_none() && initialization_failure.is_none() {
            match ServiceProbeSupervisor::for_running_service() {
                Ok(owner) => *supervisor = Some(owner),
                Err(error) => *initialization_failure = Some(error),
            }
        }
        match supervisor {
            Some(owner) if !request.cancelled() => match owner.probe_once() {
                Ok(report) => {
                    let (outcome, helper_exit) = ProbeObservation::from_report(report);
                    (
                        outcome,
                        CleanupObservation::ReportAndExitConfirmed,
                        helper_exit,
                        false,
                    )
                }
                Err(error) => {
                    let quarantined = owner.is_quarantined();
                    (
                        ProbeObservation::SupervisorFailure { failure: error },
                        if quarantined {
                            CleanupObservation::Quarantined
                        } else {
                            CleanupObservation::NoRetainedRun
                        },
                        HelperExitObservation::Unknown,
                        quarantined,
                    )
                }
            },
            Some(_) => (
                ProbeObservation::CancelledBeforeProbe,
                CleanupObservation::NoRetainedRun,
                HelperExitObservation::NotStarted,
                false,
            ),
            None => (
                ProbeObservation::SupervisorFailure {
                    failure: initialization_failure
                        .unwrap_or(ProbeSupervisorError::NotRunningService),
                },
                CleanupObservation::Unknown,
                HelperExitObservation::NotStarted,
                true,
            ),
        }
    };
    let record = ProbeDiagnosticRecord::new(
        file.slot(),
        std::process::id(),
        started,
        diagnostic_time(),
        outcome,
        cleanup,
        helper_exit,
    );
    file.write_record(record)?;
    Ok(quarantined)
}

fn registry_error(error: crate::RegistryError) -> ServiceError {
    if error == crate::RegistryError::MaintenanceRequired {
        ServiceError::RegistryMaintenanceRequired
    } else {
        ServiceError::RegistryUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_cancellation_detects_stop_and_owner_disconnection() {
        let (sender, receiver) = mpsc::channel();
        assert!(!cancellation_requested(&receiver));
        sender.send(()).unwrap();
        assert!(cancellation_requested(&receiver));
        drop(sender);
        assert!(cancellation_requested(&receiver));
    }
}
