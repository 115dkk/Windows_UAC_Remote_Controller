// SPDX-License-Identifier: GPL-2.0-or-later
//! Trusted service worker: lifecycle, protected identity and bounded journal.
//! It contains no listener, pairing endpoint, prompt adapter or fake UAC.
#![forbid(unsafe_code)]

use crate::{
    ProbeSupervisorError, ServiceProbeSupervisor,
    diagnostic::{
        CleanupObservation, HelperExitObservation, ProbeAdmission, ProbeDiagnosticRecord,
        ProbeObservation,
    },
};
use crate::{ServiceError, ServiceRegistry, ffi};
use activity_journal::{ActivityEvent, FailureKind, Journal, Limits, ServiceOutcome, UnixMillis};
use std::{
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_identity::{IdentityError, PcIdentityKey};

pub(crate) static PROBE_REQUESTS: ProbeAdmission = ProbeAdmission::new();

#[derive(Clone, Copy, Debug)]
pub(crate) enum WorkerEvent {
    Progress,
    Ready,
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
    pub(crate) fn spawn() -> Result<Self, ServiceError> {
        let (stop, requests) = mpsc::channel();
        let (sender, events) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("service-lifecycle".into())
            .spawn(move || {
                // No unwind reaches SCM or disappears as a falsely successful stop.
                let outcome = std::panic::catch_unwind(|| run(&requests, &sender))
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
    matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected))
}

fn run(stop: &Receiver<()>, events: &Sender<WorkerEvent>) -> Result<(), ServiceError> {
    // Identity and future transport/prompt workers belong at this trusted Rust seam.
    // They must initialize genuinely before claiming any additional readiness,
    // obey cancellation, and never expose their credentials through presentation.
    if cancellation_requested(stop) {
        return Ok(());
    }
    let _installation = ffi::validate_installation(true)?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    let directory = ffi::open_activity_directory()?;
    let mut journal = Journal::open(directory.path(), Limits::default(), now()?)
        .map_err(|_| ServiceError::JournalUnavailable)?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    // Key work stays on the service worker, never the SCM entry callback or
    // a WebView/IPC thread. Only genuine absence permits initial creation.
    let mut trust_directory = ffi::TrustDirectory::open_for_service()?;
    let registry_absent = trust_directory.is_empty_registry_absent()?;
    // This private disposition is produced only here by the actual key API,
    // never supplied by a renderer, file, phone or caller freshness boolean.
    enum IdentityOrigin {
        Existing,
        CreatedNow,
    }
    let (identity, origin) = match PcIdentityKey::open_existing_for_service() {
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
            (
                PcIdentityKey::create_for_service()
                    .map_err(|_| ServiceError::IdentityUnavailable)?,
                IdentityOrigin::CreatedNow,
            )
        }
        Err(_) => return Err(ServiceError::IdentityUnavailable),
    };
    let mut registry = match origin {
        IdentityOrigin::Existing => ServiceRegistry::open_existing(&identity, trust_directory),
        IdentityOrigin::CreatedNow => {
            ServiceRegistry::initialize_empty_after_key_creation(&identity, trust_directory)
        }
    }
    .map_err(registry_error)?;
    // Read from the actual committed owner before service readiness. No engine,
    // phone handshake or enrollment endpoint is started by this lifecycle host.
    let _registry_checkpoint = registry.checkpoint_for_engine().map_err(registry_error)?;
    if cancellation_requested(stop) {
        registry.close().map_err(registry_error)?;
        return identity
            .close()
            .map_err(|_| ServiceError::IdentityUnavailable);
    }
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    append(
        &mut journal,
        ActivityEvent::Service(ServiceOutcome::Started),
    )?;
    // Explicit fixed-schema diagnostics for the integrations NOT provided by
    // this lifecycle host. These events do not contain paths or authority state.
    append(
        &mut journal,
        ActivityEvent::Failure(FailureKind::PlatformUnavailable),
    )?;
    append(
        &mut journal,
        ActivityEvent::Failure(FailureKind::TransportUnavailable),
    )?;
    // Passive fixed-slot inspection only, never a startup probe. Failure/full
    // storage disables this diagnostic without bypassing identity/registry init.
    PROBE_REQUESTS.prepare(
        crate::native::probe_control_registration_ready(_installation.executable())
            .and_then(|()| directory.probe_slot_available()),
    );
    events
        .send(WorkerEvent::Ready)
        .map_err(|_| ServiceError::WorkerFailed)?;
    let mut last_purge = Instant::now();
    let mut supervisor = None;
    let mut supervisor_initialization_failed = None;
    loop {
        match stop.recv_timeout(Duration::from_millis(200)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
        if let Some(request) = PROBE_REQUESTS.take() {
            // The guard latches unavailable on storage error/unwind. Supervisor
            // ownership is retained here across every request and quarantine.
            let result = run_requested_probe(
                &directory,
                &mut supervisor,
                &mut supervisor_initialization_failed,
                &request,
            );
            match result {
                Ok(quarantined) => request.finish(directory.probe_slot_available(), quarantined),
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
    PROBE_REQUESTS.close();
    drop(supervisor);
    registry.close().map_err(registry_error)?;
    identity
        .close()
        .map_err(|_| ServiceError::IdentityUnavailable)?;
    // Journal drops before the directory/installation pins, never the reverse.
    drop(journal);
    drop(directory);
    Ok(())
}

fn diagnostic_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
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
