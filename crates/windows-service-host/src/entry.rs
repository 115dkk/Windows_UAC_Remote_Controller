// SPDX-License-Identifier: GPL-2.0-or-later
//! Sole SCM callback boundary. Callbacks retain no user data/raw context pointer;
//! their bounded channel is process-lifetime owned, not freed after first Stop.

use crate::{
    ServiceError, ServiceOperation,
    contract::{LIFECYCLE_TIMEOUT, POLL_INTERVAL, continuing_pending_start, remaining_budget},
    ffi::win_error,
    native::scm_error,
    runtime::{Worker, WorkerEvent},
    startup_phase::{ReportPhase, worker_finished_outcome},
};
use std::{
    ffi::c_void,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{
            ERROR_BUSY, ERROR_CALL_NOT_IMPLEMENTED, ERROR_EXCEPTION_IN_SERVICE,
            ERROR_NO_MORE_FILES, ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_SPECIFIC_ERROR,
        },
        System::Services::{
            RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
            SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
            SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        },
    },
    core::w,
};

static DISPATCHED: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static CONTROLS: OnceLock<SyncSender<()>> = OnceLock::new();
static OUTCOME: OnceLock<Result<(), ServiceError>> = OnceLock::new();

pub(crate) fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::Acquire)
}

pub(crate) fn dispatch() -> Result<(), ServiceError> {
    if DISPATCHED.swap(true, Ordering::AcqRel) {
        return Err(ServiceError::AlreadyDispatched);
    }
    windows_service::service_dispatcher::start(crate::SERVICE_NAME, scm_main)
        .map_err(|e| scm_error(ServiceOperation::Dispatch, e))?;
    OUTCOME
        .get()
        .copied()
        .unwrap_or(Err(ServiceError::WorkerFailed))
}

extern "system" fn scm_main(argument_count: u32, _arguments: *mut *mut u16) {
    // SCM owns argument pointers; we deliberately never dereference or retain
    // them. Only argv[0] (the SCM service name) is permitted, no runtime payload.
    let result = std::panic::catch_unwind(|| service_main(argument_count))
        .unwrap_or(Err(ServiceError::WorkerFailed));
    let _ = OUTCOME.set(result);
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    // No Rust unwind may cross the Windows callback ABI, including an unexpected
    // panic in a future change to the bounded notification path.
    std::panic::catch_unwind(|| handle_control(control)).unwrap_or(ERROR_EXCEPTION_IN_SERVICE.0)
}

fn handle_control(control: u32) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP_REQUESTED.store(true, Ordering::Release);
            crate::runtime::PROBE_REQUESTS.close();
        }
        SERVICE_CONTROL_INTERROGATE => (),
        crate::PROBE_CONTROL_CODE => {
            // The existing service DACL grants user-defined control only to
            // SYSTEM/Administrators. This callback only latches one request;
            // no file, token, UIA or child-process operation occurs here.
            return match crate::runtime::PROBE_REQUESTS.request() {
                Ok(()) => 0,
                Err(ServiceError::ProbeBusy) => ERROR_BUSY.0,
                Err(ServiceError::ProbeSlotsFull) => ERROR_NO_MORE_FILES.0,
                Err(_) => ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0,
            };
        }
        _ => return ERROR_CALL_NOT_IMPLEMENTED.0,
    }
    // A full notification queue cannot discard Stop: the atomic latch above
    // survives it. No blocking work occurs in a Windows control callback.
    if let Some(sender) = CONTROLS.get() {
        let _ = sender.try_send(());
    }
    0
}

struct Reporter {
    handle: SERVICE_STATUS_HANDLE,
    last: SERVICE_STATUS,
    phase: ReportPhase,
}

impl Reporter {
    fn register() -> Result<Self, ServiceError> {
        // SAFETY: fixed terminated service name, static ABI-correct callback,
        // null context never dereferenced. SCM owns the returned status handle;
        // it must NOT be passed to CloseHandle/CloseServiceHandle.
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(w!("UacRemoteController"), Some(control_handler), None)
        }
        .map_err(|e| win_error(ServiceOperation::RegisterHandler, e))?;
        Ok(Self {
            handle,
            last: SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                ..Default::default()
            },
            phase: ReportPhase::Starting,
        })
    }

    fn report(
        &mut self,
        phase: ReportPhase,
        checkpoint: u32,
        failure: Option<ServiceError>,
    ) -> Result<(), ServiceError> {
        #[cfg(all(windows, feature = "lab-software-identity"))]
        if let Some(failure) = &failure {
            crate::lab::record_failure(failure);
        }
        let status = Self::status_for(phase, checkpoint, failure);
        self.send_status(&status)?;
        // Interrogation/progress repeat only a status actually accepted by SCM.
        self.last = status;
        self.phase = phase;
        Ok(())
    }

    fn status_for(
        phase: ReportPhase,
        checkpoint: u32,
        failure: Option<ServiceError>,
    ) -> SERVICE_STATUS {
        let state = match phase {
            ReportPhase::Starting => SERVICE_START_PENDING,
            ReportPhase::PlatformInitializing | ReportPhase::Ready => SERVICE_RUNNING,
            ReportPhase::Stopping => SERVICE_STOP_PENDING,
            ReportPhase::Stopped => SERVICE_STOPPED,
        };
        let pending = phase.pending();
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if phase.accepts_controls() {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: if failure.is_some() {
                ERROR_SERVICE_SPECIFIC_ERROR.0
            } else {
                0
            },
            dwServiceSpecificExitCode: failure.map_or(0, ServiceError::service_diagnostic_code),
            dwCheckPoint: if pending { checkpoint } else { 0 },
            dwWaitHint: if pending {
                LIFECYCLE_TIMEOUT.as_millis() as u32
            } else {
                0
            },
        }
    }

    fn repeat(&self) -> Result<(), ServiceError> {
        self.send_status(&self.last)
    }

    fn send_status(&self, status: &SERVICE_STATUS) -> Result<(), ServiceError> {
        // SAFETY: handle belongs to this registered SCM service; initialized
        // status is borrowed for one synchronous call, and never held by Windows.
        unsafe { SetServiceStatus(self.handle, status) }
            .map_err(|e| win_error(ServiceOperation::ReportStatus, e))
    }
}

fn service_main(argument_count: u32) -> Result<(), ServiceError> {
    let (sender, controls) = mpsc::sync_channel(8);
    CONTROLS
        .set(sender)
        .map_err(|_| ServiceError::AlreadyDispatched)?;
    let mut reporter = Reporter::register()?;
    reporter.report(ReportPhase::Starting, 1, None)?;
    if argument_count != 1 {
        reporter.report(
            ReportPhase::Stopped,
            0,
            Some(ServiceError::InvalidArguments),
        )?;
        return Err(ServiceError::InvalidArguments);
    }
    let startup_began = Instant::now();
    let mut worker = match Worker::spawn(startup_began) {
        Ok(worker) => worker,
        Err(error) => {
            reporter.report(ReportPhase::Stopped, 0, Some(error))?;
            return Err(error);
        }
    };
    lifecycle(&mut reporter, &mut worker, &controls, startup_began)
}

fn lifecycle(
    reporter: &mut Reporter,
    worker: &mut Worker,
    controls: &Receiver<()>,
    startup_began: Instant,
) -> Result<(), ServiceError> {
    let mut pending_since = Some(startup_began);
    let mut stopping = false;
    let mut checkpoint = 1u32;
    let mut finished = None;
    loop {
        if let Some(began) = pending_since {
            remaining_budget(began.elapsed())?;
        }
        if stop_requested() && !stopping {
            stopping = true;
            pending_since = Some(continuing_pending_start(pending_since, Instant::now()));
            checkpoint = 1;
            reporter.report(ReportPhase::Stopping, checkpoint, None)?;
            worker.request_stop();
        }
        if finished.is_none() {
            match worker.next_event()? {
                Some(WorkerEvent::Progress) if !stopping => {
                    checkpoint = checkpoint.saturating_add(1);
                    // Initialization progress cannot regress an accepted Running
                    // report or advertise readiness before the actual Ready event.
                    reporter.report(reporter.phase.progress()?, checkpoint, None)?;
                }
                Some(WorkerEvent::ScmRunningRequired(request)) if !stopping => {
                    let phase = reporter.phase.platform_initializing()?;
                    request.complete_after_report(startup_began, stop_requested, || {
                        reporter.report(phase, 0, None)
                    })?;
                    // Only platform initialization is released. The original
                    // pending deadline and closed probe/control admission remain.
                }
                Some(WorkerEvent::Ready(request)) if !stopping => {
                    let phase = reporter.phase.ready()?;
                    request.complete_after_report(
                        startup_began,
                        stop_requested,
                        || reporter.report(phase, 0, None),
                        || crate::runtime::PROBE_REQUESTS.enable_after_scm_running(),
                    )?;
                    pending_since = None;
                }
                Some(WorkerEvent::Finished(result)) => {
                    finished = Some(worker_finished_outcome(result, stopping));
                    pending_since = Some(continuing_pending_start(pending_since, Instant::now()));
                    reporter.report(ReportPhase::Stopping, 1, None)?;
                }
                Some(_) | None => (),
            }
        }
        if let Some(outcome) = finished
            && worker.is_finished()
        {
            let joined = worker.join_finished();
            let outcome = outcome.and(joined);
            reporter.report(ReportPhase::Stopped, 0, outcome.err())?;
            return outcome;
        }
        match controls.recv_timeout(POLL_INTERVAL) {
            Ok(()) => reporter.repeat()?,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ServiceError::WorkerFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_running_has_no_controls_until_worker_ready() {
        let platform = ReportPhase::Starting.platform_initializing().unwrap();
        for phase in [platform, platform.progress().unwrap()] {
            let status = Reporter::status_for(phase, 9, None);
            assert_eq!(status.dwCurrentState, SERVICE_RUNNING);
            assert_eq!(status.dwControlsAccepted, 0);
            assert_eq!(status.dwCheckPoint, 0);
            assert_eq!(status.dwWaitHint, 0);
        }
        let ready = Reporter::status_for(platform.ready().unwrap(), 9, None);
        assert_eq!(ready.dwCurrentState, SERVICE_RUNNING);
        assert_eq!(
            ready.dwControlsAccepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
    }

    #[test]
    fn failed_startup_reports_real_error_without_readiness_controls() {
        let stopping = Reporter::status_for(ReportPhase::Stopping, 1, None);
        assert_eq!(stopping.dwCurrentState, SERVICE_STOP_PENDING);
        assert_eq!(stopping.dwControlsAccepted, 0);
        let stopped = Reporter::status_for(
            ReportPhase::Stopped,
            0,
            Some(ServiceError::IdentityUnavailable),
        );
        assert_eq!(stopped.dwCurrentState, SERVICE_STOPPED);
        assert_eq!(stopped.dwControlsAccepted, 0);
        assert_eq!(stopped.dwWin32ExitCode, ERROR_SERVICE_SPECIFIC_ERROR.0);
        assert_eq!(
            stopped.dwServiceSpecificExitCode,
            ServiceError::IdentityUnavailable.service_diagnostic_code()
        );
    }
}
