// SPDX-License-Identifier: GPL-2.0-or-later
//! Sole SCM callback boundary. Callbacks retain no user data/raw context pointer;
//! their bounded channel is process-lifetime owned, not freed after first Stop.

use crate::{
    ServiceError, ServiceOperation,
    contract::{LIFECYCLE_TIMEOUT, POLL_INTERVAL, continuing_pending_start, remaining_budget},
    ffi::win_error,
    native::scm_error,
    runtime::{Worker, WorkerEvent},
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
            SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
            SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
            SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
        },
    },
    core::w,
};

static DISPATCHED: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static CONTROLS: OnceLock<SyncSender<()>> = OnceLock::new();
static OUTCOME: OnceLock<Result<(), ServiceError>> = OnceLock::new();

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
        })
    }

    fn report(
        &mut self,
        state: SERVICE_STATUS_CURRENT_STATE,
        checkpoint: u32,
        failure: Option<ServiceError>,
    ) -> Result<(), ServiceError> {
        let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
        self.last = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: if failure.is_some() {
                ERROR_SERVICE_SPECIFIC_ERROR.0
            } else {
                0
            },
            dwServiceSpecificExitCode: failure.map_or(0, |error| u32::from(error.exit_code())),
            dwCheckPoint: if pending { checkpoint } else { 0 },
            dwWaitHint: if pending {
                LIFECYCLE_TIMEOUT.as_millis() as u32
            } else {
                0
            },
        };
        self.repeat()
    }

    fn repeat(&self) -> Result<(), ServiceError> {
        // SAFETY: handle belongs to this registered SCM service; initialized
        // status is borrowed for one synchronous call, and never held by Windows.
        unsafe { SetServiceStatus(self.handle, &self.last) }
            .map_err(|e| win_error(ServiceOperation::ReportStatus, e))
    }
}

fn service_main(argument_count: u32) -> Result<(), ServiceError> {
    let (sender, controls) = mpsc::sync_channel(8);
    CONTROLS
        .set(sender)
        .map_err(|_| ServiceError::AlreadyDispatched)?;
    let mut reporter = Reporter::register()?;
    reporter.report(SERVICE_START_PENDING, 1, None)?;
    if argument_count != 1 {
        reporter.report(SERVICE_STOPPED, 0, Some(ServiceError::InvalidArguments))?;
        return Err(ServiceError::InvalidArguments);
    }
    let mut worker = match Worker::spawn() {
        Ok(worker) => worker,
        Err(error) => {
            reporter.report(SERVICE_STOPPED, 0, Some(error))?;
            return Err(error);
        }
    };
    lifecycle(&mut reporter, &mut worker, &controls)
}

fn lifecycle(
    reporter: &mut Reporter,
    worker: &mut Worker,
    controls: &Receiver<()>,
) -> Result<(), ServiceError> {
    let mut pending_since = Some(Instant::now());
    let mut stopping = false;
    let mut checkpoint = 1u32;
    let mut finished = None;
    loop {
        if let Some(began) = pending_since {
            remaining_budget(began.elapsed())?;
        }
        if STOP_REQUESTED.load(Ordering::Acquire) && !stopping {
            stopping = true;
            pending_since = Some(Instant::now());
            checkpoint = 1;
            reporter.report(SERVICE_STOP_PENDING, checkpoint, None)?;
            worker.request_stop();
        }
        if finished.is_none() {
            match worker.next_event()? {
                Some(WorkerEvent::Progress) if !stopping => {
                    checkpoint = checkpoint.saturating_add(1);
                    reporter.report(SERVICE_START_PENDING, checkpoint, None)?;
                }
                Some(WorkerEvent::Ready) if !stopping => {
                    reporter.report(SERVICE_RUNNING, 0, None)?;
                    crate::runtime::PROBE_REQUESTS.enable_after_scm_running();
                    pending_since = None;
                }
                Some(WorkerEvent::Finished(result)) => {
                    let result = if !stopping && result.is_ok() {
                        Err(ServiceError::WorkerFailed)
                    } else {
                        result
                    };
                    finished = Some(result);
                    pending_since = Some(continuing_pending_start(pending_since, Instant::now()));
                    reporter.report(SERVICE_STOP_PENDING, 1, None)?;
                }
                Some(_) | None => (),
            }
        }
        if let Some(outcome) = finished
            && worker.is_finished()
        {
            let joined = worker.join_finished();
            let outcome = outcome.and(joined);
            reporter.report(SERVICE_STOPPED, 0, outcome.err())?;
            return outcome;
        }
        match controls.recv_timeout(POLL_INTERVAL) {
            Ok(()) => reporter.repeat()?,
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ServiceError::WorkerFailed),
        }
    }
}
