// SPDX-License-Identifier: GPL-2.0-or-later
//! Private, thread-affine native supervisor. No process handle or launch parameter
//! crosses the safe public boundary. This module is dormant until a separately
//! reviewed service-internal call is added.
use crate::{ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{GetExitCodeProcess, WaitForSingleObject},
    },
    core::Error as WinError,
};
use windows_prompt_probe::supervision::{HelperMessage, ReportOutcome, ServiceMessage};

mod active_run;
#[cfg(test)]
mod active_run_tests;
mod native_run;
use active_run::ActiveRun;
mod io;
mod launch;
pub(in crate::ffi) mod pairing_inspector;
mod preflight;
mod token;

use preflight::Preflight;

static OWNED: AtomicBool = AtomicBool::new(false);
// A failed CloseHandle is not proof of release. Never reset this process-local
// latch: another supervisor must not hide or replace uncertain native ownership.
static CLOSE_FAILURE: AtomicI32 = AtomicI32::new(0);
const CLEANUP_BUDGET: Duration = Duration::from_millis(1_000);
const WATCH_SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

pub(super) fn native(stage: Stage, error: WinError) -> Error {
    Error::Native {
        stage,
        hresult: error.code().0,
    }
}

pub(super) struct Handle {
    value: Option<HANDLE>,
    _thread: PhantomData<Rc<()>>,
}
impl Handle {
    fn new(value: HANDLE, stage: Stage) -> Result<Self, Error> {
        if value.is_invalid() {
            return Err(native(stage, WinError::from_thread()));
        }
        Ok(Self {
            value: Some(value),
            _thread: PhantomData,
        })
    }
    fn raw(&self) -> HANDLE {
        self.value.unwrap_or_default()
    }
    fn close(&mut self) {
        if let Some(value) = self.value.take() {
            // SAFETY: uniquely owned real kernel handle, never pseudo/inherited.
            // Callers close the job deliberately to trigger kill-on-close; other
            // native borrows have completed, or pending I/O storage is retained.
            if let Err(error) = unsafe { CloseHandle(value) } {
                let _ = CLOSE_FAILURE.compare_exchange(
                    0,
                    error.code().0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct Supervisor {
    active: Option<ActiveRun>,
    // Original fixed failure is retained while cleanup is unresolved. It is not
    // replaced with a fabricated completed report, including after retry errors.
    failure: Option<Error>,
    poisoned: bool,
}
impl Supervisor {
    pub(crate) fn new() -> Result<Self, Error> {
        if OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let mut owner = Self {
            active: None,
            failure: None,
            poisoned: false,
        };
        let result = Preflight::observe();
        match result {
            Ok(preflight) => drop(preflight),
            Err(error) => {
                owner.failure = Some(error);
                owner.check_close_failure()?;
                return Err(error);
            }
        }
        owner.check_close_failure()?;
        Ok(owner)
    }
    fn check_close_failure(&mut self) -> Result<(), Error> {
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            self.poisoned = true;
            return Err(Error::CleanupUnconfirmed);
        }
        Ok(())
    }
    pub(crate) fn is_quarantined(&self) -> bool {
        self.active.is_some() || self.poisoned || CLOSE_FAILURE.load(Ordering::Acquire) != 0
    }
    pub(crate) fn quarantined_cause(&self) -> Option<Error> {
        if !self.is_quarantined() {
            return None;
        }
        self.failure.or_else(|| {
            let hresult = CLOSE_FAILURE.load(Ordering::Acquire);
            (hresult != 0).then_some(Error::Native {
                stage: Stage::CleanupWait,
                hresult,
            })
        })
    }
    pub(crate) fn run(&mut self) -> Result<ReportOutcome, Error> {
        if self.is_quarantined() {
            return Err(Error::Quarantined);
        }
        self.check_close_failure()?;
        self.failure = None;
        let preflight = match Preflight::observe() {
            Ok(preflight) => preflight,
            Err(error) => {
                self.failure = Some(error);
                self.check_close_failure()?;
                return Err(error);
            }
        };
        // ActiveRun adopts every successfully created child before any later
        // fallible setup. Errors after creation therefore always pass cleanup.
        self.active = Some(match ActiveRun::prepare(preflight) {
            Ok(run) => run,
            Err(error) => {
                self.failure = Some(error);
                self.check_close_failure()?;
                return Err(error);
            }
        });
        let result = self.active.as_mut().ok_or(Error::Quarantined)?.execute();
        match result {
            Ok(report) => {
                // execute proves child exit, pipe EOF, no pending I/O and empty
                // job before releasing owners. No report escapes before cleanup.
                self.active.take();
                self.check_close_failure()?;
                Ok(report)
            }
            Err(error) => {
                self.failure = Some(error);
                if self.retry_cleanup().is_err() {
                    return Err(Error::CleanupUnconfirmed);
                }
                Err(error)
            }
        }
    }
    pub(crate) fn retry_cleanup(&mut self) -> Result<(), Error> {
        if let Some(run) = &mut self.active {
            if !run.cleanup()? {
                return Err(Error::CleanupUnconfirmed);
            }
            self.active.take();
        }
        self.check_close_failure()
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        let clean = self.retry_cleanup().is_ok();
        if !clean {
            if let Some(run) = self.active.take() {
                // Closing the owned kill-on-close job is a final termination
                // request, NOT confirmation. Retain all other handles/buffers and
                // the process-wide lease until OS process teardown. No UAF and
                // no new helper is allowed while this ownership is uncertain.
                run.retain_uncertain();
            }
            return;
        }
        OWNED.store(false, Ordering::Release);
    }
}

pub(crate) enum WatchPoll {
    Pending,
    Message(HelperMessage),
    Exited,
}

pub(crate) struct WatchOwner {
    active: Option<ActiveRun>,
    shutdown_began: Option<Instant>,
    stop_issued: bool,
    poisoned: bool,
    lease_held: bool,
}
impl WatchOwner {
    pub(crate) fn new() -> Result<Self, Error> {
        if OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let mut owner = Self {
            active: None,
            shutdown_began: None,
            stop_issued: false,
            poisoned: false,
            lease_held: true,
        };
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            owner.poisoned = true;
            // Keep the process-wide lease held permanently. A prior close failure
            // means native ownership is uncertain even though this owner has no run.
            owner.lease_held = false;
            return Err(Error::CleanupUnconfirmed);
        }
        let preflight = match Preflight::observe() {
            Ok(preflight) => preflight,
            Err(error) => {
                owner.release_unused_lease();
                return Err(if owner.is_quarantined() {
                    Error::CleanupUnconfirmed
                } else {
                    error
                });
            }
        };
        owner.active = Some(match ActiveRun::prepare(preflight) {
            Ok(run) => run,
            Err(error) => {
                owner.release_unused_lease();
                return Err(if owner.is_quarantined() {
                    Error::CleanupUnconfirmed
                } else {
                    error
                });
            }
        });
        if let Err(error) = owner
            .active
            .as_mut()
            .ok_or(Error::Quarantined)?
            .launch_watch()
        {
            let cleanup = owner
                .active
                .as_mut()
                .ok_or(Error::Quarantined)?
                .cleanup_with_budget(CLEANUP_BUDGET);
            match cleanup {
                Ok(true) => {
                    owner.active = None;
                    owner.release_unused_lease();
                    return Err(if owner.is_quarantined() {
                        Error::CleanupUnconfirmed
                    } else {
                        error
                    });
                }
                Ok(false) | Err(_) => {
                    owner.poisoned = true;
                    if let Some(run) = owner.active.as_mut() {
                        let _ = run.request_termination();
                    }
                    return Err(Error::CleanupUnconfirmed);
                }
            }
        }
        Ok(owner)
    }

    fn release_unused_lease(&mut self) {
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            self.poisoned = true;
            // Do not let Drop interpret this process-wide quarantine as a lease it
            // may release. OWNED deliberately remains set.
            self.lease_held = false;
            return;
        }
        if self.active.is_none() && !self.poisoned && self.lease_held {
            OWNED.store(false, Ordering::Release);
            self.lease_held = false;
        }
    }

    pub(crate) fn session(&self) -> u32 {
        self.active.as_ref().map_or(0, ActiveRun::session)
    }

    pub(crate) fn is_quarantined(&self) -> bool {
        self.poisoned || CLOSE_FAILURE.load(Ordering::Acquire) != 0
    }

    pub(crate) fn poll(&mut self) -> Result<WatchPoll, Error> {
        if self.shutdown_began.is_some() {
            return Ok(WatchPoll::Pending);
        }
        self.active.as_mut().ok_or(Error::Quarantined)?.poll_watch()
    }

    pub(crate) fn write(&mut self, message: ServiceMessage) -> Result<(), Error> {
        if self.shutdown_began.is_some() {
            return Err(Error::ApplyRefused);
        }
        self.active
            .as_mut()
            .ok_or(Error::Quarantined)?
            .write_watch(&message)
    }

    pub(crate) fn fail_current(&mut self) -> Result<(), Error> {
        let Some(run) = &mut self.active else {
            return Ok(());
        };
        if let Err(error) = run.request_termination() {
            self.poisoned = true;
            return Err(error);
        }
        match run.poll_cleanup() {
            Ok(true) => self.active = None,
            Ok(false) => {}
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        }
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            self.poisoned = true;
            return Err(Error::CleanupUnconfirmed);
        }
        Ok(())
    }

    pub(crate) fn reap_current(&mut self) -> Result<bool, Error> {
        let Some(run) = &mut self.active else {
            return Ok(true);
        };
        match run.poll_cleanup() {
            Ok(true) => {
                self.active = None;
                Ok(true)
            }
            Ok(false) if CLOSE_FAILURE.load(Ordering::Acquire) != 0 => {
                self.poisoned = true;
                Err(Error::CleanupUnconfirmed)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    pub(crate) fn relaunch(&mut self) -> Result<(), Error> {
        if self.is_quarantined() || self.active.is_some() || self.shutdown_began.is_some() {
            return Err(Error::Quarantined);
        }
        let preflight = match Preflight::observe() {
            Ok(preflight) => preflight,
            Err(error) => {
                if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
                    self.poisoned = true;
                    return Err(Error::CleanupUnconfirmed);
                }
                return Err(error);
            }
        };
        let mut run = match ActiveRun::prepare(preflight) {
            Ok(run) => run,
            Err(error) => {
                if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
                    self.poisoned = true;
                    return Err(Error::CleanupUnconfirmed);
                }
                return Err(error);
            }
        };
        if let Err(error) = run.launch_watch() {
            match run.cleanup_with_budget(CLEANUP_BUDGET) {
                Ok(true) if CLOSE_FAILURE.load(Ordering::Acquire) != 0 => {
                    self.poisoned = true;
                    return Err(Error::CleanupUnconfirmed);
                }
                Ok(true) => return Err(error),
                Ok(false) | Err(_) => {
                    let _ = run.request_termination();
                    self.active = Some(run);
                    self.poisoned = true;
                    return Err(Error::CleanupUnconfirmed);
                }
            }
        }
        self.active = Some(run);
        Ok(())
    }

    pub(crate) fn begin_shutdown(&mut self) {
        if self.shutdown_began.is_none() {
            self.shutdown_began = Some(Instant::now());
        }
    }

    pub(crate) fn poll_shutdown(&mut self) -> bool {
        let began = *self.shutdown_began.get_or_insert_with(Instant::now);
        let Some(run) = &mut self.active else {
            self.release_unused_lease();
            return !self.is_quarantined();
        };
        if !self.stop_issued {
            match run.write_watch(&ServiceMessage::Stop) {
                Ok(()) => self.stop_issued = true,
                Err(Error::Busy) => {
                    let _ = run.poll_watch();
                    if began.elapsed() < WATCH_SHUTDOWN_BUDGET {
                        return false;
                    }
                    self.stop_issued = true;
                }
                Err(_) => self.stop_issued = true,
            }
        }
        let exited_cleanly = match run.process_exited(0) {
            Ok(exited) => exited,
            Err(_) if began.elapsed() < WATCH_SHUTDOWN_BUDGET => return false,
            Err(_) => {
                self.poisoned = true;
                return false;
            }
        };
        if self.stop_issued && exited_cleanly {
            match run.drain_shutdown() {
                Ok(true) => {
                    self.active = None;
                    self.release_unused_lease();
                    return !self.is_quarantined();
                }
                Err(active_run::ShutdownDrainError::Cancel) => {
                    self.poisoned = true;
                    return false;
                }
                Ok(false) if began.elapsed() < WATCH_SHUTDOWN_BUDGET => return false,
                Ok(false) => {}
                Err(_) if began.elapsed() < WATCH_SHUTDOWN_BUDGET => return false,
                Err(_) => {}
            }
        } else if began.elapsed() < WATCH_SHUTDOWN_BUDGET {
            let _ = run.poll_watch();
            return false;
        }
        // The graceful wait has elapsed. Close the kill-on-close job once; later
        // polls only retry proving process exit and overlapped cancellation.
        if run.close_for_shutdown().is_err() {
            self.poisoned = true;
            return false;
        }
        match run.poll_cleanup() {
            Ok(true) => {
                self.active = None;
                self.release_unused_lease();
                !self.is_quarantined()
            }
            Ok(false) => false,
            Err(_) => {
                self.poisoned = true;
                false
            }
        }
    }
}
impl Drop for WatchOwner {
    fn drop(&mut self) {
        self.begin_shutdown();
        if self.poll_shutdown() && self.active.is_none() && !self.is_quarantined() {
            return;
        }
        if let Some(run) = self.active.take() {
            run.retain_uncertain();
        }
    }
}

fn exited(process: HANDLE, timeout: u32) -> Result<bool, Error> {
    // SAFETY: retained owned process with SYNCHRONIZE, not a PID reopen; bounded
    // read-only wait is the exit proof (never STILL_ACTIVE exit-code inference).
    match unsafe { WaitForSingleObject(process, timeout) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(native(Stage::ChildWait, WinError::from_thread())),
    }
}
fn exit_code(process: HANDLE) -> Result<u32, Error> {
    let mut code = 0;
    // SAFETY: retained query handle and initialized output; callers separately
    // prove process exit, so STILL_ACTIVE is not used as a liveness sentinel.
    unsafe { GetExitCodeProcess(process, &mut code) }
        .map_err(|error| native(Stage::ChildWait, error))?;
    Ok(code)
}
