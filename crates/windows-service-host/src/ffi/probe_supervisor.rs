// SPDX-License-Identifier: GPL-2.0-or-later
//! Private, thread-affine native supervisor. No process handle or launch parameter
//! crosses the safe public boundary. This module is dormant until a separately
//! reviewed service-internal call is added.
use crate::{ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::{
    marker::PhantomData,
    mem,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            JobObjects::{
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
                QueryInformationJobObject, TerminateJobObject,
            },
            Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId},
            Threading::{GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject},
        },
    },
    core::Error as WinError,
};
use windows_prompt_probe::supervision::{
    CHALLENGE_BYTES, Challenge, REPORT_BYTES, ReportOutcome, decode_report,
};

mod io;
mod launch;
mod preflight;
mod token;
use io::{Completed, Kind, PendingIo};
use preflight::Preflight;

static OWNED: AtomicBool = AtomicBool::new(false);
// A failed CloseHandle is not proof of release. Never reset this process-local
// latch: another supervisor must not hide or replace uncertain native ownership.
static CLOSE_FAILURE: AtomicI32 = AtomicI32::new(0);
const CLEANUP_BUDGET: Duration = Duration::from_millis(1_000);

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
            if let Some(mut run) = self.active.take() {
                // Closing the owned kill-on-close job is a final termination
                // request, NOT confirmation. Retain all other handles/buffers and
                // the process-wide lease until OS process teardown. No UAF and
                // no new helper is allowed while this ownership is uncertain.
                run.job.close();
                mem::forget(run);
            }
            return;
        }
        OWNED.store(false, Ordering::Release);
    }
}

struct ActiveRun {
    preflight: Preflight,
    job: Handle,
    child: Option<Handle>,
    thread: Option<Handle>,
    pipe: Option<Handle>,
    operation: Option<PendingIo>,
    pid: u32,
    creation: u64,
    assigned: bool,
    began: Instant,
}
impl ActiveRun {
    fn prepare(preflight: Preflight) -> Result<Self, Error> {
        let job = launch::job(&preflight)?;
        Ok(Self {
            preflight,
            job,
            child: None,
            thread: None,
            pipe: None,
            operation: None,
            pid: 0,
            creation: 0,
            assigned: false,
            began: Instant::now(),
        })
    }
    fn process(&self) -> Result<HANDLE, Error> {
        self.child
            .as_ref()
            .map(Handle::raw)
            .ok_or(Error::PeerMismatch)
    }
    fn pipe(&self) -> Result<HANDLE, Error> {
        self.pipe
            .as_ref()
            .map(Handle::raw)
            .ok_or(Error::PeerMismatch)
    }
    fn budget(&self) -> Result<u32, Error> {
        crate::probe_supervisor::wait_slice(self.began.elapsed())
    }
    fn execute(&mut self) -> Result<ReportOutcome, Error> {
        self.preflight.recheck()?;
        self.budget()?;
        launch::child(self)?;
        self.budget()?;
        launch::assign_and_authenticate(self)?;
        self.pipe = Some(launch::pipe(&self.preflight, self.pid)?);
        self.operation = Some(PendingIo::start(
            self.pipe()?,
            Kind::Connect,
            Stage::ConnectPipe,
            self.began,
        )?);
        self.preflight.recheck()?;
        self.budget()?;
        // SAFETY: retained created child's sole initial thread, created suspended;
        // job assignment/authentication and pipe creation succeeded first. No UI
        // input or foreign process thread is resumed. Exactly one suspension only.
        let previous =
            unsafe { ResumeThread(self.thread.as_ref().ok_or(Error::PeerMismatch)?.raw()) };
        if previous == u32::MAX {
            return Err(native(Stage::CreateChild, WinError::from_thread()));
        }
        if previous != 1 {
            return Err(Error::PeerMismatch);
        }
        if !matches!(self.await_io()?, Completed::Count(0)) {
            return Err(Error::InvalidReport);
        }
        self.authenticate_pipe()?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::EntropyUnavailable)?;
        let challenge = Challenge::new(nonce).map_err(|_| Error::EntropyUnavailable)?;
        // Authentication/SCM/WTS and entropy calls may have consumed the budget.
        // Never issue the UIA-start challenge based on an earlier observation.
        self.budget()?;
        self.operation = Some(PendingIo::start(
            self.pipe()?,
            Kind::Write(&challenge.encode()),
            Stage::ChallengeWrite,
            self.began,
        )?);
        if !matches!(self.await_io()?, Completed::Count(CHALLENGE_BYTES)) {
            return Err(Error::InvalidReport);
        }
        self.operation = Some(PendingIo::start(
            self.pipe()?,
            Kind::Read(REPORT_BYTES + 1),
            Stage::ReportRead,
            self.began,
        )?);
        let Completed::Bytes(bytes) = self.await_io()? else {
            return Err(Error::InvalidReport);
        };
        let report = decode_report(&bytes, challenge).map_err(|_| Error::InvalidReport)?;
        // One message only. Any second byte/message, even a second valid report,
        // is rejected. EOF alone is insufficient until the retained child exits.
        self.operation = Some(PendingIo::start(
            self.pipe()?,
            Kind::Read(1),
            Stage::EofRead,
            self.began,
        )?);
        if !matches!(self.await_io()?, Completed::Eof) {
            return Err(Error::InvalidReport);
        }
        let process = self.process()?;
        loop {
            let wait = self.budget()?;
            if exited(process, wait)? {
                break;
            }
        }
        let code = exit_code(process)?;
        let expected = match report {
            ReportOutcome::Observed(_) => 0,
            ReportOutcome::Unavailable(_) => 1,
        };
        if code != expected {
            return Err(Error::HelperFailed(code));
        }
        if !self.job_empty()? {
            return Err(Error::CleanupUnconfirmed);
        }
        self.preflight.recheck()?;
        self.budget()?;
        Ok(report)
    }
    fn await_io(&mut self) -> Result<Completed, Error> {
        loop {
            let wait = self.budget()?;
            let pipe = self.pipe()?;
            let operation = self.operation.as_mut().ok_or(Error::InvalidReport)?;
            if let Some(completed) = operation.poll(pipe)? {
                self.operation.take();
                return Ok(completed);
            }
            // SAFETY: own operation's live event. Short bounded waits permit
            // deadline/process checks; no sleep or UI/message pumping occurs.
            match unsafe { WaitForSingleObject(operation.event(), wait) } {
                WAIT_OBJECT_0 | WAIT_TIMEOUT => (),
                _ => return Err(native(Stage::ReportRead, WinError::from_thread())),
            }
            if exited(self.process()?, 0)? {
                // Drain any already-buffered completed report/EOF after exit,
                // but never wait a fresh interval for a dead child's handshake.
                let pipe = self.pipe()?;
                let operation = self.operation.as_mut().ok_or(Error::InvalidReport)?;
                if let Some(completed) = operation.poll(pipe)? {
                    self.operation.take();
                    return Ok(completed);
                }
                return Err(Error::HelperFailed(exit_code(self.process()?)?));
            }
        }
    }
    fn authenticate_pipe(&self) -> Result<(), Error> {
        let (mut pid, mut session) = (0, 0);
        // SAFETY: exclusively owned connected local pipe, distinct scalar out;
        // no impersonation or name-based trust. Match actual retained child.
        unsafe { GetNamedPipeClientProcessId(self.pipe()?, &mut pid) }
            .map_err(|error| native(Stage::AuthenticatePeer, error))?;
        // SAFETY: same live connected endpoint, initialized scalar session out.
        unsafe { GetNamedPipeClientSessionId(self.pipe()?, &mut session) }
            .map_err(|error| native(Stage::AuthenticatePeer, error))?;
        if pid != self.pid || session != self.preflight.session.id || exited(self.process()?, 0)? {
            return Err(Error::PeerMismatch);
        }
        launch::authenticate_child(self)?;
        self.preflight.recheck()
    }
    fn job_empty(&self) -> Result<bool, Error> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut length = 0;
        // SAFETY: owned job, fixed accounting query and initialized exact output.
        unsafe {
            QueryInformationJobObject(
                Some(self.job.raw()),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                mem::size_of_val(&info) as u32,
                Some(&mut length),
            )
        }
        .map_err(|error| native(Stage::CleanupWait, error))?;
        if length as usize != mem::size_of_val(&info) {
            return Err(Error::CleanupUnconfirmed);
        }
        Ok(info.ActiveProcesses == 0)
    }
    fn cleanup(&mut self) -> Result<bool, Error> {
        let began = Instant::now();
        if let (Some(pipe), Some(operation)) = (&self.pipe, &mut self.operation) {
            let _ = operation.cancel(pipe.raw());
        }
        if let Some(child) = &self.child
            && !exited(child.raw(), 0)?
        {
            // SAFETY: terminate only this newly owned job or, if assignment
            // failed, the still-suspended child created by this supervisor.
            // Failure never relinquishes ownership or counts as termination.
            let result = unsafe {
                if self.assigned {
                    TerminateJobObject(self.job.raw(), 2)
                } else {
                    TerminateProcess(child.raw(), 2)
                }
            };
            if result.is_err() && !exited(child.raw(), 0)? {
                return Ok(false);
            }
        }
        loop {
            let mut io_done = true;
            if let (Some(pipe), Some(operation)) = (&self.pipe, &mut self.operation) {
                let _ = operation.poll(pipe.raw());
                io_done = !operation.in_flight();
                if io_done {
                    self.operation.take();
                }
            }
            let process_done = match &self.child {
                Some(child) => exited(child.raw(), 0)?,
                None => true,
            };
            if process_done && io_done && self.job_empty()? {
                return Ok(true);
            }
            if began.elapsed() >= CLEANUP_BUDGET {
                return Ok(false);
            }
            let event = if !io_done {
                self.operation.as_ref().map(PendingIo::event)
            } else {
                self.child.as_ref().map(Handle::raw)
            };
            if let Some(event) = event {
                // SAFETY: retained event/process handle; bounded wait only. A
                // signaled event does NOT by itself establish cancellation.
                match unsafe { WaitForSingleObject(event, 10) } {
                    WAIT_OBJECT_0 | WAIT_TIMEOUT => (),
                    _ => return Ok(false),
                }
            } else {
                return Ok(false);
            }
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
