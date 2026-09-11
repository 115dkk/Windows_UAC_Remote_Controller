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
    CHALLENGE_BYTES, Challenge, HelperMessage, MAX_REPORT_BYTES, MAX_WATCH_MESSAGE_BYTES,
    ReportOutcome, ServiceMessage, decode_report,
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
            if let Some(mut run) = self.active.take() {
                // Closing the owned kill-on-close job is a final termination
                // request, NOT confirmation. Retain all other handles/buffers and
                // the process-wide lease until OS process teardown. No UAF and
                // no new helper is allowed while this ownership is uncertain.
                run.job.close();
                run.job_closed = true;
                mem::forget(run);
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
        self.active
            .as_ref()
            .map_or(0, |active| active.preflight.session.id)
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
        let exited_cleanly = match run.process() {
            Ok(process) => match exited(process, 0) {
                Ok(exited) => exited,
                Err(_) if began.elapsed() < WATCH_SHUTDOWN_BUDGET => return false,
                Err(_) => {
                    self.poisoned = true;
                    return false;
                }
            },
            Err(_) if began.elapsed() < WATCH_SHUTDOWN_BUDGET => return false,
            Err(_) => {
                self.poisoned = true;
                return false;
            }
        };
        if self.stop_issued && exited_cleanly {
            if run.cancel_io().is_err() {
                self.poisoned = true;
                return false;
            }
            match run.poll_cleanup() {
                Ok(true) => {
                    self.active = None;
                    self.release_unused_lease();
                    return !self.is_quarantined();
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
        if !run.job_closed {
            if run.cancel_io().is_err() {
                self.poisoned = true;
                return false;
            }
            run.job.close();
            run.job_closed = true;
            if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
                self.poisoned = true;
                return false;
            }
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
        if let Some(mut run) = self.active.take() {
            if !run.job_closed {
                run.job.close();
                run.job_closed = true;
            }
            mem::forget(run);
        }
    }
}

struct ActiveRun {
    preflight: Preflight,
    job: Handle,
    job_closed: bool,
    child: Option<Handle>,
    thread: Option<Handle>,
    pipe: Option<Handle>,
    operation: Option<PendingIo>,
    watch_read: Option<PendingIo>,
    watch_write: Option<PendingIo>,
    watch_connected: bool,
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
            job_closed: false,
            child: None,
            thread: None,
            pipe: None,
            operation: None,
            watch_read: None,
            watch_write: None,
            watch_connected: false,
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
    fn launch_watch(&mut self) -> Result<(), Error> {
        self.preflight.recheck()?;
        launch::child(self, true)?;
        launch::assign_and_authenticate(self)?;
        self.pipe = Some(launch::pipe(&self.preflight, self.pid)?);
        self.operation = Some(PendingIo::start_watch(
            self.pipe()?,
            Kind::Connect,
            Stage::ConnectPipe,
        )?);
        self.preflight.recheck()?;
        // SAFETY: retained created child's sole suspended thread. Fixed job, pipe,
        // token and image checks completed before the exact watch argv is resumed.
        let previous =
            unsafe { ResumeThread(self.thread.as_ref().ok_or(Error::PeerMismatch)?.raw()) };
        if previous != 1 {
            return Err(if previous == u32::MAX {
                native(Stage::CreateChild, WinError::from_thread())
            } else {
                Error::PeerMismatch
            });
        }
        Ok(())
    }

    fn poll_watch(&mut self) -> Result<WatchPoll, Error> {
        if exited(self.process()?, 0)? {
            return Ok(WatchPoll::Exited);
        }
        let pipe = self.pipe()?;
        if !self.watch_connected {
            let Some(operation) = &mut self.operation else {
                return Err(Error::InvalidReport);
            };
            match operation.poll(pipe)? {
                None => return Ok(WatchPoll::Pending),
                Some(Completed::Count(0)) => {
                    self.operation = None;
                    self.authenticate_pipe()?;
                    self.watch_connected = true;
                }
                Some(_) => return Err(Error::InvalidReport),
            }
        }
        if let Some(write) = &mut self.watch_write
            && let Some(completed) = write.poll(pipe)?
        {
            match completed {
                Completed::Count(count)
                    if count == write.expected_write_bytes().ok_or(Error::InvalidReport)? =>
                {
                    self.watch_write = None;
                }
                _ => return Err(Error::InvalidReport),
            }
        }
        if self.watch_read.is_none() {
            self.watch_read = Some(PendingIo::start_watch(
                pipe,
                Kind::Read(MAX_WATCH_MESSAGE_BYTES),
                Stage::ReportRead,
            )?);
        }
        let read = self.watch_read.as_mut().ok_or(Error::InvalidReport)?;
        match read.poll(pipe)? {
            None => Ok(WatchPoll::Pending),
            Some(Completed::Bytes(bytes)) => {
                self.watch_read = None;
                let message = HelperMessage::from_wire(&bytes).map_err(|_| Error::InvalidReport)?;
                Ok(WatchPoll::Message(message))
            }
            Some(Completed::Eof) => {
                self.watch_read = None;
                Ok(WatchPoll::Exited)
            }
            Some(Completed::Count(_)) => Err(Error::InvalidReport),
        }
    }

    fn write_watch(&mut self, message: &ServiceMessage) -> Result<(), Error> {
        if !self.watch_connected {
            return Err(Error::Busy);
        }
        let pipe = self.pipe()?;
        if let Some(write) = &mut self.watch_write {
            match write.poll(pipe)? {
                Some(Completed::Count(count))
                    if count == write.expected_write_bytes().ok_or(Error::InvalidReport)? =>
                {
                    self.watch_write = None;
                }
                Some(_) => return Err(Error::InvalidReport),
                None => return Err(Error::Busy),
            }
        }
        let bytes = message.to_wire().map_err(|_| Error::InvalidReport)?;
        self.watch_write = Some(PendingIo::start_watch(
            pipe,
            Kind::Write(&bytes),
            Stage::ChallengeWrite,
        )?);
        Ok(())
    }

    fn execute(&mut self) -> Result<ReportOutcome, Error> {
        self.preflight.recheck()?;
        self.budget()?;
        launch::child(self, false)?;
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
            // One complete message and one extra byte to reject an oversized
            // frame. PendingIo heap-allocates it and retains it through cancel.
            Kind::Read(MAX_REPORT_BYTES + 1),
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
        let expected = match &report {
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
        self.cleanup_with_budget(CLEANUP_BUDGET)
    }

    fn cancel_io(&mut self) -> Result<(), Error> {
        if let Some(pipe) = &self.pipe {
            for operation in [
                &mut self.operation,
                &mut self.watch_read,
                &mut self.watch_write,
            ]
            .into_iter()
            .flatten()
            {
                operation.cancel(pipe.raw())?;
            }
        }
        Ok(())
    }

    fn request_termination(&mut self) -> Result<(), Error> {
        self.cancel_io()?;
        if let Some(child) = &self.child
            && !exited(child.raw(), 0)?
        {
            // SAFETY: terminate only this newly owned job or, if assignment
            // failed, the still-suspended child created by this supervisor.
            // Failure never relinquishes ownership or counts as termination.
            let result = unsafe {
                if self.assigned && !self.job_closed {
                    TerminateJobObject(self.job.raw(), 2)
                } else if self.assigned {
                    Ok(())
                } else {
                    TerminateProcess(child.raw(), 2)
                }
            };
            if result.is_err() && !exited(child.raw(), 0)? {
                return Err(Error::CleanupUnconfirmed);
            }
        }
        Ok(())
    }

    fn poll_cleanup(&mut self) -> Result<bool, Error> {
        let mut io_done = true;
        if let Some(pipe) = &self.pipe {
            for operation in [
                &mut self.operation,
                &mut self.watch_read,
                &mut self.watch_write,
            ] {
                if let Some(pending) = operation {
                    let in_flight = match pending.poll(pipe.raw()) {
                        Ok(_) => pending.in_flight(),
                        Err(_) if pending.in_flight() => {
                            return Err(Error::CleanupUnconfirmed);
                        }
                        Err(_) => false,
                    };
                    if in_flight {
                        io_done = false;
                    } else {
                        *operation = None;
                    }
                }
            }
        }
        let process_done = match &self.child {
            Some(child) => exited(child.raw(), 0)?,
            None => true,
        };
        // Once kill-on-close was requested, the retained process wait is the
        // available completion proof because the job handle can no longer be
        // queried. Before close, retain the stronger empty-job check.
        let job_done = if self.job_closed {
            process_done
        } else {
            self.job_empty()?
        };
        Ok(process_done && io_done && job_done)
    }

    fn cleanup_with_budget(&mut self, budget: Duration) -> Result<bool, Error> {
        let began = Instant::now();
        self.request_termination()?;
        loop {
            if self.poll_cleanup()? {
                return Ok(true);
            }
            if began.elapsed() >= budget {
                return Ok(false);
            }
            let event = self
                .operation
                .as_ref()
                .filter(|operation| operation.in_flight())
                .or_else(|| {
                    self.watch_read
                        .as_ref()
                        .filter(|operation| operation.in_flight())
                })
                .or_else(|| {
                    self.watch_write
                        .as_ref()
                        .filter(|operation| operation.in_flight())
                })
                .map(PendingIo::event)
                .or_else(|| self.child.as_ref().map(Handle::raw));
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
