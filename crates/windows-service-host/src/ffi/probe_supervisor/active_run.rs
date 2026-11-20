// SPDX-License-Identifier: GPL-2.0-or-later
//! One owner for child, job and pending buffers. Callers retain their independent
//! leases and protocol state, but cannot release or replace native operations.
use super::{
    CLEANUP_BUDGET, Error, Stage, WatchPoll,
    io::{Completed, Kind},
    native_run::NativeRunIo,
    preflight::Preflight,
};
use std::{
    mem,
    time::{Duration, Instant},
};
use windows_prompt_probe::supervision::{
    CHALLENGE_BYTES, Challenge, HelperMessage, MAX_REPORT_BYTES, MAX_WATCH_MESSAGE_BYTES,
    ReportOutcome, ServiceMessage, decode_report,
};

// Only this adapter touches native resources. Operations remain owned by ActiveRun
// until the adapter proves their kernel borrow ended, including failed completions.
pub(super) trait RunIo {
    type Operation;
    fn recheck(&self) -> Result<(), Error>;
    fn launch_child(
        &mut self,
        watch: bool,
        inspection: Option<u64>,
        began: Instant,
    ) -> Result<(), Error>;
    fn assign_and_authenticate(&mut self, inspection: Option<u64>) -> Result<(), Error>;
    fn resume(&self) -> Result<(), Error>;
    fn authenticate_pipe(&self, inspection: Option<u64>) -> Result<(), Error>;
    fn session(&self) -> u32;
    fn start(
        &self,
        kind: Kind<'_>,
        stage: Stage,
        began: Option<Instant>,
    ) -> Result<Self::Operation, Error>;
    fn poll(&self, operation: &mut Self::Operation) -> Result<Option<Completed>, Error>;
    fn cancel(&self, operation: &mut Self::Operation) -> Result<(), Error>;
    fn in_flight(operation: &Self::Operation) -> bool;
    fn expected_write_bytes(operation: &Self::Operation) -> Option<usize>;
    fn wait_operation(&self, operation: &Self::Operation, wait: u32) -> Result<(), Error>;
    fn wait_cleanup(&self, operation: Option<&Self::Operation>) -> bool;
    fn process_exited(&self, wait: u32) -> Result<Option<bool>, Error>;
    fn exit_code(&self) -> Result<u32, Error>;
    fn job_empty(&self) -> Result<bool, Error>;
    fn terminate(&self, job_closed: bool) -> Result<(), Error>;
    fn close_job(&mut self);
    fn close_failed(&self) -> bool;
}

pub(super) enum ShutdownDrainError {
    Cancel,
    Drain,
}

pub(super) struct ActiveRun<B: RunIo = NativeRunIo> {
    io: B,
    inspection: Option<u64>,
    began: Instant,
    job_closed: bool,
    operation: Option<B::Operation>,
    watch_read: Option<B::Operation>,
    watch_write: Option<B::Operation>,
    watch_connected: bool,
}

impl ActiveRun {
    pub(super) fn prepare(preflight: Preflight) -> Result<Self, Error> {
        Ok(Self::with_io(NativeRunIo::prepare(preflight)?))
    }
    pub(super) fn prepare_inspection(preflight: Preflight, cutoff: u64) -> Result<Self, Error> {
        let mut run = Self::prepare(preflight)?;
        run.inspection = Some(cutoff);
        Ok(run)
    }
}

pub(super) fn inspection_budget(cutoff: Option<u64>) -> Result<(), Error> {
    if let Some(cutoff) = cutoff {
        crate::ffi::pairing_peer::service_positive(|| {
            crate::ffi::pairing_peer::renderer::check_cutoff(cutoff)
        })
        .map_err(|_| Error::TimedOut)?;
    }
    Ok(())
}

impl<B: RunIo> ActiveRun<B> {
    pub(super) fn with_io(io: B) -> Self {
        Self {
            io,
            inspection: None,
            began: Instant::now(),
            job_closed: false,
            operation: None,
            watch_read: None,
            watch_write: None,
            watch_connected: false,
        }
    }
    pub(super) fn session(&self) -> u32 {
        self.io.session()
    }
    fn budget(&self) -> Result<u32, Error> {
        crate::probe_supervisor::wait_slice(self.began.elapsed())
    }
    pub(super) fn process_exited(&self, wait: u32) -> Result<bool, Error> {
        self.io.process_exited(wait)?.ok_or(Error::PeerMismatch)
    }
    pub(super) fn authenticate_pipe(&self) -> Result<(), Error> {
        self.io.authenticate_pipe(self.inspection)
    }
    pub(super) fn launch_watch(&mut self) -> Result<(), Error> {
        inspection_budget(self.inspection)?;
        self.io.recheck()?;
        self.io.launch_child(true, self.inspection, self.began)?;
        self.io.assign_and_authenticate(self.inspection)?;
        self.begin_operation(Kind::Connect, Stage::ConnectPipe, None)?;
        self.io.recheck()?;
        inspection_budget(self.inspection)?;
        self.io.resume()
    }
    fn begin_operation(
        &mut self,
        kind: Kind<'_>,
        stage: Stage,
        began: Option<Instant>,
    ) -> Result<(), Error> {
        if self.operation.is_some() || self.watch_read.is_some() || self.watch_write.is_some() {
            return Err(Error::Busy);
        }
        self.operation = Some(self.io.start(kind, stage, began)?);
        Ok(())
    }
    pub(super) fn begin_inspection_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.operation.is_some() || self.watch_read.is_some() || self.watch_write.is_some() {
            return Err(Error::Busy);
        }
        self.authenticate_pipe()?;
        // Per-operation budget; never replaces the original ceremony cutoff.
        self.began = Instant::now();
        self.begin_operation(Kind::Write(bytes), Stage::ChallengeWrite, Some(self.began))
    }
    pub(super) fn begin_inspection_read(
        &mut self,
        bytes: usize,
        stage: Stage,
    ) -> Result<(), Error> {
        self.begin_operation(Kind::Read(bytes), stage, Some(self.began))
    }
    fn poll_operation(&mut self) -> Result<Option<Completed>, Error> {
        let pending = self.operation.as_mut().ok_or(Error::InvalidReport)?;
        let completed = self.io.poll(pending)?;
        if completed.is_some() {
            self.operation = None;
        }
        Ok(completed)
    }
    fn poll_operation_slice(
        &mut self,
        wait: u32,
        inspection: bool,
    ) -> Result<Option<Completed>, Error> {
        if let Some(completed) = self.poll_operation()? {
            return Ok(Some(completed));
        }
        self.io
            .wait_operation(self.operation.as_ref().ok_or(Error::InvalidReport)?, wait)?;
        if self.process_exited(0)? {
            // Consume the last buffered completion without starting a new wait
            // after exit. The operation is removed exactly once by poll_operation.
            if let Some(completed) = self.poll_operation()? {
                return Ok(Some(completed));
            }
            return Err(if inspection {
                Error::PeerMismatch
            } else {
                Error::HelperFailed(self.io.exit_code()?)
            });
        }
        Ok(None)
    }
    pub(super) fn poll_inspection_operation(&mut self) -> Result<Option<Completed>, Error> {
        self.poll_operation_slice(self.budget()?.min(25), true)
    }
    fn await_io(&mut self) -> Result<Completed, Error> {
        loop {
            if let Some(completed) = self.poll_operation_slice(self.budget()?, false)? {
                return Ok(completed);
            }
        }
    }
    pub(super) fn poll_watch(&mut self) -> Result<WatchPoll, Error> {
        if self.process_exited(0)? {
            return Ok(WatchPoll::Exited);
        }
        if !self.watch_connected {
            let operation = self.operation.as_mut().ok_or(Error::InvalidReport)?;
            match self.io.poll(operation)? {
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
            && let Some(completed) = self.io.poll(write)?
        {
            match completed {
                Completed::Count(count)
                    if count == B::expected_write_bytes(write).ok_or(Error::InvalidReport)? =>
                {
                    self.watch_write = None;
                }
                _ => return Err(Error::InvalidReport),
            }
        }
        if self.watch_read.is_none() {
            self.watch_read = Some(self.io.start(
                Kind::Read(MAX_WATCH_MESSAGE_BYTES),
                Stage::ReportRead,
                None,
            )?);
        }
        let read = self.watch_read.as_mut().ok_or(Error::InvalidReport)?;
        match self.io.poll(read)? {
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
    pub(super) fn write_watch(&mut self, message: &ServiceMessage) -> Result<(), Error> {
        if !self.watch_connected {
            return Err(Error::Busy);
        }
        if let Some(write) = &mut self.watch_write {
            match self.io.poll(write)? {
                Some(Completed::Count(count))
                    if count == B::expected_write_bytes(write).ok_or(Error::InvalidReport)? =>
                {
                    self.watch_write = None;
                }
                Some(_) => return Err(Error::InvalidReport),
                None => return Err(Error::Busy),
            }
        }
        let bytes = message.to_wire().map_err(|_| Error::InvalidReport)?;
        self.watch_write = Some(
            self.io
                .start(Kind::Write(&bytes), Stage::ChallengeWrite, None)?,
        );
        Ok(())
    }
    pub(super) fn execute(&mut self) -> Result<ReportOutcome, Error> {
        self.io.recheck()?;
        self.budget()?;
        self.io.launch_child(false, self.inspection, self.began)?;
        self.budget()?;
        self.io.assign_and_authenticate(self.inspection)?;
        self.begin_operation(Kind::Connect, Stage::ConnectPipe, Some(self.began))?;
        self.io.recheck()?;
        self.budget()?;
        self.io.resume()?;
        if !matches!(self.await_io()?, Completed::Count(0)) {
            return Err(Error::InvalidReport);
        }
        self.authenticate_pipe()?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::EntropyUnavailable)?;
        let challenge = Challenge::new(nonce).map_err(|_| Error::EntropyUnavailable)?;
        // Authentication/SCM/WTS and entropy calls may have consumed the budget.
        self.budget()?;
        self.begin_operation(
            Kind::Write(&challenge.encode()),
            Stage::ChallengeWrite,
            Some(self.began),
        )?;
        if !matches!(self.await_io()?, Completed::Count(CHALLENGE_BYTES)) {
            return Err(Error::InvalidReport);
        }
        self.begin_operation(
            Kind::Read(MAX_REPORT_BYTES + 1),
            Stage::ReportRead,
            Some(self.began),
        )?;
        let Completed::Bytes(bytes) = self.await_io()? else {
            return Err(Error::InvalidReport);
        };
        let report = decode_report(&bytes, challenge).map_err(|_| Error::InvalidReport)?;
        // One message only; any second message is rejected before child exit.
        self.begin_operation(Kind::Read(1), Stage::EofRead, Some(self.began))?;
        if !matches!(self.await_io()?, Completed::Eof) {
            return Err(Error::InvalidReport);
        }
        while !self.process_exited(self.budget()?)? {}
        let code = self.io.exit_code()?;
        let expected = match &report {
            ReportOutcome::Observed(_) => 0,
            ReportOutcome::Unavailable(_) => 1,
        };
        if code != expected {
            return Err(Error::HelperFailed(code));
        }
        // One-shot retains its single accounting query, not the inspector's wait.
        if !self.io.job_empty()? {
            return Err(Error::CleanupUnconfirmed);
        }
        self.io.recheck()?;
        self.budget()?;
        Ok(report)
    }
    pub(super) fn finish_inspection(&mut self) -> Result<(), Error> {
        while !self.process_exited(self.budget()?.min(25))? {}
        let code = self.io.exit_code()?;
        // A signalled process does not prove job disassociation. Keep the same
        // independent cleanup budget and accounting cadence as the inspector.
        let began = Instant::now();
        let mut empty = self.io.job_empty()?;
        while !empty && began.elapsed() < CLEANUP_BUDGET {
            std::thread::sleep(Duration::from_millis(5));
            empty = self.io.job_empty()?;
        }
        if code != 0 || !empty {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note(&format!(
                "inspector cleanup: exit={code:#010x} job_empty={empty}"
            ));
            return Err(Error::CleanupUnconfirmed);
        }
        Ok(())
    }
    fn cancel_io(&mut self) -> Result<(), Error> {
        for operation in [
            &mut self.operation,
            &mut self.watch_read,
            &mut self.watch_write,
        ]
        .into_iter()
        .flatten()
        {
            self.io.cancel(operation)?;
        }
        Ok(())
    }
    pub(super) fn request_termination(&mut self) -> Result<(), Error> {
        self.cancel_io()?;
        self.io.terminate(self.job_closed)
    }
    pub(super) fn drain_shutdown(&mut self) -> Result<bool, ShutdownDrainError> {
        self.cancel_io().map_err(|_| ShutdownDrainError::Cancel)?;
        self.poll_cleanup().map_err(|_| ShutdownDrainError::Drain)
    }
    pub(super) fn close_for_shutdown(&mut self) -> Result<(), Error> {
        if !self.job_closed {
            self.cancel_io()?;
            self.close_job();
            if self.io.close_failed() {
                return Err(Error::CleanupUnconfirmed);
            }
        }
        Ok(())
    }
    fn close_job(&mut self) {
        if !self.job_closed {
            self.io.close_job();
            self.job_closed = true;
        }
    }
    pub(super) fn retain_uncertain(mut self) {
        // Final kill-on-close is a request, not proof. Keep the pipe, process,
        // events and pending buffers alive until OS teardown, as before.
        self.close_job();
        mem::forget(self);
    }
    pub(super) fn poll_cleanup(&mut self) -> Result<bool, Error> {
        let mut io_done = true;
        for operation in [
            &mut self.operation,
            &mut self.watch_read,
            &mut self.watch_write,
        ] {
            if let Some(pending) = operation {
                let in_flight = match self.io.poll(pending) {
                    Ok(_) => B::in_flight(pending),
                    Err(_) if B::in_flight(pending) => return Err(Error::CleanupUnconfirmed),
                    Err(_) => false,
                };
                if in_flight {
                    io_done = false;
                } else {
                    *operation = None;
                }
            }
        }
        // Launch may have failed before creating a child. Only cleanup treats
        // that absence as done; protocol callers still require a retained child.
        let process_done = self.io.process_exited(0)?.unwrap_or(true);
        // After kill-on-close, only the retained process wait is available.
        let job_done = if self.job_closed {
            process_done
        } else {
            self.io.job_empty()?
        };
        Ok(process_done && io_done && job_done)
    }
    pub(super) fn cleanup(&mut self) -> Result<bool, Error> {
        self.cleanup_with_budget(CLEANUP_BUDGET)
    }
    pub(super) fn cleanup_with_budget(&mut self, budget: Duration) -> Result<bool, Error> {
        let began = Instant::now();
        self.request_termination()?;
        loop {
            if self.poll_cleanup()? {
                return Ok(true);
            }
            if began.elapsed() >= budget {
                return Ok(false);
            }
            let pending = self
                .operation
                .as_ref()
                .filter(|op| B::in_flight(op))
                .or_else(|| self.watch_read.as_ref().filter(|op| B::in_flight(op)))
                .or_else(|| self.watch_write.as_ref().filter(|op| B::in_flight(op)));
            if !self.io.wait_cleanup(pending) {
                return Ok(false);
            }
        }
    }
}
impl<B: RunIo> Drop for ActiveRun<B> {
    fn drop(&mut self) {
        self.close_job();
    }
}
