// SPDX-License-Identifier: GPL-2.0-or-later
//! One service-created, nonvisual SYSTEM child in the registered renderer's
//! session. Independent lease: the existing consent watcher stays alive.
use super::*;
use crate::ffi::pairing_peer::renderer;
use windows_prompt_probe::pairing_inspection::{Binding, Reply, Request};

static INSPECTOR_OWNED: AtomicBool = AtomicBool::new(false);
pub(in crate::ffi) struct Owner {
    run: Option<ActiveRun>,
    cutoff: u64,
    sequence: u64,
    failed: bool,
    closed: bool,
    cleaning: bool,
}
impl Owner {
    pub(in crate::ffi) fn bind(
        binding: Binding,
        session: u32,
    ) -> Result<Self, crate::PairingPeerError> {
        if INSPECTOR_OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(crate::PairingPeerError::InvalidPhase);
        }
        let mut owner = Self {
            run: None,
            cutoff: binding.cutoff,
            sequence: 0,
            failed: false,
            closed: false,
            cleaning: false,
        };
        let result = (|| {
            owner.budget()?;
            let preflight = Preflight::observe().map_err(mapped)?;
            if preflight.session.id != session {
                return Err(crate::PairingPeerError::Rejected);
            }
            owner.run = Some(ActiveRun::prepare(preflight).map_err(mapped)?);
            let run = owner
                .run
                .as_mut()
                .ok_or(crate::PairingPeerError::InvalidPhase)?;
            run.inspection = Some(binding.cutoff);
            run.launch_watch().map_err(mapped)?;
            if !matches!(owner.await_operation()?, Completed::Count(0)) {
                return Err(crate::PairingPeerError::Malformed);
            }
            owner
                .run
                .as_ref()
                .ok_or(crate::PairingPeerError::InvalidPhase)?
                .authenticate_pipe()
                .map_err(mapped)?;
            owner.exchange(Request::Bind(binding), false)?;
            Ok(())
        })();
        if let Err(error) = result {
            owner.failed = true;
            return Err(error);
        }
        Ok(owner)
    }
    fn budget(&self) -> Result<(), crate::PairingPeerError> {
        if self.closed || (self.failed && !self.cleaning) {
            return Err(crate::PairingPeerError::InvalidPhase);
        }
        if self.cleaning {
            return Ok(());
        }
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            return Err(crate::PairingPeerError::CleanupUnconfirmed);
        }
        crate::ffi::pairing_peer::service_positive(|| renderer::check_cutoff(self.cutoff))
    }
    fn await_operation(&mut self) -> Result<Completed, crate::PairingPeerError> {
        loop {
            self.budget()?;
            let run = self
                .run
                .as_mut()
                .ok_or(crate::PairingPeerError::InvalidPhase)?;
            let wait = run.budget().map_err(mapped)?.min(25);
            let pipe = run.pipe().map_err(mapped)?;
            let operation = run
                .operation
                .as_mut()
                .ok_or(crate::PairingPeerError::InvalidPhase)?;
            if let Some(done) = operation.poll(pipe).map_err(mapped)? {
                run.operation = None;
                return Ok(done);
            }
            // SAFETY: only the owned, live operation event; original ceremony
            // and short operation deadlines and service stop rechecked per slice.
            match unsafe { WaitForSingleObject(operation.event(), wait) } {
                WAIT_OBJECT_0 | WAIT_TIMEOUT => (),
                _ => return Err(mapped(native(Stage::ReportRead, WinError::from_thread()))),
            }
            if exited(run.process().map_err(mapped)?, 0).map_err(mapped)? {
                let pipe = run.pipe().map_err(mapped)?;
                if let Some(done) = run
                    .operation
                    .as_mut()
                    .ok_or(crate::PairingPeerError::InvalidPhase)?
                    .poll(pipe)
                    .map_err(mapped)?
                {
                    run.operation = None;
                    return Ok(done);
                }
                return Err(crate::PairingPeerError::Rejected);
            }
        }
    }
    fn exchange(&mut self, request: Request, closing: bool) -> Result<(), crate::PairingPeerError> {
        self.budget()?;
        let bytes = request
            .encode()
            .map_err(|_| crate::PairingPeerError::Malformed)?;
        let run = self
            .run
            .as_mut()
            .ok_or(crate::PairingPeerError::InvalidPhase)?;
        run.authenticate_pipe().map_err(mapped)?;
        run.began = Instant::now(); // Per-operation budget; never replaces cutoff.
        run.operation = Some(
            PendingIo::start(
                run.pipe().map_err(mapped)?,
                Kind::Write(&bytes),
                Stage::ChallengeWrite,
                run.began,
            )
            .map_err(mapped)?,
        );
        if !matches!(self.await_operation()?, Completed::Count(count) if count == bytes.len()) {
            return Err(crate::PairingPeerError::Malformed);
        }
        let run = self
            .run
            .as_mut()
            .ok_or(crate::PairingPeerError::InvalidPhase)?;
        run.operation = Some(
            PendingIo::start(
                run.pipe().map_err(mapped)?,
                Kind::Read(windows_prompt_probe::pairing_inspection::MAX_BYTES),
                Stage::ReportRead,
                run.began,
            )
            .map_err(mapped)?,
        );
        let Completed::Bytes(bytes) = self.await_operation()? else {
            return Err(crate::PairingPeerError::Malformed);
        };
        let reply = Reply::decode(&bytes).map_err(|_| crate::PairingPeerError::Malformed)?;
        if reply.sequence != self.sequence {
            return Err(crate::PairingPeerError::Rejected);
        }
        if let Some(error) = reply.failure {
            return Err(crate::PairingPeerError::Service(
                crate::ServiceError::RendererNative {
                    stage: error.stage,
                    hresult: error.hresult,
                },
            ));
        }
        if !closing {
            self.run
                .as_ref()
                .ok_or(crate::PairingPeerError::InvalidPhase)?
                .authenticate_pipe()
                .map_err(mapped)?;
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(crate::PairingPeerError::Malformed)?;
        self.budget()
    }
    pub(in crate::ffi) fn check(&mut self) -> Result<(), crate::PairingPeerError> {
        let result = self.exchange(Request::Check(self.sequence), false);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(in crate::ffi) fn close(&mut self) -> Result<(), crate::PairingPeerError> {
        if self.closed {
            return Ok(());
        }
        self.cleaning = true;
        if self.failed
            || crate::entry::stop_requested()
            || renderer::check_cutoff(self.cutoff).is_err()
        {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note(&format!(
                "inspector abort: failed={} stop={} cutoff_elapsed={}",
                self.failed,
                crate::entry::stop_requested(),
                renderer::check_cutoff(self.cutoff).is_err()
            ));
            return self.abort_cleanup();
        }
        let result = self.close_inner();
        if result.is_err() {
            self.failed = true;
            self.abort_cleanup()?;
        }
        result
    }
    fn close_inner(&mut self) -> Result<(), crate::PairingPeerError> {
        self.exchange(Request::Close(self.sequence), true)?;
        let run = self
            .run
            .as_mut()
            .ok_or(crate::PairingPeerError::InvalidPhase)?;
        run.operation = Some(
            PendingIo::start(
                run.pipe().map_err(mapped)?,
                Kind::Read(1),
                Stage::EofRead,
                run.began,
            )
            .map_err(mapped)?,
        );
        if !matches!(self.await_operation()?, Completed::Eof) {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note("inspector cleanup: close reply was not end of stream");
            return Err(crate::PairingPeerError::Malformed);
        }
        let run = self
            .run
            .as_mut()
            .ok_or(crate::PairingPeerError::InvalidPhase)?;
        while !exited(
            run.process().map_err(mapped)?,
            run.budget().map_err(mapped)?.min(25),
        )
        .map_err(mapped)?
        {}
        let code = exit_code(run.process().map_err(mapped)?).map_err(mapped)?;
        // A signalled process object does not yet prove the job has released
        // it: the accounting still counted the exited child on the first query.
        // Give that disassociation the same bounded budget the forceful path
        // uses, so a normal cleanup is not reported as an uncertain one.
        let began = Instant::now();
        let mut empty = run.job_empty().map_err(mapped)?;
        while !empty && began.elapsed() < CLEANUP_BUDGET {
            std::thread::sleep(Duration::from_millis(5));
            empty = run.job_empty().map_err(mapped)?;
        }
        if code != 0 || !empty {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note(&format!(
                "inspector cleanup: exit={code:#010x} job_empty={empty}"
            ));
            return Err(crate::PairingPeerError::CleanupUnconfirmed);
        }
        self.run = None;
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note("inspector cleanup: a latched handle close failure remains");
            return Err(crate::PairingPeerError::CleanupUnconfirmed);
        }
        self.closed = true;
        INSPECTOR_OWNED.store(false, Ordering::Release);
        Ok(())
    }
    fn abort_cleanup(&mut self) -> Result<(), crate::PairingPeerError> {
        if let Some(run) = self.run.as_mut()
            && !matches!(run.cleanup_with_budget(CLEANUP_BUDGET), Ok(true))
        {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note("inspector abort: the budgeted cleanup stayed unconfirmed");
            return Err(crate::PairingPeerError::CleanupUnconfirmed);
        }
        self.run = None;
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            #[cfg(all(windows, feature = "lab-software-identity"))]
            crate::lab::record_note("inspector abort: a latched handle close failure remains");
            return Err(crate::PairingPeerError::CleanupUnconfirmed);
        }
        self.closed = true;
        INSPECTOR_OWNED.store(false, Ordering::Release);
        Ok(())
    }
}
fn mapped(error: Error) -> crate::PairingPeerError {
    match error {
        Error::Native { hresult, .. } => {
            crate::PairingPeerError::Service(crate::ServiceError::RendererNative {
                stage: 22,
                hresult,
            })
        }
        Error::CleanupUnconfirmed => crate::PairingPeerError::CleanupUnconfirmed,
        _ => crate::PairingPeerError::Rejected,
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        if let Some(mut run) = self.run.take()
            && !matches!(run.cleanup_with_budget(CLEANUP_BUDGET), Ok(true))
        {
            run.job.close();
            run.job_closed = true;
            mem::forget(run);
            crate::ffi::pairing_peer::quarantine_boundary();
            return;
        }
        if CLOSE_FAILURE.load(Ordering::Acquire) != 0 {
            crate::ffi::pairing_peer::quarantine_boundary();
        } else {
            INSPECTOR_OWNED.store(false, Ordering::Release);
        }
    }
}
