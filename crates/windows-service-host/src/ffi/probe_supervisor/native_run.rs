// SPDX-License-Identifier: GPL-2.0-or-later
//! Thread-affine Windows resources used only by ActiveRun's lifecycle adapter.
use super::{
    CLOSE_FAILURE, Error, Handle, Stage,
    active_run::RunIo,
    exit_code, exited,
    io::{Completed, Kind, PendingIo},
    launch, native,
    preflight::Preflight,
};
use std::{mem, sync::atomic::Ordering, time::Instant};
use windows::{
    Win32::{
        Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            JobObjects::{
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
                QueryInformationJobObject, TerminateJobObject,
            },
            Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId},
            Threading::{ResumeThread, TerminateProcess, WaitForSingleObject},
        },
    },
    core::Error as WinError,
};

pub(super) struct NativeRunIo {
    pub(super) preflight: Preflight,
    pub(super) job: Handle,
    pub(super) child: Option<Handle>,
    pub(super) thread: Option<Handle>,
    pub(super) pipe: Option<Handle>,
    pub(super) pid: u32,
    pub(super) creation: u64,
    pub(super) assigned: bool,
}
impl NativeRunIo {
    pub(super) fn prepare(preflight: Preflight) -> Result<Self, Error> {
        let job = launch::job(&preflight)?;
        Ok(Self {
            preflight,
            job,
            child: None,
            thread: None,
            pipe: None,
            pid: 0,
            creation: 0,
            assigned: false,
        })
    }
    pub(super) fn process(&self) -> Result<HANDLE, Error> {
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
}
impl RunIo for NativeRunIo {
    type Operation = PendingIo;
    fn recheck(&self) -> Result<(), Error> {
        self.preflight.recheck()
    }
    fn launch_child(
        &mut self,
        watch: bool,
        inspection: Option<u64>,
        began: Instant,
    ) -> Result<(), Error> {
        launch::child(self, watch, inspection, began)
    }
    fn assign_and_authenticate(&mut self, inspection: Option<u64>) -> Result<(), Error> {
        launch::assign_and_authenticate(self, inspection)
    }
    fn resume(&self) -> Result<(), Error> {
        // SAFETY: retained created child's sole initial suspended thread. Fixed
        // job, token, image and pipe checks complete before resuming exact argv.
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
    fn authenticate_pipe(&self, inspection: Option<u64>) -> Result<(), Error> {
        let (mut pid, mut session) = (0, 0);
        // SAFETY: exclusively owned connected local pipe, distinct scalar outputs;
        // no impersonation or name-based trust. Match the actual retained child.
        unsafe { GetNamedPipeClientProcessId(self.pipe()?, &mut pid) }
            .map_err(|error| native(Stage::AuthenticatePeer, error))?;
        // SAFETY: same live connected endpoint, initialized scalar session output.
        unsafe { GetNamedPipeClientSessionId(self.pipe()?, &mut session) }
            .map_err(|error| native(Stage::AuthenticatePeer, error))?;
        if pid != self.pid || session != self.preflight.session.id || exited(self.process()?, 0)? {
            return Err(Error::PeerMismatch);
        }
        launch::authenticate_child(self, inspection)?;
        self.preflight.recheck()
    }
    fn session(&self) -> u32 {
        self.preflight.session.id
    }
    fn start(
        &self,
        kind: Kind<'_>,
        stage: Stage,
        began: Option<Instant>,
    ) -> Result<PendingIo, Error> {
        match began {
            Some(began) => PendingIo::start(self.pipe()?, kind, stage, began),
            None => PendingIo::start_watch(self.pipe()?, kind, stage),
        }
    }
    fn poll(&self, operation: &mut PendingIo) -> Result<Option<Completed>, Error> {
        operation.poll(self.pipe()?)
    }
    fn cancel(&self, operation: &mut PendingIo) -> Result<(), Error> {
        operation.cancel(self.pipe()?)
    }
    fn in_flight(operation: &PendingIo) -> bool {
        operation.in_flight()
    }
    fn expected_write_bytes(operation: &PendingIo) -> Option<usize> {
        operation.expected_write_bytes()
    }
    fn wait_operation(&self, operation: &PendingIo, wait: u32) -> Result<(), Error> {
        // SAFETY: owned operation's live event. Short bounded waits permit the
        // caller to recheck process/deadline; no UI or message pumping occurs.
        match unsafe { WaitForSingleObject(operation.event(), wait) } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
            _ => Err(native(Stage::ReportRead, WinError::from_thread())),
        }
    }
    fn wait_cleanup(&self, operation: Option<&PendingIo>) -> bool {
        let event = operation
            .map(PendingIo::event)
            .or_else(|| self.child.as_ref().map(Handle::raw));
        if let Some(event) = event {
            // SAFETY: retained event/process handle; bounded wait only. A signaled
            // event does NOT by itself establish cancellation.
            matches!(
                unsafe { WaitForSingleObject(event, 10) },
                WAIT_OBJECT_0 | WAIT_TIMEOUT
            )
        } else {
            false
        }
    }
    fn process_exited(&self, wait: u32) -> Result<Option<bool>, Error> {
        self.child
            .as_ref()
            .map(|child| exited(child.raw(), wait))
            .transpose()
    }
    fn exit_code(&self) -> Result<u32, Error> {
        exit_code(self.process()?)
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
    fn terminate(&self, job_closed: bool) -> Result<(), Error> {
        if let Some(child) = &self.child
            && !exited(child.raw(), 0)?
        {
            // SAFETY: terminate only this newly owned job or, if assignment
            // failed, the still-suspended child created by this supervisor.
            // Failure never relinquishes ownership or counts as termination.
            let result = unsafe {
                if self.assigned && !job_closed {
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
    fn close_job(&mut self) {
        self.job.close();
    }
    fn close_failed(&self) -> bool {
        CLOSE_FAILURE.load(Ordering::Acquire) != 0
    }
}
