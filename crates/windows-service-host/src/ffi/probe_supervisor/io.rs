// SPDX-License-Identifier: GPL-2.0-or-later
//! Probe-specific bounds, event ownership, deadline and stage mapping over the
//! private shared overlapped storage primitive. Process/job ownership stays in
//! the original supervisor; this adapter does not own or expose another pipe.
#[cfg(test)]
use super::super::overlapped_pipe;
use super::super::overlapped_pipe::{BufferLimits, EventHandle, IoError, PendingOperation};
pub(super) use super::super::overlapped_pipe::{Completed, Kind};
use super::{Handle, native};
use crate::{ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::time::Instant;
use windows::{
    Win32::{Foundation::HANDLE, System::Threading::CreateEventW},
    core::PCWSTR,
};
use windows_prompt_probe::supervision::MAX_REPORT_BYTES;

const LIMITS: BufferLimits = BufferLimits {
    max_read: MAX_REPORT_BYTES + 1,
    max_write: MAX_REPORT_BYTES,
};

impl EventHandle for Handle {
    fn raw_event(&self) -> HANDLE {
        self.raw()
    }
}

pub(super) struct PendingIo {
    operation: PendingOperation<Handle>,
    stage: Stage,
}
impl PendingIo {
    pub(super) fn start(
        pipe: HANDLE,
        kind: Kind<'_>,
        stage: Stage,
        began: Instant,
    ) -> Result<Self, Error> {
        // SAFETY: the same unnamed noninheritable manual-reset event as before.
        // Its original Handle Drop still latches supervisor close failures.
        let event = Handle::new(
            unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
                .map_err(|error| native(stage, error))?,
            stage,
        )?;
        let mut operation =
            PendingOperation::prepare(kind, LIMITS, event).map_err(|error| mapped(stage, error))?;
        // Event creation and ALL buffer/storage allocation precede this fresh
        // check of the ORIGINAL five-second probe budget. No native issue occurs
        // if preparation exhausted it; dropping Prepared releases only owned data.
        crate::probe_supervisor::before_deadline(began.elapsed(), || operation.issue(pipe))?
            .map_err(|error| mapped(stage, error))?;
        Ok(Self { operation, stage })
    }
    pub(super) fn event(&self) -> HANDLE {
        self.operation.event()
    }
    pub(super) fn in_flight(&self) -> bool {
        self.operation.in_flight()
    }
    pub(super) fn poll(&mut self, pipe: HANDLE) -> Result<Option<Completed>, Error> {
        self.operation
            .poll(pipe)
            .map_err(|error| mapped(self.stage, error))
    }
    pub(super) fn cancel(&mut self, pipe: HANDLE) -> Result<(), Error> {
        self.operation
            .cancel(pipe)
            .map_err(|error| mapped(Stage::CancelIo, error))
    }
}

fn mapped(stage: Stage, error: IoError) -> Error {
    match error {
        IoError::Native { hresult } => Error::Native { stage, hresult },
        IoError::InvalidBuffer | IoError::InvalidPhase => Error::InvalidReport,
    }
}

#[cfg(test)]
fn prepare_buffer(kind: Kind<'_>) -> Result<(bool, Box<[u8]>), Error> {
    overlapped_pipe::prepare_buffer(kind, LIMITS).map_err(|error| mapped(Stage::ReportRead, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_buffer_is_heap_owned_and_storage_stays_small() {
        let (read, buffer) = prepare_buffer(Kind::Read(MAX_REPORT_BYTES + 1)).unwrap();
        assert!(overlapped_pipe::storage_size_for_tests() < 256);
        assert!(read);
        assert_eq!(buffer.len(), MAX_REPORT_BYTES + 1);
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn connect_and_eof_only_allocate_their_requested_length() {
        let (read, bytes) = prepare_buffer(Kind::Connect).unwrap();
        assert!(!read);
        assert!(bytes.is_empty());
        let (read, bytes) = prepare_buffer(Kind::Read(1)).unwrap();
        assert!(read);
        assert_eq!(&*bytes, &[0]);
    }

    #[test]
    fn oversized_or_empty_reads_are_rejected_before_allocation() {
        for length in [0, MAX_REPORT_BYTES + 2, usize::MAX] {
            assert!(matches!(
                prepare_buffer(Kind::Read(length)),
                Err(Error::InvalidReport)
            ));
        }
        let bytes = vec![0; MAX_REPORT_BYTES + 1];
        assert!(matches!(
            prepare_buffer(Kind::Write(&bytes)),
            Err(Error::InvalidReport)
        ));
    }

    #[test]
    fn writes_own_an_exact_independent_copy() {
        let mut source = vec![1, 2, 3];
        let (read, bytes) = prepare_buffer(Kind::Write(&source)).unwrap();
        source.fill(9);
        assert!(!read);
        assert_eq!(&*bytes, &[1, 2, 3]);
    }

    #[test]
    fn native_errors_retain_original_operation_or_cancel_stage() {
        for stage in [
            Stage::ConnectPipe,
            Stage::ChallengeWrite,
            Stage::ReportRead,
            Stage::EofRead,
            Stage::CancelIo,
        ] {
            let hresult = windows::core::HRESULT::from_win32(5).0;
            assert_eq!(
                mapped(stage, IoError::Native { hresult }),
                Error::Native { stage, hresult }
            );
        }
        for error in [IoError::InvalidBuffer, IoError::InvalidPhase] {
            assert_eq!(mapped(Stage::ReportRead, error), Error::InvalidReport);
        }
    }
}
