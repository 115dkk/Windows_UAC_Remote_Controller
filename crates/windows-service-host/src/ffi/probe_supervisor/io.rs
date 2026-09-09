// SPDX-License-Identifier: GPL-2.0-or-later
//! One overlapped operation and stable owned memory. No buffer is freed pending IO.
use super::{Handle, native};
use crate::{ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::{cell::UnsafeCell, mem, time::Instant};
use windows::{
    Win32::{
        Foundation::{
            ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_MORE_DATA,
            ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, HANDLE,
        },
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::ConnectNamedPipe,
            Threading::CreateEventW,
        },
    },
    core::{HRESULT, PCWSTR},
};
use windows_prompt_probe::supervision::MAX_REPORT_BYTES;

struct Storage {
    overlapped: OVERLAPPED,
    // Allocate the contents on the heap before boxing Storage. A MAX_REPORT_BYTES
    // array temporary here would consume most of the Windows thread stack.
    buffer: Box<[u8]>,
}
pub(super) enum Completed {
    Bytes(Vec<u8>),
    Count(usize),
    Eof,
}
#[derive(Clone, Copy)]
pub(super) enum Kind<'a> {
    Connect,
    Write(&'a [u8]),
    Read(usize),
}
pub(super) struct PendingIo {
    storage: Option<Box<UnsafeCell<Storage>>>,
    // Acquired once before issuing I/O. Never reborrow/reallocate the buffer
    // through its owning Box while the kernel can still access these bytes.
    buffer: *mut u8,
    event: Option<Handle>,
    pending: bool,
    read: bool,
    maximum: usize,
    stage: Stage,
}
impl PendingIo {
    pub(super) fn start(
        pipe: HANDLE,
        kind: Kind<'_>,
        stage: Stage,
        began: Instant,
    ) -> Result<Self, Error> {
        // SAFETY: unnamed noninheritable manual-reset event, no external handle/name.
        let event = Handle::new(
            unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
                .map_err(|error| native(stage, error))?,
            stage,
        )?;
        let (read, buffer) = prepare_buffer(kind)?;
        let maximum = buffer.len();
        let storage = Storage {
            overlapped: OVERLAPPED {
                hEvent: event.raw(),
                ..Default::default()
            },
            buffer,
        };
        let mut operation = Self {
            storage: Some(Box::new(UnsafeCell::new(storage))),
            buffer: std::ptr::null_mut(),
            event: Some(event),
            pending: false,
            read,
            maximum,
            stage,
        };
        let pointer = operation.pointer();
        // SAFETY: boxed initialized storage; no native operation has started.
        // This is the only mutable borrow through the owned buffer descriptor.
        // Neither allocation is subsequently moved, resized or replaced.
        operation.buffer = unsafe { (*pointer).buffer.as_mut_ptr() };
        let buffer = operation.buffer;
        // SAFETY: boxed UnsafeCell storage stays at a stable address through
        // completion/cancel acknowledgement. No Rust reference accesses these
        // bytes while the kernel may mutate OVERLAPPED/read data. Pipe/event
        // owners outlive the operation. Slice borrows end when the call returns,
        // but their backing allocation is intentionally retained until completion.
        // Event creation/allocation may have taken time. Check the original
        // run deadline after setup, before issuing any native operation.
        let result = crate::probe_supervisor::before_deadline(began.elapsed(), || unsafe {
            let overlapped = std::ptr::addr_of_mut!((*pointer).overlapped);
            match kind {
                Kind::Connect => ConnectNamedPipe(pipe, Some(overlapped)),
                Kind::Write(_) => WriteFile(
                    pipe,
                    Some(std::slice::from_raw_parts(buffer, maximum)),
                    None,
                    Some(overlapped),
                ),
                Kind::Read(_) => ReadFile(
                    pipe,
                    Some(std::slice::from_raw_parts_mut(buffer, maximum)),
                    None,
                    Some(overlapped),
                ),
            }
        })?;
        match result {
            Ok(()) => operation.pending = true,
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                operation.pending = true
            }
            Err(error)
                if matches!(kind, Kind::Connect)
                    && error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => {}
            Err(error) if error.code() == HRESULT::from_win32(ERROR_BROKEN_PIPE.0) => {
                operation.read = true;
                operation.maximum = 0;
                return Ok(operation);
            }
            Err(error) => return Err(native(stage, error)),
        }
        Ok(operation)
    }
    fn pointer(&self) -> *mut Storage {
        self.storage
            .as_ref()
            .map_or(std::ptr::null_mut(), |storage| storage.get())
    }
    pub(super) fn event(&self) -> HANDLE {
        self.event.as_ref().map_or(HANDLE::default(), Handle::raw)
    }
    pub(super) fn in_flight(&self) -> bool {
        self.pending
    }
    pub(super) fn poll(&mut self, pipe: HANDLE) -> Result<Option<Completed>, Error> {
        if !self.pending {
            return Ok(Some(if self.read {
                Completed::Eof
            } else {
                Completed::Count(0)
            }));
        }
        let mut count = 0;
        // SAFETY: stable pending OVERLAPPED allocation, owned live pipe and
        // exclusive scalar output. FALSE never waits or frees an in-flight buffer.
        let result = unsafe {
            GetOverlappedResult(
                pipe,
                std::ptr::addr_of!((*self.pointer()).overlapped),
                &mut count,
                false,
            )
        };
        match result {
            Ok(()) => {
                self.pending = false;
                if count as usize > self.maximum {
                    return Err(Error::InvalidReport);
                }
                if self.read {
                    // SAFETY: successful completion proves native writes ended;
                    // count is bounded before copying the initialized byte region.
                    let bytes =
                        unsafe { std::slice::from_raw_parts(self.buffer, count as usize) }.to_vec();
                    Ok(Some(Completed::Bytes(bytes)))
                } else {
                    Ok(Some(Completed::Count(count as usize)))
                }
            }
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_INCOMPLETE.0) => Ok(None),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_BROKEN_PIPE.0) => {
                self.pending = false;
                Ok(Some(Completed::Eof))
            }
            Err(error)
                if [ERROR_OPERATION_ABORTED.0, ERROR_MORE_DATA.0]
                    .iter()
                    .any(|code| error.code() == HRESULT::from_win32(*code)) =>
            {
                self.pending = false;
                Err(native(self.stage, error))
            }
            // An unexpected query error is NOT proof the IO stopped. Retain it.
            Err(error) => Err(native(self.stage, error)),
        }
    }
    pub(super) fn cancel(&mut self, pipe: HANDLE) -> Result<(), Error> {
        if !self.pending {
            return Ok(());
        }
        // SAFETY: cancel only this retained operation on its own live pipe. The
        // buffer/event remain owned until poll proves completion/abort.
        match unsafe { CancelIoEx(pipe, Some(std::ptr::addr_of!((*self.pointer()).overlapped))) } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_NOT_FOUND.0) => Ok(()),
            Err(error) => Err(native(Stage::CancelIo, error)),
        }
    }
}

impl Drop for PendingIo {
    fn drop(&mut self) {
        if self.pending {
            // Fail-safe only if the supervisor itself is dropped while cleanup
            // cannot be confirmed. Never free kernel-referenced memory/event.
            // The supervisor also permanently retains its process-wide lease.
            if let Some(storage) = self.storage.take() {
                mem::forget(storage);
            }
            if let Some(event) = self.event.take() {
                mem::forget(event);
            }
        }
    }
}

// Only the requested bounded length is allocated: connect and EOF probes do not
// each reserve a maximum report. Validation happens before allocating/copying.
fn prepare_buffer(kind: Kind<'_>) -> Result<(bool, Box<[u8]>), Error> {
    let (read, length) = match kind {
        Kind::Connect => (false, 0),
        Kind::Write(bytes) if bytes.len() <= MAX_REPORT_BYTES => (false, bytes.len()),
        Kind::Read(count) if (1..=MAX_REPORT_BYTES + 1).contains(&count) => (true, count),
        Kind::Write(_) | Kind::Read(_) => return Err(Error::InvalidReport),
    };
    let mut buffer = vec![0; length].into_boxed_slice();
    if let Kind::Write(bytes) = kind {
        buffer.copy_from_slice(bytes);
    }
    Ok((read, buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_buffer_is_heap_owned_and_storage_stays_small() {
        let (read, buffer) = prepare_buffer(Kind::Read(MAX_REPORT_BYTES + 1)).unwrap();
        let storage = Storage {
            overlapped: OVERLAPPED::default(),
            buffer,
        };
        assert!(mem::size_of_val(&storage) < 256);
        assert!(read);
        assert_eq!(storage.buffer.len(), MAX_REPORT_BYTES + 1);
        assert!(storage.buffer.iter().all(|byte| *byte == 0));
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
}
