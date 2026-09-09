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

const BUFFER_BYTES: usize = 513;
struct Storage {
    overlapped: OVERLAPPED,
    buffer: [u8; BUFFER_BYTES],
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
        let mut storage = Storage {
            overlapped: OVERLAPPED {
                hEvent: event.raw(),
                ..Default::default()
            },
            buffer: [0; BUFFER_BYTES],
        };
        let (read, maximum) = match kind {
            Kind::Connect => (false, 0),
            Kind::Write(bytes) => {
                if bytes.len() > BUFFER_BYTES {
                    return Err(Error::InvalidReport);
                }
                storage.buffer[..bytes.len()].copy_from_slice(bytes);
                (false, bytes.len())
            }
            Kind::Read(count) => {
                if count == 0 || count > BUFFER_BYTES {
                    return Err(Error::InvalidReport);
                }
                (true, count)
            }
        };
        let mut operation = Self {
            storage: Some(Box::new(UnsafeCell::new(storage))),
            event: Some(event),
            pending: false,
            read,
            maximum,
            stage,
        };
        let pointer = operation.pointer();
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
                    Some(std::slice::from_raw_parts(
                        std::ptr::addr_of!((*pointer).buffer).cast(),
                        maximum,
                    )),
                    None,
                    Some(overlapped),
                ),
                Kind::Read(_) => ReadFile(
                    pipe,
                    Some(std::slice::from_raw_parts_mut(
                        std::ptr::addr_of_mut!((*pointer).buffer).cast(),
                        maximum,
                    )),
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
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::addr_of!((*self.pointer()).buffer).cast(),
                            count as usize,
                        )
                    }
                    .to_vec();
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
