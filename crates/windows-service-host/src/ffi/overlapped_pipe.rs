// SPDX-License-Identifier: GPL-2.0-or-later
//! Private operation storage, not a pipe/peer/protocol owner. The caller retains
//! the ORIGINAL pipe and full enclosing reservation until cancellation is drained.
//! Dropping this core pending retains its storage AND event, but not that pipe.
use std::{cell::UnsafeCell, fmt, mem};
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
        },
    },
    core::HRESULT,
};

/// Implementations own one live noninheritable manual-reset event. Its handle
/// remains unchanged while borrowed; Drop retains the caller's close-failure
/// policy. This trait and every raw HANDLE below stay inside the private FFI.
pub(super) trait EventHandle {
    fn raw_event(&self) -> HANDLE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IoError {
    Native { hresult: i32 },
    InvalidBuffer,
    InvalidPhase,
}

#[derive(Clone, Copy)]
pub(super) struct BufferLimits {
    pub(super) max_read: usize,
    pub(super) max_write: usize,
}

#[derive(Clone, Copy)]
pub(super) enum Kind<'a> {
    Connect,
    Write(&'a [u8]),
    Read(usize),
}

#[derive(Eq, PartialEq)]
pub(super) enum Completed {
    Bytes(Vec<u8>),
    Count(usize),
    Eof,
}
impl fmt::Debug for Completed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Completed([redacted])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationKind {
    Connect,
    Write,
    Read,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    InFlight,
    Complete,
}

struct Storage {
    overlapped: OVERLAPPED,
    // Buffer contents are heap allocated BEFORE boxing Storage. No maximum-size
    // array temporary can consume the Windows worker's stack.
    buffer: Box<[u8]>,
}

pub(super) struct PendingOperation<E: EventHandle> {
    storage: Option<Box<UnsafeCell<Storage>>>,
    // Acquired only before issue. Do not reborrow the owning buffer descriptor
    // while the kernel can mutate OVERLAPPED/read bytes.
    buffer: *mut u8,
    event: Option<E>,
    phase: Phase,
    kind: OperationKind,
    read: bool,
    maximum: usize,
}

impl<E: EventHandle> PendingOperation<E> {
    /// All allocation/copy occurs here. The caller must check its ORIGINAL
    /// deadline and other admission conditions AFTER prepare, BEFORE issue.
    pub(super) fn prepare(kind: Kind<'_>, limits: BufferLimits, event: E) -> Result<Self, IoError> {
        let (read, buffer) = prepare_buffer(kind, limits)?;
        let maximum = buffer.len();
        let storage = Storage {
            overlapped: OVERLAPPED {
                hEvent: event.raw_event(),
                ..Default::default()
            },
            buffer,
        };
        let mut operation = Self {
            storage: Some(Box::new(UnsafeCell::new(storage))),
            buffer: std::ptr::null_mut(),
            event: Some(event),
            phase: Phase::Prepared,
            kind: match kind {
                Kind::Connect => OperationKind::Connect,
                Kind::Write(_) => OperationKind::Write,
                Kind::Read(_) => OperationKind::Read,
            },
            read,
            maximum,
        };
        // SAFETY: initialized boxed storage, no operation issued. This is the
        // only mutable borrow through the buffer's Box; allocations never move.
        operation.buffer = unsafe { (*operation.pointer()).buffer.as_mut_ptr() };
        Ok(operation)
    }

    pub(super) fn issue(&mut self, pipe: HANDLE) -> Result<(), IoError> {
        if self.phase != Phase::Prepared {
            return Err(IoError::InvalidPhase);
        }
        let pointer = self.pointer();
        let buffer = self.buffer;
        // SAFETY: stable boxed UnsafeCell storage and owned event. The PRIVATE
        // caller owns this exact live overlapped pipe through completion/drain.
        // Temporary slices do not outlive this call, but their backing allocation
        // is retained while the kernel borrows it. No Rust reference accesses the
        // OVERLAPPED/read bytes before a terminal completion observation.
        let result = unsafe {
            let overlapped = std::ptr::addr_of_mut!((*pointer).overlapped);
            match self.kind {
                OperationKind::Connect => ConnectNamedPipe(pipe, Some(overlapped)),
                OperationKind::Write => WriteFile(
                    pipe,
                    Some(std::slice::from_raw_parts(buffer, self.maximum)),
                    None,
                    Some(overlapped),
                ),
                OperationKind::Read => ReadFile(
                    pipe,
                    Some(std::slice::from_raw_parts_mut(buffer, self.maximum)),
                    None,
                    Some(overlapped),
                ),
            }
        };
        self.accept_issue_result(result.map_err(|error| error.code().0))
    }

    fn accept_issue_result(&mut self, result: Result<(), i32>) -> Result<(), IoError> {
        if self.phase != Phase::Prepared {
            return Err(IoError::InvalidPhase);
        }
        // Every issue attempt is single-use, including an immediate failure.
        self.phase = Phase::Complete;
        match result {
            Ok(()) => self.phase = Phase::InFlight,
            Err(code) if code == HRESULT::from_win32(ERROR_IO_PENDING.0).0 => {
                self.phase = Phase::InFlight;
            }
            Err(code)
                if self.kind == OperationKind::Connect
                    && code == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0).0 => {}
            Err(code) if code == HRESULT::from_win32(ERROR_BROKEN_PIPE.0).0 => {
                self.read = true;
                self.maximum = 0;
            }
            Err(hresult) => return Err(IoError::Native { hresult }),
        }
        Ok(())
    }

    fn pointer(&self) -> *mut Storage {
        self.storage
            .as_ref()
            .map_or(std::ptr::null_mut(), |storage| storage.get())
    }

    pub(super) fn event(&self) -> HANDLE {
        self.event
            .as_ref()
            .map_or(HANDLE::default(), EventHandle::raw_event)
    }

    pub(super) fn in_flight(&self) -> bool {
        self.phase == Phase::InFlight
    }

    pub(super) fn poll(&mut self, pipe: HANDLE) -> Result<Option<Completed>, IoError> {
        match self.phase {
            Phase::Prepared => return Err(IoError::InvalidPhase),
            Phase::Complete => {
                // Preserve the probe's completed-operation cleanup sentinel.
                // Callers must take/drop an operation after its first terminal
                // result; this does not erase any earlier protocol/native error.
                return Ok(Some(if self.read {
                    Completed::Eof
                } else {
                    Completed::Count(0)
                }));
            }
            Phase::InFlight => (),
        }
        let mut count = 0;
        // SAFETY: exact live pipe plus retained stable OVERLAPPED; exclusive
        // scalar output. FALSE does not wait or end the kernel borrow by itself.
        let result = unsafe {
            GetOverlappedResult(
                pipe,
                std::ptr::addr_of!((*self.pointer()).overlapped),
                &mut count,
                false,
            )
        };
        self.accept_poll_result(result.map(|()| count).map_err(|error| error.code().0))
    }

    fn accept_poll_result(
        &mut self,
        result: Result<u32, i32>,
    ) -> Result<Option<Completed>, IoError> {
        if self.phase != Phase::InFlight {
            return Err(IoError::InvalidPhase);
        }
        match result {
            Ok(count) => {
                self.phase = Phase::Complete;
                if count as usize > self.maximum {
                    return Err(IoError::InvalidBuffer);
                }
                if self.read {
                    // SAFETY: successful native completion ended writes, and
                    // count was checked before copying initialized buffer bytes.
                    let bytes =
                        unsafe { std::slice::from_raw_parts(self.buffer, count as usize) }.to_vec();
                    Ok(Some(Completed::Bytes(bytes)))
                } else {
                    Ok(Some(Completed::Count(count as usize)))
                }
            }
            Err(code) if code == HRESULT::from_win32(ERROR_IO_INCOMPLETE.0).0 => Ok(None),
            Err(code) if code == HRESULT::from_win32(ERROR_BROKEN_PIPE.0).0 => {
                self.phase = Phase::Complete;
                Ok(Some(Completed::Eof))
            }
            Err(hresult)
                if [ERROR_OPERATION_ABORTED.0, ERROR_MORE_DATA.0]
                    .iter()
                    .any(|code| hresult == HRESULT::from_win32(*code).0) =>
            {
                self.phase = Phase::Complete;
                Err(IoError::Native { hresult })
            }
            // A failed query is not proof that the operation stopped. Keep all
            // kernel-borrowed memory/event and require later confirmed drain.
            Err(hresult) => Err(IoError::Native { hresult }),
        }
    }

    pub(super) fn cancel(&mut self, pipe: HANDLE) -> Result<(), IoError> {
        if !self.in_flight() {
            return Ok(());
        }
        // SAFETY: cancels only this retained operation on its ORIGINAL live
        // pipe. The caller must continue polling; success/NOT_FOUND is not drain.
        let result =
            unsafe { CancelIoEx(pipe, Some(std::ptr::addr_of!((*self.pointer()).overlapped))) };
        self.accept_cancel_result(result.map_err(|error| error.code().0))
    }

    fn accept_cancel_result(&self, result: Result<(), i32>) -> Result<(), IoError> {
        match result {
            Ok(()) => Ok(()),
            Err(code) if code == HRESULT::from_win32(ERROR_NOT_FOUND.0).0 => Ok(()),
            Err(hresult) => Err(IoError::Native { hresult }),
        }
    }
}

impl<E: EventHandle> Drop for PendingOperation<E> {
    fn drop(&mut self) {
        if self.in_flight() {
            // Fail-safe only. The enclosing owner separately retains its pipe,
            // full identity/context reservation and quarantine until real drain.
            if let Some(storage) = self.storage.take() {
                mem::forget(storage);
            }
            if let Some(event) = self.event.take() {
                mem::forget(event);
            }
        }
    }
}

// The private adapters supply explicit protocol caps. DWORD bounds are checked
// before allocation too; connect/EOF reads allocate only their requested length.
pub(super) fn prepare_buffer(
    kind: Kind<'_>,
    limits: BufferLimits,
) -> Result<(bool, Box<[u8]>), IoError> {
    if limits.max_read > u32::MAX as usize || limits.max_write > u32::MAX as usize {
        return Err(IoError::InvalidBuffer);
    }
    let (read, length) = match kind {
        Kind::Connect => (false, 0),
        Kind::Write(bytes) if bytes.len() <= limits.max_write => (false, bytes.len()),
        Kind::Read(count) if count != 0 && count <= limits.max_read => (true, count),
        Kind::Write(_) | Kind::Read(_) => return Err(IoError::InvalidBuffer),
    };
    let mut buffer = vec![0; length].into_boxed_slice();
    if let Kind::Write(bytes) = kind {
        buffer.copy_from_slice(bytes);
    }
    Ok((read, buffer))
}

#[cfg(test)]
pub(super) fn storage_size_for_tests() -> usize {
    mem::size_of::<Storage>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    // No native event or pipe exists in these state fixtures, and issue/pending
    // poll/cancel are NEVER called. Only private result classifiers are exercised.
    struct EventFixture(Rc<Cell<usize>>);
    impl EventHandle for EventFixture {
        fn raw_event(&self) -> HANDLE {
            HANDLE::default()
        }
    }
    impl Drop for EventFixture {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    fn prepared(kind: Kind<'_>, drops: &Rc<Cell<usize>>) -> PendingOperation<EventFixture> {
        PendingOperation::prepare(
            kind,
            BufferLimits {
                max_read: 8,
                max_write: 8,
            },
            EventFixture(Rc::clone(drops)),
        )
        .unwrap()
    }
    fn code(value: u32) -> i32 {
        HRESULT::from_win32(value).0
    }

    #[test]
    fn prepared_storage_is_stable_and_closes_event_without_issuing() {
        let drops = Rc::new(Cell::new(0));
        let operation = prepared(Kind::Read(4), &drops);
        let pointer = operation.pointer();
        let buffer = operation.buffer;
        let moved = Box::new(operation);
        assert_eq!(moved.pointer(), pointer);
        assert_eq!(moved.buffer, buffer);
        assert!(!moved.in_flight());
        drop(moved);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn synchronous_and_pending_issue_results_both_require_completion() {
        for result in [Ok(()), Err(code(ERROR_IO_PENDING.0))] {
            let drops = Rc::new(Cell::new(0));
            let mut operation = prepared(Kind::Write(&[1, 2]), &drops);
            operation.accept_issue_result(result).unwrap();
            assert!(operation.in_flight());
            assert_eq!(
                operation.accept_issue_result(Ok(())),
                Err(IoError::InvalidPhase)
            );
            assert!(operation.in_flight());
            assert_eq!(
                operation.accept_poll_result(Ok(2)),
                Ok(Some(Completed::Count(2)))
            );
            assert!(!operation.in_flight());
            drop(operation);
            assert_eq!(drops.get(), 1);
        }
    }

    #[test]
    fn already_connected_race_and_broken_pipe_are_distinct_terminal_results() {
        let drops = Rc::new(Cell::new(0));
        let mut connect = prepared(Kind::Connect, &drops);
        connect
            .accept_issue_result(Err(code(ERROR_PIPE_CONNECTED.0)))
            .unwrap();
        assert_eq!(
            connect.poll(HANDLE::default()),
            Ok(Some(Completed::Count(0)))
        );
        assert_eq!(
            connect.accept_issue_result(Ok(())),
            Err(IoError::InvalidPhase)
        );
        let mut read = prepared(Kind::Read(1), &drops);
        read.accept_issue_result(Err(code(ERROR_BROKEN_PIPE.0)))
            .unwrap();
        assert_eq!(read.poll(HANDLE::default()), Ok(Some(Completed::Eof)));
        let mut not_connect = prepared(Kind::Read(1), &drops);
        assert_eq!(
            not_connect.accept_issue_result(Err(code(ERROR_PIPE_CONNECTED.0))),
            Err(IoError::Native {
                hresult: code(ERROR_PIPE_CONNECTED.0)
            })
        );
        assert!(!not_connect.in_flight());
    }

    #[test]
    fn cancel_success_or_not_found_and_unknown_poll_error_do_not_release_borrow() {
        let drops = Rc::new(Cell::new(0));
        let mut operation = prepared(Kind::Read(1), &drops);
        operation
            .accept_issue_result(Err(code(ERROR_IO_PENDING.0)))
            .unwrap();
        for result in [Ok(()), Err(code(ERROR_NOT_FOUND.0))] {
            operation.accept_cancel_result(result).unwrap();
            assert!(operation.in_flight());
        }
        assert_eq!(
            operation.accept_poll_result(Err(code(ERROR_IO_INCOMPLETE.0))),
            Ok(None)
        );
        assert!(operation.in_flight());
        let denied = code(5);
        assert_eq!(
            operation.accept_poll_result(Err(denied)),
            Err(IoError::Native { hresult: denied })
        );
        assert_eq!(
            operation.accept_cancel_result(Err(denied)),
            Err(IoError::Native { hresult: denied })
        );
        assert!(operation.in_flight());
        // Only the synthetic terminal completion permits ordinary member drop.
        assert_eq!(
            operation.accept_poll_result(Err(code(ERROR_OPERATION_ABORTED.0))),
            Err(IoError::Native {
                hresult: code(ERROR_OPERATION_ABORTED.0)
            })
        );
        assert!(!operation.in_flight());
        drop(operation);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn more_data_rejects_message_and_successful_count_is_bounded_after_completion() {
        let drops = Rc::new(Cell::new(0));
        for result in [Err(code(ERROR_MORE_DATA.0)), Ok(2)] {
            let mut operation = prepared(Kind::Read(1), &drops);
            operation.accept_issue_result(Ok(())).unwrap();
            let expected = if result.is_ok() {
                IoError::InvalidBuffer
            } else {
                IoError::Native {
                    hresult: code(ERROR_MORE_DATA.0),
                }
            };
            assert_eq!(operation.accept_poll_result(result), Err(expected));
            assert!(!operation.in_flight());
        }
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn read_bytes_or_broken_pipe_release_only_after_terminal_poll_result() {
        let drops = Rc::new(Cell::new(0));
        let mut read = prepared(Kind::Read(4), &drops);
        assert_eq!(read.poll(HANDLE::default()), Err(IoError::InvalidPhase));
        read.accept_issue_result(Err(code(ERROR_IO_PENDING.0)))
            .unwrap();
        assert_eq!(
            read.accept_poll_result(Ok(4)),
            Ok(Some(Completed::Bytes(vec![0; 4])))
        );
        assert!(!read.in_flight());
        drop(read);
        assert_eq!(drops.get(), 1);
        let mut read = prepared(Kind::Read(1), &drops);
        read.accept_issue_result(Ok(())).unwrap();
        assert_eq!(
            read.accept_poll_result(Err(code(ERROR_BROKEN_PIPE.0))),
            Ok(Some(Completed::Eof))
        );
        assert!(!read.in_flight());
        drop(read);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn explicit_read_and_write_caps_reject_before_allocation() {
        let limits = BufferLimits {
            max_read: 2,
            max_write: 3,
        };
        assert!(matches!(
            prepare_buffer(Kind::Read(0), limits),
            Err(IoError::InvalidBuffer)
        ));
        assert!(matches!(
            prepare_buffer(Kind::Read(3), limits),
            Err(IoError::InvalidBuffer)
        ));
        assert!(matches!(
            prepare_buffer(Kind::Write(&[0; 4]), limits),
            Err(IoError::InvalidBuffer)
        ));
        assert_eq!(
            prepare_buffer(Kind::Read(2), limits).unwrap(),
            (true, vec![0; 2].into_boxed_slice())
        );
        assert_eq!(
            prepare_buffer(Kind::Write(&[1, 2, 3]), limits).unwrap(),
            (false, vec![1, 2, 3].into_boxed_slice())
        );
        assert!(matches!(
            prepare_buffer(
                Kind::Connect,
                BufferLimits {
                    max_read: usize::MAX,
                    max_write: 0
                }
            ),
            Err(IoError::InvalidBuffer)
        ));
        assert!(matches!(
            prepare_buffer(
                Kind::Connect,
                BufferLimits {
                    max_read: 0,
                    max_write: usize::MAX
                }
            ),
            Err(IoError::InvalidBuffer)
        ));
    }

    #[test]
    fn pending_drop_retains_owned_event_instead_of_claiming_cancellation() {
        let drops = Rc::new(Cell::new(0));
        let mut operation = prepared(Kind::Read(1), &drops);
        operation
            .accept_issue_result(Err(code(ERROR_IO_PENDING.0)))
            .unwrap();
        drop(operation); // Intentionally retains this tiny synthetic storage/event.
        assert_eq!(drops.get(), 0);
        assert_eq!(Rc::strong_count(&drops), 2);
    }
}
