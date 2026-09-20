// SPDX-License-Identifier: GPL-2.0-or-later
//! Windows-only FFI ownership boundary. No raw handle/pointer escapes this module.
//!
//! The thread desktop is borrowed from the current live thread and never closed.
//! The input desktop is a separately opened, noninheritable owned handle, released
//! exactly once on the normal path or by Drop on early-return/unwind paths. Both
//! wrappers are thread-affine, private, non-Clone and non-Copy. No callback,
//! desktop assignment, desktop switch, privilege change or input operation exists.

use std::{fmt, marker::PhantomData, rc::Rc};

use windows::{
    Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE},
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            StationsAndDesktops::{
                CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetThreadDesktop,
                GetUserObjectInformationW, HDESK, OpenInputDesktop, UOI_NAME,
            },
            Threading::GetCurrentThreadId,
        },
    },
    core::{Error as WindowsError, HRESULT},
};

use crate::{
    DesktopCategory, DesktopObservation, DesktopTarget, MAX_DESKTOP_NAME_UNITS, ObserveError,
    ObserveOperation,
    name::{classify_name_result, units_for_byte_length},
};

pub(super) fn observe() -> Result<DesktopObservation, ObserveError> {
    let process_session_id = current_process_session()?;
    let thread = BorrowedThreadDesktop::current()?;
    let thread_desktop = thread.category()?;
    let input = OwnedInputDesktop::open_read_only()?;
    let input_desktop = input.category()?;
    // Normal-path close errors are surfaced instead of reporting a clean success.
    // If any earlier operation failed, Drop still attempts to release the handle.
    input.close()?;
    Ok(DesktopObservation {
        process_session_id,
        thread_desktop,
        input_desktop,
    })
}

fn current_process_session() -> Result<u32, ObserveError> {
    let process_id = std::process::id();
    let mut session_id = 0_u32;
    // SAFETY: process_id identifies this live process. session_id is aligned,
    // initialized, exclusively borrowed writable u32 storage for the full
    // synchronous call. Windows does not retain this pointer. No access rights
    // are elevated or changed; failure is propagated with fixed metadata only.
    unsafe { ProcessIdToSessionId(process_id, &mut session_id) }
        .map_err(|error| os_error(ObserveOperation::CurrentProcessSession, error))?;
    Ok(session_id)
}

/// Borrowed from the current thread; deliberately has NO Drop implementation.
/// Thread affinity plus module privacy keeps the handle on its owning live
/// thread throughout this synchronous observation. No API changes its desktop.
struct BorrowedThreadDesktop {
    handle: HDESK,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl BorrowedThreadDesktop {
    fn current() -> Result<Self, ObserveError> {
        // SAFETY: GetCurrentThreadId has no pointer arguments or preconditions.
        // The calling thread necessarily remains alive for this synchronous call.
        let thread_id = unsafe { GetCurrentThreadId() };
        // SAFETY: thread_id is the current live thread. This only obtains its
        // borrowed desktop handle; the handle is never passed to CloseDesktop,
        // assigned to another thread, stored externally or used after this scope.
        let handle = unsafe { GetThreadDesktop(thread_id) }
            .map_err(|error| os_error(ObserveOperation::CurrentThreadDesktop, error))?;
        Ok(Self {
            handle,
            _thread_affinity: PhantomData,
        })
    }

    fn category(&self) -> Result<DesktopCategory, ObserveError> {
        read_desktop_category(&self.handle, DesktopTarget::Thread)
    }
}

impl fmt::Debug for BorrowedThreadDesktop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BorrowedThreadDesktop([redacted])")
    }
}

/// Owns only OpenInputDesktop's separately opened handle. Option is taken before
/// closing so explicit close and Drop can never both close the same handle.
struct OwnedInputDesktop {
    handle: Option<HDESK>,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl OwnedInputDesktop {
    fn open_read_only() -> Result<Self, ObserveError> {
        // SAFETY: All arguments are value flags: zero control flags, inheritance
        // false, and only DESKTOP_READOBJECTS. This requests neither switch,
        // enumeration, write, hook, execute nor security-descriptor rights. The
        // returned valid handle is immediately placed in a unique RAII owner.
        // We accept access denial; no privilege or policy fallback is attempted.
        let handle =
            unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
                .map_err(|error| os_error(ObserveOperation::OpenInputDesktop, error))?;
        Ok(Self {
            handle: Some(handle),
            _thread_affinity: PhantomData,
        })
    }

    fn category(&self) -> Result<DesktopCategory, ObserveError> {
        // The only operation taking the handle consumes self, so a live shared
        // borrow always has its owned handle. Avoid relying on that invariant
        // for memory safety by reporting an error if it is ever violated.
        let handle = self
            .handle
            .as_ref()
            .ok_or(ObserveError::InputHandleAlreadyReleased)?;
        read_desktop_category(handle, DesktopTarget::Input)
    }

    fn close(mut self) -> Result<(), ObserveError> {
        let handle = self
            .handle
            .take()
            .ok_or(ObserveError::InputHandleAlreadyReleased)?;
        // SAFETY: This is solely the owned handle returned by OpenInputDesktop,
        // never the borrowed GetThreadDesktop handle. All queries/borrows
        // have finished; no thread was assigned this handle. Taking it before
        // the call prevents double-close, even if CloseDesktop reports failure.
        unsafe { CloseDesktop(handle) }
            .map_err(|error| os_error(ObserveOperation::CloseInputDesktop, error))?;
        Ok(())
    }
}

impl Drop for OwnedInputDesktop {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: Drop holds the sole remaining ownership of this valid,
            // separately opened input-desktop handle; it was never assigned to
            // any thread. Queries have ended, and taking it prevents double-close.
            // On an earlier failure/unwind, Drop cannot return an error; release
            // is best-effort and does not replace the already-failing outcome.
            let _ = unsafe { CloseDesktop(handle) };
        }
    }
}

impl fmt::Debug for OwnedInputDesktop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedInputDesktop([redacted])")
    }
}

fn read_desktop_category(
    handle: &HDESK,
    target: DesktopTarget,
) -> Result<DesktopCategory, ObserveError> {
    let operation = match target {
        DesktopTarget::Thread => ObserveOperation::ThreadDesktopName,
        DesktopTarget::Input => ObserveOperation::InputDesktopName,
    };
    let mut required_bytes = 0_u32;
    // SAFETY: handle is borrowed from a live private desktop wrapper for this
    // complete synchronous operation. HANDLE conversion preserves the opaque
    // value without taking ownership. No output buffer is supplied (length 0).
    // required_bytes is a properly aligned, exclusive, initialized u32 pointer
    // valid until the call returns, and Windows retains neither pointer.
    let probe = unsafe {
        GetUserObjectInformationW(
            HANDLE(handle.0),
            UOI_NAME,
            None,
            0,
            Some(&mut required_bytes),
        )
    };
    match probe {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {}
        Err(error) => return Err(os_error(operation, error)),
        Ok(()) => return Err(ObserveError::UnexpectedProbeSuccess { target }),
    }
    let count = units_for_byte_length(required_bytes)
        .map_err(|reason| ObserveError::DesktopName { target, reason })?;
    // Fixed-size initialized u16 storage provides UTF-16 alignment. A nonzero
    // sentinel prevents an unwritten slot from accidentally passing NUL checks.
    // The caller-controlled/API-reported length never controls an allocation.
    let mut storage = [0xffff_u16; MAX_DESKTOP_NAME_UNITS];
    let buffer = &mut storage[..count];
    let mut returned_bytes = 0_u32;
    // SAFETY: count was bounded to 1..=MAX_DESKTOP_NAME_UNITS and required_bytes
    // equals count * size_of::<u16>(). buffer is initialized, u16-aligned,
    // exclusively mutable writable storage for exactly that supplied byte count.
    // returned_bytes is separate initialized aligned storage. Neither pointer is
    // retained by this synchronous API; the borrowed desktop handle stays valid.
    // We do not interpret any buffer bytes until the API reports success.
    unsafe {
        GetUserObjectInformationW(
            HANDLE(handle.0),
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            required_bytes,
            Some(&mut returned_bytes),
        )
    }
    .map_err(|error| os_error(operation, error))?;
    classify_name_result(buffer, returned_bytes)
        .map_err(|reason| ObserveError::DesktopName { target, reason })
}

fn os_error(operation: ObserveOperation, error: WindowsError) -> ObserveError {
    ObserveError::WindowsCall {
        operation,
        hresult: error.code().0,
    }
}
