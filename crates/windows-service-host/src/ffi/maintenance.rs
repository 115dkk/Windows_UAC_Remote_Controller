// SPDX-License-Identifier: GPL-2.0-or-later
//! One protected, machine-wide lock serializes installation, removal and repair.

use std::{mem::size_of, ptr};

use windows::{
    Win32::{
        Foundation::{ERROR_ACCESS_DENIED, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Security::SECURITY_ATTRIBUTES,
        System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    },
    core::w,
};

use super::{OwnedHandle, security::SecurityDescriptor, win_error};
use crate::{ServiceError, ServiceOperation};

const WAIT_MILLIS: u32 = 60_000;

#[derive(Debug)]
pub(crate) struct MaintenanceGuard {
    handle: OwnedHandle,
}

pub(crate) fn acquire() -> Result<MaintenanceGuard, ServiceError> {
    // SYNCHRONIZE | MUTEX_MODIFY_STATE only: administrators and SYSTEM can wait
    // and release after acquisition, but cannot change the mutex object's DACL.
    let descriptor =
        SecurityDescriptor::from_sddl("O:SYG:SYD:P(A;;0x00100001;;;SY)(A;;0x00100001;;;BA)")?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    };
    // SAFETY: fixed Global name and live fixed SYSTEM/Administrators descriptor.
    // Creation does not take ownership; the returned owning handle is adopted once.
    // If an existing same-name object has a hostile type or DACL, CreateMutexW
    // refuses it; this code never opens a fallback name or broadens access.
    let handle = match unsafe {
        CreateMutexW(
            Some(ptr::from_ref(&attributes)),
            false,
            w!("Global\\UacRemoteController.Maintenance.v1"),
        )
    } {
        Ok(handle) => handle,
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
            return Err(ServiceError::UnsafePermissions);
        }
        Err(error) => {
            return Err(win_error(ServiceOperation::AcquireMaintenanceLock, error));
        }
    };
    let handle = OwnedHandle(handle);
    // SAFETY: live waitable mutex handle, bounded 60-second wait, no alertable wait.
    let wait = unsafe { WaitForSingleObject(handle.0, WAIT_MILLIS) };
    if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
        return Ok(MaintenanceGuard { handle });
    }
    if wait == WAIT_TIMEOUT {
        return Err(ServiceError::Timeout);
    }
    Err(win_error(
        ServiceOperation::AcquireMaintenanceLock,
        windows::core::Error::from_thread(),
    ))
}

impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after this thread acquired the mutex.
        // Release occurs once before the owning handle's destructor closes it.
        let _ = unsafe { ReleaseMutex(self.handle.0) };
    }
}
