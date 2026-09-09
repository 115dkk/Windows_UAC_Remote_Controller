// SPDX-License-Identifier: GPL-2.0-or-later
//! Reviewed Windows FFI boundary. Native handles never cross the public API.
//! Every borrowed pointer is bounded by an owned OS allocation or stack buffer.
//! Directory/file handles omit FILE_SHARE_DELETE and stay alive through the
//! privileged operation, pinning validated paths under the intact-OS model.

mod diagnostic;
mod elevation;
mod filesystem;
#[cfg(target_pointer_width = "64")]
pub(crate) mod probe_supervisor;
mod security;
mod trust_store;

pub(crate) use elevation::request_elevated_control;
pub(crate) use trust_store::{
    MAX_TRUST_FILE_BYTES, ServiceTrustFile, TrustDirectory, provision_trust_directory,
};

pub(crate) use filesystem::{
    ActivityDirectory, expected_executable, open_activity_directory, provision_activity_directory,
    validate_installation,
};
pub(crate) use security::{harden_service, require_elevated, verify_service_security};

use crate::{ServiceError, ServiceOperation};
use std::{ffi::OsStr, fmt, os::windows::ffi::OsStrExt};
use windows::{
    Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
    core::PCWSTR,
};

pub(crate) fn win_error(operation: ServiceOperation, error: windows::core::Error) -> ServiceError {
    ServiceError::WindowsCall {
        operation,
        code: error.code().0 as u32,
    }
}

struct Wide(Vec<u16>);
impl Wide {
    fn new(text: impl AsRef<OsStr>) -> Result<Self, ServiceError> {
        let mut units: Vec<u16> = text.as_ref().encode_wide().collect();
        if units.len() > 32_000 || units.contains(&0) {
            return Err(ServiceError::UnsafePath);
        }
        units.push(0);
        Ok(Self(units))
    }
    fn ptr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
}

struct OwnedHandle(HANDLE);
impl fmt::Debug for OwnedHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedHandle(redacted)")
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: constructed only from a successful owning Windows handle
        // result, never pseudo/null/invalid handles; released exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: only successful LocalAlloc-family API outputs enter this
        // guard; all borrowed descriptor/SID pointers expire before this drop.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}
