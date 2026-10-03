// SPDX-License-Identifier: GPL-2.0-or-later
//! One protected installation-local file serializes install, removal and repair.

use std::{mem::size_of, path::Path, ptr, thread, time::Duration};

use windows::{
    Win32::{
        Foundation::{ERROR_DELETE_PENDING, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_DELETE_ON_CLOSE,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE, OPEN_ALWAYS,
        },
    },
    core::HRESULT,
};

use super::{
    OwnedHandle, Wide,
    filesystem::{inspect_open_handle, known_folder, pin_ancestors},
    security::SecurityDescriptor,
    win_error,
};
use crate::{
    INSTALLATION_FOLDER, ServiceError, ServiceOperation,
    policy::{self, ObjectPolicy},
};

const LOCK_FILE: &str = "maintenance.lock";
const RETRY_INTERVAL: Duration = Duration::from_millis(250);
const RETRY_LIMIT: u16 = 240;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetryDecision {
    Retry,
    Timeout,
}

const fn retry_decision(elapsed_intervals: u16) -> RetryDecision {
    if elapsed_intervals < RETRY_LIMIT {
        RetryDecision::Retry
    } else {
        RetryDecision::Timeout
    }
}

fn is_lock_contention(error: &windows::core::Error) -> bool {
    [ERROR_SHARING_VIOLATION, ERROR_DELETE_PENDING]
        .into_iter()
        .any(|code| error.code() == HRESULT::from_win32(code.0) || error.code().0 as u32 == code.0)
}

#[derive(Debug)]
pub(crate) struct MaintenanceGuard {
    _lock: OwnedHandle,
    _pins: Vec<OwnedHandle>,
}

pub(crate) fn acquire() -> Result<MaintenanceGuard, ServiceError> {
    let program_files = known_folder(&windows::Win32::UI::Shell::FOLDERID_ProgramFiles)?;
    let installation = program_files.join(INSTALLATION_FOLDER);
    let path = installation.join(LOCK_FILE);
    let trusted = policy::trusted_system_sids();
    let mut pins = pin_ancestors(&program_files, &trusted)?;
    pins.push(super::filesystem::open_checked(
        &installation,
        true,
        ObjectPolicy::Installation,
        &trusted,
    )?);
    let lock = open_with_retry(&path, &trusted)?;
    // Recheck the retained parent after opening/possibly creating the lock leaf.
    inspect_open_handle(
        pins.last().ok_or(ServiceError::UntrustedInstallation)?,
        &installation,
        true,
        ObjectPolicy::Installation,
        &trusted,
    )?;
    Ok(MaintenanceGuard {
        _lock: lock,
        _pins: pins,
    })
}

fn open_with_retry(path: &Path, trusted: &[Vec<u8>]) -> Result<OwnedHandle, ServiceError> {
    let descriptor = SecurityDescriptor::from_sddl("D:P(A;;FA;;;SY)(A;;FA;;;BA)")?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    };
    let wide = Wide::new(path)?;
    let mut elapsed_intervals: u16 = 0;
    loop {
        // SAFETY: fixed leaf below retained protected installation pins; OPEN_ALWAYS
        // cannot escape that parent, share0 is the lock, DELETE_ON_CLOSE removes only
        // this exact file, and the protected descriptor is applied atomically if new.
        let opened = unsafe {
            CreateFileW(
                wide.ptr(),
                (GENERIC_READ | GENERIC_WRITE).0 | DELETE.0,
                FILE_SHARE_MODE(0),
                Some(ptr::from_ref(&attributes)),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        };
        match opened {
            Ok(raw) => {
                let handle = OwnedHandle(raw);
                inspect_open_handle(&handle, path, false, ObjectPolicy::Installation, trusted)?;
                return Ok(handle);
            }
            Err(error) if is_lock_contention(&error) => match retry_decision(elapsed_intervals) {
                RetryDecision::Retry => {
                    thread::sleep(RETRY_INTERVAL);
                    elapsed_intervals += 1;
                }
                RetryDecision::Timeout => return Err(ServiceError::Timeout),
            },
            Err(error) => {
                return Err(win_error(ServiceOperation::AcquireMaintenanceLock, error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_violations_retry_then_timeout_at_sixty_seconds() {
        assert_eq!(RETRY_INTERVAL, Duration::from_millis(250));
        assert_eq!(RETRY_LIMIT, 240);
        assert_eq!(retry_decision(0), RetryDecision::Retry);
        assert_eq!(retry_decision(239), RetryDecision::Retry);
        assert_eq!(retry_decision(240), RetryDecision::Timeout);
        assert_eq!(retry_decision(u16::MAX), RetryDecision::Timeout);
    }
}
