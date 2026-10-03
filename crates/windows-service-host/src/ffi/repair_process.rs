// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed child invocation used only after repair has re-hashed the main binary.

use std::{mem::size_of, path::Path, time::Duration};

use windows::{
    Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            CREATE_NO_WINDOW, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION,
            STARTUPINFOW, WaitForSingleObject,
        },
    },
    core::PWSTR,
};

use super::{OwnedHandle, Wide, win_error};
use crate::{ServiceError, ServiceOperation};

#[derive(Clone, Copy, Debug)]
pub(crate) enum RepairChildVerb {
    Install,
    Start,
}

impl RepairChildVerb {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Start => "start",
        }
    }
}

pub(crate) fn run(
    executable: &Path,
    verb: RepairChildVerb,
    timeout: Duration,
) -> Result<(), ServiceError> {
    let verb = verb.as_str();
    let executable_text = executable.to_str().ok_or(ServiceError::UnsafePath)?;
    let image = Wide::new(executable)?;
    let mut command: Vec<u16> = format!("\"{executable_text}\" {verb}\0")
        .encode_utf16()
        .collect();
    let directory = Wide::new(executable.parent().ok_or(ServiceError::UnsafePath)?)?;
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: fixed checked image and enum-selected verb; mutable terminated
    // command buffer and startup/output structures live through the synchronous
    // call. bInheritHandles is false and no environment pointer is supplied.
    unsafe {
        CreateProcessW(
            image.ptr(),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            directory.ptr(),
            &startup,
            &mut info,
        )
    }
    .map_err(|error| win_error(ServiceOperation::LaunchRepairChild, error))?;
    if info.hProcess.is_invalid()
        || info.hThread.is_invalid()
        || info.dwProcessId == 0
        || info.dwThreadId == 0
    {
        // CreateProcessW succeeded but did not return its documented pair of live
        // handles. Close any valid output without constructing an invalid owner.
        if !info.hProcess.is_invalid() {
            drop(OwnedHandle(info.hProcess));
        }
        if !info.hThread.is_invalid() {
            drop(OwnedHandle(info.hThread));
        }
        return Err(ServiceError::UnexpectedState);
    }
    let process = OwnedHandle(info.hProcess);
    let _thread = OwnedHandle(info.hThread);
    let milliseconds = u32::try_from(timeout.as_millis()).map_err(|_| ServiceError::Timeout)?;
    // SAFETY: live child-process handle, bounded non-alertable wait.
    let wait = unsafe { WaitForSingleObject(process.0, milliseconds) };
    if wait == WAIT_TIMEOUT {
        return Err(ServiceError::Timeout);
    }
    if wait != WAIT_OBJECT_0 {
        return Err(win_error(
            ServiceOperation::WaitRepairChild,
            windows::core::Error::from_thread(),
        ));
    }
    let mut exit_code = 0;
    // SAFETY: signaled child handle remains owned and output is initialized.
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
        .map_err(|error| win_error(ServiceOperation::WaitRepairChild, error))?;
    if exit_code != 0 {
        return Err(ServiceError::UnexpectedState);
    }
    Ok(())
}
