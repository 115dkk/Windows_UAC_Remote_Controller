// SPDX-License-Identifier: GPL-2.0-or-later
//! The only UI elevation bridge: one fixed protected executable and enum verb.

use super::{OwnedHandle, Wide, validate_installation, win_error};
use crate::{
    ControlOutcome, ServiceControlIntent, ServiceError, ServiceOperation,
    contract::LIFECYCLE_TIMEOUT, native,
};
use std::mem::size_of;
use windows::{
    Win32::{
        Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{GetExitCodeProcess, WaitForSingleObject},
        UI::Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
    },
    core::w,
};

pub(crate) fn request_elevated_control(
    intent: ServiceControlIntent,
) -> Result<ControlOutcome, ServiceError> {
    let installation = validate_installation(false)?;
    native::verify_ui_helper_target(installation.executable())?;
    let executable = Wide::new(installation.executable())?;
    let arguments = Wide::new(intent.argument())?;
    let directory = Wide::new(
        installation
            .executable()
            .parent()
            .ok_or(ServiceError::UnsafePath)?,
    )?;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("runas"),
        lpFile: executable.ptr(),
        lpParameters: arguments.ptr(),
        lpDirectory: directory.ptr(),
        nShow: 0, // SW_HIDE: helper console only, never Windows consent.
        ..Default::default()
    };
    // SAFETY: all strings are owned and pinned through this synchronous call.
    // Executable is the validated protected constant helper, never caller input;
    // the only parameter is one fixed enum verb. Windows performs elevation.
    match unsafe { ShellExecuteExW(&mut info) } {
        Ok(()) => (),
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_CANCELLED.0) => {
            return Ok(ControlOutcome::UserCancelled);
        }
        Err(error) => return Err(win_error(ServiceOperation::LaunchElevatedHelper, error)),
    }
    if info.hProcess.is_invalid() {
        // Launch did not provide a waitable process; no completion is invented.
        return Ok(ControlOutcome::CompletionStatusUnknown);
    }
    let process = OwnedHandle(info.hProcess);
    // SAFETY: ShellExecuteExW transferred this waitable process handle under
    // NOCLOSEPROCESS. Timeout closes our handle but never kills the helper.
    let wait = unsafe { WaitForSingleObject(process.0, LIFECYCLE_TIMEOUT.as_millis() as u32) };
    if wait == WAIT_TIMEOUT {
        return Ok(ControlOutcome::StillRunning);
    }
    if wait != WAIT_OBJECT_0 {
        return Err(win_error(
            ServiceOperation::WaitElevatedHelper,
            windows::core::Error::from_thread(),
        ));
    }
    let mut exit_code = 0;
    // SAFETY: process is signaled/terminated, remains owned, and output is valid.
    unsafe { GetExitCodeProcess(process.0, &mut exit_code) }
        .map_err(|e| win_error(ServiceOperation::WaitElevatedHelper, e))?;
    if exit_code != 0 {
        return Ok(ControlOutcome::HelperFailed { exit_code });
    }
    match crate::query_status() {
        Ok(snapshot) => Ok(ControlOutcome::Completed { snapshot }),
        Err(_) => Ok(ControlOutcome::CompletionStatusUnknown),
    }
}
