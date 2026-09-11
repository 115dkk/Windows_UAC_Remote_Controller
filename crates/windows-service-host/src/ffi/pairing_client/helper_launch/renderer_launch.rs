// SPDX-License-Identifier: GPL-2.0-or-later
//! One final renderer created with protected process/thread/desktop descriptors.
//! The original Helper owns launch/control only: no window, switch or secret.

use super::{
    ClientError, Error, Handle, PairingClient, PairingPeerRole, Stage, UNHEALTHY, Wide,
    cleanup_state, peer_error_at, process_identity, process_image,
};
use crate::{
    ffi::{pairing_peer::renderer as native_renderer, security::SecurityDescriptor},
    pairing_handoff::{RendererProcess, RendererRequest},
};
use std::{fmt, mem, sync::atomic::Ordering};
use windows::{
    Win32::{
        Foundation::{
            DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, ERROR_CANCELLED, ERROR_FILE_NOT_FOUND,
            HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::SECURITY_ATTRIBUTES,
        System::{
            StationsAndDesktops::{
                CloseDesktop, CreateDesktopW, DESKTOP_CONTROL_FLAGS, GetProcessWindowStation,
                GetThreadDesktop, HDESK, OpenDesktopW, SetThreadDesktop, UOI_NAME,
            },
            SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
                GetCurrentProcess, GetCurrentThreadId, GetExitCodeProcess, PROCESS_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResumeThread, STARTUPINFOW,
                TerminateProcess, WaitForSingleObject,
            },
        },
    },
    core::{Error as WinError, HRESULT, PCWSTR, PWSTR},
};

fn mapped(error: crate::PairingPeerError) -> Error {
    peer_error_at(Stage::QueryOwnIdentity, error).into()
}
fn native(stage: u8, error: WinError) -> Error {
    mapped(native_renderer::native(stage, error))
}
#[derive(Default)]
struct ResumeState {
    attempted: bool,
    termination_attempted: bool,
}
impl ResumeState {
    fn claim_resume(&mut self) -> Result<(), Error> {
        if self.attempted || self.termination_attempted {
            return Err(Error::InvalidPhase);
        }
        self.attempted = true;
        Ok(())
    }
    fn claim_termination(&mut self, created: bool) -> bool {
        if !created || self.attempted || self.termination_attempted {
            return false;
        }
        self.termination_attempted = true;
        true
    }
}
fn claim_desktop_close(attempted: &mut bool) -> Result<(), Error> {
    if *attempted {
        return Err(Error::CleanupUnconfirmed);
    }
    *attempted = true;
    Ok(())
}
struct Inner {
    request: Option<RendererRequest>,
    claimed: bool,
    created: bool,
    unknown_launch: bool,
    process: Option<Handle>,
    thread: Option<Handle>,
    metadata: Option<RendererProcess>,
    desktop: Option<HDESK>,
    old_thread_desktop: Option<HDESK>,
    thread_restored: bool,
    desktop_close_attempted: bool,
    resume: ResumeState,
    exit_observed: Option<u32>,
    closing: bool,
    drained: bool,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
}
pub(super) struct HelperRendererLaunch {
    inner: Option<Box<Inner>>,
}
impl fmt::Debug for HelperRendererLaunch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HelperRendererLaunch(redacted, nonvisual)")
    }
}
impl HelperRendererLaunch {
    pub(super) fn new() -> Self {
        Self {
            inner: Some(Box::new(Inner {
                request: None,
                claimed: false,
                created: false,
                unknown_launch: false,
                process: None,
                thread: None,
                metadata: None,
                desktop: None,
                old_thread_desktop: None,
                thread_restored: true,
                desktop_close_attempted: false,
                resume: ResumeState::default(),
                exit_observed: None,
                closing: false,
                drained: false,
                first_failure: None,
                cleanup_failure: None,
            })),
        }
    }
    pub(super) fn begin(
        &mut self,
        client: &mut PairingClient,
        mut request: RendererRequest,
    ) -> Result<(RendererRequest, RendererProcess), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            if inner.claimed {
                return Err(Error::InvalidPhase);
            }
            inner.claimed = true;
            client.inner_mut().fence()?;
            request.cutoff = request.cutoff.min(
                native_renderer::original_cutoff(client.inner_ref().budget.deadline)
                    .map_err(mapped)?,
            );
            inner.request = Some(request);
            native_renderer::check_setup_cutoff(request.cutoff).map_err(mapped)?;
            let connection = client
                .inner_ref()
                .connection
                .as_ref()
                .ok_or(Error::InvalidPhase)?;
            if connection.role != PairingPeerRole::Helper {
                return Err(Error::InvalidPhase);
            }
            native_renderer::require_owner(&connection.own.token, connection.own.session)
                .map_err(mapped)?;
            let sid = connection.service_sid.clone();
            let executable = connection.installation.service().to_path_buf();
            // SAFETY: borrowed current station and desktop. Neither borrowed
            // reference is closed, changed globally, inherited or exported.
            let station = unsafe { GetProcessWindowStation() }.map_err(|error| native(1, error))?;
            native_renderer::check_station(HANDLE(station.0)).map_err(mapped)?;
            let thread_id = unsafe { GetCurrentThreadId() };
            let old = unsafe { GetThreadDesktop(thread_id) }.map_err(|error| native(1, error))?;
            inner.old_thread_desktop = Some(old);
            let name = native_renderer::display_name(request.invocation);
            let name_wide = Wide::new(&name).map_err(ClientError::Service)?;
            client.inner_mut().fence()?;
            native_renderer::check_setup_cutoff(request.cutoff).map_err(mapped)?;
            // SAFETY: one fixed-prefix name, actual current WinSta0. Only a
            // definite missing object admits creation; no collision/ACL repair.
            match unsafe {
                OpenDesktopW(
                    name_wide.ptr(),
                    DESKTOP_CONTROL_FLAGS(0),
                    false,
                    native_renderer::DESKTOP_RIGHTS,
                )
            } {
                Ok(existing) => {
                    inner.desktop = Some(existing);
                    return Err(Error::Protocol);
                }
                Err(error) if error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => (),
                Err(error) => return Err(native(1, error)),
            }
            let desktop_sd = native_renderer::descriptor(native_renderer::Profile::Desktop, &sid)
                .map_err(mapped)?;
            let desktop_sa = attributes(&desktop_sd);
            client.inner_mut().fence()?;
            native_renderer::check_setup_cutoff(request.cutoff).map_err(mapped)?;
            // SAFETY: fresh explicitly secured application desktop, no hooks or
            // inheritance. This creates no application window and never switches input.
            let desktop = unsafe {
                CreateDesktopW(
                    name_wide.ptr(),
                    PCWSTR::null(),
                    None,
                    DESKTOP_CONTROL_FLAGS(0),
                    native_renderer::DESKTOP_RIGHTS,
                    Some(&desktop_sa),
                )
            }
            .map_err(|error| native(1, error))?;
            inner.desktop = Some(desktop);
            inner.thread_restored = false;
            // SAFETY: restore this non-UI thread's original assignment only;
            // no SwitchDesktop, window creation or global station mutation.
            unsafe { SetThreadDesktop(old) }.map_err(|error| native(1, error))?;
            inner.thread_restored = true;
            if native_renderer::object_text(HANDLE(desktop.0), UOI_NAME).map_err(mapped)? != name {
                return Err(Error::Protocol);
            }
            native_renderer::verify_descriptor(
                HANDLE(desktop.0),
                native_renderer::Profile::Desktop,
                &sid,
            )
            .map_err(mapped)?;
            let process_sd = native_renderer::descriptor(native_renderer::Profile::Process, &sid)
                .map_err(mapped)?;
            let thread_sd = native_renderer::descriptor(native_renderer::Profile::Thread, &sid)
                .map_err(mapped)?;
            let process_sa = attributes(&process_sd);
            let thread_sa = attributes(&thread_sd);
            let target = executable.to_str().ok_or(Error::InvalidPhase)?;
            if target.contains('"') {
                return Err(Error::InvalidPhase);
            }
            let image = Wide::new(&executable).map_err(ClientError::Service)?;
            let mut command: Vec<u16> = format!(
                "\"{target}\" pair-renderer {} {}\0",
                request.invocation.pending().argument(),
                request.invocation.display().argument()
            )
            .encode_utf16()
            .collect();
            let directory = Wide::new(executable.parent().ok_or(Error::InvalidPhase)?)
                .map_err(ClientError::Service)?;
            let mut desktop_path: Vec<u16> = format!("WinSta0\\{name}\0").encode_utf16().collect();
            let environment = environment(request.cutoff)?;
            let startup = STARTUPINFOW {
                cb: mem::size_of::<STARTUPINFOW>() as u32,
                lpDesktop: PWSTR(desktop_path.as_mut_ptr()),
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            client.inner_mut().fence()?;
            native_renderer::check_setup_cutoff(request.cutoff).map_err(mapped)?;
            inner.unknown_launch = true;
            // SAFETY: fixed pinned executable/closed public argv, exact desktop,
            // explicit process+thread descriptors AT creation, no inherited handles,
            // own admitted primary token and no shell/privilege/token substitution.
            unsafe {
                CreateProcessW(
                    image.ptr(),
                    Some(PWSTR(command.as_mut_ptr())),
                    Some(&process_sa),
                    Some(&thread_sa),
                    false,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    Some(environment.as_ptr().cast()),
                    directory.ptr(),
                    &startup,
                    &mut info,
                )
            }
            .map_err(|error| native(3, error))?;
            // Adopt successful outputs BEFORE every fallible identity/readback.
            inner.process = Some(Handle(info.hProcess));
            inner.thread = Some(Handle(info.hThread));
            inner.created = true;
            inner.unknown_launch = false;
            if info.hProcess.is_invalid()
                || info.hThread.is_invalid()
                || info.dwProcessId == 0
                || info.dwThreadId == 0
            {
                return Err(Error::LaunchUnconfirmed);
            }
            let metadata = RendererProcess {
                pid: info.dwProcessId,
                created: process_identity(info.hProcess, info.dwProcessId).map_err(mapped)?,
                thread: info.dwThreadId,
            };
            inner.metadata = Some(metadata);
            inner.recheck(client)?;
            native_renderer::verify_descriptor(
                info.hProcess,
                native_renderer::Profile::Process,
                &sid,
            )
            .map_err(mapped)?;
            native_renderer::verify_descriptor(
                info.hThread,
                native_renderer::Profile::Thread,
                &sid,
            )
            .map_err(mapped)?;
            inner.recheck(client)?;
            Ok((request, metadata))
        })();
        result.map_err(|error| inner.fail(error))
    }
    pub(super) fn resume(
        &mut self,
        client: &mut PairingClient,
        request: RendererRequest,
    ) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            if inner.request != Some(request) || !inner.created || inner.first_failure.is_some() {
                return Err(Error::InvalidPhase);
            }
            inner.recheck(client)?;
            native_renderer::check_setup_cutoff(request.cutoff).map_err(mapped)?;
            inner.resume.claim_resume()?; // BEFORE native call; uncertainty cannot kill/retry.
            let thread = inner.thread.as_ref().ok_or(Error::LaunchUnconfirmed)?.0;
            // SAFETY: exactly the retained initial thread from our suspended
            // creation, and only after authenticated service registration.
            let previous = unsafe { ResumeThread(thread) };
            if previous != 1 {
                return Err(if previous == u32::MAX {
                    native(6, WinError::from_thread())
                } else {
                    Error::LaunchUnconfirmed
                });
            }
            let process = inner.process.as_ref().ok_or(Error::LaunchUnconfirmed)?.0;
            let mut reduced = HANDLE::default();
            // SAFETY: reduce our actual returned child handle after resume was
            // attempted; no caller PID, inheritance or access increase.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    process,
                    GetCurrentProcess(),
                    &mut reduced,
                    PROCESS_QUERY_LIMITED_INFORMATION.0 | PROCESS_SYNCHRONIZE.0,
                    false,
                    DUPLICATE_HANDLE_OPTIONS(0),
                )
            }
            .map_err(|error| native(5, error))?;
            let reduced = Handle::new(reduced)?;
            drop(inner.process.replace(reduced));
            drop(inner.thread.take());
            cleanup_state()?;
            inner.recheck(client)
        })();
        result.map_err(|error| inner.fail(error))
    }
    pub(super) fn recheck(&mut self, client: &mut PairingClient) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = inner.recheck(client);
        result.map_err(|error| inner.fail(error))
    }
    pub(super) fn close_requested(&mut self) {
        self.inner_mut().closing = true;
    }
    pub(super) fn cancel(&mut self) {
        let inner = self.inner_mut();
        inner.fail(Error::Cancelled);
        inner.request_pre_resume_termination();
    }
    pub(super) fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
    }
    pub(super) fn failure(&self) -> Option<Error> {
        self.inner
            .as_ref()
            .and_then(|inner| inner.first_failure.or(inner.cleanup_failure))
    }
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner
            .as_deref_mut()
            .expect("renderer launch exists until Drop")
    }
}
impl Inner {
    fn fail(&mut self, error: Error) -> Error {
        self.closing = true;
        *self.first_failure.get_or_insert(error)
    }
    fn recheck(&self, client: &mut PairingClient) -> Result<(), Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        client.inner_mut().fence()?;
        let request = self.request.ok_or(Error::InvalidPhase)?;
        native_renderer::check_cutoff(request.cutoff).map_err(mapped)?;
        let process = self.process.as_ref().ok_or(Error::LaunchUnconfirmed)?.0;
        let metadata = self.metadata.ok_or(Error::LaunchUnconfirmed)?;
        if process_identity(process, metadata.pid).map_err(mapped)? != metadata.created {
            return Err(Error::LaunchUnconfirmed);
        }
        let connection = client
            .inner_ref()
            .connection
            .as_ref()
            .ok_or(Error::InvalidPhase)?;
        connection
            .installation
            .check_service_image(&process_image(process)?)
            .map_err(ClientError::Service)?;
        let token = crate::ffi::pairing_peer::TokenFacts::observe(process).map_err(mapped)?;
        native_renderer::require_owner(&token, connection.own.session).map_err(mapped)?;
        client.inner_mut().fence()?;
        native_renderer::check_cutoff(request.cutoff).map_err(mapped)
    }
    fn exit(&self) -> Result<Option<u32>, Error> {
        let Some(process) = self.process.as_ref() else {
            return Ok(None);
        };
        if process.0.is_invalid() {
            return Err(Error::LaunchUnconfirmed);
        }
        // SAFETY: our retained actual creation handle or its reduced duplicate.
        match unsafe { WaitForSingleObject(process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                // SAFETY: actual signalled process, initialized exit output.
                unsafe { GetExitCodeProcess(process.0, &mut code) }
                    .map_err(|error| native(9, error))?;
                Ok(Some(code))
            }
            _ => Err(native(9, WinError::from_thread())),
        }
    }
    fn request_pre_resume_termination(&mut self) {
        let Some(process) = self.process.as_ref() else {
            return;
        };
        if process.0.is_invalid() || !self.resume.claim_termination(self.created) {
            return;
        }
        // SAFETY: ROOT-approved downward cleanup ONLY for the exact handle
        // returned by THIS successful suspended CreateProcess, before ANY
        // ResumeThread attempt. No PID kill/retry, resumed-child or job route.
        if let Err(error) = unsafe { TerminateProcess(process.0, ERROR_CANCELLED.0) }
            && !matches!(self.exit(), Ok(Some(_)))
        {
            self.cleanup_failure.get_or_insert(native(8, error));
        }
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        if !self.closing {
            self.fail(Error::Cancelled);
        }
        if self.first_failure.is_some() {
            self.request_pre_resume_termination();
        }
        if self.unknown_launch {
            return Err(Error::LaunchUnconfirmed);
        }
        if self.created && self.exit_observed.is_none() {
            let Some(code) = self.exit()? else {
                return Ok(false);
            };
            self.exit_observed = Some(code);
            if code != 0 {
                self.first_failure
                    .get_or_insert(Error::HelperExited { exit_code: code });
            }
        }
        if !self.thread_restored || (self.desktop.is_some() && self.old_thread_desktop.is_none()) {
            return Err(Error::CleanupUnconfirmed);
        }
        drop(self.thread.take());
        drop(self.process.take());
        if let Some(desktop) = self.desktop {
            claim_desktop_close(&mut self.desktop_close_attempted)
                .map_err(|error| self.cleanup_failure.unwrap_or(error))?;
            // SAFETY: owned bootstrap/open reference, original thread assignment
            // already restored and actual child exit observed. Never borrowed.
            if let Err(error) = unsafe { CloseDesktop(desktop) } {
                let error = native(10, error);
                self.cleanup_failure.get_or_insert(error);
                UNHEALTHY.store(true, Ordering::Release);
                return Err(error);
            }
            self.desktop = None;
        }
        cleanup_state()?;
        if let Some(error) = self.cleanup_failure {
            return Err(error);
        }
        self.drained = true;
        Ok(true)
    }
}
impl Drop for HelperRendererLaunch {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && !inner.drained
        {
            inner.fail(Error::Cancelled);
            inner.request_pre_resume_termination();
            if !matches!(inner.drain(), Ok(true)) {
                UNHEALTHY.store(true, Ordering::Release);
                mem::forget(inner);
            }
        }
    }
}
fn attributes(descriptor: &SecurityDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    }
}
fn environment(cutoff: u64) -> Result<Vec<u16>, Error> {
    native_renderer::check_cutoff(cutoff).map_err(mapped)?;
    let mut windows = [0_u16; 1024];
    let mut system = [0_u16; 1024];
    // SAFETY: fixed OS directory APIs and owned bounded UTF-16 buffers.
    let a = unsafe { GetWindowsDirectoryW(Some(&mut windows)) } as usize;
    let b = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    if a == 0 || b == 0 || a >= windows.len() || b >= system.len() {
        return Err(native(3, WinError::from_thread()));
    }
    let windows = String::from_utf16(&windows[..a]).map_err(|_| Error::Protocol)?;
    let system = String::from_utf16(&system[..b]).map_err(|_| Error::Protocol)?;
    if windows.contains('\0') || system.contains('\0') {
        return Err(Error::Protocol);
    }
    Ok(format!(
        "PATH={system}\0SystemRoot={windows}\0{}={cutoff:016x}\0WINDIR={windows}\0\0",
        native_renderer::CUTOFF_ENV
    )
    .encode_utf16()
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_created_never_resume_attempted_child_can_enter_one_termination_call() {
        let mut initial = ResumeState::default();
        assert!(!initial.claim_termination(false));
        assert!(initial.claim_termination(true));
        assert!(!initial.claim_termination(true));
        assert!(initial.claim_resume().is_err());
        let mut resumed = ResumeState::default();
        resumed.claim_resume().unwrap();
        assert!(!resumed.claim_termination(true));
        assert!(resumed.claim_resume().is_err());
        // A failed/uncertain OS resume leaves the same attempted latch set.
        assert!(!resumed.claim_termination(true));
    }
    #[test]
    fn uncertain_desktop_close_never_reenters_native_close_from_drain_or_drop() {
        let mut attempted = false;
        let mut calls = 0;
        claim_desktop_close(&mut attempted).unwrap();
        calls += 1;
        // Synthetic native close failed. The original raw owner must be retained.
        assert_eq!(
            claim_desktop_close(&mut attempted),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(
            claim_desktop_close(&mut attempted),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(calls, 1);
    }
}
