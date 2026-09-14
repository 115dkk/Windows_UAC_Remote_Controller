// SPDX-License-Identifier: GPL-2.0-or-later
//! Native checks run by the fixed service-created SYSTEM child in WinSta0.
//! The Session0 parent independently retains the original renderer identity and
//! all policy/image/token checks; this owner retains the actual USER objects.
use super::*;
use windows::Win32::{
    Foundation::{ERROR_INVALID_DATA, HWND, LPARAM, SetLastError},
    System::{
        StationsAndDesktops::{EnumDesktopWindows, GetThreadDesktop, SetThreadDesktop},
        Threading::GetCurrentThreadId,
    },
    UI::{
        Input::KeyboardAndMouse::IsWindowEnabled,
        WindowsAndMessaging::{GetClassNameW, GetWindowThreadProcessId, IsWindow, IsWindowVisible},
    },
};
use windows::core::BOOL;
use windows_prompt_probe::pairing_inspection::{Binding, Failure, Inspector};

#[derive(Default)]
pub(in crate::ffi) struct NativeInspector {
    bound: Option<Bound>,
    claimed: bool,
    failed: bool,
}
struct Bound {
    binding: Binding,
    process: Handle,
    thread: Handle,
    token: TokenFacts,
    session: SessionEpoch,
    desktop: Option<UserObject>,
    opened_desktop: Option<UserObject>,
    station: Option<UserObject>,
    sid: Vec<u8>,
    invocation: RendererInvocation,
    inspector_thread: u32,
    original_desktop: Option<HDESK>,
    restoration_required: bool,
    restoration_attempted: bool,
}
fn failure(error: Error) -> Failure {
    match error {
        Error::Service(ServiceError::RendererNative { stage, hresult }) => {
            Failure { stage, hresult }
        }
        Error::Native { hresult, .. } => Failure { stage: 23, hresult },
        _ => Failure {
            stage: 23,
            hresult: 0x8007_000d_u32 as i32,
        },
    }
}
fn object_stage(stage: u8, error: Error) -> Error {
    match error {
        Error::Service(ServiceError::RendererNative { stage: 2, hresult }) => {
            Error::Service(ServiceError::RendererNative { stage, hresult })
        }
        _ => error,
    }
}
impl Inspector for NativeInspector {
    fn bind(&mut self, binding: Binding) -> Result<(), Failure> {
        let result = (|| {
            if self.claimed {
                return Err(Error::InvalidPhase);
            }
            self.claimed = true;
            check_cutoff(binding.cutoff)?;
            let (own, station) = unsafe {
                // SAFETY: borrowed own process/station; not closed or changed.
                (
                    GetCurrentProcess(),
                    windows::Win32::System::StationsAndDesktops::GetProcessWindowStation(),
                )
            };
            let own = TokenFacts::observe(own)?;
            let session = SessionEpoch::observe(own.session)?;
            check_station(HANDLE(station.map_err(|e| native(24, e))?.0))
                .map_err(|error| object_stage(24, error))?;
            let invocation = RendererInvocation::new(
                crate::PendingElevationId::from_bytes(binding.pending).map_err(Error::Service)?,
                crate::PendingElevationId::from_bytes(binding.display).map_err(Error::Service)?,
            )
            .map_err(Error::Service)?;
            let sid = OwnServiceSid::lookup().map_err(Error::Service)?.bytes();
            // SAFETY: candidate supplied only by actual SCM SYSTEM parent on its
            // authenticated PID-bound channel, read/duplicate/synchronize only.
            let process = Handle::new(
                unsafe {
                    OpenProcess(
                        PROCESS_ACCESS_RIGHTS(PROCESS_RIGHTS),
                        false,
                        binding.process,
                    )
                }
                .map_err(|e| native(3, e))?,
                super::super::PairingPeerStage::QueryProcess,
            )?;
            let thread = Handle::new(
                unsafe { OpenThread(THREAD_ACCESS_RIGHTS(THREAD_RIGHTS), false, binding.thread) }
                    .map_err(|e| native(3, e))?,
                super::super::PairingPeerStage::QueryProcess,
            )?;
            let token = TokenFacts::observe(process.raw())?;
            require_owner(&token, session.id)?;
            self.bound = Some(Bound {
                binding,
                process,
                thread,
                token,
                session,
                desktop: None,
                opened_desktop: None,
                station: None,
                sid,
                invocation,
                inspector_thread: unsafe { GetCurrentThreadId() },
                original_desktop: None,
                restoration_required: false,
                restoration_attempted: false,
            });
            let bound = self.bound.as_mut().ok_or(Error::InvalidPhase)?;
            bound.identity()?;
            duplicate_object(
                bound.process.raw(),
                binding.desktop,
                DESKTOP_INSPECT,
                5,
                &mut bound.desktop,
            )
            .map_err(|error| object_stage(25, error))?;
            duplicate_object(
                bound.process.raw(),
                binding.station,
                STATION_INSPECT,
                21,
                &mut bound.station,
            )
            .map_err(|error| object_stage(26, error))?;
            // Independent read-only open in this process's actual WinSta0.
            // Equality with the retained duplicate proves station membership;
            // matching names alone never establish object identity.
            let desktop = bound.desktop.as_ref().ok_or(Error::InvalidPhase)?;
            if !matches!(desktop.kind, ObjectKind::Desktop)
                || object_text(desktop.raw, UOI_NAME)? != display_name(invocation)
            {
                return Err(Error::Rejected);
            }
            verify_descriptor(desktop.raw, Profile::Desktop, &bound.sid)?;
            let station = bound.station.as_ref().ok_or(Error::InvalidPhase)?;
            if !matches!(station.kind, ObjectKind::Station) {
                return Err(Error::Rejected);
            }
            check_station(station.raw).map_err(|error| object_stage(28, error))?;
            let name: Vec<u16> = format!("{}\0", display_name(invocation))
                .encode_utf16()
                .collect();
            bound.identity()?;
            // SAFETY: fixed generated name, same-session current WinSta0, exact
            // noninherited inspection mask. No desktop switch,
            // thread assignment, object creation, ACL or privilege mutation.
            let opened = unsafe {
                windows::Win32::System::StationsAndDesktops::OpenDesktopW(
                    windows::core::PCWSTR(name.as_ptr()),
                    windows::Win32::System::StationsAndDesktops::DESKTOP_CONTROL_FLAGS(0),
                    false,
                    DESKTOP_INSPECT,
                )
            }
            .map_err(|error| native(30, error))?;
            bound.opened_desktop = Some(UserObject {
                raw: HANDLE(opened.0),
                kind: ObjectKind::Desktop,
            });
            // Only the windowless SYSTEM inspector thread is associated. This
            // does not show a window or change the user's input desktop.
            bound.attach_context()?;
            bound.check()
        })();
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(failure)
    }
    fn check(&mut self) -> Result<(), Failure> {
        let result = if self.failed {
            Err(Error::Rejected)
        } else {
            self.bound
                .as_ref()
                .ok_or(Error::InvalidPhase)
                .and_then(Bound::check)
        };
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(failure)
    }
    fn close(&mut self) -> Result<(), Failure> {
        if let Some(bound) = self.bound.as_mut() {
            // No liveness/deadline prerequisites during cleanup. Never close a
            // USER object while this inspector may still be attached to it.
            bound.restore_context().map_err(failure)?;
            for object in [
                &mut bound.desktop,
                &mut bound.opened_desktop,
                &mut bound.station,
            ]
            .into_iter()
            .flatten()
            {
                object.close().map_err(failure)?;
            }
        }
        self.bound = None;
        cleanup_state().map_err(failure)
    }
}
impl Bound {
    fn attach_context(&mut self) -> Result<(), Error> {
        self.identity()?;
        if self.original_desktop.is_some()
            || self.restoration_required
            || unsafe { GetCurrentThreadId() } != self.inspector_thread
        {
            return Err(Error::InvalidPhase);
        }
        let desktop = self.desktop.as_ref().ok_or(Error::InvalidPhase)?.raw;
        let opened = self.opened_desktop.as_ref().ok_or(Error::InvalidPhase)?.raw;
        if !unsafe { CompareObjectHandles(desktop, opened) }.as_bool() {
            return Err(Error::Rejected);
        }
        let original =
            unsafe { GetThreadDesktop(self.inspector_thread) }.map_err(|e| native(33, e))?;
        if !object_text(HANDLE(original.0), UOI_NAME)?.eq_ignore_ascii_case("Default") {
            return Err(Error::Rejected);
        }
        self.original_desktop = Some(original); // borrowed, never closed
        self.restoration_required = true; // set BEFORE even a failed attachment
        // SAFETY: exact independently verified same-session WinSta0 object;
        // current owned inspector thread has no windows/hooks or message pump.
        unsafe { SetThreadDesktop(HDESK(opened.0)) }.map_err(|e| native(33, e))?;
        self.check_context()
    }
    fn check_context(&self) -> Result<(), Error> {
        if !self.restoration_required
            || self.restoration_attempted
            || unsafe { GetCurrentThreadId() } != self.inspector_thread
        {
            return Err(Error::InvalidPhase);
        }
        // This is a SELF association query, not the incompatible foreign-TID
        // operation. It proves the metadata reads run in the intended context.
        let actual =
            unsafe { GetThreadDesktop(self.inspector_thread) }.map_err(|e| native(33, e))?;
        let opened = self.opened_desktop.as_ref().ok_or(Error::InvalidPhase)?.raw;
        if !unsafe { CompareObjectHandles(HANDLE(actual.0), opened) }.as_bool() {
            return Err(Error::Rejected);
        }
        Ok(())
    }
    fn restore_context(&mut self) -> Result<(), Error> {
        if !self.restoration_required {
            return Ok(());
        }
        if self.restoration_attempted || unsafe { GetCurrentThreadId() } != self.inspector_thread {
            return Err(Error::CleanupUnconfirmed);
        }
        self.restoration_attempted = true;
        let original = self.original_desktop.ok_or(Error::CleanupUnconfirmed)?;
        // SAFETY: restore only this same windowless thread's saved original
        // borrowed association. Failure is latched; no retry or USER close.
        unsafe { SetThreadDesktop(original) }.map_err(|e| native(33, e))?;
        let actual =
            unsafe { GetThreadDesktop(self.inspector_thread) }.map_err(|e| native(33, e))?;
        if !unsafe { CompareObjectHandles(HANDLE(actual.0), HANDLE(original.0)) }.as_bool() {
            return Err(Error::CleanupUnconfirmed);
        }
        self.restoration_required = false;
        Ok(())
    }
    fn identity(&self) -> Result<(), Error> {
        check_cutoff(self.binding.cutoff)?;
        if self.restoration_required {
            self.check_context()?;
        }
        if process_identity(self.process.raw(), self.binding.process)? != self.binding.created
            || thread_creation(self.thread.raw())? != self.binding.thread_created
            || unsafe { WaitForSingleObject(self.thread.raw(), 0) } != WAIT_TIMEOUT
            // SAFETY: exact retained initial-thread query handle.
            || unsafe { GetProcessIdOfThread(self.thread.raw()) } != self.binding.process
            || TokenFacts::observe(self.process.raw())? != self.token
            || SessionEpoch::observe(self.session.id)? != self.session
        {
            return Err(Error::Rejected);
        }
        require_owner(&self.token, self.session.id)?;
        verify_descriptor(self.process.raw(), Profile::Process, &self.sid)?;
        verify_descriptor(self.thread.raw(), Profile::Thread, &self.sid)?;
        cleanup_state()
    }
    fn check(&self) -> Result<(), Error> {
        self.identity()?;
        let desktop = self.desktop.as_ref().ok_or(Error::InvalidPhase)?;
        let opened = self.opened_desktop.as_ref().ok_or(Error::InvalidPhase)?;
        let station = self.station.as_ref().ok_or(Error::InvalidPhase)?;
        if !matches!(desktop.kind, ObjectKind::Desktop)
            || !matches!(station.kind, ObjectKind::Station)
            || object_text(desktop.raw, UOI_NAME).map_err(|error| object_stage(27, error))?
                != display_name(self.invocation)
        {
            return Err(Error::Rejected);
        }
        verify_descriptor(desktop.raw, Profile::Desktop, &self.sid)?;
        // SAFETY: both owned live desktop handles, acquired independently by
        // duplicate and explicit USER open. Never accept merely matching names.
        if !unsafe { CompareObjectHandles(opened.raw, desktop.raw) }.as_bool() {
            return Err(Error::Rejected);
        }
        check_station(station.raw).map_err(|error| object_stage(28, error))?;
        self.window_membership(desktop.raw)?;
        self.identity()
    }

    fn window_owner(&self, window: HWND) -> Result<(), Error> {
        let mut process = 0;
        // SAFETY: a candidate only, queried rather than dereferenced. Kernel
        // owner facts must match the retained live original process and thread.
        if !unsafe { IsWindow(Some(window)) }.as_bool()
            || unsafe { IsWindowVisible(window) }.as_bool()
            || unsafe { IsWindowEnabled(window) }.as_bool()
            || unsafe { GetWindowThreadProcessId(window, Some(&mut process)) }
                != self.binding.thread
            || process != self.binding.process
        {
            return Err(Error::Rejected);
        }
        let mut class = [0_u16; 64];
        let length = unsafe { GetClassNameW(window, &mut class) };
        if length <= 0 || length as usize >= class.len() {
            return Err(native(32, WinError::from_thread()));
        }
        if String::from_utf16(&class[..length as usize]).map_err(|_| Error::Malformed)?
            != crate::ffi::pairing_client::renderer_witness::CLASS_NAME
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }
    fn window_membership(&self, desktop: HANDLE) -> Result<(), Error> {
        let value = usize::try_from(self.binding.window).map_err(|_| Error::Malformed)?;
        if value == 0 || value == usize::MAX {
            return Err(Error::Malformed);
        }
        let window = HWND(value as *mut _);
        self.window_owner(window)?;
        let mut scan = Scan {
            window,
            process: self.binding.process,
            thread: self.binding.thread,
            count: 0,
            seen: false,
            failed: false,
        };
        // SAFETY: retained independently verified desktop, fixed synchronous
        // callback, stack context lives for the COMPLETE enumeration. The
        // callback never allocates, panics, pumps messages or retains pointers.
        unsafe {
            EnumDesktopWindows(
                Some(HDESK(desktop.0)),
                Some(visit_window),
                LPARAM(ptr::from_mut(&mut scan) as isize),
            )
        }
        .map_err(|error| native(32, error))?;
        if scan.failed || !scan.seen {
            return Err(Error::Rejected);
        }
        self.window_owner(window)
    }
}

struct Scan {
    window: HWND,
    process: u32,
    thread: u32,
    count: usize,
    seen: bool,
    failed: bool,
}
unsafe extern "system" fn visit_window(window: HWND, parameter: LPARAM) -> BOOL {
    if parameter.0 == 0 {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return false.into();
    }
    // SAFETY: only window_membership passes its exclusive live stack context.
    let scan = unsafe { &mut *(parameter.0 as *mut Scan) };
    if scan.count >= 512 {
        scan.failed = true;
    } else {
        scan.count += 1;
        if window == scan.window {
            let mut process = 0;
            let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut process)) };
            if scan.seen || process != scan.process || thread != scan.thread {
                scan.failed = true;
            }
            scan.seen = true;
        }
    }
    if scan.failed {
        unsafe { SetLastError(ERROR_INVALID_DATA) };
        return false.into();
    }
    true.into()
}
impl Drop for NativeInspector {
    fn drop(&mut self) {
        if self.close().is_err()
            && let Some(bound) = self.bound.take()
        {
            BOUNDARY_HEALTH.quarantine();
            mem::forget(bound);
        }
    }
}
