// SPDX-License-Identifier: GPL-2.0-or-later
//! One invisible, empty, noninteractive witness on the original renderer
//! thread. Kept through CloseAck until actual service EOF, not tied to visible UI.
use super::renderer_ui::Error;
use std::{
    marker::PhantomData,
    mem,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Threading::{GetCurrentProcessId, GetCurrentThreadId},
        },
        UI::{
            Input::KeyboardAndMouse::IsWindowEnabled,
            WindowsAndMessaging::{
                CreateWindowExW, DefWindowProcW, DestroyWindow, GetWindowThreadProcessId, IsWindow,
                IsWindowVisible, MSG, PM_NOREMOVE, PeekMessageW, RegisterClassExW,
                UnregisterClassW, WINDOW_EX_STYLE, WM_CLOSE, WM_ENABLE, WM_NCDESTROY, WM_SETTEXT,
                WM_SHOWWINDOW, WM_SYSCOMMAND, WM_USER, WNDCLASSEXW, WS_DISABLED, WS_POPUP,
            },
        },
    },
    core::{Error as WinError, PCWSTR},
};

pub(in crate::ffi) const CLASS_NAME: &str = "UacRemoteControllerPairingWitness";
static CLAIMED: AtomicBool = AtomicBool::new(false);
static FAILED: AtomicBool = AtomicBool::new(false);
static CLOSING: AtomicBool = AtomicBool::new(false);
static DESTROYED: AtomicBool = AtomicBool::new(false);

pub(super) struct Witness {
    hwnd: HWND,
    instance: HINSTANCE,
    atom: u16,
    thread: u32,
    closed: bool,
    close_attempted: bool,
    _thread_bound: PhantomData<Rc<()>>,
}
impl Witness {
    pub(super) fn create() -> Result<Self, Error> {
        if CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::InvalidState);
        }
        // SAFETY: original current thread and current module only; no foreign
        // process, arbitrary module, window, payload pointer or path argument.
        let instance = HINSTANCE(unsafe { GetModuleHandleW(None)? }.0);
        let thread = unsafe { GetCurrentThreadId() };
        let name: Vec<u16> = CLASS_NAME.encode_utf16().chain([0]).collect();
        let class = WNDCLASSEXW {
            cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(procedure),
            hInstance: instance,
            lpszClassName: PCWSTR(name.as_ptr()),
            ..Default::default()
        };
        let atom = unsafe { RegisterClassExW(&class) };
        if atom == 0 {
            return Err(WinError::from_thread().into());
        }
        let mut owner = Self {
            hwnd: HWND::default(),
            instance,
            atom,
            thread,
            closed: false,
            close_attempted: false,
            _thread_bound: PhantomData,
        };
        // SAFETY: fixed process-local class, empty caption, disabled invisible
        // top-level window on the already verified private thread desktop. No
        // user-data pointer, parent, menu, timer, show or input-desktop switch.
        owner.hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(name.as_ptr()),
                windows::core::w!(""),
                WS_POPUP | WS_DISABLED,
                0,
                0,
                1,
                1,
                None,
                None,
                Some(instance),
                None,
            )?
        };
        owner.check()?;
        Ok(owner)
    }
    pub(super) fn raw(&self) -> Result<u64, Error> {
        self.check()?;
        Ok(self.hwnd.0 as usize as u64)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.closed
            || FAILED.load(Ordering::Acquire)
            || DESTROYED.load(Ordering::Acquire)
            || unsafe { GetCurrentThreadId() } != self.thread
        {
            return Err(Error::InvalidState);
        }
        let mut process = 0;
        if FAILED.load(Ordering::Acquire)
            || DESTROYED.load(Ordering::Acquire)
            || !unsafe { IsWindow(Some(self.hwnd)) }.as_bool()
            || unsafe { IsWindowVisible(self.hwnd) }.as_bool()
            || unsafe { IsWindowEnabled(self.hwnd) }.as_bool()
            || unsafe { GetWindowThreadProcessId(self.hwnd, Some(&mut process)) } != self.thread
            || process != unsafe { GetCurrentProcessId() }
        {
            FAILED.store(true, Ordering::Release);
            return Err(Error::InvalidState);
        }
        Ok(())
    }
    pub(super) fn pump(&mut self) -> Result<(), Error> {
        self.check()?;
        // Called only when the visible UI owner is absent. Avoid dispatching
        // arbitrary UI callbacks through a shared &Owner/budget observation.
        // This class has no Rust user-data pointer; sent notifications only
        // update the process-local atomic latches. Queued input is retained.
        let mut message = MSG::default();
        let _ = unsafe { PeekMessageW(&mut message, None, WM_USER, WM_USER, PM_NOREMOVE) };
        self.check()
    }
    pub(super) fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        if self.close_attempted {
            return Err(Error::InvalidState);
        }
        if unsafe { GetCurrentThreadId() } != self.thread {
            return Err(Error::InvalidState);
        }
        self.close_attempted = true;
        let mut failure = None;
        CLOSING.store(true, Ordering::Release);
        if !self.hwnd.0.is_null() {
            // SAFETY: exact window created on this thread, after service EOF on
            // normal completion. No foreign HWND or thread termination occurs.
            if let Err(error) = unsafe { DestroyWindow(self.hwnd) } {
                failure = Some(Error::Native(error));
            } else {
                self.hwnd = HWND::default();
            }
        }
        if self.hwnd.0.is_null() && self.atom != 0 {
            let name: Vec<u16> = CLASS_NAME.encode_utf16().chain([0]).collect();
            if let Err(error) =
                unsafe { UnregisterClassW(PCWSTR(name.as_ptr()), Some(self.instance)) }
            {
                failure = Some(Error::Native(error));
            } else {
                self.atom = 0;
            }
        }
        self.closed = self.hwnd.0.is_null() && self.atom == 0;
        if let Some(error) = failure {
            return Err(error);
        }
        if FAILED.load(Ordering::Acquire) {
            return Err(Error::InvalidState);
        }
        Ok(())
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        if self.close().is_err() {
            FAILED.store(true, Ordering::Release);
        }
    }
}
unsafe extern "system" fn procedure(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // No pointer from any message is dereferenced and no message is a decision,
    // display instruction or recreation request. Destruction/visibility latch.
    match message {
        WM_CLOSE | WM_SETTEXT | WM_SYSCOMMAND => return LRESULT(0),
        WM_SHOWWINDOW | WM_ENABLE if wparam.0 != 0 => {
            FAILED.store(true, Ordering::Release);
            return LRESULT(0);
        }
        WM_NCDESTROY => {
            DESTROYED.store(true, Ordering::Release);
            if !CLOSING.load(Ordering::Acquire) {
                FAILED.store(true, Ordering::Release);
            }
        }
        _ => (),
    }
    // SAFETY: remaining messages use Windows' default procedure; no callbacks
    // into a dropped Rust object or caller-provided pointer are installed.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}
