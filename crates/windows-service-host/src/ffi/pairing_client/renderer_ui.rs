// SPDX-License-Identifier: GPL-2.0-or-later
//! Protected pairing presentation on the renderer's initial private desktop.
//!
//! The owner is confined to the creating thread. Its HWND user-data pointer is
//! valid only from WM_NCCREATE until it is cleared before DestroyWindow. GDI and
//! desktop handles are owned here and released once. The UI collects only fixed
//! button and keyboard decisions. It never reads text, the clipboard or input
//! hooks, and it creates no process, network connection, key or pairing grant.
#![allow(unsafe_code)]

use presentation_i18n::{Locale, tr};
use qrcode::{Color, QrCode};
use std::{fmt, mem, ptr, time::Instant};
use windows::{
    Win32::{
        Foundation::{COLORREF, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::{
            AddFontMemResourceEx, BeginPaint, BitBlt, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS,
            CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreateSolidBrush,
            DEFAULT_CHARSET, DT_CENTER, DT_NOPREFIX, DT_RTLREADING, DT_SINGLELINE, DT_VCENTER,
            DT_WORDBREAK, DeleteDC, DeleteObject, DrawTextW, EndPaint, FF_DONTCARE, FW_BOLD,
            FW_NORMAL, FillRect, HBRUSH, HDC, HFONT, HGDIOBJ, InvalidateRect, OUT_DEFAULT_PRECIS,
            PAINTSTRUCT, RemoveFontMemResourceEx, SRCCOPY, SelectObject, SetBkMode, SetTextColor,
            TRANSPARENT,
        },
        System::{
            LibraryLoader::GetModuleHandleW,
            StationsAndDesktops::{
                CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_SWITCHDESKTOP, GetThreadDesktop,
                HDESK, OpenInputDesktop, SwitchDesktop,
            },
            Threading::GetCurrentThreadId,
        },
        UI::{
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::{VK_ESCAPE, VK_RETURN},
            WindowsAndMessaging::{
                BN_CLICKED, BS_DEFPUSHBUTTON, BS_MULTILINE, BS_PUSHBUTTON, CREATESTRUCTW,
                CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow,
                DispatchMessageW, GWLP_USERDATA, GetClientRect, GetSystemMetrics, HMENU, KillTimer,
                MSG, PM_REMOVE, PeekMessageW, RegisterClassExW, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW,
                SendMessageW, SetTimer, SetWindowLongPtrW, ShowWindow, TranslateMessage,
                UnregisterClassW, WINDOW_EX_STYLE, WM_COMMAND, WM_ERASEBKGND, WM_KEYDOWN,
                WM_NCCREATE, WM_PAINT, WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_CHILD,
                WS_EX_RTLREADING, WS_POPUP, WS_VISIBLE,
            },
        },
    },
    core::{Error as WinError, PCWSTR},
};

const CLASS_NAME: &str = "UacRemoteControllerPairingRenderer";
const CONFIRM_ID: usize = 1001;
const CANCEL_ID: usize = 1002;
const TIMER_ID: usize = 1;
const TIMER_MS: u32 = 1000;
const QUIET_MODULES: usize = 4;

#[derive(Debug)]
pub(super) enum Error {
    Native(#[allow(dead_code)] WinError),
    InvalidState,
    Qr,
}
impl From<WinError> for Error {
    fn from(value: WinError) -> Self {
        Self::Native(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UiEvent {
    Confirmed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Invitation,
    Comparison,
    Outcome(bool),
    Expired,
}

pub(super) struct RendererWindow {
    owner: Box<WindowOwner>,
}

struct WindowOwner {
    hwnd: HWND,
    confirm: HWND,
    cancel: HWND,
    original_desktop: Option<HDESK>,
    class_atom: u16,
    instance: HINSTANCE,
    title_font: HFONT,
    body_font: HFONT,
    code_font: HFONT,
    font_resources: Vec<HANDLE>,
    locale: Locale,
    background: HBRUSH,
    surface: HBRUSH,
    border: HBRUSH,
    modules: Vec<bool>,
    module_width: usize,
    deadline: Instant,
    remaining_second: u64,
    screen: Screen,
    code: String,
    event: Option<UiEvent>,
    paint_failed: bool,
    closed: bool,
}
impl fmt::Debug for RendererWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RendererWindow(redacted)")
    }
}

impl WindowOwner {
    fn copy(&self, source: &'static str) -> &'static str {
        tr(self.locale, source)
    }

    fn window_direction(&self) -> WINDOW_EX_STYLE {
        // Do not use WS_EX_LAYOUTRTL: it would also mirror QR pixel geometry.
        if self.locale.is_rtl() {
            WS_EX_RTLREADING
        } else {
            WINDOW_EX_STYLE(0)
        }
    }

    fn text_direction(&self) -> windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT {
        if self.locale.is_rtl() {
            DT_RTLREADING
        } else {
            windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(0)
        }
    }

    fn remaining_copy(&self) -> String {
        // Only these fixed formatting placeholders are replaced; translated
        // text is not a format string. Trusted LTR embedding keeps mm:ss ordered.
        let minutes = format!("{:02}", self.remaining_second / 60);
        let seconds = format!("{:02}", self.remaining_second % 60);
        let time = format!("\u{202a}{minutes}:{seconds}\u{202c}");
        self.copy("남은 시간 {:02}:{:02}")
            .replace("{:02}:{:02}", &time)
    }

    fn register_fonts(&mut self) -> Result<(), Error> {
        let mut files = Vec::from(font_bytes(Locale::En));
        if font_face(self.locale) != "UAC Sans" {
            files.extend(font_bytes(self.locale));
        }
        for bytes in files {
            let length = u32::try_from(bytes.len()).map_err(|_| Error::InvalidState)?;
            let mut count = 0_u32;
            // SAFETY: immutable compile-time font bytes remain live for the
            // process; exact length and initialized output, no caller font/path.
            let resource = unsafe {
                AddFontMemResourceEx(bytes.as_ptr().cast(), length, None, &raw mut count)
            };
            if resource.is_invalid() {
                return Err(WinError::from_thread().into());
            }
            self.font_resources.push(resource); // Adopt before validating count.
            if count == 0 {
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }

    fn create(text: &str, deadline: Instant) -> Result<RendererWindow, Error> {
        if Instant::now() >= deadline {
            return Err(Error::InvalidState);
        }
        let (modules, module_width) = qr_modules(text)?;
        // SAFETY: current process module and current thread's already assigned desktop only.
        let module = unsafe { GetModuleHandleW(None)? };
        let instance = HINSTANCE(module.0);
        let class_name = wide(CLASS_NAME);
        let class = WNDCLASSEXW {
            cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        // SAFETY: fixed process-local class with a static window procedure.
        let class_atom = unsafe { RegisterClassExW(&class) };
        if class_atom == 0 {
            return Err(WinError::from_thread().into());
        }
        let mut owner = Box::new(Self {
            hwnd: HWND::default(),
            confirm: HWND::default(),
            cancel: HWND::default(),
            original_desktop: None,
            class_atom,
            instance,
            title_font: HFONT::default(),
            body_font: HFONT::default(),
            code_font: HFONT::default(),
            font_resources: Vec::new(),
            // Cosmetic current-account preference only. The helper's admitted
            // account can differ from the starter's for alternate-admin UAC;
            // never inspect another user's hive or add a locale IPC argument.
            locale: crate::get_language_settings()
                .map(|settings| settings.effective_locale())
                .unwrap_or(Locale::En),
            background: HBRUSH::default(),
            surface: HBRUSH::default(),
            border: HBRUSH::default(),
            modules,
            module_width,
            deadline,
            remaining_second: remaining_seconds(deadline),
            screen: Screen::Invitation,
            code: String::new(),
            event: None,
            paint_failed: false,
            closed: false,
        });
        if let Err(error) = owner.create_native() {
            return match owner.close() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
        Ok(RendererWindow { owner })
    }

    fn create_native(&mut self) -> Result<(), Error> {
        // SAFETY: input desktop is opened for switch-only ownership and retained until close.
        self.original_desktop = Some(unsafe {
            OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_SWITCHDESKTOP)?
        });
        // SAFETY: screen metric reads have no caller-owned pointers.
        let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        // SAFETY: screen metric reads have no caller-owned pointers.
        let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        if width <= 0 || height <= 0 {
            return Err(Error::InvalidState);
        }
        let class_name = wide(CLASS_NAME);
        let caption = wide(self.copy("UAC 원격 승인"));
        // SAFETY: this Box remains pinned until creation returns; WM_NCCREATE stores
        // its pointer in GWLP_USERDATA. The pointer is cleared before destruction.
        self.hwnd = unsafe {
            CreateWindowExW(
                self.window_direction(),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(caption.as_ptr()),
                WS_POPUP | WS_VISIBLE,
                0,
                0,
                width,
                height,
                None,
                None,
                Some(self.instance),
                Some(ptr::from_mut(self).cast()),
            )?
        };
        // SAFETY: the newly created owned top-level window remains live.
        let dpi = unsafe { GetDpiForWindow(self.hwnd) }.max(96);
        self.register_fonts()?;
        self.title_font = font(dpi, 20, FW_BOLD.0 as i32, font_face(self.locale))?;
        self.body_font = font(dpi, 14, FW_NORMAL.0 as i32, font_face(self.locale))?;
        // Comparison digits are immutable ASCII and always use the Latin face.
        self.code_font = font(dpi, 40, FW_BOLD.0 as i32, "UAC Sans")?;
        self.background = brush(0xf2f6f7)?;
        self.surface = brush(0xffffff)?;
        self.border = brush(0xd7e3e7)?;
        // SAFETY: current thread desktop is the launcher-assigned private desktop.
        let private = unsafe { GetThreadDesktop(GetCurrentThreadId())? };
        // SAFETY: window exists on private before it becomes the input desktop.
        unsafe { SwitchDesktop(private)? };
        // SAFETY: valid visible top-level window and owner timer.
        unsafe {
            let _previously_visible = ShowWindow(self.hwnd, SW_SHOW);
            if SetTimer(Some(self.hwnd), TIMER_ID, TIMER_MS, None) == 0 {
                return Err(WinError::from_thread().into());
            }
        }
        self.repaint()
    }

    pub(super) fn show_comparison(&mut self, code: &str) -> Result<(), Error> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::InvalidState);
        }
        self.code = format!("{} {}", &code[..3], &code[3..]);
        self.screen = Screen::Comparison;
        self.ensure_buttons()?;
        self.repaint()
    }

    pub(super) fn show_outcome(&mut self, enrolled: bool) -> Result<(), Error> {
        self.screen = Screen::Outcome(enrolled);
        self.hide_buttons()?;
        self.repaint()
    }

    pub(super) fn show_expired(&mut self) -> Result<(), Error> {
        self.screen = Screen::Expired;
        self.hide_buttons()?;
        self.repaint()
    }

    /// Pumps pending messages and returns at most one recorded decision.
    fn pump(&mut self) -> Result<Option<UiEvent>, Error> {
        if self.closed || self.hwnd.0.is_null() || self.paint_failed {
            return Err(Error::InvalidState);
        }
        let now_remaining = remaining_seconds(self.deadline);
        if now_remaining != self.remaining_second {
            self.remaining_second = now_remaining;
            self.repaint()?;
        }
        let mut message = MSG::default();
        // SAFETY: current-thread queue only; each removed message is translated and dispatched once.
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            if self.screen == Screen::Comparison && message.message == WM_KEYDOWN {
                if message.wParam.0 == usize::from(VK_RETURN.0) {
                    self.event = Some(UiEvent::Confirmed);
                    continue;
                }
                if message.wParam.0 == usize::from(VK_ESCAPE.0) {
                    self.event = Some(UiEvent::Cancelled);
                    continue;
                }
            }
            // SAFETY: this message was removed from the current thread queue once.
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if self.paint_failed {
            return Err(Error::InvalidState);
        }
        Ok(self.event.take())
    }

    fn ensure_buttons(&mut self) -> Result<(), Error> {
        if !self.confirm.0.is_null() {
            return Ok(());
        }
        let button = wide("BUTTON");
        let confirm = wide(self.copy("숫자가 같아요"));
        let cancel = wide(self.copy("다릅니다, 취소"));
        // SAFETY: fixed standard child controls parented to the owned top-level window.
        unsafe {
            self.confirm = CreateWindowExW(
                self.window_direction(),
                PCWSTR(button.as_ptr()),
                PCWSTR(confirm.as_ptr()),
                WS_CHILD
                    | WS_VISIBLE
                    | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(
                        (BS_DEFPUSHBUTTON | BS_MULTILINE) as u32,
                    ),
                0,
                0,
                1,
                1,
                Some(self.hwnd),
                Some(HMENU(CONFIRM_ID as *mut _)),
                Some(self.instance),
                None,
            )?;
            self.cancel = CreateWindowExW(
                self.window_direction(),
                PCWSTR(button.as_ptr()),
                PCWSTR(cancel.as_ptr()),
                WS_CHILD
                    | WS_VISIBLE
                    | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(
                        (BS_PUSHBUTTON | BS_MULTILINE) as u32,
                    ),
                0,
                0,
                1,
                1,
                Some(self.hwnd),
                Some(HMENU(CANCEL_ID as *mut _)),
                Some(self.instance),
                None,
            )?;
            // Both fixed child controls borrow this owner's live font only;
            // windows are destroyed before the HFONT and memory-font resources.
            SendMessageW(
                self.confirm,
                WM_SETFONT,
                Some(WPARAM(self.body_font.0 as usize)),
                Some(LPARAM(1)),
            );
            SendMessageW(
                self.cancel,
                WM_SETFONT,
                Some(WPARAM(self.body_font.0 as usize)),
                Some(LPARAM(1)),
            );
        }
        self.layout_buttons()
    }

    fn layout_buttons(&self) -> Result<(), Error> {
        if self.confirm.0.is_null() {
            return Ok(());
        }
        let mut rect = RECT::default();
        // SAFETY: owned valid top-level and child windows.
        unsafe { GetClientRect(self.hwnd, &mut rect)? };
        // SAFETY: the owned top-level window remains live while controls are laid out.
        let dpi = unsafe { GetDpiForWindow(self.hwnd) }.max(96) as i32;
        let scale = |value: i32| value * dpi / 96;
        let button_width = scale(184);
        let button_height = scale(60);
        let gap = scale(16);
        let left = (rect.right - button_width * 2 - gap) / 2;
        let top = rect.bottom / 2 + scale(120);
        let (confirm_left, cancel_left) = if self.locale.is_rtl() {
            (left + button_width + gap, left)
        } else {
            (left, left + button_width + gap)
        };
        // SAFETY: both child controls and their parent remain live and thread-owned.
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::MoveWindow(
                self.confirm,
                confirm_left,
                top,
                button_width,
                button_height,
                true,
            )?;
            windows::Win32::UI::WindowsAndMessaging::MoveWindow(
                self.cancel,
                cancel_left,
                top,
                button_width,
                button_height,
                true,
            )?;
        }
        Ok(())
    }

    fn hide_buttons(&mut self) -> Result<(), Error> {
        let mut first = None;
        // SAFETY: child HWNDs are either null or owned live controls.
        unsafe {
            if !self.confirm.0.is_null() {
                if let Err(error) = DestroyWindow(self.confirm) {
                    first.get_or_insert(Error::Native(error));
                }
                self.confirm = HWND::default();
            }
            if !self.cancel.0.is_null() {
                if let Err(error) = DestroyWindow(self.cancel) {
                    first.get_or_insert(Error::Native(error));
                }
                self.cancel = HWND::default();
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn repaint(&self) -> Result<(), Error> {
        if !self.hwnd.0.is_null() {
            // SAFETY: owned live window; erase is false for double-buffered paint.
            unsafe {
                let _ = InvalidateRect(Some(self.hwnd), None, false);
            };
        }
        Ok(())
    }

    fn paint(&self) -> Result<(), Error> {
        let mut paint = PAINTSTRUCT::default();
        // SAFETY: balanced BeginPaint/EndPaint for the owned HWND.
        let target = unsafe { BeginPaint(self.hwnd, &mut paint) };
        let result = self.paint_to(target);
        // SAFETY: balances the successful BeginPaint using the same HWND and state.
        unsafe {
            let _ = EndPaint(self.hwnd, &paint);
        };
        result
    }

    fn paint_to(&self, target: HDC) -> Result<(), Error> {
        let mut client = RECT::default();
        // SAFETY: valid HWND and initialized output.
        unsafe { GetClientRect(self.hwnd, &mut client)? };
        let width = client.right.max(1);
        let height = client.bottom.max(1);
        // SAFETY: the paint HDC is live for this balanced paint operation.
        let memory = unsafe { CreateCompatibleDC(Some(target)) };
        if memory.0.is_null() {
            return Err(WinError::from_thread().into());
        }
        // SAFETY: target is the same live paint HDC and dimensions are positive.
        let bitmap = unsafe { CreateCompatibleBitmap(target, width, height) };
        if bitmap.0.is_null() {
            // SAFETY: the newly owned compatible DC has no selected owned bitmap.
            unsafe {
                let _ = DeleteDC(memory);
            };
            return Err(WinError::from_thread().into());
        }
        // SAFETY: memory and bitmap are live compatible GDI objects.
        let old_bitmap = unsafe { SelectObject(memory, HGDIOBJ(bitmap.0)) };
        let result = self.draw(memory, client).and_then(|()| {
            // SAFETY: both compatible DCs remain live and dimensions match the bitmap.
            unsafe {
                BitBlt(target, 0, 0, width, height, Some(memory), 0, 0, SRCCOPY)
                    .map_err(Error::from)
            }
        });
        // SAFETY: restore the prior bitmap before deleting the owned bitmap and DC.
        unsafe {
            SelectObject(memory, old_bitmap);
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
            let _ = DeleteDC(memory);
        }
        result
    }

    fn draw(&self, dc: HDC, client: RECT) -> Result<(), Error> {
        // SAFETY: the memory DC and owned brushes are live for this paint.
        unsafe {
            FillRect(dc, &client, self.background);
            SetBkMode(dc, TRANSPARENT);
        }
        // SAFETY: the owned top-level window remains live during painting.
        let dpi = unsafe { GetDpiForWindow(self.hwnd) }.max(96) as i32;
        let scale = |value: i32| value * dpi / 96;
        let card_width = (client.right * 72 / 100).min(scale(760));
        let card_height = (client.bottom * 82 / 100).min(scale(820));
        let left = (client.right - card_width) / 2;
        let top = (client.bottom - card_height) / 2;
        let border = RECT {
            left,
            top,
            right: left + card_width,
            bottom: top + card_height,
        };
        // SAFETY: the memory DC and owned border brush are live for this paint.
        unsafe { FillRect(dc, &border, self.border) };
        let surface = RECT {
            left: left + 1,
            top: top + 1,
            right: left + card_width - 1,
            bottom: top + card_height - 1,
        };
        // SAFETY: the memory DC and owned surface brush are live for this paint.
        unsafe { FillRect(dc, &surface, self.surface) };
        draw_text(
            dc,
            self.title_font,
            self.copy("UAC 원격 승인 · PC 연결"),
            RECT {
                left: left + scale(32),
                top: top + scale(26),
                right: left + card_width - scale(32),
                bottom: top + scale(92),
            },
            0x152c35,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        match self.screen {
            Screen::Invitation => {
                self.draw_invitation(dc, left, top, card_width, card_height, scale)?;
            }
            Screen::Comparison => self.draw_comparison(dc, left, top, card_width, scale),
            Screen::Outcome(enrolled) => self.draw_message(
                dc,
                left,
                top,
                card_width,
                if enrolled {
                    "휴대폰을 연결했어요."
                } else {
                    "휴대폰을 연결하지 못했어요. 다시 시도해 주세요."
                },
                scale,
            ),
            Screen::Expired => self.draw_message(
                dc,
                left,
                top,
                card_width,
                "확인 시간이 지났어요. PC에서 다시 시도해 주세요.",
                scale,
            ),
        }
        Ok(())
    }

    fn draw_invitation(
        &self,
        dc: HDC,
        left: i32,
        top: i32,
        card_width: i32,
        card_height: i32,
        scale: impl Fn(i32) -> i32,
    ) -> Result<(), Error> {
        draw_text(
            dc,
            self.body_font,
            self.copy("UAC 원격 승인 앱에서 [PC의 QR 코드 촬영]을 누르고 이 QR을 비춰 주세요."),
            RECT {
                left: left + scale(36),
                top: top + scale(100),
                right: left + card_width - scale(36),
                bottom: top + scale(176),
            },
            0x536971,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        // SAFETY: screen metric reads have no caller-owned pointers.
        let shorter = unsafe { GetSystemMetrics(SM_CXSCREEN).min(GetSystemMetrics(SM_CYSCREEN)) };
        let available_height = (card_height - scale(280)).max(1);
        let target = (shorter * 38 / 100).min(available_height);
        let module_px = (target / (self.module_width + QUIET_MODULES * 2) as i32).max(1);
        let total = module_px * (self.module_width + QUIET_MODULES * 2) as i32;
        let qr_left = left + (card_width - total) / 2;
        let qr_top = top + scale(190) + (available_height - total).max(0) / 2;
        let white = RECT {
            left: qr_left,
            top: qr_top,
            right: qr_left + total,
            bottom: qr_top + total,
        };
        // SAFETY: the memory DC and owned white surface brush are live.
        unsafe { FillRect(dc, &white, self.surface) };
        let dark = brush(0x152c35)?;
        for (index, module) in self.modules.iter().enumerate() {
            if !module {
                continue;
            }
            let x = index % self.module_width;
            let y = index / self.module_width;
            let rect = RECT {
                left: qr_left + (x + QUIET_MODULES) as i32 * module_px,
                top: qr_top + (y + QUIET_MODULES) as i32 * module_px,
                right: qr_left + (x + QUIET_MODULES + 1) as i32 * module_px,
                bottom: qr_top + (y + QUIET_MODULES + 1) as i32 * module_px,
            };
            // SAFETY: the memory DC and temporary QR brush are live.
            unsafe { FillRect(dc, &rect, dark) };
        }
        // SAFETY: the temporary QR brush is no longer selected or borrowed.
        unsafe {
            let _ = DeleteObject(HGDIOBJ(dark.0));
        };
        draw_text(
            dc,
            self.body_font,
            &self.remaining_copy(),
            RECT {
                left: left + scale(24),
                top: qr_top + total + scale(18),
                right: left + card_width - scale(24),
                bottom: qr_top + total + scale(52),
            },
            0x536971,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | self.text_direction(),
        );
        Ok(())
    }

    fn draw_comparison(
        &self,
        dc: HDC,
        left: i32,
        top: i32,
        card_width: i32,
        scale: impl Fn(i32) -> i32,
    ) {
        draw_text(
            dc,
            self.body_font,
            self.copy("휴대폰에 표시된 숫자와 같은지 확인해 주세요."),
            RECT {
                left: left + scale(36),
                top: top + scale(100),
                right: left + card_width - scale(36),
                bottom: top + scale(150),
            },
            0x536971,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        draw_text(
            dc,
            self.code_font,
            &self.code,
            RECT {
                left: left + scale(36),
                top: top + scale(170),
                right: left + card_width - scale(36),
                bottom: top + scale(260),
            },
            0x152c35,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
    }

    fn draw_message(
        &self,
        dc: HDC,
        left: i32,
        top: i32,
        card_width: i32,
        text: &str,
        scale: impl Fn(i32) -> i32,
    ) {
        draw_text(
            dc,
            self.title_font,
            tr(self.locale, text),
            RECT {
                left: left + scale(48),
                top: top + scale(170),
                right: left + card_width - scale(48),
                bottom: top + scale(300),
            },
            0x152c35,
            DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
    }

    /// Destroys the window and returns input to the original desktop. Idempotent.
    fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let mut first = None;
        if let Some(original) = self.original_desktop.take() {
            // SAFETY: retained switch-only input desktop owner, closed after switch attempt.
            unsafe {
                if let Err(error) = SwitchDesktop(original) {
                    first.get_or_insert(Error::Native(error));
                }
                if let Err(error) = CloseDesktop(original) {
                    first.get_or_insert(Error::Native(error));
                }
            }
        }
        if !self.hwnd.0.is_null() {
            // SAFETY: owned HWND. Clear the only raw owner pointer before destruction.
            unsafe {
                let _ = KillTimer(Some(self.hwnd), TIMER_ID);
                SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0);
                if let Err(error) = DestroyWindow(self.hwnd) {
                    first = Some(Error::Native(error));
                }
            }
            self.hwnd = HWND::default();
            self.confirm = HWND::default();
            self.cancel = HWND::default();
        }
        let mut objects_deleted = true;
        for object in [
            HGDIOBJ(self.title_font.0),
            HGDIOBJ(self.body_font.0),
            HGDIOBJ(self.code_font.0),
            HGDIOBJ(self.background.0),
            HGDIOBJ(self.surface.0),
            HGDIOBJ(self.border.0),
        ] {
            if !object.0.is_null() {
                // SAFETY: each uniquely owned GDI object is deleted once after the window.
                unsafe {
                    if !DeleteObject(object).as_bool() {
                        objects_deleted = false;
                        first.get_or_insert(Error::Native(WinError::from_thread()));
                    }
                }
            }
        }
        self.title_font = HFONT::default();
        self.body_font = HFONT::default();
        self.code_font = HFONT::default();
        // If HWND/GDI cleanup was uncertain, leave the private font resources
        // registered until process teardown rather than invalidating a borrower.
        let release_fonts = objects_deleted && first.is_none();
        for resource in self.font_resources.drain(..).filter(|_| release_fonts) {
            // SAFETY: successfully registered owned memory-font handle; every
            // window/HFONT borrowing it has been destroyed/deleted above.
            if !unsafe { RemoveFontMemResourceEx(resource) }.as_bool() {
                first.get_or_insert(Error::Native(WinError::from_thread()));
            }
        }
        self.background = HBRUSH::default();
        self.surface = HBRUSH::default();
        self.border = HBRUSH::default();
        if self.class_atom != 0 {
            let class = wide(CLASS_NAME);
            // SAFETY: this process-local fixed class has no remaining owned window.
            unsafe {
                if let Err(error) = UnregisterClassW(PCWSTR(class.as_ptr()), Some(self.instance)) {
                    first.get_or_insert(Error::Native(error));
                }
            }
            self.class_atom = 0;
        }
        first.map_or(Ok(()), Err)
    }
}

impl RendererWindow {
    /// Creates the window on the current thread desktop, then switches input to it.
    pub(super) fn show_invitation(text: &str, deadline: Instant) -> Result<Self, Error> {
        WindowOwner::create(text, deadline)
    }

    pub(super) fn show_comparison(&mut self, code: &str) -> Result<(), Error> {
        self.owner.show_comparison(code)
    }

    pub(super) fn show_outcome(&mut self, enrolled: bool) -> Result<(), Error> {
        self.owner.show_outcome(enrolled)
    }

    pub(super) fn show_expired(&mut self) -> Result<(), Error> {
        self.owner.show_expired()
    }

    /// Pumps pending messages and returns at most one recorded decision.
    pub(super) fn pump(&mut self) -> Result<Option<UiEvent>, Error> {
        self.owner.pump()
    }

    /// Destroys the window and returns input to the original desktop. Idempotent.
    pub(super) fn close(&mut self) -> Result<(), Error> {
        self.owner.close()
    }
}

impl Drop for RendererWindow {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: lparam is CREATESTRUCTW for WM_NCCREATE. lpCreateParams points
        // to the boxed owner supplied to CreateWindowExW and remains live.
        let create = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
        // SAFETY: hwnd is being created and receives only the supplied owner pointer.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize) };
    }
    // SAFETY: only our create parameter is stored, and close clears it first.
    let owner = unsafe {
        let value = windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        (!value.eq(&0)).then(|| &mut *(value as *mut WindowOwner))
    };
    match message {
        WM_ERASEBKGND => LRESULT(1),
        WM_PAINT => {
            if let Some(owner) = owner {
                if owner.paint().is_err() {
                    owner.paint_failed = true;
                }
                return LRESULT(0);
            }
            // SAFETY: forwards the untouched message parameters to the default procedure.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
        WM_TIMER => {
            if let Some(owner) = owner
                && owner.repaint().is_err()
            {
                owner.paint_failed = true;
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            if let Some(owner) = owner {
                let id = wparam.0 & 0xffff;
                let notification = (wparam.0 >> 16) as u32;
                if notification == BN_CLICKED && owner.screen == Screen::Comparison {
                    owner.event = match id {
                        CONFIRM_ID => Some(UiEvent::Confirmed),
                        CANCEL_ID => Some(UiEvent::Cancelled),
                        _ => owner.event,
                    };
                }
            }
            LRESULT(0)
        }
        WM_KEYDOWN => {
            if let Some(owner) = owner
                && owner.screen == Screen::Comparison
            {
                if wparam.0 == usize::from(VK_RETURN.0) {
                    owner.event = Some(UiEvent::Confirmed);
                } else if wparam.0 == usize::from(VK_ESCAPE.0) {
                    owner.event = Some(UiEvent::Cancelled);
                }
            }
            LRESULT(0)
        }
        // SAFETY: forwards each unhandled message unchanged to the default procedure.
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

fn color(value: u32) -> COLORREF {
    COLORREF(((value & 0xff) << 16) | (value & 0xff00) | ((value >> 16) & 0xff))
}

fn brush(value: u32) -> Result<HBRUSH, Error> {
    // SAFETY: CreateSolidBrush copies the COLORREF and returns an owned handle.
    let brush = unsafe { CreateSolidBrush(color(value)) };
    if brush.0.is_null() {
        Err(WinError::from_thread().into())
    } else {
        Ok(brush)
    }
}

fn font_face(locale: Locale) -> &'static str {
    match locale {
        Locale::Ko => "UAC Sans KR",
        Locale::Ja => "UAC Sans JP",
        Locale::ZhHans => "UAC Sans SC",
        Locale::ZhHant => "UAC Sans TC",
        Locale::Ar => "UAC Sans Arabic",
        _ => "UAC Sans",
    }
}

fn font_bytes(locale: Locale) -> [&'static [u8]; 2] {
    // Exact array lengths come from assets/fonts/native/manifest.json and are
    // checked by rustc against include_bytes!. The pinned analyzer models that
    // builtin with an inferred array length (upstream issue/PR22520); an unsized
    // slice leaves that length unconstrained even with an explicit slice type.
    // These are the same fixed compile-time inputs; no runtime path is accepted.
    static LATIN_REGULAR: &[u8; 646148] =
        include_bytes!("../../../../../assets/fonts/native/UACSans-Regular.ttf");
    static LATIN_BOLD: &[u8; 648272] =
        include_bytes!("../../../../../assets/fonts/native/UACSans-Bold.ttf");
    static KOREAN_REGULAR: &[u8; 2533808] =
        include_bytes!("../../../../../assets/fonts/native/UACSansKR-Regular.ttf");
    static KOREAN_BOLD: &[u8; 2478456] =
        include_bytes!("../../../../../assets/fonts/native/UACSansKR-Bold.ttf");
    static JAPANESE_REGULAR: &[u8; 5766888] =
        include_bytes!("../../../../../assets/fonts/native/UACSansJP-Regular.ttf");
    static JAPANESE_BOLD: &[u8; 5761684] =
        include_bytes!("../../../../../assets/fonts/native/UACSansJP-Bold.ttf");
    static SIMPLIFIED_REGULAR: &[u8; 10595936] =
        include_bytes!("../../../../../assets/fonts/native/UACSansSC-Regular.ttf");
    static SIMPLIFIED_BOLD: &[u8; 10585460] =
        include_bytes!("../../../../../assets/fonts/native/UACSansSC-Bold.ttf");
    static TRADITIONAL_REGULAR: &[u8; 7149184] =
        include_bytes!("../../../../../assets/fonts/native/UACSansTC-Regular.ttf");
    static TRADITIONAL_BOLD: &[u8; 7143712] =
        include_bytes!("../../../../../assets/fonts/native/UACSansTC-Bold.ttf");
    static ARABIC_REGULAR: &[u8; 194328] =
        include_bytes!("../../../../../assets/fonts/native/UACSansArabic-Regular.ttf");
    static ARABIC_BOLD: &[u8; 194512] =
        include_bytes!("../../../../../assets/fonts/native/UACSansArabic-Bold.ttf");
    match locale {
        Locale::Ko => [KOREAN_REGULAR, KOREAN_BOLD],
        Locale::Ja => [JAPANESE_REGULAR, JAPANESE_BOLD],
        Locale::ZhHans => [SIMPLIFIED_REGULAR, SIMPLIFIED_BOLD],
        Locale::ZhHant => [TRADITIONAL_REGULAR, TRADITIONAL_BOLD],
        Locale::Ar => [ARABIC_REGULAR, ARABIC_BOLD],
        _ => [LATIN_REGULAR, LATIN_BOLD],
    }
}

fn font(dpi: u32, points: i32, weight: i32, face: &str) -> Result<HFONT, Error> {
    let face = wide(face);
    let height = -(points * dpi as i32 / 72);
    // SAFETY: fixed face and value parameters; returned font is uniquely owned.
    let font = unsafe {
        CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            FF_DONTCARE.0 as u32,
            PCWSTR(face.as_ptr()),
        )
    };
    if font.0.is_null() {
        Err(WinError::from_thread().into())
    } else {
        Ok(font)
    }
}

fn draw_text(
    dc: HDC,
    font: HFONT,
    text: &str,
    mut rect: RECT,
    text_color: u32,
    flags: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
) {
    let mut text: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: live memory DC, owned font and bounded mutable UTF-16/RECT buffers.
    unsafe {
        let old = SelectObject(dc, HGDIOBJ(font.0));
        SetTextColor(dc, color(text_color));
        DrawTextW(dc, &mut text, &mut rect, flags);
        SelectObject(dc, old);
    }
}

fn remaining_seconds(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_secs()
}

fn qr_modules(text: &str) -> Result<(Vec<bool>, usize), Error> {
    let qr = QrCode::new(text.as_bytes()).map_err(|_| Error::Qr)?;
    let width = qr.width();
    let modules = qr
        .to_colors()
        .into_iter()
        .map(|module| module == Color::Dark)
        .collect::<Vec<_>>();
    if width == 0 || modules.len() != width * width {
        return Err(Error::Qr);
    }
    Ok((modules, width))
}

#[cfg(test)]
fn paint_modules(
    modules: &[bool],
    width: usize,
    module_px: usize,
    quiet: usize,
    rgb: &mut [u8],
    stride: usize,
) {
    if width == 0 || module_px == 0 || modules.len() != width.saturating_mul(width) {
        return;
    }
    for (index, dark) in modules.iter().copied().enumerate() {
        if !dark {
            continue;
        }
        let module_x = index % width;
        let module_y = index / width;
        for y in 0..module_px {
            for x in 0..module_px {
                let pixel_x = (module_x + quiet) * module_px + x;
                let pixel_y = (module_y + quiet) * module_px + y;
                let offset = pixel_y
                    .checked_mul(stride)
                    .and_then(|value| value.checked_add(pixel_x.saturating_mul(3)));
                if let Some(offset) = offset
                    && let Some(pixel) = rgb.get_mut(offset..offset + 3)
                {
                    pixel.fill(0);
                }
            }
        }
    }
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;
    use approval_protocol::{DeviceId, PcIdentity};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
    use service_protocol::{
        PairingChallenge, PairingInvitation, PairingInvitationFields, PairingNonce,
    };
    use std::net::SocketAddr;

    fn public(seed: u8) -> secure_channel::TlsPublicKey {
        let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = p256::PublicKey::from_sec1_bytes(
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        secure_channel::TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes())
            .unwrap()
    }

    fn invitation_text() -> String {
        PairingInvitation::new(PairingInvitationFields {
            ceremony_nonce: PairingNonce::from_bytes([1; 32]).unwrap(),
            attestation_challenge: PairingChallenge::from_bytes([2; 32]).unwrap(),
            pc: PcIdentity::from_bytes([3; 32]).unwrap(),
            recipient_device: DeviceId::from_bytes([4; 16]).unwrap(),
            pc_signing_key: public(5),
            pc_transport_key: public(6),
            relay_address: SocketAddr::from(([192, 0, 2, 42], 7443)),
            route: [7; 32],
        })
        .unwrap()
        .to_qr_text()
    }

    #[test]
    fn rendered_modules_decode_to_the_exact_canonical_invitation() {
        let text = invitation_text();
        let (modules, width) = qr_modules(&text).unwrap();
        let module_px = 8;
        let side = (width + QUIET_MODULES * 2) * module_px;
        let stride = side * 3;
        let mut rgb = vec![255; side * stride];
        paint_modules(&modules, width, module_px, QUIET_MODULES, &mut rgb, stride);
        let mut prepared =
            rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| rgb[y * stride + x * 3]);
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1);
        let (_, decoded) = grids[0].decode().unwrap();
        assert_eq!(decoded, text);
    }
}
