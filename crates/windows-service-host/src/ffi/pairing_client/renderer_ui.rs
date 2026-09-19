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
            DEFAULT_CHARSET, DT_CALCRECT, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_RTLREADING,
            DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DeleteDC, DeleteObject, DrawTextW, EndPaint,
            FF_DONTCARE, FW_BOLD, FW_NORMAL, FillRect, GetDC, GetStockObject, HBRUSH, HDC, HFONT,
            HGDIOBJ, InvalidateRect, NULL_PEN, OUT_DEFAULT_PRECIS, PAINTSTRUCT, ReleaseDC,
            RemoveFontMemResourceEx, RoundRect, SRCCOPY, SelectObject, SetBkMode, SetTextColor,
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
            Controls::{DRAWITEMSTRUCT, ODS_DISABLED, ODS_FLAGS, ODS_FOCUS, ODS_SELECTED},
            HiDpi::GetDpiForWindow,
            Input::KeyboardAndMouse::{VK_ESCAPE, VK_RETURN},
            WindowsAndMessaging::{
                BN_CLICKED, BS_OWNERDRAW, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CreateWindowExW,
                DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA, GetClientRect,
                GetSystemMetrics, HMENU, KillTimer, MSG, PM_REMOVE, PeekMessageW, RegisterClassExW,
                SM_CXSCREEN, SM_CYSCREEN, SW_SHOW, SendMessageW, SetTimer, SetWindowLongPtrW,
                ShowWindow, TranslateMessage, UnregisterClassW, WINDOW_EX_STYLE, WM_COMMAND,
                WM_DRAWITEM, WM_ERASEBKGND, WM_KEYDOWN, WM_NCCREATE, WM_PAINT, WM_SETFONT,
                WM_TIMER, WNDCLASSEXW, WS_CHILD, WS_EX_RTLREADING, WS_POPUP, WS_VISIBLE,
            },
        },
    },
    core::{Error as WinError, PCWSTR},
};

const CLASS_NAME: &str = "UacRemoteControllerPairingRenderer";
const CONFIRM_ID: usize = 1001;
const CANCEL_ID: usize = 1002;
/// The introduction's proceed button is deliberately NOT `CONFIRM_ID`: that
/// identifier means "the six digits match" and nothing else may ever wear it.
const START_ID: usize = 1003;
const TIMER_ID: usize = 1;
const TIMER_MS: u32 = 1000;
const QUIET_MODULES: usize = 4;
/// A camera and the lab's screenshot decoder both read the module grid. Never
/// paint one smaller than the size those two already read successfully.
const MIN_MODULE_PX: i32 = 3;
const INK: u32 = 0x152c35;
const MUTED_INK: u32 = 0x536971;
const FAINT_INK: u32 = 0x7b8f97;
const ACCENT: u32 = 0x0b7285;
const CAUTION_SURFACE: u32 = 0xfff4e0;
const CAUTION_INK: u32 = 0x7a4f00;

#[derive(Debug)]
pub(super) enum Error {
    Native(WinError),
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
    /// The introduction was read and dismissed. Purely presentational: this
    /// owner turns it into the QR screen and never reports it to the protocol.
    Proceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Introduction,
    Invitation,
    Comparison,
    Outcome(bool),
    Expired,
}

impl Screen {
    /// The screens that accept a decision. Esc leaves from either one.
    fn is_interactive(self) -> bool {
        matches!(
            self,
            Self::Introduction | Self::Invitation | Self::Comparison
        )
    }
}

const INTRODUCTION_BODY: &str = "QR 코드로 이 컴퓨터에 휴대폰을 등록하는 절차입니다. 휴대폰에서 QR 코드 연결을 켠 다음 진행해 주세요.";
const INTRODUCTION_EXIT: &str = "ESC를 누르거나 [취소]를 눌러 언제든 중지할 수 있습니다.";
const INTRODUCTION_CAUTION: &str = "주의: 다른 사람의 요청으로 이 절차에 들어왔다면 지금 바로 중지하세요. QR 코드를 다른 사람에게 절대 공유하지 마세요.";

/// The card the QR and its outcomes paint inside. Control layout reads the same
/// rectangle the painter does, so a button cannot land off the surface.
fn card_rect(client: RECT, dpi: i32) -> RECT {
    let scale = |value: i32| value * dpi / 96;
    let width = (client.right * 72 / 100).min(scale(760));
    // Tall enough that the footer still holds the way out on a short display.
    let height = (client.bottom * 96 / 100).min(scale(900));
    let left = (client.right - width) / 2;
    let top = (client.bottom - height) / 2;
    RECT {
        left,
        top,
        right: left + width,
        bottom: top + height,
    }
}

/// The introduction's bands, measured from its own copy. Sizing the card to the
/// text is what keeps a short notice from floating above a half-empty card and a
/// long translation from being clipped, in every language, without a per-locale
/// number anywhere.
#[derive(Clone, Copy, Debug, PartialEq)]
struct IntroductionLayout {
    card: RECT,
    body: RECT,
    escape: RECT,
    caution: RECT,
    button_top: i32,
    button_height: i32,
}

/// Where the QR sits and where the footer starts, derived together so neither
/// can be moved without the other. The QR is measured first and the way out is
/// anchored to the card, so a cramped display loses margin, never legibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InvitationLayout {
    qr_top: i32,
    qr_side: i32,
    module_px: i32,
    countdown_top: i32,
    button_top: i32,
    button_height: i32,
}

fn invitation_layout(card: RECT, dpi: i32, shorter: i32, modules: usize) -> InvitationLayout {
    let scale = |value: i32| value * dpi / 96;
    let quiet = (modules + QUIET_MODULES * 2) as i32;
    let card_height = card.bottom - card.top;
    let footer = scale(164);
    // A short card gives up the breathing room under its copy before it gives
    // up either the smallest readable code or the way out beneath it.
    let header = scale(214)
        .min(card_height - footer - MIN_MODULE_PX * quiet - scale(8))
        .max(scale(200));
    let band = (card_height - header - footer).max(1);
    let target = (shorter * 38 / 100).min(band);
    let module_px = (target / quiet.max(1)).max(MIN_MODULE_PX);
    let qr_side = module_px * quiet;
    let qr_top = card.top + header + (band - qr_side).max(0) / 2;
    InvitationLayout {
        qr_top,
        qr_side,
        module_px,
        countdown_top: qr_top + qr_side + scale(14),
        button_top: card.bottom - scale(118),
        button_height: scale(56),
    }
}

pub(super) struct RendererWindow {
    owner: Box<WindowOwner>,
}

struct WindowOwner {
    hwnd: HWND,
    /// Each child control holds exactly one meaning for the whole run. `start`
    /// only ever dismisses the introduction and `confirm` only ever answers the
    /// comparison; neither is reused for the other screen's question.
    start: HWND,
    confirm: HWND,
    cancel: HWND,
    original_desktop: Option<HDESK>,
    class_atom: u16,
    instance: HINSTANCE,
    title_font: HFONT,
    body_font: HFONT,
    code_font: HFONT,
    hint_font: HFONT,
    font_resources: Vec<HANDLE>,
    locale: Locale,
    background: HBRUSH,
    surface: HBRUSH,
    border: HBRUSH,
    modules: Vec<bool>,
    module_width: usize,
    usb: bool,
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

    fn dpi(&self) -> i32 {
        // SAFETY: the owned top-level window remains live for this owner.
        unsafe { GetDpiForWindow(self.hwnd) }.max(96) as i32
    }

    /// The card for whichever screen is showing. The introduction measures its
    /// own copy, so it needs a device context; every other screen ignores it.
    fn card(&self, dc: HDC, client: RECT, dpi: i32) -> RECT {
        if self.screen == Screen::Introduction {
            self.introduction_layout(dc, client, dpi).card
        } else {
            card_rect(client, dpi)
        }
    }

    fn introduction_layout(&self, dc: HDC, client: RECT, dpi: i32) -> IntroductionLayout {
        let scale = |value: i32| value * dpi / 96;
        let flags = DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction();
        let width = (client.right * 72 / 100).min(scale(760));
        let left = (client.right - width) / 2;
        let text_width = (width - scale(88)).max(1);
        let measure = |source: &'static str, w: i32| {
            measure_text(dc, self.body_font, self.copy(source), w, flags)
        };
        let body = measure(INTRODUCTION_BODY, text_width);
        let escape = measure(INTRODUCTION_EXIT, text_width);
        let caution = measure(INTRODUCTION_CAUTION, (text_width - scale(48)).max(1));
        // One stack of fixed gaps around three measured blocks. Changing a gap
        // here moves the card with it; nothing is positioned from the bottom.
        let height = (scale(26 + 66 + 18 + 20 + 26 + 40 + 32 + 72 + 44) + body + escape + caution)
            .min(client.bottom * 92 / 100);
        let top = (client.bottom - height) / 2;
        let band = |from: i32, tall: i32| RECT {
            left: left + scale(44),
            top: from,
            right: left + width - scale(44),
            bottom: from + tall,
        };
        let body_top = top + scale(26 + 66 + 18);
        let escape_top = body_top + body + scale(20);
        let caution_top = escape_top + escape + scale(26);
        IntroductionLayout {
            card: RECT {
                left,
                top,
                right: left + width,
                bottom: top + height,
            },
            body: band(body_top, body),
            escape: band(escape_top, escape),
            caution: band(caution_top, caution + scale(40)),
            button_top: caution_top + caution + scale(40 + 32),
            button_height: scale(72),
        }
    }

    fn invitation_layout(&self, card: RECT, dpi: i32) -> InvitationLayout {
        // SAFETY: screen metric reads have no caller-owned pointers.
        let shorter = unsafe { GetSystemMetrics(SM_CXSCREEN).min(GetSystemMetrics(SM_CYSCREEN)) };
        invitation_layout(card, dpi, shorter, self.module_width)
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
        // Neither a deadline the reader is racing nor a promise that the screen
        // acts on its own. Just when it ends, which claims nothing about who is
        // in control of it.
        self.copy("{:02}:{:02} 후 종료")
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

    fn create(text: &str, deadline: Instant, usb: bool) -> Result<RendererWindow, Error> {
        if Instant::now() >= deadline {
            return Err(Error::InvalidState);
        }
        let (modules, module_width) = if usb {
            (Vec::new(), 21)
        } else {
            qr_modules(text)?
        };
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
            start: HWND::default(),
            confirm: HWND::default(),
            cancel: HWND::default(),
            original_desktop: None,
            class_atom,
            instance,
            title_font: HFONT::default(),
            body_font: HFONT::default(),
            code_font: HFONT::default(),
            hint_font: HFONT::default(),
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
            usb,
            deadline,
            remaining_second: remaining_seconds(deadline),
            // The QR is never the first thing the takeover shows. The reader
            // gets told what this is, and how to leave, before it appears.
            screen: if usb {
                Screen::Invitation
            } else {
                Screen::Introduction
            },
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
        self.title_font = font(dpi, 22, FW_BOLD.0 as i32, font_face(self.locale))?;
        self.body_font = font(dpi, 16, FW_NORMAL.0 as i32, font_face(self.locale))?;
        // Comparison digits are immutable ASCII and always use the Latin face.
        self.code_font = font(dpi, 40, FW_BOLD.0 as i32, "UAC Sans")?;
        self.hint_font = font(dpi, 13, FW_NORMAL.0 as i32, font_face(self.locale))?;
        self.background = brush(0xf2f6f7)?;
        self.surface = brush(0xffffff)?;
        self.border = brush(0xd7e3e7)?;
        // The way out exists before the desktop switches, not after it.
        if self.usb {
            self.show_invitation_button()?;
        } else {
            self.show_introduction_buttons()?;
        }
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

    /// Leaves the introduction for the QR itself. Local presentation only: no
    /// frame is sent and the protocol phase is untouched by this transition.
    fn show_qr(&mut self) -> Result<(), Error> {
        if self.screen != Screen::Introduction {
            return Err(Error::InvalidState);
        }
        self.hide_buttons()?;
        self.screen = Screen::Invitation;
        self.show_invitation_button()?;
        self.repaint()
    }

    pub(super) fn show_comparison(&mut self, code: &str) -> Result<(), Error> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::InvalidState);
        }
        self.code = format!("{} {}", &code[..3], &code[3..]);
        // The introduction's proceed button must never survive into a screen
        // where a click means "the digits match"; replace the whole row.
        self.hide_buttons()?;
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
            if message.message == WM_KEYDOWN
                && let Some(event) = self.key_decision(message.wParam.0)
            {
                self.event = Some(event);
                continue;
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
        // Reading the introduction is a local presentation step, so it is spent
        // here and never reported as a decision to the pairing protocol.
        if self.event == Some(UiEvent::Proceeded) {
            self.event = None;
            self.show_qr()?;
        }
        Ok(self.event.take())
    }

    /// The only two keys this window reads, and only where they mean something.
    /// Escape leaves from any screen that still offers a way out; Enter answers
    /// whichever question that screen is asking, and asks none of its own.
    fn key_decision(&self, key: usize) -> Option<UiEvent> {
        if key == usize::from(VK_ESCAPE.0) && self.screen.is_interactive() {
            return Some(UiEvent::Cancelled);
        }
        if key == usize::from(VK_RETURN.0) {
            return match self.screen {
                Screen::Introduction => Some(UiEvent::Proceeded),
                Screen::Comparison => Some(UiEvent::Confirmed),
                _ => None,
            };
        }
        None
    }

    /// Creates one fixed push button owned by this window. The label is authored
    /// copy and the identifier is a compile-time constant; neither is caller
    /// text, a path, a command or anything read from the pipe.
    ///
    /// The control is owner drawn because this process carries no application
    /// manifest and enables no theming, so a standard button is painted by
    /// comctl32's classic path: a grey raised block, next to a window whose
    /// every other pixel is drawn here. `draw_button` paints it instead. The
    /// class and the window text stay exactly what they were, because CI drives
    /// this window through them.
    fn push_button(&self, label: &str, id: usize) -> Result<HWND, Error> {
        let class = wide("BUTTON");
        let text = wide(label);
        // SAFETY: fixed standard child control parented to the owned top-level window.
        let button = unsafe {
            CreateWindowExW(
                self.window_direction(),
                PCWSTR(class.as_ptr()),
                PCWSTR(text.as_ptr()),
                WS_CHILD
                    | WS_VISIBLE
                    | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(BS_OWNERDRAW as u32),
                0,
                0,
                1,
                1,
                Some(self.hwnd),
                Some(HMENU(id as *mut _)),
                Some(self.instance),
                None,
            )?
        };
        // The control borrows this owner's live font only; every button is
        // destroyed before the HFONT and the memory-font resources are released.
        // SAFETY: the newly created owned control and this owner's live font.
        unsafe {
            SendMessageW(
                button,
                WM_SETFONT,
                Some(WPARAM(self.body_font.0 as usize)),
                Some(LPARAM(1)),
            );
        }
        Ok(button)
    }

    fn show_introduction_buttons(&mut self) -> Result<(), Error> {
        if !self.start.0.is_null() {
            return Ok(());
        }
        let start = self.push_button(self.button_copy(START_ID), START_ID)?;
        self.start = start;
        let cancel = self.push_button(self.button_copy(CANCEL_ID), CANCEL_ID)?;
        self.cancel = cancel;
        self.layout_buttons()
    }

    /// The one place a button's label is chosen. Creation and owner drawing both
    /// read it, so what is painted cannot drift from the window text the control
    /// was made with, which is what CI drives this window by. Every screen that
    /// offers a way out words it for the question that screen is asking.
    fn button_copy(&self, id: usize) -> &'static str {
        match (id, self.screen) {
            (START_ID, _) => self.copy("QR 코드 보기"),
            (CONFIRM_ID, _) => self.copy("숫자가 같아요"),
            (CANCEL_ID, Screen::Introduction) => self.copy("취소"),
            (CANCEL_ID, Screen::Invitation) => self.copy("취소하고 돌아가기"),
            (CANCEL_ID, _) => self.copy("다릅니다, 취소"),
            _ => "",
        }
    }

    fn show_invitation_button(&mut self) -> Result<(), Error> {
        if !self.cancel.0.is_null() {
            return Ok(());
        }
        let cancel = self.push_button(self.button_copy(CANCEL_ID), CANCEL_ID)?;
        self.cancel = cancel;
        self.layout_buttons()
    }

    fn ensure_buttons(&mut self) -> Result<(), Error> {
        if !self.confirm.0.is_null() {
            return Ok(());
        }
        let confirm = self.push_button(self.button_copy(CONFIRM_ID), CONFIRM_ID)?;
        self.confirm = confirm;
        let cancel = self.push_button(self.button_copy(CANCEL_ID), CANCEL_ID)?;
        self.cancel = cancel;
        self.layout_buttons()
    }

    /// Paints one button, because nothing else on this window is painted by the
    /// system and a standard control here is a grey raised block from comctl32's
    /// classic path. The fill, the border and the three-point radius are the
    /// ones the gallery mock in `ui/src/PairingCeremony.tsx` was reviewed with.
    /// Pressed and focus are this function's own, since a static mock has no use
    /// for them; hover is deliberately absent, as it is in the reviewed design.
    fn draw_button(&self, item: &DRAWITEMSTRUCT) {
        let label = self.button_copy(item.CtlID as usize);
        if label.is_empty() || item.hDC.is_invalid() {
            return;
        }
        let dpi = self.dpi();
        let scale = |value: i32| (value * dpi / 96).max(1);
        let state = |flag: ODS_FLAGS| item.itemState.0 & flag.0 != 0;
        let pressed = state(ODS_SELECTED);
        let disabled = state(ODS_DISABLED);
        let focused = state(ODS_FOCUS);
        // The button that carries the screen's answer wears the accent, and the
        // mock draws its border and the ring outside it as one solid edge, so
        // that edge is twice as thick rather than a different colour.
        let emphasised = is_answer(item.CtlID as usize);
        let thickness = if emphasised { scale(2) } else { scale(1) };
        let face = if pressed && !disabled {
            0xe6eef0
        } else {
            0xfdfdfd
        };
        let edge = match (disabled, emphasised) {
            (true, _) => 0xd7e3e7,
            (false, true) => ACCENT,
            (false, false) => 0xadadad,
        };
        let radius = scale(6);
        // Border, then face inside it, then a focus ring inside that. Each is a
        // filled rounded rectangle rather than a stroke, which is how this file
        // already draws every other shape.
        // Nothing erases an owner-drawn control's background, and the corners a
        // rounded rectangle leaves out would keep whatever was there before. The
        // buttons are anchored inside the card on every screen that has them, so
        // the card's own surface is what those corners must show.
        // SAFETY: the device context belongs to this draw request and the
        // surface brush is this owner's, alive for the whole run.
        unsafe { FillRect(item.hDC, &item.rcItem, self.surface) };
        let mut plates = vec![(0, edge), (thickness, face)];
        if focused && !disabled {
            let ring = thickness + scale(3);
            plates.push((ring, ACCENT));
            plates.push((ring + scale(1), face));
        }
        for (inset, fill) in plates {
            let Ok(plate) = brush(fill) else {
                return; // Half a button is still better than a failed ceremony.
            };
            // SAFETY: the device context belongs to this draw request, the brush
            // is owned here, and both the pen and the brush are restored before
            // the brush is deleted.
            unsafe {
                let previous_pen = SelectObject(item.hDC, GetStockObject(NULL_PEN));
                let previous_brush = SelectObject(item.hDC, HGDIOBJ(plate.0));
                let corner = (radius - inset).max(1);
                let _ = RoundRect(
                    item.hDC,
                    item.rcItem.left + inset,
                    item.rcItem.top + inset,
                    item.rcItem.right - inset,
                    item.rcItem.bottom - inset,
                    corner,
                    corner,
                );
                SelectObject(item.hDC, previous_brush);
                SelectObject(item.hDC, previous_pen);
                let _ = DeleteObject(HGDIOBJ(plate.0));
            }
        }
        // DT_VCENTER does not survive DT_WORDBREAK, so the wrapped height is
        // measured first and centred here. A label too tall for its button is
        // drawn from the top rather than clipped symmetrically.
        let padding = scale(8);
        let flags = DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction();
        let width = (item.rcItem.right - item.rcItem.left - padding * 2).max(1);
        let height = measure_text(item.hDC, self.body_font, label, width, flags);
        let room = item.rcItem.bottom - item.rcItem.top;
        let top = item.rcItem.top + ((room - height) / 2).max(0);
        // SAFETY: the device context belongs to this draw request.
        unsafe { SetBkMode(item.hDC, TRANSPARENT) };
        draw_text(
            item.hDC,
            self.body_font,
            label,
            RECT {
                left: item.rcItem.left + padding,
                top,
                right: item.rcItem.right - padding,
                bottom: top + height.max(room),
            },
            if disabled { FAINT_INK } else { INK },
            flags,
        );
    }

    fn move_button(
        &self,
        button: HWND,
        left: i32,
        top: i32,
        width: i32,
        height: i32,
    ) -> Result<(), Error> {
        // SAFETY: the child control and its parent remain live and thread-owned.
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::MoveWindow(
                button, left, top, width, height, true,
            )?;
        }
        Ok(())
    }

    fn layout_buttons(&self) -> Result<(), Error> {
        // SAFETY: paired GetDC/ReleaseDC on the owned window. The context is
        // only measured from and drawn into by DT_CALCRECT, which paints nothing.
        let dc = unsafe { GetDC(Some(self.hwnd)) };
        if dc.0.is_null() {
            return Err(Error::InvalidState);
        }
        let placed = self.place_buttons(dc);
        // SAFETY: releases the context this call acquired, exactly once.
        unsafe {
            ReleaseDC(Some(self.hwnd), dc);
        }
        placed
    }

    fn place_buttons(&self, dc: HDC) -> Result<(), Error> {
        let mut client = RECT::default();
        // SAFETY: owned valid top-level window and initialized output.
        unsafe { GetClientRect(self.hwnd, &mut client)? };
        let dpi = self.dpi();
        let scale = |value: i32| value * dpi / 96;
        let card = self.card(dc, client, dpi);
        match self.screen {
            // A single way out, anchored to the card's footer so it can never be
            // laid over the modules the phone camera has to read.
            Screen::Invitation => {
                if self.cancel.0.is_null() {
                    return Ok(());
                }
                let layout = self.invitation_layout(card, dpi);
                let width = scale(300).min(card.right - card.left - scale(72)).max(1);
                self.move_button(
                    self.cancel,
                    (client.right - width) / 2,
                    layout.button_top,
                    width,
                    layout.button_height,
                )
            }
            Screen::Introduction | Screen::Comparison => {
                let introducing = self.screen == Screen::Introduction;
                let primary = if introducing {
                    self.start
                } else {
                    self.confirm
                };
                if primary.0.is_null() || self.cancel.0.is_null() {
                    return Ok(());
                }
                // Wide enough that the longest translated label needs two lines
                // rather than three, and tall enough to hold those two.
                let width = scale(240);
                let height = scale(72);
                let gap = scale(16);
                let left = (client.right - width * 2 - gap) / 2;
                let (top, height) = if introducing {
                    let layout = self.introduction_layout(dc, client, dpi);
                    (layout.button_top, layout.button_height)
                } else {
                    (client.bottom / 2 + scale(120), height)
                };
                let (primary_left, cancel_left) = if self.locale.is_rtl() {
                    (left + width + gap, left)
                } else {
                    (left, left + width + gap)
                };
                self.move_button(primary, primary_left, top, width, height)?;
                self.move_button(self.cancel, cancel_left, top, width, height)
            }
            Screen::Outcome(_) | Screen::Expired => Ok(()),
        }
    }

    fn hide_buttons(&mut self) -> Result<(), Error> {
        let mut first = None;
        for button in [&mut self.start, &mut self.confirm, &mut self.cancel] {
            if button.0.is_null() {
                continue;
            }
            // SAFETY: a non-null field here is an owned live control of this window.
            unsafe {
                if let Err(error) = DestroyWindow(*button) {
                    first.get_or_insert(Error::Native(error));
                }
            }
            *button = HWND::default();
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
        let dpi = self.dpi();
        let scale = |value: i32| value * dpi / 96;
        let border = self.card(dc, client, dpi);
        let left = border.left;
        let top = border.top;
        let card_width = border.right - border.left;
        let card_height = border.bottom - border.top;
        // One signature, in one corner. A takeover that names itself is a
        // program; the same mark repeated around the screen would be a seal.
        self.draw_signature(dc, client, border, scale(28), scale(24), scale(36));
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
            self.copy(if self.usb && self.screen == Screen::Invitation {
                "USB 연결 대기"
            } else if self.screen == Screen::Introduction {
                "QR 연결 절차를 시작합니다."
            } else {
                "UAC 원격 승인 · PC 연결"
            }),
            RECT {
                left: left + scale(32),
                top: top + scale(26),
                right: left + card_width - scale(32),
                bottom: top + scale(96),
            },
            INK,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        match self.screen {
            Screen::Introduction => self.draw_introduction(dc, client, dpi),
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

    /// The product mark and name, once, in the screen's leading top corner. The
    /// mark is the app icon's two shapes redrawn with axis-aligned primitives;
    /// no image, file or resource is loaded to paint it.
    fn draw_signature(&self, dc: HDC, client: RECT, card: RECT, margin: i32, top: i32, size: i32) {
        let Ok(accent) = brush(ACCENT) else {
            return; // Decoration only: never fail a pairing screen over it.
        };
        let leading = if self.locale.is_rtl() {
            client.right - margin - size
        } else {
            margin
        };
        let unit = |value: i32| leading + value * size / 40;
        let row = |value: i32| top + value * size / 40;
        // SAFETY: the memory DC, the temporary accent brush and this owner's
        // live surface brush are all valid for the whole of this paint.
        unsafe {
            let previous_brush = SelectObject(dc, HGDIOBJ(accent.0));
            // A stock pen is process-owned and must never be deleted here.
            let previous_pen = SelectObject(dc, GetStockObject(NULL_PEN));
            let radius = size * 24 / 40;
            let _ = RoundRect(dc, leading, top, leading + size, top + size, radius, radius);
            SelectObject(dc, previous_pen);
            SelectObject(dc, previous_brush);
            // The monitor, its screen, its stand and the phone beside it.
            FillRect(
                dc,
                &RECT {
                    left: unit(7),
                    top: row(9),
                    right: unit(30),
                    bottom: row(26),
                },
                self.surface,
            );
            FillRect(
                dc,
                &RECT {
                    left: unit(10),
                    top: row(12),
                    right: unit(27),
                    bottom: row(23),
                },
                accent,
            );
            FillRect(
                dc,
                &RECT {
                    left: unit(12),
                    top: row(29),
                    right: unit(25),
                    bottom: row(31),
                },
                self.surface,
            );
            FillRect(
                dc,
                &RECT {
                    left: unit(23),
                    top: row(17),
                    right: unit(35),
                    bottom: row(34),
                },
                self.surface,
            );
            FillRect(
                dc,
                &RECT {
                    left: unit(25),
                    top: row(19),
                    right: unit(33),
                    bottom: row(30),
                },
                accent,
            );
            // The temporary brush is no longer selected or borrowed.
            let _ = DeleteObject(HGDIOBJ(accent.0));
        }
        // The card is painted over this corner afterwards. A translated name
        // that would run under it is dropped rather than sliced; the mark alone
        // still signs the screen, which is all one corner has to do.
        let (text_left, text_right, alignment) = if self.locale.is_rtl() {
            (
                card.right + size / 4,
                leading - size / 4,
                windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(0),
            )
        } else {
            (leading + size + size / 4, card.left - size / 4, DT_LEFT)
        };
        let name = self.copy("UAC 원격 승인");
        if text_right - text_left < measure_width(dc, self.body_font, name) {
            return;
        }
        draw_text(
            dc,
            self.body_font,
            name,
            RECT {
                left: text_left,
                top,
                right: text_right,
                bottom: top + size,
            },
            ACCENT,
            alignment | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | self.text_direction(),
        );
    }

    /// Says what the ceremony is, that it can be stopped, and what sharing this
    /// code would hand over, before the code itself is ever shown.
    fn draw_introduction(&self, dc: HDC, client: RECT, dpi: i32) {
        let scale = |value: i32| value * dpi / 96;
        let layout = self.introduction_layout(dc, client, dpi);
        let flags = DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction();
        draw_text(
            dc,
            self.body_font,
            self.copy(INTRODUCTION_BODY),
            layout.body,
            MUTED_INK,
            flags,
        );
        draw_text(
            dc,
            self.body_font,
            self.copy(INTRODUCTION_EXIT),
            layout.escape,
            MUTED_INK,
            flags,
        );
        let Ok(surface) = brush(CAUTION_SURFACE) else {
            return; // Decoration only: never fail the ceremony over a fill.
        };
        // SAFETY: the memory DC and the temporary caution brush are live here.
        unsafe {
            FillRect(dc, &layout.caution, surface);
            let _ = DeleteObject(HGDIOBJ(surface.0));
        }
        draw_text(
            dc,
            self.body_font,
            self.copy(INTRODUCTION_CAUTION),
            RECT {
                left: layout.caution.left + scale(24),
                top: layout.caution.top + scale(20),
                right: layout.caution.right - scale(24),
                bottom: layout.caution.bottom - scale(20),
            },
            CAUTION_INK,
            flags,
        );
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
        if self.usb {
            draw_text(dc, self.body_font,
                self.copy("휴대폰에서 USB 연결을 허용하십시오. 연결 후 두 기기의 비교 코드를 확인하십시오."),
                RECT { left: left + scale(36), top: top + scale(140),
                    right: left + card_width - scale(36), bottom: top + scale(280) },
                MUTED_INK, DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction());
            draw_text(
                dc,
                self.body_font,
                &self.remaining_copy(),
                RECT {
                    left: left + scale(36),
                    top: top + scale(310),
                    right: left + card_width - scale(36),
                    bottom: top + scale(360),
                },
                MUTED_INK,
                DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
            );
            return Ok(());
        }
        draw_text(
            dc,
            self.body_font,
            self.copy("UAC 원격 승인 앱에서 [PC의 QR 코드 촬영]을 누르고 이 QR을 비춰 주세요."),
            RECT {
                left: left + scale(36),
                top: top + scale(104),
                right: left + card_width - scale(36),
                bottom: top + scale(188),
            },
            MUTED_INK,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        let layout = self.invitation_layout(
            RECT {
                left,
                top,
                right: left + card_width,
                bottom: top + card_height,
            },
            self.dpi(),
        );
        let InvitationLayout {
            qr_top,
            qr_side: total,
            module_px,
            countdown_top,
            ..
        } = layout;
        let qr_left = left + (card_width - total) / 2;
        let white = RECT {
            left: qr_left,
            top: qr_top,
            right: qr_left + total,
            bottom: qr_top + total,
        };
        // SAFETY: the memory DC and owned white surface brush are live.
        unsafe { FillRect(dc, &white, self.surface) };
        let dark = brush(INK)?;
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
                top: countdown_top,
                right: left + card_width - scale(24),
                bottom: countdown_top + scale(32),
            },
            MUTED_INK,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | self.text_direction(),
        );
        // Under the cancel button, which layout_buttons anchors to this footer.
        draw_text(
            dc,
            self.hint_font,
            self.copy("ESC 키를 눌러도 바로 돌아가요."),
            RECT {
                left: left + scale(24),
                top: top + card_height - scale(48),
                right: left + card_width - scale(24),
                bottom: top + card_height - scale(16),
            },
            FAINT_INK,
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
                top: top + scale(104),
                right: left + card_width - scale(36),
                bottom: top + scale(184),
            },
            MUTED_INK,
            DT_CENTER | DT_WORDBREAK | DT_NOPREFIX | self.text_direction(),
        );
        draw_text(
            dc,
            self.code_font,
            &self.code,
            RECT {
                left: left + scale(36),
                top: top + scale(196),
                right: left + card_width - scale(36),
                bottom: top + scale(286),
            },
            INK,
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
            INK,
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
            self.start = HWND::default();
            self.confirm = HWND::default();
            self.cancel = HWND::default();
        }
        let mut objects_deleted = true;
        for object in [
            HGDIOBJ(self.title_font.0),
            HGDIOBJ(self.body_font.0),
            HGDIOBJ(self.code_font.0),
            HGDIOBJ(self.hint_font.0),
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
        self.hint_font = HFONT::default();
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
    /// Creates the window on the current thread desktop, then switches input to
    /// it. The QR is prepared but not shown: the introduction comes first.
    pub(super) fn open(text: &str, deadline: Instant, usb: bool) -> Result<Self, Error> {
        WindowOwner::create(text, deadline, usb)
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
        WM_DRAWITEM => {
            if let Some(owner) = owner {
                // SAFETY: for WM_DRAWITEM lparam is a DRAWITEMSTRUCT the sender
                // keeps live for the whole of this call, and it is only read.
                let item = unsafe { &*(lparam.0 as *const DRAWITEMSTRUCT) };
                owner.draw_button(item);
                return LRESULT(1);
            }
            // SAFETY: forwards the untouched message parameters to the default procedure.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
        WM_COMMAND => {
            if let Some(owner) = owner {
                let id = wparam.0 & 0xffff;
                let notification = (wparam.0 >> 16) as u32;
                if notification == BN_CLICKED {
                    // Each identifier is honoured only on the screen whose
                    // question it answers, whatever control happens to exist.
                    owner.event = match (id, owner.screen) {
                        (START_ID, Screen::Introduction) => Some(UiEvent::Proceeded),
                        (CONFIRM_ID, Screen::Comparison) => Some(UiEvent::Confirmed),
                        (CANCEL_ID, screen) if screen.is_interactive() => Some(UiEvent::Cancelled),
                        _ => owner.event,
                    };
                }
            }
            LRESULT(0)
        }
        WM_KEYDOWN => {
            if let Some(owner) = owner
                && let Some(event) = owner.key_decision(wparam.0)
            {
                owner.event = Some(event);
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

/// The identifiers whose button carries the screen's answer rather than its way
/// out. Owner drawing cannot ask the system for this: `BS_OWNERDRAW` occupies
/// the same four style bits as `BS_DEFPUSHBUTTON`, so the two cannot be worn at
/// once. Nothing was lost with that style. Enter never went through it; `pump`
/// reads the key itself and `key_decision` answers for the screen.
fn is_answer(id: usize) -> bool {
    matches!(id, START_ID | CONFIRM_ID)
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

/// The width one line of this copy needs, used to decide whether a translated
/// name fits the room a corner actually has.
fn measure_width(dc: HDC, font: HFONT, text: &str) -> i32 {
    let mut text: Vec<u16> = text.encode_utf16().collect();
    let mut rect = RECT::default();
    // SAFETY: live DC, owned font and bounded mutable UTF-16/RECT buffers.
    // DT_CALCRECT measures into the rect and paints nothing.
    unsafe {
        let old = SelectObject(dc, HGDIOBJ(font.0));
        DrawTextW(
            dc,
            &mut text,
            &mut rect,
            DT_SINGLELINE | DT_CALCRECT | DT_NOPREFIX,
        );
        SelectObject(dc, old);
    }
    (rect.right - rect.left).max(0)
}

/// The height this copy needs at the given width, so a band can be filled to fit
/// its own text in every language instead of one height guessed for all of them.
fn measure_text(
    dc: HDC,
    font: HFONT,
    text: &str,
    width: i32,
    flags: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
) -> i32 {
    let mut text: Vec<u16> = text.encode_utf16().collect();
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: width.max(1),
        bottom: 0,
    };
    // SAFETY: live memory DC, owned font and bounded mutable UTF-16/RECT buffers.
    // DT_CALCRECT measures into the rect and paints nothing.
    unsafe {
        let old = SelectObject(dc, HGDIOBJ(font.0));
        DrawTextW(dc, &mut text, &mut rect, flags | DT_CALCRECT);
        SelectObject(dc, old);
    }
    (rect.bottom - rect.top).max(0)
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

    /// The QR keeps the module size a camera and the lab decoder already read,
    /// and the way out stays on the card without ever covering the code. The
    /// widths are the ones the lab runner and ordinary displays actually use.
    #[test]
    fn every_supported_display_keeps_the_code_legible_and_the_way_out_reachable() {
        let modules = qr_modules(&invitation_text()).unwrap().1;
        assert!(modules >= 21);
        for (width, height, dpi) in [
            (1024, 768, 96),
            (1280, 720, 96),
            (1366, 768, 96),
            (1920, 1080, 96),
            (2560, 1440, 96),
            (3840, 2160, 192),
        ] {
            let client = RECT {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            };
            let card = card_rect(client, dpi);
            let layout = invitation_layout(card, dpi, width.min(height), modules);
            let scale = |value: i32| value * dpi / 96;
            let label = format!("{width}x{height}@{dpi} modules={modules} {layout:?} {card:?}");
            assert!(
                card.top >= 0 && card.bottom <= height,
                "{label}: card on screen"
            );
            assert!(
                layout.module_px >= MIN_MODULE_PX,
                "{label}: {} px modules",
                layout.module_px
            );
            assert!(
                layout.qr_top >= card.top + scale(200),
                "{label}: the code never covers the copy above it"
            );
            assert!(
                layout.countdown_top + scale(32) <= layout.button_top,
                "{label}: countdown clears the button"
            );
            assert!(
                layout.qr_top + layout.qr_side <= layout.countdown_top,
                "{label}: the button row never covers the code"
            );
            assert!(
                layout.button_top + layout.button_height <= card.bottom,
                "{label}: the way out stays on the card"
            );
        }
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
