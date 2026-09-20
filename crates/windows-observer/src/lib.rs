// SPDX-License-Identifier: GPL-2.0-or-later
//! Read-only diagnostics for this process's current Windows session/desktops.
//!
//! Desktop categories are untrusted diagnostic observations, not authenticated
//! prompt identities, UAC detection, credentials, approval or permission proofs.
//! In particular, `Winlogon` alone establishes none of those properties. The
//! process session is not necessarily the active console or an intended user's
//! session. The separate observations are not an atomic desktop-state snapshot.
//!
//! This crate never switches desktops, induces UAC, registers a service, starts
//! processes, changes policy, captures windows/screens, injects input or acts on
//! consent/credential prompts. Raw handles and desktop-name text stay private.

#![deny(unsafe_code)]

use std::fmt;

use thiserror::Error;

#[cfg(any(windows, test))]
mod name;

// The sole reviewed Windows FFI boundary. Every unsafe block documents its
// handle ownership, pointer lifetime/alignment, bounds and privilege invariants.
#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;

/// Maximum accepted desktop-name size, INCLUDING the terminating UTF-16 NUL.
/// This is a defensive application bound, not a claimed Windows name limit.
pub const MAX_DESKTOP_NAME_UNITS: usize = 512;
pub const MAX_DESKTOP_NAME_BYTES: u32 = (MAX_DESKTOP_NAME_UNITS * 2) as u32;

/// Classification only. Other names are deliberately never retained or printed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DesktopCategory {
    Default,
    Winlogon,
    Other,
}

impl DesktopCategory {
    pub const fn diagnostic_label(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Winlogon => "Winlogon",
            Self::Other => "Other(redacted)",
        }
    }
}

impl fmt::Debug for DesktopCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.diagnostic_label())
    }
}

impl fmt::Display for DesktopCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.diagnostic_label())
    }
}

/// Owned diagnostic values with no desktop handle, name text or screen content.
/// A successful observation is not an authorization or UAC-success report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopObservation {
    process_session_id: u32,
    thread_desktop: DesktopCategory,
    input_desktop: DesktopCategory,
}

impl DesktopObservation {
    pub const fn platform(&self) -> &'static str {
        "windows"
    }

    pub const fn process_session_id(&self) -> u32 {
        self.process_session_id
    }

    pub const fn thread_desktop(&self) -> DesktopCategory {
        self.thread_desktop
    }

    pub const fn input_desktop(&self) -> DesktopCategory {
        self.input_desktop
    }
}

/// Observe once with the caller's existing permissions. No elevation or policy
/// fallback is attempted when Windows refuses access. Access failures, invalid
/// Unicode and unsupported platforms are errors, not fabricated observations.
///
/// This example type-checks usage without reading the real desktop during tests.
///
/// ```
/// use windows_observer::{DesktopObservation, ObserveError, observe_current_input_desktop};
/// let observe: fn() -> Result<DesktopObservation, ObserveError> = observe_current_input_desktop;
/// let _ = observe; // Deliberately not called by this compile-time usage example.
/// ```
///
/// Raw desktop handles cannot be obtained through the public observation API.
///
/// ```compile_fail
/// fn raw_handle(value: windows_observer::DesktopObservation) {
///     let _ = value.raw_handle();
/// }
/// ```
pub fn observe_current_input_desktop() -> Result<DesktopObservation, ObserveError> {
    #[cfg(windows)]
    {
        ffi::observe()
    }
    #[cfg(not(windows))]
    {
        Err(ObserveError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopTarget {
    Thread,
    Input,
}

impl fmt::Display for DesktopTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Thread => "thread desktop",
            Self::Input => "input desktop",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveOperation {
    CurrentProcessSession,
    CurrentThreadDesktop,
    OpenInputDesktop,
    ThreadDesktopName,
    InputDesktopName,
    CloseInputDesktop,
}

impl fmt::Display for ObserveOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CurrentProcessSession => "current process session query",
            Self::CurrentThreadDesktop => "current thread desktop query",
            Self::OpenInputDesktop => "read-only input desktop open",
            Self::ThreadDesktopName => "thread desktop name query",
            Self::InputDesktopName => "input desktop name query",
            Self::CloseInputDesktop => "input desktop handle release",
        })
    }
}

/// Strict decoder failures retain no original name units or replacement text.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DesktopNameError {
    #[error("desktop-name byte length is zero, odd or outside the bound")]
    InvalidByteLength,
    #[error("desktop-name result exceeds the supplied initialized buffer")]
    ResultExceedsBuffer,
    #[error("desktop name is empty")]
    EmptyName,
    #[error("desktop name does not end with exactly one NUL")]
    InvalidTerminator,
    #[error("desktop name contains invalid UTF-16")]
    InvalidUtf16,
}

/// Error metadata is restricted to fixed operations, fixed decode reasons and
/// numeric HRESULTs. No raw handles, desktop-name text or system-message strings.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ObserveError {
    #[error("read-only desktop observation is supported only on Windows")]
    UnsupportedPlatform,
    #[error("Windows observation failed at {operation} (HRESULT {hresult:#010x})")]
    WindowsCall {
        operation: ObserveOperation,
        hresult: i32,
    },
    #[error("invalid {target} name: {reason}")]
    DesktopName {
        target: DesktopTarget,
        reason: DesktopNameError,
    },
    #[error("unexpected success from the zero-buffer {target} name-length query")]
    UnexpectedProbeSuccess { target: DesktopTarget },
    #[error("input-desktop handle was already released")]
    InputHandleAlreadyReleased,
}
