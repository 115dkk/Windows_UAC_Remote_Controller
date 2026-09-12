// SPDX-License-Identifier: GPL-2.0-or-later
//! Current interactive app only. No installer/service invocation, foreign app
//! identity, pinning bypass, token, shell verb or writable registry API exists.
//! Begin functions run on the foreground Tauri UI thread; returned operations
//! only await the already-started agile WinRT operation off that thread.

use std::{future::Future, pin::Pin};
use windows::{
    UI::Shell::{ITaskbarManagerDesktopAppSupportStatics, TaskbarManager},
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        System::{
            Registry::{
                HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
                RegGetValueW,
            },
            WinRT::{RO_INIT_SINGLETHREADED, RoInitialize, RoUninitialize},
        },
    },
    core::{PCWSTR, factory, w},
};

const INSTALL_KEY: PCWSTR =
    w!("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\휴대폰 승인");
const LAF_KEY: PCWSTR = w!(
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\LimitedAccessFeatures\\com.microsoft.windows.taskbar.pin"
);
// Microsoft's public feature-detection seed, NOT an unlock/access token.
const LAF_SEED: PCWSTR = w!("4096B239A7295B635C090E647E867B5707DA6AB6CB78340B01FE4E0C8F4953D4");

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskbarStatus {
    Hidden,
    Available,
    Pinned,
    Unavailable,
    Declined,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TaskbarOffer {
    pub version: Option<String>,
    pub status: TaskbarStatus,
}

type Operation<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Read-only installer suggestion and actual OS capability/pinned state.
/// Call on the initialized foreground app UI thread; never prompts to pin.
pub fn begin_taskbar_offer() -> Operation<TaskbarOffer> {
    let version = installer_request_version();
    let Some(version) = version else {
        return Box::pin(async {
            TaskbarOffer {
                version: None,
                status: TaskbarStatus::Hidden,
            }
        });
    };
    let prepared = (|| {
        let _apartment = Apartment::enter()?;
        let manager = manager()?;
        let allowed = manager.IsPinningAllowed().ok()?;
        Some((manager.IsCurrentAppPinnedAsync().ok()?, allowed))
    })();
    Box::pin(async move {
        let status = match prepared {
            Some((operation, allowed)) => match operation.await {
                Ok(true) => TaskbarStatus::Pinned,
                Ok(false) if allowed => TaskbarStatus::Available,
                _ => TaskbarStatus::Unavailable,
            },
            None => TaskbarStatus::Unavailable,
        };
        TaskbarOffer {
            version: Some(version),
            status,
        }
    })
}

/// Explicit app-button action only. Starts the official consent request now,
/// on the foreground UI thread, and yields without blocking the message pump.
/// The OS return value, not intent or API dispatch, determines success.
pub fn begin_taskbar_pin() -> Operation<TaskbarStatus> {
    let operation = (|| {
        let _apartment = Apartment::enter()?;
        let manager = manager()?;
        if !manager.IsPinningAllowed().ok()? {
            return None;
        }
        manager.RequestPinCurrentAppAsync().ok()
    })();
    Box::pin(async move {
        match operation {
            Some(operation) => match operation.await {
                Ok(true) => TaskbarStatus::Pinned,
                Ok(false) => TaskbarStatus::Declined,
                Err(_) => TaskbarStatus::Unavailable,
            },
            None => TaskbarStatus::Unavailable,
        }
    })
}

fn manager() -> Option<TaskbarManager> {
    // Old Windows requires a Microsoft-issued application-specific LAF token.
    // We have no such grant; expose manual shell instructions instead.
    if read_dword(LAF_KEY, LAF_SEED).ok()?.unwrap_or(0) != 0 {
        return None;
    }
    factory::<TaskbarManager, ITaskbarManagerDesktopAppSupportStatics>().ok()?;
    TaskbarManager::GetDefault().ok()
}

struct Apartment;
impl Apartment {
    fn enter() -> Option<Self> {
        // SAFETY: called only on the Tauri UI thread, already an STA. Each
        // successful additional WinRT initialization is balanced on this same
        // thread; Tauri retains its own apartment while the agile op completes.
        unsafe { RoInitialize(RO_INIT_SINGLETHREADED) }.ok()?;
        Some(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: same lexical UI-thread scope as successful RoInitialize.
        unsafe { RoUninitialize() };
    }
}

fn read_dword(key: PCWSTR, value: PCWSTR) -> Result<Option<u32>, ()> {
    let mut data = 0_u32;
    let mut bytes = 4_u32;
    // SAFETY: fixed internal NUL-terminated key/value names; four writable
    // stack bytes, type-restricted read, no handles acquired or writes made.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            value,
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            None,
            Some((&raw mut data).cast()),
            Some(&raw mut bytes),
        )
    };
    if result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if result != ERROR_SUCCESS || bytes != 4 {
        return Err(());
    }
    Ok(Some(data))
}

fn installer_request_version() -> Option<String> {
    if read_dword(INSTALL_KEY, w!("TaskbarPinRequested")).ok()?? != 1 {
        return None;
    }
    let mut units = [0_u16; 96];
    let mut bytes = (units.len() * 2) as u32;
    // SAFETY: fixed names; bounded writable UTF-16 stack buffer with its exact
    // byte count. REG_SZ-only read cannot expand an environment variable.
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            INSTALL_KEY,
            w!("TaskbarPinRequestVersion"),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(units.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        )
    };
    if result != ERROR_SUCCESS || !(4..=192).contains(&bytes) || !bytes.is_multiple_of(2) {
        return None;
    }
    let version = parse_version(&units[..bytes as usize / 2])?;
    // Recheck the commit flag after the version read. Installer writes 0 first
    // and 1 last; a race can only suppress this presentation-only suggestion.
    (read_dword(INSTALL_KEY, w!("TaskbarPinRequested")).ok()?? == 1).then_some(version)
}

fn parse_version(units: &[u16]) -> Option<String> {
    let (&0, content) = units.split_last()? else {
        return None;
    };
    let version = String::from_utf16(content).ok()?;
    (!version.is_empty()
        && version.len() <= 95
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte)))
    .then_some(version)
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn version_is_bounded_plain_presentation_data() {
        let utf16 = |text: &str| text.encode_utf16().collect::<Vec<_>>();
        assert_eq!(
            parse_version(&utf16("0.1.0-alpha.14\0")).as_deref(),
            Some("0.1.0-alpha.14")
        );
        for invalid in ["", "\0", "1.0", "1\0evil\0", "../foo\0", "안녕\0"] {
            assert_eq!(parse_version(&utf16(invalid)), None);
        }
        assert_eq!(
            parse_version(&utf16(&format!("{}\0", "a".repeat(96)))),
            None
        );
    }
}
