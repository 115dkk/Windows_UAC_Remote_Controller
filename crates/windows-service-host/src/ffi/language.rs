// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed current-user presentation preference. HKCU is intentionally the current
//! process account, never a caller-selected hive/user/SID. No service identity,
//! trust registry, install ACL or authorization setting is read or changed here.

use presentation_i18n::{LanguageSettings, valid_preference};
use windows::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS},
        Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME},
        System::Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
            RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW,
        },
    },
    core::{PCWSTR, PWSTR, w},
};

const KEY: PCWSTR = w!("Software\\dkk115\\UacRemoteController\\Presentation");
const VALUE: PCWSTR = w!("Language");

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LanguageError {
    #[error("unsupported language preference")]
    InvalidPreference,
    #[error("language settings are unavailable")]
    Unavailable,
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: owned success output from RegCreateKeyExW, closed once.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

fn system_locales() -> Result<Vec<String>, LanguageError> {
    let mut count = 0;
    let mut units = [0_u16; 4096];
    let mut capacity = units.len() as u32;
    // SAFETY: fixed documented MUI language-name query, exclusive stack outputs
    // and exact UTF-16 capacity. No returned pointer is followed or retained.
    unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &raw mut count,
            Some(PWSTR(units.as_mut_ptr())),
            &raw mut capacity,
        )
    }
    .map_err(|_| LanguageError::Unavailable)?;
    let used = capacity as usize;
    if count == 0
        || count > 16
        || !(2..=units.len()).contains(&used)
        || units[used - 2..used] != [0, 0]
    {
        return Err(LanguageError::Unavailable);
    }
    let mut locales = Vec::with_capacity(count as usize);
    for item in units[..used - 1]
        .split(|unit| *unit == 0)
        .filter(|item| !item.is_empty())
    {
        if item.len() > 128 {
            return Err(LanguageError::Unavailable);
        }
        let tag = String::from_utf16(item).map_err(|_| LanguageError::Unavailable)?;
        if !tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(LanguageError::Unavailable);
        }
        locales.push(tag);
    }
    if locales.len() != count as usize {
        return Err(LanguageError::Unavailable);
    }
    Ok(locales)
}

fn preference() -> Result<String, LanguageError> {
    let mut units = [0_u16; 32];
    let mut bytes = (units.len() * 2) as u32;
    // SAFETY: fixed HKCU key/value, REG_SZ-only bounded stack read. No environment
    // expansion, arbitrary registry path, impersonation or elevation is used.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            KEY,
            VALUE,
            RRF_RT_REG_SZ,
            None,
            Some(units.as_mut_ptr().cast()),
            Some(&raw mut bytes),
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok("system".into());
    }
    if status != ERROR_SUCCESS || !(2..=64).contains(&bytes) || !bytes.is_multiple_of(2) {
        return Err(LanguageError::Unavailable);
    }
    let selected = &units[..bytes as usize / 2];
    let Some((&0, content)) = selected.split_last() else {
        return Err(LanguageError::Unavailable);
    };
    let text = String::from_utf16(content).map_err(|_| LanguageError::Unavailable)?;
    // This cosmetic key is user-writable, not trusted authority. Invalid values
    // safely restore system language; they never become text/code/path input.
    Ok(if valid_preference(&text) {
        text
    } else {
        "system".into()
    })
}

pub fn get_language_settings() -> Result<LanguageSettings, LanguageError> {
    Ok(LanguageSettings {
        preference: preference()?,
        system_locales: system_locales()?,
    })
}

pub fn set_language_preference(language: &str) -> Result<LanguageSettings, LanguageError> {
    if !valid_preference(language) {
        return Err(LanguageError::InvalidPreference);
    }
    let mut handle = HKEY::default();
    // SAFETY: fixed HKCU child only, narrow value-write right, initialized output;
    // default inherited current-user ACL is appropriate for cosmetic settings.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            KEY,
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &raw mut handle,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(LanguageError::Unavailable);
    }
    let key = Key(handle);
    let bytes: Vec<u8> = language
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    // SAFETY: owned opened key, fixed value name and a bounded complete REG_SZ
    // byte slice whose allocation stays live through this synchronous copy.
    let status = unsafe { RegSetValueExW(key.0, VALUE, None, REG_SZ, Some(&bytes)) };
    if status != ERROR_SUCCESS {
        return Err(LanguageError::Unavailable);
    }
    drop(key);
    get_language_settings()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_windows_display_language_query_is_bounded_without_registry_mutation() {
        let settings = get_language_settings().expect("Windows UI language query must succeed");
        assert!(valid_preference(&settings.preference));
        assert!(!settings.system_locales.is_empty());
        assert!(settings.system_locales.len() <= 16);
        assert!(settings.system_locales.iter().all(|tag| tag.len() <= 128));
    }

    #[test]
    fn invalid_writes_are_rejected_before_opening_any_registry_key() {
        for value in ["", "en-US", "EN", "system\0", "../ar", "ar\u{202e}"] {
            assert_eq!(
                set_language_preference(value),
                Err(LanguageError::InvalidPreference)
            );
        }
    }
}
