// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure bounded UTF-16 decoding. No pointers, platform calls, or raw-name output.

use crate::{DesktopCategory, DesktopNameError, MAX_DESKTOP_NAME_BYTES};

pub(crate) fn units_for_byte_length(bytes: u32) -> Result<usize, DesktopNameError> {
    if bytes == 0 || bytes > MAX_DESKTOP_NAME_BYTES || !bytes.is_multiple_of(2) {
        return Err(DesktopNameError::InvalidByteLength);
    }
    // The prior bound is 1024 bytes, representable on all supported Rust targets.
    Ok((bytes / 2) as usize)
}

pub(crate) fn classify_name_result(
    initialized_buffer: &[u16],
    returned_bytes: u32,
) -> Result<DesktopCategory, DesktopNameError> {
    let count = units_for_byte_length(returned_bytes)?;
    let name = initialized_buffer
        .get(..count)
        .ok_or(DesktopNameError::ResultExceedsBuffer)?;
    let (&terminator, body) = name
        .split_last()
        .ok_or(DesktopNameError::InvalidTerminator)?;
    if terminator != 0 || body.contains(&0) {
        return Err(DesktopNameError::InvalidTerminator);
    }
    if body.is_empty() {
        return Err(DesktopNameError::EmptyName);
    }
    // Strict conversion is deliberate: replacement characters could conceal a
    // malformed OS result. Only the category survives beyond this function.
    let decoded = String::from_utf16(body).map_err(|_| DesktopNameError::InvalidUtf16)?;
    Ok(if decoded.eq_ignore_ascii_case("Default") {
        DesktopCategory::Default
    } else if decoded.eq_ignore_ascii_case("Winlogon") {
        DesktopCategory::Winlogon
    } else {
        DesktopCategory::Other
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_DESKTOP_NAME_UNITS;

    fn classify(name: &str) -> Result<DesktopCategory, DesktopNameError> {
        let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
        classify_name_result(&units, (units.len() * 2) as u32)
    }

    #[test]
    fn known_names_use_ascii_case_insensitive_classification_only() {
        for name in ["Default", "default", "DEFAULT", "DeFaUlT"] {
            assert_eq!(classify(name), Ok(DesktopCategory::Default));
        }
        for name in ["Winlogon", "winlogon", "WINLOGON", "wInLoGoN"] {
            assert_eq!(classify(name), Ok(DesktopCategory::Winlogon));
        }
        for name in [
            "Other fixture",
            "Winlogon ",
            " Winlogon",
            "Winlogon\\Default",
            "Wіnlogon",
            "데스크톱",
            "😀",
        ] {
            assert_eq!(classify(name), Ok(DesktopCategory::Other));
        }
    }

    #[test]
    fn lengths_are_bytes_even_positive_and_bounded() {
        for bytes in [
            0,
            1,
            3,
            MAX_DESKTOP_NAME_BYTES + 1,
            MAX_DESKTOP_NAME_BYTES + 2,
            u32::MAX,
        ] {
            assert_eq!(
                units_for_byte_length(bytes),
                Err(DesktopNameError::InvalidByteLength)
            );
        }
        assert_eq!(units_for_byte_length(2), Ok(1));
        assert_eq!(
            units_for_byte_length(MAX_DESKTOP_NAME_BYTES),
            Ok(MAX_DESKTOP_NAME_UNITS)
        );
        assert_eq!(
            classify_name_result(&[65, 0], 6),
            Err(DesktopNameError::ResultExceedsBuffer)
        );
        assert_eq!(
            classify_name_result(&[], 2),
            Err(DesktopNameError::ResultExceedsBuffer)
        );
    }

    #[test]
    fn exact_maximum_name_fits_and_one_more_unit_fails() {
        let mut units = vec![65_u16; MAX_DESKTOP_NAME_UNITS];
        units[MAX_DESKTOP_NAME_UNITS - 1] = 0;
        assert_eq!(
            classify_name_result(&units, MAX_DESKTOP_NAME_BYTES),
            Ok(DesktopCategory::Other)
        );
        units.insert(0, 65);
        assert_eq!(
            classify_name_result(&units, MAX_DESKTOP_NAME_BYTES + 2),
            Err(DesktopNameError::InvalidByteLength)
        );
    }

    #[test]
    fn empty_missing_embedded_and_extra_nuls_are_rejected() {
        assert_eq!(
            classify_name_result(&[0], 2),
            Err(DesktopNameError::EmptyName)
        );
        for units in [vec![65], vec![65, 0, 66, 0], vec![65, 0, 0]] {
            assert_eq!(
                classify_name_result(&units, (units.len() * 2) as u32),
                Err(DesktopNameError::InvalidTerminator)
            );
        }
    }

    #[test]
    fn malformed_utf16_is_an_error_not_lossy_replacement() {
        for units in [
            vec![0xd800, 0],
            vec![0xdc00, 0],
            vec![0xd800, 65, 0],
            vec![0xdc00, 0xd800, 0],
        ] {
            assert_eq!(
                classify_name_result(&units, (units.len() * 2) as u32),
                Err(DesktopNameError::InvalidUtf16)
            );
        }
        assert_eq!(
            classify_name_result(&[0xd83d, 0xde00, 0], 6),
            Ok(DesktopCategory::Other)
        );
    }

    #[test]
    fn only_reported_initialized_units_are_read_and_other_text_is_redacted() {
        let mut units: Vec<u16> = "Default".encode_utf16().chain([0]).collect();
        let returned_bytes = (units.len() * 2) as u32;
        units.extend_from_slice(&[0xd800, 0xffff, 0]);
        assert_eq!(
            classify_name_result(&units, returned_bytes),
            Ok(DesktopCategory::Default)
        );
        let other = classify("fixture-private-desktop-name").unwrap();
        assert_eq!(format!("{other:?}"), "Other(redacted)");
        assert_eq!(format!("{other}"), "Other(redacted)");
        assert!(!format!("{other:?}").contains("fixture-private-desktop-name"));
    }
}
