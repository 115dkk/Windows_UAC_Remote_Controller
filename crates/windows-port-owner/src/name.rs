// SPDX-License-Identifier: GPL-2.0-or-later

// Unicode 17.0 General_Category=Cf, from
// https://www.unicode.org/Public/17.0.0/ucd/extracted/DerivedGeneralCategory.txt.
// Cc is supplied by char::is_control. No new Unicode runtime dependency.
fn hidden(value: char) -> bool {
    value.is_control()
        || matches!(value as u32,
            0x00ad | 0x0600..=0x0605 | 0x061c | 0x06dd | 0x070f |
            0x0890..=0x0891 | 0x08e2 | 0x180e | 0x200b..=0x200f |
            0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f |
            0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd |
            0x13430..=0x1343f | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a |
            0xe0001 | 0xe0020..=0xe007f)
}

pub(super) fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 64
        && !value
            .chars()
            .any(|c| hidden(c) || matches!(c, '/' | '\\' | ':'))
}

#[cfg(any(windows, test))]
pub(super) fn sanitize(units: &[u16]) -> Option<String> {
    let path = String::from_utf16_lossy(units);
    // Split BEFORE filtering/truncation: directory text must never become a name.
    let name: String = path
        .rsplit(['/', '\\', ':'])
        .next()?
        .chars()
        .filter(|c| !hidden(*c))
        .take(64)
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(value: &str) -> Option<String> {
        sanitize(&value.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn strips_paths_controls_and_format_characters_before_capping_chars() {
        assert_eq!(
            clean("C:\\private\\bank\\vera\u{202e}port.exe"),
            Some("veraport.exe".into())
        );
        assert_eq!(
            clean("/private/한\n글\u{e0001}.exe"),
            Some("한글.exe".into())
        );
        assert_eq!(clean("C:bank.exe"), Some("bank.exe".into()));
        assert_eq!(clean("C:\\private\\"), None);
        assert_eq!(clean("\u{0}\u{ad}\u{2066}"), None);
        assert_eq!(
            clean(&format!("C:\\private\\{}", "한".repeat(70)))
                .unwrap()
                .chars()
                .count(),
            64
        );
        assert_eq!(
            sanitize(&[0xd800, 0x2e, 0x65, 0x78, 0x65]),
            Some("�.exe".into())
        );
    }

    #[test]
    fn validates_wire_names_with_the_same_bound_and_categories() {
        assert!(valid(&"한".repeat(64)));
        for value in [
            "",
            "C:\\private\\a.exe",
            "a/b",
            "a\n",
            "a\u{202e}",
            "a\u{1343f}",
        ] {
            assert!(!valid(value));
        }
        assert!(!valid(&"a".repeat(65)));
    }
}
