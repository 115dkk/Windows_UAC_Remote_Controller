// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic protocol fixtures, not native rendering or authentication evidence.

#![forbid(unsafe_code)]

use approval_protocol::{
    ContentError, MAX_DETAILS_BYTES, MAX_PATH_BYTES, MAX_PROGRAM_NAME_BYTES,
    MAX_REQUEST_CONTENT_BYTES, RequestContent,
};
use sha2::{Digest, Sha256};

// Independent canonical vector construction. Display representations must never
// be substituted for the original UTF-8 field bytes in this record.
fn original_bytes_digest(program: &str, path: &str, details: &str) -> [u8; 32] {
    let mut bytes = b"Windows-UAC-Remote-Controller/request-content/v1\0\x00\x01".to_vec();
    for (tag, field) in [(1_u8, program), (2_u8, path), (3_u8, details)] {
        bytes.push(tag);
        bytes.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Sha256::digest(bytes).into()
}

#[test]
fn direction_controls_and_arabic_shaping_are_preserved_in_request_content_and_digest() {
    let program = "برنامج\u{200d}\u{200c} عربي \u{202e}extension.exe\u{202c}";
    let path = "C:\\ملفات\\invoice\u{202e}extension.exe\u{202c}";
    let details = "fixture-only \u{2066}argument\u{2069}\n\u{061c}نص عربي";
    let content = RequestContent::new(program, path, details).unwrap();
    assert_eq!(content.program_name().as_bytes(), program.as_bytes());
    assert_eq!(content.path().as_bytes(), path.as_bytes());
    assert_eq!(content.details().as_bytes(), details.as_bytes());
    assert_eq!(
        content.digest().as_bytes(),
        &original_bytes_digest(program, path, details)
    );

    let visible_program = "برنامج\u{200d}\u{200c} عربي [U+202E]extension.exe[U+202C]";
    let visible_path = "C:\\ملفات\\invoice[U+202E]extension.exe[U+202C]";
    let visible_details = "fixture-only [U+2066]argument[U+2069]\n[U+061C]نص عربي";
    let display_content =
        RequestContent::new(visible_program, visible_path, visible_details).unwrap();
    assert_ne!(content.digest(), display_content.digest());
    assert_ne!(
        content.digest().as_bytes(),
        &original_bytes_digest(visible_program, visible_path, visible_details)
    );
    // Rendering a separate value cannot normalize or consume the source object.
    assert_eq!(content.program_name(), program);
    assert_eq!(content.path(), path);
    assert_eq!(content.details(), details);
}

#[test]
fn all_direction_controls_remain_distinct_protocol_bytes() {
    let controls = [
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{206a}', '\u{206b}',
        '\u{206c}', '\u{206d}', '\u{206e}', '\u{206f}',
    ];
    let plain = RequestContent::new("fixtureextension.exe", "path", "details").unwrap();
    for control in controls {
        let program = format!("fixture{control}extension.exe");
        let content = RequestContent::new(&program, "path", "details").unwrap();
        assert_eq!(content.program_name(), program);
        assert_ne!(content.digest(), plain.digest());
        assert_eq!(
            content.digest().as_bytes(),
            &original_bytes_digest(&program, "path", "details")
        );
    }
}

#[test]
fn full_bound_content_retains_the_original_extension_and_uses_original_byte_limits() {
    let suffix = "\u{202e}extension.exe";
    let bounded = |maximum: usize| format!("{}{suffix}", "a".repeat(maximum - suffix.len()));
    let program = bounded(MAX_PROGRAM_NAME_BYTES);
    let path = bounded(MAX_PATH_BYTES);
    let details = bounded(MAX_DETAILS_BYTES);
    let content = RequestContent::new(&program, &path, &details).unwrap();
    assert_eq!(content.program_name(), program);
    assert_eq!(content.path(), path);
    assert_eq!(content.details(), details);
    assert_eq!(
        content.program_name().len() + content.path().len() + content.details().len(),
        MAX_REQUEST_CONTENT_BYTES
    );
    assert!(content.program_name().ends_with(suffix));
    assert!(content.path().ends_with(suffix));
    assert!(content.details().ends_with(suffix));
    assert_eq!(
        content.digest().as_bytes(),
        &original_bytes_digest(&program, &path, &details)
    );
    // Display expansion is permitted at presentation time, not before protocol
    // validation: this escaped representation exceeds the original field limit.
    let expanded_program = program.replace('\u{202e}', "[U+202E]");
    assert!(expanded_program.len() > MAX_PROGRAM_NAME_BYTES);
    assert_eq!(
        RequestContent::new(&expanded_program, &path, &details),
        Err(ContentError::InvalidLength)
    );
}
