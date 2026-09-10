// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic status data only. No HTTPS, trust roots, clocks or device evidence.

use super::{MAX_BODY_BYTES, MAX_ENTRIES, MAX_SERIAL_BYTES, RevocationList};
use crate::VerificationError;

fn parse(text: &str) -> RevocationList {
    RevocationList::parse(text.as_bytes()).expect("synthetic status document")
}

fn malformed(text: &str) {
    assert!(
        matches!(
            RevocationList::parse(text.as_bytes()),
            Err(VerificationError::Der)
        ),
        "synthetic malformed document must fail"
    );
}

fn bounded(text: &str) {
    assert!(
        matches!(
            RevocationList::parse(text.as_bytes()),
            Err(VerificationError::Bounds)
        ),
        "synthetic oversized document must fail"
    );
}

fn rows(count: usize) -> String {
    let mut document = String::from("{\"entries\":{");
    for serial in 1..=count {
        if serial != 1 {
            document.push(',');
        }
        document.push_str(&format!("\"{serial:x}\":{{\"status\":\"REVOKED\"}}"));
    }
    document.push_str("}}");
    document
}

#[test]
fn empty_entries_are_data_not_a_trusted_or_fresh_snapshot() {
    let list = parse(r#"{"entries":{}}"#);
    assert!(list.serials.is_empty());
    assert!(!list.contains_serial(&[1]).unwrap());
    // There is deliberately no clock, HTTPS assertion or freshness constructor.
}

#[test]
fn both_documented_statuses_are_rejection_members() {
    let list = parse(r#"{"entries":{"a":{"status":"REVOKED"},"bc":{"status":"SUSPENDED"}}}"#);
    assert!(list.contains_serial(&[0x0a]).unwrap());
    assert!(list.contains_serial(&[0xbc]).unwrap());
    assert!(!list.contains_serial(&[0x0b]).unwrap());
}

#[test]
fn digit_only_serials_are_hexadecimal_never_decimal() {
    let list = parse(r#"{"entries":{"10":{"status":"REVOKED"},"1234":{"status":"SUSPENDED"}}}"#);
    assert!(list.contains_serial(&[0x10]).unwrap());
    assert!(list.contains_serial(&[0x12, 0x34]).unwrap());
    assert!(!list.contains_serial(&[10]).unwrap());
    assert!(!list.contains_serial(&[0x04, 0xd2]).unwrap());
}

#[test]
fn odd_hex_lengths_and_high_bit_magnitudes_are_supported() {
    let list = parse(
        r#"{"entries":{"1":{"status":"REVOKED"},"abc":{"status":"REVOKED"},"80":{"status":"REVOKED"}}}"#,
    );
    assert!(list.contains_serial(&[1]).unwrap());
    assert!(list.contains_serial(&[0x0a, 0xbc]).unwrap());
    assert!(list.contains_serial(&[0x80]).unwrap());
    assert!(!list.contains_serial(&[0xab, 0x0c]).unwrap());
}

#[test]
fn lookup_normalizes_only_a_bounded_leading_zero_representation() {
    let list = parse(r#"{"entries":{"abc":{"status":"REVOKED"}}}"#);
    assert!(list.contains_serial(&[0, 0x0a, 0xbc]).unwrap());
    assert!(list.contains_serial(&[0, 0, 0x0a, 0xbc]).unwrap());
    assert!(!list.contains_serial(&[0x0a, 0xbc, 0]).unwrap());
    for serial in [&[][..], &[0][..], &[0, 0][..]] {
        assert!(matches!(
            list.contains_serial(serial),
            Err(VerificationError::Der)
        ));
    }
    assert!(matches!(
        list.contains_serial(&[0; MAX_SERIAL_BYTES + 2]),
        Err(VerificationError::Bounds)
    ));
}

#[test]
fn serial_magnitude_has_an_exact_32_byte_limit() {
    let key = "ff".repeat(MAX_SERIAL_BYTES);
    let document = format!(r#"{{"entries":{{"{key}":{{"status":"REVOKED"}}}}}}"#);
    let list = parse(&document);
    assert!(list.contains_serial(&[0xff; MAX_SERIAL_BYTES]).unwrap());
    let mut padded = vec![0];
    padded.extend_from_slice(&[0xff; MAX_SERIAL_BYTES]);
    assert!(list.contains_serial(&padded).unwrap());
    assert!(matches!(
        list.contains_serial(&[1; MAX_SERIAL_BYTES + 1]),
        Err(VerificationError::Bounds)
    ));
    let too_long = "f".repeat(MAX_SERIAL_BYTES * 2 + 1);
    bounded(&format!(
        r#"{{"entries":{{"{too_long}":{{"status":"REVOKED"}}}}}}"#
    ));
}

#[test]
fn zero_padded_uppercase_and_non_hex_keys_are_not_repaired() {
    for key in [
        "", "0", "00", "01", "0a", "A", "aB", "0x10", "-1", "+1", "1.0", " 1", "1 ", "１２", "g",
    ] {
        let document = serde_json::json!({"entries": {(key): {"status": "REVOKED"}}});
        malformed(&document.to_string());
    }
}

#[test]
fn duplicate_root_field_including_json_escaped_alias_is_rejected() {
    malformed(r#"{"entries":{},"entries":{}}"#);
    malformed(r#"{"entries":{},"entr\u0069es":{}}"#);
}

#[test]
fn duplicate_serial_magnitudes_including_escaped_keys_are_rejected() {
    malformed(r#"{"entries":{"1":{"status":"REVOKED"},"1":{"status":"REVOKED"}}}"#);
    malformed(r#"{"entries":{"1":{"status":"REVOKED"},"\u0031":{"status":"SUSPENDED"}}}"#);
    // Noncanonical zero padding cannot create a second normalized identity.
    malformed(r#"{"entries":{"1":{"status":"REVOKED"},"01":{"status":"SUSPENDED"}}}"#);
    malformed(r#"{"entries":{"0":{"status":"REVOKED"},"00":{"status":"REVOKED"}}}"#);
}

#[test]
fn duplicate_row_fields_are_rejected_even_when_values_agree() {
    for extra in [
        r#""status":"REVOKED""#,
        r#""reason":"UNSPECIFIED","reason":"UNSPECIFIED""#,
        r#""comment":"synthetic","comment":"synthetic""#,
        r#""expires":"2000-01-01","expires":"2000-01-01""#,
        r#""st\u0061tus":"REVOKED""#,
    ] {
        malformed(&format!(
            r#"{{"entries":{{"a":{{"status":"REVOKED",{extra}}}}}}}"#
        ));
    }
}

#[test]
fn missing_required_fields_and_wrong_container_types_fail() {
    for document in [
        "",
        "null",
        "[]",
        "{}",
        r#""entries""#,
        r#"{"entries":null}"#,
        r#"{"entries":[]}"#,
        r#"{"entries":{"1":null}}"#,
        r#"{"entries":{"1":[]}}"#,
        r#"{"entries":{"1":"REVOKED"}}"#,
        r#"{"entries":{"1":{}}}"#,
        r#"{"entries":{"1":{"reason":"UNSPECIFIED"}}}"#,
    ] {
        malformed(document);
    }
}

#[test]
fn unknown_fields_are_rejected_at_every_schema_level() {
    malformed(r#"{"entries":{},"extra":{}}"#);
    malformed(r#"{"entries":{"1":{"status":"REVOKED","extra":true}}}"#);
    malformed(r#"{"entries":{"1":{"status":"REVOKED","entries":{}}}}"#);
    malformed(r#"{"status":"REVOKED","entries":{}}"#);
    malformed(r#"{"entries":{"reason":{"status":"REVOKED"}}}"#);
}

#[test]
fn unknown_status_or_wrong_status_scalar_never_becomes_an_empty_list() {
    for value in [
        serde_json::json!("VALID"),
        serde_json::json!("UNKNOWN"),
        serde_json::json!("revoked"),
        serde_json::json!("REVOKED\u{0}"),
        serde_json::json!(null),
        serde_json::json!(true),
        serde_json::json!(1),
    ] {
        malformed(&serde_json::json!({"entries":{"1":{"status":value}}}).to_string());
    }
}

#[test]
fn all_documented_reasons_are_accepted_but_unknown_reason_is_rejected() {
    for reason in [
        "UNSPECIFIED",
        "KEY_COMPROMISE",
        "CA_COMPROMISE",
        "SUPERSEDED",
        "SOFTWARE_FLAW",
    ] {
        let list = parse(
            &serde_json::json!({"entries":{"1":{"status":"SUSPENDED","reason":reason}}})
                .to_string(),
        );
        assert!(list.contains_serial(&[1]).unwrap());
    }
    malformed(r#"{"entries":{"1":{"status":"REVOKED","reason":"OTHER"}}}"#);
    malformed(r#"{"entries":{"1":{"status":"REVOKED","reason":null}}}"#);
}

#[test]
fn optional_expiry_and_reason_do_not_locally_unrevoke_published_entries() {
    let list = parse(
        r#"{"entries":{"1":{"status":"REVOKED","expires":"2000-01-01","reason":"SUPERSEDED","comment":"synthetic old status"},"2":{"status":"SUSPENDED","expires":"9999-12-31","reason":"SOFTWARE_FLAW"}}}"#,
    );
    assert!(list.contains_serial(&[1]).unwrap());
    assert!(list.contains_serial(&[2]).unwrap());
}

#[test]
fn expiry_uses_documented_calendar_date_shape_not_a_timestamp_or_clock() {
    for date in ["2024-02-29", "2000-02-29", "2023-12-31", "0000-01-01"] {
        assert!(
            parse(
                &serde_json::json!({"entries":{"1":{"status":"REVOKED","expires":date}}})
                    .to_string()
            )
            .contains_serial(&[1])
            .unwrap()
        );
    }
    for date in [
        "2023-02-29",
        "1900-02-29",
        "2024-00-01",
        "2024-13-01",
        "2024-01-00",
        "2024-04-31",
        "2024-1-01",
        "2024/01/01",
        "abcd-01-01",
        "",
    ] {
        malformed(
            &serde_json::json!({"entries":{"1":{"status":"REVOKED","expires":date}}}).to_string(),
        );
    }
    bounded(r#"{"entries":{"1":{"status":"REVOKED","expires":"2024-01-01T00:00:00Z"}}}"#);
}

#[test]
fn comment_limit_counts_unicode_characters_not_utf8_bytes() {
    for comment in [
        "a".repeat(140),
        "가".repeat(140),
        "🦀".repeat(140),
        String::new(),
    ] {
        let list = parse(
            &serde_json::json!({"entries":{"1":{"status":"REVOKED","comment":comment}}})
                .to_string(),
        );
        assert!(list.contains_serial(&[1]).unwrap());
    }
    for comment in ["a".repeat(141), "🦀".repeat(141)] {
        bounded(
            &serde_json::json!({"entries":{"1":{"status":"REVOKED","comment":comment}}})
                .to_string(),
        );
    }
}

#[test]
fn escaped_strings_are_validated_after_decoding_and_not_retained_in_debug() {
    let list = parse(
        r#"{"entries":{"\u0061":{"status":"RE\u0056OKED","comment":"synthetic-secret-marker\n\u0000","expires":"2000-01-01"}}}"#,
    );
    assert!(list.contains_serial(&[10]).unwrap());
    let debug = format!("{list:?}");
    assert!(debug.contains("entries: 1"));
    assert!(!debug.contains("synthetic-secret-marker"));
    assert!(!debug.contains("REVOKED"));
    assert!(!debug.contains("2000-01-01"));
}

#[test]
fn malformed_utf8_and_unicode_surrogates_are_rejected() {
    let mut bytes = br#"{"entries":{"1":{"status":"REVOKED","comment":""#.to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(br#""}}}"#);
    assert!(matches!(
        RevocationList::parse(&bytes),
        Err(VerificationError::Der)
    ));
    malformed(r#"{"entries":{"1":{"status":"REVOKED","comment":"\ud800"}}}"#);
}

#[test]
fn nested_non_string_values_and_deep_unknown_payloads_are_not_walked() {
    for field in ["status", "comment", "reason", "expires"] {
        let mut document = format!("{{\"entries\":{{\"1\":{{\"{field}\":");
        document.push_str(&"[".repeat(256));
        document.push('0');
        document.push_str(&"]".repeat(256));
        document.push_str("}}}");
        malformed(&document);
    }
    malformed(r#"{"entries":{"1":{"status":{"status":"REVOKED"}}}}"#);
}

#[test]
fn trailing_documents_truncation_and_non_json_syntax_fail() {
    for document in [
        r#"{"entries":{}} {"entries":{}}"#,
        r#"{"entries":{},}"#,
        r#"{"entries":{"1":{"status":"REVOKED"}}"#,
        r#"{/* synthetic comment */"entries":{}}"#,
    ] {
        malformed(document);
    }
    assert!(parse(" \n{\"entries\":{}}\t\r\n").serials.is_empty());
}

#[test]
fn field_status_reason_and_serial_strings_are_bounded() {
    bounded(&serde_json::json!({"entries":{"1":{"status":"x".repeat(10)}}}).to_string());
    bounded(
        &serde_json::json!({"entries":{"1":{"status":"REVOKED","reason":"x".repeat(15)}}})
            .to_string(),
    );
    bounded(r#"{"entries":{},"long_field_name":"synthetic"}"#);
}

#[test]
fn whole_body_bound_precedes_json_parsing() {
    assert!(matches!(
        RevocationList::parse(&vec![b' '; MAX_BODY_BYTES + 1]),
        Err(VerificationError::Bounds)
    ));
    let mut exact = br#"{"entries":{}}"#.to_vec();
    exact.resize(MAX_BODY_BYTES, b' ');
    assert!(RevocationList::parse(&exact).unwrap().serials.is_empty());
}

#[test]
fn entry_count_has_an_exact_32768_bound() {
    let exact = rows(MAX_ENTRIES);
    assert!(exact.len() < MAX_BODY_BYTES);
    let list = parse(&exact);
    assert_eq!(list.serials.len(), MAX_ENTRIES);
    assert!(list.contains_serial(&[0x80, 0]).unwrap());
    bounded(&rows(MAX_ENTRIES + 1));
}
