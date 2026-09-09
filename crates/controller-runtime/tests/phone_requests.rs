// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic native DTOs only. No peer, authentication or native OS exercised.
use controller_runtime::{
    MAX_PHONE_REQUEST_DETAILS_JSON_BYTES, MAX_PHONE_REQUESTS_JSON_BYTES, RequestCatalogState,
    check_request_locator, decode_phone_request_details_json, decode_phone_requests_json,
};
use serde_json::{Value, json};

const LOCATOR: &str = "0123456789abcdef0123456789abcdef";

fn row() -> Value {
    json!({"id":LOCATOR,"computerName":"연결한 컴퓨터","programName":"PowerShell",
        "executablePath":"C:\\example\\pwsh.exe","programElided":false,"pathElided":false,
        "hasDetails":true,"remainingSeconds":42,"refreshAfterMillis":1000,
        "state":"pending","canApprove":true,"canDeny":true})
}

fn catalog() -> Value {
    json!({"version":1,"status":"ready","revision":"18446744073709551615",
        "peerCount":1,"connectedPeerCount":1,"requests":[row()]})
}

fn details() -> Value {
    json!({"version":1,"id":LOCATOR,"programName":"PowerShell",
        "executablePath":"C:\\example\\pwsh.exe","details":"<not-markup>\n\t\"original\"",
        "remainingSeconds":42,"refreshAfterMillis":1000})
}

#[test]
fn catalogue_is_strict_bounded_and_never_contains_bulk_commands() {
    let value = decode_phone_requests_json(&serde_json::to_vec(&catalog()).unwrap()).unwrap();
    assert_eq!(value.catalog.revision, u64::MAX.to_string());
    assert_eq!(value.catalog.status, RequestCatalogState::Ready);
    assert_eq!(value.requests.len(), 1);
    assert!(
        serde_json::to_value(&value.requests).unwrap()[0]
            .get("details")
            .is_none()
    );
    for (field, invalid) in [
        ("version", json!(2)),
        ("status", json!("connected")),
        ("revision", json!(9007199254740993_u64)),
        ("revision", json!("01")),
        ("revision", json!("+1")),
        ("revision", json!("18446744073709551616")),
        ("peerCount", json!(33)),
        ("peerCount", json!(0)),
        ("connectedPeerCount", json!(2)),
        ("authenticated", json!(true)),
    ] {
        let mut document = catalog();
        document[field] = invalid;
        assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
    }
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; MAX_PHONE_REQUESTS_JSON_BYTES + 1],
    ] {
        assert!(decode_phone_requests_json(&bytes).is_err());
    }
}

#[test]
fn nonready_is_not_a_known_empty_inventory_and_zero_peers_is_not_connected() {
    for status in ["unavailable", "reconciling"] {
        let mut document = catalog();
        document["status"] = json!(status);
        let value = decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_ne!(value.catalog.status, RequestCatalogState::Ready);
        assert!(value.requests.is_empty());
    }
    let mut empty = catalog();
    empty["requests"] = json!([]);
    empty["peerCount"] = json!(0);
    empty["connectedPeerCount"] = json!(0);
    let value = decode_phone_requests_json(&serde_json::to_vec(&empty).unwrap()).unwrap();
    assert_eq!(value.catalog.peer_count, 0);
    assert_eq!(value.catalog.connected_peer_count, 0);
}

#[test]
fn rows_reject_contradictions_lossy_display_and_authority_fields() {
    for (field, invalid) in [
        ("id", json!("../../key")),
        ("computerName", json!("invented host")),
        ("programName", json!("a".repeat(513))),
        ("executablePath", json!("😀".repeat(513))),
        ("programName", json!("bad\0name")),
        ("remainingSeconds", json!(0)),
        ("remainingSeconds", json!(301)),
        ("refreshAfterMillis", json!(60001)),
        ("refreshAfterMillis", json!(42001)),
        ("state", json!("expired")),
        ("state", json!("authenticating")),
        ("details", json!("unexpected bulk body")),
        ("signature", json!("unexpected authority")),
    ] {
        let mut document = catalog();
        document["requests"][0][field] = invalid;
        assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
    }
    let mut document = catalog();
    document["requests"][0]["programElided"] = json!(true);
    document["requests"][0]["hasDetails"] = json!(false);
    assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
    for rows in [vec![row(), row()], (0..33).map(|_| row()).collect()] {
        let mut document = catalog();
        document["requests"] = json!(rows);
        assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
    }
}

#[test]
fn denial_hint_may_remain_available_during_local_authentication() {
    for state in ["authenticating", "waiting", "sending", "awaiting_outcome"] {
        let mut document = catalog();
        document["requests"][0]["state"] = json!(state);
        document["requests"][0]["canApprove"] = json!(false);
        let value = decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(!value.requests[0].can_approve);
        assert!(value.requests[0].can_deny);
    }
}

#[test]
fn on_demand_details_preserve_exact_text_but_do_not_log_it() {
    let document = details();
    let value = decode_phone_request_details_json(&serde_json::to_vec(&document).unwrap(), LOCATOR)
        .unwrap();
    assert_eq!(value.details, document["details"].as_str().unwrap());
    assert!(!format!("{value:?}").contains("original"));
    assert!(!format!("{value:?}").contains(LOCATOR));
    assert!(
        decode_phone_request_details_json(&serde_json::to_vec(&document).unwrap(), &"a".repeat(32))
            .is_err()
    );
}

#[test]
fn details_allow_worst_case_escaped_original_fields_without_unbounded_input() {
    let mut document = details();
    for field in ["programName", "executablePath", "details"] {
        document[field] = json!("\u{0001}".repeat(96 * 1024));
    }
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(bytes.len() < MAX_PHONE_REQUEST_DETAILS_JSON_BYTES);
    assert!(decode_phone_request_details_json(&bytes, LOCATOR).is_ok());
    document["details"] = json!("a".repeat(96 * 1024 + 1));
    assert!(
        decode_phone_request_details_json(&serde_json::to_vec(&document).unwrap(), LOCATOR)
            .is_err()
    );
    assert!(
        decode_phone_request_details_json(
            &vec![b' '; MAX_PHONE_REQUEST_DETAILS_JSON_BYTES + 1],
            LOCATOR
        )
        .is_err()
    );
}

#[test]
fn locator_and_details_accept_no_renderer_authentication_claim() {
    assert!(check_request_locator(LOCATOR).is_ok());
    for invalid in ["", "x", "0123456789ABCDEF0123456789ABCDEF"] {
        assert!(check_request_locator(invalid).is_err());
    }
    for (field, invalid) in [
        ("version", json!(2)),
        ("details", json!("x\0")),
        ("authenticated", json!(true)),
        ("deadlineNanos", json!(1)),
        ("refreshAfterMillis", json!(60001)),
    ] {
        let mut document = details();
        document[field] = invalid;
        assert!(
            decode_phone_request_details_json(&serde_json::to_vec(&document).unwrap(), LOCATOR)
                .is_err()
        );
    }
}
