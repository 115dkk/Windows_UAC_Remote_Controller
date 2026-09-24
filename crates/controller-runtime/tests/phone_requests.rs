// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic native DTOs only. No peer, authentication or native OS exercised.
use controller_runtime::{
    MAX_PHONE_REQUEST_DETAILS_JSON_BYTES, MAX_PHONE_REQUESTS_JSON_BYTES, PcConnectionFailure,
    PcConnectionView, RequestCatalogState, check_request_locator,
    decode_phone_request_details_json, decode_phone_requests_json,
};
use serde_json::{Value, json};

const LOCATOR: &str = "0123456789abcdef0123456789abcdef";

fn row() -> Value {
    json!({"id":LOCATOR,"computerName":"연결한 PC","programName":"PowerShell",
        "executablePath":"C:\\example\\pwsh.exe","programElided":false,"pathElided":false,
        "hasDetails":true,"remainingSeconds":42,"refreshAfterMillis":1000,
        "state":"pending","canApprove":true,"canDeny":true})
}

fn catalog() -> Value {
    json!({"version":2,"status":"ready","revision":"18446744073709551615",
        "peerCount":1,"connectedPeerCount":1,"peers":[{"id":"1".repeat(64),"revision":"1","routePresent":true,"connected":true}],"requests":[row()]})
}

fn details() -> Value {
    json!({"version":1,"id":LOCATOR,"programName":"PowerShell",
        "executablePath":"C:\\example\\pwsh.exe","details":"<not-markup>\n\t\"original\"",
        "remainingSeconds":42,"refreshAfterMillis":1000})
}

#[test]
fn decision_receipts_are_optional_bounded_and_strict_display_only() {
    assert!(
        decode_phone_requests_json(&serde_json::to_vec(&catalog()).unwrap())
            .unwrap()
            .catalog
            .decisions
            .is_empty()
    );
    let decision = json!({"id": LOCATOR, "action":"approve", "phase":"approved",
        "elapsedMillis":1300, "timingAvailable":true, "authenticationMillis":1000, "afterAuthenticationMillis":300});
    let mut document = catalog();
    document["decisions"] = json!([decision.clone()]);
    assert_eq!(
        decode_phone_requests_json(&serde_json::to_vec(&document).unwrap())
            .unwrap()
            .catalog
            .decisions
            .len(),
        1
    );
    for (key, invalid) in [
        ("id", json!("unknown")),
        ("action", json!("execute")),
        ("phase", json!("socket_written")),
        ("elapsedMillis", json!(300001)),
        ("authenticationMillis", json!(1301)),
        ("afterAuthenticationMillis", json!(400)),
        ("requestBody", json!("not permitted")),
        ("action", json!("deny")),
        ("phase", json!("awaiting_pc")),
        ("timingAvailable", json!(false)),
    ] {
        let mut invalid_document = document.clone();
        invalid_document["decisions"][0][key] = invalid;
        assert!(
            decode_phone_requests_json(&serde_json::to_vec(&invalid_document).unwrap()).is_err()
        );
    }
    document["decisions"] = json!([decision.clone(), decision]);
    assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
}

fn disconnected() -> Value {
    let mut document = catalog();
    document["connectedPeerCount"] = json!(0);
    document["peers"][0]["connected"] = json!(false);
    document
}

fn decode(document: &Value) -> Result<controller_runtime::PhoneRequestCatalog, ()> {
    decode_phone_requests_json(&serde_json::to_vec(document).unwrap()).map_err(|_| ())
}

#[test]
fn connection_diagnosis_is_optional_and_presented_exactly() {
    assert_eq!(decode(&catalog()).unwrap().catalog.connection, None);
    let mut document = disconnected();
    document["connection"] = Value::Null;
    assert_eq!(decode(&document).unwrap().catalog.connection, None);
    for (dialing, failure, external) in [
        (true, Value::Null, false),
        (false, json!("unreachable"), false),
        (false, json!("refused"), true),
        (true, json!("no_answer"), true),
    ] {
        let connection = json!({"dialing":dialing,"lastFailure":failure,"externalRoute":external});
        document["connection"] = connection.clone();
        let value = decode(&document).unwrap();
        let expected = PcConnectionView {
            dialing,
            last_failure: match failure.as_str() {
                None => None,
                Some("unreachable") => Some(PcConnectionFailure::Unreachable),
                Some("refused") => Some(PcConnectionFailure::Refused),
                Some(_) => Some(PcConnectionFailure::NoAnswer),
            },
            external_route: external,
        };
        assert_eq!(value.catalog.connection, Some(expected));
        // The presentation receives the same shape the native side sent.
        assert_eq!(
            serde_json::to_value(&value.catalog).unwrap()["connection"],
            connection
        );
    }
    // A fully connected catalogue may still say whether an outside route exists.
    let mut connected = catalog();
    connected["connection"] = json!({"dialing":false,"lastFailure":null,"externalRoute":true});
    assert!(decode(&connected).unwrap().catalog.connection.is_some());
    assert_eq!(
        serde_json::to_value(&decode(&catalog()).unwrap().catalog).unwrap()["connection"],
        Value::Null
    );
}

#[test]
fn connection_diagnosis_rejects_unknown_incomplete_and_contradictory_values() {
    let valid = json!({"dialing":true,"lastFailure":"refused","externalRoute":false});
    let mut document = disconnected();
    document["connection"] = valid.clone();
    assert!(decode(&document).is_ok());
    for (key, invalid) in [
        ("lastFailure", json!("timeout")),
        ("lastFailure", json!("")),
        ("lastFailure", json!(1)),
        ("dialing", json!("true")),
        ("dialing", Value::Null),
        ("externalRoute", json!(1)),
        ("externalRoute", Value::Null),
        ("address", json!("192.0.2.1:7443")),
    ] {
        let mut invalid_document = document.clone();
        invalid_document["connection"][key] = invalid;
        assert!(decode(&invalid_document).is_err(), "{key}");
    }
    for key in ["dialing", "lastFailure", "externalRoute"] {
        let mut invalid_document = document.clone();
        invalid_document["connection"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        assert!(decode(&invalid_document).is_err(), "missing {key}");
    }
    for invalid in [json!(true), json!("dialing"), json!([valid.clone()])] {
        let mut invalid_document = document.clone();
        invalid_document["connection"] = invalid;
        assert!(decode(&invalid_document).is_err());
    }
    // Every paired PC connected: nothing is being dialled and nothing failed.
    for connection in [
        json!({"dialing":true,"lastFailure":null,"externalRoute":false}),
        json!({"dialing":false,"lastFailure":"no_answer","externalRoute":false}),
    ] {
        let mut contradictory = catalog();
        contradictory["connection"] = connection;
        assert!(decode(&contradictory).is_err());
    }
    // No paired PC: there is nothing to describe.
    let mut unpaired = catalog();
    unpaired["requests"] = json!([]);
    unpaired["peerCount"] = json!(0);
    unpaired["connectedPeerCount"] = json!(0);
    unpaired["peers"] = json!([]);
    assert!(decode(&unpaired).is_ok());
    unpaired["connection"] = json!({"dialing":false,"lastFailure":null,"externalRoute":false});
    assert!(decode(&unpaired).is_err());
}

#[test]
fn unavailable_catalogue_drops_the_connection_diagnosis() {
    let mut document = disconnected();
    document["connection"] = json!({"dialing":true,"lastFailure":"no_answer","externalRoute":true});
    for (status, kept) in [
        ("unavailable", false),
        ("reconciling", true),
        ("ready", true),
    ] {
        document["status"] = json!(status);
        assert_eq!(
            decode(&document).unwrap().catalog.connection.is_some(),
            kept,
            "{status}"
        );
    }
}

#[test]
fn local_feedback_is_distinct_from_pc_results_and_has_no_pc_latency() {
    for phase in [
        "authenticating",
        "preparing",
        "sending",
        "awaiting_pc",
        "authentication_cancelled",
        "local_unconfirmed",
    ] {
        let mut document = catalog();
        document["decisions"] = json!([{"id":LOCATOR, "action":"approve", "phase":phase,
            "elapsedMillis":120, "authenticationMillis":null, "afterAuthenticationMillis":null}]);
        assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_ok());
        document["decisions"][0]["authenticationMillis"] = json!(100);
        document["decisions"][0]["afterAuthenticationMillis"] = json!(20);
        assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
    }
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
        ("version", json!(1)),
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
        assert_eq!(value.devices.len(), usize::from(status == "reconciling"));
    }
    let mut empty = catalog();
    empty["requests"] = json!([]);
    empty["peerCount"] = json!(0);
    empty["connectedPeerCount"] = json!(0);
    empty["peers"] = json!([]);
    let value = decode_phone_requests_json(&serde_json::to_vec(&empty).unwrap()).unwrap();
    assert_eq!(value.catalog.peer_count, 0);
    assert_eq!(value.catalog.connected_peer_count, 0);
}

#[test]
fn paired_pc_rows_require_complete_bounded_metadata_and_observed_connection() {
    let mut document = catalog();
    let value = decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(value.devices.len(), 1);
    assert!(value.devices[0].connected);
    document["connectedPeerCount"] = json!(0);
    document["peers"][0]["connected"] = json!(false);
    let value = decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(!value.devices[0].connected);
    assert_eq!(value.devices[0].name, "PC 111111111111");
    for (field, invalid) in [
        ("id", json!("0".repeat(64))),
        ("id", json!("1".repeat(65))),
        ("revision", json!("0")),
        ("revision", json!("01")),
        ("revision", json!("9007199254740992")),
        ("connected", json!(true)),
    ] {
        let mut invalid_document = document.clone();
        invalid_document["peers"][0][field] = invalid;
        assert!(
            decode_phone_requests_json(&serde_json::to_vec(&invalid_document).unwrap()).is_err()
        );
    }
    document["peers"] = json!([]);
    assert!(decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).is_err());
}

#[test]
fn localized_native_computer_labels_do_not_hide_the_paired_pc_catalogue() {
    for label in ["연결한 PC", "Paired PC", "Gekoppelter PC", "接続済みの PC"] {
        let mut document = catalog();
        document["requests"][0]["computerName"] = json!(label);
        let value = decode_phone_requests_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(value.requests[0].computer_name, label);
        assert_eq!(value.devices.len(), 1);
    }
}

#[test]
fn rows_reject_contradictions_lossy_display_and_authority_fields() {
    for (field, invalid) in [
        ("id", json!("../../key")),
        ("computerName", json!("")),
        ("computerName", json!("x".repeat(129))),
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
