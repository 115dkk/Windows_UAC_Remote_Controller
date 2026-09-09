// SPDX-License-Identifier: GPL-2.0-or-later
use controller_runtime::{
    ActivityKind, AppSnapshot, Availability, MAX_PHONE_HISTORY_JSON_BYTES, MobileReadiness,
    NotificationPolicy, decode_phone_history_json, encode_phone_history,
};
use serde_json::json;

#[test]
fn exact_native_terminal_projection_does_not_invent_windows_approval() {
    let records = decode_phone_history_json(
        &serde_json::to_vec(&json!({
            "schemaVersion":1, "records":[
                {"id":"a".repeat(64),"timestampMillis":900,"kind":"pc_completed"},
                {"id":"b".repeat(64),"timestampMillis":1000,"kind":"expired"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(records[0].kind, ActivityKind::PcCompleted);
    assert_eq!(records[0].timestamp_millis, 900);
    assert_eq!(records[1].timestamp_millis, 1000);
    let snapshot = AppSnapshot::from_android_policy_and_history(
        NotificationPolicy::default(),
        MobileReadiness::UNAVAILABLE,
        Some(records),
    );
    assert_eq!(snapshot.data_availability.activity, Availability::Available);
    assert_eq!(
        snapshot.data_availability.requests,
        Availability::Unavailable
    );
    assert!(snapshot.can_clear_activity);
    assert!(!snapshot.can_pair);
    assert!(snapshot.requests.is_empty());
}

#[test]
fn unavailable_history_is_distinct_from_a_confirmed_empty_native_history() {
    for (input, expected) in [
        (None, Availability::Unavailable),
        (Some(Vec::new()), Availability::Available),
    ] {
        let snapshot = AppSnapshot::from_android_policy_and_history(
            NotificationPolicy::default(),
            MobileReadiness::UNAVAILABLE,
            input,
        );
        assert_eq!(snapshot.data_availability.activity, expected);
        assert!(!snapshot.can_clear_activity);
    }
    assert_eq!(
        encode_phone_history(&[]).unwrap(),
        r#"{"schemaVersion":1,"records":[]}"#
    );
    assert!(
        decode_phone_history_json(br#"{"schemaVersion":1,"records":[]}"#)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn history_bridge_rejects_unknown_false_success_duplicate_and_excessive_data() {
    let row = json!({"id":"a".repeat(64),"timestampMillis":1,"kind":"expired"});
    for value in [
        json!({}),
        json!({"schemaVersion":2,"records":[]}),
        json!({"schemaVersion":1,"records":[],"authenticated":true}),
        json!({"schemaVersion":1,"records":[row.clone(),row.clone()]}),
        json!({"schemaVersion":1,"records":[{"id":"a".repeat(64),"timestampMillis":1,"kind":"approved"}]}),
        json!({"schemaVersion":1,"records":[{"id":"x","timestampMillis":1,"kind":"expired"}]}),
        json!({"schemaVersion":1,"records":[{"id":"A".repeat(64),"timestampMillis":1,"kind":"expired"}]}),
        json!({"schemaVersion":1,"records":[{"id":"a".repeat(64),"timestampMillis":u64::MAX,"kind":"expired"}]}),
        json!({"schemaVersion":1,"records":vec![row;513]}),
    ] {
        assert!(decode_phone_history_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(decode_phone_history_json(&vec![b' '; MAX_PHONE_HISTORY_JSON_BYTES + 1]).is_err());
    assert!(
        decode_phone_history_json(br#"{"schemaVersion":1,"schemaVersion":1,"records":[]}"#)
            .is_err()
    );
}
