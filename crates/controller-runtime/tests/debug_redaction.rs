// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic presentation values only; never real commands or device identities.
use controller_runtime::{
    ActivityKind, ActivityView, AppSnapshot, DataAvailability, NotificationPolicy,
    PairedDeviceView, Platform, RequestState, RequestView,
};

#[test]
fn presentation_debug_never_emits_identifiers_names_paths_or_commands() {
    let secret = "SYNTHETIC_NOT_A_REAL_SECRET";
    let device = PairedDeviceView {
        id: secret.into(),
        name: secret.into(),
        connected: false,
        last_seen_label: Some(secret.into()),
    };
    let request = RequestView {
        id: secret.into(),
        computer_name: secret.into(),
        program_name: secret.into(),
        executable_path: secret.into(),
        details: secret.into(),
        remaining_seconds: 17,
        state: RequestState::Pending,
        can_approve: false,
        can_deny: false,
    };
    let activity = ActivityView {
        id: secret.into(),
        timestamp_millis: 123,
        kind: ActivityKind::Expired,
    };
    for debug in [
        format!("{device:?}"),
        format!("{request:?}"),
        format!("{activity:?}"),
    ] {
        assert!(!debug.contains(secret));
    }
    let snapshot = AppSnapshot {
        schema_version: 1,
        platform: Platform::Android,
        computer_name: secret.into(),
        service: None,
        mobile: None,
        policy: NotificationPolicy::default(),
        devices: vec![device],
        requests: vec![request],
        activity: vec![activity],
        data_availability: DataAvailability::UNAVAILABLE,
        can_pair: false,
        can_unpair: false,
        can_clear_activity: false,
        issue: None,
    };
    assert!(!format!("{snapshot:#?}").contains(secret));
    // Redaction is not a mutation of user-facing details in the intended DTO.
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap()["requests"][0]["details"],
        secret
    );
}
