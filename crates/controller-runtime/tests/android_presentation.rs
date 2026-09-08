// SPDX-License-Identifier: GPL-2.0-or-later
use controller_runtime::{
    AppSnapshot, DataAvailability, MobileReadiness, NotificationPermission, NotificationPolicy,
    ScreenLockState, decode_notification_policy_document,
};

#[test]
fn native_policy_presentation_does_not_invent_request_owners_or_a_missing_lock() {
    let snapshot = AppSnapshot::from_android_policy(
        NotificationPolicy::default(),
        MobileReadiness::UNAVAILABLE,
    );
    assert_eq!(snapshot.data_availability, DataAvailability::UNAVAILABLE);
    assert_eq!(
        snapshot.mobile.unwrap().screen_lock,
        ScreenLockState::Unavailable
    );
    assert!(!snapshot.can_pair && !snapshot.can_unpair && !snapshot.can_clear_activity);
    assert!(
        snapshot.requests.is_empty() && snapshot.devices.is_empty() && snapshot.service.is_none()
    );
    let readiness = MobileReadiness {
        screen_lock: ScreenLockState::Configured,
        notifications: NotificationPermission::Denied,
        can_open_lock_settings: false,
    };
    assert_eq!(
        AppSnapshot::from_android_policy(NotificationPolicy::default(), readiness).mobile,
        Some(readiness)
    );
}

#[test]
fn legacy_document_requires_version_and_explicit_policy_fields() {
    assert!(
        decode_notification_policy_document(
            br#"{"schema_version":1,"policy":{"schedule":{"mode":"always"},"alert":"sound"}}"#
        )
        .is_ok()
    );
    for document in [
        r#"{}"#,
        r#"{"schema_version":1,"policy":{}}"#,
        r#"{"schema_version":2,"policy":{"schedule":{"mode":"always"},"alert":"sound"}}"#,
        r#"{"schema_version":1,"policy":{"schedule":{"mode":"always"},"alert":"sound"},"extra":true}"#,
    ] {
        assert!(decode_notification_policy_document(document.as_bytes()).is_err());
    }
    assert!(decode_notification_policy_document(&vec![b'x'; 16 * 1024 + 1]).is_err());
}
