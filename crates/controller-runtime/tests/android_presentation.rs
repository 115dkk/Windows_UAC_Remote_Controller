// SPDX-License-Identifier: GPL-2.0-or-later
use controller_runtime::{
    AppSnapshot, DataAvailability, MobileReadiness, NotificationPermission, NotificationPolicy,
    PhoneServiceState, PhoneServiceView, ScreenLockState, ServiceAction,
    decode_notification_policy_document,
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
        can_open_notification_settings: true,
        can_open_pairing_scanner: false,
    };
    assert_eq!(
        AppSnapshot::from_android_policy(NotificationPolicy::default(), readiness).mobile,
        Some(readiness)
    );
}

#[test]
fn stopped_service_snapshot_has_no_fabricated_policy_or_available_history() {
    let service = PhoneServiceView {
        state: PhoneServiceState::Stopped,
        boot_enabled: Some(false),
        can_start: true,
        can_stop: false,
        policy_owner_ready: false,
    };
    let snapshot = AppSnapshot::from_android_service(service, MobileReadiness::UNAVAILABLE);
    assert_eq!(snapshot.schema_version, 3);
    assert_eq!(snapshot.phone_service, Some(service));
    assert!(snapshot.policy.is_none());
    assert_eq!(snapshot.data_availability, DataAvailability::UNAVAILABLE);
    let json = serde_json::to_value(snapshot).unwrap();
    assert!(json["policy"].is_null());
    assert_eq!(json["phoneService"]["bootEnabled"], false);
    assert_eq!(json["phoneService"]["canStart"], true);
}

#[test]
fn native_service_dto_requires_known_complete_fields_and_no_authentication_extras() {
    let valid = serde_json::json!({
        "state":"unavailable", "bootEnabled":null, "canStart":false,
        "canStop":false, "policyOwnerReady":false
    });
    let value: PhoneServiceView = serde_json::from_value(valid.clone()).unwrap();
    assert_eq!(value.checked(), Some(PhoneServiceView::UNAVAILABLE));
    for name in [
        "state",
        "bootEnabled",
        "canStart",
        "canStop",
        "policyOwnerReady",
    ] {
        let mut missing = valid.clone();
        assert!(missing.as_object_mut().unwrap().remove(name).is_some());
        assert!(serde_json::from_value::<PhoneServiceView>(missing).is_err());
    }
    for (name, extra) in [
        ("state", serde_json::json!("future")),
        ("bootEnabled", serde_json::json!("true")),
        ("authenticated", serde_json::json!(true)),
    ] {
        let mut invalid = valid.clone();
        invalid[name] = extra;
        assert!(serde_json::from_value::<PhoneServiceView>(invalid).is_err());
    }
}

#[test]
fn contradictory_phone_availability_never_becomes_a_valid_observation() {
    let unavailable = PhoneServiceView::UNAVAILABLE;
    for invalid in [
        PhoneServiceView {
            can_start: true,
            ..unavailable
        },
        PhoneServiceView {
            policy_owner_ready: true,
            ..unavailable
        },
        PhoneServiceView {
            state: PhoneServiceState::LocalSettingsReady,
            ..unavailable
        },
        PhoneServiceView {
            state: PhoneServiceState::CleanupPending,
            boot_enabled: Some(false),
            can_start: true,
            ..unavailable
        },
    ] {
        assert!(invalid.checked().is_none());
    }
}

#[test]
fn phone_control_never_advertises_installer_or_restart_from_start_stop_hints() {
    let stopped = PhoneServiceView {
        state: PhoneServiceState::Stopped,
        boot_enabled: Some(false),
        can_start: true,
        ..PhoneServiceView::UNAVAILABLE
    };
    assert!(stopped.checked().is_some());
    assert!(stopped.allows(ServiceAction::Start));
    for action in [
        ServiceAction::Install,
        ServiceAction::Stop,
        ServiceAction::Restart,
        ServiceAction::Uninstall,
    ] {
        assert!(!stopped.allows(action));
    }
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
