// SPDX-License-Identifier: GPL-2.0-or-later
//! Isolated synthetic filesystem fixtures only; no native service/device QA.

use std::fs;
use std::path::Path;

use controller_runtime::{
    AlertMode, AppPrivateDirectory, AppRuntime, MAX_POLICY_DOCUMENT_BYTES, NotificationPolicy,
    POLICY_FILE_NAME, POLICY_LOCK_FILE_NAME, POLICY_STAGING_FILE_NAME, Platform, PreferenceError,
    Schedule, UnavailablePlatformAdapter, decode_notification_policy_json,
};
use serde_json::json;

fn open(path: &Path) -> Result<AppRuntime, controller_runtime::AppIssue> {
    AppRuntime::open(
        AppPrivateDirectory::from_native_app_data(path)
            .map_err(controller_runtime::AppIssue::from)?,
        Platform::Unsupported,
        None,
        Box::new(UnavailablePlatformAdapter),
    )
}

fn document(policy: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema_version": 1, "policy": policy})).expect("synthetic document")
}

#[test]
fn absent_policy_defaults_without_creating_a_policy_document() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let mut runtime = open(directory.path()).expect("open local preferences");
    let snapshot = runtime.snapshot();
    assert_eq!(snapshot.policy, Some(NotificationPolicy::default()));
    let policy = snapshot.policy.as_ref().expect("observed local policy");
    assert_eq!(policy.schedule(), &Schedule::Always);
    assert_eq!(policy.alert(), AlertMode::Sound);
    assert!(!directory.path().join(POLICY_FILE_NAME).exists());
    let lock_path = directory.path().join(POLICY_LOCK_FILE_NAME);
    assert_eq!(fs::metadata(&lock_path).expect("lock metadata").len(), 0);
    // Windows enforces the lifetime byte-range lock even for reads of an empty
    // file. Inspect its bytes only after relinquishing that real OS lock.
    drop(runtime);
    assert_eq!(fs::read(lock_path).expect("released lock"), b"");
}

#[test]
fn existing_empty_partial_or_corrupt_documents_never_default_or_reset() {
    let cases = [
        Vec::new(),
        b"{}".to_vec(),
        b"not JSON".to_vec(),
        document(json!({})),
        document(json!({"schedule": {"mode": "always"}})),
        document(json!({"alert": "sound"})),
        document(json!({"schedule": null, "alert": "sound"})),
    ];
    for bytes in cases {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let file = directory.path().join(POLICY_FILE_NAME);
        fs::write(&file, &bytes).expect("write corrupt synthetic fixture");
        assert_eq!(
            open(directory.path())
                .expect_err("existing input must not default")
                .code,
            "preferences_recovery_required"
        );
        assert_eq!(fs::read(file).expect("preserved fixture"), bytes);
    }
}

#[test]
fn unsupported_version_is_distinct_and_is_not_rewritten() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let bytes = serde_json::to_vec(&json!({
        "schema_version": 2,
        "policy": {"schedule": {"mode": "never"}, "alert": "silent"}
    }))
    .expect("synthetic document");
    let file = directory.path().join(POLICY_FILE_NAME);
    fs::write(&file, &bytes).expect("write future-version fixture");
    assert_eq!(
        open(directory.path()).expect_err("unknown version").code,
        "preferences_version_unsupported"
    );
    assert_eq!(fs::read(file).expect("preserved fixture"), bytes);
}

#[test]
fn save_and_reopen_keep_explicit_never_and_alert_mode() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let expected = NotificationPolicy::new(Some(Schedule::Never), AlertMode::VibrateOnly);
    {
        let mut runtime = open(directory.path()).expect("open preferences");
        assert_eq!(
            runtime.save_policy(expected.clone()).expect("save").policy,
            Some(expected.clone())
        );
        assert!(!directory.path().join(POLICY_STAGING_FILE_NAME).exists());
        let stored: serde_json::Value = serde_json::from_slice(
            &fs::read(directory.path().join(POLICY_FILE_NAME)).expect("saved bytes"),
        )
        .expect("saved JSON");
        assert_eq!(
            stored,
            json!({
                "schema_version": 1,
                "policy": {"schedule": {"mode": "never"}, "alert": "vibrate_only"}
            })
        );
    }
    assert!(directory.path().join(POLICY_LOCK_FILE_NAME).exists());
    let mut reopened = open(directory.path()).expect("reopen saved preferences");
    assert_eq!(reopened.snapshot().policy, Some(expected));
    reopened
        .save_policy(NotificationPolicy::default())
        .expect("atomic replacement of existing file");
    assert_eq!(
        reopened.snapshot().policy,
        Some(NotificationPolicy::default())
    );
}

#[test]
fn second_writer_is_rejected_until_the_first_runtime_drops() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let first = open(directory.path()).expect("first writer");
    assert_eq!(
        open(directory.path()).expect_err("exclusive writer").code,
        "preferences_in_use"
    );
    drop(first);
    let _second = open(directory.path()).expect("lock released without deleting lock path");
}

#[test]
fn failed_save_preserves_previous_disk_settings_and_cached_policy() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let mut runtime = open(directory.path()).expect("open preferences");
    let previous = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
    runtime.save_policy(previous.clone()).expect("initial save");
    let file = directory.path().join(POLICY_FILE_NAME);
    let bytes = fs::read(&file).expect("initial bytes");
    let staging = directory.path().join(POLICY_STAGING_FILE_NAME);
    fs::write(&staging, b"synthetic incomplete preference write")
        .expect("staging collision fixture");
    assert_eq!(
        runtime
            .save_policy(NotificationPolicy::default())
            .expect_err("do not overwrite staging")
            .code,
        "preferences_recovery_required"
    );
    assert_eq!(runtime.snapshot().policy, Some(previous));
    assert_eq!(fs::read(file).expect("previous file remains"), bytes);
    assert_eq!(
        fs::read(staging).expect("staging remains for explicit recovery"),
        b"synthetic incomplete preference write"
    );
}

#[test]
fn external_policy_change_is_not_silently_overwritten() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let mut runtime = open(directory.path()).expect("open preferences");
    runtime
        .save_policy(NotificationPolicy::default())
        .expect("initial save");
    let changed = document(json!({"schedule": {"mode": "never"}, "alert": "silent"}));
    let file = directory.path().join(POLICY_FILE_NAME);
    fs::write(&file, &changed).expect("synthetic external modification");
    assert_eq!(
        runtime
            .save_policy(NotificationPolicy::default())
            .expect_err("external change")
            .code,
        "preferences_changed"
    );
    assert_eq!(
        runtime.snapshot().policy,
        Some(NotificationPolicy::default())
    );
    assert_eq!(fs::read(file).expect("external bytes preserved"), changed);
}

#[test]
fn disappeared_policy_is_not_recreated_as_a_default() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let mut runtime = open(directory.path()).expect("open preferences");
    let previous = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
    runtime.save_policy(previous.clone()).expect("initial save");
    fs::remove_file(directory.path().join(POLICY_FILE_NAME)).expect("synthetic external deletion");
    assert_eq!(
        runtime
            .save_policy(NotificationPolicy::default())
            .expect_err("missing existing file")
            .code,
        "preferences_changed"
    );
    assert_eq!(runtime.snapshot().policy, Some(previous));
    assert!(!directory.path().join(POLICY_FILE_NAME).exists());
}

#[test]
fn oversized_file_and_nonempty_lock_are_rejected_without_modification() {
    for name in [POLICY_FILE_NAME, POLICY_LOCK_FILE_NAME] {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let bytes = vec![b'x'; MAX_POLICY_DOCUMENT_BYTES + 1];
        let path = directory.path().join(name);
        fs::write(&path, &bytes).expect("oversized synthetic fixture");
        assert_eq!(
            open(directory.path()).expect_err("bounded rejection").code,
            "preferences_recovery_required"
        );
        assert_eq!(fs::read(path).expect("unchanged fixture"), bytes);
    }
}

#[test]
fn unknown_authority_fields_are_rejected_at_every_document_level() {
    let policy = json!({"schedule": {"mode": "always"}, "alert": "sound"});
    let cases = [
        json!({"schema_version": 1, "policy": policy, "screen_lock_configured": true}),
        json!({"schema_version": 1, "policy": {"schedule": {"mode": "always"}, "alert": "sound", "approval_key": "synthetic-not-a-key"}}),
        json!({"schema_version": 1, "policy": {"schedule": {"mode": "always", "authorized": true}, "alert": "sound"}}),
        json!({"schema_version": 1, "policy": {"schedule": {"mode": "weekly", "windows": [
            {"days": 1, "start_minute": 0, "end_minute": 60, "can_approve": true}
        ]}, "alert": "sound"}}),
    ];
    for case in cases {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let bytes = serde_json::to_vec(&case).expect("synthetic document");
        fs::write(directory.path().join(POLICY_FILE_NAME), &bytes).expect("injected fixture");
        assert_eq!(
            open(directory.path())
                .expect_err("authority field rejected")
                .code,
            "preferences_recovery_required"
        );
    }
}

#[test]
fn bounded_frontend_decoder_reuses_validated_schedule_and_rejects_defaults() {
    let valid = br#"{"schedule":{"mode":"weekly","windows":[{"days":1,"start_minute":1320,"end_minute":120}]},"alert":"vibrate_only"}"#;
    let policy = decode_notification_policy_json(valid).expect("valid overnight window");
    assert_eq!(policy.alert(), AlertMode::VibrateOnly);
    assert!(matches!(policy.schedule(), Schedule::Weekly(_)));
    let invalid = [
        json!({}),
        json!({"schedule": null, "alert": "sound"}),
        json!({"schedule": {"mode": "always"}, "alert": "sound", "screenLock": "configured"}),
        json!({"schedule": {"mode": "always", "windows": []}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": []}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": [{"days": 0, "start_minute": 1, "end_minute": 2}]}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": [{"days": 128, "start_minute": 1, "end_minute": 2}]}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": [{"days": 1, "start_minute": 1440, "end_minute": 0}]}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": [{"days": 1, "start_minute": 0, "end_minute": 1441}]}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": [{"days": 1, "start_minute": 30, "end_minute": 30}]}, "alert": "sound"}),
        json!({"schedule": {"mode": "weekly", "windows": vec![json!({"days": 1, "start_minute": 0, "end_minute": 60}); 33]}, "alert": "sound"}),
    ];
    for input in invalid {
        assert_eq!(
            decode_notification_policy_json(&serde_json::to_vec(&input).expect("fixture"))
                .expect_err("invalid input")
                .code,
            "invalid_notification_policy"
        );
    }
    assert_eq!(
        decode_notification_policy_json(&vec![b' '; MAX_POLICY_DOCUMENT_BYTES + 1])
            .expect_err("actual byte bound")
            .code,
        "invalid_notification_policy"
    );
}

#[test]
fn duplicate_fields_and_trailing_json_are_rejected() {
    for bytes in [
        br#"{"schedule":{"mode":"always"},"schedule":{"mode":"never"},"alert":"sound"}"#.as_slice(),
        br#"{"schedule":{"mode":"always"},"alert":"sound"} {}"#.as_slice(),
        br#"{"schedule":{"mode":"weekly","windows":[{"days":1,"days":2,"start_minute":0,"end_minute":60}]},"alert":"sound"}"#.as_slice(),
    ] {
        assert!(decode_notification_policy_json(bytes).is_err());
    }
}

#[test]
fn existing_directory_is_required_and_no_parent_or_directory_is_created() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let missing = directory.path().join("missing-native-directory");
    assert_eq!(
        AppPrivateDirectory::from_native_app_data(&missing).expect_err("no implicit creation"),
        PreferenceError::DirectoryUnavailable
    );
    assert!(!missing.exists());
    assert_eq!(
        AppPrivateDirectory::from_native_app_data("relative-native-directory")
            .expect_err("absolute only"),
        PreferenceError::UnsafeEntry
    );
    assert!(AppPrivateDirectory::from_native_app_data(directory.path().join("..")).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_and_hardlinked_preference_files_are_rejected() {
    use std::os::unix::fs::symlink;

    for name in [
        POLICY_FILE_NAME,
        POLICY_LOCK_FILE_NAME,
        POLICY_STAGING_FILE_NAME,
    ] {
        let directory = tempfile::tempdir().expect("isolated fixture");
        let target = directory.path().join("synthetic-target");
        fs::write(&target, b"synthetic target data").expect("target fixture");
        symlink(&target, directory.path().join(name)).expect("symlink fixture");
        assert_eq!(
            open(directory.path()).expect_err("no symlink files").code,
            "preferences_unavailable"
        );
        assert_eq!(
            fs::read(target).expect("target unchanged"),
            b"synthetic target data"
        );
    }
    let directory = tempfile::tempdir().expect("isolated fixture");
    let target = directory.path().join("synthetic-target");
    fs::write(
        &target,
        document(json!({"schedule": {"mode": "never"}, "alert": "silent"})),
    )
    .expect("target fixture");
    fs::hard_link(&target, directory.path().join(POLICY_FILE_NAME)).expect("hardlink fixture");
    assert_eq!(
        open(directory.path()).expect_err("no hardlinked file").code,
        "preferences_unavailable"
    );
}

#[cfg(unix)]
#[test]
fn symlink_directory_or_ancestor_is_not_canonicalized_into_acceptance() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("isolated fixture");
    let actual = directory.path().join("actual");
    fs::create_dir(&actual).expect("fixture directory");
    fs::create_dir(actual.join("child")).expect("fixture child");
    let link = directory.path().join("link");
    symlink(&actual, &link).expect("fixture symlink");
    assert_eq!(
        AppPrivateDirectory::from_native_app_data(&link).expect_err("reject leaf link"),
        PreferenceError::UnsafeEntry
    );
    assert_eq!(
        AppPrivateDirectory::from_native_app_data(link.join("child"))
            .expect_err("reject ancestor link"),
        PreferenceError::UnsafeEntry
    );
}

#[test]
fn error_serialization_never_echoes_the_invalid_path_or_file_contents() {
    let directory = tempfile::tempdir().expect("isolated fixture");
    let marker = "synthetic-private-input-not-a-secret";
    fs::write(directory.path().join(POLICY_FILE_NAME), marker).expect("malformed fixture");
    let issue = open(directory.path()).expect_err("malformed data");
    let encoded = serde_json::to_string(&issue).expect("fixed issue JSON");
    assert!(!encoded.contains(marker));
    assert!(!encoded.contains(&directory.path().to_string_lossy().to_string()));
    assert!(encoded.contains("nextAction"));
    assert!(!encoded.contains("next_action"));
}
