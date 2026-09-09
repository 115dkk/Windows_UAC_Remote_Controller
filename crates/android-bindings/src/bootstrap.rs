// SPDX-License-Identifier: GPL-2.0-or-later
//! First Application adoption. No create-on-open-error and no recovery/reset.
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use notification_policy::NotificationPolicy;
use phone_state_store::{INTENT_FILE_NAME, LOCK_FILE_NAME, SNAPSHOT_FILE_NAME, STAGING_FILE_NAME};

use crate::{BridgeError, NativePlatform};

pub(crate) const MARKER: &str = "native-owner.started";
const MAGIC: &[u8; 8] = b"UACBOOT1";

pub(crate) enum InitialState {
    Existing,
    Fresh(NotificationPolicy),
}

/// Caller holds native private-directory provenance and the component owner
/// lease. Existing artifacts always select open, even if a snapshot is missing.
/// Fresh creation additionally requires no controller keystore keys, a readable
/// legacy document (if present), an empty directory and an exclusive durable
/// first-attempt marker. An interrupted attempt is never silently repeated.
pub(crate) fn prepare(
    path: &Path,
    platform: &dyn NativePlatform,
) -> Result<InitialState, BridgeError> {
    let mut existing = false;
    for (index, entry) in fs::read_dir(path).map_err(storage)?.enumerate() {
        if index >= 5 {
            return Err(BridgeError::StorageUnavailable);
        }
        let entry = entry.map_err(storage)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(BridgeError::StorageUnavailable);
        };
        match name {
            MARKER => {
                verify_marker(&entry.path())?;
                existing = true;
            }
            SNAPSHOT_FILE_NAME | LOCK_FILE_NAME | STAGING_FILE_NAME | INTENT_FILE_NAME => {
                existing = true
            }
            _ => return Err(BridgeError::StorageUnavailable),
        }
    }
    if existing {
        return Ok(InitialState::Existing);
    }
    if platform.has_device_keys()? {
        return Err(BridgeError::StorageUnavailable);
    }
    let policy = match platform.legacy_policy_document()? {
        Some(document) => {
            controller_runtime::decode_notification_policy_document(document.as_bytes())
                .map_err(|_| BridgeError::StorageUnavailable)?
        }
        None => NotificationPolicy::default(),
    };
    let mut marker = options(true)
        .create_new(true)
        .open(path.join(MARKER))
        .map_err(storage)?;
    regular(&marker.metadata().map_err(storage)?)?;
    marker.write_all(MAGIC).map_err(storage)?;
    marker.sync_all().map_err(storage)?;
    // Native constructors still require DirectorySynced store receipts. This
    // marker additionally syncs its directory on Android/Unix; Windows host
    // models must never be described as native durability proof.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(storage)?;
    }
    Ok(InitialState::Fresh(policy))
}

fn verify_marker(path: &Path) -> Result<(), BridgeError> {
    let metadata = fs::symlink_metadata(path).map_err(storage)?;
    regular(&metadata)?;
    if metadata.len() != MAGIC.len() as u64 {
        return Err(BridgeError::StorageUnavailable);
    }
    let file = options(false).open(path).map_err(storage)?;
    regular(&file.metadata().map_err(storage)?)?;
    let mut bytes = Vec::new();
    file.take(MAGIC.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage)?;
    if bytes != MAGIC {
        return Err(BridgeError::StorageUnavailable);
    }
    Ok(())
}

fn options(write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000).share_mode(0x0001);
    }
    options
}

fn regular(metadata: &fs::Metadata) -> Result<(), BridgeError> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(BridgeError::StorageUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(BridgeError::StorageUnavailable);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(BridgeError::StorageUnavailable);
        }
    }
    Ok(())
}

fn storage(_: impl std::fmt::Debug) -> BridgeError {
    BridgeError::StorageUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeClock;
    use notification_policy::{AlertMode, Schedule};

    struct Platform {
        keys: Result<bool, BridgeError>,
        legacy: Result<Option<String>, BridgeError>,
    }
    impl NativePlatform for Platform {
        fn reopen_local_key_sets(
            &self,
            _: Vec<crate::NativeLocalKeySet>,
        ) -> Result<(), BridgeError> {
            unreachable!("bootstrap does not reopen keys")
        }
        fn release_local_key_references(&self) -> Result<(), BridgeError> {
            unreachable!("bootstrap does not release key references")
        }
        fn state_directory(&self) -> Result<String, BridgeError> {
            unreachable!("not a directory resolver test")
        }
        fn clock(&self) -> Result<NativeClock, BridgeError> {
            unreachable!("not a native clock test")
        }
        fn unix_millis(&self) -> Result<u64, BridgeError> {
            unreachable!("bootstrap does not record outcomes")
        }
        fn clear_request_notifications(&self) -> Result<(), BridgeError> {
            unreachable!("bootstrap does not clear notifications")
        }
        fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
            self.legacy.clone()
        }
        fn has_device_keys(&self) -> Result<bool, BridgeError> {
            self.keys
        }
    }
    fn empty() -> Platform {
        Platform {
            keys: Ok(false),
            legacy: Ok(None),
        }
    }

    #[test]
    fn first_unenrolled_initialization_records_a_marker_before_returning_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let InitialState::Fresh(policy) = prepare(directory.path(), &empty()).unwrap() else {
            panic!("new installation")
        };
        assert_eq!(policy, NotificationPolicy::default());
        assert_eq!(fs::read(directory.path().join(MARKER)).unwrap(), MAGIC);
        assert!(matches!(
            prepare(directory.path(), &empty()).unwrap(),
            InitialState::Existing
        ));
    }

    #[test]
    fn interrupted_or_partial_state_is_never_a_new_installation() {
        for name in [
            SNAPSHOT_FILE_NAME,
            LOCK_FILE_NAME,
            STAGING_FILE_NAME,
            INTENT_FILE_NAME,
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::write(directory.path().join(name), b"incomplete").unwrap();
            assert!(matches!(
                prepare(directory.path(), &empty()).unwrap(),
                InitialState::Existing
            ));
            assert!(!directory.path().join(MARKER).exists());
        }
    }

    #[test]
    fn old_keys_or_unavailable_keystore_never_become_fresh_defaults() {
        for keys in [Ok(true), Err(BridgeError::NativeUnavailable)] {
            let directory = tempfile::tempdir().unwrap();
            assert!(prepare(directory.path(), &Platform { keys, ..empty() }).is_err());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn strict_legacy_policy_is_seeded_without_reopening_an_old_store() {
        let directory = tempfile::tempdir().unwrap();
        let legacy =
            r#"{"schema_version":1,"policy":{"schedule":{"mode":"never"},"alert":"silent"}}"#;
        let InitialState::Fresh(policy) = prepare(
            directory.path(),
            &Platform {
                legacy: Ok(Some(legacy.into())),
                ..empty()
            },
        )
        .unwrap() else {
            panic!("first migration")
        };
        assert_eq!(
            policy,
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent)
        );
    }

    #[test]
    fn malformed_or_unreadable_legacy_state_is_not_migrated_as_defaults() {
        for legacy in [
            Ok(Some("{}".into())),
            Ok(Some("x".repeat(16 * 1024 + 1))),
            Ok(Some(
                r#"{"schema_version":2,"policy":{"schedule":{"mode":"always"},"alert":"sound"}}"#
                    .into(),
            )),
            Err(BridgeError::StorageUnavailable),
        ] {
            let directory = tempfile::tempdir().unwrap();
            assert!(prepare(directory.path(), &Platform { legacy, ..empty() }).is_err());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn unknown_directory_entries_and_corrupt_markers_are_preserved_and_rejected() {
        for (name, bytes) in [
            ("unexpected", b"data".as_slice()),
            (MARKER, b"".as_slice()),
            (MARKER, b"BADBOOT1".as_slice()),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(name);
            fs::write(&path, bytes).unwrap();
            assert!(prepare(directory.path(), &empty()).is_err());
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn existing_state_does_not_reimport_changed_legacy_preferences() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(LOCK_FILE_NAME), []).unwrap();
        let platform = Platform {
            keys: Err(BridgeError::NativeUnavailable),
            legacy: Err(BridgeError::StorageUnavailable),
        };
        assert!(matches!(
            prepare(directory.path(), &platform).unwrap(),
            InitialState::Existing
        ));
    }
}
