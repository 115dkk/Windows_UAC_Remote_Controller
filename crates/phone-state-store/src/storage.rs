// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
#[cfg(not(target_os = "android"))]
use std::fs::TryLockError;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use crate::{
    Durability, INTENT_FILE_NAME, LOCK_FILE_NAME, MAX_FILE_BYTES, SNAPSHOT_FILE_NAME,
    STAGING_FILE_NAME, StoreError,
};

const INTENT: &[u8; 9] = b"WUACDIRT\x01";

/// Native-host assertion of an existing, provisioned, app-private directory.
///
/// Obtain it from the native app-data resolver, never renderer/network input.
/// The host must enforce ownership/ACLs, exclusive use of the fixed filenames,
/// trusted ancestors and appropriate backup/restore policy. Shape checks do not
/// establish those properties. No directory or permission is created/repaired.
/// Unix final-component no-follow opens do not make path-based rename safe
/// against an adversary who can rename an ancestor. Windows ancestors are held
/// without share-delete and with actual read/list access, not attributes alone.
pub struct NativePrivateDirectory {
    path: PathBuf,
    directory: File,
    #[cfg(windows)]
    _ancestor_pins: Vec<File>,
}

impl fmt::Debug for NativePrivateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativePrivateDirectory(native_host_provenance)")
    }
}

impl NativePrivateDirectory {
    pub fn from_native_app_data(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        platform_durability()?;
        let path = path.as_ref();
        validate_absolute_path(path)?;
        #[cfg(windows)]
        let mut pins = Vec::new();
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            validate_directory(
                &fs::symlink_metadata(ancestor).map_err(|_| StoreError::DirectoryUnavailable)?,
            )?;
            #[cfg(windows)]
            pins.push(open_directory(ancestor)?);
        }
        let directory = open_directory(path)?;
        same_directory_at_path(
            path,
            &directory
                .metadata()
                .map_err(|_| StoreError::DirectoryUnavailable)?,
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            directory,
            #[cfg(windows)]
            _ancestor_pins: pins,
        })
    }

    fn validate(&self) -> Result<(), StoreError> {
        for ancestor in self.path.ancestors() {
            validate_directory(
                &fs::symlink_metadata(ancestor).map_err(|_| StoreError::DirectoryUnavailable)?,
            )?;
        }
        same_directory_at_path(
            &self.path,
            &self
                .directory
                .metadata()
                .map_err(|_| StoreError::DirectoryUnavailable)?,
        )
    }

    fn sync(&self) -> Result<Durability, StoreError> {
        self.validate()?;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        self.directory
            .sync_all()
            .map_err(|_| StoreError::CommitUncertain)?;
        platform_durability()
    }
}

pub(crate) struct Storage {
    directory: NativePrivateDirectory,
    // Never unlink/replace/clone this handle or expose it. Every cooperative
    // owner must lock this same persistent file. Unix locks remain advisory.
    lock: File,
}

// Constructible only after this Storage creates and synchronizes the fixed
// intent. Closing/dropping it never removes the directory entry.
pub(crate) struct PendingIntent {
    file: File,
}

impl Storage {
    pub(crate) fn create_fresh(directory: NativePrivateDirectory) -> Result<Self, StoreError> {
        directory.validate()?;
        for name in [
            LOCK_FILE_NAME,
            SNAPSHOT_FILE_NAME,
            STAGING_FILE_NAME,
            INTENT_FILE_NAME,
        ] {
            if checked_file(&directory.path.join(name))?.is_some() {
                return Err(StoreError::StateAlreadyExists);
            }
        }
        let path = directory.path.join(LOCK_FILE_NAME);
        let lock = file_options(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    StoreError::StateAlreadyExists
                } else {
                    StoreError::WriteFailed
                }
            })?;
        take_lock(&path, &lock)?;
        lock.sync_all().map_err(|_| StoreError::CommitUncertain)?;
        let storage = Self { directory, lock };
        storage.ensure_clean()?;
        if checked_file(&storage.path(SNAPSHOT_FILE_NAME))?.is_some() {
            return Err(StoreError::StateAlreadyExists);
        }
        Ok(storage)
    }

    pub(crate) fn open_existing(directory: NativePrivateDirectory) -> Result<Self, StoreError> {
        directory.validate()?;
        let path = directory.path.join(LOCK_FILE_NAME);
        let lock = open_regular(&path, true)?;
        take_lock(&path, &lock)?;
        let storage = Self { directory, lock };
        storage.ensure_clean()?;
        Ok(storage)
    }

    pub(crate) fn read_current(&self) -> Result<Vec<u8>, StoreError> {
        self.ensure_clean()?;
        let (_, bytes) = read_document(&self.path(SNAPSHOT_FILE_NAME), false)?;
        Ok(bytes)
    }

    pub(crate) fn sync_unchanged(&self, expected: &[u8]) -> Result<Durability, StoreError> {
        self.ensure_clean()?;
        let (file, bytes) = read_document(&self.path(SNAPSHOT_FILE_NAME), true)?;
        if bytes != expected {
            return Err(StoreError::ExternalChange);
        }
        file.sync_all().map_err(|_| StoreError::CommitUncertain)?;
        self.directory
            .sync()
            .map_err(|_| StoreError::CommitUncertain)
    }

    pub(crate) fn replace(
        &self,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<Durability, StoreError> {
        let intent = self.reserve(expected)?;
        self.commit_reserved(intent, expected, next)
    }

    pub(crate) fn reserve(&self, expected: Option<&[u8]>) -> Result<PendingIntent, StoreError> {
        self.ensure_clean()?;
        self.check_expected(expected)?;
        let intent_path = self.path(INTENT_FILE_NAME);
        let mut intent = create_regular(&intent_path)?;
        intent
            .write_all(INTENT)
            .map_err(|_| StoreError::WriteFailed)?;
        intent.sync_all().map_err(|_| StoreError::CommitUncertain)?;
        // Persist a separate intent BEFORE replacing any current snapshot. A
        // staging name alone disappears in rename and cannot serve this role.
        self.directory
            .sync()
            .map_err(|_| StoreError::CommitUncertain)?;
        self.validate_lock()?;
        self.ensure_staging_absent()?;
        self.check_expected(expected)?;
        check_owned_contents(&intent_path, &mut intent, INTENT)?;
        Ok(PendingIntent { file: intent })
    }

    pub(crate) fn commit_reserved(
        &self,
        mut intent: PendingIntent,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> Result<Durability, StoreError> {
        self.validate_lock()?;
        self.ensure_staging_absent()?;
        self.check_expected(expected)?;
        check_owned_contents(&self.path(INTENT_FILE_NAME), &mut intent.file, INTENT)?;

        if expected == Some(next) {
            let (current, bytes) = read_document(&self.path(SNAPSHOT_FILE_NAME), true)?;
            if bytes != next {
                return Err(StoreError::ExternalChange);
            }
            current
                .sync_all()
                .map_err(|_| StoreError::CommitUncertain)?;
            self.directory
                .sync()
                .map_err(|_| StoreError::CommitUncertain)?;
            return self.finish_intent(intent);
        }

        let staging_path = self.path(STAGING_FILE_NAME);
        let mut staging = create_regular(&staging_path)?;
        staging
            .write_all(next)
            .map_err(|_| StoreError::WriteFailed)?;
        staging
            .sync_all()
            .map_err(|_| StoreError::CommitUncertain)?;
        check_owned_contents(&staging_path, &mut staging, next)?;
        self.validate_lock()?;
        self.check_expected(expected)?;
        check_owned_contents(&self.path(INTENT_FILE_NAME), &mut intent.file, INTENT)?;
        // Windows no-share-delete handles must close before rename. The
        // trusted private parent is still required for that final path window.
        drop(staging);
        fs::rename(&staging_path, self.path(SNAPSHOT_FILE_NAME))
            .map_err(|_| StoreError::CommitUncertain)?;
        // Everything from the rename attempt onward is uncertain on failure;
        // never claim that the prior snapshot remains the committed state.
        let (current, bytes) = read_document(&self.path(SNAPSHOT_FILE_NAME), true)
            .map_err(|_| StoreError::CommitUncertain)?;
        if bytes != next {
            return Err(StoreError::CommitUncertain);
        }
        current
            .sync_all()
            .map_err(|_| StoreError::CommitUncertain)?;
        self.directory
            .sync()
            .map_err(|_| StoreError::CommitUncertain)?;
        self.finish_intent(intent)
    }

    fn finish_intent(&self, mut intent: PendingIntent) -> Result<Durability, StoreError> {
        let intent_path = self.path(INTENT_FILE_NAME);
        check_owned_contents(&intent_path, &mut intent.file, INTENT)
            .map_err(|_| StoreError::CommitUncertain)?;
        drop(intent);
        // Only this operation's exact fixed intent is removed. There is no
        // cleanup of an existing/stale/unknown intent, staging file or snapshot.
        fs::remove_file(&intent_path).map_err(|_| StoreError::CommitUncertain)?;
        self.directory
            .sync()
            .map_err(|_| StoreError::CommitUncertain)
    }

    fn check_expected(&self, expected: Option<&[u8]>) -> Result<(), StoreError> {
        match expected {
            Some(expected) => {
                let (_, bytes) = read_document(&self.path(SNAPSHOT_FILE_NAME), false)?;
                if bytes != expected {
                    return Err(StoreError::ExternalChange);
                }
            }
            None => {
                if checked_file(&self.path(SNAPSHOT_FILE_NAME))?.is_some() {
                    return Err(StoreError::ExternalChange);
                }
            }
        }
        Ok(())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path.join(name)
    }

    fn validate_lock(&self) -> Result<(), StoreError> {
        self.directory.validate()?;
        let metadata = self.lock.metadata().map_err(|_| StoreError::ReadFailed)?;
        validate_regular(&metadata)?;
        if metadata.len() != 0 {
            return Err(StoreError::RecoveryRequired);
        }
        same_file_at_path(&self.path(LOCK_FILE_NAME), &metadata)
    }

    fn ensure_clean(&self) -> Result<(), StoreError> {
        self.validate_lock()?;
        self.ensure_staging_absent()?;
        if checked_file(&self.path(INTENT_FILE_NAME))?.is_some() {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }

    fn ensure_staging_absent(&self) -> Result<(), StoreError> {
        if checked_file(&self.path(STAGING_FILE_NAME))?.is_some() {
            Err(StoreError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

fn take_lock(path: &Path, lock: &File) -> Result<(), StoreError> {
    let metadata = lock.metadata().map_err(|_| StoreError::ReadFailed)?;
    validate_regular(&metadata)?;
    same_file_at_path(path, &metadata)?;
    if metadata.len() != 0 {
        return Err(StoreError::RecoveryRequired);
    }
    #[cfg(target_os = "android")]
    {
        use rustix::fs::{FlockOperation, flock};
        match flock(lock, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(()),
            Err(error) if io::Error::from(error).kind() == io::ErrorKind::WouldBlock => {
                Err(StoreError::WriterLocked)
            }
            Err(_) => Err(StoreError::ReadFailed),
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        match lock.try_lock() {
            Ok(()) => Ok(()),
            Err(TryLockError::WouldBlock) => Err(StoreError::WriterLocked),
            Err(TryLockError::Error(_)) => Err(StoreError::ReadFailed),
        }
    }
}

fn create_regular(path: &Path) -> Result<File, StoreError> {
    let file = file_options(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                StoreError::RecoveryRequired
            } else {
                StoreError::WriteFailed
            }
        })?;
    let metadata = file.metadata().map_err(|_| StoreError::WriteFailed)?;
    validate_regular(&metadata)?;
    same_file_at_path(path, &metadata)?;
    Ok(file)
}

fn open_regular(path: &Path, write: bool) -> Result<File, StoreError> {
    checked_file(path)?.ok_or(StoreError::MissingState)?;
    let file = file_options(write)
        .open(path)
        .map_err(|_| StoreError::ReadFailed)?;
    let metadata = file.metadata().map_err(|_| StoreError::ReadFailed)?;
    validate_regular(&metadata)?;
    same_file_at_path(path, &metadata)?;
    Ok(file)
}

fn read_document(path: &Path, write: bool) -> Result<(File, Vec<u8>), StoreError> {
    let metadata = checked_file(path)?.ok_or(StoreError::MissingState)?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(StoreError::SnapshotTooLarge);
    }
    let mut file = open_regular(path, write)?;
    let metadata = file.metadata().map_err(|_| StoreError::ReadFailed)?;
    if metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(StoreError::SnapshotTooLarge);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::ReadFailed)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(StoreError::SnapshotTooLarge);
    }
    same_file_at_path(path, &file.metadata().map_err(|_| StoreError::ReadFailed)?)?;
    Ok((file, bytes))
}

fn check_owned_contents(path: &Path, file: &mut File, expected: &[u8]) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(|_| StoreError::ReadFailed)?;
    same_file_at_path(path, &metadata)?;
    if metadata.len() != expected.len() as u64 {
        return Err(StoreError::ExternalChange);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| StoreError::ReadFailed)?;
    let mut bytes = Vec::with_capacity(expected.len());
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::ReadFailed)?;
    if bytes != expected {
        return Err(StoreError::ExternalChange);
    }
    Ok(())
}

fn file_options(write: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x0003;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ_WRITE);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .mode(0o600);
    }
    options
}

fn open_directory(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES_AND_LIST_DIRECTORY: u32 = 0x0081;
        const FILE_SHARE_READ_WRITE: u32 = 0x0003;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .access_mode(FILE_READ_ATTRIBUTES_AND_LIST_DIRECTORY)
            .share_mode(FILE_SHARE_READ_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY);
    }
    let file = options
        .open(path)
        .map_err(|_| StoreError::DirectoryUnavailable)?;
    validate_directory(
        &file
            .metadata()
            .map_err(|_| StoreError::DirectoryUnavailable)?,
    )?;
    Ok(file)
}

fn platform_durability() -> Result<Durability, StoreError> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        Ok(Durability::DirectorySynced)
    }
    #[cfg(windows)]
    {
        Ok(Durability::FileSyncedOnly)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux", windows)))]
    {
        Err(StoreError::UnsupportedPlatform)
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), StoreError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::UnsafeEntry);
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err(StoreError::UnsafeEntry);
        }
        for part in path.components() {
            if let Component::Normal(part) = part {
                let text = part.to_str().ok_or(StoreError::UnsafeEntry)?;
                if text.ends_with(['.', ' '])
                    || text.contains(':')
                    || text.chars().any(char::is_control)
                {
                    return Err(StoreError::UnsafeEntry);
                }
            }
        }
    }
    Ok(())
}

fn checked_file(path: &Path) -> Result<Option<Metadata>, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular(&metadata)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(StoreError::ReadFailed),
    }
}

fn validate_directory(metadata: &Metadata) -> Result<(), StoreError> {
    if !metadata.is_dir() || is_link_or_reparse(metadata) {
        Err(StoreError::UnsafeEntry)
    } else {
        Ok(())
    }
}

fn validate_regular(metadata: &Metadata) -> Result<(), StoreError> {
    if !metadata.is_file() || is_link_or_reparse(metadata) {
        return Err(StoreError::UnsafeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(StoreError::UnsafeEntry);
        }
    }
    Ok(())
}

fn same_file_at_path(path: &Path, opened: &Metadata) -> Result<(), StoreError> {
    validate_regular(opened)?;
    let current = checked_file(path)?.ok_or(StoreError::ExternalChange)?;
    same_identity(opened, &current)
}

fn same_directory_at_path(path: &Path, opened: &Metadata) -> Result<(), StoreError> {
    validate_directory(opened)?;
    let current = fs::symlink_metadata(path).map_err(|_| StoreError::DirectoryUnavailable)?;
    validate_directory(&current)?;
    same_identity(opened, &current)
}

fn same_identity(opened: &Metadata, current: &Metadata) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(StoreError::ExternalChange);
        }
    }
    #[cfg(not(unix))]
    let _ = (opened, current);
    Ok(())
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}
