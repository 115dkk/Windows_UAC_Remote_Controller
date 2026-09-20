// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use notification_policy::{AlertMode, NotificationPolicy, Schedule};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::AppIssue;

pub const MAX_POLICY_DOCUMENT_BYTES: usize = 16 * 1024;
pub const POLICY_DOCUMENT_VERSION: u32 = 1;
pub const POLICY_FILE_NAME: &str = "notification-policy.json";
pub const POLICY_LOCK_FILE_NAME: &str = "notification-policy.lock";
pub const POLICY_STAGING_FILE_NAME: &str = "notification-policy.staging";

/// A native-host assertion that this existing directory is app-private.
///
/// Construct only from the platform's application-data path resolver, never a
/// renderer path, environment variable, URL or remote input. The native host is
/// responsible for appropriate ownership/ACLs and protecting ancestors from
/// untrusted replacement. This safe crate checks shape and links, not ACLs.
/// Windows ancestors are pinned without share-delete while storage is open.
/// Unix no-follow opens protect final components; trusted private ancestors
/// remain a host invariant because portable std does not offer handle-relative
/// rename. These preference files never contain or confer authority.
///
/// This constructor creates no directory, repairs no permissions and never
/// canonicalizes through a symlink. The parent must provision the app-data
/// directory using its native trusted lifecycle before calling it.
pub struct AppPrivateDirectory {
    path: PathBuf,
    #[cfg(windows)]
    _pins: Vec<File>,
}

impl fmt::Debug for AppPrivateDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AppPrivateDirectory(native_host_provenance)")
    }
}

impl AppPrivateDirectory {
    pub fn from_native_app_data(path: impl AsRef<Path>) -> Result<Self, PreferenceError> {
        let path = path.as_ref();
        validate_absolute_path(path)?;
        #[cfg(windows)]
        let mut pins = Vec::new();
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let metadata = fs::symlink_metadata(ancestor)
                .map_err(|_| PreferenceError::DirectoryUnavailable)?;
            validate_directory(&metadata)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // Safe std CreateFile options. Pin the directory against rename
                // or removal; open a reparse point itself, never its target.
                const FILE_READ_ATTRIBUTES: u32 = 0x0080;
                const FILE_LIST_DIRECTORY: u32 = 0x0001;
                const FILE_SHARE_READ_WRITE: u32 = 0x0003;
                const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                let pin = OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY)
                    .share_mode(FILE_SHARE_READ_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(ancestor)
                    .map_err(|_| PreferenceError::DirectoryUnavailable)?;
                validate_directory(
                    &pin.metadata()
                        .map_err(|_| PreferenceError::DirectoryUnavailable)?,
                )?;
                pins.push(pin);
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            #[cfg(windows)]
            _pins: pins,
        })
    }
}

/// Fixed storage categories only: errors carry no paths, contents or OS text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PreferenceError {
    #[error("the native application-data directory is unavailable")]
    DirectoryUnavailable,
    #[error("the preference path or entry is not supported")]
    UnsafeEntry,
    #[error("another process owns the preference writer lock")]
    WriterLocked,
    #[error("the preference lock unexpectedly contains data")]
    UnexpectedLockContent,
    #[error("unfinished preference storage requires explicit recovery")]
    RecoveryRequired,
    #[error("the saved preference document is malformed")]
    CorruptDocument,
    #[error("the saved preference document has an unsupported version")]
    UnsupportedVersion,
    #[error("the preference document exceeds its byte bound")]
    DocumentTooLarge,
    #[error("notification preference input is invalid")]
    InvalidPolicy,
    #[error("the saved preference document changed outside this runtime")]
    ExternalChange,
    #[error("preference storage could not be read")]
    ReadFailed,
    #[error("preference storage could not be written")]
    WriteFailed,
}

impl From<PreferenceError> for AppIssue {
    fn from(error: PreferenceError) -> Self {
        match error {
            PreferenceError::WriterLocked => Self {
                code: "preferences_in_use",
                message: "다른 앱 창에서 알림 설정을 사용 중입니다.",
                next_action: Some("다른 창을 닫은 뒤 다시 열어 주세요."),
            },
            PreferenceError::UnsupportedVersion => Self {
                code: "preferences_version_unsupported",
                message: "이 버전의 앱에서는 저장된 알림 설정을 읽을 수 없습니다.",
                next_action: Some("알림 설정을 저장한 버전 이상의 앱으로 다시 열어 주세요."),
            },
            PreferenceError::CorruptDocument
            | PreferenceError::DocumentTooLarge
            | PreferenceError::UnexpectedLockContent
            | PreferenceError::RecoveryRequired => Self {
                code: "preferences_recovery_required",
                message: "저장된 알림 설정을 읽지 못했습니다. 기존 파일은 변경하지 않았습니다.",
                next_action: Some("앱을 닫고 설치 지원 안내에 따라 설정 파일을 점검해 주세요."),
            },
            PreferenceError::InvalidPolicy => Self {
                code: "invalid_notification_policy",
                message: "알림 설정을 저장하지 못했습니다.",
                next_action: Some("요일과 시작·종료 시간을 확인한 뒤 다시 저장해 주세요."),
            },
            PreferenceError::ExternalChange => Self {
                code: "preferences_changed",
                message: "앱 밖에서 알림 설정 파일이 변경되어 저장하지 않았습니다.",
                next_action: Some("앱을 다시 열어 저장된 설정을 확인해 주세요."),
            },
            PreferenceError::WriteFailed => Self {
                code: "preferences_save_failed",
                message: "알림 설정을 저장하지 못했습니다. 이전 설정을 유지합니다.",
                next_action: Some("저장 공간과 앱의 저장 권한을 확인해 주세요."),
            },
            PreferenceError::DirectoryUnavailable
            | PreferenceError::UnsafeEntry
            | PreferenceError::ReadFailed => Self {
                code: "preferences_unavailable",
                message: "알림 설정 저장소에 접근하지 못했습니다.",
                next_action: Some("앱의 저장 권한과 설치 상태를 확인한 뒤 다시 열어 주세요."),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDefinition {
    // Unlike notification-policy's generic input format, existing local files
    // must contain both fields. An existing `{}` must not become a default.
    schedule: Schedule,
    alert: AlertMode,
}

impl From<PolicyDefinition> for NotificationPolicy {
    fn from(policy: PolicyDefinition) -> Self {
        Self::new(Some(policy.schedule), policy.alert)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    schema_version: u32,
    policy: PolicyDefinition,
}

#[derive(Serialize)]
struct EncodedPolicyDocument<'a> {
    schema_version: u32,
    policy: &'a NotificationPolicy,
}

/// Decode a bounded frontend policy payload with no defaults or unknown fields.
/// Native hosts should use this before passing a decoded policy to `save_policy`.
/// It accepts notification-policy's snake_case fields, not snapshot camelCase.
pub fn decode_notification_policy_json(bytes: &[u8]) -> Result<NotificationPolicy, AppIssue> {
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(PreferenceError::InvalidPolicy.into());
    }
    serde_json::from_slice::<PolicyDefinition>(bytes)
        .map(Into::into)
        .map_err(|_| PreferenceError::InvalidPolicy.into())
}

/// Bounded, read-only migration decoder for the former native preference file.
/// This neither opens a second store nor treats a corrupt document as defaults.
pub fn decode_notification_policy_document(bytes: &[u8]) -> Result<NotificationPolicy, AppIssue> {
    if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
        return Err(PreferenceError::DocumentTooLarge.into());
    }
    decode_document(bytes).map_err(Into::into)
}

pub(crate) struct PreferenceStore {
    directory: AppPrivateDirectory,
    // Never unlink this path, including Drop: another writer must lock the same
    // file object. Windows denies replacement for the lifetime of this handle.
    lock: File,
    current_bytes: Option<Vec<u8>>,
}

impl fmt::Debug for PreferenceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreferenceStore")
            .field("writer_lock_held", &true)
            .finish_non_exhaustive()
    }
}

impl PreferenceStore {
    pub(crate) fn open(
        directory: AppPrivateDirectory,
    ) -> Result<(Self, NotificationPolicy), PreferenceError> {
        let lock_path = directory.path.join(POLICY_LOCK_FILE_NAME);
        checked_file(&lock_path)?;
        let lock = match options(true).create_new(true).open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                checked_file(&lock_path)?;
                options(true)
                    .open(&lock_path)
                    .map_err(|_| PreferenceError::ReadFailed)?
            }
            Err(_) => return Err(PreferenceError::WriteFailed),
        };
        let metadata = lock.metadata().map_err(|_| PreferenceError::ReadFailed)?;
        validate_regular(&metadata)?;
        same_file_at_path(&lock_path, &metadata)?;
        if metadata.len() != 0 {
            return Err(PreferenceError::UnexpectedLockContent);
        }
        match try_lock_file(&lock) {
            Ok(()) => (),
            Err(TryLockError::WouldBlock) => return Err(PreferenceError::WriterLocked),
            Err(TryLockError::Error(_)) => return Err(PreferenceError::ReadFailed),
        }
        let mut storage = Self {
            directory,
            lock,
            current_bytes: None,
        };
        storage.ensure_staging_absent()?;
        let bytes = storage.read_current()?;
        let policy = match &bytes {
            Some(bytes) => decode_document(bytes)?,
            None => NotificationPolicy::default(),
        };
        storage.current_bytes = bytes;
        Ok((storage, policy))
    }

    pub(crate) fn save(&mut self, policy: &NotificationPolicy) -> Result<(), PreferenceError> {
        self.validate_lock()?;
        self.ensure_staging_absent()?;
        // Re-read with the same bound before replacing; external changes,
        // corruption or disappearance must not be silently overwritten.
        if self.read_current()? != self.current_bytes {
            return Err(PreferenceError::ExternalChange);
        }
        let bytes = serde_json::to_vec(&EncodedPolicyDocument {
            schema_version: POLICY_DOCUMENT_VERSION,
            policy,
        })
        .map_err(|_| PreferenceError::WriteFailed)?;
        if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(PreferenceError::DocumentTooLarge);
        }
        let staging_path = self.directory.path.join(POLICY_STAGING_FILE_NAME);
        let mut staging = options(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    PreferenceError::RecoveryRequired
                } else {
                    PreferenceError::WriteFailed
                }
            })?;
        validate_regular(
            &staging
                .metadata()
                .map_err(|_| PreferenceError::WriteFailed)?,
        )?;
        staging
            .write_all(&bytes)
            .map_err(|_| PreferenceError::WriteFailed)?;
        staging
            .sync_all()
            .map_err(|_| PreferenceError::WriteFailed)?;
        // No current-file write occurs until the complete staging file is synced.
        // Keep at most this fixed staging file on failure; never silently delete
        // or promote a crash remainder. Recovery belongs to a future native owner.
        drop(staging);
        self.validate_lock()?;
        checked_file(&staging_path)?.ok_or(PreferenceError::RecoveryRequired)?;
        if self.read_current()? != self.current_bytes {
            return Err(PreferenceError::ExternalChange);
        }
        fs::rename(&staging_path, self.directory.path.join(POLICY_FILE_NAME))
            .map_err(|_| PreferenceError::WriteFailed)?;
        // Commit cached state only after atomic replacement succeeds. The file
        // is synced, but no cross-platform power-loss durability is claimed.
        self.current_bytes = Some(bytes);
        Ok(())
    }

    fn validate_lock(&self) -> Result<(), PreferenceError> {
        let metadata = self
            .lock
            .metadata()
            .map_err(|_| PreferenceError::ReadFailed)?;
        validate_regular(&metadata)?;
        if metadata.len() != 0 {
            return Err(PreferenceError::UnexpectedLockContent);
        }
        same_file_at_path(&self.directory.path.join(POLICY_LOCK_FILE_NAME), &metadata)
    }

    fn read_current(&self) -> Result<Option<Vec<u8>>, PreferenceError> {
        let path = self.directory.path.join(POLICY_FILE_NAME);
        let Some(metadata) = checked_file(&path)? else {
            return Ok(None);
        };
        if metadata.len() > MAX_POLICY_DOCUMENT_BYTES as u64 {
            return Err(PreferenceError::DocumentTooLarge);
        }
        let file = options(false)
            .open(&path)
            .map_err(|_| PreferenceError::ReadFailed)?;
        let metadata = file.metadata().map_err(|_| PreferenceError::ReadFailed)?;
        validate_regular(&metadata)?;
        same_file_at_path(&path, &metadata)?;
        if metadata.len() > MAX_POLICY_DOCUMENT_BYTES as u64 {
            return Err(PreferenceError::DocumentTooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        // Actual bytes read are bounded even if the file grows after metadata.
        file.take(MAX_POLICY_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PreferenceError::ReadFailed)?;
        if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(PreferenceError::DocumentTooLarge);
        }
        Ok(Some(bytes))
    }

    fn ensure_staging_absent(&self) -> Result<(), PreferenceError> {
        if checked_file(&self.directory.path.join(POLICY_STAGING_FILE_NAME))?.is_some() {
            return Err(PreferenceError::RecoveryRequired);
        }
        Ok(())
    }
}

fn decode_document(bytes: &[u8]) -> Result<NotificationPolicy, PreferenceError> {
    let document: PolicyDocument =
        serde_json::from_slice(bytes).map_err(|_| PreferenceError::CorruptDocument)?;
    if document.schema_version != POLICY_DOCUMENT_VERSION {
        return Err(PreferenceError::UnsupportedVersion);
    }
    Ok(document.policy.into())
}

fn validate_absolute_path(path: &Path) -> Result<(), PreferenceError> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(PreferenceError::UnsafeEntry);
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        // Reject UNC/device namespaces and ambiguous DOS aliases. Native Tauri
        // app-data resolvers should provide an ordinary absolute local path.
        if !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err(PreferenceError::UnsafeEntry);
        }
        for part in path.components() {
            if let Component::Normal(part) = part {
                let text = part.to_str().ok_or(PreferenceError::UnsafeEntry)?;
                if text.ends_with(['.', ' '])
                    || text.contains(':')
                    || text.chars().any(char::is_control)
                {
                    return Err(PreferenceError::UnsafeEntry);
                }
            }
        }
    }
    Ok(())
}

fn options(write: bool) -> OpenOptions {
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
        // Constants only; all operations remain safe std. NONBLOCK prevents a
        // malicious FIFO from hanging the app before regular-file validation.
        options
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .mode(0o600);
    }
    options
}

fn try_lock_file(file: &File) -> Result<(), TryLockError> {
    // Rust 1.97's std Unix file-lock implementation excludes Android. Use a
    // safe borrowed-fd wrapper there; never continue with an unlocked writer.
    #[cfg(target_os = "android")]
    {
        rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                let error = io::Error::from(error);
                if error.kind() == io::ErrorKind::WouldBlock {
                    TryLockError::WouldBlock
                } else {
                    TryLockError::Error(error)
                }
            },
        )
    }
    #[cfg(not(target_os = "android"))]
    {
        file.try_lock()
    }
}

fn checked_file(path: &Path) -> Result<Option<Metadata>, PreferenceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular(&metadata)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PreferenceError::ReadFailed),
    }
}

fn validate_directory(metadata: &Metadata) -> Result<(), PreferenceError> {
    if !metadata.is_dir() || is_link_or_reparse(metadata) {
        return Err(PreferenceError::UnsafeEntry);
    }
    Ok(())
}

fn validate_regular(metadata: &Metadata) -> Result<(), PreferenceError> {
    if !metadata.is_file() || is_link_or_reparse(metadata) {
        return Err(PreferenceError::UnsafeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(PreferenceError::UnsafeEntry);
        }
    }
    Ok(())
}

fn same_file_at_path(path: &Path, opened: &Metadata) -> Result<(), PreferenceError> {
    let current = checked_file(path)?.ok_or(PreferenceError::ExternalChange)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(PreferenceError::ExternalChange);
        }
    }
    #[cfg(not(unix))]
    {
        // Windows denies share-delete on the opened file and every ancestor;
        // the caller-provided private directory provenance is still required.
        let _ = (current, opened);
    }
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
