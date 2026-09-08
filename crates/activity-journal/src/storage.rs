use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::{FileTarget, IoOperation, JournalError};

pub(crate) const CURRENT_NAME: &str = "activity.jsonl";
pub(crate) const STAGING_NAME: &str = "activity.staging";
const LOCK_NAME: &str = "journal.lock";

pub(crate) struct Storage {
    directory: PathBuf,
    // Dropping the handle releases the OS lock. Never delete the lock pathname:
    // doing so could give another opener a different, concurrently locked inode.
    _lock: File,
}

impl fmt::Debug for Storage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Storage")
            .field("writer_lock_held", &true)
            .finish_non_exhaustive()
    }
}

impl Storage {
    pub(crate) fn open(directory: &Path) -> Result<Self, JournalError> {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| io_error(IoOperation::InspectDirectory, error))?;
        if !metadata.is_dir() || is_link_or_reparse(&metadata) {
            return Err(JournalError::UnsafeEntry(FileTarget::Directory));
        }
        let directory = fs::canonicalize(directory)
            .map_err(|error| io_error(IoOperation::ResolveDirectory, error))?;
        let lock_path = directory.join(LOCK_NAME);
        checked_entry(&lock_path, FileTarget::Lock)?;
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                checked_entry(&lock_path, FileTarget::Lock)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(|error| io_error(IoOperation::OpenLock, error))?
            }
            Err(error) => return Err(io_error(IoOperation::OpenLock, error)),
        };
        let metadata = lock
            .metadata()
            .map_err(|error| io_error(IoOperation::InspectEntry, error))?;
        validate_regular(&metadata, FileTarget::Lock)?;
        if metadata.len() != 0 {
            return Err(JournalError::UnexpectedLockContent);
        }
        match try_lock_file(&lock) {
            Ok(()) => Ok(Self {
                directory,
                _lock: lock,
            }),
            Err(TryLockError::WouldBlock) => Err(JournalError::WriterLocked),
            Err(TryLockError::Error(error)) => Err(io_error(IoOperation::AcquireLock, error)),
        }
    }

    pub(crate) fn read_current(&self, max_bytes: usize) -> Result<Option<Vec<u8>>, JournalError> {
        self.ensure_no_staging()?;
        let path = self.directory.join(CURRENT_NAME);
        let Some(metadata) = checked_entry(&path, FileTarget::Current)? else {
            return Ok(None);
        };
        if metadata.len() > max_bytes as u64 {
            return Err(JournalError::StorageTooLarge);
        }
        let file = File::open(path).map_err(|error| io_error(IoOperation::ReadCurrent, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error(IoOperation::InspectEntry, error))?;
        validate_regular(&metadata, FileTarget::Current)?;
        if metadata.len() > max_bytes as u64 {
            return Err(JournalError::StorageTooLarge);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        // Bound the actual read too, rather than trusting a pre-read size check.
        file.take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(IoOperation::ReadCurrent, error))?;
        if bytes.len() > max_bytes {
            return Err(JournalError::StorageTooLarge);
        }
        Ok(Some(bytes))
    }

    pub(crate) fn replace(&self, bytes: &[u8]) -> Result<(), JournalError> {
        self.ensure_no_staging()?;
        self.validate_current_entry()?;
        let staging_path = self.directory.join(STAGING_NAME);
        let mut staging = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(JournalError::StagingRecoveryRequired);
            }
            Err(error) => return Err(io_error(IoOperation::CreateStaging, error)),
        };
        // Failed writes/sync/rename keep the previous current file, and leave
        // this one fixed-name staging file for explicit operator recovery.
        staging
            .write_all(bytes)
            .map_err(|error| io_error(IoOperation::WriteStaging, error))?;
        staging
            .sync_all()
            .map_err(|error| io_error(IoOperation::SyncStaging, error))?;
        drop(staging);
        replace_staging(&staging_path, &self.directory.join(CURRENT_NAME))
    }

    pub(crate) fn validate_current_entry(&self) -> Result<(), JournalError> {
        checked_entry(&self.directory.join(CURRENT_NAME), FileTarget::Current)?;
        Ok(())
    }

    pub(crate) fn discard_staging(&self) -> Result<(), JournalError> {
        let path = self.directory.join(STAGING_NAME);
        if checked_entry(&path, FileTarget::Staging)?.is_some() {
            fs::remove_file(path).map_err(|error| io_error(IoOperation::RemoveStaging, error))?;
        }
        Ok(())
    }

    fn ensure_no_staging(&self) -> Result<(), JournalError> {
        if checked_entry(&self.directory.join(STAGING_NAME), FileTarget::Staging)?.is_some() {
            return Err(JournalError::StagingRecoveryRequired);
        }
        Ok(())
    }
}

fn checked_entry(path: &Path, target: FileTarget) -> Result<Option<Metadata>, JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_regular(&metadata, target)?;
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(IoOperation::InspectEntry, error)),
    }
}

fn validate_regular(metadata: &Metadata, target: FileTarget) -> Result<(), JournalError> {
    if !metadata.is_file() || is_link_or_reparse(metadata) {
        Err(JournalError::UnsafeEntry(target))
    } else {
        Ok(())
    }
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

fn replace_staging(staging: &Path, current: &Path) -> Result<(), JournalError> {
    // Same-directory atomic replacement on a filesystem providing rename's
    // replacement semantics. No cross-platform power-loss durability claim:
    // this safe-std implementation does not fsync the containing directory.
    fs::rename(staging, current).map_err(|error| io_error(IoOperation::ReplaceCurrent, error))
}

fn io_error(operation: IoOperation, error: io::Error) -> JournalError {
    JournalError::Io {
        operation,
        kind: error.kind(),
    }
}

fn try_lock_file(file: &File) -> Result<(), TryLockError> {
    // std File::try_lock is Unsupported on Android in Rust 1.97. The safe
    // rustix API retains the same nonblocking, lifetime-of-this-file contract.
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{CURRENT_NAME, STAGING_NAME, replace_staging};
    use crate::{IoOperation, JournalError};

    #[test]
    fn failed_replacement_preserves_the_previous_current_file() {
        let directory = tempfile::Builder::new()
            .prefix("activity-journal-rename-test-")
            .tempdir()
            .expect("private test directory");
        let current = directory.path().join(CURRENT_NAME);
        fs::write(&current, b"synthetic previous bytes").expect("write fixture");
        let result = replace_staging(&directory.path().join(STAGING_NAME), &current);
        assert!(matches!(
            result,
            Err(JournalError::Io {
                operation: IoOperation::ReplaceCurrent,
                ..
            })
        ));
        assert_eq!(
            fs::read(current).expect("read fixture"),
            b"synthetic previous bytes"
        );
    }
}
