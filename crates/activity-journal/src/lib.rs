//! Bounded diagnostic storage and a separate pure terminal-outcome history model.
//!
//! [`OutcomeHistory`] performs no filesystem I/O. Its bounded bytes must be
//! committed with the producer inbox and its acknowledgments in one transaction.
//! Its wall-clock and retained-row deduplication rules deliberately differ from
//! the filesystem-backed [`Journal`] described below. Neither model is authority.
//!
//! This crate is not authorization state, a credential store, or tamper-proof
//! audit storage. Its typed events cannot carry arbitrary strings or payloads.
//! Application authorization must never depend on a successful journal write,
//! journal replay, or an event claiming that Windows applied a phone decision.
//!
//! # Execution and trust boundary
//!
//! Run this synchronous, bounded full-file I/O on a background journal task,
//! never the latency-critical approval path. A trusted service chooses the
//! directory and supplies the time. Do not expose its path, append, clear, or
//! recovery operations as a generic network/UI API.
//!
//! The directory must already exist on a filesystem supporting exclusive file
//! locks and same-directory atomic replacement. OS ownership/ACLs must protect
//! it and every ancestor against untrusted mutation. We reject final-component
//! symlinks/reparse points where detectable; safe std path-based APIs cannot
//! establish those ACLs, prevent all path races, or defeat an attacker who can
//! mutate the directory. Windows service ACL provisioning is outside this crate.
//!
//! `journal.lock` remains in place and is held exclusively for the lifetime of
//! `Journal`. A fixed `activity.staging` file is created exclusively, synced,
//! and renamed over `activity.jsonl`. A failed write/rename leaves the previous
//! current file and at most one staging file. Recovery is explicit; unrelated
//! files are never removed. This is atomic replacement, not a cross-platform
//! power-loss durability guarantee: the directory itself is not synced.
//!
//! # Retention and clock rollback
//!
//! Every open, append, read, and purge validates bounded storage. Malformed,
//! oversized, unsupported-version, and unfinished files fail without silently
//! truncating data. Explicit clear can recover from corrupt/oversized storage;
//! staging disposal never promotes unvalidated staged data.
//!
//! Retention uses a persisted nondecreasing trusted-clock high-water mark.
//! Records exactly `max_age_ms` old are retained. A backwards clock never moves
//! the cutoff backwards; append rejects timestamps below that high-water mark.
//! Open/read/purge still enforce record and byte caps and retain the time floor.
//! Elapsed age cannot be inferred while a supplied clock is stalled/rolled back;
//! byte/count bounds still hold, and historical records never reappear. Explicit
//! clear discards all history and resets the clock baseline.

#![forbid(unsafe_code)]

mod format;
mod outcome_history;
mod storage;
mod types;

use std::io;
use std::path::Path;

use thiserror::Error;

use format::State;
pub use outcome_history::{
    HistoryInsert, HistoryPruneReport, MAX_OUTCOME_HISTORY_BYTES, MAX_OUTCOME_HISTORY_RECORDS,
    OutcomeHistory, OutcomeHistoryError, OutcomeHistoryLimits, OutcomeHistoryRecord,
};
use storage::Storage;
pub use types::{
    ActivityEvent, ActivityRecord, ConnectionOutcome, Decision, FailureKind, Limits, LimitsError,
    MAX_FILE_BYTES, MAX_LINE_BYTES, MAX_RECORDS, MAX_RETENTION_MS, MAX_UNIX_MILLIS, MIN_LINE_BYTES,
    PurgeReport, RequestOutcome, ServiceOutcome, TimestampError, UnixMillis,
};

/// Exclusive owner of one bounded diagnostic journal. `Debug` does not include
/// filesystem paths, file contents, or operating-system error strings.
#[derive(Debug)]
pub struct Journal {
    storage: Storage,
    limits: Limits,
}

impl Journal {
    /// Opens an existing trusted directory, creating an empty journal if absent,
    /// and immediately persists any age purge or clock high-water update.
    ///
    /// Existing storage must already fit the configured byte/line/count limits.
    /// A crash staging file blocks open until explicitly discarded or cleared.
    pub fn open(
        directory: impl AsRef<Path>,
        limits: Limits,
        now: UnixMillis,
    ) -> Result<Self, JournalError> {
        let journal = Self {
            storage: Storage::open(directory.as_ref())?,
            limits,
        };
        let bytes = journal.storage.read_current(limits.max_file_bytes())?;
        let new_file = bytes.is_none();
        let mut state = match bytes {
            Some(bytes) => State::decode(&bytes, limits)?,
            None => State::empty(now),
        };
        let prepared = state.prepare(now, limits)?;
        if new_file || prepared.changed {
            journal.storage.replace(&prepared.bytes)?;
        }
        Ok(journal)
    }

    /// Appends one trusted diagnostic outcome. The newest records fitting all
    /// age/count/byte bounds survive. Returns the successful retention changes.
    /// A clock earlier than any previously persisted observation is rejected.
    pub fn append(
        &mut self,
        now: UnixMillis,
        event: ActivityEvent,
    ) -> Result<PurgeReport, JournalError> {
        let mut state = self.load()?;
        if now < state.last_observed() {
            return Err(JournalError::ClockRollback);
        }
        state.records.push(ActivityRecord::new(now, event));
        let prepared = state.prepare(now, self.limits)?;
        self.storage.replace(&prepared.bytes)?;
        Ok(prepared.report)
    }

    /// Returns at most `limit` retained records, newest first. The caller cannot
    /// expand storage/memory bounds with a large requested limit. A read also
    /// purges expired records and persists a newer trusted-clock observation.
    pub fn recent(
        &mut self,
        now: UnixMillis,
        limit: usize,
    ) -> Result<Vec<ActivityRecord>, JournalError> {
        let mut state = self.load()?;
        let prepared = state.prepare(now, self.limits)?;
        if prepared.changed {
            self.storage.replace(&prepared.bytes)?;
        }
        Ok(state.records.into_iter().rev().take(limit).collect())
    }

    /// Enforces age/count/byte bounds using the nondecreasing trusted-clock
    /// floor. Already malformed or oversized input is rejected, not repaired.
    pub fn purge(&mut self, now: UnixMillis) -> Result<PurgeReport, JournalError> {
        let mut state = self.load()?;
        let prepared = state.prepare(now, self.limits)?;
        if prepared.changed {
            self.storage.replace(&prepared.bytes)?;
        }
        Ok(prepared.report)
    }

    /// Explicitly deletes all journal history and any regular staging file,
    /// then writes an empty journal with a reset trusted-clock baseline. It can
    /// recover corrupt/oversized current storage without parsing it. Links and
    /// other non-regular owned entries are still rejected and not removed.
    ///
    /// The previous current file is retained if creating, writing, syncing, or
    /// replacing the new file fails. A prior staging file may already have been
    /// removed because its deletion is explicitly part of this clear operation.
    pub fn clear(&mut self, now: UnixMillis) -> Result<(), JournalError> {
        self.storage.validate_current_entry()?;
        self.storage.discard_staging()?;
        let prepared = State::empty(now).prepare(now, self.limits)?;
        self.storage.replace(&prepared.bytes)
    }

    /// Explicit recovery for a directory whose current storage cannot be opened.
    /// Acquires the same exclusive writer lock and performs `clear` without
    /// first deserializing or silently repairing damaged data.
    pub fn clear_storage(
        directory: impl AsRef<Path>,
        limits: Limits,
        now: UnixMillis,
    ) -> Result<Self, JournalError> {
        let mut journal = Self {
            storage: Storage::open(directory.as_ref())?,
            limits,
        };
        journal.clear(now)?;
        Ok(journal)
    }

    /// Explicitly discards only the regular `activity.staging` file under an
    /// exclusive writer lock. Current storage and unrelated files are untouched.
    /// Drop any open `Journal` before calling this associated recovery function.
    /// The staged contents may be incomplete forensic data; callers must choose
    /// this destructive recovery deliberately. No automatic stage promotion.
    pub fn discard_staging(directory: impl AsRef<Path>) -> Result<(), JournalError> {
        Storage::open(directory.as_ref())?.discard_staging()
    }

    pub const fn limits(&self) -> Limits {
        self.limits
    }

    fn load(&self) -> Result<State, JournalError> {
        let bytes = self
            .storage
            .read_current(self.limits.max_file_bytes())?
            .ok_or(JournalError::MissingStorage)?;
        State::decode(&bytes, self.limits)
    }
}

/// Fixed categories only: never a path, input contents, or raw OS/JSON error.
#[derive(Debug, Error)]
pub enum JournalError {
    #[error("another writer owns the activity journal")]
    WriterLocked,
    #[error("journal lock file unexpectedly contains data")]
    UnexpectedLockContent,
    #[error("journal entry is not an accepted regular file or directory: {0:?}")]
    UnsafeEntry(FileTarget),
    #[error("journal staging file requires explicit recovery")]
    StagingRecoveryRequired,
    #[error("activity journal storage is missing")]
    MissingStorage,
    #[error("activity journal storage is malformed or has unsupported metadata")]
    CorruptStorage,
    #[error("activity journal exceeds the configured file byte limit")]
    StorageTooLarge,
    #[error("activity journal exceeds the configured record count")]
    TooManyRecords,
    #[error("activity journal exceeds the configured JSON line byte limit")]
    LineTooLarge,
    #[error("activity journal could not encode its fixed event schema")]
    EncodingFailed,
    #[error("activity timestamp precedes the persisted trusted-clock observation")]
    ClockRollback,
    #[error("activity journal I/O failed during {operation:?}: {kind:?}")]
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTarget {
    Directory,
    Lock,
    Current,
    Staging,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOperation {
    InspectDirectory,
    ResolveDirectory,
    InspectEntry,
    OpenLock,
    AcquireLock,
    ReadCurrent,
    CreateStaging,
    WriteStaging,
    SyncStaging,
    ReplaceCurrent,
    RemoveStaging,
}
