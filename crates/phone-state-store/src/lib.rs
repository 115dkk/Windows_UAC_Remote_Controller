// SPDX-License-Identifier: GPL-2.0-or-later

//! Bounded native checkpoint bytes, not a key store or an authorization source.
//!
//! The native domain owner supplies an already provisioned private directory,
//! validates checkpoint contents, and commits before emitting external effects.
//! Android/Linux commits require file and directory synchronization. Windows
//! receipts deliberately describe only file synchronization and are for model
//! tests, not proof of Android power-loss durability. See the crate README.

#![forbid(unsafe_code)]

use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;

mod storage;

pub use storage::NativePrivateDirectory;

/// Maximum domain payload; the fixed storage frame adds 54 bytes.
pub const MAX_SNAPSHOT_BYTES: usize = 384 * 1024;
pub const SNAPSHOT_FILE_NAME: &str = "phone-state.snapshot";
pub const LOCK_FILE_NAME: &str = "phone-state.lock";
pub const STAGING_FILE_NAME: &str = "phone-state.staging";
pub const INTENT_FILE_NAME: &str = "phone-state.intent";

const MAGIC: &[u8; 8] = b"WUACPST\0";
const VERSION: u16 = 1;
const PREFIX_BYTES: usize = 22;
const HEADER_BYTES: usize = PREFIX_BYTES + 32;
const MAX_FILE_BYTES: usize = HEADER_BYTES + MAX_SNAPSHOT_BYTES;

/// What synchronization calls this commit completed, not authentication proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Durability {
    /// Android/Linux: file and containing-directory synchronization completed.
    /// This remains conditional on the filesystem/device honoring those calls.
    DirectorySynced,
    /// Windows model tests only: file synchronization completed. No portable
    /// directory-flush or power-loss-persistent rename is established here.
    FileSyncedOnly,
}

/// A successful byte-store operation. Never a peer/approval/OS-action receipt.
#[must_use]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    generation: u64,
    durability: Durability,
    changed: bool,
}

impl CommitReceipt {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn durability(self) -> Durability {
        self.durability
    }

    pub const fn changed(self) -> bool {
        self.changed
    }
}

/// Fixed categories only. No OS text, paths, payloads, or nested error sources.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    #[error("the native private storage directory is unavailable")]
    DirectoryUnavailable,
    #[error("this platform has no supported storage durability profile")]
    UnsupportedPlatform,
    #[error("a storage path or entry is not supported")]
    UnsafeEntry,
    #[error("phone state already exists or creation was incomplete")]
    StateAlreadyExists,
    #[error("required phone state is missing")]
    MissingState,
    #[error("another owner holds the phone state writer lock")]
    WriterLocked,
    #[error("incomplete phone state requires explicit native recovery")]
    RecoveryRequired,
    #[error("the phone state snapshot is corrupt")]
    CorruptSnapshot,
    #[error("the phone state snapshot version is unsupported")]
    UnsupportedVersion,
    #[error("the phone state snapshot exceeds its byte limit")]
    SnapshotTooLarge,
    #[error("phone state changed outside this owner")]
    ExternalChange,
    #[error("phone state could not be read")]
    ReadFailed,
    #[error("phone state could not be written")]
    WriteFailed,
    #[error("phone state commit completion is uncertain")]
    CommitUncertain,
    #[error("the phone state owner is faulted and must not emit effects")]
    Poisoned,
    #[error("the phone state generation is exhausted")]
    GenerationExhausted,
}

struct Snapshot {
    frame: Vec<u8>,
    generation: u64,
}

impl Snapshot {
    fn encode(payload: &[u8], generation: u64) -> Result<Self, StoreError> {
        if payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::SnapshotTooLarge);
        }
        if generation == 0 {
            return Err(StoreError::CorruptSnapshot);
        }
        let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&VERSION.to_be_bytes());
        frame.extend_from_slice(&generation.to_be_bytes());
        let length = u32::try_from(payload.len()).map_err(|_| StoreError::SnapshotTooLarge)?;
        frame.extend_from_slice(&length.to_be_bytes());
        let mut hash = Sha256::new();
        hash.update(&frame);
        hash.update(payload);
        frame.extend_from_slice(&hash.finalize());
        frame.extend_from_slice(payload);
        Ok(Self { frame, generation })
    }

    fn decode(frame: Vec<u8>) -> Result<Self, StoreError> {
        if frame.len() > MAX_FILE_BYTES {
            return Err(StoreError::SnapshotTooLarge);
        }
        if frame.len() < HEADER_BYTES || &frame[..8] != MAGIC {
            return Err(StoreError::CorruptSnapshot);
        }
        let version = u16::from_be_bytes(
            frame[8..10]
                .try_into()
                .map_err(|_| StoreError::CorruptSnapshot)?,
        );
        if version != VERSION {
            return Err(StoreError::UnsupportedVersion);
        }
        let generation = u64::from_be_bytes(
            frame[10..18]
                .try_into()
                .map_err(|_| StoreError::CorruptSnapshot)?,
        );
        if generation == 0 {
            return Err(StoreError::CorruptSnapshot);
        }
        let length = u32::from_be_bytes(
            frame[18..22]
                .try_into()
                .map_err(|_| StoreError::CorruptSnapshot)?,
        );
        let length = usize::try_from(length).map_err(|_| StoreError::SnapshotTooLarge)?;
        if length > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::SnapshotTooLarge);
        }
        if frame.len() != HEADER_BYTES + length {
            return Err(StoreError::CorruptSnapshot);
        }
        let mut hash = Sha256::new();
        hash.update(&frame[..PREFIX_BYTES]);
        hash.update(&frame[HEADER_BYTES..]);
        if hash.finalize()[..] != frame[PREFIX_BYTES..HEADER_BYTES] {
            return Err(StoreError::CorruptSnapshot);
        }
        Ok(Self { frame, generation })
    }

    fn payload(&self) -> &[u8] {
        &self.frame[HEADER_BYTES..]
    }
}

/// One non-cloneable native owner and one lifetime OS writer lock.
///
/// All methods perform blocking filesystem I/O except `snapshot`. Call from the
/// native storage actor/background worker, never a UI event-loop callback. The
/// opaque bytes are domain-owned: this type does not validate enrollment,
/// replay cutoffs, permissions, bodies, keys, or checkpoint schema semantics.
pub struct SnapshotStore {
    storage: storage::Storage,
    current: Snapshot,
    poisoned: bool,
}

impl fmt::Debug for SnapshotStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnapshotStore")
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl SnapshotStore {
    /// Create generation one only when every fixed store artifact is absent.
    /// The host must separately establish that fresh enrollment is appropriate;
    /// absence alone cannot distinguish first use from deleted/restored state.
    /// Failures can leave an explicit incomplete store; nothing is auto-cleaned.
    pub fn create_fresh(
        directory: NativePrivateDirectory,
        initial: &[u8],
    ) -> Result<(Self, CommitReceipt), StoreError> {
        let current = Snapshot::encode(initial, 1)?;
        let storage = storage::Storage::create_fresh(directory)?;
        let durability = storage.replace(None, &current.frame)?;
        let receipt = CommitReceipt {
            generation: 1,
            durability,
            changed: true,
        };
        Ok((
            Self {
                storage,
                current,
                poisoned: false,
            },
            receipt,
        ))
    }

    /// Open only complete existing state. Missing files, a dirty intent, staging
    /// leftovers, and corrupt frames fail closed without rewriting any file.
    pub fn open_existing(directory: NativePrivateDirectory) -> Result<Self, StoreError> {
        let storage = storage::Storage::open_existing(directory)?;
        let current = Snapshot::decode(storage.read_current()?)?;
        Ok(Self {
            storage,
            current,
            poisoned: false,
        })
    }

    /// The cached, frame-checked payload, not a fresh disk read or authority.
    /// Domain decoding is required before use. A faulted owner exposes no bytes.
    pub fn snapshot(&self) -> Result<&[u8], StoreError> {
        self.ensure_healthy()?;
        Ok(self.current.payload())
    }

    /// Reserve the fixed intent before accepting an intake classification.
    /// On Android/Linux the intent's file and directory barriers complete
    /// before this returns. On Windows it remains a FileSyncedOnly model.
    ///
    /// The domain owner must keep its candidate state/effects unaccepted until
    /// this succeeds, and release them only after `Transition::commit` succeeds.
    /// Failure before the barrier is unaccepted input, not a persisted drop.
    /// Dropping the guard leaves intent and faults this owner; no abort cleanup
    /// or recovery is implicit. A successful unchanged commit is explicit.
    pub fn begin_transition(&mut self) -> Result<Transition<'_>, StoreError> {
        self.ensure_healthy()?;
        let result = self.storage.reserve(Some(&self.current.frame));
        // Fault while reserved, not just in Drop: even forgetting a guard
        // cannot make this owner reuse cached state or start another commit.
        self.poisoned = true;
        let intent = result?;
        Ok(Transition {
            store: self,
            intent: Some(intent),
            completed: false,
        })
    }

    /// Commit before releasing domain effects. Every call checks the existing
    /// disk frame, even for identical bytes. No-op commits synchronize without
    /// rewriting bytes or incrementing the generation. Storage failures poison
    /// this owner; in particular an uncertain commit is never reported as an
    /// unchanged old snapshot. Oversized caller input alone does not poison it.
    /// For intake acceptance, use `begin_transition` BEFORE classification;
    /// this convenience method cannot protect an already accepted disposition.
    pub fn commit(&mut self, payload: &[u8]) -> Result<CommitReceipt, StoreError> {
        self.ensure_healthy()?;
        if payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::SnapshotTooLarge);
        }
        let result = self.commit_checked(payload);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn commit_checked(&mut self, payload: &[u8]) -> Result<CommitReceipt, StoreError> {
        if payload == self.current.payload() {
            let durability = self.storage.sync_unchanged(&self.current.frame)?;
            return Ok(CommitReceipt {
                generation: self.current.generation,
                durability,
                changed: false,
            });
        }
        let generation = self
            .current
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let next = Snapshot::encode(payload, generation)?;
        let durability = self
            .storage
            .replace(Some(&self.current.frame), &next.frame)?;
        self.current = next;
        Ok(CommitReceipt {
            generation,
            durability,
            changed: true,
        })
    }

    fn ensure_healthy(&self) -> Result<(), StoreError> {
        if self.poisoned {
            Err(StoreError::Poisoned)
        } else {
            Ok(())
        }
    }
}

/// An exclusive intake reservation, not permission to approve or notify.
///
/// Only successful explicit commit clears its intent. Drop (including unwind)
/// leaves the intent and faults the owner. No paths, bytes or OS handles are
/// exposed. Checkpoint schema and acceptance/effects remain domain-owned.
#[must_use = "commit the transition explicitly; dropping it faults the store"]
pub struct Transition<'store> {
    store: &'store mut SnapshotStore,
    intent: Option<storage::PendingIntent>,
    completed: bool,
}

impl fmt::Debug for Transition<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Transition(reserved_native_state)")
    }
}

impl Transition<'_> {
    /// Finish this reserved transition before releasing candidate state/effects.
    /// Same bytes explicitly synchronize and clear intent without changing the
    /// snapshot generation. Any failure, including oversized input, leaves a
    /// faulted owner and does not erase unfinished intent.
    pub fn commit(mut self, payload: &[u8]) -> Result<CommitReceipt, StoreError> {
        if payload.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::SnapshotTooLarge);
        }
        let changed = payload != self.store.current.payload();
        let generation = if changed {
            self.store
                .current
                .generation
                .checked_add(1)
                .ok_or(StoreError::GenerationExhausted)?
        } else {
            self.store.current.generation
        };
        let next = if changed {
            Some(Snapshot::encode(payload, generation)?)
        } else {
            None
        };
        let frame = next
            .as_ref()
            .map_or(self.store.current.frame.as_slice(), |snapshot| {
                snapshot.frame.as_slice()
            });
        let intent = self.intent.take().ok_or(StoreError::Poisoned)?;
        let durability =
            self.store
                .storage
                .commit_reserved(intent, Some(&self.store.current.frame), frame)?;
        if let Some(next) = next {
            self.store.current = next;
        }
        self.store.poisoned = false;
        self.completed = true;
        Ok(CommitReceipt {
            generation,
            durability,
            changed,
        })
    }
}

impl Drop for Transition<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.store.poisoned = true;
        }
        // PendingIntent only closes the handle; its filename is not removed.
    }
}
