// SPDX-License-Identifier: GPL-2.0-or-later
//! Typed restoration of the existing privileged registry, not another owner.
//!
//! No bytes, serde, file paths, transport pins, key attestation or enrollment
//! RPC are accepted here. A trusted host must decode its bounded protected
//! composite, establish that it is the current committed state, and then build
//! this typed checkpoint. Shape validation cannot detect a well-formed older
//! checkpoint or establish Windows caller privilege or storage freshness.
//!
//! Only active membership and the original allocator sequence are retained.
//! Revocation still removes an active entry; explicit privileged re-enrollment
//! remains allowed with a new revision. No permanent ID/key bans are invented.
//! Neither pending requests nor authorized decisions are checkpointed. A restored
//! registry enters a new ApprovalEngine, which starts a fresh random epoch and
//! has no old pending state. A live engine's registry cannot be swapped/reset.

use std::{collections::BTreeMap, fmt};

use approval_protocol::DeviceId;
use thiserror::Error;

use crate::{
    ApprovalEngine, DeviceKeys, Enrollment, MAX_TRUSTED_DEVICES, PrivilegedDeviceRegistry,
};

/// Immutable typed active membership. DeviceId and DeviceKeys already enforce
/// their nonzero identifier and canonical distinct-key construction invariants.
/// The enclosing checkpoint additionally validates global revision/key uniqueness.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryCheckpointEntry {
    device_id: DeviceId,
    revision: u64,
    keys: DeviceKeys,
}

impl RegistryCheckpointEntry {
    /// Construct metadata only; this is not permission to enroll or restore it.
    pub fn new(
        device_id: DeviceId,
        revision: u64,
        keys: DeviceKeys,
    ) -> Result<Self, RegistryCheckpointError> {
        if revision == 0 {
            return Err(RegistryCheckpointError::InvalidRevision);
        }
        Ok(Self {
            device_id,
            revision,
            keys,
        })
    }

    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn keys(&self) -> &DeviceKeys {
        &self.keys
    }
}

impl fmt::Debug for RegistryCheckpointEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCheckpointEntry")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Bounded immutable registry metadata. Clone copies at most 32 public-key rows,
/// never an engine, private key, request body or AuthorizedDecision capability.
/// This value has no serialization traits or untrusted wire parser. Its host
/// owns durable publication together with its device-to-transport-pin mapping.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistryCheckpoint {
    capacity: usize,
    next_revision: u64,
    entries: Vec<RegistryCheckpointEntry>,
}

impl RegistryCheckpoint {
    /// Validate the complete typed candidate without enrolling any device.
    ///
    /// Consumes at most capacity+1 entries; excess input fails rather than being
    /// truncated. Input ordering is irrelevant: accepted rows are stored in
    /// canonical DeviceId order. Duplicate IDs are rejected, never overwritten.
    /// Preserve next_revision even when entries is empty. u64::MAX is accepted
    /// as an exhausted allocator state; it must never be reset to regain space.
    pub fn new(
        capacity: usize,
        next_revision: u64,
        entries: impl IntoIterator<Item = RegistryCheckpointEntry>,
    ) -> Result<Self, RegistryCheckpointError> {
        validate_header(capacity, next_revision)?;
        let mut bounded = Vec::with_capacity(capacity);
        for entry in entries {
            if bounded.len() == capacity {
                return Err(RegistryCheckpointError::TooManyEntries);
            }
            bounded.push(entry);
        }
        validate_entries(capacity, next_revision, &bounded)?;
        bounded.sort_unstable_by_key(|entry| entry.device_id);
        Ok(Self {
            capacity,
            next_revision,
            entries: bounded,
        })
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Exact next allocator value, not max(active revisions)+1. Revocation and
    /// replacement leave gaps which must survive process restart unchanged.
    pub const fn next_revision(&self) -> u64 {
        self.next_revision
    }

    /// Active entries in ascending DeviceId order; no mutable access is exposed.
    pub fn entries(&self) -> &[RegistryCheckpointEntry] {
        &self.entries
    }
}

impl fmt::Debug for RegistryCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistryCheckpoint")
            .field("capacity", &self.capacity)
            .field("next_revision", &self.next_revision)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl PrivilegedDeviceRegistry {
    /// Export bounded metadata from this exact live allocator. A successful
    /// export is not a durable commit or permission to publish enrollment effects.
    pub fn checkpoint_for_privileged_host(&self) -> RegistryCheckpoint {
        RegistryCheckpoint {
            capacity: self.capacity,
            next_revision: self.next_revision,
            entries: self
                .devices
                .iter()
                .map(|(device_id, enrollment)| RegistryCheckpointEntry {
                    device_id: *device_id,
                    revision: enrollment.revision,
                    keys: enrollment.keys.clone(),
                })
                .collect(),
        }
    }

    /// Restore active membership and allocator history exactly. Never replay
    /// enroll calls, infer next_revision from active rows, or default on failure.
    /// The host must supply current protected committed state and serialize this
    /// initialization before admitting peers. This does not prove that provenance.
    pub fn restore_for_privileged_host(
        checkpoint: RegistryCheckpoint,
    ) -> Result<Self, RegistryCheckpointError> {
        validate_entries(
            checkpoint.capacity,
            checkpoint.next_revision,
            &checkpoint.entries,
        )?;
        let devices: BTreeMap<_, _> = checkpoint
            .entries
            .into_iter()
            .map(|entry| {
                (
                    entry.device_id,
                    Enrollment {
                        revision: entry.revision,
                        keys: entry.keys,
                    },
                )
            })
            .collect();
        Ok(Self {
            devices,
            capacity: checkpoint.capacity,
            next_revision: checkpoint.next_revision,
        })
    }
}

impl ApprovalEngine {
    /// Read-only export from the engine's actual registry. It does not expose
    /// mutable registry access, restore pending state or replace the live owner.
    /// Enrollment changes, durable commit and adapter/peer dispatch must remain
    /// serialized by the containing service; this is not a storage receipt.
    pub fn registry_checkpoint_for_privileged_host(&self) -> RegistryCheckpoint {
        self.devices.checkpoint_for_privileged_host()
    }
}

fn validate_header(capacity: usize, next_revision: u64) -> Result<(), RegistryCheckpointError> {
    if capacity == 0 || capacity > MAX_TRUSTED_DEVICES {
        return Err(RegistryCheckpointError::InvalidCapacity);
    }
    if next_revision == 0 {
        return Err(RegistryCheckpointError::InvalidNextRevision);
    }
    Ok(())
}

fn validate_entries(
    capacity: usize,
    next_revision: u64,
    entries: &[RegistryCheckpointEntry],
) -> Result<(), RegistryCheckpointError> {
    validate_header(capacity, next_revision)?;
    if entries.len() > capacity {
        return Err(RegistryCheckpointError::TooManyEntries);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.revision == 0 || entry.revision >= next_revision {
            return Err(RegistryCheckpointError::InvalidRevision);
        }
        if entry.keys.approval() == entry.keys.denial() {
            return Err(RegistryCheckpointError::KeyReuse);
        }
        for previous in &entries[..index] {
            if previous.device_id == entry.device_id {
                return Err(RegistryCheckpointError::DuplicateDevice);
            }
            if previous.revision == entry.revision {
                return Err(RegistryCheckpointError::DuplicateRevision);
            }
            if previous.keys.shares_key(&entry.keys) {
                return Err(RegistryCheckpointError::KeyReuse);
            }
        }
    }
    Ok(())
}

/// Fixed validation categories; identifiers, public keys and input values are
/// deliberately not attached to diagnostics. No raw storage/parser error exists.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryCheckpointError {
    #[error("registry checkpoint capacity is outside the supported bound")]
    InvalidCapacity,
    #[error("registry checkpoint exceeds its configured active-entry capacity")]
    TooManyEntries,
    #[error("registry checkpoint next revision must be nonzero")]
    InvalidNextRevision,
    #[error("registry checkpoint entry revision must be nonzero and below its next revision")]
    InvalidRevision,
    #[error("registry checkpoint contains a duplicate active device")]
    DuplicateDevice,
    #[error("registry checkpoint contains a duplicate active revision")]
    DuplicateRevision,
    #[error("registry checkpoint reuses an active purpose-specific key")]
    KeyReuse,
}
