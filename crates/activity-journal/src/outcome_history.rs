// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure body-free display history for a single atomic inbox/history owner.
//!
//! This model has no store, authentication, acknowledgment or notification API.
//! The native owner must put the complete history and producer replay state in
//! the SAME durable transaction as removal from the producer outcome outbox.
//! Never acknowledge a producer after only an in-memory insert or encoding.
//!
//! Deduplication lasts only while a row is retained. Prune, capacity eviction and
//! clear do not keep hidden receipt pins: persistent producer replay protection
//! must prevent an already acknowledged request from producing a new outcome.
//! This is not independent exactly-once delivery or protection against rollback
//! of the enclosing state. Encoded IDs are opaque display metadata, not proofs.
//!
//! Native UNIX time is only first-recorded display time and a retention input.
//! Backward corrections are accepted without changing existing timestamps. Age
//! pruning retains future-dated rows until native time catches up; insertion
//! order, not wall-clock order, enforces the independent count bound. A forward
//! correction can prune early. A later correction cannot recover removed data;
//! supplying a pruned ID again CAN reinsert it here, so the enclosing atomic
//! owner and producer replay guards must prevent that legitimate redelivery.
//! Authorization needs its own monotonic clocks and never uses these timestamps.
//! An unavailable/invalid native time must be rejected by the owner before
//! recording or acknowledging an outcome.

use std::fmt;

use notification_policy::RequestOutcome;
use phone_request_core::PendingOutcome;
use thiserror::Error;

use crate::{MAX_RETENTION_MS, UnixMillis};

pub const MAX_OUTCOME_HISTORY_RECORDS: usize = 512;
/// Complete maximum encoding: fixed 22-byte header and 512 fixed 41-byte rows.
pub const MAX_OUTCOME_HISTORY_BYTES: usize = 21_014;

const MAGIC: &[u8; 8] = b"WUACHST\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 22;
const RECORD_BYTES: usize = 41;
const DEFAULT_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

/// Validated bounds for this projection, separate from diagnostic Journal limits.
/// The native owner may choose fixed defaults and refuse other encoded limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeHistoryLimits {
    max_records: usize,
    max_age_ms: u64,
}

impl OutcomeHistoryLimits {
    pub const fn new(max_records: usize, max_age_ms: u64) -> Result<Self, OutcomeHistoryError> {
        if max_records == 0
            || max_records > MAX_OUTCOME_HISTORY_RECORDS
            || max_age_ms == 0
            || max_age_ms > MAX_RETENTION_MS
        {
            return Err(OutcomeHistoryError::InvalidLimits);
        }
        Ok(Self {
            max_records,
            max_age_ms,
        })
    }

    pub const fn max_records(self) -> usize {
        self.max_records
    }

    pub const fn max_age_ms(self) -> u64 {
        self.max_age_ms
    }
}

impl Default for OutcomeHistoryLimits {
    fn default() -> Self {
        Self {
            max_records: MAX_OUTCOME_HISTORY_RECORDS,
            max_age_ms: DEFAULT_MAX_AGE_MS,
        }
    }
}

/// Immutable projection of one producer outcome. It intentionally omits request
/// body, binding, device names, command lines, keys and authentication claims.
/// `CompletedByPc` is preserved exactly: it is NOT a diagnostic `WindowsApplied`,
/// nor does it distinguish approval, denial or another PC completion reason.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OutcomeHistoryRecord {
    delivery_id: [u8; 32],
    timestamp: UnixMillis,
    outcome: RequestOutcome,
}

impl OutcomeHistoryRecord {
    pub const fn delivery_id(&self) -> &[u8; 32] {
        &self.delivery_id
    }

    pub const fn timestamp(self) -> UnixMillis {
        self.timestamp
    }

    pub const fn outcome(self) -> RequestOutcome {
        self.outcome
    }
}

impl fmt::Debug for OutcomeHistoryRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutcomeHistoryRecord([redacted], not_windows_result_proof)")
    }
}

/// Bounded pure candidate state. Clone is also bounded; neither clone, mutation
/// nor encoding commits data or permits a caller to acknowledge the producer.
#[derive(Clone, Eq, PartialEq)]
pub struct OutcomeHistory {
    limits: OutcomeHistoryLimits,
    records: Vec<OutcomeHistoryRecord>,
}

impl fmt::Debug for OutcomeHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutcomeHistory")
            .field("limits", &self.limits)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl OutcomeHistory {
    pub fn new(limits: OutcomeHistoryLimits) -> Self {
        Self {
            limits,
            records: Vec::new(),
        }
    }

    pub const fn limits(&self) -> OutcomeHistoryLimits {
        self.limits
    }

    /// Retained rows, oldest insertion first. This is not sorted by timestamp:
    /// backward native-clock corrections never rewrite the historical order.
    pub fn records(&self) -> &[OutcomeHistoryRecord] {
        &self.records
    }

    /// Records a committed producer's immutable pending metadata as a candidate.
    ///
    /// Retained ID checks run BEFORE pruning. The same ID/outcome is unchanged,
    /// including its first timestamp, even if a duplicate carries a much later
    /// or earlier time. An ID/outcome conflict fails without any mutation. This
    /// projection cannot revalidate the binding hash because it stores no binding;
    /// the validated producer and enclosing private checkpoint supply that trust.
    ///
    /// A new row prunes ages relative to this actual native time, then evicts the
    /// oldest insertion if needed. Rows exactly max_age_ms old remain. Successful
    /// encoding and insertion are not durable receipts or proof of OS delivery.
    pub fn record_pending(
        &mut self,
        pending: &PendingOutcome,
        now: UnixMillis,
    ) -> Result<HistoryInsert, OutcomeHistoryError> {
        let id = pending.delivery_id();
        if let Some(existing) = self
            .records
            .iter()
            .find(|row| row.delivery_id == *id.as_bytes())
        {
            return if existing.outcome == pending.outcome() {
                Ok(HistoryInsert::AlreadyRecorded)
            } else {
                Err(OutcomeHistoryError::OutcomeConflict)
            };
        }

        // Reserve before any mutation. At full count, pruning/eviction makes an
        // existing slot available, so no transient 513th retained row is needed.
        if self.records.len() < self.limits.max_records {
            self.records
                .try_reserve_exact(1)
                .map_err(|_| OutcomeHistoryError::AllocationFailed)?;
        }
        let mut report = self.prune(now);
        if self.records.len() == self.limits.max_records {
            self.records.remove(0);
            report.capacity_records = 1;
        }
        self.records.push(OutcomeHistoryRecord {
            delivery_id: *id.as_bytes(),
            timestamp: now,
            outcome: pending.outcome(),
        });
        report.remaining_records = self.records.len();
        Ok(HistoryInsert::Inserted(report))
    }

    /// No permanent time floor: backward corrections retain future-dated rows,
    /// while the count bound still holds. Prune never restores removed rows, but
    /// does not prevent their IDs being inserted again. This touches history
    /// only; the caller must retain producer replay guards.
    pub fn prune(&mut self, now: UnixMillis) -> HistoryPruneReport {
        let cutoff = now.get().saturating_sub(self.limits.max_age_ms);
        let before = self.records.len();
        self.records.retain(|row| row.timestamp.get() >= cutoff);
        HistoryPruneReport {
            expired_records: before - self.records.len(),
            capacity_records: 0,
            remaining_records: self.records.len(),
        }
    }

    /// Clears visible history only. No producer acknowledgment or replay state
    /// is changed, and no hidden delivery-ID pins or clock floor remain here.
    pub fn clear(&mut self) -> usize {
        let count = self.records.len();
        self.records.clear();
        count
    }

    /// Strict bounded v1 binary projection. No checksum/authentication is added:
    /// the enclosing SnapshotStore owns framing/integrity/durability, and the
    /// native transaction owner must validate consistency with its producer.
    pub fn to_bytes(&self) -> Result<Vec<u8>, OutcomeHistoryError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(HEADER_BYTES + RECORD_BYTES * self.records.len())
            .map_err(|_| OutcomeHistoryError::AllocationFailed)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&(self.limits.max_records as u16).to_be_bytes());
        bytes.extend_from_slice(&self.limits.max_age_ms.to_be_bytes());
        bytes.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for record in &self.records {
            bytes.extend_from_slice(&record.delivery_id);
            bytes.extend_from_slice(&record.timestamp.get().to_be_bytes());
            bytes.push(outcome_tag(record.outcome));
        }
        Ok(bytes)
    }

    /// Decodes without pruning, time observations or reset-on-error. Rejects
    /// excess bytes/counts before allocating, malformed/truncated/trailing data,
    /// unsupported versions, invalid limits/times/tags and every duplicate ID.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OutcomeHistoryError> {
        if bytes.len() > MAX_OUTCOME_HISTORY_BYTES {
            return Err(OutcomeHistoryError::TooLarge);
        }
        let mut input = Input { bytes, offset: 0 };
        if input.take::<8>()? != *MAGIC {
            return Err(OutcomeHistoryError::MalformedEncoding);
        }
        if u16::from_be_bytes(input.take()?) != VERSION {
            return Err(OutcomeHistoryError::UnsupportedVersion);
        }
        let limits = OutcomeHistoryLimits::new(
            usize::from(u16::from_be_bytes(input.take()?)),
            u64::from_be_bytes(input.take()?),
        )?;
        let count = usize::from(u16::from_be_bytes(input.take()?));
        if count > limits.max_records {
            return Err(OutcomeHistoryError::TooManyRecords);
        }
        if bytes.len() != HEADER_BYTES + count * RECORD_BYTES {
            return Err(OutcomeHistoryError::MalformedEncoding);
        }
        let mut records: Vec<OutcomeHistoryRecord> = Vec::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| OutcomeHistoryError::AllocationFailed)?;
        for _ in 0..count {
            let delivery_id = input.take::<32>()?;
            if records.iter().any(|row| row.delivery_id == delivery_id) {
                return Err(OutcomeHistoryError::DuplicateDeliveryId);
            }
            let timestamp = UnixMillis::new(u64::from_be_bytes(input.take()?))
                .map_err(|_| OutcomeHistoryError::MalformedEncoding)?;
            let outcome = outcome_from_tag(input.take::<1>()?[0])?;
            records.push(OutcomeHistoryRecord {
                delivery_id,
                timestamp,
                outcome,
            });
        }
        Ok(Self { limits, records })
    }
}

/// In-memory result only. AlreadyRecorded never refreshes or reinserts a row and
/// never means a producer acknowledgment, Windows application or native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryInsert {
    Inserted(HistoryPruneReport),
    AlreadyRecorded,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HistoryPruneReport {
    pub expired_records: usize,
    pub capacity_records: usize,
    pub remaining_records: usize,
}

/// Fixed categories only. Never contains an ID, body, timestamp or parser text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OutcomeHistoryError {
    #[error("outcome history limits are outside the supported bounds")]
    InvalidLimits,
    #[error("outcome history exceeds the hard byte limit")]
    TooLarge,
    #[error("outcome history encoding is malformed")]
    MalformedEncoding,
    #[error("outcome history version is unsupported")]
    UnsupportedVersion,
    #[error("outcome history exceeds its record count limit")]
    TooManyRecords,
    #[error("outcome history contains a repeated delivery identity")]
    DuplicateDeliveryId,
    #[error("outcome history identity conflicts with its recorded outcome")]
    OutcomeConflict,
    #[error("bounded outcome history allocation failed")]
    AllocationFailed,
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], OutcomeHistoryError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(OutcomeHistoryError::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(OutcomeHistoryError::MalformedEncoding)?
            .try_into()
            .map_err(|_| OutcomeHistoryError::MalformedEncoding)?;
        self.offset = end;
        Ok(value)
    }
}

const fn outcome_tag(outcome: RequestOutcome) -> u8 {
    match outcome {
        RequestOutcome::CancelledByPc => 1,
        RequestOutcome::ExpiredByPc => 2,
        RequestOutcome::ExpiredLocally => 3,
        RequestOutcome::CompletedByPc => 4,
    }
}

const fn outcome_from_tag(tag: u8) -> Result<RequestOutcome, OutcomeHistoryError> {
    match tag {
        1 => Ok(RequestOutcome::CancelledByPc),
        2 => Ok(RequestOutcome::ExpiredByPc),
        3 => Ok(RequestOutcome::ExpiredLocally),
        4 => Ok(RequestOutcome::CompletedByPc),
        _ => Err(OutcomeHistoryError::MalformedEncoding),
    }
}
