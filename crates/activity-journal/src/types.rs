use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Absolute parser and retention limits, independent of caller configuration.
pub const MAX_RECORDS: usize = 4_096;
pub const MAX_FILE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_LINE_BYTES: usize = 1_024;
pub const MIN_LINE_BYTES: usize = 256;
pub const MAX_RETENTION_MS: u64 = 366 * 24 * 60 * 60 * 1_000;
/// Last millisecond of year 9999. Larger values are not accepted from storage.
pub const MAX_UNIX_MILLIS: u64 = 253_402_300_799_999;

/// A trusted caller's UNIX timestamp, not a phone- or network-supplied clock.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct UnixMillis(u64);

impl UnixMillis {
    pub const fn new(value: u64) -> Result<Self, TimestampError> {
        if value <= MAX_UNIX_MILLIS {
            Ok(Self(value))
        } else {
            Err(TimestampError)
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for UnixMillis {
    type Error = TimestampError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UnixMillis> for u64 {
    fn from(value: UnixMillis) -> Self {
        value.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("timestamp is outside the supported UNIX millisecond range")]
pub struct TimestampError;

/// Immutable bounds. JSON line limits exclude the terminating newline; the file
/// limit includes every byte, including the header and all newlines.
///
/// The lower byte bounds reserve enough room for a header and one event of this
/// schema. Tightening limits below an existing file's size/line/count requires
/// explicit recovery: oversized input is never silently truncated on open.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "LimitsWire", into = "LimitsWire")]
pub struct Limits {
    max_records: usize,
    max_file_bytes: usize,
    max_line_bytes: usize,
    max_age_ms: u64,
}

impl Limits {
    pub fn new(
        max_records: usize,
        max_file_bytes: usize,
        max_line_bytes: usize,
        max_age_ms: u64,
    ) -> Result<Self, LimitsError> {
        if max_records == 0 || max_records > MAX_RECORDS {
            return Err(LimitsError::RecordCount);
        }
        if !(MIN_LINE_BYTES..=MAX_LINE_BYTES).contains(&max_line_bytes) {
            return Err(LimitsError::LineBytes);
        }
        if max_file_bytes > MAX_FILE_BYTES || max_file_bytes < 2 * (max_line_bytes + 1) {
            return Err(LimitsError::FileBytes);
        }
        if max_age_ms == 0 || max_age_ms > MAX_RETENTION_MS {
            return Err(LimitsError::Age);
        }
        Ok(Self {
            max_records,
            max_file_bytes,
            max_line_bytes,
            max_age_ms,
        })
    }

    pub const fn max_records(self) -> usize {
        self.max_records
    }

    pub const fn max_file_bytes(self) -> usize {
        self.max_file_bytes
    }

    pub const fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    pub const fn max_age_ms(self) -> u64 {
        self.max_age_ms
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 1_000,
            max_file_bytes: 512 * 1_024,
            max_line_bytes: 512,
            max_age_ms: 30 * 24 * 60 * 60 * 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LimitsError {
    #[error("record count must be within the supported nonzero range")]
    RecordCount,
    #[error("JSON line byte limit must be within the supported range")]
    LineBytes,
    #[error("file byte limit must fit a header and event and not exceed the hard cap")]
    FileBytes,
    #[error("retention age must be within the supported nonzero range")]
    Age,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LimitsWire {
    max_records: usize,
    max_file_bytes: usize,
    max_line_bytes: usize,
    max_age_ms: u64,
}

impl TryFrom<LimitsWire> for Limits {
    type Error = LimitsError;

    fn try_from(value: LimitsWire) -> Result<Self, Self::Error> {
        Self::new(
            value.max_records,
            value.max_file_bytes,
            value.max_line_bytes,
            value.max_age_ms,
        )
    }
}

impl From<Limits> for LimitsWire {
    fn from(value: Limits) -> Self {
        Self {
            max_records: value.max_records,
            max_file_bytes: value.max_file_bytes,
            max_line_bytes: value.max_line_bytes,
            max_age_ms: value.max_age_ms,
        }
    }
}

/// Diagnostic facts reported by trusted producers, never authorization inputs.
/// There is deliberately no string, identifier, arbitrary payload, or off-hours
/// discard variant. Notification policy discards off-hours requests without
/// creating history. Do not translate internal/raw errors into freeform fields.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "category",
    content = "outcome",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ActivityEvent {
    Connection(ConnectionOutcome),
    Service(ServiceOutcome),
    Failure(FailureKind),
    Request(RequestOutcome),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOutcome {
    PairedDeviceConnected,
    PairedDeviceDisconnected,
    RelayConnected,
    RelayDisconnected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOutcome {
    Started,
    Stopping,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    AuthenticationRejected,
    MalformedProtocolMessage,
    ReplayRejected,
    TransportUnavailable,
    PlatformUnavailable,
    RequestValidationFailed,
    DeliveryFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

/// These states are intentionally distinct. A verified or sent phone decision
/// does not mean Windows applied it. `WindowsApplied` may only be emitted when
/// a trusted Windows adapter has actual application evidence; this crate cannot
/// supply that evidence or replace Windows authentication with its own result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "state",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RequestOutcome {
    Observed,
    NotificationSent,
    PhoneDecisionVerified { decision: Decision },
    DecisionSentToWindows { decision: Decision },
    WindowsApplied { decision: Decision },
    WindowsRejected,
    WindowsOutcomeUnknown,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivityRecord {
    timestamp_unix_ms: UnixMillis,
    event: ActivityEvent,
}

impl ActivityRecord {
    pub(crate) const fn new(timestamp_unix_ms: UnixMillis, event: ActivityEvent) -> Self {
        Self {
            timestamp_unix_ms,
            event,
        }
    }

    pub const fn timestamp(self) -> UnixMillis {
        self.timestamp_unix_ms
    }

    pub const fn event(self) -> ActivityEvent {
        self.event
    }
}

/// Counts removed by a successful retention operation; no recorded event data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PurgeReport {
    pub expired_records: usize,
    pub capacity_records: usize,
    pub remaining_records: usize,
}
