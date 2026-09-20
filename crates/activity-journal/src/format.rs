use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ActivityRecord, JournalError, Limits, PurgeReport, UnixMillis};

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(try_from = "HeaderWire", into = "HeaderWire")]
struct Header {
    last_observed_unix_ms: UnixMillis,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeaderWire {
    format_version: u32,
    last_observed_unix_ms: UnixMillis,
}

impl TryFrom<HeaderWire> for Header {
    type Error = &'static str;

    fn try_from(value: HeaderWire) -> Result<Self, Self::Error> {
        if value.format_version != FORMAT_VERSION {
            return Err("unsupported activity journal format version");
        }
        Ok(Self {
            last_observed_unix_ms: value.last_observed_unix_ms,
        })
    }
}

impl From<Header> for HeaderWire {
    fn from(value: Header) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            last_observed_unix_ms: value.last_observed_unix_ms,
        }
    }
}

#[derive(Debug)]
pub(crate) struct State {
    header: Header,
    pub(crate) records: Vec<ActivityRecord>,
}

impl State {
    pub(crate) fn empty(now: UnixMillis) -> Self {
        Self {
            header: Header {
                last_observed_unix_ms: now,
            },
            records: Vec::new(),
        }
    }

    pub(crate) fn last_observed(&self) -> UnixMillis {
        self.header.last_observed_unix_ms
    }

    pub(crate) fn decode(bytes: &[u8], limits: Limits) -> Result<Self, JournalError> {
        if bytes.len() > limits.max_file_bytes() {
            return Err(JournalError::StorageTooLarge);
        }
        // A complete file is nonempty and every JSON line ends with a newline.
        // A partial final line is forensic data, not a record to silently drop.
        let body = bytes
            .strip_suffix(b"\n")
            .ok_or(JournalError::CorruptStorage)?;
        let mut lines = body.split(|byte| *byte == b'\n');
        let header: Header =
            decode_line(lines.next().ok_or(JournalError::CorruptStorage)?, limits)?;
        let mut records: Vec<ActivityRecord> = Vec::new();
        for line in lines {
            if records.len() >= limits.max_records() {
                return Err(JournalError::TooManyRecords);
            }
            let record: ActivityRecord = decode_line(line, limits)?;
            // Validate metadata across records as well as the individually
            // validated timestamp/version types used by deserialization.
            if record.timestamp() > header.last_observed_unix_ms
                || records
                    .last()
                    .is_some_and(|previous| record.timestamp() < previous.timestamp())
            {
                return Err(JournalError::CorruptStorage);
            }
            records.push(record);
        }
        Ok(Self { header, records })
    }

    /// Updates the nondecreasing trusted-clock floor and keeps the newest
    /// records fitting every bound. Equality with the age boundary is retained.
    pub(crate) fn prepare(
        &mut self,
        now: UnixMillis,
        limits: Limits,
    ) -> Result<Prepared, JournalError> {
        let previous_clock = self.last_observed();
        self.header.last_observed_unix_ms = previous_clock.max(now);
        let cutoff = self
            .last_observed()
            .get()
            .saturating_sub(limits.max_age_ms());
        let before_age = self.records.len();
        self.records
            .retain(|record| record.timestamp().get() >= cutoff);
        let expired_records = before_age - self.records.len();
        let count_excess = self.records.len().saturating_sub(limits.max_records());
        self.records.drain(..count_excess);

        let header = encode_line(&self.header, limits)?;
        let lines: Vec<Vec<u8>> = self
            .records
            .iter()
            .map(|record| encode_line(record, limits))
            .collect::<Result<_, _>>()?;
        // Limits cap these sums well below usize::MAX on supported targets.
        let mut total_bytes = header.len() + lines.iter().map(Vec::len).sum::<usize>();
        let mut byte_excess = 0;
        while total_bytes > limits.max_file_bytes() {
            let oldest = lines.get(byte_excess).ok_or(JournalError::EncodingFailed)?;
            total_bytes -= oldest.len();
            byte_excess += 1;
        }
        self.records.drain(..byte_excess);
        let mut bytes = Vec::with_capacity(total_bytes);
        bytes.extend_from_slice(&header);
        for line in &lines[byte_excess..] {
            bytes.extend_from_slice(line);
        }
        let report = PurgeReport {
            expired_records,
            capacity_records: count_excess + byte_excess,
            remaining_records: self.records.len(),
        };
        Ok(Prepared {
            changed: previous_clock != self.last_observed()
                || report.expired_records != 0
                || report.capacity_records != 0,
            bytes,
            report,
        })
    }
}

pub(crate) struct Prepared {
    pub(crate) bytes: Vec<u8>,
    pub(crate) report: PurgeReport,
    pub(crate) changed: bool,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Prepared")
            .field("byte_count", &self.bytes.len())
            .field("report", &self.report)
            .field("changed", &self.changed)
            .finish()
    }
}

fn decode_line<T: serde::de::DeserializeOwned>(
    line: &[u8],
    limits: Limits,
) -> Result<T, JournalError> {
    if line.len() > limits.max_line_bytes() {
        return Err(JournalError::LineTooLarge);
    }
    if line.is_empty() {
        return Err(JournalError::CorruptStorage);
    }
    // Do not retain serde's raw error text or the input in the public error.
    serde_json::from_slice(line).map_err(|_| JournalError::CorruptStorage)
}

fn encode_line<T: Serialize>(value: &T, limits: Limits) -> Result<Vec<u8>, JournalError> {
    let mut line = serde_json::to_vec(value).map_err(|_| JournalError::EncodingFailed)?;
    if line.len() > limits.max_line_bytes() {
        return Err(JournalError::LineTooLarge);
    }
    line.push(b'\n');
    Ok(line)
}
