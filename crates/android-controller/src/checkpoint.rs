// SPDX-License-Identifier: GPL-2.0-or-later
//! One byte-store payload for the replay owner AND its bounded user history.
//! A checksum/file location is not authentication; callers own native provenance.
use std::{collections::BTreeSet, fmt};

use activity_journal::{
    MAX_OUTCOME_HISTORY_BYTES, OutcomeHistory, OutcomeHistoryError, OutcomeHistoryLimits,
};
use phone_request_core::{InboxCheckpoint, InboxCheckpointError};
use phone_state_store::MAX_SNAPSHOT_BYTES;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"UACOWNR\0";
const LEGACY_MAGIC: &[u8; 8] = b"UACINBX\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 18;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ControllerCheckpointError {
    #[error("the composite phone checkpoint encoding is invalid")]
    InvalidEncoding,
    #[error("the composite phone checkpoint version is unsupported")]
    UnsupportedVersion,
    #[error("the combined phone checkpoint exceeds its byte bound")]
    TooLarge,
    #[error("legacy request-bearing state needs explicit history reconciliation")]
    LegacyHistoryReconciliationRequired,
    #[error("phone history limits differ from the native owner's fixed profile")]
    HistoryProfileMismatch,
    #[error("one outcome is both recorded and pending in the same checkpoint")]
    RecordedPendingOverlap,
    #[error("the nested inbox checkpoint is invalid")]
    Inbox(InboxCheckpointError),
    #[error("the nested outcome history is invalid")]
    History(OutcomeHistoryError),
}

/// Strict metadata-only representation; not a runtime, permission or action token.
pub struct ControllerCheckpoint {
    inbox: InboxCheckpoint,
    history: OutcomeHistory,
}

impl fmt::Debug for ControllerCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerCheckpoint")
            .field("history_count", &self.history.records().len())
            .finish_non_exhaustive()
    }
}

impl ControllerCheckpoint {
    pub(crate) fn new(
        inbox: InboxCheckpoint,
        history: OutcomeHistory,
    ) -> Result<Self, ControllerCheckpointError> {
        let value = Self { inbox, history };
        value.validate_relationship()?;
        Ok(value)
    }

    pub fn inbox(&self) -> &InboxCheckpoint {
        &self.inbox
    }
    pub fn history(&self) -> &OutcomeHistory {
        &self.history
    }
    pub(crate) fn into_parts(self) -> (InboxCheckpoint, OutcomeHistory) {
        (self.inbox, self.history)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ControllerCheckpointError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(ControllerCheckpointError::TooLarge);
        }
        // Explicit legacy dispatch, never a parse-error/unknown-version fallback.
        // Only the previously shipped policy-only application state can migrate.
        if bytes.starts_with(LEGACY_MAGIC) {
            let inbox =
                InboxCheckpoint::from_bytes(bytes).map_err(ControllerCheckpointError::Inbox)?;
            if !inbox.is_policy_only() {
                return Err(ControllerCheckpointError::LegacyHistoryReconciliationRequired);
            }
            return Self::new(inbox, OutcomeHistory::new(OutcomeHistoryLimits::default()));
        }
        if bytes.len() < HEADER_BYTES || !bytes.starts_with(MAGIC) {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(ControllerCheckpointError::UnsupportedVersion);
        }
        let inbox_len = length(&bytes[10..14])?;
        let history_len = length(&bytes[14..18])?;
        if inbox_len == 0 || history_len == 0 {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        if inbox_len > MAX_SNAPSHOT_BYTES || history_len > MAX_OUTCOME_HISTORY_BYTES {
            return Err(ControllerCheckpointError::TooLarge);
        }
        let inbox_end = HEADER_BYTES
            .checked_add(inbox_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        let total = inbox_end
            .checked_add(history_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        if total != bytes.len() {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        let inbox = InboxCheckpoint::from_bytes(&bytes[HEADER_BYTES..inbox_end])
            .map_err(ControllerCheckpointError::Inbox)?;
        let history = OutcomeHistory::from_bytes(&bytes[inbox_end..])
            .map_err(ControllerCheckpointError::History)?;
        Self::new(inbox, history)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ControllerCheckpointError> {
        self.validate_relationship()?;
        let inbox = self
            .inbox
            .to_bytes()
            .map_err(ControllerCheckpointError::Inbox)?;
        let history = self
            .history
            .to_bytes()
            .map_err(ControllerCheckpointError::History)?;
        let total = HEADER_BYTES
            .checked_add(inbox.len())
            .and_then(|v| v.checked_add(history.len()))
            .filter(|v| *v <= MAX_SNAPSHOT_BYTES)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(inbox.len())
                .map_err(|_| ControllerCheckpointError::TooLarge)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(history.len())
                .map_err(|_| ControllerCheckpointError::TooLarge)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&inbox);
        bytes.extend_from_slice(&history);
        Ok(bytes)
    }

    fn validate_relationship(&self) -> Result<(), ControllerCheckpointError> {
        if self.history.limits() != OutcomeHistoryLimits::default() {
            return Err(ControllerCheckpointError::HistoryProfileMismatch);
        }
        let recorded: BTreeSet<_> = self
            .history
            .records()
            .iter()
            .map(|row| *row.delivery_id())
            .collect();
        if self
            .inbox
            .pending_outcomes()
            .iter()
            .any(|row| recorded.contains(row.delivery_id().as_bytes()))
        {
            return Err(ControllerCheckpointError::RecordedPendingOverlap);
        }
        Ok(())
    }
}

fn length(bytes: &[u8]) -> Result<usize, ControllerCheckpointError> {
    let value = u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| ControllerCheckpointError::InvalidEncoding)?,
    );
    usize::try_from(value).map_err(|_| ControllerCheckpointError::TooLarge)
}
