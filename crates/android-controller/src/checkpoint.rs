// SPDX-License-Identifier: GPL-2.0-or-later
//! One byte-store payload for replay state, history, local keys and peer associations.
//! A checksum/file location is not authentication; callers own native provenance.
use std::{collections::BTreeSet, fmt};

use activity_journal::{
    MAX_OUTCOME_HISTORY_BYTES, OutcomeHistory, OutcomeHistoryError, OutcomeHistoryLimits,
};
use phone_request_core::{InboxCheckpoint, InboxCheckpointError};
use phone_state_store::MAX_SNAPSHOT_BYTES;
use thiserror::Error;

use crate::{
    LocalKeyError, LocalKeyLedger, MAX_LOCAL_KEY_LEDGER_BYTES, MAX_PEER_ASSOCIATION_LEDGER_BYTES,
    PeerAssociationError, PeerAssociationLedger,
};

const MAGIC: &[u8; 8] = b"UACOWNR\0";
const LEGACY_MAGIC: &[u8; 8] = b"UACINBX\0";
const VERSION: u16 = 3;
const LEGACY_COMPOSITE_VERSION: u16 = 1;
const LOCAL_KEYS_VERSION: u16 = 2;
const LEGACY_HEADER_BYTES: usize = 18;
const LOCAL_KEYS_HEADER_BYTES: usize = 22;
const HEADER_BYTES: usize = 26;

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
    #[error("the nested local key metadata is invalid")]
    LocalKeys(LocalKeyError),
    #[error("the nested peer association metadata or local-key relationship is invalid")]
    PeerAssociations(PeerAssociationError),
}

/// Strict metadata-only representation; not a runtime, permission or action token.
pub struct ControllerCheckpoint {
    inbox: InboxCheckpoint,
    history: OutcomeHistory,
    local_keys: LocalKeyLedger,
    peer_associations: PeerAssociationLedger,
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
        Self::with_local_keys(inbox, history, LocalKeyLedger::default())
    }

    pub(crate) fn with_local_keys(
        inbox: InboxCheckpoint,
        history: OutcomeHistory,
        local_keys: LocalKeyLedger,
    ) -> Result<Self, ControllerCheckpointError> {
        Self::with_peer_associations(inbox, history, local_keys, PeerAssociationLedger::default())
    }

    pub(crate) fn with_peer_associations(
        inbox: InboxCheckpoint,
        history: OutcomeHistory,
        local_keys: LocalKeyLedger,
        peer_associations: PeerAssociationLedger,
    ) -> Result<Self, ControllerCheckpointError> {
        let value = Self {
            inbox,
            history,
            local_keys,
            peer_associations,
        };
        value.validate_relationship()?;
        Ok(value)
    }

    pub fn inbox(&self) -> &InboxCheckpoint {
        &self.inbox
    }
    pub fn history(&self) -> &OutcomeHistory {
        &self.history
    }
    pub fn local_keys(&self) -> &LocalKeyLedger {
        &self.local_keys
    }
    pub fn peer_associations(&self) -> &PeerAssociationLedger {
        &self.peer_associations
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        InboxCheckpoint,
        OutcomeHistory,
        LocalKeyLedger,
        PeerAssociationLedger,
    ) {
        (
            self.inbox,
            self.history,
            self.local_keys,
            self.peer_associations,
        )
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
        if bytes.len() < LEGACY_HEADER_BYTES || !bytes.starts_with(MAGIC) {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        let version = u16::from_be_bytes([bytes[8], bytes[9]]);
        if ![LEGACY_COMPOSITE_VERSION, LOCAL_KEYS_VERSION, VERSION].contains(&version) {
            return Err(ControllerCheckpointError::UnsupportedVersion);
        }
        let inbox_len = length(&bytes[10..14])?;
        let history_len = length(&bytes[14..18])?;
        let (header_bytes, key_len, association_len) = if version == VERSION {
            if bytes.len() < HEADER_BYTES {
                return Err(ControllerCheckpointError::InvalidEncoding);
            }
            let key_len = length(&bytes[18..22])?;
            let association_len = length(&bytes[22..26])?;
            if key_len == 0 || association_len == 0 {
                return Err(ControllerCheckpointError::InvalidEncoding);
            }
            (HEADER_BYTES, key_len, association_len)
        } else if version == LOCAL_KEYS_VERSION {
            if bytes.len() < LOCAL_KEYS_HEADER_BYTES {
                return Err(ControllerCheckpointError::InvalidEncoding);
            }
            let key_len = length(&bytes[18..22])?;
            if key_len == 0 {
                return Err(ControllerCheckpointError::InvalidEncoding);
            }
            // Explicit v2 migration supplies absent associations only. It does
            // not turn CreatedUnverified local metadata into pairing authority.
            (LOCAL_KEYS_HEADER_BYTES, key_len, 0)
        } else {
            // This only supplies absent metadata. The native owner MUST check
            // real namespace absence under the store lock before migration.
            (LEGACY_HEADER_BYTES, 0, 0)
        };
        if inbox_len == 0 || history_len == 0 {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        if inbox_len > MAX_SNAPSHOT_BYTES
            || history_len > MAX_OUTCOME_HISTORY_BYTES
            || key_len > MAX_LOCAL_KEY_LEDGER_BYTES
            || association_len > MAX_PEER_ASSOCIATION_LEDGER_BYTES
        {
            return Err(ControllerCheckpointError::TooLarge);
        }
        let inbox_end = header_bytes
            .checked_add(inbox_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        let history_end = inbox_end
            .checked_add(history_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        let keys_end = history_end
            .checked_add(key_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        let total = keys_end
            .checked_add(association_len)
            .ok_or(ControllerCheckpointError::TooLarge)?;
        if total != bytes.len() {
            return Err(ControllerCheckpointError::InvalidEncoding);
        }
        let inbox = InboxCheckpoint::from_bytes(&bytes[header_bytes..inbox_end])
            .map_err(ControllerCheckpointError::Inbox)?;
        let history = OutcomeHistory::from_bytes(&bytes[inbox_end..history_end])
            .map_err(ControllerCheckpointError::History)?;
        let local_keys = if key_len == 0 {
            LocalKeyLedger::default()
        } else {
            LocalKeyLedger::from_bytes(&bytes[history_end..keys_end])
                .map_err(ControllerCheckpointError::LocalKeys)?
        };
        let peer_associations = if association_len == 0 {
            PeerAssociationLedger::default()
        } else {
            PeerAssociationLedger::from_bytes(&bytes[keys_end..])
                .map_err(ControllerCheckpointError::PeerAssociations)?
        };
        Self::with_peer_associations(inbox, history, local_keys, peer_associations)
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
        let local_keys = self
            .local_keys
            .to_bytes()
            .map_err(ControllerCheckpointError::LocalKeys)?;
        let peer_associations = self
            .peer_associations
            .to_bytes()
            .map_err(ControllerCheckpointError::PeerAssociations)?;
        let total = HEADER_BYTES
            .checked_add(inbox.len())
            .and_then(|v| v.checked_add(history.len()))
            .and_then(|v| v.checked_add(local_keys.len()))
            .and_then(|v| v.checked_add(peer_associations.len()))
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
        bytes.extend_from_slice(
            &u32::try_from(local_keys.len())
                .map_err(|_| ControllerCheckpointError::TooLarge)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(peer_associations.len())
                .map_err(|_| ControllerCheckpointError::TooLarge)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&inbox);
        bytes.extend_from_slice(&history);
        bytes.extend_from_slice(&local_keys);
        bytes.extend_from_slice(&peer_associations);
        Ok(bytes)
    }

    fn validate_relationship(&self) -> Result<(), ControllerCheckpointError> {
        self.peer_associations
            .validate_relationships(&self.local_keys)
            .map_err(ControllerCheckpointError::PeerAssociations)?;
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
