// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict append transactions. Parsing never recovers a last-good authority.
#![forbid(unsafe_code)]

use approval_protocol::DecisionPublicKey;
use sha2::{Digest, Sha256};

use super::{
    RegistryError,
    model::{Document, Input, MAX_DOCUMENT_BYTES, RegistryChange},
};

const MAGIC: &[u8; 8] = b"WUACTRST";
const INTENT: &[u8; 8] = b"WUACINT1";
const COMMIT: &[u8; 8] = b"WUACCOM1";
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/registry-transaction/v1\0";
const HEADER_BYTES: usize = 43;
const INTENT_BYTES: usize = 84;
const COMMIT_PREFIX_BYTES: usize = 20;
pub(super) const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
#[cfg(windows)]
const _: () = assert!(MAX_FILE_BYTES as u64 == crate::ffi::MAX_TRUST_FILE_BYTES);
const MAX_TRANSACTIONS: u64 = 512;

pub(super) struct Journal {
    pub(super) document: Document,
    length: usize,
    sequence: u64,
    digest: [u8; 32],
}

pub(super) struct PreparedWrite {
    pub(super) expected_length: u64,
    pub(super) intent: Vec<u8>,
    pub(super) commit: Vec<u8>,
    pub(super) next: Journal,
}

pub(super) trait AppendSink {
    fn append_and_flush(&mut self, expected: u64, bytes: &[u8]) -> Result<u64, RegistryError>;
}

#[cfg(windows)]
impl AppendSink for crate::ffi::ServiceTrustFile {
    fn append_and_flush(&mut self, expected: u64, bytes: &[u8]) -> Result<u64, RegistryError> {
        crate::ffi::ServiceTrustFile::append_and_flush(self, expected, bytes)
            .map_err(|_| RegistryError::Unavailable)
    }
}

pub(super) fn publish<S: AppendSink>(
    state: &mut Option<Journal>,
    sink: &mut S,
    prepared: PreparedWrite,
) -> Result<(), RegistryError> {
    // Close before the first I/O, including panic unwinding. Native File only
    // implements this private seam; test sinks prove ownership rules, not disk.
    *state = None;
    let after_intent = sink.append_and_flush(prepared.expected_length, &prepared.intent)?;
    if after_intent != prepared.expected_length + prepared.intent.len() as u64 {
        return Err(RegistryError::Unavailable);
    }
    let after_commit = sink.append_and_flush(after_intent, &prepared.commit)?;
    if after_commit != after_intent + prepared.commit.len() as u64 {
        return Err(RegistryError::Unavailable);
    }
    // A final legal write may consume maintenance headroom. Its failure here
    // does NOT claim rollback: bytes may be committed, but authority stays shut.
    prepared.next.ensure_writable()?;
    *state = Some(prepared.next);
    Ok(())
}

impl Journal {
    pub(super) fn initial(pc: DecisionPublicKey) -> Result<PreparedWrite, RegistryError> {
        let document = Document::empty(pc.clone())?;
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&1_u16.to_be_bytes());
        header.extend_from_slice(pc.compressed_sec1_bytes());
        let empty = Self {
            document: document.clone(),
            length: HEADER_BYTES,
            sequence: 0,
            digest: [0; 32],
        };
        let mut prepared = empty.prepare(document)?;
        header.extend_from_slice(&prepared.intent);
        prepared.expected_length = 0;
        prepared.intent = header;
        Ok(prepared)
    }

    pub(super) fn restore(pc: DecisionPublicKey, bytes: &[u8]) -> Result<Self, RegistryError> {
        if bytes.len() <= HEADER_BYTES || bytes.len() > MAX_FILE_BYTES {
            return Err(RegistryError::InvalidState);
        }
        let mut input = Input(bytes);
        if &input.take::<8>()? != MAGIC
            || u16::from_be_bytes(input.take()?) != 1
            || &input.take::<33>()? != pc.compressed_sec1_bytes()
        {
            return Err(RegistryError::InvalidState);
        }
        let mut sequence = 0_u64;
        let mut digest = [0; 32];
        let mut last: Option<Document> = None;
        while !input.0.is_empty() {
            sequence = sequence
                .checked_add(1)
                .ok_or(RegistryError::MaintenanceRequired)?;
            if sequence > MAX_TRANSACTIONS {
                return Err(RegistryError::MaintenanceRequired);
            }
            let intent = input.take::<INTENT_BYTES>()?;
            let mut fields = Input(&intent);
            if &fields.take::<8>()? != INTENT
                || u64::from_be_bytes(fields.take()?) != sequence
                || fields.take::<32>()? != digest
            {
                return Err(RegistryError::InvalidState);
            }
            let length = u32::from_be_bytes(fields.take()?) as usize;
            let payload_hash: [u8; 32] = fields.take()?;
            if length == 0 || length > MAX_DOCUMENT_BYTES {
                return Err(RegistryError::InvalidState);
            }
            let commit = input.take::<COMMIT_PREFIX_BYTES>()?;
            let mut fields = Input(&commit);
            if &fields.take::<8>()? != COMMIT
                || u64::from_be_bytes(fields.take()?) != sequence
                || u32::from_be_bytes(fields.take()?) as usize != length
            {
                return Err(RegistryError::InvalidState);
            }
            let payload = input.0.get(..length).ok_or(RegistryError::InvalidState)?;
            input.0 = &input.0[length..];
            let found: [u8; 32] = input.take()?;
            let hash: [u8; 32] = Sha256::digest(payload).into();
            if hash != payload_hash || found != transaction_hash(&pc, &intent, &commit, payload) {
                return Err(RegistryError::InvalidState);
            }
            let document = Document::decode(pc.clone(), payload)?;
            if let Some(previous) = &last {
                if document.core.capacity() != previous.core.capacity()
                    || document.core.next_revision() < previous.core.next_revision()
                {
                    return Err(RegistryError::InvalidState);
                }
            } else if !document.core.entries().is_empty()
                || document.core.next_revision() != 1
                || document.core.capacity() != 32
            {
                // Initial creation can never import/enroll a candidate phone.
                return Err(RegistryError::InvalidState);
            }
            last = Some(document);
            digest = found;
        }
        Ok(Self {
            document: last.ok_or(RegistryError::InvalidState)?,
            length: bytes.len(),
            sequence,
            digest,
        })
    }

    pub(super) fn ensure_writable(&self) -> Result<(), RegistryError> {
        let remaining = MAX_FILE_BYTES.saturating_sub(self.length);
        if self.sequence >= MAX_TRANSACTIONS
            || self.document.core.next_revision() == u64::MAX
            || remaining < INTENT_BYTES + COMMIT_PREFIX_BYTES + MAX_DOCUMENT_BYTES + 32
        {
            return Err(RegistryError::MaintenanceRequired);
        }
        Ok(())
    }

    pub(super) fn prepare_change(
        &self,
        change: RegistryChange,
    ) -> Result<PreparedWrite, RegistryError> {
        self.ensure_writable()?;
        self.prepare(self.document.changed(change)?)
    }

    fn prepare(&self, document: Document) -> Result<PreparedWrite, RegistryError> {
        self.ensure_writable()?;
        let payload = document.encode();
        let mut intent = Vec::with_capacity(INTENT_BYTES);
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(RegistryError::MaintenanceRequired)?;
        intent.extend_from_slice(INTENT);
        intent.extend_from_slice(&sequence.to_be_bytes());
        intent.extend_from_slice(&self.digest);
        intent.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        intent.extend_from_slice(&Sha256::digest(&payload));
        let mut commit = Vec::with_capacity(COMMIT_PREFIX_BYTES + payload.len() + 32);
        commit.extend_from_slice(COMMIT);
        commit.extend_from_slice(&sequence.to_be_bytes());
        commit.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        let digest = transaction_hash(&document.pc, &intent, &commit, &payload);
        commit.extend_from_slice(&payload);
        commit.extend_from_slice(&digest);
        let length = self.length + intent.len() + commit.len();
        if length > MAX_FILE_BYTES {
            return Err(RegistryError::MaintenanceRequired);
        }
        Ok(PreparedWrite {
            expected_length: self.length as u64,
            intent,
            commit,
            next: Self {
                document,
                length,
                sequence,
                digest,
            },
        })
    }
}

fn transaction_hash(
    pc: &DecisionPublicKey,
    intent: &[u8],
    commit: &[u8],
    payload: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        DOMAIN,
        pc.compressed_sec1_bytes().as_slice(),
        intent,
        commit,
        payload,
    ] {
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
impl PreparedWrite {
    pub(super) fn append_fixture(self, bytes: &mut Vec<u8>) -> Journal {
        assert_eq!(bytes.len() as u64, self.expected_length);
        bytes.extend_from_slice(&self.intent);
        bytes.extend_from_slice(&self.commit);
        self.next
    }
}

#[cfg(test)]
mod semantic_tests {
    use super::*;
    use crate::trust_registry::tests::{device, keys, pc};
    use approval_core::RegistryCheckpoint;

    #[test]
    fn correctly_hashed_nonempty_initial_state_is_not_initialization_authority() {
        let initial = Journal::initial(pc()).unwrap();
        let mut bytes = initial.intent[..HEADER_BYTES].to_vec();
        let empty = Document::empty(pc()).unwrap();
        let nonempty = empty
            .changed(RegistryChange::Enroll {
                device: device(1),
                keys: keys(2),
            })
            .unwrap();
        let base = Journal {
            document: empty,
            length: HEADER_BYTES,
            sequence: 0,
            digest: [0; 32],
        };
        base.prepare(nonempty).unwrap().append_fixture(&mut bytes);
        assert!(Journal::restore(pc(), &bytes).is_err());
    }

    #[test]
    fn correctly_hashed_highwater_regression_and_capacity_change_are_rejected() {
        let mut original = vec![];
        let state = Journal::initial(pc())
            .unwrap()
            .append_fixture(&mut original);
        let state = state
            .prepare_change(RegistryChange::Enroll {
                device: device(1),
                keys: keys(2),
            })
            .unwrap()
            .append_fixture(&mut original);
        let mut regressed = original.clone();
        // Deliberately bypass the private legitimate-change constructor to
        // prove semantic validation, not only bitflip/hash validation.
        state
            .prepare(Document::empty(pc()).unwrap())
            .unwrap()
            .append_fixture(&mut regressed);
        assert!(Journal::restore(pc(), &regressed).is_err());
        let mut changed = state.document.clone();
        changed.core = RegistryCheckpoint::new(
            31,
            changed.core.next_revision(),
            changed.core.entries().to_vec(),
        )
        .unwrap();
        let mut resized = original;
        state.prepare(changed).unwrap().append_fixture(&mut resized);
        assert!(Journal::restore(pc(), &resized).is_err());
    }
}
