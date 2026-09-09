// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded LOCAL key-lifecycle metadata, not enrollment or a key-store owner.
//!
//! A trusted Rust owner generates fresh handle/challenge values with its CSPRNG,
//! commits Preparing in its existing controller transaction BEFORE any native key
//! creation, and commits an exact public observation as CreatedUnverified later.
//! These pure methods/bytes are not commit receipts or permission to call native
//! APIs. Reopened Preparing always needs reconciliation: never retry creation
//! merely because no descriptor was committed. CreatedUnverified permits only
//! the host's separately gated read-only native identity/policy inspection, not
//! pairing, signing, authentication or proof of native hardware/attestation.
//!
//! No deletion, expiry, alias, key provider, private key, PC identity or recovery
//! method exists. The 32-set limit matches the native owner's 96 role references;
//! exhaustion requires a future explicit workflow, not silent eviction/reset.
//! All observed keys remain unverified and all challenges stay retained. Fresh
//! entropy/protected-state provenance and rollback detection remain host duties.

use std::{collections::BTreeMap, fmt};

use secure_channel::TlsPublicKey;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"UACLKEY\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 12;
const PREPARING_BYTES: usize = 1 + 32 + 32;
const SPKI_BYTES: usize = 91;
const CREATED_BYTES: usize = PREPARING_BYTES + 3 * SPKI_BYTES;

pub const MAX_LOCAL_KEY_SETS: usize = 32;
/// Exact v1 hard cap: header12 + 32 * (phase1 + handle32 + challenge32 + keys273).
pub const MAX_LOCAL_KEY_LEDGER_BYTES: usize = HEADER_BYTES + MAX_LOCAL_KEY_SETS * CREATED_BYTES;

macro_rules! local_identifier {
    ($name:ident, $error:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, LocalKeyError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(LocalKeyError::$error);
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

local_identifier!(
    LocalKeyHandle,
    InvalidHandle,
    "Nonzero local creation handle. Parsing cannot prove freshness, ownership or enrollment."
);
local_identifier!(
    LocalAttestationChallenge,
    InvalidChallenge,
    "Nonzero local attestation challenge. Not an attestation result or authentication proof."
);

/// Immutable public observation for one exact local creation. TlsPublicKey is
/// reused only as the strict canonical 91-byte P-256 SPKI codec, including for
/// approval/denial roles; its name does not grant transport enrollment or trust.
#[derive(Clone, PartialEq)]
pub struct LocalKeySetDescriptor {
    handle: LocalKeyHandle,
    challenge: LocalAttestationChallenge,
    approval: TlsPublicKey,
    denial: TlsPublicKey,
    transport: TlsPublicKey,
}

impl LocalKeySetDescriptor {
    pub fn new(
        handle: LocalKeyHandle,
        challenge: LocalAttestationChallenge,
        approval: TlsPublicKey,
        denial: TlsPublicKey,
        transport: TlsPublicKey,
    ) -> Result<Self, LocalKeyError> {
        if approval == denial || approval == transport || denial == transport {
            return Err(LocalKeyError::KeyReuse);
        }
        Ok(Self {
            handle,
            challenge,
            approval,
            denial,
            transport,
        })
    }

    pub const fn handle(&self) -> LocalKeyHandle {
        self.handle
    }
    pub const fn challenge(&self) -> LocalAttestationChallenge {
        self.challenge
    }
    pub const fn approval_key(&self) -> &TlsPublicKey {
        &self.approval
    }
    pub const fn denial_key(&self) -> &TlsPublicKey {
        &self.denial
    }
    pub const fn transport_key(&self) -> &TlsPublicKey {
        &self.transport
    }

    fn public_keys(&self) -> [&TlsPublicKey; 3] {
        [&self.approval, &self.denial, &self.transport]
    }

    fn shares_key(&self, other: &Self) -> bool {
        self.public_keys()
            .into_iter()
            .any(|key| other.public_keys().contains(&key))
    }
}

impl fmt::Debug for LocalKeySetDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalKeySetDescriptor([redacted], unverified)")
    }
}

/// Read-only phase view. Constructing a value cannot insert it into a ledger or
/// make a native key operation permissible; only the trusted owner may compose
/// ledger transitions with actual durable commits and read-only reconciliation.
#[derive(Clone, PartialEq)]
pub enum LocalKeySetPhase {
    Preparing {
        handle: LocalKeyHandle,
        challenge: LocalAttestationChallenge,
    },
    CreatedUnverified(Box<LocalKeySetDescriptor>),
}

impl LocalKeySetPhase {
    pub fn handle(&self) -> LocalKeyHandle {
        match self {
            Self::Preparing { handle, .. } => *handle,
            Self::CreatedUnverified(descriptor) => descriptor.handle(),
        }
    }

    pub fn challenge(&self) -> LocalAttestationChallenge {
        match self {
            Self::Preparing { challenge, .. } => *challenge,
            Self::CreatedUnverified(descriptor) => descriptor.challenge(),
        }
    }

    pub fn descriptor(&self) -> Option<&LocalKeySetDescriptor> {
        match self {
            Self::Preparing { .. } => None,
            Self::CreatedUnverified(descriptor) => Some(descriptor),
        }
    }
}

impl fmt::Debug for LocalKeySetPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Preparing { .. } => "LocalKeySetPhase::Preparing([redacted])",
            Self::CreatedUnverified(_) => "LocalKeySetPhase::CreatedUnverified([redacted])",
        })
    }
}

/// Pure bounded state suitable for one controller transaction candidate. Clone
/// copies metadata only and performs no key operation or durable transition.
#[derive(Clone, Default, PartialEq)]
pub struct LocalKeyLedger {
    entries: BTreeMap<LocalKeyHandle, LocalKeySetPhase>,
}

impl fmt::Debug for LocalKeyLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeyLedger")
            .field("set_count", &self.entries.len())
            .field(
                "preparing_count",
                &self
                    .entries
                    .values()
                    .filter(|phase| phase.descriptor().is_none())
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

impl LocalKeyLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn get(&self, handle: LocalKeyHandle) -> Option<&LocalKeySetPhase> {
        self.entries.get(&handle)
    }

    /// Immutable entries in ascending handle order, bounded to 32 total sets.
    pub fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = &LocalKeySetPhase> + DoubleEndedIterator {
        self.entries.values()
    }

    /// New metadata candidate only. Handle and challenge must each be unique in
    /// their respective retained namespaces; byte shape cannot establish CSPRNG
    /// freshness. Existing Preparing/CreatedUnverified always rejects this call,
    /// even for identical values. Commit before the owner's first native attempt.
    pub fn begin_creation(
        &mut self,
        handle: LocalKeyHandle,
        challenge: LocalAttestationChallenge,
    ) -> Result<(), LocalKeyError> {
        if self.entries.contains_key(&handle) {
            return Err(LocalKeyError::HandleAlreadyTracked);
        }
        if self
            .entries
            .values()
            .any(|phase| phase.challenge() == challenge)
        {
            return Err(LocalKeyError::ChallengeAlreadyTracked);
        }
        if self.entries.len() == MAX_LOCAL_KEY_SETS {
            return Err(LocalKeyError::CapacityReached);
        }
        self.entries
            .insert(handle, LocalKeySetPhase::Preparing { handle, challenge });
        Ok(())
    }

    /// Observes an exact pending creation; it does not generate/reopen a key.
    /// Only an identical already-created descriptor is idempotent. Every error
    /// preserves the previous state, including Preparing after a conflicting
    /// observation. No OS authenticity, chain policy or enrollment is inferred.
    pub fn record_created(
        &mut self,
        descriptor: LocalKeySetDescriptor,
    ) -> Result<LocalKeyObservation, LocalKeyError> {
        let handle = descriptor.handle();
        match self.entries.get(&handle) {
            None => return Err(LocalKeyError::MissingPreparation),
            Some(LocalKeySetPhase::CreatedUnverified(existing)) => {
                return if existing.as_ref() == &descriptor {
                    Ok(LocalKeyObservation::AlreadyRecordedUnverified)
                } else {
                    Err(LocalKeyError::ConflictingObservation)
                };
            }
            Some(LocalKeySetPhase::Preparing { challenge, .. })
                if *challenge != descriptor.challenge() =>
            {
                return Err(LocalKeyError::ChallengeMismatch);
            }
            Some(LocalKeySetPhase::Preparing { .. }) => (),
        }
        if self
            .entries
            .values()
            .filter_map(LocalKeySetPhase::descriptor)
            .any(|existing| existing.shares_key(&descriptor))
        {
            return Err(LocalKeyError::KeyReuse);
        }
        self.entries.insert(
            handle,
            LocalKeySetPhase::CreatedUnverified(Box::new(descriptor)),
        );
        Ok(LocalKeyObservation::RecordedUnverified)
    }

    /// v1: magic8, version u16 BE, count u16 BE, sorted rows. Each row is phase
    /// u8 (1 Preparing / 2 CreatedUnverified), handle32, challenge32; phase2 adds
    /// approval/denial/transport SPKI91 each, in that order. No optional extension.
    /// The outer controller SnapshotStore owns integrity/commit, not this codec.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LocalKeyError> {
        let size = HEADER_BYTES
            + self
                .entries
                .values()
                .map(|phase| {
                    if phase.descriptor().is_some() {
                        CREATED_BYTES
                    } else {
                        PREPARING_BYTES
                    }
                })
                .sum::<usize>();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| LocalKeyError::AllocationFailed)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for phase in self.entries.values() {
            bytes.push(if phase.descriptor().is_some() { 2 } else { 1 });
            bytes.extend_from_slice(phase.handle().as_bytes());
            bytes.extend_from_slice(phase.challenge().as_bytes());
            if let Some(descriptor) = phase.descriptor() {
                for key in descriptor.public_keys() {
                    bytes.extend_from_slice(key.as_spki_der());
                }
            }
        }
        Ok(bytes)
    }

    /// Strict bounded reconstruction only. Unknown/truncated/trailing data,
    /// unsorted/duplicate handles, reused challenges or keys and noncanonical
    /// public keys fail; nothing is reset, skipped, retried or made trusted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LocalKeyError> {
        if bytes.len() > MAX_LOCAL_KEY_LEDGER_BYTES {
            return Err(LocalKeyError::TooLarge);
        }
        let mut input = Input { bytes, offset: 0 };
        if input.take::<8>()? != *MAGIC {
            return Err(LocalKeyError::InvalidEncoding);
        }
        if u16::from_be_bytes(input.take()?) != VERSION {
            return Err(LocalKeyError::UnsupportedVersion);
        }
        let count = usize::from(u16::from_be_bytes(input.take()?));
        if count > MAX_LOCAL_KEY_SETS {
            return Err(LocalKeyError::TooManySets);
        }
        let mut ledger = Self::new();
        let mut previous = None;
        for _ in 0..count {
            let tag = input.take::<1>()?[0];
            if tag != 1 && tag != 2 {
                return Err(LocalKeyError::InvalidEncoding);
            }
            let handle = LocalKeyHandle::from_bytes(input.take()?)?;
            if let Some(prior) = previous {
                if handle == prior {
                    return Err(LocalKeyError::HandleAlreadyTracked);
                }
                if handle < prior {
                    return Err(LocalKeyError::NonCanonicalOrder);
                }
            }
            previous = Some(handle);
            let challenge = LocalAttestationChallenge::from_bytes(input.take()?)?;
            // Pure reconstruction uses the same metadata invariants. It never
            // starts/retries the external native creation represented by phase1.
            ledger.begin_creation(handle, challenge)?;
            if tag == 2 {
                let approval = read_public_key(&mut input)?;
                let denial = read_public_key(&mut input)?;
                let transport = read_public_key(&mut input)?;
                let descriptor =
                    LocalKeySetDescriptor::new(handle, challenge, approval, denial, transport)?;
                let _ = ledger.record_created(descriptor)?;
            }
        }
        if input.offset != bytes.len() {
            return Err(LocalKeyError::InvalidEncoding);
        }
        Ok(ledger)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKeyObservation {
    RecordedUnverified,
    AlreadyRecordedUnverified,
}

/// Fixed categories only; no aliases, keys, handles, challenges or provider text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalKeyError {
    #[error("local key handle must be nonzero")]
    InvalidHandle,
    #[error("local key attestation challenge must be nonzero")]
    InvalidChallenge,
    #[error("local key handle is already tracked and cannot start another creation")]
    HandleAlreadyTracked,
    #[error("local key attestation challenge is already tracked")]
    ChallengeAlreadyTracked,
    #[error("local key ledger capacity reached")]
    CapacityReached,
    #[error("local key observation has no matching preparation")]
    MissingPreparation,
    #[error("local key observation does not match its prepared challenge")]
    ChallengeMismatch,
    #[error("local key observation conflicts with the recorded public identities")]
    ConflictingObservation,
    #[error("local key roles or sets reuse a public key")]
    KeyReuse,
    #[error("local key public identity is not canonical P-256 SPKI")]
    InvalidPublicKey,
    #[error("local key ledger encoding is invalid")]
    InvalidEncoding,
    #[error("local key ledger version is unsupported")]
    UnsupportedVersion,
    #[error("local key ledger exceeds its byte bound")]
    TooLarge,
    #[error("local key ledger exceeds its set count bound")]
    TooManySets,
    #[error("local key ledger handles are not in canonical order")]
    NonCanonicalOrder,
    #[error("bounded local key encoding allocation failed")]
    AllocationFailed,
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], LocalKeyError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(LocalKeyError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(LocalKeyError::InvalidEncoding)?
            .try_into()
            .map_err(|_| LocalKeyError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
}

fn read_public_key(input: &mut Input<'_>) -> Result<TlsPublicKey, LocalKeyError> {
    TlsPublicKey::from_spki_der(&input.take::<SPKI_BYTES>()?)
        .map_err(|_| LocalKeyError::InvalidPublicKey)
}
