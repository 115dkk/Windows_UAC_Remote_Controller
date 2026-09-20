// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed, frozen candidate metadata and a public comparison code, NOT an
//! enrollment acceptance, committed registry receipt or authorization token.
//!
//! The privileged PC ceremony owner must atomically freeze exactly ONE fully
//! attested, three-role proof-of-possession-verified candidate, select its
//! actual registry allocator's next revision, and sign NO replacement for that
//! ceremony. These are independent native-owner obligations, not codec facts.
//! The phone may display the comparison code only after an independent PC-pin
//! signature check and a match against its ORIGINAL immutable local key tuple,
//! invitation and ceremony context. It must retain the signed intended revision
//! for the later enrollment-acceptance comparison; it cannot invent an expected
//! context from this reply. Native helper confirmation must still be live and
//! bound to the original deadline/cancellation before the existing final commit.
//!
//! No type here proves fresh UAC, attestation, possession, one-use/freeze,
//! deadline, native-display liveness or either durable commit. The six digits
//! are public comparison data, not a secret, credential or authority.

use std::fmt;

use approval_protocol::{DeviceId, MAX_DER_SIGNATURE_BYTES, MIN_DER_SIGNATURE_BYTES, PcIdentity};
use secure_channel::TlsPublicKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{PairingChallenge, PairingError, PairingNonce, PhoneKeyDigest, SPKI_BYTES};
use crate::{PcPublicKey, codec::Reader};

const MAGIC: &[u8; 8] = b"WUACFRZ\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/candidate-frozen/v1\0";
const SAS_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pairing-sas/v1\0";
const BODY_BYTES: usize = 12 + 32 + 32 + 32 + 16 + 8 + 32 + SPKI_BYTES * 2 + 32;

/// Exact fixed-v1 maximum: 378-byte header/body + 2-byte DER length + 72-byte DER.
pub const MAX_FROZEN_CANDIDATE_BYTES: usize = BODY_BYTES + 2 + MAX_DER_SIGNATURE_BYTES;

/// Width-only invitation-context digest. Arbitrary bytes (including zero) are
/// representable; this type proves neither a trusted invitation nor its origin.
/// The native owner computes/retains the digest of its original invitation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InvitationContextDigest([u8; 32]);

impl InvitationContextDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InvitationContextDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationContextDigest([redacted], width_only)")
    }
}

/// Original-context values, not evidence of their provenance. The phone owner
/// supplies this from its original immutable ceremony and exact three-role key
/// tuple, independently of the received candidate. No fourth phone key exists.
/// The PC-selected intended revision is deliberately not an original phone
/// context value: it is separately signed, SAS-bound and retained for acceptance.
#[derive(Clone, Eq, PartialEq)]
pub struct FrozenCandidateContext {
    pub ceremony_nonce: PairingNonce,
    pub attestation_challenge: PairingChallenge,
    pub pc: PcIdentity,
    pub recipient_device: DeviceId,
    pub phone_keys: PhoneKeyDigest,
    pub pc_signing_key: TlsPublicKey,
    pub pc_transport_key: TlsPublicKey,
    pub invitation_context: InvitationContextDigest,
}

impl fmt::Debug for FrozenCandidateContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenCandidateContext([redacted], shape_only)")
    }
}

/// Freely constructible shape-only metadata. A valid signature does not certify
/// that the PC actually froze the candidate or committed this revision.
#[derive(Clone, Eq, PartialEq)]
pub struct FrozenCandidateFields {
    pub context: FrozenCandidateContext,
    /// The existing allocator returns its current next_revision and THEN
    /// advances it. Supply that actual next_revision unchanged, not next+1 or
    /// max(active revisions)+1. Zero and the exhausted u64::MAX state reject.
    pub intended_registry_revision: u64,
}

impl FrozenCandidateFields {
    fn validate(&self) -> Result<(), FrozenCandidateError> {
        if self.intended_registry_revision == 0
            || self.intended_registry_revision.checked_add(1).is_none()
        {
            return Err(FrozenCandidateError::InvalidRevision);
        }
        Ok(())
    }
}

impl fmt::Debug for FrozenCandidateFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenCandidateFields([redacted], not_committed)")
    }
}

pub struct UnsignedFrozenCandidate {
    fields: FrozenCandidateFields,
}

impl UnsignedFrozenCandidate {
    pub fn new(fields: FrozenCandidateFields) -> Result<Self, FrozenCandidateError> {
        fields.validate()?;
        Ok(Self { fields })
    }

    /// Canonical SHA256withECDSA input for the existing PC signing-key owner.
    /// Its native owner must freeze/attest/check possession before signing;
    /// this method must not be exposed as a generic signing RPC.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(&self.fields)
    }

    pub fn with_der_signature(
        self,
        der: &[u8],
    ) -> Result<SignedFrozenCandidate, FrozenCandidateError> {
        super::validate_signature(der).map_err(FrozenCandidateError::from_pairing)?;
        Ok(SignedFrozenCandidate {
            fields: self.fields,
            der: der.to_vec(),
        })
    }
}

impl fmt::Debug for UnsignedFrozenCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnsignedFrozenCandidate([redacted])")
    }
}

#[derive(Clone)]
pub struct SignedFrozenCandidate {
    fields: FrozenCandidateFields,
    der: Vec<u8>,
}

impl SignedFrozenCandidate {
    pub fn from_wire(bytes: &[u8]) -> Result<Self, FrozenCandidateError> {
        if !(BODY_BYTES + 2 + MIN_DER_SIGNATURE_BYTES..=MAX_FROZEN_CANDIDATE_BYTES)
            .contains(&bytes.len())
        {
            return Err(FrozenCandidateError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        if array::<8>(&mut reader)? != *MAGIC {
            return Err(FrozenCandidateError::InvalidEncoding);
        }
        if u16::from_be_bytes(array(&mut reader)?) != VERSION {
            return Err(FrozenCandidateError::UnsupportedVersion);
        }
        if array::<1>(&mut reader)? != [KIND] {
            return Err(FrozenCandidateError::UnsupportedKind);
        }
        if array::<1>(&mut reader)? != [0] {
            return Err(FrozenCandidateError::InvalidEncoding);
        }
        let ceremony_nonce = PairingNonce::from_bytes(array(&mut reader)?)
            .map_err(FrozenCandidateError::from_pairing)?;
        let attestation_challenge = PairingChallenge::from_bytes(array(&mut reader)?)
            .map_err(FrozenCandidateError::from_pairing)?;
        let pc = PcIdentity::from_bytes(array(&mut reader)?)
            .map_err(|_| FrozenCandidateError::InvalidFields)?;
        let recipient_device = DeviceId::from_bytes(array(&mut reader)?)
            .map_err(|_| FrozenCandidateError::InvalidFields)?;
        let intended_registry_revision = u64::from_be_bytes(array(&mut reader)?);
        let phone_keys = PhoneKeyDigest::from_bytes(array(&mut reader)?);
        let pc_signing_key = super::key(&mut reader).map_err(FrozenCandidateError::from_pairing)?;
        let pc_transport_key =
            super::key(&mut reader).map_err(FrozenCandidateError::from_pairing)?;
        let invitation_context = InvitationContextDigest::from_bytes(array(&mut reader)?);
        let fields = FrozenCandidateFields {
            context: FrozenCandidateContext {
                ceremony_nonce,
                attestation_challenge,
                pc,
                recipient_device,
                phone_keys,
                pc_signing_key,
                pc_transport_key,
                invitation_context,
            },
            intended_registry_revision,
        };
        fields.validate()?;
        let signature_length = usize::from(u16::from_be_bytes(array(&mut reader)?));
        let der = reader
            .take(signature_length)
            .map_err(|_| FrozenCandidateError::InvalidLength)?;
        reader
            .finish()
            .map_err(|_| FrozenCandidateError::InvalidLength)?;
        super::validate_signature(der).map_err(FrozenCandidateError::from_pairing)?;
        Ok(Self {
            fields,
            der: der.to_vec(),
        })
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = body(&self.fields);
        bytes.extend_from_slice(&(self.der.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.der);
        bytes
    }

    /// The pin must come from the independently retained original native trust
    /// context, not the message's own signing-key field. Signature validity is
    /// only one prerequisite; no comparison code is available on this result
    /// until the original context is matched.
    pub fn verify(
        &self,
        trusted_pc_signing: &TlsPublicKey,
    ) -> Result<VerifiedFrozenCandidate, FrozenCandidateError> {
        if &self.fields.context.pc_signing_key != trusted_pc_signing {
            return Err(FrozenCandidateError::UntrustedPcKey);
        }
        let key = PcPublicKey::from_spki_der(trusted_pc_signing.as_spki_der())
            .map_err(|_| FrozenCandidateError::InvalidKey)?;
        key.verify_transcript(&signing_bytes(&self.fields), &self.der)
            .map_err(|_| FrozenCandidateError::InvalidSignature)?;
        Ok(VerifiedFrozenCandidate {
            fields: self.fields.clone(),
        })
    }
}

impl fmt::Debug for SignedFrozenCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedFrozenCandidate([redacted])")
    }
}

/// Non-Clone signature observation, not a one-use or live-ceremony capability.
/// ```compile_fail
/// fn duplicate(value: service_protocol::VerifiedFrozenCandidate) {
///     let _copy = value.clone();
/// }
/// ```
/// ```compile_fail
/// fn display_before_matching(value: service_protocol::VerifiedFrozenCandidate) {
///     let _code = value.comparison_code();
/// }
/// ```
pub struct VerifiedFrozenCandidate {
    fields: FrozenCandidateFields,
}

impl VerifiedFrozenCandidate {
    pub const fn fields(&self) -> &FrozenCandidateFields {
        &self.fields
    }

    /// Consume verification and compare every original context field. The
    /// caller must supply its independently retained immutable context, NEVER a
    /// context reconstructed from fields() or the reply. This checks equality,
    /// not provenance/liveness; the owner must retain intended_registry_revision
    /// and require it again on the later, distinct enrollment acceptance.
    pub fn match_original(
        self,
        expected: &FrozenCandidateContext,
    ) -> Result<MatchedFrozenCandidate, FrozenCandidateError> {
        if &self.fields.context != expected {
            return Err(FrozenCandidateError::OriginalContextMismatch);
        }
        Ok(MatchedFrozenCandidate {
            fields: self.fields,
        })
    }
}

impl fmt::Debug for VerifiedFrozenCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedFrozenCandidate([redacted], signature_only)")
    }
}

/// Signature plus exact supplied-context equality only. The PC freeze,
/// attestation/PoP, original deadline, cancellation and native display/consent
/// remain separate. Re-verifying the same wire is possible and not replay-safe.
/// ```compile_fail
/// fn duplicate(value: service_protocol::MatchedFrozenCandidate) {
///     let _copy = value.clone();
/// }
/// ```
pub struct MatchedFrozenCandidate {
    fields: FrozenCandidateFields,
}

impl MatchedFrozenCandidate {
    pub const fn fields(&self) -> &FrozenCandidateFields {
        &self.fields
    }

    /// Six ASCII decimal digits of the FULL big-endian SHA-256 integer modulo
    /// 1,000,000 over SAS_DOMAIN || canonical frozen BODY (not the signature).
    /// This is public comparison data, not authorization or a secret token.
    pub fn comparison_code(&self) -> PairingComparisonCode {
        let mut digest = Sha256::new();
        digest.update(SAS_DOMAIN);
        digest.update(body(&self.fields));
        decimal_code(digest.finalize().into())
    }
}

impl fmt::Debug for MatchedFrozenCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MatchedFrozenCandidate([redacted], context_match_only)")
    }
}

/// Explicit display access for public six-digit comparison data. Debug remains
/// redacted and there is no Display/serde implementation or public constructor.
/// Clone exists so a session can report the code it already sent to its display.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingComparisonCode(String);

impl PairingComparisonCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingComparisonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingComparisonCode([redacted], public_comparison_only)")
    }
}

fn decimal_code(hash: [u8; 32]) -> PairingComparisonCode {
    let mut remainder = 0u32;
    for byte in hash {
        // The intermediate is <= 255,999,999: no truncation, overflow or new
        // bignum/crypto dependency is needed for the full 256-bit remainder.
        remainder = (remainder * 256 + u32::from(byte)) % 1_000_000;
    }
    PairingComparisonCode(format!("{remainder:06}"))
}

fn array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], FrozenCandidateError> {
    super::array(reader).map_err(FrozenCandidateError::from_pairing)
}

fn body(fields: &FrozenCandidateFields) -> Vec<u8> {
    let context = &fields.context;
    let mut bytes = Vec::with_capacity(BODY_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[KIND, 0]);
    bytes.extend_from_slice(context.ceremony_nonce.as_bytes());
    bytes.extend_from_slice(context.attestation_challenge.as_bytes());
    bytes.extend_from_slice(context.pc.as_bytes());
    bytes.extend_from_slice(context.recipient_device.as_bytes());
    bytes.extend_from_slice(&fields.intended_registry_revision.to_be_bytes());
    bytes.extend_from_slice(context.phone_keys.as_bytes());
    bytes.extend_from_slice(context.pc_signing_key.as_spki_der());
    bytes.extend_from_slice(context.pc_transport_key.as_spki_der());
    bytes.extend_from_slice(context.invitation_context.as_bytes());
    bytes
}

fn signing_bytes(fields: &FrozenCandidateFields) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + BODY_BYTES);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&body(fields));
    bytes
}

#[derive(Clone, Copy, Eq, Error, PartialEq)]
pub enum FrozenCandidateError {
    #[error("frozen candidate fields are invalid")]
    InvalidFields,
    #[error("frozen candidate revision cannot be allocated")]
    InvalidRevision,
    #[error("frozen candidate length is invalid")]
    InvalidLength,
    #[error("frozen candidate encoding is invalid")]
    InvalidEncoding,
    #[error("frozen candidate version is unsupported")]
    UnsupportedVersion,
    #[error("frozen candidate kind is unsupported")]
    UnsupportedKind,
    #[error("frozen candidate public key encoding is invalid")]
    InvalidKey,
    #[error("frozen candidate signature is invalid")]
    InvalidSignature,
    #[error("frozen candidate does not match the trusted PC key")]
    UntrustedPcKey,
    #[error("frozen candidate does not match the original context")]
    OriginalContextMismatch,
}

impl FrozenCandidateError {
    fn from_pairing(error: PairingError) -> Self {
        match error {
            PairingError::InvalidFields | PairingError::KeyReuse => Self::InvalidFields,
            PairingError::InvalidLength => Self::InvalidLength,
            PairingError::InvalidEncoding => Self::InvalidEncoding,
            PairingError::UnsupportedVersion => Self::UnsupportedVersion,
            PairingError::UnsupportedKind => Self::UnsupportedKind,
            PairingError::InvalidKey => Self::InvalidKey,
            PairingError::InvalidSignature => Self::InvalidSignature,
            PairingError::UntrustedPcKey => Self::UntrustedPcKey,
        }
    }
}

impl fmt::Debug for FrozenCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FrozenCandidateError([redacted])")
    }
}

#[cfg(test)]
mod tests;
