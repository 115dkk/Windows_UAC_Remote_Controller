// SPDX-License-Identifier: GPL-2.0-or-later
//! Canonical PC enrollment-acceptance statement, not ceremony authorization,
//! attestation, freshness, key possession, a committed registry or an action.
//! The receiving owner must enforce those independent conditions exactly once.
#![forbid(unsafe_code)]

mod frozen;
pub use frozen::{
    FrozenCandidateContext, FrozenCandidateError, FrozenCandidateFields, InvitationContextDigest,
    MAX_FROZEN_CANDIDATE_BYTES, MatchedFrozenCandidate, PairingComparisonCode,
    SignedFrozenCandidate, UnsignedFrozenCandidate, VerifiedFrozenCandidate,
};

use approval_protocol::{DeviceId, MAX_DER_SIGNATURE_BYTES, MIN_DER_SIGNATURE_BYTES, PcIdentity};
use secure_channel::{CertificateVerifySignature, TlsPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

use crate::{PcPublicKey, codec::Reader};

const MAGIC: &[u8; 8] = b"WUACENR\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;
const SPKI_BYTES: usize = 91;
const BODY_BYTES: usize = 12 + 32 + 32 + 32 + 16 + 8 + 32 + SPKI_BYTES * 2;
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/enrollment-acceptance/v1\0";
const KEY_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pairing-phone-key-digest/v1\0";

/// Exact v1 upper bound:346-byte header/body +2-byte DER length +72-byte DER.
pub const MAX_ENROLLMENT_ACCEPTANCE_BYTES: usize = BODY_BYTES + 2 + MAX_DER_SIGNATURE_BYTES;

macro_rules! nonce {
    ($name:ident) => {
        /// A nonzero fixed-width value. Parsing proves neither CSPRNG origin,
        /// freshness, ceremony membership nor permission to enroll.
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $name([u8; 32]);
        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PairingError> {
                if bytes.iter().all(|value| *value == 0) {
                    return Err(PairingError::InvalidFields);
                }
                Ok(Self(bytes))
            }
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}
nonce!(PairingNonce);
nonce!(PairingChallenge);

/// Fixed-role digest of three public keys; not an attestation or enrollment proof.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PhoneKeyDigest([u8; 32]);
impl PhoneKeyDigest {
    pub fn from_keys(
        approval: &TlsPublicKey,
        denial: &TlsPublicKey,
        transport: &TlsPublicKey,
    ) -> Result<Self, PairingError> {
        if approval == denial || approval == transport || denial == transport {
            return Err(PairingError::KeyReuse);
        }
        let mut hash = Sha256::new();
        hash.update(KEY_DOMAIN);
        for (role, key) in [(1u8, approval), (2, denial), (3, transport)] {
            // TlsPublicKey owns the validated canonical91-byte representation.
            hash.update([role]);
            hash.update(key.as_spki_der());
        }
        Ok(Self(hash.finalize().into()))
    }
    /// Width-only decoding for the wire. The owner must compare this value with
    /// from_keys over its exact candidate tuple; arbitrary bytes prove nothing.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl fmt::Debug for PhoneKeyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhoneKeyDigest([redacted])")
    }
}

/// Plain, structurally validated statement fields. All trust/currentness comes
/// from the separate native ceremony owner, never this freely constructible DTO.
#[derive(Clone, Eq, PartialEq)]
pub struct EnrollmentAcceptanceFields {
    pub ceremony_nonce: PairingNonce,
    pub attestation_challenge: PairingChallenge,
    pub pc: PcIdentity,
    pub recipient_device: DeviceId,
    pub registry_revision: u64,
    pub phone_keys: PhoneKeyDigest,
    pub pc_signing_key: TlsPublicKey,
    pub pc_transport_key: TlsPublicKey,
}
impl EnrollmentAcceptanceFields {
    fn validate(&self) -> Result<(), PairingError> {
        if self.registry_revision == 0 {
            return Err(PairingError::InvalidFields);
        }
        // One PC may use its existing domain-separated identity key for both
        // PC roles. Phone-role key separation is established by from_keys and
        // the receiving owner's exact candidate comparison, not guessed here.
        Ok(())
    }
}
impl fmt::Debug for EnrollmentAcceptanceFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentAcceptanceFields([redacted], shape_only)")
    }
}

pub struct UnsignedEnrollmentAcceptance {
    fields: EnrollmentAcceptanceFields,
}
impl UnsignedEnrollmentAcceptance {
    pub fn new(fields: EnrollmentAcceptanceFields) -> Result<Self, PairingError> {
        fields.validate()?;
        Ok(Self { fields })
    }
    /// Exact SHA256withECDSA input. The trusted PC key owner must construct
    /// this statement from a real committed acceptance, not a generic sign RPC.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(&self.fields)
    }
    pub fn with_der_signature(
        self,
        der: &[u8],
    ) -> Result<SignedEnrollmentAcceptance, PairingError> {
        validate_signature(der)?;
        Ok(SignedEnrollmentAcceptance {
            fields: self.fields,
            der: der.to_vec(),
        })
    }
}
impl fmt::Debug for UnsignedEnrollmentAcceptance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnsignedEnrollmentAcceptance([redacted])")
    }
}

#[derive(Clone)]
pub struct SignedEnrollmentAcceptance {
    fields: EnrollmentAcceptanceFields,
    der: Vec<u8>,
}
impl SignedEnrollmentAcceptance {
    /// Strict fixed-v1 decoding only. A parsed signature is not yet verified.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, PairingError> {
        if !(BODY_BYTES + 2 + MIN_DER_SIGNATURE_BYTES..=MAX_ENROLLMENT_ACCEPTANCE_BYTES)
            .contains(&bytes.len())
        {
            return Err(PairingError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        if array::<8>(&mut reader)? != *MAGIC {
            return Err(PairingError::InvalidEncoding);
        }
        if u16::from_be_bytes(array(&mut reader)?) != VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if array::<1>(&mut reader)? != [KIND] {
            return Err(PairingError::UnsupportedKind);
        }
        if array::<1>(&mut reader)? != [0] {
            return Err(PairingError::InvalidEncoding);
        }
        let fields = EnrollmentAcceptanceFields {
            ceremony_nonce: PairingNonce::from_bytes(array(&mut reader)?)?,
            attestation_challenge: PairingChallenge::from_bytes(array(&mut reader)?)?,
            pc: PcIdentity::from_bytes(array(&mut reader)?)
                .map_err(|_| PairingError::InvalidFields)?,
            recipient_device: DeviceId::from_bytes(array(&mut reader)?)
                .map_err(|_| PairingError::InvalidFields)?,
            registry_revision: u64::from_be_bytes(array(&mut reader)?),
            phone_keys: PhoneKeyDigest::from_bytes(array(&mut reader)?),
            pc_signing_key: key(&mut reader)?,
            pc_transport_key: key(&mut reader)?,
        };
        fields.validate()?;
        let signature_length = usize::from(u16::from_be_bytes(array(&mut reader)?));
        let der = reader
            .take(signature_length)
            .map_err(|_| PairingError::InvalidLength)?;
        reader.finish().map_err(|_| PairingError::InvalidLength)?;
        validate_signature(der)?;
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
    /// The trusted PC key is supplied independently of this message. A valid
    /// signature does NOT prove live ceremony, current revision/attestation,
    /// expiry, possession or either side's durable commit. Check those upstream.
    pub fn verify(
        &self,
        trusted_pc_signing: &TlsPublicKey,
    ) -> Result<VerifiedEnrollmentAcceptance, PairingError> {
        if &self.fields.pc_signing_key != trusted_pc_signing {
            return Err(PairingError::UntrustedPcKey);
        }
        let key = PcPublicKey::from_spki_der(trusted_pc_signing.as_spki_der())
            .map_err(|_| PairingError::InvalidKey)?;
        key.verify_transcript(&signing_bytes(&self.fields), &self.der)
            .map_err(|_| PairingError::InvalidSignature)?;
        Ok(VerifiedEnrollmentAcceptance {
            fields: self.fields.clone(),
        })
    }
}
impl fmt::Debug for SignedEnrollmentAcceptance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedEnrollmentAcceptance([redacted])")
    }
}

/// Private construction after verification against an independently trusted pin.
/// Non-Clone does not make the wire one-use: the native owner enforces replay.
/// ```compile_fail
/// fn duplicate(value: service_protocol::VerifiedEnrollmentAcceptance) {
///     let _copy = value.clone();
/// }
/// ```
pub struct VerifiedEnrollmentAcceptance {
    fields: EnrollmentAcceptanceFields,
}
impl VerifiedEnrollmentAcceptance {
    pub const fn fields(&self) -> &EnrollmentAcceptanceFields {
        &self.fields
    }
}
impl fmt::Debug for VerifiedEnrollmentAcceptance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedEnrollmentAcceptance([redacted], signature_only)")
    }
}

fn array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], PairingError> {
    reader
        .take(N)
        .map_err(|_| PairingError::InvalidLength)?
        .try_into()
        .map_err(|_| PairingError::InvalidLength)
}
fn key(reader: &mut Reader<'_>) -> Result<TlsPublicKey, PairingError> {
    TlsPublicKey::from_spki_der(
        reader
            .take(SPKI_BYTES)
            .map_err(|_| PairingError::InvalidLength)?,
    )
    .map_err(|_| PairingError::InvalidKey)
}
fn validate_signature(bytes: &[u8]) -> Result<(), PairingError> {
    if !(MIN_DER_SIGNATURE_BYTES..=MAX_DER_SIGNATURE_BYTES).contains(&bytes.len()) {
        return Err(PairingError::InvalidSignature);
    }
    // Existing canonical P-256 DER/scalar validation; no signature arithmetic.
    CertificateVerifySignature::from_der(bytes)
        .map(|_| ())
        .map_err(|_| PairingError::InvalidSignature)
}
fn body(fields: &EnrollmentAcceptanceFields) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BODY_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[KIND, 0]);
    bytes.extend_from_slice(fields.ceremony_nonce.as_bytes());
    bytes.extend_from_slice(fields.attestation_challenge.as_bytes());
    bytes.extend_from_slice(fields.pc.as_bytes());
    bytes.extend_from_slice(fields.recipient_device.as_bytes());
    bytes.extend_from_slice(&fields.registry_revision.to_be_bytes());
    bytes.extend_from_slice(fields.phone_keys.as_bytes());
    bytes.extend_from_slice(fields.pc_signing_key.as_spki_der());
    bytes.extend_from_slice(fields.pc_transport_key.as_spki_der());
    bytes
}
fn signing_bytes(fields: &EnrollmentAcceptanceFields) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + BODY_BYTES);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&body(fields));
    bytes
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairingError {
    #[error("pairing acceptance fields are invalid")]
    InvalidFields,
    #[error("pairing acceptance length is invalid")]
    InvalidLength,
    #[error("pairing acceptance encoding is invalid")]
    InvalidEncoding,
    #[error("pairing acceptance version is unsupported")]
    UnsupportedVersion,
    #[error("pairing acceptance kind is unsupported")]
    UnsupportedKind,
    #[error("pairing public key encoding is invalid")]
    InvalidKey,
    #[error("phone key roles must be distinct")]
    KeyReuse,
    #[error("pairing acceptance signature is invalid")]
    InvalidSignature,
    #[error("pairing acceptance does not match the trusted PC key")]
    UntrustedPcKey,
}

#[cfg(test)]
mod tests;
