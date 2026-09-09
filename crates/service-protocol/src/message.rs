// SPDX-License-Identifier: GPL-2.0-or-later
use std::{fmt, sync::Arc};

use approval_protocol::{
    BootEpoch, MAX_DER_SIGNATURE_BYTES, MAX_REQUEST_CONTENT_BYTES, MIN_DER_SIGNATURE_BYTES,
    PcIdentity, RequestBinding, RequestContent,
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use thiserror::Error;

use crate::codec;

pub const MAX_REQUEST_LIFETIME_NANOS: u64 = 120_000_000_000;
pub(crate) const MAX_BODY_BYTES: usize = 3 + 180 + 8 + 12 + MAX_REQUEST_CONTENT_BYTES;
pub const MAX_PC_EVENT_BYTES: usize = 8 + 4 + MAX_BODY_BYTES + 2 + MAX_DER_SIGNATURE_BYTES;
pub(crate) const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pc-event/v1\0";
pub(crate) const MAGIC: &[u8; 8] = b"WUACSRV\0";

/// A fresh phone challenge echoed by the service's signed clock response.
/// Generate independently with the platform CSPRNG for every probe; never reuse.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ClockProbeNonce([u8; 32]);

impl ClockProbeNonce {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PcEventError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(PcEventError::InvalidFields);
        }
        Ok(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClockProbeNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClockProbeNonce([redacted])")
    }
}

/// An actual service/OS outcome, not delivery, intent or signature acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestResolution {
    Approved,
    Denied,
    Cancelled,
    Expired,
    Failed,
}

/// Nanoseconds on the current service epoch. Zero is a valid issuance/sample
/// at epoch start; unlike a future ExpiryTick it does not need to be positive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceTick(u64);
impl ServiceTick {
    pub const fn from_nanos_since_epoch(value: u64) -> Self {
        Self(value)
    }
    pub const fn as_nanos_since_epoch(self) -> u64 {
        self.0
    }
}

/// Public data shape; construction of this enum conveys NO authentication.
#[derive(Clone, Eq, PartialEq)]
pub enum PcEvent {
    Opened {
        binding: RequestBinding,
        issued_at: ServiceTick,
        content: Arc<RequestContent>,
    },
    Resolved {
        binding: RequestBinding,
        /// Original REQUEST issuance, never the time of this resolution. Keep
        /// the same value after expiry so the exact lifetime/tombstone matches.
        issued_at: ServiceTick,
        outcome: RequestResolution,
    },
    Clock {
        pc: PcIdentity,
        epoch: BootEpoch,
        probe: ClockProbeNonce,
        sampled_at: ServiceTick,
    },
}

impl PcEvent {
    pub const fn pc(&self) -> PcIdentity {
        match self {
            Self::Opened { binding, .. } | Self::Resolved { binding, .. } => binding.pc(),
            Self::Clock { pc, .. } => *pc,
        }
    }
    pub const fn epoch(&self) -> BootEpoch {
        match self {
            Self::Opened { binding, .. } | Self::Resolved { binding, .. } => binding.epoch(),
            Self::Clock { epoch, .. } => *epoch,
        }
    }
    fn validate(&self) -> Result<(), PcEventError> {
        match self {
            Self::Opened {
                binding,
                issued_at,
                content,
            } => {
                validate_window(*binding, *issued_at)?;
                if binding.content_digest() != content.digest() {
                    return Err(PcEventError::ContentMismatch);
                }
                Ok(())
            }
            Self::Resolved {
                binding, issued_at, ..
            } => validate_window(*binding, *issued_at),
            Self::Clock { .. } => Ok(()),
        }
    }
}

fn validate_window(binding: RequestBinding, issued_at: ServiceTick) -> Result<(), PcEventError> {
    let lifetime = binding
        .expiry()
        .as_nanos_since_epoch()
        .checked_sub(issued_at.as_nanos_since_epoch())
        .ok_or(PcEventError::InvalidLifetime)?;
    if lifetime == 0 || lifetime > MAX_REQUEST_LIFETIME_NANOS {
        return Err(PcEventError::InvalidLifetime);
    }
    Ok(())
}

impl fmt::Debug for PcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Opened { .. } => "PcEvent::Opened([redacted])",
            Self::Resolved { .. } => "PcEvent::Resolved([redacted])",
            Self::Clock { .. } => "PcEvent::Clock([redacted])",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedPcEvent(PcEvent);

impl UnsignedPcEvent {
    /// Trusted service code must supply its actual immutable OS capture and
    /// epoch timestamps. This constructor cannot verify native provenance.
    pub fn new(event: PcEvent) -> Result<Self, PcEventError> {
        event.validate()?;
        Ok(Self(event))
    }
    /// Sign these exact bytes with SHA256withECDSA, or hash them exactly once
    /// before the TPM's digest-signing operation. Do not log this display body.
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_record(&codec::encode(&self.0))
    }
    pub fn with_der_signature(self, der: &[u8]) -> Result<SignedPcEvent, PcEventError> {
        signature(der)?;
        Ok(SignedPcEvent {
            event: self.0,
            der: der.to_vec(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PcPublicKey(VerifyingKey);

impl PcPublicKey {
    /// Canonical uncompressed P-256 SPKI, as retained in native peer metadata.
    /// Parsing a public key does not establish its enrollment or provenance.
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, PcEventError> {
        if bytes.len() != 91 {
            return Err(PcEventError::InvalidKey);
        }
        let key =
            p256::PublicKey::from_public_key_der(bytes).map_err(|_| PcEventError::InvalidKey)?;
        let canonical = key
            .to_public_key_der()
            .map_err(|_| PcEventError::InvalidKey)?;
        if canonical.as_bytes() != bytes {
            return Err(PcEventError::InvalidKey);
        }
        Ok(Self(VerifyingKey::from(key)))
    }

    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, PcEventError> {
        if !matches!(
            (bytes.len(), bytes.first()),
            (33, Some(2 | 3)) | (65, Some(4))
        ) {
            return Err(PcEventError::InvalidKey);
        }
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| PcEventError::InvalidKey)
    }
    fn verify(&self, body: &[u8], der: &[u8]) -> Result<(), PcEventError> {
        let signature = signature(der)?;
        let normalized = signature.normalize_s().unwrap_or(signature);
        self.0
            .verify(&signing_record(body), &normalized)
            .map_err(|_| PcEventError::InvalidSignature)
    }
}

impl fmt::Debug for PcPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PcPublicKey([redacted])")
    }
}

/// Syntactically signed, not yet authenticated. Only verify produces a trusted
/// message. DER byte equality is never a replay/identity check.
#[derive(Clone)]
pub struct SignedPcEvent {
    event: PcEvent,
    der: Vec<u8>,
}

impl SignedPcEvent {
    pub fn to_wire(&self) -> Vec<u8> {
        let body = codec::encode(&self.event);
        let mut bytes = Vec::with_capacity(14 + body.len() + self.der.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&(self.der.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.der);
        bytes
    }
    pub fn verify(
        &self,
        expected_pc: PcIdentity,
        key: &PcPublicKey,
    ) -> Result<VerifiedPcEvent, PcEventError> {
        key.verify(&codec::encode(&self.event), &self.der)?;
        if self.event.pc() != expected_pc {
            return Err(PcEventError::WrongPc);
        }
        Ok(VerifiedPcEvent {
            event: self.event.clone(),
            verification_key: key.clone(),
        })
    }
}

impl fmt::Debug for SignedPcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedPcEvent([redacted])")
    }
}

/// Created only after signature verification with the supplied PC/key tuple.
/// The caller must obtain that tuple from its current trusted enrollment mapping;
/// this codec does not query a registry or establish revocation/attestation.
/// Freshness, a live epoch, revocation, delivery schedule and OS success still
/// belong to the receiving service/application state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPcEvent {
    event: PcEvent,
    // Preserve the key that actually passed verification. A caller must not
    // later attach a replacement association merely because its PC ID matches.
    // PcPublicKey's Debug is redacted and there is no public event constructor.
    verification_key: PcPublicKey,
}

impl VerifiedPcEvent {
    pub fn from_wire(
        bytes: &[u8],
        expected_pc: PcIdentity,
        key: &PcPublicKey,
    ) -> Result<Self, PcEventError> {
        if bytes.len() > MAX_PC_EVENT_BYTES || bytes.len() < 14 + MIN_DER_SIGNATURE_BYTES {
            return Err(PcEventError::InvalidLength);
        }
        let mut reader = codec::Reader::new(bytes);
        if reader.take(8)? != MAGIC {
            return Err(PcEventError::InvalidEncoding);
        }
        let size = reader.u32()? as usize;
        if size > MAX_BODY_BYTES {
            return Err(PcEventError::InvalidLength);
        }
        let body = reader.take(size)?;
        let signature_length = usize::from(reader.u16()?);
        let der = reader.take(signature_length)?;
        reader.finish()?;
        // Authenticate before allocating text or exposing any event fields.
        key.verify(body, der)?;
        let event = codec::decode(body)?;
        event.validate()?;
        if event.pc() != expected_pc {
            return Err(PcEventError::WrongPc);
        }
        Ok(Self {
            event,
            verification_key: key.clone(),
        })
    }
    pub fn event(&self) -> &PcEvent {
        &self.event
    }
    /// The exact cryptographic verification key, not a fresh enrollment lookup.
    /// This still does not prove a TLS peer, recipient, current registration,
    /// native provenance or permission to issue a device decision.
    pub fn verification_key(&self) -> &PcPublicKey {
        &self.verification_key
    }
}

fn signing_record(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + body.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(body);
    bytes
}

fn signature(bytes: &[u8]) -> Result<Signature, PcEventError> {
    if !(MIN_DER_SIGNATURE_BYTES..=MAX_DER_SIGNATURE_BYTES).contains(&bytes.len()) {
        return Err(PcEventError::InvalidSignature);
    }
    let result = Signature::from_der(bytes).map_err(|_| PcEventError::InvalidSignature)?;
    if result.to_der().as_bytes() != bytes {
        return Err(PcEventError::InvalidSignature);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PcEventError {
    #[error("PC event has an invalid length")]
    InvalidLength,
    #[error("PC event has an invalid encoding")]
    InvalidEncoding,
    #[error("PC event has invalid fields")]
    InvalidFields,
    #[error("PC event uses an unsupported version")]
    UnsupportedVersion,
    #[error("PC event uses an unsupported kind")]
    UnsupportedKind,
    #[error("PC event contains invalid UTF-8 text")]
    InvalidText,
    #[error("PC event content does not match the signed binding")]
    ContentMismatch,
    #[error("PC event lifetime is invalid")]
    InvalidLifetime,
    #[error("PC public key is invalid")]
    InvalidKey,
    #[error("PC event signature is invalid")]
    InvalidSignature,
    #[error("PC event does not match the enrolled PC")]
    WrongPc,
}
