// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact request bindings and authenticated remote decisions, not Windows approval.
//!
//! This crate contains no private signing key, enrollment authority, transport,
//! process execution, input injection, or OS authentication interface. A valid
//! signature proves possession of an enrolled key, not that Android performed
//! authentication or that Windows displayed or applied anything. The privileged
//! host must verify hardware-key attestation and enforce the intended approval
//! key's per-use OS-authentication policy before enrollment.
//!
//! P-256/SHA-256 is fixed, not negotiated. Android's ASN.1 DER ECDSA signatures
//! are accepted only when the DER encoding is strict and round-trips exactly.
//! Both mathematically valid S representatives are accepted for Android interop;
//! signature bytes must NEVER serve as a replay identity. The complete request
//! binding is that identity. Approval and denial have separate signing domains
//! and must additionally use separate enrolled keys in the service.

#![forbid(unsafe_code)]

use std::fmt;

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
/// Conservative budget for one Windows-origin text field, including headroom
/// for the terminator in a 32,767 UTF-16-code-unit Windows text limit. Every
/// well-formed scalar needs at most three UTF-8 bytes per UTF-16 code unit;
/// supplementary characters need four bytes for two units, not four per unit.
/// This is a transport/content budget, not proof of any particular OS source.
pub const MAX_WINDOWS_TEXT_CODE_UNITS: usize = 32_768;
pub const MAX_PROGRAM_NAME_BYTES: usize = MAX_WINDOWS_TEXT_CODE_UNITS * 3;
pub const MAX_PATH_BYTES: usize = MAX_WINDOWS_TEXT_CODE_UNITS * 3;
pub const MAX_DETAILS_BYTES: usize = MAX_WINDOWS_TEXT_CODE_UNITS * 3;
/// At most 288 KiB of UTF-8 payload in one content value, excluding allocation
/// headers. Callers must also bound concurrent requests and transport frames.
pub const MAX_REQUEST_CONTENT_BYTES: usize =
    MAX_PROGRAM_NAME_BYTES + MAX_PATH_BYTES + MAX_DETAILS_BYTES;
pub const MAX_DER_SIGNATURE_BYTES: usize = 72;
pub const MIN_DER_SIGNATURE_BYTES: usize = 8;

const CONTENT_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/request-content/v1\0";
const APPROVAL_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/approve/v1\0";
const DENIAL_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/deny/v1\0";
const WIRE_MAGIC: &[u8; 8] = b"WUACDEC\0";
const BINDING_BYTES: usize = 32 + 32 + 4 + 8 + 32 + 32 + 32 + 8;
const UNSIGNED_BYTES: usize = 2 + 16 + 1 + BINDING_BYTES;
const WIRE_PREFIX_BYTES: usize = WIRE_MAGIC.len() + UNSIGNED_BYTES + 2;
pub const MAX_WIRE_DECISION_BYTES: usize = WIRE_PREFIX_BYTES + MAX_DER_SIGNATURE_BYTES;

/// Identifiers are fixed-width, nonzero values. Debug never reveals their bytes.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("identifier must not be all zeroes")]
pub struct InvalidIdentifier;

macro_rules! identifier {
    ($name:ident, $size:expr, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn from_bytes(bytes: [u8; $size]) -> Result<Self, InvalidIdentifier> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(InvalidIdentifier);
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
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

identifier!(
    PcIdentity,
    32,
    "Stable enrolled PC identity, provisioned by the privileged host."
);
identifier!(
    BootEpoch,
    32,
    "Fresh random service-start epoch; never reused across restarts."
);
identifier!(
    RequestId,
    32,
    "Service-generated random request identifier; not a signature hash."
);
identifier!(
    ChallengeNonce,
    32,
    "Independent service-generated random per-request challenge."
);
identifier!(
    DeviceId,
    16,
    "Enrolled device identity; not an untrusted display name."
);

/// Windows session number together with its logon LUID; session numbers alone
/// can be reused. The OS adapter, not a phone or renderer, supplies both values.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsSession {
    session_id: u32,
    logon_id: u64,
}

impl OsSession {
    pub const fn new(session_id: u32, logon_id: u64) -> Self {
        Self {
            session_id,
            logon_id,
        }
    }

    pub const fn session_id(self) -> u32 {
        self.session_id
    }

    pub const fn logon_id(self) -> u64 {
        self.logon_id
    }
}

impl fmt::Debug for OsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OsSession([redacted])")
    }
}

/// Exact UTF-8 data for presentation and binding; NEVER an executable command.
///
/// Fields are separately length-prefixed when hashed. No concatenation,
/// case-folding, path resolution, Unicode normalization, or shell parsing is
/// performed. The privileged OS adapter must capture these fields immutably
/// from its verified target and retain that target separately. Hashing these
/// strings does not authenticate their OS origin or establish target identity.
/// The name is generic: GUI applications and terminal shells both fit without
/// inventing a shell for a nonterminal request. This is not a complete Windows
/// metadata schema or a lossy UTF-16 conversion policy.
///
/// Details can contain sensitive command-line text needed for on-demand display.
/// Retain them only for that live request, transport them only confidentially to
/// the enrolled phone, and never serialize them into logs, telemetry or history.
/// Redacted Debug avoids accidental formatting, not heap/crash-dump disclosure.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestContent {
    program_name: String,
    path: String,
    details: String,
}

impl RequestContent {
    pub fn new(program_name: &str, path: &str, details: &str) -> Result<Self, ContentError> {
        validate_text(program_name, MAX_PROGRAM_NAME_BYTES, false)?;
        validate_text(path, MAX_PATH_BYTES, false)?;
        validate_text(details, MAX_DETAILS_BYTES, true)?;
        Ok(Self {
            program_name: program_name.to_owned(),
            path: path.to_owned(),
            details: details.to_owned(),
        })
    }

    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn details(&self) -> &str {
        &self.details
    }

    pub fn digest(&self) -> ContentDigest {
        let mut digest = Sha256::new();
        digest.update(CONTENT_DOMAIN);
        digest.update(PROTOCOL_VERSION.to_be_bytes());
        for (tag, value) in [
            (1_u8, self.program_name.as_bytes()),
            (2_u8, self.path.as_bytes()),
            (3_u8, self.details.as_bytes()),
        ] {
            digest.update([tag]);
            // All three fields were bounded to substantially less than u32::MAX.
            digest.update((value.len() as u32).to_be_bytes());
            digest.update(value);
        }
        ContentDigest(digest.finalize().into())
    }
}

impl fmt::Debug for RequestContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestContent([redacted])")
    }
}

fn validate_text(value: &str, maximum: usize, allow_empty: bool) -> Result<(), ContentError> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum {
        return Err(ContentError::InvalidLength);
    }
    if value.contains('\0') {
        return Err(ContentError::EmbeddedNul);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ContentError {
    #[error("request content field has an invalid byte length")]
    InvalidLength,
    #[error("request content must not contain NUL")]
    EmbeddedNul,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentDigest([redacted])")
    }
}

/// Opaque nanoseconds since this service epoch's trusted monotonic start.
/// Phones must echo/sign it, never interpret it as a wall-clock deadline.
/// Only the service's actual `Instant` deadline decides expiration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExpiryTick(u64);

impl ExpiryTick {
    pub fn from_nanos_since_epoch(value: u64) -> Result<Self, InvalidExpiry> {
        if value == 0 {
            return Err(InvalidExpiry);
        }
        Ok(Self(value))
    }

    pub const fn as_nanos_since_epoch(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("expiry tick must be positive")]
pub struct InvalidExpiry;

/// Immutable exact binding. Construction alone conveys no authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestBinding {
    pc: PcIdentity,
    epoch: BootEpoch,
    session: OsSession,
    request_id: RequestId,
    nonce: ChallengeNonce,
    content_digest: ContentDigest,
    expiry: ExpiryTick,
}

impl RequestBinding {
    pub const fn new(
        pc: PcIdentity,
        epoch: BootEpoch,
        session: OsSession,
        request_id: RequestId,
        nonce: ChallengeNonce,
        content_digest: ContentDigest,
        expiry: ExpiryTick,
    ) -> Self {
        Self {
            pc,
            epoch,
            session,
            request_id,
            nonce,
            content_digest,
            expiry,
        }
    }

    pub const fn pc(self) -> PcIdentity {
        self.pc
    }
    pub const fn epoch(self) -> BootEpoch {
        self.epoch
    }
    pub const fn session(self) -> OsSession {
        self.session
    }
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }
    pub const fn nonce(self) -> ChallengeNonce {
        self.nonce
    }
    pub const fn content_digest(self) -> ContentDigest {
        self.content_digest
    }
    pub const fn expiry(self) -> ExpiryTick {
        self.expiry
    }

    fn append_bytes(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.pc.as_bytes());
        bytes.extend_from_slice(self.epoch.as_bytes());
        bytes.extend_from_slice(&self.session.session_id.to_be_bytes());
        bytes.extend_from_slice(&self.session.logon_id.to_be_bytes());
        bytes.extend_from_slice(self.request_id.as_bytes());
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes.extend_from_slice(self.content_digest.as_bytes());
        bytes.extend_from_slice(&self.expiry.0.to_be_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecisionPurpose {
    Approve,
    Deny,
}

impl DecisionPurpose {
    const fn discriminant(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::Deny => 2,
        }
    }

    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Approve => APPROVAL_DOMAIN,
            Self::Deny => DENIAL_DOMAIN,
        }
    }
}

/// Public statement to be signed by the correct purpose-specific Android key.
/// This is not a signing API and cannot produce an authorized decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsignedDecision {
    binding: RequestBinding,
    device_id: DeviceId,
    purpose: DecisionPurpose,
}

impl UnsignedDecision {
    pub const fn new(
        binding: RequestBinding,
        device_id: DeviceId,
        purpose: DecisionPurpose,
    ) -> Self {
        Self {
            binding,
            device_id,
            purpose,
        }
    }

    pub const fn binding(self) -> RequestBinding {
        self.binding
    }
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }
    pub const fn purpose(self) -> DecisionPurpose {
        self.purpose
    }

    /// Canonical input to Android `SHA256withECDSA`: domain, version (u16 BE),
    /// device (16), purpose (u8), PC (32), epoch (32), session (u32 BE), logon
    /// LUID (u64 BE), request (32), nonce (32), content hash (32), expiry (u64 BE).
    /// Do not prehash again before passing this to `SHA256withECDSA`.
    pub fn signing_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.purpose.domain().len() + UNSIGNED_BYTES);
        bytes.extend_from_slice(self.purpose.domain());
        self.append_bytes(&mut bytes);
        bytes
    }

    fn append_bytes(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.push(self.purpose.discriminant());
        self.binding.append_bytes(bytes);
    }
}

/// Validated SEC1 P-256 key, stored in unique compressed form for key equality.
/// Hardware provenance and authentication policy must be verified by the host;
/// this constructor only validates the curve point and SEC1 encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct DecisionPublicKey {
    compressed_sec1: [u8; 33],
}

impl DecisionPublicKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        if !matches!(
            (bytes.len(), bytes.first()),
            (33, Some(2 | 3)) | (65, Some(4))
        ) {
            return Err(SignatureError::MalformedPublicKey);
        }
        let key =
            VerifyingKey::from_sec1_bytes(bytes).map_err(|_| SignatureError::MalformedPublicKey)?;
        let point = key.to_encoded_point(true);
        let compressed_sec1 = point
            .as_bytes()
            .try_into()
            .map_err(|_| SignatureError::MalformedPublicKey)?;
        Ok(Self { compressed_sec1 })
    }

    pub const fn compressed_sec1_bytes(&self) -> &[u8; 33] {
        &self.compressed_sec1
    }
}

impl fmt::Debug for DecisionPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionPublicKey([redacted])")
    }
}

#[derive(Clone)]
pub struct SignedDecision {
    statement: UnsignedDecision,
    signature: Signature,
}

impl SignedDecision {
    pub fn from_der(statement: UnsignedDecision, der: &[u8]) -> Result<Self, SignatureError> {
        if !(MIN_DER_SIGNATURE_BYTES..=MAX_DER_SIGNATURE_BYTES).contains(&der.len()) {
            return Err(SignatureError::MalformedSignature);
        }
        let signature = Signature::from_der(der).map_err(|_| SignatureError::MalformedSignature)?;
        if signature.to_der().as_bytes() != der {
            return Err(SignatureError::MalformedSignature);
        }
        Ok(Self {
            statement,
            signature,
        })
    }

    pub const fn statement(&self) -> UnsignedDecision {
        self.statement
    }

    pub fn verify(&self, key: &DecisionPublicKey) -> Result<(), SignatureError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(key.compressed_sec1_bytes())
            .map_err(|_| SignatureError::MalformedPublicKey)?;
        // Normalize S for verifier compatibility, not for replay detection.
        // The input DER itself was already strictly validated in from_der.
        let signature = self.signature.normalize_s().unwrap_or(self.signature);
        verifying_key
            .verify(&self.statement.signing_bytes(), &signature)
            .map_err(|_| SignatureError::VerificationFailed)
    }

    /// Fixed fields followed by a u16 BE DER length and that exact DER value.
    /// This bounded encoding carries no request content or secret credential.
    pub fn to_wire(&self) -> Vec<u8> {
        let der = self.signature.to_der();
        let mut bytes = Vec::with_capacity(WIRE_PREFIX_BYTES + der.as_bytes().len());
        bytes.extend_from_slice(WIRE_MAGIC);
        self.statement.append_bytes(&mut bytes);
        bytes.extend_from_slice(&(der.as_bytes().len() as u16).to_be_bytes());
        bytes.extend_from_slice(der.as_bytes());
        bytes
    }

    /// Strict, size-bounded parser. No ignored extensions, trailing bytes,
    /// unknown versions, alternate algorithms, or attacker-sized allocations.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        if !(WIRE_PREFIX_BYTES + MIN_DER_SIGNATURE_BYTES..=MAX_WIRE_DECISION_BYTES)
            .contains(&bytes.len())
        {
            return Err(WireError::InvalidLength);
        }
        let mut reader = Reader { remaining: bytes };
        if &reader.take::<8>()? != WIRE_MAGIC {
            return Err(WireError::InvalidMagic);
        }
        if u16::from_be_bytes(reader.take()?) != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        let device_id =
            DeviceId::from_bytes(reader.take()?).map_err(|_| WireError::InvalidField)?;
        let purpose = match reader.take::<1>()?[0] {
            1 => DecisionPurpose::Approve,
            2 => DecisionPurpose::Deny,
            _ => return Err(WireError::InvalidPurpose),
        };
        let pc = PcIdentity::from_bytes(reader.take()?).map_err(|_| WireError::InvalidField)?;
        let epoch = BootEpoch::from_bytes(reader.take()?).map_err(|_| WireError::InvalidField)?;
        let session = OsSession::new(
            u32::from_be_bytes(reader.take()?),
            u64::from_be_bytes(reader.take()?),
        );
        let request_id =
            RequestId::from_bytes(reader.take()?).map_err(|_| WireError::InvalidField)?;
        let nonce =
            ChallengeNonce::from_bytes(reader.take()?).map_err(|_| WireError::InvalidField)?;
        let content_digest = ContentDigest::from_bytes(reader.take()?);
        let expiry = ExpiryTick::from_nanos_since_epoch(u64::from_be_bytes(reader.take()?))
            .map_err(|_| WireError::InvalidField)?;
        let signature_length = usize::from(u16::from_be_bytes(reader.take()?));
        if signature_length != reader.remaining.len() {
            return Err(WireError::InvalidLength);
        }
        let binding = RequestBinding::new(
            pc,
            epoch,
            session,
            request_id,
            nonce,
            content_digest,
            expiry,
        );
        Self::from_der(
            UnsignedDecision::new(binding, device_id, purpose),
            reader.remaining,
        )
        .map_err(|_| WireError::MalformedSignature)
    }
}

impl fmt::Debug for SignedDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedDecision")
            .field("statement", &self.statement)
            .field("signature", &"[redacted]")
            .finish()
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let head = self.remaining.get(..N).ok_or(WireError::InvalidLength)?;
        let result = head.try_into().map_err(|_| WireError::InvalidLength)?;
        self.remaining = &self.remaining[N..];
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("malformed P-256 SEC1 public key")]
    MalformedPublicKey,
    #[error("malformed strict-DER ECDSA signature")]
    MalformedSignature,
    #[error("decision signature verification failed")]
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("decision wire length is invalid")]
    InvalidLength,
    #[error("decision wire magic is invalid")]
    InvalidMagic,
    #[error("decision protocol version is unsupported")]
    UnsupportedVersion,
    #[error("decision purpose is invalid")]
    InvalidPurpose,
    #[error("decision binding field is invalid")]
    InvalidField,
    #[error("decision wire signature is malformed")]
    MalformedSignature,
}
