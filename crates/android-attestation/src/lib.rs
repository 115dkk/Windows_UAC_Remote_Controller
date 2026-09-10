// SPDX-License-Identifier: GPL-2.0-or-later
//! PC-side verification of bounded, untrusted Android public-key evidence.
//!
//! Key properties are not owner enrollment intent, key possession, proof of a
//! currently uncompromised phone, or a registry commit. Verification is pure;
//! the separate status fetch accepts no caller-selected URI, path or trust store.
//! No private key, signer, native operation or renderer entry is exposed here.
#![forbid(unsafe_code)]

mod certificate;
mod chain;
mod description;
mod fetch;
mod policy;
mod revocation;
mod roots;

pub use fetch::fetch_google_status;
pub use policy::{PlatformMinimums, TrustedStatusSnapshot, VerificationPolicy};
use secure_channel::TlsPublicKey;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;

/// Expected values supplied by the protected ceremony owner, not claims copied
/// from candidate certificates. Parsing cannot prove ceremony freshness/intent.
#[derive(Clone)]
pub struct ExpectedKeyBundle {
    challenge: [u8; 32],
    keys: [TlsPublicKey; 3],
}
impl fmt::Debug for ExpectedKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedKeyBundle([redacted])")
    }
}
impl ExpectedKeyBundle {
    pub fn from_trusted_host(
        challenge: [u8; 32],
        approval: TlsPublicKey,
        denial: TlsPublicKey,
        transport: TlsPublicKey,
    ) -> Result<Self, VerificationError> {
        if challenge.iter().all(|value| *value == 0) {
            return Err(VerificationError::ChallengeMismatch);
        }
        if approval == denial || approval == transport || denial == transport {
            return Err(VerificationError::KeyReuse);
        }
        Ok(Self {
            challenge,
            keys: [approval, denial, transport],
        })
    }
}

/// Leaf-first, three fixed-role certificate lists. Bounds precede DER decoding.
pub struct CandidateEvidence<'a> {
    chains: [&'a [&'a [u8]]; 3],
}
impl fmt::Debug for CandidateEvidence<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CandidateEvidence([redacted])")
    }
}
impl<'a> CandidateEvidence<'a> {
    pub fn new(
        approval: &'a [&'a [u8]],
        denial: &'a [&'a [u8]],
        transport: &'a [&'a [u8]],
    ) -> Result<Self, VerificationError> {
        let chains = [approval, denial, transport];
        for chain in chains {
            if chain.is_empty()
                || chain.len() > 8
                || chain
                    .iter()
                    .any(|cert| cert.is_empty() || cert.len() > 8192)
                || chain.iter().map(|cert| cert.len()).sum::<usize>() > 32768
            {
                return Err(VerificationError::Bounds);
            }
        }
        Ok(Self { chains })
    }
}

/// Non-Clone, privately constructed key-property proof. This is NOT permission
/// to enroll, key-possession proof, same-physical-phone proof or approval intent.
/// The service must separately validate the exact live QR/UAC ceremony/bundle.
///
/// Evidence cannot be copied and consumed for multiple registry mutations:
/// ```compile_fail
/// use android_attestation::VerifiedKeyBundle;
/// fn no_duplicate(proof: &VerifiedKeyBundle) -> VerifiedKeyBundle {
///     (*proof).clone()
/// }
/// ```
pub struct VerifiedKeyBundle {
    keys: [TlsPublicKey; 3],
    challenge: [u8; 32],
    policy: [u8; 32],
    checked_utc: Duration,
    utc_deadline: Option<Duration>,
    deadline: Instant,
    status_identity: Arc<()>,
}
impl fmt::Debug for VerifiedKeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedKeyBundle([redacted], not_enrollment_authority)")
    }
}
impl VerifiedKeyBundle {
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// Consume immediately at the protected registry's logical mutation point.
    /// The caller still owns the independent ceremony deadline/intent check.
    pub fn into_current_keys(
        self,
        current_policy: &VerificationPolicy,
        current_status: &TrustedStatusSnapshot,
    ) -> Result<[TlsPublicKey; 3], VerificationError> {
        let now = policy::Clock::capture()?;
        current_status.require_current(&now)?;
        if now.monotonic >= self.deadline
            || now.utc < self.checked_utc
            || self
                .utc_deadline
                .is_some_and(|deadline| now.utc >= deadline)
            || !Arc::ptr_eq(&self.status_identity, &current_status.identity)
        {
            return Err(VerificationError::StaleStatus);
        }
        if current_policy.fingerprint() != self.policy {
            return Err(VerificationError::InvalidPolicy);
        }
        Ok(self.keys)
    }
}

/// Verify original certificate signatures, exact Android profile/key binding,
/// three role policies, release identity and a current trusted rejection list.
/// Fixed release roots only; no caller-selected CA/root-store or network URL.
pub fn verify_key_bundle(
    evidence: &CandidateEvidence<'_>,
    expected: &ExpectedKeyBundle,
    policy: &VerificationPolicy,
    status: &TrustedStatusSnapshot,
) -> Result<VerifiedKeyBundle, VerificationError> {
    verify_with_anchors(evidence, expected, policy, status, roots::google()?)
}

fn verify_with_anchors(
    evidence: &CandidateEvidence<'_>,
    expected: &ExpectedKeyBundle,
    policy: &VerificationPolicy,
    status: &TrustedStatusSnapshot,
    anchors: &[roots::Anchor],
) -> Result<VerifiedKeyBundle, VerificationError> {
    let now = policy::Clock::capture()?;
    status.require_current(&now)?;
    let mut deadline = status.deadline.min(
        now.monotonic
            .checked_add(Duration::from_secs(30))
            .ok_or(VerificationError::StaleStatus)?,
    );
    let mut utc_deadline: Option<Duration> = None;
    let roles = [
        description::KeyRole::Approval,
        description::KeyRole::Denial,
        description::KeyRole::Transport,
    ];
    let description_policy = policy.description(&expected.challenge);
    for ((chain, key), role) in evidence.chains.into_iter().zip(&expected.keys).zip(roles) {
        let verified = chain::verify_with_anchors(chain, key, now.utc, &status.entries, anchors)?;
        let metadata =
            description::verify_description(&verified.description, &description_policy, role)?;
        if let chain::ChainProfile::Rkp5(level) = verified.profile
            && (metadata.attestation_security_level != level
                || metadata.keymint_security_level != level)
        {
            return Err(VerificationError::PlatformPolicy);
        }
        if let Some(expiry) = verified.valid_until {
            let remaining = expiry
                .checked_sub(now.utc)
                .ok_or(VerificationError::Chain)?;
            deadline = deadline.min(
                now.monotonic
                    .checked_add(remaining)
                    .ok_or(VerificationError::Chain)?,
            );
            utc_deadline = Some(utc_deadline.map_or(expiry, |old| old.min(expiry)));
        }
    }
    let after = policy::Clock::capture()?;
    status.require_current(&after)?;
    if after.monotonic >= deadline
        || after.utc < now.utc
        || utc_deadline.is_some_and(|end| after.utc >= end)
    {
        return Err(VerificationError::StaleStatus);
    }
    Ok(VerifiedKeyBundle {
        keys: expected.keys.clone(),
        challenge: expected.challenge,
        policy: policy.fingerprint(),
        checked_utc: after.utc,
        utc_deadline,
        deadline,
        status_identity: Arc::clone(&status.identity),
    })
}

/// Fixed categories only: never retain certificate data or parser/provider text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationError {
    #[error("attestation evidence exceeds its bounds")]
    Bounds,
    #[error("attestation encoding is invalid")]
    Der,
    #[error("attestation profile is unsupported")]
    UnsupportedProfile,
    #[error("attestation challenge does not match")]
    ChallengeMismatch,
    #[error("attested key policy does not match")]
    KeyPolicy,
    #[error("attested application identity does not match")]
    AppIdentity,
    #[error("attested platform policy does not match")]
    PlatformPolicy,
    #[error("trusted verification policy is unavailable or invalid")]
    InvalidPolicy,
    #[error("attestation root is not trusted")]
    UntrustedRoot,
    #[error("attestation certificate path is invalid")]
    Chain,
    #[error("attestation certificate signature did not verify")]
    Signature,
    #[error("attestation certificate is revoked or suspended")]
    Revoked,
    #[error("trusted revocation status is unavailable or stale")]
    StaleStatus,
    #[error("the fixed certificate-status source is unavailable")]
    StatusUnavailable,
    #[error("attested public key does not match")]
    KeyMismatch,
    #[error("attestation key roles must be distinct")]
    KeyReuse,
}

#[cfg(test)]
mod test_fixture;

#[cfg(test)]
mod tests;
