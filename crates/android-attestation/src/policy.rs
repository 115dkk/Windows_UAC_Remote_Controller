// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit trusted-owner configuration; no default/debug/peer-selected trust.

use crate::{
    VerificationError as Error,
    description::{self, DescriptionPolicy},
    revocation::RevocationList,
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformMinimums {
    pub os_version: u32,
    pub os_patch: u32,
    pub vendor_patch: Option<u32>,
    pub boot_patch: Option<u32>,
}

#[derive(Clone)]
pub struct VerificationPolicy {
    signers: Vec<[u8; 32]>,
    minimum_version: u64,
    minimums: PlatformMinimums,
    fingerprint: [u8; 32],
}

impl fmt::Debug for VerificationPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerificationPolicy([redacted])")
    }
}

impl VerificationPolicy {
    /// The protected release/owner supplies these values. A candidate, relay,
    /// renderer or debug certificate is NEVER their source. This validates the
    /// configuration's shape, not its provenance; there is deliberately no default.
    pub fn from_trusted_host(
        signer_certificate_sha256: Vec<[u8; 32]>,
        minimum_app_version: u64,
        minimums: PlatformMinimums,
    ) -> Result<Self, Error> {
        if minimum_app_version == 0
            || signer_certificate_sha256
                .iter()
                .any(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(Error::InvalidPolicy);
        }
        let mut policy = Self {
            signers: signer_certificate_sha256,
            minimum_version: minimum_app_version,
            minimums,
            fingerprint: [0; 32],
        };
        // Configuration validation only: no certificate is verified and this
        // sentinel is never used as an actual attestation challenge.
        description::validate_policy(&policy.description(&[1; 32]))?;
        policy.signers.sort();
        let mut digest = Sha256::new();
        digest.update(b"Windows-UAC-Remote-Controller/attestation-policy/v1\0");
        digest.update((policy.signers.len() as u32).to_le_bytes());
        for signer in &policy.signers {
            digest.update(signer);
        }
        digest.update(minimum_app_version.to_le_bytes());
        digest.update(minimums.os_version.to_le_bytes());
        digest.update(minimums.os_patch.to_le_bytes());
        for floor in [minimums.vendor_patch, minimums.boot_patch] {
            digest.update([u8::from(floor.is_some())]);
            digest.update(floor.unwrap_or(0).to_le_bytes());
        }
        policy.fingerprint = digest.finalize().into();
        Ok(policy)
    }

    pub(crate) fn description<'a>(&'a self, challenge: &'a [u8; 32]) -> DescriptionPolicy<'a> {
        DescriptionPolicy {
            challenge,
            signer_digests: &self.signers,
            min_app_version: self.minimum_version,
            min_os_version: self.minimums.os_version,
            min_os_patch: self.minimums.os_patch,
            min_vendor_patch: self.minimums.vendor_patch,
            min_boot_patch: self.minimums.boot_patch,
        }
    }

    pub(crate) const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// Capture immediately BEFORE the trusted owner's fixed-origin HTTPS request.
/// This clock observation does not authenticate any connection or response.
pub(crate) struct StatusFetchStarted {
    pub(crate) clock: Clock,
}
impl fmt::Debug for StatusFetchStarted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StatusFetchStarted([redacted])")
    }
}
impl StatusFetchStarted {
    pub(crate) fn capture() -> Result<Self, Error> {
        Ok(Self {
            clock: Clock::capture()?,
        })
    }
}

/// Process-local snapshot produced only by the fixed authenticated status fetch.
/// Not serializable; no public parser, cache restoration or empty-on-error path.
///
/// Unauthenticated caller data cannot construct one:
/// ```compile_fail
/// use android_attestation::TrustedStatusSnapshot;
/// fn no_empty_snapshot() -> TrustedStatusSnapshot {
///     TrustedStatusSnapshot {}
/// }
/// ```
pub struct TrustedStatusSnapshot {
    pub(crate) entries: RevocationList,
    pub(crate) received_clock: Clock,
    pub(crate) deadline: Instant,
    pub(crate) identity: Arc<()>,
}
impl fmt::Debug for TrustedStatusSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustedStatusSnapshot([redacted])")
    }
}
impl TrustedStatusSnapshot {
    /// The crate's fixed fetch must have authenticated the Google origin and
    /// computed remaining HTTP freshness (including Age/Cache-Control). Neither
    /// a forwarding process's boolean nor an old body under a new clock suffices.
    /// The initial request time conservatively includes network/parse latency.
    /// No network is performed in this private parsing/freshness step.
    pub(crate) fn from_authenticated_google_response(
        started: StatusFetchStarted,
        body: &[u8],
        remaining_http_freshness: Duration,
    ) -> Result<Self, Error> {
        if remaining_http_freshness.is_zero() {
            return Err(Error::StaleStatus);
        }
        let deadline = started
            .clock
            .monotonic
            .checked_add(remaining_http_freshness.min(Duration::from_secs(86_400)))
            .ok_or(Error::StaleStatus)?;
        let entries = RevocationList::parse(body)?;
        let value = Self {
            entries,
            received_clock: started.clock,
            deadline,
            identity: Arc::new(()),
        };
        value.require_current(&Clock::capture()?)?;
        Ok(value)
    }

    pub(crate) fn require_current(&self, now: &Clock) -> Result<(), Error> {
        if now.monotonic < self.received_clock.monotonic
            || now.monotonic >= self.deadline
            || now.utc < self.received_clock.utc
        {
            Err(Error::StaleStatus)
        } else {
            Ok(())
        }
    }
}

pub(crate) struct Clock {
    pub(crate) utc: Duration,
    pub(crate) monotonic: Instant,
}
impl Clock {
    pub(crate) fn capture() -> Result<Self, Error> {
        let monotonic = Instant::now();
        let utc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::InvalidPolicy)?;
        Ok(Self { utc, monotonic })
    }
}

#[cfg(test)]
mod tests;
