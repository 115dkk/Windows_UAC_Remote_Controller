// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit Android factory/RKP profiles, not generic web-PKI validation.

use crate::{
    VerificationError as Error,
    certificate::{self, Certificate},
    description::HardwareLevel,
    revocation::RevocationList,
    roots::{Anchor, RootKind},
};
use der::{
    Decode, Tag, Tagged,
    asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef},
};
use secure_channel::TlsPublicKey;
use std::{fmt, time::Duration};
use x509_cert::{
    ext::pkix::{BasicConstraints, KeyUsage},
    name::Name,
};

const CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const SERIAL_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChainProfile {
    Factory4,
    Rkp5(HardwareLevel),
}

pub(crate) struct VerifiedChain {
    pub(crate) description: Vec<u8>,
    pub(crate) profile: ChainProfile,
    pub(crate) valid_until: Option<Duration>,
}

impl fmt::Debug for VerifiedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedChain([redacted])")
    }
}

pub(crate) fn verify_with_anchors(
    input: &[&[u8]],
    expected: &TlsPublicKey,
    now: Duration,
    revoked: &RevocationList,
    anchors: &[Anchor],
) -> Result<VerifiedChain, Error> {
    if input.is_empty()
        || input.len() > 8
        || input
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > 8192)
        || input.iter().map(|bytes| bytes.len()).sum::<usize>() > 32768
    {
        return Err(Error::Bounds);
    }
    let mut certificates = Vec::with_capacity(input.len());
    for bytes in input {
        if certificates
            .iter()
            .any(|cert: &Certificate<'_>| cert.encoded == *bytes)
        {
            return Err(Error::Chain);
        }
        certificates.push(Certificate::parse(bytes)?);
    }
    // Work root-first internally; callers preserve Keystore's leaf-first order.
    certificates.reverse();
    let root = certificates.first().ok_or(Error::Chain)?;
    let anchor = anchors
        .iter()
        .find(|anchor| root.spki() == anchor.spki)
        .ok_or(Error::UntrustedRoot)?;
    let configured = Certificate::parse(&anchor.der)?;
    root.verify_issued_by(&configured)?;
    if root.parsed.tbs_certificate().subject() != configured.parsed.tbs_certificate().subject() {
        return Err(Error::UntrustedRoot);
    }
    for pair in certificates.windows(2) {
        pair[1].verify_issued_by(&pair[0])?;
    }
    for cert in &certificates {
        if revoked.contains_serial(cert.serial())? {
            return Err(Error::Revoked);
        }
    }
    let profile = classify(&certificates, anchor.kind)?;
    let last = certificates.len() - 1;
    for (index, cert) in certificates.iter().enumerate() {
        if cert.extension(certificate::KEY_DESCRIPTION).is_some() != (index == last) {
            return Err(Error::Chain);
        }
        if cert.extension(certificate::PROVISIONING).is_some()
            && (!matches!(profile, ChainProfile::Rkp5(_)) || index != last - 1)
        {
            return Err(Error::Chain);
        }
    }
    let leaf = &certificates[last];
    if leaf.spki() != expected.as_spki_der() {
        return Err(Error::KeyMismatch);
    }
    let mut expiry = None;
    // Configured anchor policy supersedes old/reissued root certificate expiry.
    for (index, cert) in certificates.iter().enumerate().skip(1) {
        constraints(cert, index, last, profile, &certificates)?;
        let validity = cert.parsed.tbs_certificate().validity();
        let before = validity.not_before.to_unix_duration();
        let after = validity.not_after.to_unix_duration();
        if after < before {
            return Err(Error::Chain);
        }
        // Direct app-key dates are device selected, never freshness evidence.
        if index == last {
            continue;
        }
        if now < before {
            return Err(Error::Chain);
        }
        if matches!(profile, ChainProfile::Rkp5(_)) {
            if now >= after {
                return Err(Error::Chain);
            }
            expiry = Some(expiry.map_or(after, |old: Duration| old.min(after)));
        }
    }
    // Apply the trusted root's CA/path-length policy, not a peer's replacement.
    constraints(&configured, 0, last, profile, &certificates)?;
    Ok(VerifiedChain {
        description: leaf
            .extension(certificate::KEY_DESCRIPTION)
            .ok_or(Error::Chain)?
            .to_vec(),
        profile,
        valid_until: expiry,
    })
}

fn classify(certificates: &[Certificate<'_>], root: RootKind) -> Result<ChainProfile, Error> {
    if certificates.len() == 4 && root == RootKind::FactoryRsa {
        let subject = certificates[1].parsed.tbs_certificate().subject();
        if attribute(subject, SERIAL_NAME)?.is_some()
            && attribute(subject, CN)? != Some("Droid CA2")
        {
            return Ok(ChainProfile::Factory4);
        }
    }
    if certificates.len() == 5 {
        for (index, name) in [(1, "Droid CA2"), (2, "Droid CA3")] {
            let subject = certificates[index].parsed.tbs_certificate().subject();
            if attribute(subject, CN)? != Some(name)
                || attribute(subject, ORGANIZATION)? != Some("Google LLC")
                || attribute(subject, SERIAL_NAME)?.is_some()
            {
                return Err(Error::UnsupportedProfile);
            }
        }
        let attester = certificates[3].parsed.tbs_certificate().subject();
        if attribute(attester, CN)?.is_none() {
            return Err(Error::UnsupportedProfile);
        }
        return match attribute(attester, ORGANIZATION)? {
            Some("TEE") => Ok(ChainProfile::Rkp5(HardwareLevel::Tee)),
            Some("StrongBox") => Ok(ChainProfile::Rkp5(HardwareLevel::StrongBox)),
            _ => Err(Error::UnsupportedProfile),
        };
    }
    Err(Error::UnsupportedProfile)
}

fn attribute(name: &Name, wanted: ObjectIdentifier) -> Result<Option<&str>, Error> {
    if name.len() > 32 {
        return Err(Error::Bounds);
    }
    let mut found = None;
    for rdn in name.iter_rdn() {
        if rdn.len() > 8 {
            return Err(Error::Bounds);
        }
        for attribute in rdn.iter().filter(|attribute| attribute.oid == wanted) {
            if found.is_some() {
                return Err(Error::UnsupportedProfile);
            }
            match attribute.value.tag() {
                Tag::PrintableString => {
                    attribute
                        .value
                        .decode_as::<PrintableStringRef<'_>>()
                        .map_err(|_| Error::Der)?;
                }
                Tag::Utf8String => {
                    attribute
                        .value
                        .decode_as::<Utf8StringRef<'_>>()
                        .map_err(|_| Error::Der)?;
                }
                _ => return Err(Error::UnsupportedProfile),
            }
            let text = std::str::from_utf8(attribute.value.value()).map_err(|_| Error::Der)?;
            if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
                return Err(Error::UnsupportedProfile);
            }
            found = Some(text);
        }
    }
    Ok(found)
}

fn constraints(
    cert: &Certificate<'_>,
    index: usize,
    last: usize,
    profile: ChainProfile,
    path: &[Certificate<'_>],
) -> Result<(), Error> {
    let basic = cert
        .extension(certificate::BASIC_CONSTRAINTS)
        .map(BasicConstraints::from_der)
        .transpose()
        .map_err(|_| Error::Der)?;
    let usage = cert
        .extension(certificate::KEY_USAGE)
        .map(KeyUsage::from_der)
        .transpose()
        .map_err(|_| Error::Der)?;
    if index == last {
        if basic
            .as_ref()
            .is_some_and(|basic| basic.ca || basic.path_len_constraint.is_some())
            || usage
                .as_ref()
                .is_some_and(|usage| !usage.digital_signature() || usage.key_cert_sign())
        {
            return Err(Error::KeyPolicy);
        }
        return Ok(());
    }
    let basic = basic.ok_or(Error::UnsupportedProfile)?;
    let legacy_attester = profile == ChainProfile::Factory4 && index == last - 1;
    if !basic.ca {
        if !legacy_attester
            || basic.path_len_constraint.is_some()
            || !usage
                .as_ref()
                .is_some_and(|usage| usage.digital_signature() && usage.0.bits() == 1)
        {
            return Err(Error::UnsupportedProfile);
        }
        return Ok(());
    }
    if usage.as_ref().is_some_and(|usage| !usage.key_cert_sign()) {
        return Err(Error::UnsupportedProfile);
    }
    if let Some(limit) = basic.path_len_constraint {
        let mut below = 0u8;
        for issuer in &path[index + 1..last] {
            let child = issuer
                .extension(certificate::BASIC_CONSTRAINTS)
                .map(BasicConstraints::from_der)
                .transpose()
                .map_err(|_| Error::Der)?;
            if child.is_some_and(|value| value.ca) {
                below += 1;
            }
        }
        if below > limit {
            return Err(Error::Chain);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
