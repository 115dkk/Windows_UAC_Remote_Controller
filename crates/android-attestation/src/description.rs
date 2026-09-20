// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed Android KeyDescription policy, not certificate/path validation, native
//! authentication, co-residency of keys or permission to enroll a device.
#![forbid(unsafe_code)]

use crate::VerificationError as Error;
use der::{
    Decode, Reader, SliceReader, Tag, Tagged,
    asn1::{AnyRef, Null, OctetStringRef},
};
use std::fmt;

const MAX_DESCRIPTION_BYTES: usize = 8 * 1024;
const MAX_APP_ID_BYTES: usize = 1024;
const MAX_AUTHORIZATIONS: usize = 32;
const MAX_SIGNERS: usize = 16;
const PACKAGE: &[u8] = b"dev.dkk115.uacremote";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyRole {
    Approval,
    Denial,
    Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HardwareLevel {
    Tee,
    StrongBox,
}

pub(crate) struct DescriptionPolicy<'a> {
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) signer_digests: &'a [[u8; 32]],
    pub(crate) min_app_version: u64,
    pub(crate) min_os_version: u32,
    pub(crate) min_os_patch: u32,
    pub(crate) min_vendor_patch: Option<u32>,
    pub(crate) min_boot_patch: Option<u32>,
}
impl fmt::Debug for DescriptionPolicy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DescriptionPolicy([redacted])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct KeyDescription {
    pub(crate) attestation_version: u32,
    pub(crate) attestation_security_level: HardwareLevel,
    pub(crate) keymint_version: u32,
    pub(crate) keymint_security_level: HardwareLevel,
    pub(crate) os_version: u32,
    pub(crate) os_patch: u32,
    pub(crate) vendor_patch: Option<u32>,
    pub(crate) boot_patch: Option<u32>,
    pub(crate) app_version: u64,
}
impl fmt::Debug for KeyDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyDescription(metadata_only)")
    }
}

#[derive(Default)]
struct Authorizations<'a> {
    purpose: Option<u64>,
    algorithm: Option<u64>,
    size: Option<u64>,
    digest: Option<u64>,
    curve: Option<u64>,
    origin: Option<u64>,
    no_auth: bool,
    auth_type: Option<u64>,
    root: bool,
    os: Option<u32>,
    patch: Option<u32>,
    vendor: Option<u32>,
    boot: Option<u32>,
    app: Option<&'a [u8]>,
    module_hash: bool,
}

fn next<'a>(reader: &mut SliceReader<'a>) -> Result<AnyRef<'a>, Error> {
    AnyRef::decode(reader).map_err(|_| Error::Der)
}
fn nested<'a>(value: AnyRef<'a>, tag: Tag) -> Result<SliceReader<'a>, Error> {
    if value.tag() != tag {
        return Err(Error::Der);
    }
    SliceReader::new(value.value()).map_err(|_| Error::Der)
}
fn finish(reader: SliceReader<'_>) -> Result<(), Error> {
    reader.finish().map_err(|_| Error::Der)
}
fn integer(value: AnyRef<'_>) -> Result<u64, Error> {
    value.decode_as::<u64>().map_err(|_| Error::Der)
}
fn integer32(value: AnyRef<'_>) -> Result<u32, Error> {
    value.decode_as::<u32>().map_err(|_| Error::Der)
}
fn enumerated(value: AnyRef<'_>) -> Result<u32, Error> {
    if value.tag() != Tag::Enumerated {
        return Err(Error::Der);
    }
    // ENUMERATED and nonnegative INTEGER have the same canonical value octets.
    // The DER library checks sign/minimality/overflow; only the already-checked
    // universal tag is adapted, never a handwritten BER length/value parser.
    AnyRef::new(Tag::Integer, value.value())
        .map_err(|_| Error::Der)?
        .decode_as::<u32>()
        .map_err(|_| Error::Der)
}
fn octets<'a>(value: AnyRef<'a>) -> Result<&'a [u8], Error> {
    value
        .decode_as::<&OctetStringRef>()
        .map(|value| value.as_bytes())
        .map_err(|_| Error::Der)
}
fn null(value: AnyRef<'_>) -> Result<(), Error> {
    value
        .decode_as::<Null>()
        .map(|_| ())
        .map_err(|_| Error::Der)
}
fn singleton(value: AnyRef<'_>) -> Result<u64, Error> {
    let mut set = nested(value, Tag::Set)?;
    let only = integer(next(&mut set)?)?;
    if !set.is_finished() {
        return Err(Error::KeyPolicy);
    }
    finish(set)?;
    Ok(only)
}

fn valid_month(value: u32) -> bool {
    (1000..=9999).contains(&(value / 100)) && (1..=12).contains(&(value % 100))
}
fn valid_date(value: u32) -> bool {
    let year = value / 10000;
    let month = value / 100 % 100;
    let day = value % 100;
    if !(1000..=9999).contains(&year) || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&day)
}
pub(crate) fn validate_policy(policy: &DescriptionPolicy<'_>) -> Result<(), Error> {
    if policy.challenge.iter().all(|byte| *byte == 0)
        || policy.signer_digests.is_empty()
        || policy.signer_digests.len() > MAX_SIGNERS
        || policy.min_app_version > i64::MAX as u64
        || !(110000..=999999).contains(&policy.min_os_version)
        || !valid_month(policy.min_os_patch)
        || policy
            .min_vendor_patch
            .is_some_and(|value| !valid_date(value))
        || policy
            .min_boot_patch
            .is_some_and(|value| !valid_date(value))
    {
        return Err(Error::InvalidPolicy);
    }
    for (index, digest) in policy.signer_digests.iter().enumerate() {
        if policy.signer_digests[..index].contains(digest) {
            return Err(Error::InvalidPolicy);
        }
    }
    Ok(())
}
fn hardware(value: u32, version: u32) -> Result<HardwareLevel, Error> {
    match value {
        1 => Ok(HardwareLevel::Tee),
        2 if version >= 3 => Ok(HardwareLevel::StrongBox),
        _ => Err(Error::PlatformPolicy),
    }
}
fn versions(attestation: u32, keymint: u32) -> Result<(), Error> {
    // Published schemas plus Google's pinned Sony/sdk33 fixture's exact (3,41)
    // compatibility pair. v1 has no app-ID. Never guess unknown version layouts.
    if matches!(
        (attestation, keymint),
        (2, 3)
            | (3, 4)
            | (3, 41)
            | (4, 41)
            | (100, 100)
            | (200, 200)
            | (300, 300)
            | (400, 400)
            | (500, 500)
    ) {
        Ok(())
    } else {
        Err(Error::UnsupportedProfile)
    }
}

fn root_of_trust(value: AnyRef<'_>, version: u32) -> Result<(), Error> {
    let mut root = nested(value, Tag::Sequence)?;
    let boot_key = octets(next(&mut root)?)?;
    if boot_key.is_empty() || boot_key.len() > 128 {
        return Err(Error::PlatformPolicy);
    }
    let locked = next(&mut root)?
        .decode_as::<bool>()
        .map_err(|_| Error::Der)?;
    let state = enumerated(next(&mut root)?)?;
    if !locked || state != 0 {
        return Err(Error::PlatformPolicy);
    }
    if version >= 3 {
        let boot_hash = octets(next(&mut root)?)?;
        if boot_hash.is_empty() || boot_hash.len() > 128 {
            return Err(Error::PlatformPolicy);
        }
    }
    finish(root)
}

fn authorizations<'a>(
    value: AnyRef<'a>,
    hardware_list: bool,
    version: u32,
) -> Result<Authorizations<'a>, Error> {
    let mut list = nested(value, Tag::Sequence)?;
    let mut result = Authorizations::default();
    let mut previous = None;
    let mut count = 0;
    while !list.is_finished() {
        count += 1;
        if count > MAX_AUTHORIZATIONS {
            return Err(Error::Bounds);
        }
        let explicit = next(&mut list)?;
        let Tag::ContextSpecific {
            constructed: true,
            number,
        } = explicit.tag()
        else {
            return Err(Error::Der);
        };
        let tag = number.value();
        if previous.is_some_and(|old| old >= tag) {
            return Err(Error::Der);
        }
        previous = Some(tag);
        // Every explicit wrapper contains exactly ONE complete DER value.
        let inner = AnyRef::from_der(explicit.value()).map_err(|_| Error::Der)?;
        match tag {
            1 | 2 | 3 | 5 | 10 | 503 | 504 | 702 => {
                if !hardware_list {
                    return Err(Error::KeyPolicy);
                }
                match tag {
                    1 => result.purpose = Some(singleton(inner)?),
                    2 => result.algorithm = Some(integer(inner)?),
                    3 => result.size = Some(integer(inner)?),
                    5 => result.digest = Some(singleton(inner)?),
                    10 => result.curve = Some(integer(inner)?),
                    503 => {
                        null(inner)?;
                        result.no_auth = true;
                    }
                    504 => result.auth_type = Some(integer(inner)?),
                    702 => result.origin = Some(integer(inner)?),
                    _ => unreachable!(),
                }
            }
            704 | 705 | 706 | 718 | 719 => {
                if !hardware_list {
                    return Err(Error::PlatformPolicy);
                }
                if matches!(tag, 718 | 719) && version < 3 {
                    return Err(Error::UnsupportedProfile);
                }
                match tag {
                    704 => {
                        root_of_trust(inner, version)?;
                        result.root = true;
                    }
                    705 => result.os = Some(integer32(inner)?),
                    706 => result.patch = Some(integer32(inner)?),
                    718 => result.vendor = Some(integer32(inner)?),
                    719 => result.boot = Some(integer32(inner)?),
                    _ => unreachable!(),
                }
            }
            709 => {
                if hardware_list {
                    return Err(Error::AppIdentity);
                }
                let app = octets(inner)?;
                if app.is_empty() || app.len() > MAX_APP_ID_BYTES {
                    return Err(Error::Bounds);
                }
                result.app = Some(app);
            }
            701 => {
                if hardware_list {
                    return Err(Error::UnsupportedProfile);
                }
                // Informational software timestamp; never used for freshness.
                let _ = integer(inner)?;
            }
            303 if version >= 3 => {
                if !hardware_list {
                    return Err(Error::KeyPolicy);
                }
                null(inner)?;
            }
            703 if version == 2 => {
                if !hardware_list {
                    return Err(Error::KeyPolicy);
                }
                null(inner)?;
            }
            724 if version >= 400 => {
                // Published module-information SHA256 only. Enforcement list
                // does not confer authority; never retain or use this metadata.
                if octets(inner)?.len() != 32 {
                    return Err(Error::UnsupportedProfile);
                }
                result.module_hash = true;
            }
            505 => {
                let _ = integer32(inner)?;
                // Absence is required: explicitly zero is STILL timeout-based.
                return Err(Error::KeyPolicy);
            }
            506..=509 | 305 => {
                null(inner)?;
                return Err(Error::KeyPolicy);
            }
            4 | 6 | 7 | 8 | 11 | 200 | 203 | 302 | 400..=405 | 502 | 600 => {
                return Err(Error::KeyPolicy);
            }
            // This generator does not request ID/device-unique attestation.
            // Unknown or non-attested tags are not silently discarded.
            _ => return Err(Error::UnsupportedProfile),
        }
    }
    finish(list)?;
    Ok(result)
}

fn application_id(bytes: &[u8], policy: &DescriptionPolicy<'_>) -> Result<u64, Error> {
    if bytes.len() > MAX_APP_ID_BYTES {
        return Err(Error::Bounds);
    }
    let outer = AnyRef::from_der(bytes).map_err(|_| Error::Der)?;
    let mut sequence = nested(outer, Tag::Sequence)?;
    let mut packages = nested(next(&mut sequence)?, Tag::Set)?;
    // Exactly one package; no additional shared-UID member can acquire this key.
    let mut package = nested(next(&mut packages)?, Tag::Sequence)?;
    if octets(next(&mut package)?)? != PACKAGE {
        return Err(Error::AppIdentity);
    }
    let version = integer(next(&mut package)?)?;
    if version < policy.min_app_version || version > i64::MAX as u64 {
        return Err(Error::AppIdentity);
    }
    finish(package)?;
    if !packages.is_finished() {
        return Err(Error::AppIdentity);
    }
    finish(packages)?;
    let mut signers = nested(next(&mut sequence)?, Tag::Set)?;
    let mut previous: Option<&[u8]> = None;
    let mut count = 0;
    while !signers.is_finished() {
        count += 1;
        if count > MAX_SIGNERS {
            return Err(Error::Bounds);
        }
        let digest = octets(next(&mut signers)?)?;
        if digest.len() != 32 {
            return Err(Error::AppIdentity);
        }
        // All elements are OCTET STRING of identical length: this byte order
        // IS their full-DER SET OF order. Duplicate members are also refused.
        if previous.is_some_and(|old| old >= digest) {
            return Err(Error::Der);
        }
        previous = Some(digest);
        if !policy
            .signer_digests
            .iter()
            .any(|allowed| allowed.as_slice() == digest)
        {
            return Err(Error::AppIdentity);
        }
    }
    finish(signers)?;
    finish(sequence)?;
    if count != policy.signer_digests.len() {
        return Err(Error::AppIdentity);
    }
    Ok(version)
}

pub(crate) fn verify_description(
    bytes: &[u8],
    policy: &DescriptionPolicy<'_>,
    role: KeyRole,
) -> Result<KeyDescription, Error> {
    if bytes.is_empty() || bytes.len() > MAX_DESCRIPTION_BYTES {
        return Err(Error::Bounds);
    }
    validate_policy(policy)?;
    let outer = AnyRef::from_der(bytes).map_err(|_| Error::Der)?;
    let mut sequence = nested(outer, Tag::Sequence)?;
    let attestation_version = integer32(next(&mut sequence)?)?;
    let attestation_level = enumerated(next(&mut sequence)?)?;
    let keymint_version = integer32(next(&mut sequence)?)?;
    let keymint_level = enumerated(next(&mut sequence)?)?;
    versions(attestation_version, keymint_version)?;
    let attestation_security_level = hardware(attestation_level, attestation_version)?;
    let keymint_security_level = hardware(keymint_level, attestation_version)?;
    // Explicit project profile: the attester and attested key must use the same
    // hardware level. Do not silently admit mixed levels on factory paths.
    if attestation_security_level != keymint_security_level {
        return Err(Error::PlatformPolicy);
    }
    if octets(next(&mut sequence)?)? != policy.challenge {
        return Err(Error::ChallengeMismatch);
    }
    if !octets(next(&mut sequence)?)?.is_empty() {
        return Err(Error::UnsupportedProfile);
    }
    let software = authorizations(next(&mut sequence)?, false, attestation_version)?;
    let hardware = authorizations(next(&mut sequence)?, true, attestation_version)?;
    finish(sequence)?;
    if software.module_hash && hardware.module_hash {
        return Err(Error::UnsupportedProfile);
    }
    if hardware.purpose != Some(2)
        || hardware.algorithm != Some(3)
        || hardware.size != Some(256)
        || hardware.digest != Some(4)
        || hardware.curve != Some(1)
        || hardware.origin != Some(0)
    {
        return Err(Error::KeyPolicy);
    }
    match role {
        KeyRole::Approval if !hardware.no_auth && hardware.auth_type == Some(3) => (),
        KeyRole::Denial | KeyRole::Transport
            if hardware.no_auth && hardware.auth_type.is_none() => {}
        _ => return Err(Error::KeyPolicy),
    }
    let os_version = hardware.os.ok_or(Error::PlatformPolicy)?;
    let os_patch = hardware.patch.ok_or(Error::PlatformPolicy)?;
    if !hardware.root
        || !(110000..=999999).contains(&os_version)
        || os_version < policy.min_os_version
        || !valid_month(os_patch)
        || os_patch < policy.min_os_patch
        || hardware.vendor.is_some_and(|value| !valid_date(value))
        || hardware.boot.is_some_and(|value| !valid_date(value))
        || policy
            .min_vendor_patch
            .is_some_and(|minimum| hardware.vendor.is_none_or(|value| value < minimum))
        || policy
            .min_boot_patch
            .is_some_and(|minimum| hardware.boot.is_none_or(|value| value < minimum))
    {
        return Err(Error::PlatformPolicy);
    }
    let app_version = application_id(software.app.ok_or(Error::AppIdentity)?, policy)?;
    Ok(KeyDescription {
        attestation_version,
        attestation_security_level,
        keymint_version,
        keymint_security_level,
        os_version,
        os_patch,
        vendor_patch: hardware.vendor,
        boot_patch: hardware.boot,
        app_version,
    })
}

#[cfg(test)]
mod tests;
