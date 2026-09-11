// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe policy decisions and bounded parsing of documented Windows SD/SID data.
//! This module never dereferences native pointers or substitutes for token APIs.

use std::fmt;

use crate::{IdentityError, IdentityPolicy, PERSISTENT_KEY_NAME};

#[cfg(not(feature = "lab-software-identity"))]
pub(super) const PROVIDER_NAME: &str = "Microsoft Platform Crypto Provider";
/// Lab builds only (hosted runners have no TPM). Never selected at runtime.
#[cfg(feature = "lab-software-identity")]
pub(super) const PROVIDER_NAME: &str = "Microsoft Software Key Storage Provider";
/// NCRYPT_IMPL_HARDWARE_FLAG; hardware RNG (16) is optional in production.
#[cfg(not(feature = "lab-software-identity"))]
const ACCEPTED_IMPLEMENTATION: (u32, u32) = (1, 1 | 16);
/// NCRYPT_IMPL_SOFTWARE_FLAG for the lab software provider; a hardware RNG flag
/// (16) may accompany it on virtual machines and is tolerated there only.
#[cfg(feature = "lab-software-identity")]
const ACCEPTED_IMPLEMENTATION: (u32, u32) = (2, 2 | 16);
pub(super) const MAX_DESCRIPTOR_BYTES: usize = 4096;
pub(super) const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
// GENERIC_ALL. Both exact principals need key administration during explicit
// initialization under SERVICE_SID_TYPE_RESTRICTED's second access check.
const EXPECTED_ACE_MASK: u32 = 0x1000_0000;

/// Ownership state, not authorization. In particular, a failed finalization is
/// NOT proof that this transaction owns the persistent name and may delete it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyLifecycle {
    Established,
    Creating,
    FinalizationUncertain,
    RollbackPending,
}

impl KeyLifecycle {
    pub const fn permits_configuration(self) -> bool {
        matches!(self, Self::Creating)
    }

    pub const fn permits_rollback(self) -> bool {
        matches!(self, Self::RollbackPending)
    }
}

pub(super) fn validate_provider(
    name: &[u8],
    implementation: u32,
    security_descriptors: u32,
) -> Result<(), IdentityError> {
    if !utf16_property_matches(name, PROVIDER_NAME) {
        return Err(IdentityError::Policy(
            IdentityPolicy::PlatformProviderRequired,
        ));
    }
    // Production: hardware is mandatory and hardware RNG optional. Software,
    // removable, virtual-isolation-only and unknown flags are rejected, not
    // guessed at. The lab feature instead requires exactly the software flag.
    let (required, allowed) = ACCEPTED_IMPLEMENTATION;
    if implementation & required != required || implementation & !allowed != 0 {
        return Err(IdentityError::Policy(
            IdentityPolicy::HardwareProviderRequired,
        ));
    }
    if security_descriptors != 1 {
        return Err(IdentityError::Policy(
            IdentityPolicy::SecurityDescriptorsRequired,
        ));
    }
    Ok(())
}

pub(super) struct ObservedKeyPolicy<'a> {
    pub name: &'a [u8],
    pub algorithm: &'a [u8],
    pub algorithm_group: &'a [u8],
    pub length_bits: u32,
    pub usage: u32,
    pub export: u32,
    pub key_type: u32,
}

impl fmt::Debug for ObservedKeyPolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservedKeyPolicy([redacted])")
    }
}

impl ObservedKeyPolicy<'_> {
    pub fn validate(&self) -> Result<(), IdentityError> {
        if !utf16_property_matches(self.name, PERSISTENT_KEY_NAME) {
            return Err(IdentityError::Policy(IdentityPolicy::FixedKeyNameRequired));
        }
        if !utf16_property_matches(self.algorithm, "ECDSA_P256")
            || !utf16_property_matches(self.algorithm_group, "ECDSA")
            || self.length_bits != 256
        {
            return Err(IdentityError::Policy(
                IdentityPolicy::P256SigningKeyRequired,
            ));
        }
        // NCRYPT_ALLOW_SIGNING_FLAG only. Unknown/future uses fail closed too.
        if self.usage != 2 {
            return Err(IdentityError::Policy(IdentityPolicy::SigningOnlyRequired));
        }
        if self.export != 0 {
            return Err(IdentityError::Policy(IdentityPolicy::NonExportableRequired));
        }
        // NCRYPT_MACHINE_KEY_FLAG only, not merely any flag-containing value.
        if self.key_type != 0x20 {
            return Err(IdentityError::Policy(IdentityPolicy::MachineKeyRequired));
        }
        Ok(())
    }
}

pub(super) fn utf16_property_matches(bytes: &[u8], expected: &str) -> bool {
    let expected_units = expected.encode_utf16().chain(std::iter::once(0));
    bytes.len() == expected_units.clone().count() * 2
        && bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .eq(expected_units)
}

/// Return one structurally bounded SID prefix. It is not account authentication.
pub(super) fn sid_prefix(bytes: &[u8]) -> Option<&[u8]> {
    let header = bytes.get(..8)?;
    if header[0] != 1 || header[1] > 15 {
        return None;
    }
    bytes.get(..8 + usize::from(header[1]) * 4)
}

pub(super) fn is_service_sid(bytes: &[u8]) -> bool {
    bytes.len() == 32
        && bytes[..12] == [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0]
        && sid_prefix(bytes) == Some(bytes)
}

pub(super) fn service_sid_sddl(bytes: &[u8]) -> Result<String, IdentityError> {
    if !is_service_sid(bytes) {
        return Err(IdentityError::Policy(IdentityPolicy::InvalidServiceSid));
    }
    // Only validated binary DWORDs become decimal digits, never caller text.
    let mut sid = String::from("S-1-5");
    for part in bytes[8..].chunks_exact(4) {
        let subauthority = u32::from_le_bytes([part[0], part[1], part[2], part[3]]);
        sid.push('-');
        sid.push_str(&subauthority.to_string());
    }
    Ok(format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
}

pub(super) fn enabled_service_group(attributes: u32) -> bool {
    // SE_GROUP_ENABLED and SE_GROUP_USE_FOR_DENY_ONLY from winnt.h.
    attributes & 4 != 0 && attributes & 16 == 0
}

pub(super) fn validate_descriptor(bytes: &[u8], service_sid: &[u8]) -> Result<(), IdentityError> {
    if descriptor_matches(bytes, service_sid).is_none() {
        return Err(IdentityError::Policy(
            IdentityPolicy::ProtectedServiceDaclRequired,
        ));
    }
    Ok(())
}

fn descriptor_matches(bytes: &[u8], service_sid: &[u8]) -> Option<()> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES || !is_service_sid(service_sid) {
        return None;
    }
    let header = bytes.get(..20)?;
    // SECURITY_DESCRIPTOR_RELATIVE: revision, reserved, control, four offsets.
    // Require self-relative + protected/present DACL. AUTO_INHERITED alone is
    // harmless metadata; every actual ACE below must have zero inheritance flags.
    let control = u16::from_le_bytes([header[2], header[3]]);
    const REQUIRED: u16 = 0x8000 | 0x1000 | 0x0004;
    if header[0] != 1
        || header[1] != 0
        || control & REQUIRED != REQUIRED
        || control & !(REQUIRED | 0x0400) != 0
        || read_u32(header, 12)? != 0
    {
        return None;
    }
    let owner_offset = relative_offset(header, 4, bytes.len())?;
    let group_offset = relative_offset(header, 8, bytes.len())?;
    let dacl_offset = relative_offset(header, 16, bytes.len())?;
    let owner = sid_prefix(bytes.get(owner_offset..)?)?;
    let group = sid_prefix(bytes.get(group_offset..)?)?;
    if owner != SYSTEM_SID || group != SYSTEM_SID {
        return None;
    }
    let acl_header = bytes.get(dacl_offset..dacl_offset.checked_add(8)?)?;
    let acl_length = usize::from(u16::from_le_bytes([acl_header[2], acl_header[3]]));
    let acl_end = dacl_offset.checked_add(acl_length)?;
    let acl = bytes.get(dacl_offset..acl_end)?;
    // Plain allow ACEs only, exactly one SYSTEM and one service SID, no slack.
    if acl_header[0] != 2
        || acl_header[1] != 0
        || acl_header[4..8] != [2, 0, 0, 0]
        || ranges_overlap(
            dacl_offset,
            acl_end,
            owner_offset,
            owner_offset + owner.len(),
        )
        || ranges_overlap(
            dacl_offset,
            acl_end,
            group_offset,
            group_offset + group.len(),
        )
    {
        return None;
    }
    let mut cursor = 8_usize;
    let mut saw_system = false;
    let mut saw_service = false;
    for _ in 0..2 {
        let ace_header = acl.get(cursor..cursor.checked_add(8)?)?;
        let size = usize::from(u16::from_le_bytes([ace_header[2], ace_header[3]]));
        if ace_header[0] != 0
            || ace_header[1] != 0
            || read_u32(ace_header, 4)? != EXPECTED_ACE_MASK
            || size < 16
            || !size.is_multiple_of(4)
        {
            return None;
        }
        let end = cursor.checked_add(size)?;
        let ace = acl.get(cursor..end)?;
        let sid = sid_prefix(ace.get(8..)?)?;
        if sid.len() + 8 != size {
            return None;
        }
        if sid == SYSTEM_SID && !saw_system {
            saw_system = true;
        } else if sid == service_sid && !saw_service {
            saw_service = true;
        } else {
            return None;
        }
        cursor = end;
    }
    (saw_system && saw_service && cursor == acl.len()).then_some(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let part = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
}

fn relative_offset(header: &[u8], field: usize, length: usize) -> Option<usize> {
    let offset = usize::try_from(read_u32(header, field)?).ok()?;
    (offset >= 20 && offset < length && offset.is_multiple_of(4)).then_some(offset)
}

fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    fn service_fixture() -> Vec<u8> {
        let mut sid = vec![1, 6, 0, 0, 0, 0, 0, 5];
        for value in [80_u32, 1, 2, 3, 4, 5] {
            sid.extend_from_slice(&value.to_le_bytes());
        }
        sid
    }

    fn descriptor_fixture() -> Vec<u8> {
        let mut bytes = vec![1, 0, 4, 0x90];
        for offset in [20_u32, 32, 0, 44] {
            bytes.extend_from_slice(&offset.to_le_bytes());
        }
        bytes.extend_from_slice(&SYSTEM_SID);
        bytes.extend_from_slice(&SYSTEM_SID);
        bytes.extend_from_slice(&[2, 0, 68, 0, 2, 0, 0, 0]);
        let service = service_fixture();
        for sid in [SYSTEM_SID.as_slice(), service.as_slice()] {
            bytes.extend_from_slice(&[0, 0]);
            bytes.extend_from_slice(
                &u16::try_from(sid.len() + 8)
                    .expect("small ACE")
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&EXPECTED_ACE_MASK.to_le_bytes());
            bytes.extend_from_slice(sid);
        }
        bytes
    }

    #[cfg(not(feature = "lab-software-identity"))]
    #[test]
    fn hardware_only_provider_and_security_descriptor_support_are_mandatory() {
        let name = wide(PROVIDER_NAME);
        for flags in [1, 17] {
            assert!(validate_provider(&name, flags, 1).is_ok());
        }
        for flags in [0, 2, 3, 8, 9, 0x20, 0x21, u32::MAX] {
            assert!(validate_provider(&name, flags, 1).is_err());
        }
        for support in [0, 2, u32::MAX] {
            assert!(validate_provider(&name, 1, support).is_err());
        }
        assert!(validate_provider(&wide("Microsoft Software Key Storage Provider"), 1, 1).is_err());
        assert_eq!(crate::IDENTITY_PROVIDER_PROFILE, "platform-crypto-provider");
    }

    #[cfg(feature = "lab-software-identity")]
    #[test]
    fn lab_feature_accepts_only_the_software_provider_with_the_exact_software_flag() {
        let name = wide(PROVIDER_NAME);
        assert!(validate_provider(&name, 2, 1).is_ok());
        assert!(validate_provider(&name, 18, 1).is_ok());
        for flags in [0, 1, 3, 8, 17, 0x20, u32::MAX] {
            assert!(validate_provider(&name, flags, 1).is_err());
        }
        assert!(validate_provider(&name, 2, 0).is_err());
        assert!(validate_provider(&wide("Microsoft Platform Crypto Provider"), 2, 1).is_err());
        assert!(crate::IDENTITY_PROVIDER_PROFILE.contains("do-not-ship"));
    }

    #[test]
    fn only_successfully_finalized_new_key_is_eligible_for_rollback() {
        assert!(KeyLifecycle::Creating.permits_configuration());
        for state in [
            KeyLifecycle::Established,
            KeyLifecycle::FinalizationUncertain,
            KeyLifecycle::RollbackPending,
        ] {
            assert!(!state.permits_configuration());
        }
        assert!(KeyLifecycle::RollbackPending.permits_rollback());
        for state in [
            KeyLifecycle::Established,
            KeyLifecycle::Creating,
            KeyLifecycle::FinalizationUncertain,
        ] {
            assert!(!state.permits_rollback());
        }
    }

    #[test]
    fn named_key_must_have_exact_curve_usage_scope_and_export_policy() {
        let name = wide(PERSISTENT_KEY_NAME);
        let algorithm = wide("ECDSA_P256");
        let group = wide("ECDSA");
        let mut observation = ObservedKeyPolicy {
            name: &name,
            algorithm: &algorithm,
            algorithm_group: &group,
            length_bits: 256,
            usage: 2,
            export: 0,
            key_type: 32,
        };
        assert!(observation.validate().is_ok());
        assert_eq!(format!("{observation:?}"), "ObservedKeyPolicy([redacted])");
        for export in [1, 2, 4, 8, 16, u32::MAX] {
            observation.export = export;
            assert!(observation.validate().is_err());
        }
        observation.export = 0;
        for usage in [0, 1, 3, 4, 6, 0x00ff_ffff, u32::MAX] {
            observation.usage = usage;
            assert!(observation.validate().is_err());
        }
        observation.usage = 2;
        for key_type in [0, 1, 33, u32::MAX] {
            observation.key_type = key_type;
            assert!(observation.validate().is_err());
        }
        observation.key_type = 32;
        observation.length_bits = 384;
        assert!(observation.validate().is_err());
        observation.length_bits = 256;
        observation.algorithm_group = &algorithm;
        assert!(observation.validate().is_err());
    }

    #[test]
    fn property_strings_require_exact_utf16_and_one_nul() {
        let good = wide("ECDSA_P256");
        assert!(utf16_property_matches(&good, "ECDSA_P256"));
        assert!(!utf16_property_matches(
            &good[..good.len() - 1],
            "ECDSA_P256"
        ));
        assert!(!utf16_property_matches(
            &good[..good.len() - 2],
            "ECDSA_P256"
        ));
        let mut extra = good.clone();
        extra.extend_from_slice(&[0, 0]);
        assert!(!utf16_property_matches(&extra, "ECDSA_P256"));
        assert!(!utf16_property_matches(
            &wide("ECDSA_P256\0other"),
            "ECDSA_P256"
        ));
        assert!(!utf16_property_matches(&[0xff, 0xd8, 0, 0], "ECDSA_P256"));
    }

    #[test]
    fn service_sid_shape_cannot_be_system_or_a_user_sid() {
        let sid = service_fixture();
        assert!(is_service_sid(&sid));
        assert_eq!(
            service_sid_sddl(&sid).expect("synthetic service SID"),
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;S-1-5-80-1-2-3-4-5)"
        );
        assert!(!is_service_sid(&SYSTEM_SID));
        for length in 0..sid.len() {
            assert!(!is_service_sid(&sid[..length]));
        }
        let mut other = sid.clone();
        other[8] = 21;
        assert!(!is_service_sid(&other));
        assert!(!enabled_service_group(0));
        assert!(enabled_service_group(4));
        assert!(enabled_service_group(4 | 2 | 8));
        assert!(!enabled_service_group(4 | 16));
    }

    #[test]
    fn accepts_only_protected_system_and_service_descriptor() {
        let descriptor = descriptor_fixture();
        assert!(validate_descriptor(&descriptor, &service_fixture()).is_ok());
        let mut changed_service = service_fixture();
        changed_service[31] = 1;
        assert!(validate_descriptor(&descriptor, &changed_service).is_err());
        for length in 0..descriptor.len() {
            assert!(validate_descriptor(&descriptor[..length], &service_fixture()).is_err());
        }
    }

    #[test]
    fn rejects_null_unprotected_extra_inherited_and_non_allow_dacls() {
        let good = descriptor_fixture();
        for (offset, value) in [
            (0, 2),     // wrong revision
            (1, 1),     // reserved
            (3, 0x80),  // unprotected DACL
            (3, 0x10),  // absolute descriptor
            (16, 0),    // NULL DACL
            (48, 3),    // additional ACE count
            (52, 1),    // deny rather than exact allow ACE
            (53, 0x10), // inherited ACE
            (53, 0x08), // inherit-only ACE
            (59, 0x80), // mask is read rather than required management rights
            (68, 32),   // changed SYSTEM SID subauthority
            (72, 5),    // object ACE
        ] {
            let mut changed = good.clone();
            changed[offset] = value;
            assert!(
                validate_descriptor(&changed, &service_fixture()).is_err(),
                "mutation at {offset} must fail"
            );
        }
        let mut huge = good;
        huge.resize(MAX_DESCRIPTOR_BYTES + 1, 0);
        assert!(validate_descriptor(&huge, &service_fixture()).is_err());
    }

    #[test]
    fn rejects_descriptor_offset_aliasing_and_truncated_sid_counts() {
        for offset in [0_u32, 1, 19, 21, 52, u32::MAX] {
            let mut descriptor = descriptor_fixture();
            descriptor[4..8].copy_from_slice(&offset.to_le_bytes());
            assert!(validate_descriptor(&descriptor, &service_fixture()).is_err());
        }
        let mut descriptor = descriptor_fixture();
        descriptor[61] = 15;
        assert!(validate_descriptor(&descriptor, &service_fixture()).is_err());
    }
}
