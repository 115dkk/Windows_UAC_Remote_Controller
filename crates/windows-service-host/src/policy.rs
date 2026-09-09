// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure, conservative policy; native code supplies only handle-observed bytes.
#![forbid(unsafe_code)]

use crate::ServiceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObjectPolicy {
    /// Create-child alone cannot replace an already existing protected child.
    Ancestor,
    /// PRIVATE ProgramData root/entry-presence anchor only. The native helper
    /// must establish retained nonempty NTFS ancestry before any path write.
    AnchoredAncestor,
    Installation,
    PrivateData,
    Service,
}

/// Local DOS absolute paths only. Reject aliases, ADS, traversal, alternate
/// separators and Win32-normalized trailing dot/space components before FFI.
pub(crate) fn checked_dos_path(path: &str) -> Result<&str, ServiceError> {
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1..3] != *b":\\"
        || path
            .chars()
            .any(|c| c.is_control() || ['/', '"', '<', '>', '|', '?', '*'].contains(&c))
    {
        return Err(ServiceError::UnsafePath);
    }
    let rest = &path[3..];
    if !rest.is_empty()
        && rest.split('\\').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || part.contains(':')
        })
    {
        return Err(ServiceError::UnsafePath);
    }
    Ok(path)
}

pub(crate) fn command_matches(actual: &str, executable: &str) -> bool {
    checked_dos_path(executable).is_ok() && actual == format!("\"{executable}\" service")
}

pub(crate) fn trusted_system_sids() -> Vec<Vec<u8>> {
    vec![
        sid(&[18]),
        sid(&[32, 544]),
        sid(&[
            80,
            956_008_885,
            3_418_522_649,
            1_831_038_044,
            1_853_292_631,
            2_271_478_464,
        ]),
    ]
}

fn sid(parts: &[u32]) -> Vec<u8> {
    let mut result = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, 5];
    for part in parts {
        result.extend(part.to_le_bytes());
    }
    result
}

fn valid_sid(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0] == 1
        && bytes[1] <= 15
        && bytes.len() == 8 + usize::from(bytes[1]) * 4
}

/// The native lookup must also report SidTypeWellKnownGroup. A syntactically
/// valid user/group SID is not sufficient authority for private service data.
pub(crate) fn service_sid_matches(bytes: &[u8], domain: &str) -> bool {
    bytes.len() == 32
        && valid_sid(bytes)
        && bytes[..12] == [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0]
        && domain.eq_ignore_ascii_case("NT SERVICE")
}

fn forbidden_mask(policy: ObjectPolicy) -> u32 {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OWNER_OR_DACL_OR_DELETE: u32 = 0x000d_0000;
    match policy {
        // FILE_DELETE_CHILD, WRITE_EA, WRITE_ATTRIBUTES. ADD_FILE (2) and
        // ADD_SUBDIRECTORY (4) are intentionally NOT replacement rights here.
        ObjectPolicy::Ancestor => GENERIC_ALL | GENERIC_WRITE | OWNER_OR_DACL_OR_DELETE | 0x150,
        // Only read/execute/synchronize, child creation and EA/attribute writes.
        // Unknown rights, delete-child, DELETE, WRITE_DAC/OWNER and generic
        // ALL/WRITE remain forbidden to untrusted principals.
        ObjectPolicy::AnchoredAncestor => !0xA012_01BF_u32,
        ObjectPolicy::Installation => GENERIC_ALL | GENERIC_WRITE | OWNER_OR_DACL_OR_DELETE | 0x156,
        ObjectPolicy::PrivateData => u32::MAX,
        // Only QUERY_CONFIG, QUERY_STATUS, ENUMERATE_DEPENDENTS, INTERROGATE,
        // READ_CONTROL are allowed to unprivileged principals. No generic
        // mappings are silently assumed for a service object.
        ObjectPolicy::Service => !(0x0002_0000 | 0x0001 | 0x0004 | 0x0008 | 0x0080),
    }
}

/// Denies are not used to justify a risky allow: rejecting them is conservative
/// in the presence of arbitrary local group membership. Only standard allow and
/// deny ACE forms are understood. Unknown/callback/object/conditional ACEs fail.
pub(crate) fn check_acl(
    owner: &[u8],
    acl: &[u8],
    trusted: &[Vec<u8>],
    policy: ObjectPolicy,
) -> Result<(), ServiceError> {
    let reject = || ServiceError::UnsafePermissions;
    if !valid_sid(owner)
        || !trusted.iter().any(|sid| sid == owner)
        || acl.len() < 8
        || !matches!(acl[0], 2 | 4)
    {
        return Err(reject());
    }
    let size = usize::from(u16::from_le_bytes([acl[2], acl[3]]));
    let count = u16::from_le_bytes([acl[4], acl[5]]);
    if size != acl.len() || count > 4_096 {
        return Err(reject());
    }
    let mut offset = 8usize;
    for _ in 0..count {
        let header = acl.get(offset..offset + 4).ok_or_else(reject)?;
        let ace_size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if !matches!(header[0], 0 | 1) || ace_size < 16 || ace_size % 4 != 0 {
            return Err(reject());
        }
        let ace = acl.get(offset..offset + ace_size).ok_or_else(reject)?;
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        if policy == ObjectPolicy::AnchoredAncestor
            && (header[1] & !0x1f != 0 || mask & !0xF01F_01FF_u32 != 0)
        {
            // The special policy understands only ordinary inheritance flags,
            // standard file rights and known generic access bits. No audit/
            // unknown flag or access mapping broadens this anchored exception.
            return Err(reject());
        }
        let principal = &ace[8..];
        if !valid_sid(principal) {
            return Err(reject());
        }
        // INHERIT_ONLY does not affect this existing object. Every existing
        // descendant is checked separately; new data children get explicit SDs.
        if header[0] == 0
            && header[1] & 0x08 == 0
            && mask & forbidden_mask(policy) != 0
            && !trusted.iter().any(|sid| sid == principal)
        {
            return Err(reject());
        }
        offset += ace_size;
    }
    if offset > size {
        return Err(reject());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(principal: &[u8], mask: u32, kind: u8, flags: u8) -> Vec<u8> {
        let ace_size = (8 + principal.len()) as u16;
        let mut bytes = vec![2, 0];
        bytes.extend((8 + ace_size).to_le_bytes());
        bytes.extend([1, 0, 0, 0, kind, flags]);
        bytes.extend(ace_size.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(principal);
        bytes
    }

    #[test]
    fn paths_reject_aliases_and_untrusted_command_shapes() {
        let executable = r"C:\Program Files\휴대폰 승인\uac-service.exe";
        assert!(checked_dos_path(executable).is_ok());
        assert!(checked_dos_path(r"C:\").is_ok());
        for bad in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            r"C:\a\..\app.exe",
            r"C:app.exe",
            r"C:\a.\app.exe",
            r"C:\a \app.exe",
            r"C:\app.exe:stream",
            r"C:/app.exe",
            r"C:\\app.exe",
            "C:\\app\n.exe",
        ] {
            assert_eq!(checked_dos_path(bad), Err(ServiceError::UnsafePath));
        }
        assert!(command_matches(
            &format!("\"{executable}\" service"),
            executable
        ));
        for bad in [
            format!("{executable} service"),
            format!("\"{executable}\" service extra"),
            format!("\"{executable}\""),
            format!("\"{executable}\" service "),
        ] {
            assert!(!command_matches(&bad, executable));
        }
    }

    #[test]
    fn ancestor_create_child_is_not_replacement_authority() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 4, 0, 0),
                &trusted,
                ObjectPolicy::Ancestor
            )
            .is_ok()
        );
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 2, 0, 0),
                &trusted,
                ObjectPolicy::Ancestor
            )
            .is_ok()
        );
        for right in [0x40, 0x1_0000, 0x4_0000, 0x8_0000, 0x1000_0000, 0x4000_0000] {
            assert!(
                check_acl(
                    &trusted[0],
                    &acl(&users, right, 0, 0),
                    &trusted,
                    ObjectPolicy::Ancestor
                )
                .is_err()
            );
        }
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 4, 0, 0),
                &trusted,
                ObjectPolicy::Installation
            )
            .is_err()
        );
    }

    #[test]
    fn anchored_program_data_metadata_exception_does_not_relax_other_paths() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        // ROOT observed this ordinary ProgramData Users mask: add file/subdir,
        // write EA and write attributes. Native anchoring is a separate gate.
        let metadata_acl = acl(&users, 0x116, 0, 0);
        assert!(
            check_acl(
                &trusted[0],
                &metadata_acl,
                &trusted,
                ObjectPolicy::AnchoredAncestor
            )
            .is_ok()
        );
        for policy in [
            ObjectPolicy::Ancestor,
            ObjectPolicy::Installation,
            ObjectPolicy::PrivateData,
        ] {
            assert!(check_acl(&trusted[0], &metadata_acl, &trusted, policy).is_err());
        }
        for rights in [
            0x1,
            0x2,
            0x4,
            0x8,
            0x10,
            0x20,
            0x80,
            0x100,
            0x0002_0000,
            0x0010_0000,
            0x8000_0000,
            0x2000_0000,
        ] {
            assert!(
                check_acl(
                    &trusted[0],
                    &acl(&users, rights, 0, 0),
                    &trusted,
                    ObjectPolicy::AnchoredAncestor
                )
                .is_ok()
            );
        }
        // Trusted SYSTEM full control is still an ordinary supported descriptor.
        assert!(
            check_acl(
                &trusted[0],
                &acl(&trusted[0], 0x001F_01FF, 0, 0),
                &trusted,
                ObjectPolicy::AnchoredAncestor
            )
            .is_ok()
        );
    }

    #[test]
    fn anchored_ancestor_still_rejects_untrusted_replacement_and_security_rights() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        for rights in [
            0x40,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            0x1000_0000,
            0x4000_0000,
            0x0100_0000,
            0x0200_0000,
            0x200,
        ] {
            assert!(
                check_acl(
                    &trusted[0],
                    &acl(&users, rights, 0, 0),
                    &trusted,
                    ObjectPolicy::AnchoredAncestor
                )
                .is_err()
            );
        }
        assert!(
            check_acl(
                &users,
                &acl(&users, 0x116, 0, 0),
                &trusted,
                ObjectPolicy::AnchoredAncestor
            )
            .is_err()
        );
    }

    #[test]
    fn anchored_ancestor_rejects_unknown_ace_flags_and_access_bits() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        for flags in [0x20, 0x40, 0x80] {
            for kind in [0, 1] {
                assert!(
                    check_acl(
                        &trusted[0],
                        &acl(&users, 0x116, kind, flags),
                        &trusted,
                        ObjectPolicy::AnchoredAncestor
                    )
                    .is_err()
                );
            }
        }
        for flags in [0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x13] {
            assert!(
                check_acl(
                    &trusted[0],
                    &acl(&users, 0x116, 0, flags),
                    &trusted,
                    ObjectPolicy::AnchoredAncestor
                )
                .is_ok()
            );
        }
        assert!(
            check_acl(
                &trusted[0],
                &acl(&trusted[0], 0x200, 0, 0),
                &trusted,
                ObjectPolicy::AnchoredAncestor
            )
            .is_err()
        );
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 0x200, 0, 0x8),
                &trusted,
                ObjectPolicy::AnchoredAncestor
            )
            .is_err()
        );
    }

    #[test]
    fn ownership_and_acl_forms_fail_closed() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        assert!(
            check_acl(
                &users,
                &acl(&trusted[0], u32::MAX, 0, 0),
                &trusted,
                ObjectPolicy::Installation
            )
            .is_err()
        );
        assert!(
            check_acl(
                &trusted[0],
                &acl(&trusted[0], u32::MAX, 0, 0),
                &trusted,
                ObjectPolicy::PrivateData
            )
            .is_ok()
        );
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 1, 0, 0),
                &trusted,
                ObjectPolicy::PrivateData
            )
            .is_err()
        );
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 1, 5, 0),
                &trusted,
                ObjectPolicy::Ancestor
            )
            .is_err()
        );
        assert!(check_acl(&trusted[0], &[], &trusted, ObjectPolicy::Ancestor).is_err());
        let mut truncated = acl(&users, 1, 0, 0);
        truncated.pop();
        assert!(check_acl(&trusted[0], &truncated, &trusted, ObjectPolicy::Ancestor).is_err());
    }

    #[test]
    fn normal_app_can_read_status_but_never_mutate_service() {
        let trusted = trusted_system_sids();
        let users = sid(&[32, 545]);
        assert!(
            check_acl(
                &trusted[0],
                &acl(&users, 4, 0, 0),
                &trusted,
                ObjectPolicy::Service
            )
            .is_ok()
        );
        for right in [2, 0x10, 0x20, 0x40, 0x100, 0x1_0000, 0x4_0000, 0x8_0000] {
            assert!(
                check_acl(
                    &trusted[0],
                    &acl(&users, right, 0, 0),
                    &trusted,
                    ObjectPolicy::Service
                )
                .is_err()
            );
        }
    }

    #[test]
    fn private_data_requires_the_exact_service_sid_namespace() {
        let service = sid(&[80, 1, 2, 3, 4, 5]);
        assert!(service_sid_matches(&service, "NT SERVICE"));
        assert!(service_sid_matches(&service, "nt service"));
        assert!(!service_sid_matches(&service, "BUILTIN"));
        assert!(!service_sid_matches(&service, "NT SERVICE\0other"));
        for principal in [sid(&[18]), sid(&[32, 544]), sid(&[21, 1, 2, 3, 4, 5])] {
            assert!(!service_sid_matches(&principal, "NT SERVICE"));
        }
        for length in 0..service.len() {
            assert!(!service_sid_matches(&service[..length], "NT SERVICE"));
        }
        let mut trailing = service;
        trailing.extend([0; 4]);
        assert!(!service_sid_matches(&trailing, "NT SERVICE"));
    }
}
