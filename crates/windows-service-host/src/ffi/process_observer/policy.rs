// SPDX-License-Identifier: GPL-2.0-or-later
//! Dedicated pure process-DACL policy; never reused for files, SCM or tokens.
#![forbid(unsafe_code)]

use crate::ServiceError;

pub(super) const OBSERVER: u32 = 0x0010_1000;
const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMIN: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const INTERACTIVE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
const MAX_ACL: usize = 16 * 1024;
const MAX_ACES: usize = 128;
const GENERIC_ALL: u32 = 0x1000_0000;
const KNOWN_TRUSTED_RIGHTS: u32 = 0xf01f_ffff;
const SYSTEM_CONTROL: u32 = 0x0006_0000 | OBSERVER; // READ_CONTROL | WRITE_DAC.

/// Interpret only trusted SYSTEM rights for the minimum-control guard. Windows
/// grants QUERY_LIMITED_INFORMATION whenever QUERY_INFORMATION is granted.
/// This arithmetic never rewrites an ACE or applies to the IU observer mask.
fn system_control_rights(mask: u32) -> u32 {
    let implied = if mask & 0x0400 != 0 { 0x1000 } else { 0 };
    if mask & GENERIC_ALL != 0 {
        SYSTEM_CONTROL
    } else {
        (mask | implied) & SYSTEM_CONTROL
    }
}

#[derive(Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(super) owner: Vec<u8>,
    pub(super) group: Option<Vec<u8>>,
    pub(super) labels: Option<Vec<u8>>,
    pub(super) control: u16,
    pub(super) acl: Vec<u8>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProcessObserverSnapshot(redacted)")
    }
}

fn rejected() -> ServiceError {
    ServiceError::UnsafePermissions
}

fn number(bytes: &[u8], at: usize) -> Result<usize, ServiceError> {
    let value = bytes.get(at..at + 4).ok_or_else(rejected)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize)
}

fn sid(bytes: &[u8], at: usize) -> Result<&[u8], ServiceError> {
    let header = bytes.get(at..at + 8).ok_or_else(rejected)?;
    if header[0] != 1 || !(1..=15).contains(&header[1]) {
        return Err(rejected());
    }
    bytes
        .get(at..at + 8 + usize::from(header[1]) * 4)
        .ok_or_else(rejected)
}

fn acl_at(bytes: &[u8], at: usize) -> Result<&[u8], ServiceError> {
    let header = bytes.get(at..at + 8).ok_or_else(rejected)?;
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    if !(8..=MAX_ACL).contains(&size) {
        return Err(rejected());
    }
    bytes.get(at..at + size).ok_or_else(rejected)
}

pub(super) fn snapshot(bytes: &[u8]) -> Result<Snapshot, ServiceError> {
    if !(20..=65_536).contains(&bytes.len()) || bytes[0] != 1 || bytes[1] != 0 {
        return Err(rejected());
    }
    let control = u16::from_le_bytes([bytes[2], bytes[3]]);
    // Native GetSecurityInfo supplies a contiguous self-relative descriptor.
    // Null/missing DACLs are never an acceptable starting or final policy.
    if control & 0x8004 != 0x8004 {
        return Err(rejected());
    }
    let mut parts: [Option<(usize, usize)>; 4] = [None, None, None, None];
    for (index, field) in [4, 8, 12, 16].into_iter().enumerate() {
        let offset = number(bytes, field)?;
        if offset == 0 {
            continue;
        }
        if offset < 20 || !offset.is_multiple_of(4) {
            return Err(rejected());
        }
        let value = if index < 2 {
            sid(bytes, offset)?
        } else {
            acl_at(bytes, offset)?
        };
        // Owner/group may share the exact same SID representation. No ACL/SID
        // overlap or partial component alias can be interpreted as policy.
        let end = offset + value.len();
        if parts.iter().enumerate().any(|(previous, part)| {
            part.is_some_and(|(start, previous_end)| {
                offset < previous_end
                    && start < end
                    && !(index == 1 && previous == 0 && offset == start && end == previous_end)
            })
        }) {
            return Err(rejected());
        }
        parts[index] = Some((offset, end));
    }
    let copied = |index: usize| parts[index].map(|(start, end)| bytes[start..end].to_vec());
    Ok(Snapshot {
        owner: copied(0).ok_or_else(rejected)?,
        group: copied(1),
        labels: copied(2),
        control,
        acl: copied(3).ok_or_else(rejected)?,
    })
}

struct CheckedAcl {
    end: usize,
    count: usize,
    observer: Option<usize>,
}

fn check(
    snapshot: &Snapshot,
    service_sid: &[u8],
    require_observer: bool,
) -> Result<CheckedAcl, ServiceError> {
    if !crate::policy::service_sid_matches(service_sid, "NT SERVICE")
        || ![SYSTEM, ADMIN, service_sid].contains(&snapshot.owner.as_slice())
    {
        return Err(rejected());
    }
    let acl = &snapshot.acl;
    if !(8..=MAX_ACL).contains(&acl.len())
        || ![2, 4].contains(&acl[0])
        || acl[1] != 0
        || acl[6..8] != [0, 0]
        || usize::from(u16::from_le_bytes([acl[2], acl[3]])) != acl.len()
    {
        return Err(rejected());
    }
    let count = usize::from(u16::from_le_bytes([acl[4], acl[5]]));
    if count == 0 || count > MAX_ACES {
        return Err(rejected());
    }
    let mut offset = 8;
    let mut observer = None;
    let mut system_control = 0;
    for _ in 0..count {
        let header = acl.get(offset..offset + 8).ok_or_else(rejected)?;
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        // Only standard, noninheriting ALLOW. Any DENY/unknown/inherited ACE
        // blocks startup; no deny is removed, reordered or overridden.
        if header[0] != 0 || header[1] != 0 || size < 20 || !size.is_multiple_of(4) {
            return Err(rejected());
        }
        let ace = acl.get(offset..offset + size).ok_or_else(rejected)?;
        let trustee = sid(ace, 8)?;
        if trustee.len() + 8 != size {
            return Err(rejected());
        }
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        if trustee == INTERACTIVE {
            if observer.is_some()
                || mask == 0
                || mask & !OBSERVER != 0
                || (require_observer && mask != OBSERVER)
            {
                return Err(rejected());
            }
            observer = Some(offset);
        } else if [SYSTEM, ADMIN, service_sid].contains(&trustee) {
            if mask == 0 || mask & !KNOWN_TRUSTED_RIGHTS != 0 {
                return Err(rejected());
            }
            if trustee == SYSTEM {
                system_control |= system_control_rights(mask);
            }
        } else {
            return Err(rejected());
        }
        offset += size;
    }
    if system_control & SYSTEM_CONTROL != SYSTEM_CONTROL
        || (require_observer && observer.is_none())
        || acl[offset..].iter().any(|byte| *byte != 0)
    {
        return Err(rejected());
    }
    Ok(CheckedAcl {
        end: offset,
        count,
        observer,
    })
}

pub(super) fn merge(snapshot: &Snapshot, service_sid: &[u8]) -> Result<Vec<u8>, ServiceError> {
    let checked = check(snapshot, service_sid, false)?;
    // Unused zero allocation padding has no ACE semantics and is not copied.
    // Every trusted ACE's bytes and order remain exactly unchanged.
    let mut acl = snapshot.acl[..checked.end].to_vec();
    if let Some(offset) = checked.observer {
        acl[offset + 4..offset + 8].copy_from_slice(&OBSERVER.to_le_bytes());
    } else {
        if checked.count == MAX_ACES {
            return Err(rejected());
        }
        acl.extend_from_slice(&[0, 0, 20, 0]);
        acl.extend_from_slice(&OBSERVER.to_le_bytes());
        acl.extend_from_slice(INTERACTIVE);
        acl[4..6].copy_from_slice(&((checked.count + 1) as u16).to_le_bytes());
    }
    if acl.len() > MAX_ACL {
        return Err(rejected());
    }
    let size = acl.len() as u16;
    acl[2..4].copy_from_slice(&size.to_le_bytes());
    Ok(acl)
}

pub(super) fn verify_readback(
    before: &Snapshot,
    after: &Snapshot,
    expected: &[u8],
    service_sid: &[u8],
) -> Result<(), ServiceError> {
    check(after, service_sid, true)?;
    // An explicit DACL legitimately clears DACL_DEFAULTED (0x0008). Every
    // other reported control bit, including protection/inheritance, is kept.
    if before.owner != after.owner
        || before.group != after.group
        || before.labels != after.labels
        || before.control & !0x0008 != after.control & !0x0008
        || after.acl != expected
    {
        return Err(rejected());
    }
    Ok(())
}

pub(super) fn startup_guard(
    stopped: bool,
    running: bool,
    controls_empty: bool,
    own_pid: bool,
) -> Result<(), ServiceError> {
    if stopped || !running || !controls_empty || !own_pid {
        Err(ServiceError::ConfigurationConflict)
    } else {
        Ok(())
    }
}

/// Redacted, bounded lab summary only; never an admission input or serializer
/// for the descriptor. Parsing stops at 128 ACEs and reports only the first 16.
#[cfg(any(test, feature = "lab-software-identity"))]
pub(super) fn diagnostic_summary(snapshot: &Snapshot, service_sid: &[u8]) -> Vec<String> {
    fn class(principal: &[u8], service_sid: &[u8]) -> (&'static str, usize) {
        if principal == SYSTEM {
            ("SYSTEM", 0)
        } else if principal == ADMIN {
            ("ADMIN", 1)
        } else if principal == service_sid
            && crate::policy::service_sid_matches(service_sid, "NT SERVICE")
        {
            ("OWN_SERVICE", 2)
        } else if principal == INTERACTIVE {
            ("IU", 3)
        } else {
            ("OTHER", 4)
        }
    }

    let acl = &snapshot.acl;
    let header = acl.get(..8);
    let count = header.map(|value| usize::from(u16::from_le_bytes([value[4], value[5]])));
    let valid_header = header.is_some_and(|value| {
        acl.len() <= MAX_ACL
            && [2, 4].contains(&value[0])
            && value[1] == 0
            && value[6..8] == [0, 0]
            && usize::from(u16::from_le_bytes([value[2], value[3]])) == acl.len()
    });
    let mut lines = vec![format!(
        "acl_summary owner={} bytes={} count={} revision={} control={} header_valid={}",
        class(&snapshot.owner, service_sid).0,
        acl.len(),
        count.unwrap_or(0),
        header.map_or(0, |value| value[0]),
        snapshot.control,
        u8::from(valid_header),
    )];
    let mut offset = 8usize;
    let mut visited = 0usize;
    let mut counts = [0usize; 5];
    let mut effective_control = 0u32;
    let mut complete = valid_header;
    if valid_header {
        for _ in 0..count.unwrap_or(0).min(MAX_ACES) {
            let Some(header) = acl.get(offset..offset + 4) else {
                complete = false;
                break;
            };
            let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
            if size < 4 || !size.is_multiple_of(4) {
                complete = false;
                break;
            }
            let Some(ace) = acl.get(offset..offset + size) else {
                complete = false;
                break;
            };
            let mask = ace.get(4..8).map_or(0, |value| {
                u32::from_le_bytes([value[0], value[1], value[2], value[3]])
            });
            // Only ordinary allow/deny forms have the SID layout used here.
            // Unknown ACE kinds retain numeric metadata and an OTHER class.
            let principal = if matches!(header[0], 0 | 1) {
                sid(ace, 8).ok().filter(|value| value.len() + 8 == size)
            } else {
                None
            };
            let (label, index) = principal.map_or(("OTHER", 4), |value| class(value, service_sid));
            counts[index] += 1;
            if label == "SYSTEM"
                && header[0] == 0
                && header[1] == 0
                && mask != 0
                && mask & !KNOWN_TRUSTED_RIGHTS == 0
            {
                effective_control |= system_control_rights(mask);
            }
            if visited < 16 {
                lines.push(format!(
                    "acl_ace index={visited} class={label} kind={} flags={} mask={mask} mask_present={} size={size}",
                    header[0], header[1], u8::from(ace.get(4..8).is_some()),
                ));
            }
            visited += 1;
            offset += size;
        }
    }
    complete &= visited == count.unwrap_or(0);
    let padding = if complete { acl.get(offset..) } else { None };
    lines.push(format!(
        "acl_totals visited={visited} system={} admin={} own_service={} iu={} other={} omitted={} complete={} padding_bytes={} padding_nonzero={} system_effective_control={effective_control} system_required_control={SYSTEM_CONTROL}",
        counts[0], counts[1], counts[2], counts[3], counts[4],
        visited.saturating_sub(16), u8::from(complete),
        padding.map_or(0, <[u8]>::len),
        u8::from(padding.is_some_and(|bytes| bytes.iter().any(|byte| *byte != 0))),
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_sid() -> Vec<u8> {
        let mut bytes = vec![1, 6, 0, 0, 0, 0, 0, 5];
        for value in [80u32, 1, 2, 3, 4, 5] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    fn ace(trustee: &[u8], mask: u32) -> Vec<u8> {
        let mut bytes = vec![0, 0];
        bytes.extend_from_slice(&((8 + trustee.len()) as u16).to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(trustee);
        bytes
    }
    fn fixture(extra: &[u8]) -> Snapshot {
        let mut acl = vec![2, 0, 0, 0, if extra.is_empty() { 2 } else { 3 }, 0, 0, 0];
        acl.extend_from_slice(&ace(SYSTEM, 0x001f_ffff));
        acl.extend_from_slice(&ace(ADMIN, GENERIC_ALL));
        acl.extend_from_slice(extra);
        let size = acl.len() as u16;
        acl[2..4].copy_from_slice(&size.to_le_bytes());
        Snapshot {
            owner: SYSTEM.to_vec(),
            group: Some(SYSTEM.to_vec()),
            labels: None,
            control: 0x9004,
            acl,
        }
    }
    #[test]
    fn observer_is_only_limited_query_and_synchronize_and_preserves_trusted_aces() {
        assert_eq!(OBSERVER, 0x1000 | 0x0010_0000);
        let before = fixture(&[]);
        let expected = merge(&before, &service_sid()).unwrap();
        assert_eq!(&expected[8..before.acl.len()], &before.acl[8..]);
        let after = Snapshot {
            acl: expected.clone(),
            ..fixture(&[])
        };
        assert!(verify_readback(&before, &after, &expected, &service_sid()).is_ok());
        assert_eq!(merge(&after, &service_sid()).unwrap(), expected);
        let partial = fixture(&ace(INTERACTIVE, 0x1000));
        assert_eq!(merge(&partial, &service_sid()).unwrap(), expected);
    }
    #[test]
    fn every_extra_observer_bit_and_wrong_trustee_are_rejected() {
        for bit in 0..32 {
            let mask = 1u32 << bit;
            if mask & OBSERVER == 0 {
                assert!(
                    merge(&fixture(&ace(INTERACTIVE, OBSERVER | mask)), &service_sid()).is_err()
                );
            }
        }
        let authenticated = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
        assert!(merge(&fixture(&ace(&authenticated, OBSERVER)), &service_sid()).is_err());
    }
    #[test]
    fn denied_inherited_unknown_empty_malformed_and_wrong_owner_fail_closed() {
        for (kind, flags) in [(1, 0), (5, 0), (9, 0), (0, 1), (0, 8), (0, 16)] {
            let mut entry = ace(INTERACTIVE, OBSERVER);
            entry[0] = kind;
            entry[1] = flags;
            assert!(merge(&fixture(&entry), &service_sid()).is_err());
        }
        let mut before = fixture(&[]);
        before.owner = INTERACTIVE.to_vec();
        assert!(merge(&before, &service_sid()).is_err());
        before = fixture(&[]);
        before.acl = vec![2, 0, 8, 0, 0, 0, 0, 0];
        assert!(merge(&before, &service_sid()).is_err());
        for end in 0..fixture(&[]).acl.len() {
            let mut broken = fixture(&[]);
            broken.acl.truncate(end);
            assert!(merge(&broken, &service_sid()).is_err());
        }
        assert!(snapshot(&[0; 20]).is_err());
        let mut null_dacl = [0; 20];
        null_dacl[0] = 1;
        null_dacl[3] = 0x80;
        assert!(snapshot(&null_dacl).is_err());
    }
    #[test]
    fn readback_requires_exact_observer_and_unchanged_security_except_defaulted() {
        let mut before = fixture(&[]);
        before.control |= 8;
        let expected = merge(&before, &service_sid()).unwrap();
        let after = Snapshot {
            acl: expected.clone(),
            ..fixture(&[])
        };
        assert!(verify_readback(&before, &after, &expected, &service_sid()).is_ok());
        assert!(verify_readback(&before, &before, &expected, &service_sid()).is_err());
        for changed in [
            Snapshot {
                control: after.control ^ 0x1000,
                ..fixture(&ace(INTERACTIVE, OBSERVER))
            },
            Snapshot {
                group: None,
                ..fixture(&ace(INTERACTIVE, OBSERVER))
            },
            Snapshot {
                labels: Some(vec![0]),
                ..fixture(&ace(INTERACTIVE, OBSERVER))
            },
        ] {
            assert!(verify_readback(&before, &changed, &expected, &service_sid()).is_err());
        }
    }
    #[test]
    fn provisioning_is_only_unstopped_own_running_startup_before_ready() {
        assert!(startup_guard(false, true, true, true).is_ok());
        for facts in [
            (true, true, true, true),
            (false, false, true, true),
            (false, true, false, true),
            (false, true, true, false),
        ] {
            assert!(startup_guard(facts.0, facts.1, facts.2, facts.3).is_err());
        }
    }
    #[test]
    fn descriptor_parser_accepts_shared_owner_group_sid_but_not_null_or_overlapping_acl() {
        let expected = fixture(&[]);
        let mut bytes = vec![
            1, 0, 4, 0x90, 20, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
        ];
        bytes.extend_from_slice(SYSTEM);
        bytes.extend_from_slice(&expected.acl);
        assert_eq!(snapshot(&bytes).unwrap(), expected);
        for offset in [0u32, 1, 20, 24, u32::MAX] {
            let mut broken = bytes.clone();
            broken[16..20].copy_from_slice(&offset.to_le_bytes());
            assert!(snapshot(&broken).is_err());
        }
        let mut no_dacl = bytes;
        no_dacl[2] &= !4;
        assert!(snapshot(&no_dacl).is_err());
    }
    #[test]
    fn missing_system_control_and_duplicate_observer_are_rejected() {
        let mut missing_control = fixture(&[]);
        missing_control.acl[12..16].copy_from_slice(&OBSERVER.to_le_bytes());
        assert!(merge(&missing_control, &service_sid()).is_err());
        let mut duplicate = fixture(&ace(INTERACTIVE, OBSERVER));
        duplicate.acl.extend_from_slice(&ace(INTERACTIVE, OBSERVER));
        let size = duplicate.acl.len() as u16;
        duplicate.acl[2..4].copy_from_slice(&size.to_le_bytes());
        duplicate.acl[4..6].copy_from_slice(&4u16.to_le_bytes());
        assert!(merge(&duplicate, &service_sid()).is_err());
    }

    #[test]
    fn system_legacy_full_and_query_information_supply_implicit_limited_query() {
        for mask in [0x001f_0fff_u32, 0x0016_0400] {
            assert_eq!(mask & 0x1000, 0);
            let mut before = fixture(&[]);
            before.acl[12..16].copy_from_slice(&mask.to_le_bytes());
            let expected = merge(&before, &service_sid()).unwrap();
            // Only the appended IU ACE/header change; legacy SYSTEM rights
            // stay byte-for-byte identical, including no added raw QLI bit.
            assert_eq!(&expected[8..before.acl.len()], &before.acl[8..]);
            assert_eq!(&expected[12..16], &mask.to_le_bytes());
            let after = Snapshot {
                acl: expected.clone(),
                ..fixture(&[])
            };
            assert!(verify_readback(&before, &after, &expected, &service_sid()).is_ok());
            assert_eq!(system_control_rights(mask), SYSTEM_CONTROL);
        }
    }

    #[test]
    fn implicit_system_query_does_not_relax_observer_or_other_required_rights() {
        for missing in [0x0002_0000_u32, 0x0004_0000, 0x0010_0000, 0x0400] {
            let mut before = fixture(&[]);
            before.acl[12..16].copy_from_slice(&(0x0016_0400 & !missing).to_le_bytes());
            assert!(merge(&before, &service_sid()).is_err());
        }
        for mask in [0x0400, 0x0010_0400, OBSERVER | 0x0400] {
            assert!(merge(&fixture(&ace(INTERACTIVE, mask)), &service_sid()).is_err());
        }
    }

    #[test]
    fn diagnostic_summary_is_classified_and_bounds_records_and_scan() {
        let mut before = fixture(&ace(INTERACTIVE, OBSERVER));
        before.acl[12..16].copy_from_slice(&0x001f_0fff_u32.to_le_bytes());
        let lines = diagnostic_summary(&before, &service_sid());
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("owner=SYSTEM"));
        assert!(lines[1].contains("class=SYSTEM"));
        assert!(lines[2].contains("class=ADMIN"));
        assert!(lines[3].contains("class=IU"));
        assert!(lines[4].contains(&format!("system_effective_control={SYSTEM_CONTROL}")));
        let unknown = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
        let mut many = fixture(&[]);
        for _ in 0..140 {
            many.acl.extend_from_slice(&ace(&unknown, 0x1000));
        }
        let size = many.acl.len() as u16;
        many.acl[2..4].copy_from_slice(&size.to_le_bytes());
        many.acl[4..6].copy_from_slice(&142u16.to_le_bytes());
        let lines = diagnostic_summary(&many, &service_sid());
        assert_eq!(lines.len(), 18);
        assert!(lines[17].contains("visited=128"));
        assert!(lines[17].contains("complete=0"));
        assert!(lines[17].contains("omitted=112"));
        assert!(lines.join("\n").len() < 8192);
        for end in 0..before.acl.len() {
            let mut broken = fixture(&[]);
            broken.acl.truncate(end);
            assert!(diagnostic_summary(&broken, &service_sid()).len() <= 18);
        }
    }
}
