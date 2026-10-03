// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure, bounded installation observations. Neither a manifest nor a UI hint
//! grants authority to restore a file; the elevated owner validates independently.
#![forbid(unsafe_code)]

use serde::Deserialize;

use crate::{InstallationIntegrityView, IntegrityStateView};

pub(crate) const FILE_NAMES: [&str; 2] = ["uac-service.exe", "uac-prompt-probe.exe"];
pub(crate) const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: usize = 4096;

/// A timed-out worker may still own native I/O. Its slot is not reusable until
/// the thread has actually exited, even if cancellation was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerAdmission {
    Start,
    Reap,
    Busy,
}

pub(crate) fn worker_admission(outstanding: bool, exited: bool) -> WorkerAdmission {
    match (outstanding, exited) {
        (false, _) => WorkerAdmission::Start,
        (true, true) => WorkerAdmission::Reap,
        (true, false) => WorkerAdmission::Busy,
    }
}

/// No partial or late result can preserve an Intact/Damaged claim after a
/// deadline, failed worker, or outstanding native operation.
pub(crate) fn completed_check(
    result: Option<InstallationIntegrityView>,
) -> InstallationIntegrityView {
    result.unwrap_or_else(|| InstallationIntegrityView {
        state: IntegrityStateView::Unknown,
        damaged: Vec::new(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManifestState {
    Valid,
    Missing,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileMatch {
    Match,
    Damaged,
    Unavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestFile {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    schema: u8,
    product: String,
    version: String,
    pub files: [ManifestFile; 2],
}

pub(crate) fn parse_manifest(bytes: &[u8], version: &str) -> Option<Manifest> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let manifest: Manifest = serde_json::from_slice(bytes).ok()?;
    if manifest.schema != 1
        || manifest.product != "uac-remote-controller"
        || manifest.version != version
        || manifest.files.iter().zip(FILE_NAMES).any(|(file, name)| {
            file.name != name
                || file.bytes == 0
                || file.bytes > MAX_IMAGE_BYTES
                || file.sha256.len() != 64
                || !file
                    .sha256
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        return None;
    }
    Some(manifest)
}

/// With no usable manifest `installed` contains only structural PE observations,
/// never a claim that an image matches a trusted digest.
pub(crate) fn classify(
    manifest: ManifestState,
    installed: [FileMatch; 2],
    source: [FileMatch; 2],
) -> InstallationIntegrityView {
    let damaged: Vec<_> = FILE_NAMES
        .into_iter()
        .zip(installed)
        .filter(|(_, state)| *state == FileMatch::Damaged)
        .map(|(name, _)| name.to_owned())
        .collect();
    let state = if manifest == ManifestState::Valid {
        if installed == [FileMatch::Match; 2] {
            IntegrityStateView::Intact
        } else if damaged.is_empty() {
            IntegrityStateView::Unknown
        } else if source == [FileMatch::Match; 2] {
            IntegrityStateView::Damaged
        } else if source.contains(&FileMatch::Damaged) {
            IntegrityStateView::SourceDamaged
        } else {
            IntegrityStateView::Unknown
        }
    } else if matches!(manifest, ManifestState::Missing | ManifestState::Invalid)
        && !damaged.is_empty()
    {
        IntegrityStateView::SourceDamaged
    } else {
        IntegrityStateView::Unknown
    };
    InstallationIntegrityView { state, damaged }
}

/// A bounded first-page structure check for old installations without hashes.
/// This detects zeroed/truncated images, not malicious modifications.
pub(crate) fn plausible_pe(header: &[u8], length: u64) -> bool {
    if length > MAX_IMAGE_BYTES || header.len() < 64 || &header[..2] != b"MZ" {
        return false;
    }
    let offset = u32::from_le_bytes(header[60..64].try_into().expect("four bytes")) as usize;
    offset >= 64
        && offset.is_multiple_of(4)
        && header.get(offset..offset.saturating_add(4)) == Some(b"PE\0\0".as_slice())
}

/// Same conservative owner/ACE policy as the service installation gate. This
/// local copy is only for the fixed elevation target, not service authorization.
pub(crate) fn protected_acl(owner: &[u8], acl: &[u8], ancestor: bool) -> bool {
    fn sid(parts: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, 5];
        for part in parts {
            bytes.extend(part.to_le_bytes());
        }
        bytes
    }
    fn valid_sid(bytes: &[u8]) -> bool {
        bytes.len() >= 8
            && bytes[0] == 1
            && bytes[1] <= 15
            && bytes.len() == 8 + usize::from(bytes[1]) * 4
    }
    let trusted = [
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
    ];
    if !valid_sid(owner)
        || !trusted.iter().any(|sid| sid == owner)
        || acl.len() < 8
        || !matches!(acl[0], 2 | 4)
        || usize::from(u16::from_le_bytes([acl[2], acl[3]])) != acl.len()
    {
        return false;
    }
    let count = u16::from_le_bytes([acl[4], acl[5]]);
    if count > 4096 {
        return false;
    }
    let forbidden = 0x500d_0000 | if ancestor { 0x150 } else { 0x156 };
    let mut offset = 8;
    for _ in 0..count {
        let Some(header) = acl.get(offset..offset + 4) else {
            return false;
        };
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if !matches!(header[0], 0 | 1) || size < 16 || !size.is_multiple_of(4) {
            return false;
        }
        let Some(ace) = acl.get(offset..offset + size) else {
            return false;
        };
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        if !valid_sid(&ace[8..])
            || (header[0] == 0
                && header[1] & 0x08 == 0
                && mask & forbidden != 0
                && !trusted.iter().any(|sid| sid == &ace[8..]))
        {
            return false;
        }
        offset += size;
    }
    offset <= acl.len()
}

/// A missing process exit code must not be confused with successful repair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairOutcome {
    Repaired,
    SourceUnusable,
    Failed,
    UserCancelled,
    StillRunning,
    CompletionStatusUnknown,
}

pub const fn repair_exit_outcome(exit_code: u32) -> RepairOutcome {
    match exit_code {
        0 => RepairOutcome::Repaired,
        20 => RepairOutcome::SourceUnusable,
        _ => RepairOutcome::Failed,
    }
}

pub(crate) const fn repair_issue(source_unusable: bool) -> crate::AppIssue {
    crate::AppIssue {
        code: if source_unusable {
            "repair_source_unusable"
        } else {
            "repair_failed"
        },
        message: if source_unusable {
            "프로그램 파일과 이 PC에 보관된 원본이 모두 손상되어 여기서는 수리할 수 없습니다. 같은 버전을 다시 설치하십시오."
        } else {
            "수리하지 못했습니다. 같은 버전을 다시 설치하십시오."
        },
        next_action: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_or_missing_completion_is_unknown_not_a_partial_integrity_claim() {
        for state in [
            IntegrityStateView::Intact,
            IntegrityStateView::Damaged,
            IntegrityStateView::SourceDamaged,
            IntegrityStateView::Unknown,
        ] {
            let late = InstallationIntegrityView {
                state,
                damaged: vec![FILE_NAMES[0].to_owned()],
            };
            assert_eq!(completed_check(Some(late.clone())), late);
            // The deadline owner discards a late result before this projection.
            // No previous/partial result survives the timeout.
            let timed_out = completed_check(None);
            assert_eq!(timed_out.state, IntegrityStateView::Unknown);
            assert!(timed_out.damaged.is_empty());
        }
    }

    #[test]
    fn a_cancelled_but_outstanding_thread_never_admits_a_second_check() {
        assert_eq!(worker_admission(false, false), WorkerAdmission::Start);
        assert_eq!(worker_admission(false, true), WorkerAdmission::Start);
        // Cancellation does not mean exit. Repeated polls keep the same slot
        // busy, regardless of how many deadline/cancel requests have occurred.
        for _ in 0..10 {
            assert_eq!(worker_admission(true, false), WorkerAdmission::Busy);
        }
        // Only a signaled native thread allows reaping; it must be joined and
        // removed before a fresh operation can replace the slot.
        assert_eq!(worker_admission(true, true), WorkerAdmission::Reap);
        assert_eq!(worker_admission(false, false), WorkerAdmission::Start);
    }

    #[test]
    fn repair_target_acl_requires_a_trusted_owner_and_no_untrusted_writer() {
        let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let users = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];
        let acl = |mask: u32| {
            let mut value = vec![2, 0, 32, 0, 1, 0, 0, 0, 0, 0, 24, 0];
            value.extend(mask.to_le_bytes());
            value.extend(users);
            value
        };
        assert!(protected_acl(&system, &acl(0x0012_00a9), false));
        assert!(!protected_acl(&users, &acl(0x0012_00a9), false));
        assert!(protected_acl(&system, &acl(2), true));
        assert!(!protected_acl(&system, &acl(2), false));
        for mask in [0x1000_0000, 0x4000_0000, 0x000d_0000, 0x40, 0x100] {
            assert!(!protected_acl(&system, &acl(mask), true));
            assert!(!protected_acl(&system, &acl(mask), false));
        }
        assert!(!protected_acl(&system, &[], false));
        let mut unknown_ace = acl(0);
        unknown_ace[8] = 5;
        assert!(!protected_acl(&system, &unknown_ace, false));
    }

    #[test]
    fn classifier_covers_every_manifest_and_file_observation_combination() {
        use FileMatch::{Damaged, Match, Unavailable};
        for manifest in [
            ManifestState::Valid,
            ManifestState::Missing,
            ManifestState::Invalid,
            ManifestState::Unavailable,
        ] {
            for first in [Match, Damaged, Unavailable] {
                for second in [Match, Damaged, Unavailable] {
                    for source_first in [Match, Damaged, Unavailable] {
                        for source_second in [Match, Damaged, Unavailable] {
                            let installed = [first, second];
                            let source = [source_first, source_second];
                            let result = classify(manifest, installed, source);
                            let any_damage = installed.contains(&Damaged);
                            let expected = match manifest {
                                ManifestState::Valid if installed == [Match; 2] => {
                                    IntegrityStateView::Intact
                                }
                                ManifestState::Valid if any_damage && source == [Match; 2] => {
                                    IntegrityStateView::Damaged
                                }
                                ManifestState::Valid if any_damage && source.contains(&Damaged) => {
                                    IntegrityStateView::SourceDamaged
                                }
                                ManifestState::Missing | ManifestState::Invalid if any_damage => {
                                    IntegrityStateView::SourceDamaged
                                }
                                _ => IntegrityStateView::Unknown,
                            };
                            assert_eq!(result.state, expected);
                            assert_eq!(
                                result.damaged.contains(&FILE_NAMES[0].to_owned()),
                                first == Damaged
                            );
                            assert_eq!(
                                result.damaged.contains(&FILE_NAMES[1].to_owned()),
                                second == Damaged
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn manifest_is_closed_bounded_and_version_specific() {
        let good = serde_json::json!({
            "schema": 1, "product": "uac-remote-controller", "version": "1.9.0",
            "files": FILE_NAMES.map(|name| serde_json::json!({"name": name, "bytes": 100, "sha256": "ab".repeat(32)}))
        });
        let encoded = serde_json::to_vec(&good).unwrap();
        assert!(parse_manifest(&encoded, "1.9.0").is_some());
        assert!(parse_manifest(&encoded, "1.8.0").is_none());
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("product", serde_json::json!("other")),
            ("extra", serde_json::json!(true)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(parse_manifest(&serde_json::to_vec(&bad).unwrap(), "1.9.0").is_none());
        }
        for (field, value) in [
            ("name", serde_json::json!("../uac-service.exe")),
            ("bytes", serde_json::json!(MAX_IMAGE_BYTES + 1)),
            ("sha256", serde_json::json!("zz".repeat(32))),
        ] {
            let mut bad = good.clone();
            bad["files"][0][field] = value;
            assert!(parse_manifest(&serde_json::to_vec(&bad).unwrap(), "1.9.0").is_none());
        }
        let mut reversed = good.clone();
        reversed["files"].as_array_mut().unwrap().reverse();
        assert!(parse_manifest(&serde_json::to_vec(&reversed).unwrap(), "1.9.0").is_none());
        assert!(parse_manifest(&vec![b' '; MAX_MANIFEST_BYTES + 1], "1.9.0").is_none());
    }

    #[test]
    fn pe_fallback_rejects_zeroed_short_and_out_of_page_headers() {
        let mut header = [0_u8; 4096];
        assert!(!plausible_pe(&header, 4096));
        header[..2].copy_from_slice(b"MZ");
        header[60..64].copy_from_slice(&64_u32.to_le_bytes());
        header[64..68].copy_from_slice(b"PE\0\0");
        assert!(plausible_pe(&header, 4096));
        assert!(!plausible_pe(&header[..64], 64));
        assert!(!plausible_pe(&header, MAX_IMAGE_BYTES + 1));
        header[60..64].copy_from_slice(&4096_u32.to_le_bytes());
        assert!(!plausible_pe(&header, 4096));
    }
}
