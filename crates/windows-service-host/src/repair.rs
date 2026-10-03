// SPDX-License-Identifier: GPL-2.0-or-later
//! Elevated repair orchestration over fixed protected paths and in-memory bytes.
#![forbid(unsafe_code)]

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::{
    SERVICE_EXECUTABLE, ServiceError, ffi,
    repair_manifest::{self, RepairFile, RepairFileName},
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
const STAGING_SUFFIX: &str = ".repair-new";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetObservation {
    Missing,
    Checked { hash_matches: bool },
    CheckFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetDecision {
    Restore,
    Skip,
    Fail,
}

const fn decide_target(observation: TargetObservation) -> TargetDecision {
    match observation {
        TargetObservation::Missing
        | TargetObservation::Checked {
            hash_matches: false,
        } => TargetDecision::Restore,
        TargetObservation::Checked { hash_matches: true } => TargetDecision::Skip,
        TargetObservation::CheckFailed => TargetDecision::Fail,
    }
}

struct SourceImage {
    manifest: RepairFile,
    bytes: Vec<u8>,
}

pub(crate) fn run() -> Result<crate::RepairOutcome, ServiceError> {
    ffi::require_elevated()?;
    let installation = ffi::validate_repair_installation()?;
    let maintenance = ffi::acquire_maintenance()?;
    // The installation and repair directory pins predate the mutex. Revalidate
    // them under the lock before trusting any descendant I/O.
    ffi::recheck_repair_installation(&installation)?;

    let manifest = read_manifest(&installation)?;
    let sources = manifest
        .files()
        .into_iter()
        .map(|file| read_source(&installation, file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(source_error)?;
    // The current image was identity-pinned before manifest I/O. Its bytes must
    // now match the protected service entry before this repairer changes anything.
    let service_source = sources
        .iter()
        .find(|source| source.manifest.name() == RepairFileName::Service)
        .ok_or(ServiceError::RepairSourceUnusable)?;
    let current = std::env::current_exe().map_err(|_| ServiceError::RepairSourceUnusable)?;
    verify_source_identity(&installation, &current, service_source.manifest)?;

    let mut restore = Vec::new();
    for source in &sources {
        match inspect_target(&installation, source) {
            Ok(TargetDecision::Restore) => restore.push(source.manifest.name()),
            Ok(TargetDecision::Skip) => {}
            Ok(TargetDecision::Fail) | Err(_) => return Err(ServiceError::UntrustedInstallation),
        }
    }

    if !restore.is_empty() {
        crate::native::stop_for_repair()?;
        for name in &restore {
            let source = sources
                .iter()
                .find(|source| source.manifest.name() == *name)
                .ok_or(ServiceError::UnexpectedState)?;
            restore_target(&installation, source)?;
        }
    }

    let main = installation.target(SERVICE_EXECUTABLE);
    for source in &sources {
        let target = installation.target(source.manifest.name().as_str());
        verify_target(&installation, &target, source.manifest)?;
    }

    // `install` takes the same mutex. Release our guard before creating the fixed
    // child to avoid self-deadlock. The protected directory pins remain alive and
    // both targets were reopened and re-hashed immediately before release.
    drop(maintenance);
    ffi::run_repair_child(&main, ffi::RepairChildVerb::Install, CHILD_TIMEOUT)?;
    ffi::run_repair_child(&main, ffi::RepairChildVerb::Start, CHILD_TIMEOUT)?;
    let status = crate::query_status()?;
    if status.installation != crate::InstallationState::Installed
        || status.state != Some(crate::ServiceState::Running)
    {
        return Err(ServiceError::UnexpectedState);
    }

    Ok(crate::RepairOutcome::new(
        restore.into_iter().map(RepairFileName::as_str).collect(),
    ))
}

fn source_error(_: ServiceError) -> ServiceError {
    ServiceError::RepairSourceUnusable
}

fn read_manifest(
    installation: &ffi::ValidatedRepairInstallation,
) -> Result<repair_manifest::RepairManifest, ServiceError> {
    let path = installation.manifest();
    let pin = ffi::open_repair_source(installation, &path)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    let bytes = ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_MANIFEST_BYTES)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    ffi::verify_repair_target(installation, &path, &pin)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    repair_manifest::parse(&bytes).map_err(|_| ServiceError::RepairSourceUnusable)
}

fn read_source(
    installation: &ffi::ValidatedRepairInstallation,
    manifest: RepairFile,
) -> Result<SourceImage, ServiceError> {
    let path = installation.source(manifest.name().as_str());
    let pin = ffi::open_repair_source(installation, &path)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    let bytes = ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    ffi::verify_repair_target(installation, &path, &pin)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    if bytes.len() as u64 != manifest.bytes()
        || digest(&bytes) != manifest.sha256()
        || !ffi::pe_header_is_plausible(&bytes)
    {
        return Err(ServiceError::RepairSourceUnusable);
    }
    Ok(SourceImage { manifest, bytes })
}

fn verify_source_identity(
    installation: &ffi::ValidatedRepairInstallation,
    path: &std::path::Path,
    expected: RepairFile,
) -> Result<(), ServiceError> {
    let pin = ffi::open_repair_source(installation, path)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    let bytes = ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    ffi::verify_repair_target(installation, path, &pin)
        .map_err(|_| ServiceError::RepairSourceUnusable)?;
    if bytes.len() as u64 != expected.bytes()
        || digest(&bytes) != expected.sha256()
        || !ffi::pe_header_is_plausible(&bytes)
    {
        return Err(ServiceError::RepairSourceUnusable);
    }
    Ok(())
}

fn inspect_target(
    installation: &ffi::ValidatedRepairInstallation,
    source: &SourceImage,
) -> Result<TargetDecision, ServiceError> {
    let path = installation.target(source.manifest.name().as_str());
    let pin = match ffi::open_optional_repair_target(installation, &path) {
        Ok(Some(pin)) => pin,
        Ok(None) => return Ok(decide_target(TargetObservation::Missing)),
        Err(_) => return Ok(decide_target(TargetObservation::CheckFailed)),
    };
    let bytes = match ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(ServiceError::RepairSourceUnusable) => {
            ffi::verify_repair_target(installation, &path, &pin)?;
            return Ok(decide_target(TargetObservation::Checked {
                hash_matches: false,
            }));
        }
        Err(error) => return Err(error),
    };
    ffi::verify_repair_target(installation, &path, &pin)?;
    Ok(decide_target(TargetObservation::Checked {
        hash_matches: bytes.len() as u64 == source.manifest.bytes()
            && digest(&bytes) == source.manifest.sha256()
            && ffi::pe_header_is_plausible(&bytes),
    }))
}

fn restore_target(
    installation: &ffi::ValidatedRepairInstallation,
    source: &SourceImage,
) -> Result<(), ServiceError> {
    let target = installation.target(source.manifest.name().as_str());
    let staging = installation.target(&format!(
        "{}{STAGING_SUFFIX}",
        source.manifest.name().as_str()
    ));
    ffi::recheck_repair_installation(installation)?;
    ffi::delete_repair_staging(installation, &staging)?;
    let result = (|| {
        let output = ffi::create_repair_target(installation, &staging)?;
        ffi::write_all_and_flush(&output, &source.bytes)?;
        drop(output);
        // A default descriptor inherits from the pinned installation directory;
        // this reopen applies the same protected ACL and no-reparse checks used by
        // every source and target before the staging name can replace anything.
        verify_target(installation, &staging, source.manifest)?;
        ffi::move_repair_staging(installation, &staging, &target)?;
        verify_target(installation, &target, source.manifest)
    })();
    if result.is_err() {
        // Best-effort cleanup is allowed only for the exact staging leaf and uses
        // the same protected open gate. The original failure remains authoritative.
        let _ = ffi::delete_repair_staging(installation, &staging);
    }
    result
}

fn verify_target(
    installation: &ffi::ValidatedRepairInstallation,
    target: &std::path::Path,
    expected: RepairFile,
) -> Result<(), ServiceError> {
    let pin = ffi::open_optional_repair_target(installation, target)?
        .ok_or(ServiceError::UnexpectedState)?;
    let bytes = match ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            ffi::verify_repair_target(installation, target, &pin)?;
            return Err(match error {
                ServiceError::RepairSourceUnusable => ServiceError::UnexpectedState,
                other => other,
            });
        }
    };
    ffi::verify_repair_target(installation, target, &pin)?;
    if bytes.len() as u64 != expected.bytes()
        || digest(&bytes) != expected.sha256()
        || !ffi::pe_header_is_plausible(&bytes)
    {
        return Err(ServiceError::UnexpectedState);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_matching_target_is_skipped() {
        assert_eq!(
            decide_target(TargetObservation::Checked { hash_matches: true }),
            TargetDecision::Skip
        );
    }

    #[test]
    fn missing_or_hash_mismatched_target_is_restored() {
        assert_eq!(
            decide_target(TargetObservation::Missing),
            TargetDecision::Restore
        );
        assert_eq!(
            decide_target(TargetObservation::Checked {
                hash_matches: false
            }),
            TargetDecision::Restore
        );
    }

    #[test]
    fn target_that_fails_protected_open_is_never_overwritten() {
        assert_eq!(
            decide_target(TargetObservation::CheckFailed),
            TargetDecision::Fail
        );
    }
}
