// SPDX-License-Identifier: GPL-2.0-or-later
//! Elevated repair orchestration over fixed protected paths and in-memory bytes.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::{
    SERVICE_EXECUTABLE, ServiceError, ServiceState, ffi,
    repair_manifest::{self, RepairFile, RepairFileName},
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetAfterFailure {
    MatchesManifest,
    Unchanged,
    DamagedReplacement,
    Unknown,
}

const fn should_restart_after_failure(
    was_running: bool,
    service: TargetAfterFailure,
    probe: TargetAfterFailure,
) -> bool {
    was_running
        && matches!(
            service,
            TargetAfterFailure::MatchesManifest | TargetAfterFailure::Unchanged
        )
        && matches!(
            probe,
            TargetAfterFailure::MatchesManifest | TargetAfterFailure::Unchanged
        )
}

struct SourceImage {
    manifest: RepairFile,
    bytes: Vec<u8>,
}

struct StagedImage {
    name: RepairFileName,
    path: std::path::PathBuf,
}

pub(crate) fn run() -> Result<crate::RepairOutcome, ServiceError> {
    ffi::harden_repair_dll_search()?;
    ffi::require_elevated()?;
    let installation = ffi::validate_repair_installation()?;
    let maintenance = ffi::acquire_maintenance()?;
    ffi::recheck_repair_installation(&installation)?;

    let result = run_locked(&installation, &maintenance);
    let cleanup = cleanup_staging(&installation);
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(original), _) => Err(original),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn run_locked(
    installation: &ffi::ValidatedRepairInstallation,
    maintenance: &ffi::MaintenanceGuard,
) -> Result<crate::RepairOutcome, ServiceError> {
    let manifest = read_manifest(installation)?;
    let sources = manifest
        .files()
        .into_iter()
        .map(|file| read_source(installation, file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(source_error)?;

    let service_source = sources
        .iter()
        .find(|source| source.manifest.name() == RepairFileName::Service)
        .ok_or(ServiceError::RepairSourceUnusable)?;
    let current = std::env::current_exe().map_err(|_| ServiceError::RepairSourceUnusable)?;
    verify_source_identity(installation, &current, service_source.manifest)?;

    let mut restore = Vec::new();
    let mut before = Vec::new();
    for source in &sources {
        match inspect_target(installation, source) {
            Ok((TargetDecision::Restore, state)) => {
                restore.push(source.manifest.name());
                before.push((source.manifest.name(), state));
            }
            Ok((TargetDecision::Skip, state)) => {
                before.push((source.manifest.name(), state));
            }
            Ok((TargetDecision::Fail, _)) | Err(_) => {
                return Err(ServiceError::UntrustedInstallation);
            }
        }
    }

    // Prepare and verify every replacement before stopping the service. This runs
    // even for a missing registration and therefore leaves no stop-before-write gap.
    let staged = prepare_staging(installation, &sources, &restore)?;
    let executable = installation.target(SERVICE_EXECUTABLE);
    let was_running = crate::native::service_running_for_repair(&executable)?;
    let stop_needed = !restore.is_empty();
    let stopped = stop_needed && was_running;
    if stop_needed {
        let stop_result = crate::native::stop_for_repair(&executable);
        if let Err(original) = stop_result {
            if stopped {
                restart_after_failure_if_safe(
                    installation,
                    &sources,
                    &before,
                    was_running,
                    &executable,
                );
            }
            return Err(original);
        }
    }

    let post_stop: Result<crate::RepairOutcome, ServiceError> = (|| {
        for image in &staged {
            let target = installation.target(image.name.as_str());
            let source = source_for(&sources, image.name)?;
            verify_target(installation, &image.path, source.manifest)?;
            ffi::move_repair_staging(installation, &image.path, &target)?;
            verify_target(installation, &target, source.manifest)?;
        }

        for source in &sources {
            let target = installation.target(source.manifest.name().as_str());
            verify_target(installation, &target, source.manifest)?;
        }

        // Both installed executable leaves were reopened, hashed and PE-checked
        // immediately above; the repair installation proof retains their parent.
        crate::native::configure_installed_service(maintenance, installation)?;
        // Configuration provisioning is complete while this repair still owns the
        // maintenance lock; starting cannot overlap install or uninstall either.
        let status = crate::native::start_for_repair(&executable)?;
        if status.state != Some(ServiceState::Running) {
            return Err(ServiceError::UnexpectedState);
        }
        Ok(crate::RepairOutcome::new(
            restore.into_iter().map(RepairFileName::as_str).collect(),
        ))
    })();

    match post_stop {
        Ok(outcome) => Ok(outcome),
        Err(original) => {
            if stopped {
                restart_after_failure_if_safe(
                    installation,
                    &sources,
                    &before,
                    was_running,
                    &executable,
                );
            }
            Err(original)
        }
    }
}

fn source_for(sources: &[SourceImage], name: RepairFileName) -> Result<&SourceImage, ServiceError> {
    sources
        .iter()
        .find(|source| source.manifest.name() == name)
        .ok_or(ServiceError::UnexpectedState)
}

fn prepare_staging(
    installation: &ffi::ValidatedRepairInstallation,
    sources: &[SourceImage],
    restore: &[RepairFileName],
) -> Result<Vec<StagedImage>, ServiceError> {
    let mut staged = Vec::new();
    let prepared: Result<Vec<StagedImage>, ServiceError> = (|| {
        for name in restore {
            let source = source_for(sources, *name)?;
            let path = staging_path(installation, *name);
            ffi::delete_repair_staging(installation, &path)?;
            let output = ffi::create_repair_target(installation, &path)?;
            ffi::write_all_and_flush(&output, &source.bytes)?;
            drop(output);
            verify_target(installation, &path, source.manifest)?;
            staged.push(StagedImage { name: *name, path });
        }
        Ok(staged)
    })();
    if prepared.is_err() {
        let _ = cleanup_staging(installation);
    }
    prepared
}

fn cleanup_staging(installation: &ffi::ValidatedRepairInstallation) -> Result<(), ServiceError> {
    let mut failure = None;
    for name in [RepairFileName::Service, RepairFileName::Probe] {
        let path = staging_path(installation, name);
        if let Err(error) = ffi::delete_repair_staging(installation, &path) {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

fn staging_path(
    installation: &ffi::ValidatedRepairInstallation,
    name: RepairFileName,
) -> std::path::PathBuf {
    installation.target(&format!("{}{STAGING_SUFFIX}", name.as_str()))
}

fn restart_after_failure_if_safe(
    installation: &ffi::ValidatedRepairInstallation,
    sources: &[SourceImage],
    before: &[(RepairFileName, TargetAfterFailure)],
    was_running: bool,
    executable: &std::path::Path,
) {
    let service = observe_after_failure(installation, sources, before, RepairFileName::Service);
    let probe = observe_after_failure(installation, sources, before, RepairFileName::Probe);
    if should_restart_after_failure(was_running, service, probe) {
        let _ = crate::native::start_for_repair(executable);
    }
}

fn observe_after_failure(
    installation: &ffi::ValidatedRepairInstallation,
    sources: &[SourceImage],
    before: &[(RepairFileName, TargetAfterFailure)],
    name: RepairFileName,
) -> TargetAfterFailure {
    let Ok(source) = source_for(sources, name) else {
        return TargetAfterFailure::Unknown;
    };
    let path = installation.target(name.as_str());
    match target_hash_matches(installation, &path, source.manifest) {
        Ok(true) => TargetAfterFailure::MatchesManifest,
        Ok(false) => before
            .iter()
            .find_map(|(candidate, state)| (*candidate == name).then_some(*state))
            .unwrap_or(TargetAfterFailure::Unknown),
        Err(_) => TargetAfterFailure::Unknown,
    }
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
) -> Result<(TargetDecision, TargetAfterFailure), ServiceError> {
    let path = installation.target(source.manifest.name().as_str());
    let pin = match ffi::open_optional_repair_target(installation, &path) {
        Ok(Some(pin)) => pin,
        Ok(None) => {
            return Ok((
                decide_target(TargetObservation::Missing),
                TargetAfterFailure::DamagedReplacement,
            ));
        }
        Err(_) => {
            return Ok((
                decide_target(TargetObservation::CheckFailed),
                TargetAfterFailure::Unknown,
            ));
        }
    };
    let bytes = match ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(ServiceError::RepairSourceUnusable) => {
            ffi::verify_repair_target(installation, &path, &pin)?;
            return Ok((
                decide_target(TargetObservation::Checked {
                    hash_matches: false,
                }),
                TargetAfterFailure::DamagedReplacement,
            ));
        }
        Err(error) => return Err(error),
    };
    ffi::verify_repair_target(installation, &path, &pin)?;
    let hash_matches = bytes.len() as u64 == source.manifest.bytes()
        && digest(&bytes) == source.manifest.sha256()
        && ffi::pe_header_is_plausible(&bytes);
    Ok((
        decide_target(TargetObservation::Checked { hash_matches }),
        if hash_matches {
            TargetAfterFailure::Unchanged
        } else {
            TargetAfterFailure::DamagedReplacement
        },
    ))
}

fn target_hash_matches(
    installation: &ffi::ValidatedRepairInstallation,
    target: &std::path::Path,
    expected: RepairFile,
) -> Result<bool, ServiceError> {
    let Some(pin) = ffi::open_optional_repair_target(installation, target)? else {
        return Ok(false);
    };
    let bytes = match ffi::read_bounded(&pin, repair_manifest::MAX_REPAIR_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(ServiceError::RepairSourceUnusable) => {
            ffi::verify_repair_target(installation, target, &pin)?;
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    ffi::verify_repair_target(installation, target, &pin)?;
    Ok(bytes.len() as u64 == expected.bytes()
        && digest(&bytes) == expected.sha256()
        && ffi::pe_header_is_plausible(&bytes))
}

fn verify_target(
    installation: &ffi::ValidatedRepairInstallation,
    target: &std::path::Path,
    expected: RepairFile,
) -> Result<(), ServiceError> {
    if target_hash_matches(installation, target, expected)? {
        Ok(())
    } else {
        Err(ServiceError::UnexpectedState)
    }
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

    #[test]
    fn post_failure_restart_requires_previous_running_and_two_safe_targets() {
        use TargetAfterFailure::{
            DamagedReplacement as Damaged, MatchesManifest as Matches, Unchanged, Unknown,
        };
        assert!(should_restart_after_failure(true, Matches, Matches));
        assert!(should_restart_after_failure(true, Matches, Unchanged));
        assert!(should_restart_after_failure(true, Unchanged, Matches));
        assert!(should_restart_after_failure(true, Unchanged, Unchanged));
        assert!(!should_restart_after_failure(false, Matches, Matches));
        for unsafe_state in [Damaged, Unknown] {
            assert!(!should_restart_after_failure(true, unsafe_state, Matches));
            assert!(!should_restart_after_failure(true, Matches, unsafe_state));
        }
    }
}
