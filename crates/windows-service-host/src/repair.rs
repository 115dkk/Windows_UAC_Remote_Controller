// SPDX-License-Identifier: GPL-2.0-or-later
//! Elevated repair orchestration over fixed protected paths and in-memory bytes.
#![forbid(unsafe_code)]

use crate::{
    ServiceError, ServiceState, ffi, ffi::ValidatedServiceInstallation,
    repair_manifest::RepairFileName,
};

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

pub(crate) fn run() -> Result<crate::RepairOutcome, ServiceError> {
    ffi::harden_repair_dll_search()?;
    ffi::require_elevated()?;
    let installation = ffi::validate_repair_installation()?;
    let maintenance = ffi::acquire_maintenance()?;
    ffi::recheck_repair_installation(&installation)?;

    let result = run_locked(&installation, &maintenance);
    let cleanup = ffi::delete_repair_staging(&installation);
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
    let sources = ffi::open_repair_source(installation, maintenance)?;
    sources.verify_running_image()?;
    let files = sources.files();
    let mut restore = Vec::new();
    let mut before = Vec::new();
    for name in files {
        let matches = ffi::open_optional_repair_target(&sources, name)
            .map_err(|_| ServiceError::UntrustedInstallation)?;
        if matches != Some(true) {
            restore.push(name);
        }
        before.push((
            name,
            if matches == Some(true) {
                TargetAfterFailure::Unchanged
            } else {
                TargetAfterFailure::DamagedReplacement
            },
        ));
    }

    // Prepare and verify every replacement before stopping the service. This runs
    // even for a missing registration and therefore leaves no stop-before-write gap.
    let staged = ffi::create_repair_target(&sources, &restore)?;
    let executable = installation.service_executable();
    let was_running = crate::native::service_running_for_repair(executable)?;
    let stop_needed = !restore.is_empty();
    let stopped = stop_needed && was_running;
    let restart_after_failure = || {
        let observe = |name| match ffi::open_optional_repair_target(&sources, name) {
            Ok(Some(true)) => TargetAfterFailure::MatchesManifest,
            Ok(_) => before
                .iter()
                .find_map(|(candidate, state)| (*candidate == name).then_some(*state))
                .unwrap_or(TargetAfterFailure::Unknown),
            Err(_) => TargetAfterFailure::Unknown,
        };
        if should_restart_after_failure(
            was_running,
            observe(RepairFileName::Service),
            observe(RepairFileName::Probe),
        ) {
            let _ = crate::native::start_for_repair(executable);
        }
    };
    if stop_needed {
        let stop_result = crate::native::stop_for_repair(executable);
        if let Err(original) = stop_result {
            if stopped {
                restart_after_failure();
            }
            return Err(original);
        }
    }

    let post_stop: Result<crate::RepairOutcome, ServiceError> = (|| {
        // The FFI consumes only its own prepared replacements and checks both
        // fixed installed leaves before allowing configuration to proceed.
        ffi::move_repair_staging(staged)?;
        crate::native::configure_installed_service(maintenance, installation)?;
        // Configuration provisioning is complete while this repair still owns the
        // maintenance lock; starting cannot overlap install or uninstall either.
        let status = crate::native::start_for_repair(executable)?;
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
                restart_after_failure();
            }
            Err(original)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
