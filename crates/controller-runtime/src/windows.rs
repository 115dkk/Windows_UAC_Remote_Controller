// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe delegation to the reviewed Windows-only service owner. No local FFI.

use windows_service_host::{
    ControlOutcome, InstallationState, ServiceControlIntent, ServiceError, ServiceOperation,
    ServiceSnapshot,
};

use crate::{
    ControlHint, ObservedServiceState, PlatformAdapter, PlatformError, ServiceAction,
    ServiceCommandOutcome, ServiceObservation, ServiceState,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPlatformAdapter;

impl PlatformAdapter for WindowsPlatformAdapter {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        let status = windows_service_host::query_status().map_err(status_error)?;
        observation(status)
    }

    fn control_service(
        &self,
        action: ServiceAction,
    ) -> Result<ServiceCommandOutcome, PlatformError> {
        // The native function independently revalidates the fixed protected
        // helper and SCM identity for every explicit user action. It never
        // receives a path, administrator boolean or arbitrary argument.
        let intent = match action {
            ServiceAction::Install => ServiceControlIntent::Install,
            ServiceAction::Start => ServiceControlIntent::Start,
            ServiceAction::Stop => ServiceControlIntent::Stop,
            ServiceAction::Restart => ServiceControlIntent::Restart,
            ServiceAction::Uninstall => ServiceControlIntent::Uninstall,
        };
        let result = match windows_service_host::request_elevated_control_from_ui(intent) {
            Ok(result) => result,
            // A wait/exit-code read error happens after helper launch. Never
            // treat it as a definitely-not-started command that can be retried.
            Err(ServiceError::WindowsCall {
                operation: ServiceOperation::WaitElevatedHelper,
                ..
            }) => {
                return Ok(ServiceCommandOutcome::CompletionStatusUnknown);
            }
            Err(error) => return Err(control_error(error)),
        };
        Ok(match result {
            ControlOutcome::UserCancelled => ServiceCommandOutcome::UserCancelled,
            ControlOutcome::StillRunning => ServiceCommandOutcome::StillRunning,
            ControlOutcome::CompletionStatusUnknown => {
                ServiceCommandOutcome::CompletionStatusUnknown
            }
            ControlOutcome::HelperFailed { .. } => ServiceCommandOutcome::HelperFailed,
            ControlOutcome::Completed { snapshot } => match observation(snapshot) {
                Ok(observation) => ServiceCommandOutcome::Completed { observation },
                Err(_) => ServiceCommandOutcome::CompletionStatusUnknown,
            },
        })
    }
}

fn observation(status: ServiceSnapshot) -> Result<ServiceObservation, PlatformError> {
    let state = match (status.installation, status.state) {
        (InstallationState::NotInstalled, None) => ObservedServiceState::NotInstalled,
        (InstallationState::Installed, Some(state)) => {
            ObservedServiceState::Installed(match state {
                windows_service_host::ServiceState::Stopped => ServiceState::Stopped,
                windows_service_host::ServiceState::StartPending => ServiceState::StartPending,
                windows_service_host::ServiceState::StopPending => ServiceState::StopPending,
                windows_service_host::ServiceState::Running => ServiceState::Running,
                windows_service_host::ServiceState::ContinuePending => {
                    ServiceState::ContinuePending
                }
                windows_service_host::ServiceState::PausePending => ServiceState::PausePending,
                windows_service_host::ServiceState::Paused => ServiceState::Paused,
            })
        }
        // Do not turn an inconsistent owner snapshot into a supported UI state.
        _ => return Err(PlatformError::StatusUnavailable),
    };
    let control = windows_service_host::is_control_helper_available()
        .map(|available| {
            if available {
                ControlHint::Available
            } else {
                ControlHint::NeedsInstaller
            }
        })
        .map_err(|_| PlatformError::HelperUnavailable);
    Ok(ServiceObservation { state, control })
}

fn status_error(error: ServiceError) -> PlatformError {
    match error {
        ServiceError::UnsupportedPlatform => PlatformError::Unsupported,
        _ => PlatformError::StatusUnavailable,
    }
}

fn control_error(error: ServiceError) -> PlatformError {
    match error {
        ServiceError::UnsupportedPlatform => PlatformError::Unsupported,
        ServiceError::UntrustedInstallation
        | ServiceError::UnsafePath
        | ServiceError::UnsafePermissions
        | ServiceError::ConfigurationConflict => PlatformError::HelperUnavailable,
        _ => PlatformError::ControlFailed,
    }
}
