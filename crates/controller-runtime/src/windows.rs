// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe delegation to the reviewed Windows-only service owner. No local FFI.

use std::net::SocketAddr;

use windows_service_host::{
    ControlOutcome, InstallationState, ServiceControlIntent, ServiceError, ServiceOperation,
    ServiceSnapshot, management_protocol::ManagementResponse,
};

use crate::{
    ControlHint, ManagementDevice, ManagementObservation, ObservedServiceState, PlatformAdapter,
    PlatformError, ServiceAction, ServiceCommandOutcome, ServiceObservation, ServiceState,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPlatformAdapter;

impl PlatformAdapter for WindowsPlatformAdapter {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        let status = windows_service_host::query_status().map_err(status_error)?;
        observation(status)
    }

    fn observe_management(&self) -> Result<ManagementObservation, PlatformError> {
        let ManagementResponse::Snapshot { relay, devices, .. } =
            windows_service_host::management_query().map_err(management_error)?
        else {
            return Err(PlatformError::StatusUnavailable);
        };
        Ok(ManagementObservation {
            relay_configured: relay.is_some(),
            devices: devices
                .into_iter()
                .map(|row| ManagementDevice {
                    id: device_hex(row.device.as_bytes()),
                    revision: row.revision,
                    route_present: row.route_present,
                    connected: row.connected,
                })
                .collect(),
        })
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

    fn remove_device(&self, device_id: &str) -> Result<(), PlatformError> {
        completed_mutation(remove_device_intent(device_id)?)
    }

    fn set_relay(&self, address: &str) -> Result<(), PlatformError> {
        let address = address
            .parse::<SocketAddr>()
            .map_err(|_| PlatformError::ControlFailed)?;
        completed_mutation(ServiceControlIntent::SetRelay(address))
    }
}

fn remove_device_intent(device_id: &str) -> Result<ServiceControlIntent, PlatformError> {
    if device_id.len() != 32 {
        return Err(PlatformError::ControlFailed);
    }
    let digit = |value: u8| match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(PlatformError::ControlFailed),
    };
    let mut bytes = [0; 16];
    for (output, pair) in bytes.iter_mut().zip(device_id.as_bytes().chunks_exact(2)) {
        *output = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    let mut wire = Vec::with_capacity(22);
    wire.extend_from_slice(b"UCMG");
    wire.extend_from_slice(&[1, 2]);
    wire.extend_from_slice(&bytes);
    let windows_service_host::management_protocol::ManagementRequest::RemoveDevice { device } =
        windows_service_host::management_protocol::decode_request(&wire)
            .map_err(|_| PlatformError::ControlFailed)?
    else {
        return Err(PlatformError::ControlFailed);
    };
    Ok(ServiceControlIntent::RemoveDevice(device))
}

fn completed_mutation(intent: ServiceControlIntent) -> Result<(), PlatformError> {
    match windows_service_host::request_elevated_control_from_ui(intent).map_err(control_error)? {
        ControlOutcome::Completed { .. } => Ok(()),
        ControlOutcome::UserCancelled
        | ControlOutcome::StillRunning
        | ControlOutcome::CompletionStatusUnknown
        | ControlOutcome::HelperFailed { .. } => Err(PlatformError::ControlFailed),
    }
}

fn device_hex(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 15)]));
    }
    value
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

fn management_error(error: ServiceError) -> PlatformError {
    match error {
        ServiceError::UnsupportedPlatform => PlatformError::Unsupported,
        _ => PlatformError::StatusUnavailable,
    }
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
