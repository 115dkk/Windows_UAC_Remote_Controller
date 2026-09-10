// SPDX-License-Identifier: GPL-2.0-or-later
//! The one fixed-identity Windows service's lifecycle, not remote UAC readiness.
//!
//! Read-only status is callable by presentation. Mutations require a real
//! elevated Windows token and validated protected installation; no caller can
//! supply a service name, executable, account, credential or command line.
//! Running means only SCM lifecycle operation. Windows prompt, phone, pairing,
//! credential entry and encrypted transport integrations remain unimplemented.

#![deny(unsafe_code)]

mod contract;
mod diagnostic;
mod probe_supervisor;
#[cfg(any(windows, test))]
pub mod tls_signer;
mod trust_registry;
pub use diagnostic::{
    MAX_PROBE_DIAGNOSTIC_BYTES, PROBE_CONTROL_CODE, PROBE_DIAGNOSTIC_FILES, ProbeRequestAccepted,
};
pub use probe_supervisor::{
    LaunchPrivilege, ProbeSupervisorError, ReportOutcome, ServiceProbeSupervisor, SupervisorStage,
};
pub use trust_registry::{
    CommittedRegistryChange, RegisteredDeviceKeys, RegistryError, ServiceRegistry,
};
#[cfg(any(windows, test))]
mod policy;

#[cfg(windows)]
#[allow(unsafe_code)]
mod entry;
#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;
#[cfg(windows)]
mod native;
#[cfg(windows)]
mod runtime;

pub use contract::{
    Command, ControlOutcome, InstallationState, RuntimeCapabilities, ServiceControlIntent,
    ServiceError, ServiceOperation, ServiceSnapshot, ServiceState, SetupFailure,
};

pub const SERVICE_NAME: &str = "UacRemoteController";
pub const SERVICE_DISPLAY_NAME: &str = "휴대폰 승인";
pub const INSTALLATION_FOLDER: &str = "휴대폰 승인";
pub const SERVICE_EXECUTABLE: &str = "uac-service.exe";

/// Query this service only, without requesting elevation or changing Windows.
/// `NotInstalled` is returned only for ERROR_SERVICE_DOES_NOT_EXIST.
pub fn query_status() -> Result<ServiceSnapshot, ServiceError> {
    #[cfg(windows)]
    {
        native::query_status()
    }
    #[cfg(not(windows))]
    {
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Explicit elevated CLI diagnostic only. Accepted means queued, not observed,
/// stored, authenticated, approved or applied. No UI intent exposes this call.
pub fn request_probe_once() -> Result<ProbeRequestAccepted, ServiceError> {
    #[cfg(windows)]
    {
        native::request_probe_once()
    }
    #[cfg(not(windows))]
    {
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Read-only presentation preflight for the fixed, protected control helper.
/// Absence is not a trust success; a later action always validates again while
/// retaining its own path pins. This function never requests Windows elevation.
pub fn is_control_helper_available() -> Result<bool, ServiceError> {
    #[cfg(windows)]
    {
        match ffi::validate_installation(false) {
            Ok(installation) => {
                native::verify_ui_helper_target(installation.executable())?;
                Ok(true)
            }
            Err(ServiceError::WindowsCall {
                operation: ServiceOperation::OpenProtectedPath,
                code: 2 | 3 | 0x8007_0002 | 0x8007_0003,
            }) => Ok(false),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(windows))]
    {
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// User-triggered Windows elevation for the fixed installed helper. Run on a
/// background UI task: Windows owns the consent prompt; after consent the helper
/// process wait is bounded. Launch is never equated with operation completion.
/// This function is never invoked automatically by `status` or CLI mutations.
pub fn request_elevated_control_from_ui(
    intent: ServiceControlIntent,
) -> Result<ControlOutcome, ServiceError> {
    #[cfg(windows)]
    {
        ffi::request_elevated_control(intent)
    }
    #[cfg(not(windows))]
    {
        let _ = intent;
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Explicit elevated registration from the fixed protected installation only.
pub fn install() -> Result<ServiceSnapshot, ServiceError> {
    mutation(Command::Install)
}

pub fn start() -> Result<ServiceSnapshot, ServiceError> {
    mutation(Command::Start)
}

pub fn stop() -> Result<ServiceSnapshot, ServiceError> {
    mutation(Command::Stop)
}

pub fn restart() -> Result<ServiceSnapshot, ServiceError> {
    mutation(Command::Restart)
}

/// Deletes only the validated service registration, never installation files.
pub fn uninstall() -> Result<ServiceSnapshot, ServiceError> {
    mutation(Command::Uninstall)
}

fn mutation(command: Command) -> Result<ServiceSnapshot, ServiceError> {
    #[cfg(windows)]
    {
        native::mutate(command)
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Join the real SCM dispatcher. This is not an interactive daemon fallback.
pub fn dispatch_service() -> Result<(), ServiceError> {
    #[cfg(windows)]
    {
        entry::dispatch()
    }
    #[cfg(not(windows))]
    {
        Err(ServiceError::UnsupportedPlatform)
    }
}
