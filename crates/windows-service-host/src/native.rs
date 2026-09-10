// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe SCM orchestration. FFI and protected-path proofs stay in private modules.
#![forbid(unsafe_code)]

use std::{
    ffi::{OsStr, OsString},
    path::Path,
    thread,
    time::Instant,
};
use windows::Win32::Foundation::{
    ERROR_BUSY, ERROR_NO_MORE_FILES, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceConfig, ServiceControlAccept, ServiceErrorControl,
        ServiceInfo, ServiceSidType, ServiceStartType, ServiceState as NativeState, ServiceStatus,
        ServiceType, UserEventCode,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{
    Command, SERVICE_DISPLAY_NAME, SERVICE_NAME, ServiceError, ServiceOperation, ServiceSnapshot,
    ServiceState,
    contract::{POLL_INTERVAL, incomplete, remaining_budget},
    ffi, policy,
};

pub(crate) fn scm_error(
    operation: ServiceOperation,
    error: windows_service::Error,
) -> ServiceError {
    match error {
        windows_service::Error::Winapi(error) => match error.raw_os_error() {
            Some(code) => ServiceError::WindowsCall {
                operation,
                code: code as u32,
            },
            None => ServiceError::UnsupportedResult(operation),
        },
        _ => ServiceError::UnsupportedResult(operation),
    }
}

fn is_code(error: &windows_service::Error, expected: u32) -> bool {
    matches!(error, windows_service::Error::Winapi(error)
        if error.raw_os_error().is_some_and(|value| value as u32 == expected))
}

fn manager(create: bool) -> Result<ServiceManager, ServiceError> {
    let access = if create {
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    } else {
        ServiceManagerAccess::CONNECT
    };
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|e| scm_error(ServiceOperation::OpenManager, e))
}

fn open(manager: &ServiceManager, access: ServiceAccess) -> Result<Option<Service>, ServiceError> {
    match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(error) if is_code(&error, ERROR_SERVICE_DOES_NOT_EXIST.0) => Ok(None),
        Err(error) => Err(scm_error(ServiceOperation::OpenService, error)),
    }
}

fn status(service: &Service) -> Result<ServiceStatus, ServiceError> {
    service
        .query_status()
        .map_err(|e| scm_error(ServiceOperation::QueryStatus, e))
}

fn snapshot(status: ServiceStatus) -> ServiceSnapshot {
    let raw_running = status.current_state == NativeState::Running;
    let initialized = initialization_complete(&status);
    let state = match status.current_state {
        NativeState::Stopped => ServiceState::Stopped,
        NativeState::StartPending => ServiceState::StartPending,
        NativeState::StopPending => ServiceState::StopPending,
        NativeState::Running if !initialized => ServiceState::StartPending,
        NativeState::Running => ServiceState::Running,
        NativeState::ContinuePending => ServiceState::ContinuePending,
        NativeState::PausePending => ServiceState::PausePending,
        NativeState::Paused => ServiceState::Paused,
    };
    let mut snapshot = ServiceSnapshot::installed(state, status.process_id);
    // Product lifecycle is pending while raw SCM Running accepts no readiness
    // controls. A nonzero PID is valid here ONLY because the raw state is Running;
    // do not widen the shared constructor's filter for raw StartPending/Stopped.
    if raw_running && !initialized {
        snapshot.process_id = status.process_id.filter(|pid| *pid != 0);
    }
    snapshot
}

fn initialization_complete(status: &ServiceStatus) -> bool {
    status.current_state == NativeState::Running
        && status
            .controls_accepted
            .contains(ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)
}

fn verify_config(
    service: &Service,
    executable: &Path,
    allow_disabled: bool,
) -> Result<ServiceConfig, ServiceError> {
    let config = service
        .query_config()
        .map_err(|e| scm_error(ServiceOperation::QueryConfiguration, e))?;
    let binary = config
        .executable_path
        .to_str()
        .ok_or(ServiceError::ConfigurationConflict)?;
    let expected = executable.to_str().ok_or(ServiceError::UnsafePath)?;
    if !policy::command_matches(binary, expected)
        || config.service_type != ServiceType::OWN_PROCESS
        || config.account_name.as_deref() != Some(OsStr::new("LocalSystem"))
        || config.display_name != OsStr::new(SERVICE_DISPLAY_NAME)
        || !config.dependencies.is_empty()
        || config.load_order_group.is_some()
        || config.error_control != ServiceErrorControl::Normal
        || !(config.start_type == ServiceStartType::AutoStart
            || (allow_disabled && config.start_type == ServiceStartType::Disabled))
    {
        return Err(ServiceError::ConfigurationConflict);
    }
    Ok(config)
}

pub(crate) fn verify_ui_helper_target(executable: &Path) -> Result<(), ServiceError> {
    if let Some(service) = open(&manager(false)?, ServiceAccess::QUERY_CONFIG)? {
        verify_config(&service, executable, true)?;
    }
    Ok(())
}

/// A dormant supervisor must be this exact running SCM process, not merely an
/// elevated or SYSTEM process. No service configuration is changed here.
#[cfg(target_pointer_width = "64")]
pub(crate) fn running_service_for_probe(executable: &Path) -> Result<Service, ServiceError> {
    let service = open(
        &manager(false)?,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG | ServiceAccess::READ_CONTROL,
    )?
    .ok_or(ServiceError::NotInstalled)?;
    verify_config(&service, executable, false)?;
    ffi::verify_service_security(&service)?;
    if service
        .get_config_service_sid_info()
        .map_err(|error| scm_error(ServiceOperation::QueryConfiguration, error))?
        != ServiceSidType::Restricted
    {
        return Err(ServiceError::ConfigurationConflict);
    }
    let observed = status(&service)?;
    if observed.current_state != NativeState::Running
        || observed.process_id != Some(std::process::id())
    {
        return Err(ServiceError::ConfigurationConflict);
    }
    Ok(service)
}

pub(crate) fn query_status() -> Result<ServiceSnapshot, ServiceError> {
    let manager = manager(false)?;
    let Some(service) = open(
        &manager,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    )?
    else {
        return Ok(ServiceSnapshot::absent());
    };
    // Read-only users need only the two explicitly allowed SCM query rights.
    // A name collision is an error, never this product's fabricated status.
    verify_config(&service, &ffi::expected_executable()?, true)?;
    Ok(snapshot(status(&service)?))
}

pub(crate) fn request_probe_once() -> Result<crate::ProbeRequestAccepted, ServiceError> {
    ffi::require_elevated()?;
    // Only the fixed installed helper may issue this CLI diagnostic. A caller
    // cannot redirect the service or promote a workspace/download executable.
    let installation = ffi::validate_installation(true)?;
    let service = open(
        &manager(false)?,
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::QUERY_CONFIG
            | ServiceAccess::READ_CONTROL
            | ServiceAccess::USER_DEFINED_CONTROL,
    )?
    .ok_or(ServiceError::NotInstalled)?;
    verify_config(&service, installation.executable(), false)?;
    ffi::verify_service_security(&service)?;
    if service
        .get_config_service_sid_info()
        .map_err(|e| scm_error(ServiceOperation::QueryConfiguration, e))?
        != ServiceSidType::Restricted
    {
        return Err(ServiceError::ConfigurationConflict);
    }
    let before = status(&service)?;
    let pid = before
        .process_id
        .filter(|pid| *pid != 0 && before.current_state == NativeState::Running)
        .ok_or(ServiceError::UnexpectedState)?;
    let code = UserEventCode::from_raw(crate::PROBE_CONTROL_CODE)
        .map_err(|_| ServiceError::InvalidArguments)?;
    match service.notify(code) {
        Ok(_) => (),
        Err(error) if is_code(&error, ERROR_BUSY.0) => return Err(ServiceError::ProbeBusy),
        Err(error) if is_code(&error, ERROR_NO_MORE_FILES.0) => {
            return Err(ServiceError::ProbeSlotsFull);
        }
        Err(error) if is_code(&error, ERROR_SERVICE_CANNOT_ACCEPT_CTRL.0) => {
            return Err(ServiceError::ProbeUnavailable);
        }
        Err(error) => return Err(scm_error(ServiceOperation::RequestProbe, error)),
    }
    let after = status(&service)?;
    if after.current_state != NativeState::Running || after.process_id != Some(pid) {
        return Err(ServiceError::UnexpectedState);
    }
    Ok(crate::ProbeRequestAccepted::new(pid))
}

/// Startup admission check only: Running may still advertise no accepted controls.
/// The callback is enabled only after the worker's full Ready event; every actual
/// probe independently verifies the running registration and its own service PID.
pub(crate) fn probe_control_registration_ready(executable: &Path) -> Result<(), ServiceError> {
    let service = open(
        &manager(false)?,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::READ_CONTROL,
    )?
    .ok_or(ServiceError::NotInstalled)?;
    verify_config(&service, executable, false)?;
    ffi::verify_service_security(&service)?;
    if service
        .get_config_service_sid_info()
        .map_err(|e| scm_error(ServiceOperation::QueryConfiguration, e))?
        != ServiceSidType::Restricted
    {
        return Err(ServiceError::ConfigurationConflict);
    }
    Ok(())
}

fn service_info(executable: &Path, start_type: ServiceStartType) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable.to_path_buf(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

pub(crate) fn mutate(command: Command) -> Result<ServiceSnapshot, ServiceError> {
    // Every explicit mutation, including an idempotent no-op, is gated by the
    // OS token. SCM access remains the final independent permission check.
    ffi::require_elevated()?;
    if command == Command::Install {
        return install();
    }
    let access = match command {
        Command::Start => ServiceAccess::START,
        Command::Stop => ServiceAccess::STOP,
        Command::Restart => ServiceAccess::START | ServiceAccess::STOP,
        Command::Uninstall => ServiceAccess::STOP | ServiceAccess::DELETE,
        _ => return Err(ServiceError::InvalidArguments),
    } | ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::READ_CONTROL;
    let manager = manager(false)?;
    let Some(service) = open(&manager, access)? else {
        return if matches!(command, Command::Stop | Command::Uninstall) {
            Ok(ServiceSnapshot::absent())
        } else {
            Err(ServiceError::NotInstalled)
        };
    };
    let installation = ffi::validate_installation(false)?;
    verify_config(&service, installation.executable(), true)?;
    ffi::verify_service_security(&service)?;
    let sid = service
        .get_config_service_sid_info()
        .map_err(|e| scm_error(ServiceOperation::QueryConfiguration, e))?;
    if sid != ServiceSidType::Restricted {
        return Err(ServiceError::ConfigurationConflict);
    }
    let began = Instant::now();
    match command {
        Command::Start => start(&service, began)?,
        Command::Stop => stop(&service, began)?,
        Command::Restart => {
            stop(&service, began)?;
            start(&service, began)?;
        }
        Command::Uninstall => {
            stop(&service, began)?;
            service
                .delete()
                .map_err(|e| scm_error(ServiceOperation::DeleteService, e))?;
            // Windows deletion cannot complete while our service handle is open.
            drop(service);
            wait_absent(&manager, began)?;
            return Ok(ServiceSnapshot::absent());
        }
        _ => return Err(ServiceError::InvalidArguments),
    }
    Ok(snapshot(status(&service)?))
}

fn install() -> Result<ServiceSnapshot, ServiceError> {
    let installation = ffi::validate_installation(true)?;
    let manager = manager(true)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::READ_CONTROL
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::WRITE_DAC;
    let service = match open(&manager, access)? {
        Some(service) => {
            let config = verify_config(&service, installation.executable(), true)?;
            // Existing own configurations may be repaired only after proving
            // that no unprivileged principal can mutate this service object.
            ffi::verify_service_security(&service)?;
            if status(&service)?.current_state != NativeState::Stopped {
                if config.start_type == ServiceStartType::AutoStart {
                    let sid = service
                        .get_config_service_sid_info()
                        .map_err(|e| scm_error(ServiceOperation::QueryConfiguration, e))?;
                    if sid != ServiceSidType::Restricted {
                        return Err(ServiceError::ConfigurationConflict);
                    }
                    return Ok(snapshot(status(&service)?));
                }
                return Err(ServiceError::UnexpectedState);
            }
            // Disable a verified stopped registration before provisioning repair;
            // failure must never leave an incompletely prepared auto-start host.
            service
                .change_config(&service_info(
                    installation.executable(),
                    ServiceStartType::Disabled,
                ))
                .map_err(|e| scm_error(ServiceOperation::HardenService, e))?;
            service
        }
        None => manager
            .create_service(
                &service_info(installation.executable(), ServiceStartType::Disabled),
                access,
            )
            .map_err(|e| scm_error(ServiceOperation::CreateService, e))?,
    };
    let prepare = || -> Result<(), ServiceError> {
        ffi::harden_service(&service)?;
        service
            .set_config_service_sid_info(ServiceSidType::Restricted)
            .map_err(|e| scm_error(ServiceOperation::HardenService, e))?;
        ffi::provision_activity_directory()?;
        ffi::provision_trust_directory()?;
        Ok(())
    };
    prepare().map_err(incomplete)?;
    service
        .change_config(&service_info(
            installation.executable(),
            ServiceStartType::AutoStart,
        ))
        .map_err(|e| incomplete(scm_error(ServiceOperation::HardenService, e)))?;
    Ok(snapshot(status(&service)?))
}

fn delay(began: Instant) -> Result<(), ServiceError> {
    let remaining = remaining_budget(began.elapsed())?;
    thread::sleep(POLL_INTERVAL.min(remaining));
    Ok(())
}

fn wait_for(service: &Service, target: NativeState, began: Instant) -> Result<(), ServiceError> {
    loop {
        remaining_budget(began.elapsed())?;
        let current = status(service)?;
        remaining_budget(began.elapsed())?;
        if reached_target(&current, target)? {
            return Ok(());
        }
        delay(began)?;
    }
}

fn reached_target(current: &ServiceStatus, target: NativeState) -> Result<bool, ServiceError> {
    if target == NativeState::Running && current.current_state == NativeState::Stopped {
        return Err(ServiceError::ServiceStopped);
    }
    // This mask indicates local bootstrap completion, not authenticated transport
    // or remote readiness. CLI/NSIS Start must wait through early Running.
    Ok(current.current_state == target
        && (target != NativeState::Running || initialization_complete(current)))
}

fn start(service: &Service, began: Instant) -> Result<(), ServiceError> {
    match status(service)?.current_state {
        NativeState::Running | NativeState::StartPending => {
            return wait_for(service, NativeState::Running, began);
        }
        NativeState::StopPending => wait_for(service, NativeState::Stopped, began)?,
        NativeState::Stopped => (),
        _ => return Err(ServiceError::UnexpectedState),
    }
    remaining_budget(began.elapsed())?;
    match service.start::<&str>(&[]) {
        Ok(()) => (),
        Err(error) if is_code(&error, ERROR_SERVICE_ALREADY_RUNNING.0) => (),
        Err(error) => return Err(scm_error(ServiceOperation::StartService, error)),
    }
    wait_for(service, NativeState::Running, began)
}

fn stop(service: &Service, began: Instant) -> Result<(), ServiceError> {
    loop {
        remaining_budget(began.elapsed())?;
        let current = status(service)?;
        remaining_budget(began.elapsed())?;
        match current.current_state {
            NativeState::Stopped => return Ok(()),
            NativeState::StopPending => return wait_for(service, NativeState::Stopped, began),
            NativeState::StartPending => delay(began)?,
            NativeState::Running if !reached_target(&current, NativeState::Running)? => {
                // Early Running still refuses STOP. Retain the bounded startup
                // wait for Stop/Restart/Uninstall, without resetting its budget.
                delay(began)?;
            }
            NativeState::Running | NativeState::Paused => break,
            _ => return Err(ServiceError::UnexpectedState),
        }
    }
    remaining_budget(began.elapsed())?;
    match service.stop() {
        Ok(_) => (),
        Err(error) if is_code(&error, ERROR_SERVICE_NOT_ACTIVE.0) => (),
        Err(error) => return Err(scm_error(ServiceOperation::StopService, error)),
    }
    wait_for(service, NativeState::Stopped, began)
}

fn wait_absent(manager: &ServiceManager, began: Instant) -> Result<(), ServiceError> {
    loop {
        remaining_budget(began.elapsed())?;
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Err(error) if is_code(&error, ERROR_SERVICE_DOES_NOT_EXIST.0) => return Ok(()),
            Err(error) if is_code(&error, ERROR_SERVICE_MARKED_FOR_DELETE.0) => (),
            Err(error) => return Err(scm_error(ServiceOperation::OpenService, error)),
            Ok(service) => drop(service),
        }
        delay(began)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use windows_service::service::ServiceExitCode;

    fn observed(state: NativeState, controls: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: Some(42),
        }
    }

    #[test]
    fn start_requires_both_controls_not_merely_scm_running() {
        for controls in [
            ServiceControlAccept::empty(),
            ServiceControlAccept::STOP,
            ServiceControlAccept::SHUTDOWN,
        ] {
            assert_eq!(
                reached_target(
                    &observed(NativeState::Running, controls),
                    NativeState::Running
                ),
                Ok(false)
            );
        }
        assert_eq!(
            reached_target(
                &observed(
                    NativeState::Running,
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                ),
                NativeState::Running,
            ),
            Ok(true)
        );
    }

    #[test]
    fn stopped_during_start_is_failure_and_stop_completion_is_unchanged() {
        let stopped = observed(NativeState::Stopped, ServiceControlAccept::empty());
        assert_eq!(
            reached_target(&stopped, NativeState::Running),
            Err(ServiceError::ServiceStopped)
        );
        assert_eq!(reached_target(&stopped, NativeState::Stopped), Ok(true));
        assert_eq!(
            reached_target(
                &observed(NativeState::StartPending, ServiceControlAccept::empty()),
                NativeState::Running,
            ),
            Ok(false)
        );
    }

    fn assert_no_remote_capabilities(snapshot: &ServiceSnapshot) {
        assert!(!snapshot.capabilities.windows_prompt_integration);
        assert!(!snapshot.capabilities.encrypted_phone_transport);
        assert!(!snapshot.capabilities.remote_approval);
        assert!(!snapshot.capabilities.credential_entry);
    }

    #[test]
    fn public_running_projection_uses_the_same_readiness_bits_as_start() {
        for pid in [Some(42), Some(0), None] {
            for (controls, expected) in [
                (ServiceControlAccept::empty(), ServiceState::StartPending),
                (ServiceControlAccept::STOP, ServiceState::StartPending),
                (ServiceControlAccept::SHUTDOWN, ServiceState::StartPending),
                (
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                    ServiceState::Running,
                ),
            ] {
                let mut status = observed(NativeState::Running, controls);
                status.process_id = pid;
                assert_eq!(
                    reached_target(&status, NativeState::Running),
                    Ok(expected == ServiceState::Running)
                );
                let public = snapshot(status);
                assert_eq!(public.state, Some(expected));
                assert_eq!(public.process_id, pid.filter(|value| *value != 0));
                assert_no_remote_capabilities(&public);
            }
        }
    }

    #[test]
    fn nonrunning_raw_states_never_inherit_the_running_pid_exception() {
        for (raw, expected) in [
            (NativeState::StartPending, ServiceState::StartPending),
            (NativeState::Stopped, ServiceState::Stopped),
            (NativeState::StopPending, ServiceState::StopPending),
            (NativeState::ContinuePending, ServiceState::ContinuePending),
            (NativeState::PausePending, ServiceState::PausePending),
            (NativeState::Paused, ServiceState::Paused),
        ] {
            let status = observed(
                raw,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            );
            assert!(!initialization_complete(&status));
            let public = snapshot(status);
            assert_eq!(public.state, Some(expected));
            assert_eq!(public.process_id, None);
            assert_no_remote_capabilities(&public);
        }
        // Only the native adapter has raw Running provenance for the exception.
        // The shared constructor must not retain guessed StartPending PIDs.
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::StartPending, Some(42)).process_id,
            None
        );
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::Stopped, Some(42)).process_id,
            None
        );
    }
}
