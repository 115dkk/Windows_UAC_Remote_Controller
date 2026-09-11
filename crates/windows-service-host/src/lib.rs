// SPDX-License-Identifier: GPL-2.0-or-later
//! The one fixed-identity Windows service's lifecycle, not remote UAC readiness.
//!
//! Read-only status is callable by presentation. Mutations require a real
//! elevated Windows token and validated protected installation; no caller can
//! supply a service name, executable, account, credential or freeform command line.
//! Running means completed local service bootstrap, not remote readiness. Raw
//! SCM Running without readiness controls projects as product StartPending.
//! The service owns a bounded native pairing-helper rendezvous; GUI initiation
//! and full ceremony/enrollment authority remain separate. Windows prompt, phone pairing,
//! credential entry and encrypted transport activation remain unimplemented.

#![deny(unsafe_code)]

mod build_policy {
    include!(concat!(env!("OUT_DIR"), "/android_signers.rs"));
}
mod contract;
mod diagnostic;
pub mod management_protocol;
/// Disposable lab builds only: the SCM exit code drops HRESULTs, so the lab
/// keeps the failure text next to the activity journal for the evidence upload.
#[cfg(all(windows, feature = "lab-software-identity"))]
mod lab {
    /// Appends one fixed-token note (no payloads) to the lab failure file.
    pub(crate) fn record_note(note: &str) {
        let Some(root) = std::env::var_os("ProgramData") else {
            return;
        };
        let path = std::path::Path::new(&root)
            .join(crate::INSTALLATION_FOLDER)
            .join("lab-failure.txt");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            use std::io::Write as _;
            let _ = writeln!(file, "{note}");
        }
    }

    pub(crate) fn record_failure(failure: &crate::ServiceError) {
        let Some(root) = std::env::var_os("ProgramData") else {
            return;
        };
        let path = std::path::Path::new(&root)
            .join(crate::INSTALLATION_FOLDER)
            .join("lab-failure.txt");
        let mut text = format!("{failure}\n{failure:?}\n");
        if let Some(descriptor) = windows_identity::lab::take_descriptor() {
            text.push_str("last-key-descriptor-hex: ");
            for byte in descriptor {
                text.push_str(&format!("{byte:02x}"));
            }
            text.push('\n');
        }
        let _ = std::fs::write(path, text);
    }
}
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
mod pairing_handoff;
#[cfg(any(windows, test))]
pub mod peer_runtime;
mod probe_supervisor;
#[cfg(any(windows, test))]
pub mod tls_signer;
mod trust_registry;
mod watch_session;
pub use diagnostic::{
    MAX_PROBE_DIAGNOSTIC_BYTES, PROBE_CONTROL_CODE, PROBE_DIAGNOSTIC_FILES, ProbeRequestAccepted,
};
pub use probe_supervisor::{
    ApplyOutcome, GoneReason, LaunchPrivilege, ProbeReport, ProbeSupervisorError, PromptAction,
    ReportOutcome, ServiceProbeSupervisor, SupervisorStage, TargetIdentity, WatchEvent,
    WatchSession,
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
#[cfg(any(windows, test))]
mod startup_phase;

pub use contract::{
    Command, ControlOutcome, InstallationState, PendingElevationId, RendererInvocation,
    RuntimeCapabilities, ServiceControlIntent, ServiceError, ServiceOperation, ServiceSnapshot,
    ServiceState, SetupFailure,
};

// Opaque native integration resources, not UI/CLI/network commands. Server
// creation proves its fixed SCM context; clients independently authenticate
// that server and their own fixed installed role. No raw handle, path or caller
// authority claim is accepted. A peer observation alone cannot enroll a phone.
#[cfg(all(windows, target_pointer_width = "64"))]
pub use ffi::{
    PairingClient, PairingClientError, PairingClientProgress, PairingClientStage,
    PairingHelperLaunch, PairingLaunchError, PairingLaunchProgress, PairingPeer, PairingPeerError,
    PairingPeerRole, PairingPeerStage, PairingPipe, PairingPipeProgress, PairingServerEndpoint,
    PairingServerEndpoints,
};

pub const SERVICE_NAME: &str = "UacRemoteController";
pub const SERVICE_DISPLAY_NAME: &str = "휴대폰 승인";
pub const INSTALLATION_FOLDER: &str = "휴대폰 승인";
pub const SERVICE_EXECUTABLE: &str = "uac-service.exe";
pub const ANDROID_SIGNER_SHA256: &[[u8; 32]] = build_policy::ANDROID_SIGNER_SHA256;

#[cfg(any(windows, test))]
pub(crate) fn android_signer_digest_strings() -> Vec<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    ANDROID_SIGNER_SHA256
        .iter()
        .map(|digest| {
            let mut value = String::with_capacity(64);
            for byte in digest {
                value.push(char::from(HEX[usize::from(byte >> 4)]));
                value.push(char::from(HEX[usize::from(byte & 15)]));
            }
            value
        })
        .collect()
}

/// One fixed helper invocation. Zero means only authenticated terminal close
/// and local I/O drain, never a grant, enrollment or remote readiness result.
pub fn run_pair_helper(id: PendingElevationId) -> Result<(), ServiceError> {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        ffi::run_pair_helper(id).map_err(|error| error.service_error())
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        let _ = id;
        Err(ServiceError::UnsupportedPlatform)
    }
}

/// Fixed nonvisual renderer bootstrap only; no window, QR, grant or enrollment.
pub fn run_pair_renderer(invocation: RendererInvocation) -> Result<(), ServiceError> {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        ffi::run_pair_renderer(invocation).map_err(|error| error.service_error())
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        let _ = invocation;
        Err(ServiceError::UnsupportedPlatform)
    }
}

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

/// Read-only snapshot for the installed medium-integrity GUI over the verified
/// management pipe: public registry metadata only, never a mutation.
pub fn management_query() -> Result<management_protocol::ManagementResponse, ServiceError> {
    management_exchange(management_protocol::ManagementRequest::Query)
}

/// Elevated CLI verbs only (`remove`, `relay`); the service refuses other clients.
#[cfg(windows)]
pub(crate) fn management_mutation(
    request: management_protocol::ManagementRequest,
) -> Result<(), ServiceError> {
    match management_exchange(request)? {
        management_protocol::ManagementResponse::Done => Ok(()),
        management_protocol::ManagementResponse::Refused(_) => Err(ServiceError::ManagementRefused),
        management_protocol::ManagementResponse::Snapshot { .. } => {
            Err(ServiceError::UnexpectedState)
        }
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn management_exchange(
    request: management_protocol::ManagementRequest,
) -> Result<management_protocol::ManagementResponse, ServiceError> {
    use std::time::{Duration, Instant};

    const POLL_DELAY: Duration = Duration::from_millis(10);
    let wire = management_protocol::encode_request(&request)
        .map_err(|_| ServiceError::InvalidArguments)?;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    let mut client = PairingClient::connect_management(start, deadline)
        .map_err(|_| ServiceError::ManagementRefused)?;
    let exchange = (|| {
        client
            .begin_write(&wire)
            .map_err(|_| ServiceError::ManagementRefused)?;
        loop {
            match client.poll().map_err(|_| ServiceError::ManagementRefused)? {
                PairingClientProgress::Pending => std::thread::sleep(POLL_DELAY),
                PairingClientProgress::Written => break,
                _ => return Err(ServiceError::ManagementRefused),
            }
        }
        client
            .begin_read()
            .map_err(|_| ServiceError::ManagementRefused)?;
        loop {
            match client.poll().map_err(|_| ServiceError::ManagementRefused)? {
                PairingClientProgress::Pending => std::thread::sleep(POLL_DELAY),
                PairingClientProgress::Read(bytes) => {
                    return management_protocol::decode_response(&bytes)
                        .map_err(|_| ServiceError::ManagementRefused);
                }
                _ => return Err(ServiceError::ManagementRefused),
            }
        }
    })();

    client.cancel();
    let cleanup = loop {
        match client.drain() {
            Ok(true) => break Ok(()),
            Ok(false) => std::thread::sleep(POLL_DELAY),
            Err(_) => break Err(ServiceError::ManagementRefused),
        }
    };
    match (exchange, cleanup) {
        (Ok(response), Ok(())) => Ok(response),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

#[cfg(not(all(windows, target_pointer_width = "64")))]
fn management_exchange(
    _request: management_protocol::ManagementRequest,
) -> Result<management_protocol::ManagementResponse, ServiceError> {
    Err(ServiceError::UnsupportedPlatform)
}

pub fn remove_device(device: approval_protocol::DeviceId) -> Result<(), ServiceError> {
    #[cfg(windows)]
    {
        native::remove_device(device)
    }
    #[cfg(not(windows))]
    {
        let _ = device;
        Err(ServiceError::UnsupportedPlatform)
    }
}

pub fn configure_relay(endpoint: std::net::SocketAddr) -> Result<(), ServiceError> {
    #[cfg(windows)]
    {
        native::configure_relay(endpoint)
    }
    #[cfg(not(windows))]
    {
        let _ = endpoint;
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
