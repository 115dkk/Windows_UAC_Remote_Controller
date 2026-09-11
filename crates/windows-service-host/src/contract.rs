// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
use std::time::{Duration, Instant};
use std::{ffi::OsStr, fmt, net::SocketAddr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// CLI input has no freeform payload. Unknown arguments are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Status,
    Service,
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
    ProbeOnce,
    Relay(SocketAddr),
    Pair(PendingElevationId),
    PairRenderer(RendererInvocation),
    Help,
}

/// Public correlation only, never a bearer grant or fresh-elevation proof.
/// Copying these bytes cannot copy a native launch/ceremony ownership right.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PendingElevationId([u8; 32]);
impl fmt::Debug for PendingElevationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingElevationId(redacted)")
    }
}
impl PendingElevationId {
    fn parse(value: &OsStr) -> Result<Self, ServiceError> {
        let text = value.to_str().ok_or(ServiceError::InvalidArguments)?;
        if text.len() != 64 {
            return Err(ServiceError::InvalidArguments);
        }
        let digit = |value: u8| match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(ServiceError::InvalidArguments),
        };
        let mut bytes = [0; 32];
        for (output, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *output = digit(pair[0])? * 16 + digit(pair[1])?;
        }
        Self::from_bytes(bytes)
    }
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Result<Self, ServiceError> {
        if bytes.iter().all(|value| *value == 0) {
            Err(ServiceError::InvalidArguments)
        } else {
            Ok(Self(bytes))
        }
    }
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    pub(crate) fn bytes(self) -> [u8; 32] {
        self.0
    }
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    pub(crate) fn argument(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(64);
        for byte in self.0 {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        text
    }
}

/// Two public correlations only. Native renderer admission still requires the
/// exact registered child/process and original authenticated service channel.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RendererInvocation {
    pending: PendingElevationId,
    display: PendingElevationId,
}
impl fmt::Debug for RendererInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendererInvocation(redacted, not_authority)")
    }
}
impl RendererInvocation {
    pub(crate) fn new(
        pending: PendingElevationId,
        display: PendingElevationId,
    ) -> Result<Self, ServiceError> {
        if pending == display {
            return Err(ServiceError::InvalidArguments);
        }
        Ok(Self { pending, display })
    }
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    pub(crate) fn pending(self) -> PendingElevationId {
        self.pending
    }
    #[cfg(any(all(windows, target_pointer_width = "64"), test))]
    pub(crate) fn display(self) -> PendingElevationId {
        self.display
    }
}

/// Presentation submits only one of these user intents. It does not supply a
/// boolean administrator claim, helper path or arbitrary command argument.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlIntent {
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
}

impl ServiceControlIntent {
    #[cfg(any(windows, test))]
    pub(crate) const fn argument(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ControlOutcome {
    UserCancelled,
    /// Windows launched the helper, but its bounded process wait expired.
    StillRunning,
    Completed {
        snapshot: ServiceSnapshot,
    },
    HelperFailed {
        exit_code: u32,
    },
    /// Helper exited successfully, but a subsequent read-only query failed.
    CompletionStatusUnknown,
}

/// The relay endpoint is a numeric socket address only (ADR 0020): no DNS
/// name, no zero port, no unspecified address, and for IPv6 no flow label,
/// scope id or IPv4-mapped form, so the stored text has exactly one spelling.
pub(crate) fn validate_relay_endpoint(endpoint: SocketAddr) -> Result<(), ServiceError> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() {
        return Err(ServiceError::InvalidArguments);
    }
    if let SocketAddr::V6(address) = endpoint
        && (address.flowinfo() != 0
            || address.scope_id() != 0
            || address.ip().to_ipv4_mapped().is_some())
    {
        return Err(ServiceError::InvalidArguments);
    }
    Ok(())
}

impl Command {
    /// Input excludes argv[0]. No arguments means read-only status.
    pub fn parse<I, S>(arguments: I) -> Result<Self, ServiceError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut arguments = arguments.into_iter();
        let Some(first) = arguments.next() else {
            return Ok(Self::Status);
        };
        let second = arguments.next();
        let third = arguments.next();
        if first.as_ref().to_str() == Some("relay") {
            if third.is_some() || arguments.next().is_some() {
                return Err(ServiceError::InvalidArguments);
            }
            let endpoint = second
                .ok_or(ServiceError::InvalidArguments)?
                .as_ref()
                .to_str()
                .ok_or(ServiceError::InvalidArguments)?
                .parse::<SocketAddr>()
                .map_err(|_| ServiceError::InvalidArguments)?;
            validate_relay_endpoint(endpoint)?;
            return Ok(Self::Relay(endpoint));
        }
        if first.as_ref().to_str() == Some("pair-renderer") {
            if arguments.next().is_some() {
                return Err(ServiceError::InvalidArguments);
            }
            let pending =
                PendingElevationId::parse(second.ok_or(ServiceError::InvalidArguments)?.as_ref())?;
            let display =
                PendingElevationId::parse(third.ok_or(ServiceError::InvalidArguments)?.as_ref())?;
            return RendererInvocation::new(pending, display).map(Self::PairRenderer);
        }
        if third.is_some() {
            return Err(ServiceError::InvalidArguments);
        }
        if first.as_ref().to_str() == Some("pair") {
            return second
                .ok_or(ServiceError::InvalidArguments)
                .and_then(|value| PendingElevationId::parse(value.as_ref()))
                .map(Self::Pair);
        }
        if second.is_some() {
            return Err(ServiceError::InvalidArguments);
        }
        match first.as_ref().to_str() {
            Some("status") => Ok(Self::Status),
            Some("service") => Ok(Self::Service),
            Some("install") => Ok(Self::Install),
            Some("start") => Ok(Self::Start),
            Some("stop") => Ok(Self::Stop),
            Some("restart") => Ok(Self::Restart),
            Some("uninstall") => Ok(Self::Uninstall),
            Some("probe-once") => Ok(Self::ProbeOnce),
            Some("help" | "--help" | "-h") => Ok(Self::Help),
            _ => Err(ServiceError::InvalidArguments),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationState {
    NotInstalled,
    Installed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
}

/// These are development capability facts, never inferred from a running PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeCapabilities {
    pub windows_prompt_integration: bool,
    pub encrypted_phone_transport: bool,
    pub remote_approval: bool,
    pub credential_entry: bool,
}

impl RuntimeCapabilities {
    pub const IMPLEMENTED: Self = Self {
        windows_prompt_integration: true,
        encrypted_phone_transport: true,
        remote_approval: true,
        credential_entry: false,
    };
}

/// Compile-time identity provider profile of THIS binary (ADR 0027). Only the
/// platform value ships; a lab build embeds a do-not-ship marker that release
/// packaging rejects. This is a build fact, not a runtime observation.
#[cfg(windows)]
pub const IDENTITY_PROVIDER_PROFILE: &str = windows_identity::IDENTITY_PROVIDER_PROFILE;
// The snapshot constructors that read this are compiled on Windows and in
// host tests only; other targets carry no profile string at all.
#[cfg(all(not(windows), test))]
pub const IDENTITY_PROVIDER_PROFILE: &str = "unsupported-platform";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceSnapshot {
    pub installation: InstallationState,
    pub state: Option<ServiceState>,
    pub process_id: Option<u32>,
    pub capabilities: RuntimeCapabilities,
    /// Build profile of the queried CLI binary, never of the running service.
    pub identity_provider: &'static str,
    /// Lowercase release signer digests compiled into this queried binary.
    pub android_signer_digests: Vec<String>,
}

impl ServiceSnapshot {
    #[cfg(any(windows, test))]
    pub(crate) fn absent() -> Self {
        Self {
            installation: InstallationState::NotInstalled,
            state: None,
            process_id: None,
            capabilities: RuntimeCapabilities::IMPLEMENTED,
            identity_provider: IDENTITY_PROVIDER_PROFILE,
            android_signer_digests: crate::android_signer_digest_strings(),
        }
    }

    #[cfg(any(windows, test))]
    pub(crate) fn installed(state: ServiceState, process_id: Option<u32>) -> Self {
        Self {
            installation: InstallationState::Installed,
            state: Some(state),
            process_id: process_id.filter(|pid| *pid != 0 && state == ServiceState::Running),
            capabilities: RuntimeCapabilities::IMPLEMENTED,
            identity_provider: IDENTITY_PROVIDER_PROFILE,
            android_signer_digests: crate::android_signer_digest_strings(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    OpenManager,
    OpenService,
    QueryStatus,
    QueryConfiguration,
    QueryToken,
    KnownFolder,
    OpenProtectedPath,
    InspectProtectedPath,
    ReadSecurity,
    ResolveServiceSid,
    CreateService,
    HardenService,
    DeleteService,
    StartService,
    StopService,
    Dispatch,
    RegisterHandler,
    ReportStatus,
    LaunchElevatedHelper,
    WaitElevatedHelper,
    RequestProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupFailure {
    Windows {
        operation: ServiceOperation,
        code: u32,
    },
    UnsafePath,
    UnsafePermissions,
    Provisioning,
    Other,
}

/// Fixed categories and numeric codes only; no OS message, argument or path.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("this service operation is supported only on Windows")]
    UnsupportedPlatform,
    #[error("unsupported arguments; use uac-service help")]
    InvalidArguments,
    #[error("an elevated Windows administrator token is required")]
    ElevationRequired,
    #[error("Windows call failed at {operation:?} (code {code:#010x})")]
    WindowsCall {
        operation: ServiceOperation,
        code: u32,
    },
    #[error("Windows returned an unsupported service result at {0:?}")]
    UnsupportedResult(ServiceOperation),
    #[error("service identity or configuration does not match this product")]
    ConfigurationConflict,
    #[error("the executable is not in the required protected installation")]
    UntrustedInstallation,
    #[error("protected path validation rejected a reparse point or path alias")]
    UnsafePath,
    #[error("protected object owner or access control is unsupported or unsafe")]
    UnsafePermissions,
    #[error("the service is not installed")]
    NotInstalled,
    #[error("the service lifecycle operation exceeded its bounded deadline")]
    Timeout,
    #[error("the service stopped before the requested running state")]
    ServiceStopped,
    #[error("this service state cannot complete the requested operation")]
    UnexpectedState,
    #[error("installation preparation failed; the registration remains disabled: {reason:?}")]
    InstallationIncomplete { reason: SetupFailure },
    #[error("a pre-provisioned private activity directory is required")]
    JournalProvisioningRequired,
    #[error("activity journal operation failed; administrator recovery may be required")]
    JournalUnavailable,
    #[error("a pre-provisioned private device-registry directory is required")]
    RegistryProvisioningRequired,
    #[error("the device registry is unavailable; trusted recovery is required")]
    RegistryUnavailable,
    #[error("the device registry reached its bounded maintenance limit")]
    RegistryMaintenanceRequired,
    #[error("the service could not initialize its protected PC identity")]
    IdentityUnavailable,
    #[cfg(windows)]
    #[error("PC identity policy rejected: {0:?}")]
    IdentityPolicy(windows_identity::IdentityPolicy),
    #[cfg(windows)]
    #[error("Windows identity operation {operation:?} failed (HRESULT {hresult:#010x})")]
    IdentityWindows {
        operation: windows_identity::IdentityOperation,
        hresult: i32,
    },
    #[cfg(windows)]
    #[error("identity native data is malformed at {0:?}")]
    IdentityMalformed(windows_identity::IdentityOperation),
    #[error("identity encoding rejected (fixed code {code})")]
    IdentityEncoding { code: u8 },
    #[error("the fixed identity key already exists; no overwrite or retry")]
    IdentityKeyAlreadyExists,
    #[error("the fixed identity key is absent")]
    IdentityKeyNotFound,
    #[error("identity creation is uncertain (HRESULT {hresult:#010x}); no retry or deletion")]
    IdentityCreationUncertain { hresult: i32 },
    #[error("identity cleanup failed (HRESULT {hresult:#010x}); native cause text was discarded")]
    IdentityCleanupFailed { hresult: i32 },
    #[error("identity handle was already released")]
    IdentityHandleAlreadyReleased,
    #[error("service startup failed at fixed stage {stage} (diagnostic {detail:#010x})")]
    StartupFailure { stage: u8, detail: u32 },
    #[error("the service clock is outside the supported range")]
    InvalidClock,
    #[error("the service lifecycle worker failed")]
    WorkerFailed,
    #[error("the SCM dispatcher cannot be registered twice in one process")]
    AlreadyDispatched,
    #[error("status output could not be encoded or written")]
    OutputUnavailable,
    #[error("a read-only diagnostic probe is already pending or running")]
    ProbeBusy,
    #[error(
        "all eight fixed diagnostic slots are occupied; explicit operator recovery is required"
    )]
    ProbeSlotsFull,
    #[error("the read-only diagnostic owner or result storage is unavailable")]
    ProbeUnavailable,
    #[error("the pairing helper handoff is unavailable or incomplete")]
    PairingHandoffUnavailable,
    #[error("pairing client Windows call failed at fixed stage {stage} (HRESULT {hresult:#010x})")]
    PairingClientNative { stage: u8, hresult: i32 },
    #[error(
        "renderer bootstrap Windows call failed at fixed stage {stage} (HRESULT {hresult:#010x})"
    )]
    RendererNative { stage: u8, hresult: i32 },
}

impl ServiceError {
    /// SCM DWORD diagnostic, distinct from the small process exit class.
    /// Explicit tables are stable even if upstream enum declaration order changes.
    /// Identity failures with HRESULT prefix 0x8009 use namespace 0xE6OOCCCC, NOT
    /// an HRESULT: OO is the explicit operation code and the original HRESULT
    /// is 0x80090000 | CCCC. This carries no diagnosis or property/secret data.
    /// This prefix includes NTE, SSPI and CRYPT errors. Other HRESULT prefixes
    /// and the raw Copy ServiceError remain unchanged.
    pub const fn service_diagnostic_code(self) -> u32 {
        match self {
            #[cfg(windows)]
            Self::IdentityPolicy(policy) => 0xE100_0000 | identity_policy_code(policy),
            #[cfg(windows)]
            Self::IdentityWindows { operation, hresult } => {
                let raw = hresult as u32;
                if raw & 0xFFFF_0000 == 0x8009_0000 {
                    0xE600_0000 | (identity_operation_code(operation) << 16) | (raw & 0xFFFF)
                } else {
                    raw
                }
            }
            #[cfg(windows)]
            Self::IdentityMalformed(operation) => 0xE200_0000 | identity_operation_code(operation),
            Self::IdentityEncoding { code } => 0xE300_0000 | code as u32,
            Self::IdentityKeyAlreadyExists => 0xE400_0001,
            Self::IdentityKeyNotFound => 0xE400_0002,
            Self::IdentityHandleAlreadyReleased => 0xE400_0003,
            Self::IdentityCreationUncertain { .. } => 0xE400_0004,
            Self::IdentityCleanupFailed { .. } => 0xE400_0005,
            Self::StartupFailure { stage, .. } => 0xE500_0000 | stage as u32,
            _ => self.exit_code() as u32,
        }
    }

    #[cfg(windows)]
    pub(crate) fn at_startup(self, stage: u8) -> Self {
        Self::StartupFailure {
            stage,
            detail: self.service_diagnostic_code(),
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_identity(error: windows_identity::IdentityError) -> Self {
        use windows_identity::{IdentityEncodingError as E, IdentityError as I};
        match error {
            I::UnsupportedPlatform => Self::UnsupportedPlatform,
            I::Policy(policy) => Self::IdentityPolicy(policy),
            I::WindowsCall { operation, hresult } => Self::IdentityWindows { operation, hresult },
            I::MalformedNativeData { operation } => Self::IdentityMalformed(operation),
            I::Encoding(error) => Self::IdentityEncoding {
                code: match error {
                    E::PublicBlobLength => 1,
                    E::PublicBlobMagic => 2,
                    E::PublicCoordinateSize => 3,
                    E::PublicPoint => 4,
                    E::SignatureLength => 5,
                    E::SignatureScalar => 6,
                    E::SignatureVerification => 7,
                },
            },
            I::KeyAlreadyExists => Self::IdentityKeyAlreadyExists,
            I::KeyNotFound => Self::IdentityKeyNotFound,
            I::CreationStateUncertain { hresult } => Self::IdentityCreationUncertain { hresult },
            I::CleanupFailed { hresult, .. } => Self::IdentityCleanupFailed { hresult },
            I::HandleAlreadyReleased => Self::IdentityHandleAlreadyReleased,
        }
    }

    /// Stable process exit classes, not raw OS text or truncated Windows codes.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidArguments => 2,
            Self::ElevationRequired => 3,
            Self::UnsupportedPlatform => 4,
            Self::UnsafePath
            | Self::UnsafePermissions
            | Self::UntrustedInstallation
            | Self::ConfigurationConflict => 5,
            Self::Timeout => 6,
            Self::JournalProvisioningRequired | Self::JournalUnavailable => 7,
            Self::RegistryProvisioningRequired
            | Self::RegistryUnavailable
            | Self::RegistryMaintenanceRequired => 8,
            _ => 1,
        }
    }
}

#[cfg(windows)]
const fn identity_policy_code(policy: windows_identity::IdentityPolicy) -> u32 {
    use windows_identity::IdentityPolicy as P;
    match policy {
        P::LocalSystemRequired => 1,
        P::ServiceSidRequired => 2,
        P::ImpersonationForbidden => 3,
        P::InvalidServiceSid => 4,
        P::PlatformProviderRequired => 5,
        P::HardwareProviderRequired => 6,
        P::SecurityDescriptorsRequired => 7,
        P::FixedKeyNameRequired => 8,
        P::P256SigningKeyRequired => 9,
        P::SigningOnlyRequired => 10,
        P::NonExportableRequired => 11,
        P::MachineKeyRequired => 12,
        P::ProtectedServiceDaclRequired => 13,
        P::ReopenedPublicKeyMismatch => 14,
    }
}

#[cfg(windows)]
const fn identity_operation_code(operation: windows_identity::IdentityOperation) -> u32 {
    use windows_identity::IdentityOperation as O;
    match operation {
        O::OpenProcessToken => 1,
        O::OpenThreadToken => 2,
        O::ReadProcessUser => 3,
        O::ReadProcessGroups => 4,
        O::LookupServiceSid => 5,
        O::CloseToken => 6,
        O::OpenProvider => 7,
        O::ReadProviderPolicy => 8,
        O::CheckAlgorithmSupport => 9,
        O::OpenKey => 10,
        O::CreateKey => 11,
        O::ReadKeyPolicy => 12,
        O::SetKeyPolicy => 13,
        O::BuildSecurityDescriptor => 14,
        O::FreeSecurityDescriptor => 15,
        O::FinalizeKey => 16,
        O::ExportPublicKey => 17,
        O::SignDigest => 18,
        O::CloseKey => 19,
        O::CloseProvider => 20,
    }
}

#[cfg(windows)]
pub(crate) fn incomplete(error: ServiceError) -> ServiceError {
    let reason = match error {
        ServiceError::WindowsCall { operation, code } => SetupFailure::Windows { operation, code },
        ServiceError::UnsafePath => SetupFailure::UnsafePath,
        ServiceError::UnsafePermissions => SetupFailure::UnsafePermissions,
        ServiceError::JournalProvisioningRequired
        | ServiceError::JournalUnavailable
        | ServiceError::RegistryProvisioningRequired
        | ServiceError::RegistryUnavailable => SetupFailure::Provisioning,
        _ => SetupFailure::Other,
    };
    ServiceError::InstallationIncomplete { reason }
}

#[cfg(any(windows, test))]
pub(crate) const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(windows, test))]
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[cfg(any(windows, test))]
pub(crate) fn remaining_budget(elapsed: Duration) -> Result<Duration, ServiceError> {
    LIFECYCLE_TIMEOUT
        .checked_sub(elapsed)
        .filter(|left| !left.is_zero())
        .ok_or(ServiceError::Timeout)
}

/// Progress toward joining an already-pending worker must not grant a new
/// startup/shutdown budget. Only an unsolicited exit from Running begins one.
#[cfg(any(windows, test))]
pub(crate) fn continuing_pending_start(existing: Option<Instant>, now: Instant) -> Instant {
    existing.unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renderer_cli_is_exact_three_tokens_canonical_and_nonauthority() {
        let pending = "11".repeat(32);
        let display = "22".repeat(32);
        let command = Command::parse(["pair-renderer", &pending, &display]).unwrap();
        let Command::PairRenderer(invocation) = command else {
            panic!("fixed renderer mode expected");
        };
        assert_eq!(invocation.pending().argument(), pending);
        assert_eq!(invocation.display().argument(), display);
        assert!(!format!("{command:?}").contains(&pending));
        for arguments in [
            vec!["pair-renderer"],
            vec!["pair-renderer", &pending],
            vec!["pair-renderer", &pending, &display, "extra"],
            vec!["pair-renderer", &pending, &pending],
        ] {
            assert_eq!(
                Command::parse(arguments),
                Err(ServiceError::InvalidArguments)
            );
        }
        for bad in [
            "00".repeat(32),
            "AA".repeat(32),
            format!(" {display}"),
            format!("{display} "),
            "g".repeat(64),
        ] {
            assert_eq!(
                Command::parse(["pair-renderer", &pending, &bad]),
                Err(ServiceError::InvalidArguments)
            );
        }
        assert_eq!(
            Command::parse(["pair", &pending, &display]),
            Err(ServiceError::InvalidArguments)
        );
    }

    #[test]
    fn service_diagnostic_keeps_existing_small_exit_classes_for_other_errors() {
        for error in [
            ServiceError::InvalidArguments,
            ServiceError::ElevationRequired,
            ServiceError::UnsupportedPlatform,
            ServiceError::UnsafePermissions,
            ServiceError::Timeout,
            ServiceError::JournalUnavailable,
            ServiceError::RegistryUnavailable,
            ServiceError::WorkerFailed,
        ] {
            assert_eq!(
                error.service_diagnostic_code(),
                u32::from(error.exit_code())
            );
        }
        fn copy_error<T: Copy>() {}
        copy_error::<ServiceError>();
    }

    #[cfg(windows)]
    #[test]
    fn identity_diagnostics_use_explicit_policy_operation_and_hresult_codes() {
        use windows_identity::{IdentityError as I, IdentityOperation as O, IdentityPolicy as P};
        assert_eq!(
            ServiceError::from_identity(I::Policy(P::LocalSystemRequired))
                .service_diagnostic_code(),
            0xE100_0001
        );
        assert_eq!(
            ServiceError::from_identity(I::Policy(P::NonExportableRequired))
                .service_diagnostic_code(),
            0xE100_000B
        );
        assert_eq!(
            ServiceError::from_identity(I::Policy(P::ProtectedServiceDaclRequired))
                .service_diagnostic_code(),
            0xE100_000D
        );
        assert_eq!(
            ServiceError::from_identity(I::Policy(P::ReopenedPublicKeyMismatch))
                .service_diagnostic_code(),
            0xE100_000E
        );
        assert_eq!(
            ServiceError::from_identity(I::MalformedNativeData {
                operation: O::FinalizeKey
            })
            .service_diagnostic_code(),
            0xE200_0010
        );
        let native = ServiceError::from_identity(I::WindowsCall {
            operation: O::OpenProvider,
            hresult: 0x8009_0029_u32 as i32,
        });
        assert_eq!(native.service_diagnostic_code(), 0xE607_0029);
        assert_eq!(native.exit_code(), 1);
        assert_eq!(
            native,
            ServiceError::IdentityWindows {
                operation: O::OpenProvider,
                hresult: 0x8009_0029_u32 as i32,
            }
        );
    }

    #[cfg(windows)]
    fn explicit_identity_operations() -> [(windows_identity::IdentityOperation, u32); 20] {
        use windows_identity::IdentityOperation as O;
        [
            (O::OpenProcessToken, 1),
            (O::OpenThreadToken, 2),
            (O::ReadProcessUser, 3),
            (O::ReadProcessGroups, 4),
            (O::LookupServiceSid, 5),
            (O::CloseToken, 6),
            (O::OpenProvider, 7),
            (O::ReadProviderPolicy, 8),
            (O::CheckAlgorithmSupport, 9),
            (O::OpenKey, 10),
            (O::CreateKey, 11),
            (O::ReadKeyPolicy, 12),
            (O::SetKeyPolicy, 13),
            (O::BuildSecurityDescriptor, 14),
            (O::FreeSecurityDescriptor, 15),
            (O::FinalizeKey, 16),
            (O::ExportPublicKey, 17),
            (O::SignDigest, 18),
            (O::CloseKey, 19),
            (O::CloseProvider, 20),
        ]
    }

    #[cfg(windows)]
    #[test]
    fn security_prefix_diagnostics_round_trip_twenty_operations_and_low_word_boundaries() {
        let low_words = [
            // SSPI SEC_E_INSUFFICIENT_MEMORY (0x300) and CRYPT_E_NOT_FOUND
            // (0x2004) share this prefix; the projection is not NTE-only.
            0_u32, 1, 0x16, 0x29, 0x30, 0xFF, 0x100, 0x300, 0x1234, 0x2004, 0x8000, 0xFFFF,
        ];
        let mut unique = std::collections::BTreeSet::new();
        for (operation, operation_code) in explicit_identity_operations() {
            // Existing malformed-native-data namespace must keep the same table.
            assert_eq!(
                ServiceError::IdentityMalformed(operation).service_diagnostic_code(),
                0xE200_0000 | operation_code
            );
            for low in low_words {
                let raw = 0x8009_0000 | low;
                let error = ServiceError::IdentityWindows {
                    operation,
                    hresult: raw as i32,
                };
                let encoded = error.service_diagnostic_code();
                assert_eq!(encoded, 0xE600_0000 | (operation_code << 16) | low);
                assert_eq!(encoded & 0xFF00_0000, 0xE600_0000);
                assert_eq!((encoded >> 16) & 0xFF, operation_code);
                assert_eq!(0x8009_0000 | (encoded & 0xFFFF), raw);
                assert!(unique.insert(encoded));
                assert_eq!(error.exit_code(), 1);
                // The mapping consumes only a Copy value, not its stored metadata.
                assert_eq!(
                    error,
                    ServiceError::IdentityWindows {
                        operation,
                        hresult: raw as i32
                    }
                );
            }
        }
        assert_eq!(unique.len(), 20 * low_words.len());
    }

    #[cfg(windows)]
    #[test]
    fn other_hresult_prefixes_are_bit_exact_passthrough() {
        for (operation, _) in explicit_identity_operations() {
            for raw in [
                0_u32,
                0x8007_0005,
                0x8008_FFFF,
                0x800A_0000,
                0x8028_4008,
                0xC000_0001,
                0xE607_0030,
                u32::MAX,
            ] {
                let error = ServiceError::IdentityWindows {
                    operation,
                    hresult: raw as i32,
                };
                assert_eq!(error.service_diagnostic_code(), raw);
                assert_eq!(error.exit_code(), 1);
            }
        }
    }

    #[test]
    fn nte_valued_uncertainty_and_cleanup_do_not_become_plain_native_failures() {
        let nte = 0x8009_0030_u32 as i32;
        for (error, expected) in [
            (ServiceError::IdentityEncoding { code: 7 }, 0xE300_0007),
            (ServiceError::IdentityKeyAlreadyExists, 0xE400_0001),
            (ServiceError::IdentityKeyNotFound, 0xE400_0002),
            (ServiceError::IdentityHandleAlreadyReleased, 0xE400_0003),
            (
                ServiceError::IdentityCreationUncertain { hresult: nte },
                0xE400_0004,
            ),
            (
                ServiceError::IdentityCleanupFailed { hresult: nte },
                0xE400_0005,
            ),
            (
                ServiceError::StartupFailure {
                    stage: 4,
                    detail: nte as u32,
                },
                0xE500_0004,
            ),
        ] {
            assert_eq!(error.service_diagnostic_code(), expected);
            assert_eq!(error.exit_code(), 1);
        }
    }

    #[cfg(windows)]
    #[test]
    fn uncertain_cleanup_encoding_and_preidentity_stages_remain_distinct_metadata() {
        use windows_identity::{
            IdentityEncodingError as E, IdentityError as I, IdentityPolicy as P,
        };
        let uncertain = ServiceError::from_identity(I::CreationStateUncertain { hresult: -1 });
        let cleanup = ServiceError::from_identity(I::CleanupFailed {
            cause: Box::new(I::Policy(P::NonExportableRequired)),
            hresult: -2,
        });
        assert_eq!(uncertain.service_diagnostic_code(), 0xE400_0004);
        assert_eq!(cleanup.service_diagnostic_code(), 0xE400_0005);
        assert!(!format!("{cleanup:?}").contains("NonExportableRequired"));
        assert_eq!(
            ServiceError::from_identity(I::Encoding(E::PublicPoint)).service_diagnostic_code(),
            0xE300_0004
        );
        assert_eq!(
            ServiceError::RegistryUnavailable
                .at_startup(4)
                .service_diagnostic_code(),
            0xE500_0004
        );
        assert_eq!(
            ServiceError::from_identity(I::HandleAlreadyReleased).service_diagnostic_code(),
            0xE400_0003
        );
    }

    #[test]
    fn default_is_read_only_and_mutations_are_explicit() {
        assert_eq!(Command::parse::<_, &str>([]), Ok(Command::Status));
        for (name, command) in [
            ("status", Command::Status),
            ("service", Command::Service),
            ("install", Command::Install),
            ("start", Command::Start),
            ("stop", Command::Stop),
            ("restart", Command::Restart),
            ("uninstall", Command::Uninstall),
        ] {
            assert_eq!(Command::parse([name]), Ok(command));
        }
    }

    #[test]
    fn arbitrary_payload_and_extra_arguments_are_rejected_without_retention() {
        for args in [
            vec!["approve"],
            vec!["install", "unexpected-input"],
            vec!["--program", "anything"],
            vec!["STATUS"],
            vec![""],
        ] {
            let error = Command::parse(args).unwrap_err();
            assert_eq!(error, ServiceError::InvalidArguments);
            assert!(!format!("{error:?}").contains("unexpected-input"));
        }
    }

    #[test]
    fn pair_is_the_only_two_argument_command_and_public_id_is_canonical_redacted_data() {
        let id = PendingElevationId::from_bytes([0xab; 32]).unwrap();
        let text = id.argument();
        assert_eq!(text, "ab".repeat(32));
        assert_eq!(
            Command::parse(["pair", text.as_str()]),
            Ok(Command::Pair(id))
        );
        assert_eq!(PendingElevationId::parse(OsStr::new(&text)), Ok(id));
        assert_eq!(
            format!("{:?}", Command::Pair(id)),
            "Pair(PendingElevationId(redacted))"
        );
        for verb in [
            "status",
            "service",
            "install",
            "start",
            "stop",
            "restart",
            "uninstall",
            "probe-once",
            "help",
        ] {
            assert_eq!(
                Command::parse([verb, text.as_str()]),
                Err(ServiceError::InvalidArguments)
            );
        }
        assert_eq!(
            Command::parse(["pair"]),
            Err(ServiceError::InvalidArguments)
        );
        assert_eq!(
            Command::parse(["pair", text.as_str(), "extra"]),
            Err(ServiceError::InvalidArguments)
        );
    }

    #[test]
    fn pair_rejects_noncanonical_zero_and_unicode_arguments_without_echo() {
        for bad in [
            "00".repeat(32),
            "AB".repeat(32),
            "a".repeat(63),
            "a".repeat(65),
            format!(" {}", "ab".repeat(32)),
            format!("{}\0", "ab".repeat(32)),
            format!("0x{}", "ab".repeat(32)),
            "é".repeat(32),
            format!("{}g", "a".repeat(63)),
        ] {
            assert_eq!(
                Command::parse(["pair", bad.as_str()]),
                Err(ServiceError::InvalidArguments)
            );
            assert!(!format!("{}", ServiceError::InvalidArguments).contains(&bad));
        }
    }

    #[cfg(windows)]
    #[test]
    fn pair_does_not_lossily_convert_unpaired_utf16() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};
        assert_eq!(
            Command::parse([OsString::from("pair"), OsString::from_wide(&[0xd800; 64])]),
            Err(ServiceError::InvalidArguments)
        );
    }

    #[cfg(unix)]
    #[test]
    fn pair_does_not_lossily_convert_invalid_os_bytes() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        assert_eq!(
            Command::parse([OsString::from("pair"), OsString::from_vec(vec![0xff; 64])]),
            Err(ServiceError::InvalidArguments)
        );
    }

    #[test]
    fn cli_capture_does_not_collect_or_reparse_a_tail_after_rejection() {
        let mut count = 0;
        let raw = [
            "pair".to_owned(),
            "ab".repeat(32),
            "extra".to_owned(),
            "never-read".to_owned(),
        ];
        let iterator = raw.iter().inspect(|_| count += 1);
        assert_eq!(
            Command::parse(iterator),
            Err(ServiceError::InvalidArguments)
        );
        assert_eq!(count, 3);
    }

    #[test]
    fn renderer_cli_rejects_the_first_excess_argument_without_reading_its_tail() {
        let mut count = 0;
        let raw = [
            "pair-renderer".to_owned(),
            "ab".repeat(32),
            "cd".repeat(32),
            "extra".to_owned(),
            "never-read".to_owned(),
        ];
        let iterator = raw.iter().inspect(|_| count += 1);
        assert_eq!(
            Command::parse(iterator),
            Err(ServiceError::InvalidArguments)
        );
        assert_eq!(count, 4);
    }

    #[test]
    fn running_reports_compile_time_implemented_capabilities() {
        let snapshot = ServiceSnapshot::installed(ServiceState::Running, Some(42));
        assert_eq!(snapshot.process_id, Some(42));
        assert_eq!(snapshot.capabilities, RuntimeCapabilities::IMPLEMENTED);
        let wire = serde_json::to_value(snapshot).unwrap();
        assert_eq!(wire["state"], "running");
        assert_eq!(wire["capabilities"]["windows_prompt_integration"], true);
        assert_eq!(wire["capabilities"]["encrypted_phone_transport"], true);
        assert_eq!(wire["capabilities"]["remote_approval"], true);
        assert_eq!(wire["capabilities"]["credential_entry"], false);
        assert_eq!(wire["identity_provider"], IDENTITY_PROVIDER_PROFILE);
        #[cfg(not(feature = "lab-software-identity"))]
        assert!(!IDENTITY_PROVIDER_PROFILE.contains("do-not-ship"));
    }

    #[test]
    fn absent_and_stopped_do_not_retain_a_pid() {
        assert_eq!(
            ServiceSnapshot::absent().installation,
            InstallationState::NotInstalled
        );
        assert_eq!(ServiceSnapshot::absent().state, None);
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::Stopped, Some(42)).process_id,
            None
        );
        assert_eq!(
            ServiceSnapshot::installed(ServiceState::Running, Some(0)).process_id,
            None
        );
    }

    #[test]
    fn deadlines_are_strictly_bounded() {
        assert_eq!(remaining_budget(Duration::ZERO), Ok(LIFECYCLE_TIMEOUT));
        assert!(remaining_budget(LIFECYCLE_TIMEOUT - POLL_INTERVAL).is_ok());
        assert_eq!(
            remaining_budget(LIFECYCLE_TIMEOUT),
            Err(ServiceError::Timeout)
        );
        assert_eq!(remaining_budget(Duration::MAX), Err(ServiceError::Timeout));
    }

    #[test]
    fn worker_finished_progress_does_not_restart_a_pending_deadline() {
        let began = Instant::now();
        let almost_finished = began + LIFECYCLE_TIMEOUT - POLL_INTERVAL;
        let continued = continuing_pending_start(Some(began), almost_finished);
        assert_eq!(continued, began);
        assert_eq!(
            remaining_budget((began + LIFECYCLE_TIMEOUT).duration_since(continued)),
            Err(ServiceError::Timeout)
        );
        assert_eq!(
            continuing_pending_start(None, almost_finished),
            almost_finished
        );
    }

    #[test]
    fn elevation_intents_have_exactly_one_constant_cli_argument() {
        for intent in [
            ServiceControlIntent::Install,
            ServiceControlIntent::Start,
            ServiceControlIntent::Stop,
            ServiceControlIntent::Restart,
            ServiceControlIntent::Uninstall,
        ] {
            assert!(Command::parse([intent.argument()]).is_ok());
            assert!(!intent.argument().contains([' ', '\\', '/', '"']));
        }
        assert!(serde_json::from_str::<ServiceControlIntent>("\"execute\"").is_err());
        let pending = serde_json::to_value(ControlOutcome::StillRunning).unwrap();
        assert_eq!(pending["outcome"], "still_running");
        assert!(pending.get("snapshot").is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_claims_a_successful_mutation() {
        assert_eq!(
            crate::query_status(),
            Err(ServiceError::UnsupportedPlatform)
        );
        for operation in [
            crate::install,
            crate::start,
            crate::stop,
            crate::restart,
            crate::uninstall,
        ] {
            assert_eq!(operation(), Err(ServiceError::UnsupportedPlatform));
        }
        assert_eq!(
            crate::dispatch_service(),
            Err(ServiceError::UnsupportedPlatform)
        );
    }
}
