// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe delegation to the reviewed Windows-only service owner. No local FFI.

use std::{
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use windows_service_host::{
    ControlOutcome, InstallationState, ServiceControlIntent, ServiceError, ServiceOperation,
    ServiceSnapshot, management_protocol::ManagementResponse,
};

use crate::{
    ControlHint, ExternalAccess, ManagementDevice, ManagementObservation, ObservedServiceState,
    PlatformAdapter, PlatformError, RelayMode, RelayState, RelayStatusView, ServiceAction,
    ServiceCommandOutcome, ServiceObservation, ServiceState,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPlatformAdapter;

/// The optional status reads get one connect attempt each after the pipe
/// rearms, so a busy service misses one now and then. A missed read keeps the
/// last answer for this long instead of flashing "unknown"; a service that
/// keeps not answering still shows as unknown after it.
const OPTIONAL_READ_HOLD: Duration = Duration::from_secs(30);
static LAST_DIRECT: Mutex<Option<(Instant, crate::DirectConnectionState)>> = Mutex::new(None);
static LAST_EXTERNAL: Mutex<Option<(Instant, crate::ExternalAccessView)>> = Mutex::new(None);

fn held<T: Clone>(slot: &Mutex<Option<(Instant, T)>>, fresh: Option<T>) -> Option<T> {
    match slot.lock() {
        Ok(mut slot) => hold(&mut slot, fresh, Instant::now()),
        Err(_) => fresh,
    }
}

fn hold<T: Clone>(slot: &mut Option<(Instant, T)>, fresh: Option<T>, now: Instant) -> Option<T> {
    if let Some(value) = fresh {
        *slot = Some((now, value.clone()));
        return Some(value);
    }
    let kept = slot
        .as_ref()
        .filter(|(at, _)| now.saturating_duration_since(*at) <= OPTIONAL_READ_HOLD)
        .map(|(_, value)| value.clone());
    if kept.is_none() {
        *slot = None;
    }
    kept
}

impl PlatformAdapter for WindowsPlatformAdapter {
    fn observe_service(&self) -> Result<ServiceObservation, PlatformError> {
        let status = windows_service_host::query_status().map_err(status_error)?;
        observation(status)
    }

    fn observe_management(&self) -> Result<ManagementObservation, PlatformError> {
        let ManagementResponse::Snapshot {
            relay,
            embedded_relay,
            relay_listening,
            devices,
            activity,
            ..
        } = windows_service_host::management_query().map_err(management_error)?
        else {
            return Err(PlatformError::StatusUnavailable);
        };
        // Independent optional read: old services do not implement it. Never
        // let a refusal invent a candidate or hide a valid ordinary snapshot.
        let internet_state = if embedded_relay && relay_listening {
            let fresh = match windows_service_host::management_direct_query() {
                Ok(ManagementResponse::DirectStatus {
                    embedded_relay: true,
                    relay_listening: true,
                    state,
                }) => Some(project_direct_state(state)),
                _ => None,
            };
            held(&LAST_DIRECT, fresh)
        } else {
            if let Ok(mut last) = LAST_DIRECT.lock() {
                *last = None;
            }
            None
        };
        // Independent optional read with the same rule: an older service or a
        // failed exchange leaves it unobserved and keeps the ordinary snapshot.
        let external_access = held(
            &LAST_EXTERNAL,
            match windows_service_host::management_external_query() {
                Ok(ManagementResponse::ExternalStatus {
                    access,
                    external,
                    source,
                    failure,
                    lan,
                }) => external_access_view(access, external, source, failure, lan),
                _ => None,
            },
        );
        Ok(ManagementObservation {
            external_access,
            activity: activity.map(crate::pc_history::project),
            relay_configured: relay.is_some(),
            relay_status: RelayStatusView {
                internet_state,
                mode: if embedded_relay {
                    RelayMode::Embedded
                } else {
                    RelayMode::External
                },
                state: match (embedded_relay, relay_listening, relay.is_some()) {
                    (true, true, true) => RelayState::Listening,
                    (true, true, false) => RelayState::WaitingNetwork,
                    (true, false, _) => RelayState::Unavailable,
                    (false, _, true) => RelayState::ExternalConfigured,
                    (false, _, false) => RelayState::Unknown,
                },
            },
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

    fn use_embedded_relay(&self) -> Result<(), PlatformError> {
        completed_mutation(ServiceControlIntent::UseEmbeddedRelay)
    }

    fn set_external_access(&self, access: ExternalAccess) -> Result<(), PlatformError> {
        // Checked again here so no invalid value can reach an elevation prompt.
        let access = access
            .validated()
            .map_err(|_| PlatformError::ControlFailed)?;
        completed_mutation(ServiceControlIntent::SetExternalAccess(access))
    }
}

/// Addresses are rendered `ip:port` (IPv6 in brackets); the LAN address is
/// the IP alone. `None` if the service sent an unusable combination.
fn external_access_view(
    access: ExternalAccess,
    external: Option<SocketAddr>,
    source: Option<direct_network::CandidateSource>,
    failure: Option<direct_network::DirectFailure>,
    lan: Option<SocketAddr>,
) -> Option<crate::ExternalAccessView> {
    use crate::{ExternalAccessFailure as Failure, ExternalAccessMode as Mode};
    use direct_network::{CandidateSource as Source, DirectFailure};
    let (mode, external_port, fixed_address) = match access.validated().ok()? {
        ExternalAccess::Automatic => (Mode::Automatic, None, None),
        ExternalAccess::RouterForward { external_port } => {
            (Mode::RouterForward, Some(external_port), None)
        }
        ExternalAccess::Fixed { address } => (Mode::Fixed, None, Some(address.to_string())),
    };
    crate::ExternalAccessView {
        mode,
        external_port,
        fixed_address,
        external_address: external.map(|address| address.to_string()),
        source: source.map(|source| match source {
            Source::Pcp => crate::ExternalCandidateSource::Pcp,
            Source::Upnp => crate::ExternalCandidateSource::Upnp,
            Source::Stun => crate::ExternalCandidateSource::Stun,
            Source::Fixed => crate::ExternalCandidateSource::Fixed,
            Source::PublicInterface => crate::ExternalCandidateSource::PublicInterface,
        }),
        lan_address: lan.map(|address| address.ip().to_string()),
        relay_port: windows_service_host::EMBEDDED_RELAY_PORT,
        failure: failure.map(|failure| match failure {
            DirectFailure::NoMappingProtocol => Failure::NoMappingProtocol,
            DirectFailure::PrivateExternalAddress => Failure::PrivateExternalAddress,
            DirectFailure::PublicAddressUnavailable => Failure::PublicAddressUnavailable,
        }),
    }
    .checked()
}

fn project_direct_state(
    state: windows_service_host::management_protocol::DirectConnectionState,
) -> crate::DirectConnectionState {
    use windows_service_host::management_protocol::DirectConnectionState as Native;
    match state {
        Native::Unknown => crate::DirectConnectionState::Unknown,
        Native::Discovering => crate::DirectConnectionState::Discovering,
        Native::LanOnly => crate::DirectConnectionState::LanOnly,
        Native::Candidate => crate::DirectConnectionState::Candidate,
        Native::Unavailable => crate::DirectConnectionState::Unavailable,
        Native::Stopped => crate::DirectConnectionState::Stopped,
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
    let windows_service_host::management_protocol::ManagementRequest::RemoveDevice { device } =
        windows_service_host::management_protocol::ManagementRequest::remove_device(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows_service_host::management_protocol::{
        ManagementRequest, decode_request, encode_request,
    };

    #[test]
    fn a_missed_optional_read_keeps_the_last_answer_only_within_the_hold() {
        let start = Instant::now();
        let mut slot = None;
        assert_eq!(hold(&mut slot, None::<u8>, start), None);
        assert_eq!(hold(&mut slot, Some(1), start), Some(1));
        assert_eq!(hold(&mut slot, None, start + OPTIONAL_READ_HOLD), Some(1));
        assert_eq!(
            hold(&mut slot, Some(2), start + OPTIONAL_READ_HOLD),
            Some(2)
        );
        let later = start + OPTIONAL_READ_HOLD * 2 + Duration::from_millis(1);
        assert_eq!(hold(&mut slot, None, later), None);
        assert!(slot.is_none());
        assert_eq!(hold(&mut slot, None, later), None);
    }

    #[test]
    fn lowercase_device_identifier_builds_typed_intent_and_round_trips() {
        for text in [
            "0123456789abcdef0123456789abcdef",
            "00000000000000000000000000000001",
            "ffffffffffffffffffffffffffffffff",
        ] {
            let ServiceControlIntent::RemoveDevice(device) = remove_device_intent(text).unwrap()
            else {
                panic!("device identifier must produce only device removal");
            };
            assert_eq!(device_hex(device.as_bytes()), text);
            let request = ManagementRequest::remove_device(*device.as_bytes()).unwrap();
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()),
                Ok(request)
            );
        }
    }

    #[test]
    fn external_status_projects_to_the_pinned_view_for_each_mode() {
        use direct_network::{CandidateSource, DirectFailure};
        let lan: SocketAddr = "192.168.1.50:7443".parse().unwrap();
        let automatic = external_access_view(
            ExternalAccess::Automatic,
            None,
            None,
            Some(DirectFailure::NoMappingProtocol),
            Some(lan),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&automatic).unwrap(),
            serde_json::json!({
                "mode": "automatic", "externalPort": null, "fixedAddress": null,
                "externalAddress": null, "source": null, "lanAddress": "192.168.1.50",
                "relayPort": 7443, "failure": "no_mapping_protocol"
            })
        );
        let forward = external_access_view(
            ExternalAccess::RouterForward {
                external_port: 8443,
            },
            Some("93.184.216.34:8443".parse().unwrap()),
            Some(CandidateSource::Stun),
            None,
            Some(lan),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&forward).unwrap(),
            serde_json::json!({
                "mode": "router_forward", "externalPort": 8443, "fixedAddress": null,
                "externalAddress": "93.184.216.34:8443", "source": "stun",
                "lanAddress": "192.168.1.50", "relayPort": 7443, "failure": null
            })
        );
        let fixed_address: SocketAddr = "[2606:4700::1111]:7443".parse().unwrap();
        let fixed = external_access_view(
            ExternalAccess::Fixed {
                address: fixed_address,
            },
            Some(fixed_address),
            Some(CandidateSource::Fixed),
            None,
            Some("[2606:4700::5]:7443".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&fixed).unwrap(),
            serde_json::json!({
                "mode": "fixed", "externalPort": null,
                "fixedAddress": "[2606:4700::1111]:7443",
                "externalAddress": "[2606:4700::1111]:7443", "source": "fixed",
                "lanAddress": "2606:4700::5", "relayPort": 7443, "failure": null
            })
        );
        // An invalid access or a contradictory observation is not presented.
        assert!(
            external_access_view(
                ExternalAccess::RouterForward { external_port: 0 },
                None,
                None,
                None,
                None
            )
            .is_none()
        );
        assert!(
            external_access_view(
                ExternalAccess::Automatic,
                Some("93.184.216.34:7443".parse().unwrap()),
                None,
                None,
                None
            )
            .is_none()
        );
    }

    #[test]
    fn invalid_device_identifiers_fail_before_mutation_intent_exists() {
        // WindowsPlatformAdapter::remove_device resolves this fallible pure
        // intent before completed_mutation can launch any elevated helper.
        // These tests never call native mutation or request elevation.
        let non_ascii = "\u{e9}".repeat(16);
        for text in [
            "",
            "00000000000000000000000000000000",
            "0123456789ABCDEF0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            " 123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcde\n",
            non_ascii.as_str(),
        ] {
            assert!(matches!(
                remove_device_intent(text),
                Err(PlatformError::ControlFailed)
            ));
        }
    }
}
