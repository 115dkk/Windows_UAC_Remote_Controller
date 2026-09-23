// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded local management protocol. It carries public registry metadata only.
#![forbid(unsafe_code)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::DeviceId;
use direct_network::{CandidateSource, DirectFailure, ExternalAccess};

pub const MAX_MANAGEMENT_FRAME: usize = 16 * 1024;
const MAGIC: &[u8; 4] = b"UCMG";
const VERSION: u8 = 3;
pub const MAX_ACTIVITY_RECORDS: usize = 64;
const MAX_ACTIVITY_JSON: usize = 12 * 1024;
const MAX_IDENTITY_PROVIDER: usize = 256;
const MAX_REFUSAL: usize = 512;
const MAX_DIGESTS: usize = 32;
const MAX_DEVICES: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ManagementRequest {
    Query,
    /// Separate optional read so legacy Snapshot bytes remain unchanged.
    QueryDirect,
    RemoveDevice {
        device: DeviceId,
    },
    SetRelay {
        address: SocketAddr,
    },
    UseEmbeddedRelay,
    /// Separate optional read, like `QueryDirect`; older services refuse it.
    QueryExternal,
    /// Elevated CLI only. The value is validated on both encode and decode.
    SetExternalAccess {
        access: ExternalAccess,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectConnectionState {
    Unknown = 0,
    Discovering = 1,
    LanOnly = 2,
    Candidate = 3,
    Unavailable = 4,
    Stopped = 5,
}

fn direct_state(value: u8) -> Result<DirectConnectionState, ManagementCodecError> {
    Ok(match value {
        0 => DirectConnectionState::Unknown,
        1 => DirectConnectionState::Discovering,
        2 => DirectConnectionState::LanOnly,
        3 => DirectConnectionState::Candidate,
        4 => DirectConnectionState::Unavailable,
        5 => DirectConnectionState::Stopped,
        _ => return Err(ManagementCodecError::Malformed),
    })
}

fn candidate_source(value: u8) -> Result<Option<CandidateSource>, ManagementCodecError> {
    Ok(Some(match value {
        0 => return Ok(None),
        1 => CandidateSource::Pcp,
        2 => CandidateSource::Upnp,
        3 => CandidateSource::Stun,
        4 => CandidateSource::Fixed,
        5 => CandidateSource::PublicInterface,
        _ => return Err(ManagementCodecError::Malformed),
    }))
}

fn candidate_source_byte(value: Option<CandidateSource>) -> u8 {
    match value {
        None => 0,
        Some(CandidateSource::Pcp) => 1,
        Some(CandidateSource::Upnp) => 2,
        Some(CandidateSource::Stun) => 3,
        Some(CandidateSource::Fixed) => 4,
        Some(CandidateSource::PublicInterface) => 5,
    }
}

fn direct_failure(value: u8) -> Result<Option<DirectFailure>, ManagementCodecError> {
    Ok(Some(match value {
        0 => return Ok(None),
        1 => DirectFailure::NoMappingProtocol,
        2 => DirectFailure::PrivateExternalAddress,
        3 => DirectFailure::PublicAddressUnavailable,
        _ => return Err(ManagementCodecError::Malformed),
    }))
}

fn direct_failure_byte(value: Option<DirectFailure>) -> u8 {
    match value {
        None => 0,
        Some(DirectFailure::NoMappingProtocol) => 1,
        Some(DirectFailure::PrivateExternalAddress) => 2,
        Some(DirectFailure::PublicAddressUnavailable) => 3,
    }
}

/// A published candidate always names its source, and a failure is reported
/// only while no candidate is published. Addresses follow the relay rules.
fn validate_external(
    external: Option<SocketAddr>,
    source: Option<CandidateSource>,
    failure: Option<DirectFailure>,
    lan: Option<SocketAddr>,
) -> Result<(), ManagementCodecError> {
    if external.is_some() != source.is_some()
        || (external.is_some() && failure.is_some())
        || external
            .into_iter()
            .chain(lan)
            .any(|address| crate::contract::validate_relay_endpoint(address).is_err())
    {
        return Err(ManagementCodecError::Malformed);
    }
    Ok(())
}

fn validate_direct(
    embedded: bool,
    listening: bool,
    state: DirectConnectionState,
) -> Result<(), ManagementCodecError> {
    if (!embedded && listening)
        || (matches!(
            state,
            DirectConnectionState::Discovering
                | DirectConnectionState::LanOnly
                | DirectConnectionState::Candidate
        ) && (!embedded || !listening))
        || (state == DirectConnectionState::Stopped && listening)
    {
        return Err(ManagementCodecError::Malformed);
    }
    Ok(())
}

impl ManagementRequest {
    /// Validates a device identifier without constructing a transport frame.
    /// This creates only a request value; mutation still requires the native
    /// elevated management path and its independent authorization checks.
    pub fn remove_device(bytes: [u8; 16]) -> Result<Self, ManagementCodecError> {
        let device = DeviceId::from_bytes(bytes).map_err(|_| ManagementCodecError::Malformed)?;
        Ok(Self::RemoveDevice { device })
    }
}

impl fmt::Debug for ManagementRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagementRequest(redacted)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceRow {
    pub device: DeviceId,
    pub revision: u64,
    pub route_present: bool,
    pub connected: bool,
    pub enrolled_unix_secs: Option<u64>,
}

impl fmt::Debug for DeviceRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRow")
            .field("revision", &self.revision)
            .field("route_present", &self.route_present)
            .field("connected", &self.connected)
            .field("enrolled_unix_secs", &self.enrolled_unix_secs)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ManagementResponse {
    DirectStatus {
        embedded_relay: bool,
        relay_listening: bool,
        state: DirectConnectionState,
    },
    /// Local clients of this PC only. `access` is the configured mode; the
    /// rest is the current gateway owner's observation, `None` without one.
    /// `external` is a published candidate, not proof of reachability.
    ExternalStatus {
        access: ExternalAccess,
        external: Option<SocketAddr>,
        source: Option<CandidateSource>,
        failure: Option<DirectFailure>,
        /// The owner's internal endpoint: this PC's routed address and port.
        lan: Option<SocketAddr>,
    },
    Snapshot {
        relay: Option<SocketAddr>,
        /// Selected service mode, independent of advertised relay readiness.
        embedded_relay: bool,
        /// Actual local HostedRelay listener state; always false externally.
        relay_listening: bool,
        identity_provider: String,
        android_signer_digests: Vec<[u8; 32]>,
        devices: Vec<DeviceRow>,
        /// Recent records from the service's exclusive journal owner. None is
        /// unavailable, distinct from a successfully read empty journal.
        activity: Option<Vec<activity_journal::ActivityRecord>>,
    },
    Done,
    Refused(String),
}

impl fmt::Debug for ManagementResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectStatus { state, .. } => f
                .debug_tuple("ManagementResponse::DirectStatus")
                .field(state)
                .finish(),
            Self::ExternalStatus {
                source, failure, ..
            } => f
                .debug_struct("ManagementResponse::ExternalStatus")
                .field("source", source)
                .field("failure", failure)
                .finish_non_exhaustive(),
            Self::Snapshot { devices, .. } => f
                .debug_struct("ManagementResponse::Snapshot")
                .field("devices", &devices.len())
                .finish_non_exhaustive(),
            Self::Done => f.write_str("ManagementResponse::Done"),
            Self::Refused(_) => f.write_str("ManagementResponse::Refused(redacted)"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementCodecError {
    Malformed,
    Oversized,
}

pub fn encode_request(request: &ManagementRequest) -> Result<Vec<u8>, ManagementCodecError> {
    let mut writer = Writer::new();
    match request {
        ManagementRequest::Query => writer.byte(1),
        ManagementRequest::QueryDirect => writer.byte(5),
        ManagementRequest::QueryExternal => writer.byte(6),
        ManagementRequest::UseEmbeddedRelay => writer.byte(4),
        ManagementRequest::SetExternalAccess { access } => {
            writer.byte(7);
            writer.external_access(*access)?;
        }
        ManagementRequest::RemoveDevice { device } => {
            writer.byte(2);
            writer.bytes(device.as_bytes());
        }
        ManagementRequest::SetRelay { address } => {
            crate::contract::validate_relay_endpoint(*address)
                .map_err(|_| ManagementCodecError::Malformed)?;
            writer.byte(3);
            writer.address(*address);
        }
    }
    writer.finish()
}

pub fn decode_request(bytes: &[u8]) -> Result<ManagementRequest, ManagementCodecError> {
    let mut reader = Reader::new(bytes)?;
    let value = match reader.byte()? {
        1 => ManagementRequest::Query,
        5 => ManagementRequest::QueryDirect,
        6 => ManagementRequest::QueryExternal,
        4 => ManagementRequest::UseEmbeddedRelay,
        7 => ManagementRequest::SetExternalAccess {
            access: reader.external_access()?,
        },
        2 => ManagementRequest::RemoveDevice {
            device: DeviceId::from_bytes(reader.array()?)
                .map_err(|_| ManagementCodecError::Malformed)?,
        },
        3 => ManagementRequest::SetRelay {
            address: reader.address()?,
        },
        _ => return Err(ManagementCodecError::Malformed),
    };
    reader.finish()?;
    Ok(value)
}

pub fn encode_response(response: &ManagementResponse) -> Result<Vec<u8>, ManagementCodecError> {
    let mut writer = Writer::new();
    match response {
        ManagementResponse::DirectStatus {
            embedded_relay,
            relay_listening,
            state,
        } => {
            validate_direct(*embedded_relay, *relay_listening, *state)?;
            writer.byte(0x84);
            writer.boolean(*embedded_relay);
            writer.boolean(*relay_listening);
            writer.byte(*state as u8);
        }
        ManagementResponse::ExternalStatus {
            access,
            external,
            source,
            failure,
            lan,
        } => {
            validate_external(*external, *source, *failure, *lan)?;
            writer.byte(0x85);
            writer.external_access(*access)?;
            writer.optional_address(*external);
            writer.byte(candidate_source_byte(*source));
            writer.byte(direct_failure_byte(*failure));
            writer.optional_address(*lan);
        }
        ManagementResponse::Snapshot {
            relay,
            embedded_relay,
            relay_listening,
            identity_provider,
            android_signer_digests,
            devices,
            activity,
        } => {
            if identity_provider.len() > MAX_IDENTITY_PROVIDER
                || android_signer_digests.len() > MAX_DIGESTS
                || devices.len() > MAX_DEVICES
            {
                return Err(ManagementCodecError::Oversized);
            }
            if identity_provider.is_empty()
                || (!*embedded_relay && *relay_listening)
                || (*embedded_relay && !*relay_listening && relay.is_some())
                || identity_provider.chars().any(char::is_control)
                || relay.is_some_and(|address| {
                    crate::contract::validate_relay_endpoint(address).is_err()
                })
            {
                return Err(ManagementCodecError::Malformed);
            }
            if android_signer_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| android_signer_digests[..index].contains(digest))
                || devices.iter().enumerate().any(|(index, row)| {
                    row.revision == 0
                        || devices[..index]
                            .iter()
                            .any(|seen| seen.device == row.device)
                })
            {
                return Err(ManagementCodecError::Malformed);
            }
            writer.byte(0x81);
            writer.optional_address(*relay);
            writer.boolean(*embedded_relay);
            writer.boolean(*relay_listening);
            writer.text(identity_provider)?;
            writer.count(android_signer_digests.len())?;
            for digest in android_signer_digests {
                writer.bytes(digest);
            }
            writer.count(devices.len())?;
            for row in devices {
                writer.bytes(row.device.as_bytes());
                writer.u64(row.revision);
                writer.boolean(row.route_present);
                writer.boolean(row.connected);
                match row.enrolled_unix_secs {
                    Some(value) => {
                        writer.byte(1);
                        writer.u64(value);
                    }
                    None => writer.byte(0),
                }
            }
            match activity {
                None => writer.byte(0),
                Some(records) => {
                    if records.len() > MAX_ACTIVITY_RECORDS {
                        return Err(ManagementCodecError::Oversized);
                    }
                    let json = serde_json::to_string(records)
                        .map_err(|_| ManagementCodecError::Malformed)?;
                    if json.len() > MAX_ACTIVITY_JSON {
                        return Err(ManagementCodecError::Oversized);
                    }
                    writer.byte(1);
                    writer.text(&json)?;
                }
            }
        }
        ManagementResponse::Done => writer.byte(0x82),
        ManagementResponse::Refused(reason) => {
            if reason.len() > MAX_REFUSAL {
                return Err(ManagementCodecError::Oversized);
            }
            if reason.is_empty() || reason.chars().any(char::is_control) {
                return Err(ManagementCodecError::Malformed);
            }
            writer.byte(0x83);
            writer.text(reason)?;
        }
    }
    writer.finish()
}

pub fn decode_response(bytes: &[u8]) -> Result<ManagementResponse, ManagementCodecError> {
    let mut reader = Reader::new(bytes)?;
    let value = match reader.byte()? {
        0x84 => {
            let embedded_relay = reader.boolean()?;
            let relay_listening = reader.boolean()?;
            let state = direct_state(reader.byte()?)?;
            validate_direct(embedded_relay, relay_listening, state)?;
            ManagementResponse::DirectStatus {
                embedded_relay,
                relay_listening,
                state,
            }
        }
        0x85 => {
            let access = reader.external_access()?;
            let external = reader.optional_address()?;
            let source = candidate_source(reader.byte()?)?;
            let failure = direct_failure(reader.byte()?)?;
            let lan = reader.optional_address()?;
            validate_external(external, source, failure, lan)?;
            ManagementResponse::ExternalStatus {
                access,
                external,
                source,
                failure,
                lan,
            }
        }
        0x81 => {
            let relay = reader.optional_address()?;
            let embedded_relay = reader.boolean()?;
            let relay_listening = reader.boolean()?;
            if (!embedded_relay && relay_listening)
                || (embedded_relay && !relay_listening && relay.is_some())
            {
                return Err(ManagementCodecError::Malformed);
            }
            let identity_provider = reader.text(MAX_IDENTITY_PROVIDER)?;
            if identity_provider.is_empty() {
                return Err(ManagementCodecError::Malformed);
            }
            let digest_count = reader.count(MAX_DIGESTS)?;
            let mut android_signer_digests = Vec::with_capacity(digest_count);
            for _ in 0..digest_count {
                let digest = reader.array()?;
                if android_signer_digests.contains(&digest) {
                    return Err(ManagementCodecError::Malformed);
                }
                android_signer_digests.push(digest);
            }
            let device_count = reader.count(MAX_DEVICES)?;
            let mut devices = Vec::with_capacity(device_count);
            for _ in 0..device_count {
                let device = DeviceId::from_bytes(reader.array()?)
                    .map_err(|_| ManagementCodecError::Malformed)?;
                let revision = reader.u64()?;
                if revision == 0 || devices.iter().any(|row: &DeviceRow| row.device == device) {
                    return Err(ManagementCodecError::Malformed);
                }
                let route_present = reader.boolean()?;
                let connected = reader.boolean()?;
                let enrolled_unix_secs = match reader.byte()? {
                    0 => None,
                    1 => Some(reader.u64()?),
                    _ => return Err(ManagementCodecError::Malformed),
                };
                devices.push(DeviceRow {
                    device,
                    revision,
                    route_present,
                    connected,
                    enrolled_unix_secs,
                });
            }
            let activity = match reader.byte()? {
                0 => None,
                1 => {
                    let json = reader.text(MAX_ACTIVITY_JSON)?;
                    let records: Vec<activity_journal::ActivityRecord> =
                        serde_json::from_str(&json).map_err(|_| ManagementCodecError::Malformed)?;
                    if records.len() > MAX_ACTIVITY_RECORDS {
                        return Err(ManagementCodecError::Malformed);
                    }
                    Some(records)
                }
                _ => return Err(ManagementCodecError::Malformed),
            };
            ManagementResponse::Snapshot {
                relay,
                embedded_relay,
                relay_listening,
                identity_provider,
                android_signer_digests,
                devices,
                activity,
            }
        }
        0x82 => ManagementResponse::Done,
        0x83 => {
            let reason = reader.text(MAX_REFUSAL)?;
            if reason.is_empty() {
                return Err(ManagementCodecError::Malformed);
            }
            ManagementResponse::Refused(reason)
        }
        _ => return Err(ManagementCodecError::Malformed),
    };
    reader.finish()?;
    Ok(value)
}

struct Writer(Vec<u8>);
impl Writer {
    fn new() -> Self {
        let mut value = Vec::with_capacity(128);
        value.extend_from_slice(MAGIC);
        value.push(VERSION);
        Self(value)
    }
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }
    fn count(&mut self, value: usize) -> Result<(), ManagementCodecError> {
        self.u16(u16::try_from(value).map_err(|_| ManagementCodecError::Oversized)?);
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<(), ManagementCodecError> {
        self.count(value.len())?;
        self.bytes(value.as_bytes());
        Ok(())
    }
    fn optional_address(&mut self, value: Option<SocketAddr>) {
        match value {
            None => self.byte(0),
            Some(address) => {
                self.byte(1);
                self.address(address);
            }
        }
    }
    fn address(&mut self, value: SocketAddr) {
        match value.ip() {
            IpAddr::V4(ip) => {
                self.byte(4);
                self.bytes(&ip.octets());
            }
            IpAddr::V6(ip) => {
                self.byte(6);
                self.bytes(&ip.octets());
            }
        }
        self.u16(value.port());
    }
    fn external_access(&mut self, value: ExternalAccess) -> Result<(), ManagementCodecError> {
        match value
            .validated()
            .map_err(|_| ManagementCodecError::Malformed)?
        {
            ExternalAccess::Automatic => self.byte(0),
            ExternalAccess::RouterForward { external_port } => {
                self.byte(1);
                self.u16(external_port);
            }
            ExternalAccess::Fixed { address } => {
                self.byte(2);
                self.address(address);
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<Vec<u8>, ManagementCodecError> {
        if self.0.len() > MAX_MANAGEMENT_FRAME {
            Err(ManagementCodecError::Oversized)
        } else {
            Ok(self.0)
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, ManagementCodecError> {
        if bytes.len() > MAX_MANAGEMENT_FRAME {
            return Err(ManagementCodecError::Oversized);
        }
        if bytes.len() < 6 || bytes.get(..4) != Some(MAGIC) || bytes[4] != VERSION {
            return Err(ManagementCodecError::Malformed);
        }
        Ok(Self { bytes, at: 5 })
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ManagementCodecError> {
        let end = self
            .at
            .checked_add(length)
            .ok_or(ManagementCodecError::Malformed)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(ManagementCodecError::Malformed)?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, ManagementCodecError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ManagementCodecError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ManagementCodecError::Malformed)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, ManagementCodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ManagementCodecError::Malformed)?,
        ))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManagementCodecError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ManagementCodecError::Malformed)
    }
    fn boolean(&mut self) -> Result<bool, ManagementCodecError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ManagementCodecError::Malformed),
        }
    }
    fn count(&mut self, maximum: usize) -> Result<usize, ManagementCodecError> {
        let value = usize::from(self.u16()?);
        if value > maximum {
            Err(ManagementCodecError::Malformed)
        } else {
            Ok(value)
        }
    }
    fn text(&mut self, maximum: usize) -> Result<String, ManagementCodecError> {
        let length = self.count(maximum)?;
        let text =
            std::str::from_utf8(self.take(length)?).map_err(|_| ManagementCodecError::Malformed)?;
        if text.chars().any(char::is_control) {
            return Err(ManagementCodecError::Malformed);
        }
        Ok(text.to_owned())
    }
    fn optional_address(&mut self) -> Result<Option<SocketAddr>, ManagementCodecError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.address().map(Some),
            _ => Err(ManagementCodecError::Malformed),
        }
    }
    fn address(&mut self) -> Result<SocketAddr, ManagementCodecError> {
        let ip = match self.byte()? {
            4 => IpAddr::V4(Ipv4Addr::from(self.array::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(self.array::<16>()?)),
            _ => return Err(ManagementCodecError::Malformed),
        };
        let address = SocketAddr::new(ip, self.u16()?);
        crate::contract::validate_relay_endpoint(address)
            .map_err(|_| ManagementCodecError::Malformed)?;
        Ok(address)
    }
    fn external_access(&mut self) -> Result<ExternalAccess, ManagementCodecError> {
        match self.byte()? {
            0 => ExternalAccess::Automatic,
            1 => ExternalAccess::RouterForward {
                external_port: self.u16()?,
            },
            2 => ExternalAccess::Fixed {
                address: self.address()?,
            },
            _ => return Err(ManagementCodecError::Malformed),
        }
        .validated()
        .map_err(|_| ManagementCodecError::Malformed)
    }
    fn finish(self) -> Result<(), ManagementCodecError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(ManagementCodecError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_direct_query_keeps_ordinary_query_wire_unchanged() {
        assert_eq!(
            encode_request(&ManagementRequest::Query).unwrap(),
            b"UCMG\x03\x01"
        );
        let wire = encode_request(&ManagementRequest::QueryDirect).unwrap();
        assert_eq!(wire, b"UCMG\x03\x05");
        assert_eq!(
            decode_request(&wire).unwrap(),
            ManagementRequest::QueryDirect
        );
        let mut extra = wire;
        extra.push(0);
        assert!(decode_request(&extra).is_err());
    }

    #[test]
    fn direct_status_is_bounded_and_not_a_connection_claim() {
        for state in [
            DirectConnectionState::Discovering,
            DirectConnectionState::LanOnly,
            DirectConnectionState::Candidate,
            DirectConnectionState::Unavailable,
            DirectConnectionState::Unknown,
        ] {
            let status = ManagementResponse::DirectStatus {
                embedded_relay: true,
                relay_listening: true,
                state,
            };
            let wire = encode_response(&status).unwrap();
            assert_eq!(wire.len(), 9);
            assert_eq!(decode_response(&wire).unwrap(), status);
            let mut bad = wire;
            bad[8] = 255;
            assert!(decode_response(&bad).is_err());
        }
        assert!(
            encode_response(&ManagementResponse::DirectStatus {
                embedded_relay: false,
                relay_listening: false,
                state: DirectConnectionState::Candidate
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::DirectStatus {
                embedded_relay: true,
                relay_listening: true,
                state: DirectConnectionState::Stopped
            })
            .is_err()
        );
    }

    fn device(value: u8) -> DeviceId {
        DeviceId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn journal_projection_round_trips_absence_empty_and_bounded_records() {
        let record: activity_journal::ActivityRecord = serde_json::from_value(serde_json::json!({
            "timestamp_unix_ms": 1000,
            "event": {"category":"request","outcome":{"state":"windows_applied","detail":{"decision":"deny"}}}
        })).unwrap();
        let snapshot = |activity| ManagementResponse::Snapshot {
            relay: None,
            embedded_relay: false,
            relay_listening: false,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![],
            devices: vec![],
            activity,
        };
        for records in [None, Some(vec![]), Some(vec![record; MAX_ACTIVITY_RECORDS])] {
            let response = snapshot(records);
            let wire = encode_response(&response).unwrap();
            assert_eq!(decode_response(&wire), Ok(response));
            for end in 0..wire.len() {
                assert!(decode_response(&wire[..end]).is_err());
            }
        }
        assert_eq!(
            encode_response(&snapshot(Some(vec![record; MAX_ACTIVITY_RECORDS + 1]))),
            Err(ManagementCodecError::Oversized)
        );
        let mut invalid = encode_response(&snapshot(None)).unwrap();
        *invalid.last_mut().unwrap() = 2;
        assert_eq!(
            decode_response(&invalid),
            Err(ManagementCodecError::Malformed)
        );
    }

    #[test]
    fn typed_device_removal_validates_identity_and_uses_current_codec() {
        assert_eq!(
            ManagementRequest::remove_device([0; 16]),
            Err(ManagementCodecError::Malformed)
        );
        for bytes in [
            [1; 16],
            [0xff; 16],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ] {
            let request = ManagementRequest::remove_device(bytes).unwrap();
            let ManagementRequest::RemoveDevice { device } = request else {
                panic!("typed constructor must create only device removal");
            };
            assert_eq!(device.as_bytes(), &bytes);
            assert_eq!(
                decode_request(&encode_request(&request).unwrap()),
                Ok(request)
            );
        }
    }

    #[test]
    fn every_request_and_response_round_trips_canonically() {
        let address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        for request in [
            ManagementRequest::Query,
            ManagementRequest::UseEmbeddedRelay,
            ManagementRequest::RemoveDevice { device: device(1) },
            ManagementRequest::SetRelay { address },
        ] {
            let wire = encode_request(&request).unwrap();
            assert_eq!(decode_request(&wire), Ok(request));
            assert!(wire.len() <= MAX_MANAGEMENT_FRAME);
        }
        let responses = [
            ManagementResponse::Done,
            ManagementResponse::Refused("요청을 처리할 수 없습니다.".into()),
            ManagementResponse::Snapshot {
                activity: None,
                relay: Some(address),
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "fixture".into(),
                android_signer_digests: vec![[7; 32]],
                devices: vec![DeviceRow {
                    device: device(2),
                    revision: 9,
                    route_present: true,
                    connected: false,
                    enrolled_unix_secs: None,
                }],
            },
        ];
        for response in responses {
            let wire = encode_response(&response).unwrap();
            assert_eq!(decode_response(&wire), Ok(response));
            assert!(wire.len() <= MAX_MANAGEMENT_FRAME);
        }
    }

    #[test]
    fn relay_telemetry_v3_has_fixed_boolean_encoding_and_rejects_v1() {
        let response = ManagementResponse::Snapshot {
            activity: None,
            relay: None,
            embedded_relay: true,
            relay_listening: false,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![],
            devices: vec![],
        };
        let wire = encode_response(&response).unwrap();
        assert_eq!(
            wire,
            b"UCMG\x03\x81\x00\x01\x00\x00\x07fixture\x00\x00\x00\x00\x00"
        );
        assert_eq!(decode_response(&wire), Ok(response));
        for offset in [7, 8] {
            for noncanonical in [2, 255] {
                let mut invalid = wire.clone();
                invalid[offset] = noncanonical;
                assert_eq!(
                    decode_response(&invalid),
                    Err(ManagementCodecError::Malformed)
                );
            }
        }
        let mut old_version = wire;
        old_version[4] = 1;
        assert_eq!(
            decode_response(&old_version),
            Err(ManagementCodecError::Malformed)
        );
    }

    #[test]
    fn relay_mode_listener_and_readiness_combinations_are_checked_both_ways() {
        let address: SocketAddr = "127.0.0.1:7443".parse().unwrap();
        for relay in [None, Some(address)] {
            for embedded_relay in [false, true] {
                for relay_listening in [false, true] {
                    let response = ManagementResponse::Snapshot {
                        activity: None,
                        relay,
                        embedded_relay,
                        relay_listening,
                        identity_provider: "fixture".into(),
                        android_signer_digests: vec![],
                        devices: vec![],
                    };
                    let valid = !((!embedded_relay && relay_listening)
                        || (embedded_relay && !relay_listening && relay.is_some()));
                    if valid {
                        assert_eq!(
                            decode_response(&encode_response(&response).unwrap()),
                            Ok(response)
                        );
                    } else {
                        assert_eq!(
                            encode_response(&response),
                            Err(ManagementCodecError::Malformed)
                        );
                        let mut wire = encode_response(&ManagementResponse::Snapshot {
                            activity: None,
                            relay,
                            embedded_relay: false,
                            relay_listening: false,
                            identity_provider: "fixture".into(),
                            android_signer_digests: vec![],
                            devices: vec![],
                        })
                        .unwrap();
                        let flags = if relay.is_some() { 14 } else { 7 };
                        wire[flags] = u8::from(embedded_relay);
                        wire[flags + 1] = u8::from(relay_listening);
                        assert_eq!(decode_response(&wire), Err(ManagementCodecError::Malformed));
                    }
                }
            }
        }
    }

    #[test]
    fn truncation_trailing_unknown_and_noncanonical_fields_are_rejected() {
        let request =
            encode_request(&ManagementRequest::RemoveDevice { device: device(3) }).unwrap();
        for end in 0..request.len() {
            assert!(decode_request(&request[..end]).is_err());
        }
        let mut trailing = request.clone();
        trailing.push(0);
        assert!(decode_request(&trailing).is_err());
        let mut unknown = request.clone();
        unknown[5] = 0xff;
        assert!(decode_request(&unknown).is_err());
        let mut bad_magic = request.clone();
        bad_magic[0] ^= 1;
        assert!(decode_request(&bad_magic).is_err());
        let mut bad_version = request;
        bad_version[4] = 1;
        assert!(decode_request(&bad_version).is_err());
        assert_eq!(
            decode_request(&vec![0; MAX_MANAGEMENT_FRAME + 1]),
            Err(ManagementCodecError::Oversized)
        );
    }

    #[test]
    fn duplicate_devices_invalid_flags_and_bounds_are_rejected() {
        let row = DeviceRow {
            device: device(4),
            revision: 1,
            route_present: false,
            connected: false,
            enrolled_unix_secs: None,
        };
        let response = ManagementResponse::Snapshot {
            activity: None,
            relay: None,
            embedded_relay: false,
            relay_listening: false,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![],
            devices: vec![row, row],
        };
        assert_eq!(
            encode_response(&response),
            Err(ManagementCodecError::Malformed)
        );
        let mut duplicate_digest_wire = encode_response(&ManagementResponse::Snapshot {
            activity: None,
            relay: None,
            embedded_relay: false,
            relay_listening: false,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![[1; 32], [2; 32]],
            devices: vec![],
        })
        .unwrap();
        let first_digest = 6 + 1 + 2 + 2 + "fixture".len() + 2;
        let second_digest = first_digest + 32;
        duplicate_digest_wire.copy_within(first_digest..second_digest, second_digest);
        assert_eq!(
            decode_response(&duplicate_digest_wire),
            Err(ManagementCodecError::Malformed)
        );
        assert_eq!(
            encode_response(&ManagementResponse::Snapshot {
                activity: None,
                relay: None,
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "fixture".into(),
                android_signer_digests: vec![[3; 32], [3; 32]],
                devices: vec![],
            }),
            Err(ManagementCodecError::Malformed)
        );
        assert!(
            encode_response(&ManagementResponse::Refused("x".repeat(MAX_REFUSAL + 1))).is_err()
        );
        assert!(
            encode_request(&ManagementRequest::SetRelay {
                address: "0.0.0.0:443".parse().unwrap(),
            })
            .is_err()
        );
        assert!(encode_response(&ManagementResponse::Refused("bad\nreason".into())).is_err());
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                activity: None,
                relay: Some("127.0.0.1:0".parse().unwrap()),
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "fixture".into(),
                android_signer_digests: vec![],
                devices: vec![],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                activity: None,
                relay: None,
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "bad\nprovider".into(),
                android_signer_digests: vec![],
                devices: vec![],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                activity: None,
                relay: None,
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "fixture".into(),
                android_signer_digests: vec![],
                devices: vec![DeviceRow { revision: 0, ..row }],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                activity: None,
                relay: None,
                embedded_relay: false,
                relay_listening: false,
                identity_provider: "x".repeat(MAX_IDENTITY_PROVIDER + 1),
                android_signer_digests: vec![],
                devices: vec![],
            })
            .is_err()
        );
        let mut done = encode_response(&ManagementResponse::Done).unwrap();
        done.push(0);
        assert!(decode_response(&done).is_err());
    }

    fn public() -> SocketAddr {
        "93.184.216.34:7443".parse().unwrap()
    }

    fn external_status(
        access: ExternalAccess,
        external: Option<SocketAddr>,
        source: Option<CandidateSource>,
        failure: Option<DirectFailure>,
        lan: Option<SocketAddr>,
    ) -> ManagementResponse {
        ManagementResponse::ExternalStatus {
            access,
            external,
            source,
            failure,
            lan,
        }
    }

    #[test]
    fn external_requests_use_new_tags_and_validate_the_access_both_ways() {
        assert_eq!(
            encode_request(&ManagementRequest::QueryExternal).unwrap(),
            b"UCMG\x03\x06"
        );
        assert_eq!(
            decode_request(b"UCMG\x03\x06"),
            Ok(ManagementRequest::QueryExternal)
        );
        assert!(decode_request(b"UCMG\x03\x06\x00").is_err());
        let v6: SocketAddr = "[2606:4700::1111]:443".parse().unwrap();
        for (access, wire) in [
            (ExternalAccess::Automatic, b"UCMG\x03\x07\x00".to_vec()),
            (
                ExternalAccess::RouterForward {
                    external_port: 7443,
                },
                b"UCMG\x03\x07\x01\x1d\x13".to_vec(),
            ),
            (
                ExternalAccess::Fixed { address: public() },
                b"UCMG\x03\x07\x02\x04\x5d\xb8\xd8\x22\x1d\x13".to_vec(),
            ),
        ] {
            let request = ManagementRequest::SetExternalAccess { access };
            assert_eq!(encode_request(&request).unwrap(), wire);
            assert_eq!(decode_request(&wire), Ok(request));
            for end in 0..wire.len() {
                assert!(decode_request(&wire[..end]).is_err());
            }
            let mut trailing = wire.clone();
            trailing.push(0);
            assert!(decode_request(&trailing).is_err());
            assert_eq!(format!("{request:?}"), "ManagementRequest(redacted)");
        }
        let request = ManagementRequest::SetExternalAccess {
            access: ExternalAccess::Fixed { address: v6 },
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()),
            Ok(request)
        );
        for access in [
            ExternalAccess::RouterForward { external_port: 0 },
            ExternalAccess::Fixed {
                address: "192.168.1.20:7443".parse().unwrap(),
            },
            ExternalAccess::Fixed {
                address: "93.184.216.34:0".parse().unwrap(),
            },
        ] {
            assert_eq!(
                encode_request(&ManagementRequest::SetExternalAccess { access }),
                Err(ManagementCodecError::Malformed)
            );
        }
        for wire in [
            &b"UCMG\x03\x07\x01\x00\x00"[..],
            b"UCMG\x03\x07\x02\x04\xc0\xa8\x01\x14\x1d\x13",
            b"UCMG\x03\x07\x02\x04\x5d\xb8\xd8\x22\x00\x00",
            b"UCMG\x03\x07\x02\x05\x5d\xb8\xd8\x22\x1d\x13",
            b"UCMG\x03\x07\x03",
            b"UCMG\x03\x07\x00\x00",
            b"UCMG\x03\x07",
        ] {
            assert_eq!(decode_request(wire), Err(ManagementCodecError::Malformed));
        }
    }

    #[test]
    fn external_status_round_trips_every_mode_source_and_failure() {
        let lan: SocketAddr = "192.168.1.50:7443".parse().unwrap();
        let responses = [
            external_status(ExternalAccess::Automatic, None, None, None, None),
            external_status(
                ExternalAccess::Automatic,
                None,
                None,
                Some(DirectFailure::NoMappingProtocol),
                Some(lan),
            ),
            external_status(
                ExternalAccess::Automatic,
                None,
                None,
                Some(DirectFailure::PrivateExternalAddress),
                Some(lan),
            ),
            external_status(
                ExternalAccess::Automatic,
                Some(public()),
                Some(CandidateSource::Pcp),
                None,
                Some(lan),
            ),
            external_status(
                ExternalAccess::Automatic,
                Some(public()),
                Some(CandidateSource::Upnp),
                None,
                Some(lan),
            ),
            external_status(
                ExternalAccess::RouterForward {
                    external_port: 8443,
                },
                Some("93.184.216.34:8443".parse().unwrap()),
                Some(CandidateSource::Stun),
                None,
                Some(lan),
            ),
            external_status(
                ExternalAccess::RouterForward {
                    external_port: 8443,
                },
                Some("93.184.216.34:8443".parse().unwrap()),
                Some(CandidateSource::PublicInterface),
                None,
                Some("93.184.216.34:7443".parse().unwrap()),
            ),
            external_status(
                ExternalAccess::RouterForward {
                    external_port: 8443,
                },
                None,
                None,
                Some(DirectFailure::PublicAddressUnavailable),
                Some(lan),
            ),
            external_status(
                ExternalAccess::Fixed { address: public() },
                Some(public()),
                Some(CandidateSource::Fixed),
                None,
                Some("[2606:4700::5]:7443".parse().unwrap()),
            ),
        ];
        for response in responses {
            let wire = encode_response(&response).unwrap();
            assert_eq!(wire[5], 0x85);
            assert_eq!(decode_response(&wire), Ok(response.clone()));
            for end in 0..wire.len() {
                assert!(decode_response(&wire[..end]).is_err());
            }
            let mut trailing = wire.clone();
            trailing.push(0);
            assert!(decode_response(&trailing).is_err());
            assert!(!format!("{response:?}").contains("93.184"));
            assert!(!format!("{response:?}").contains("192.168"));
        }
        assert_eq!(
            encode_response(&external_status(
                ExternalAccess::Automatic,
                None,
                None,
                None,
                None
            ))
            .unwrap(),
            b"UCMG\x03\x85\x00\x00\x00\x00\x00"
        );
    }

    #[test]
    fn contradictory_or_unknown_external_status_fields_are_rejected_both_ways() {
        for response in [
            // A candidate without a source, and a source without a candidate.
            external_status(ExternalAccess::Automatic, Some(public()), None, None, None),
            external_status(
                ExternalAccess::Automatic,
                None,
                Some(CandidateSource::Pcp),
                None,
                None,
            ),
            // A failure is reported only while nothing is published.
            external_status(
                ExternalAccess::Automatic,
                Some(public()),
                Some(CandidateSource::Pcp),
                Some(DirectFailure::NoMappingProtocol),
                None,
            ),
            external_status(
                ExternalAccess::Automatic,
                None,
                None,
                None,
                Some("0.0.0.0:7443".parse().unwrap()),
            ),
            external_status(
                ExternalAccess::Automatic,
                Some("93.184.216.34:0".parse().unwrap()),
                Some(CandidateSource::Pcp),
                None,
                None,
            ),
            external_status(
                ExternalAccess::RouterForward { external_port: 0 },
                None,
                None,
                None,
                None,
            ),
            external_status(
                ExternalAccess::Fixed {
                    address: "10.1.2.3:7443".parse().unwrap(),
                },
                None,
                None,
                None,
                None,
            ),
        ] {
            assert_eq!(
                encode_response(&response),
                Err(ManagementCodecError::Malformed)
            );
        }
        let valid = encode_response(&external_status(
            ExternalAccess::Automatic,
            None,
            None,
            None,
            None,
        ))
        .unwrap();
        // access, external flag, source, failure, lan flag.
        for (offset, value) in [(6, 3), (7, 2), (8, 6), (9, 4), (10, 2)] {
            let mut invalid = valid.clone();
            invalid[offset] = value;
            assert_eq!(
                decode_response(&invalid),
                Err(ManagementCodecError::Malformed)
            );
        }
        // Source byte set while no candidate is present.
        let mut orphan_source = valid.clone();
        orphan_source[8] = 1;
        assert_eq!(
            decode_response(&orphan_source),
            Err(ManagementCodecError::Malformed)
        );
        let mut candidate_and_failure = encode_response(&external_status(
            ExternalAccess::Automatic,
            Some(public()),
            Some(CandidateSource::Upnp),
            None,
            None,
        ))
        .unwrap();
        let failure_offset = candidate_and_failure.len() - 2;
        candidate_and_failure[failure_offset] = 1;
        assert_eq!(
            decode_response(&candidate_and_failure),
            Err(ManagementCodecError::Malformed)
        );
    }
}
