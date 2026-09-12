// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded local management protocol. It carries public registry metadata only.
#![forbid(unsafe_code)]

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::DeviceId;

pub const MAX_MANAGEMENT_FRAME: usize = 16 * 1024;
const MAGIC: &[u8; 4] = b"UCMG";
const VERSION: u8 = 1;
const MAX_IDENTITY_PROVIDER: usize = 256;
const MAX_REFUSAL: usize = 512;
const MAX_DIGESTS: usize = 32;
const MAX_DEVICES: usize = 32;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ManagementRequest {
    Query,
    RemoveDevice { device: DeviceId },
    SetRelay { address: SocketAddr },
    UseEmbeddedRelay,
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
    Snapshot {
        relay: Option<SocketAddr>,
        identity_provider: String,
        android_signer_digests: Vec<[u8; 32]>,
        devices: Vec<DeviceRow>,
    },
    Done,
    Refused(String),
}

impl fmt::Debug for ManagementResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        ManagementRequest::UseEmbeddedRelay => writer.byte(4),
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
        4 => ManagementRequest::UseEmbeddedRelay,
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
        ManagementResponse::Snapshot {
            relay,
            identity_provider,
            android_signer_digests,
            devices,
        } => {
            if identity_provider.len() > MAX_IDENTITY_PROVIDER
                || android_signer_digests.len() > MAX_DIGESTS
                || devices.len() > MAX_DEVICES
            {
                return Err(ManagementCodecError::Oversized);
            }
            if identity_provider.is_empty()
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
        0x81 => {
            let relay = reader.optional_address()?;
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
            ManagementResponse::Snapshot {
                relay,
                identity_provider,
                android_signer_digests,
                devices,
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

    fn device(value: u8) -> DeviceId {
        DeviceId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn every_request_and_response_round_trips_canonically() {
        let address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        for request in [
            ManagementRequest::Query,
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
                relay: Some(address),
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
        bad_version[4] = 2;
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
            relay: None,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![],
            devices: vec![row, row],
        };
        assert_eq!(
            encode_response(&response),
            Err(ManagementCodecError::Malformed)
        );
        let mut duplicate_digest_wire = encode_response(&ManagementResponse::Snapshot {
            relay: None,
            identity_provider: "fixture".into(),
            android_signer_digests: vec![[1; 32], [2; 32]],
            devices: vec![],
        })
        .unwrap();
        let first_digest = 6 + 1 + 2 + "fixture".len() + 2;
        let second_digest = first_digest + 32;
        duplicate_digest_wire.copy_within(first_digest..second_digest, second_digest);
        assert_eq!(
            decode_response(&duplicate_digest_wire),
            Err(ManagementCodecError::Malformed)
        );
        assert_eq!(
            encode_response(&ManagementResponse::Snapshot {
                relay: None,
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
                relay: Some("127.0.0.1:0".parse().unwrap()),
                identity_provider: "fixture".into(),
                android_signer_digests: vec![],
                devices: vec![],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                relay: None,
                identity_provider: "bad\nprovider".into(),
                android_signer_digests: vec![],
                devices: vec![],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                relay: None,
                identity_provider: "fixture".into(),
                android_signer_digests: vec![],
                devices: vec![DeviceRow { revision: 0, ..row }],
            })
            .is_err()
        );
        assert!(
            encode_response(&ManagementResponse::Snapshot {
                relay: None,
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
}
