// SPDX-License-Identifier: GPL-2.0-or-later
//! V2-only bounded routing hints. Neither a signature nor a route authorizes an
//! action. Receivers must bind the pending nonce, enrolled PC/device, route and
//! current boot epoch, and enforce a suspend-inclusive freshness deadline. No request
//! lifetime or immutable enrollment descriptor is modified by this protocol.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::{
    BootEpoch, DeviceId, MAX_DER_SIGNATURE_BYTES, MIN_DER_SIGNATURE_BYTES, PcIdentity,
};
use secure_channel::CertificateVerifySignature;
use thiserror::Error;

use crate::{ClockProbeNonce, PcPublicKey, codec::Reader};

const MAGIC: &[u8; 8] = b"WUACADR\0";
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/address-advertisement/v2\0";
pub const MAX_ADDRESS_CANDIDATES: usize = 4;
pub const MAX_ADDRESS_VALIDITY_SECONDS: u32 = 3600;
/// Minimum service-side spacing for routing queries, unrelated to hint freshness.
pub const ADDRESS_QUERY_MIN_INTERVAL_SECONDS: u64 = 5;
pub const ADDRESS_QUERY_BYTES: usize = 12 + 32 + 16 + 32 + 32;
pub const MAX_ADDRESS_ADVERTISEMENT_BYTES: usize =
    ADDRESS_QUERY_BYTES + 32 + 4 + 1 + 4 * 19 + 2 + MAX_DER_SIGNATURE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressControlKind {
    Query,
    Advertisement,
}

/// Classification only, not validation. A matching magic with malformed fields
/// must fail closed rather than be passed to another protocol parser.
pub fn address_control_kind(bytes: &[u8]) -> Option<AddressControlKind> {
    if bytes.get(..8)? != MAGIC {
        return None;
    }
    match bytes.get(10) {
        Some(1) => Some(AddressControlKind::Query),
        Some(2) => Some(AddressControlKind::Advertisement),
        _ => None,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AddressQuery {
    pub pc: PcIdentity,
    pub device: DeviceId,
    pub route: [u8; 32],
    pub nonce: ClockProbeNonce,
}

impl AddressQuery {
    pub fn new(
        pc: PcIdentity,
        device: DeviceId,
        route: [u8; 32],
        nonce: ClockProbeNonce,
    ) -> Result<Self, AddressError> {
        validate_route(&route)?;
        Ok(Self {
            pc,
            device,
            route,
            nonce,
        })
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = header(1);
        bytes.extend_from_slice(self.pc.as_bytes());
        bytes.extend_from_slice(self.device.as_bytes());
        bytes.extend_from_slice(&self.route);
        bytes.extend_from_slice(self.nonce.as_bytes());
        bytes
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.len() != ADDRESS_QUERY_BYTES {
            return Err(AddressError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        read_header(&mut reader, 1)?;
        let result = read_query(&mut reader)?;
        reader.finish().map_err(|_| AddressError::InvalidLength)?;
        Ok(result)
    }
}

/// Freely constructible shape. Empty endpoints with TTL zero withdraw all
/// alternate hints. Nonempty hints require TTL 1..=3600 seconds from receipt;
/// receivers must additionally bound outstanding query age and consume nonce.
/// Expired coordinates may be tried only as untrusted locators, never as fresh
/// reachability evidence; new pinned TLS and current-state checks remain mandatory.
/// Replaying a signed hint cannot refresh its deadline or override withdrawal.
#[derive(Clone, Eq, PartialEq)]
pub struct AddressAdvertisementFields {
    pub pc: PcIdentity,
    pub epoch: BootEpoch,
    pub device: DeviceId,
    pub route: [u8; 32],
    pub nonce: ClockProbeNonce,
    pub valid_for_seconds: u32,
    pub endpoints: Vec<SocketAddr>,
}

impl AddressAdvertisementFields {
    fn validate(&self) -> Result<(), AddressError> {
        validate_route(&self.route)?;
        if self.endpoints.len() > MAX_ADDRESS_CANDIDATES
            || self.valid_for_seconds > MAX_ADDRESS_VALIDITY_SECONDS
            || self.endpoints.is_empty() != (self.valid_for_seconds == 0)
        {
            return Err(AddressError::InvalidFields);
        }
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            validate_endpoint(*endpoint)?;
            if self.endpoints[..index].contains(endpoint) {
                return Err(AddressError::InvalidFields);
            }
        }
        Ok(())
    }
}

pub struct UnsignedAddressAdvertisement {
    fields: AddressAdvertisementFields,
}

impl UnsignedAddressAdvertisement {
    pub fn new(fields: AddressAdvertisementFields) -> Result<Self, AddressError> {
        fields.validate()?;
        Ok(Self { fields })
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(&self.fields)
    }
    pub fn with_der_signature(
        self,
        der: &[u8],
    ) -> Result<SignedAddressAdvertisement, AddressError> {
        validate_signature(der)?;
        Ok(SignedAddressAdvertisement {
            fields: self.fields,
            der: der.to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct SignedAddressAdvertisement {
    fields: AddressAdvertisementFields,
    der: Vec<u8>,
}

impl SignedAddressAdvertisement {
    pub fn from_wire(bytes: &[u8]) -> Result<Self, AddressError> {
        if !(ADDRESS_QUERY_BYTES + 32 + 4 + 1 + 2 + MIN_DER_SIGNATURE_BYTES
            ..=MAX_ADDRESS_ADVERTISEMENT_BYTES)
            .contains(&bytes.len())
        {
            return Err(AddressError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        read_header(&mut reader, 2)?;
        let query = read_query(&mut reader)?;
        let epoch =
            BootEpoch::from_bytes(array(&mut reader)?).map_err(|_| AddressError::InvalidFields)?;
        let valid_for_seconds = u32::from_be_bytes(array(&mut reader)?);
        let count = usize::from(array::<1>(&mut reader)?[0]);
        if count > MAX_ADDRESS_CANDIDATES {
            return Err(AddressError::InvalidFields);
        }
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            endpoints.push(read_endpoint(&mut reader)?);
        }
        let fields = AddressAdvertisementFields {
            pc: query.pc,
            epoch,
            device: query.device,
            route: query.route,
            nonce: query.nonce,
            valid_for_seconds,
            endpoints,
        };
        fields.validate()?;
        let length = usize::from(u16::from_be_bytes(array(&mut reader)?));
        let der = reader
            .take(length)
            .map_err(|_| AddressError::InvalidLength)?;
        reader.finish().map_err(|_| AddressError::InvalidLength)?;
        validate_signature(der)?;
        Ok(Self {
            fields,
            der: der.to_vec(),
        })
    }
    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = body(&self.fields);
        bytes.extend_from_slice(&(self.der.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.der);
        bytes
    }
    /// Verifies signature only. Independently enforce current enrollment,
    /// nonce, route, epoch and expiry before caching or dialing any endpoint.
    pub fn verify(&self, key: &PcPublicKey) -> Result<VerifiedAddressAdvertisement, AddressError> {
        key.verify_transcript(&signing_bytes(&self.fields), &self.der)
            .map_err(|_| AddressError::InvalidSignature)?;
        Ok(VerifiedAddressAdvertisement {
            fields: self.fields.clone(),
        })
    }
}

pub struct VerifiedAddressAdvertisement {
    fields: AddressAdvertisementFields,
}
impl VerifiedAddressAdvertisement {
    pub const fn fields(&self) -> &AddressAdvertisementFields {
        &self.fields
    }
}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    )+};
}
redacted_debug!(
    AddressQuery,
    AddressAdvertisementFields,
    UnsignedAddressAdvertisement,
    SignedAddressAdvertisement,
    VerifiedAddressAdvertisement
);

fn validate_route(route: &[u8; 32]) -> Result<(), AddressError> {
    if route.iter().all(|byte| *byte == 0) {
        Err(AddressError::InvalidFields)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_endpoint(endpoint: SocketAddr) -> Result<(), AddressError> {
    let ip = endpoint.ip();
    if endpoint.port() == 0 || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return Err(AddressError::InvalidEndpoint);
    }
    match endpoint {
        SocketAddr::V4(address)
            if address.ip().is_broadcast()
                || address.ip().octets()[0] == 0
                || address.ip().octets()[0] >= 240 =>
        {
            Err(AddressError::InvalidEndpoint)
        }
        SocketAddr::V6(address)
            if address.flowinfo() != 0
                || address.scope_id() != 0
                || address.ip().to_ipv4_mapped().is_some()
                || address.ip().is_unicast_link_local() =>
        {
            Err(AddressError::InvalidEndpoint)
        }
        _ => Ok(()),
    }
}

pub(crate) fn write_endpoint(bytes: &mut Vec<u8>, endpoint: SocketAddr) {
    bytes.push(if endpoint.is_ipv4() { 4 } else { 6 });
    bytes.extend_from_slice(&endpoint.port().to_be_bytes());
    match endpoint.ip() {
        IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.extend_from_slice(&ip.octets()),
    }
}

pub(crate) fn read_endpoint(reader: &mut Reader<'_>) -> Result<SocketAddr, AddressError> {
    let family = array::<1>(reader)?[0];
    let port = u16::from_be_bytes(array(reader)?);
    let ip = match family {
        4 => IpAddr::V4(Ipv4Addr::from(array::<4>(reader)?)),
        6 => IpAddr::V6(Ipv6Addr::from(array::<16>(reader)?)),
        _ => return Err(AddressError::InvalidEndpoint),
    };
    let endpoint = SocketAddr::new(ip, port);
    validate_endpoint(endpoint)?;
    Ok(endpoint)
}

fn header(kind: u8) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[0, 2, kind, 0]);
    bytes
}
fn read_header(reader: &mut Reader<'_>, kind: u8) -> Result<(), AddressError> {
    if array::<8>(reader)? != *MAGIC || array::<4>(reader)? != [0, 2, kind, 0] {
        return Err(AddressError::InvalidEncoding);
    }
    Ok(())
}
fn read_query(reader: &mut Reader<'_>) -> Result<AddressQuery, AddressError> {
    AddressQuery::new(
        PcIdentity::from_bytes(array(reader)?).map_err(|_| AddressError::InvalidFields)?,
        DeviceId::from_bytes(array(reader)?).map_err(|_| AddressError::InvalidFields)?,
        array(reader)?,
        ClockProbeNonce::from_bytes(array(reader)?).map_err(|_| AddressError::InvalidFields)?,
    )
}
fn body(fields: &AddressAdvertisementFields) -> Vec<u8> {
    let query = AddressQuery {
        pc: fields.pc,
        device: fields.device,
        route: fields.route,
        nonce: fields.nonce,
    };
    let mut bytes = query.to_wire();
    bytes[10] = 2;
    bytes.extend_from_slice(fields.epoch.as_bytes());
    bytes.extend_from_slice(&fields.valid_for_seconds.to_be_bytes());
    bytes.push(fields.endpoints.len() as u8);
    for endpoint in &fields.endpoints {
        write_endpoint(&mut bytes, *endpoint);
    }
    bytes
}
fn signing_bytes(fields: &AddressAdvertisementFields) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&body(fields));
    bytes
}
fn array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], AddressError> {
    reader
        .take(N)
        .map_err(|_| AddressError::InvalidLength)?
        .try_into()
        .map_err(|_| AddressError::InvalidLength)
}
fn validate_signature(der: &[u8]) -> Result<(), AddressError> {
    if !(MIN_DER_SIGNATURE_BYTES..=MAX_DER_SIGNATURE_BYTES).contains(&der.len()) {
        return Err(AddressError::InvalidSignature);
    }
    CertificateVerifySignature::from_der(der)
        .map(|_| ())
        .map_err(|_| AddressError::InvalidSignature)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AddressError {
    #[error("invalid address control length")]
    InvalidLength,
    #[error("invalid address control encoding")]
    InvalidEncoding,
    #[error("invalid address control fields")]
    InvalidFields,
    #[error("invalid address control endpoint")]
    InvalidEndpoint,
    #[error("invalid address control signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests;
