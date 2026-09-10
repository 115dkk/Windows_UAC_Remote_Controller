// SPDX-License-Identifier: GPL-2.0-or-later
//! Canonical ORIGINAL invitation shape and digest, not trusted QR provenance,
//! native consent, fresh-UAC evidence, attestation or permission to enroll.
//!
//! Native owners retain this original invitation independently of later frozen
//! candidates/acceptances. The live PC ceremony, nonce/handshake, strict single
//! candidate freeze, SAS comparison and native confirmation must reject replay
//! and unauthorized candidates. Capturing/copying a QR may cause denial of
//! service; knowing these bytes does not authorize enrollment. Decoding does not
//! start or renew the original five-minute monotonic native ceremony lifetime.
//! No wall-clock expiry, network connection, route allocation, key creation or
//! UI/scanner boundary exists here.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::{DeviceId, PcIdentity};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secure_channel::TlsPublicKey;
use sha2::{Digest, Sha256};

use super::{InvitationContextDigest, PairingChallenge, PairingNonce, SPKI_BYTES};
use crate::codec::Reader;

const MAGIC: &[u8; 8] = b"WUACQRI\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pairing-invitation/v1\0";
const FIXED_BYTES: usize = 12 + 32 + 32 + 32 + 16 + SPKI_BYTES * 2 + 1 + 2 + 32;

/// Exact IPv4 form: fixed fields341 + four address bytes.
pub const MIN_PAIRING_INVITATION_BYTES: usize = FIXED_BYTES + 4;
/// Exact IPv6 form: fixed fields341 + sixteen address bytes. No other wire size
/// is accepted in v1, even if it falls between these bounds.
pub const MAX_PAIRING_INVITATION_BYTES: usize = FIXED_BYTES + 16;
pub const PAIRING_INVITATION_QR_PREFIX: &str = "uac-remote:v1:";
/// Both permitted binary lengths are multiples of three: no base64 padding or
/// partial final symbol is necessary. Bounds include the exact14-byte prefix.
pub const MIN_PAIRING_INVITATION_QR_TEXT_BYTES: usize =
    PAIRING_INVITATION_QR_PREFIX.len() + MIN_PAIRING_INVITATION_BYTES / 3 * 4;
pub const MAX_PAIRING_INVITATION_QR_TEXT_BYTES: usize =
    PAIRING_INVITATION_QR_PREFIX.len() + MAX_PAIRING_INVITATION_BYTES / 3 * 4;

/// Freely constructible original-invitation inputs, never a trust witness.
/// The PC native ceremony supplies the fresh non-reused nonce/challenge and
/// recipient assignment. PC signing/transport keys may deliberately be equal.
/// No phone key is present before the phone creates its actual three-role set.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingInvitationFields {
    pub ceremony_nonce: PairingNonce,
    pub attestation_challenge: PairingChallenge,
    pub pc: PcIdentity,
    pub recipient_device: DeviceId,
    pub pc_signing_key: TlsPublicKey,
    pub pc_transport_key: TlsPublicKey,
    /// Numeric address only; nonzero port. IPv6 flowinfo/scope must be zero and
    /// IPv4-mapped IPv6 is rejected rather than silently rewritten as IPv4.
    /// Address reachability and deployment/egress policy are native-owner work.
    pub relay_address: SocketAddr,
    /// Public nonzero rendezvous name, NOT a secret or identity. Future carrier
    /// composition passes these bytes to the EXISTING relay_service::RouteId::new;
    /// this codec neither allocates a route nor duplicates relay registration.
    pub route: [u8; 32],
}

impl PairingInvitationFields {
    fn validate(&self) -> Result<(), PairingInvitationError> {
        if self.relay_address.port() == 0 {
            return Err(PairingInvitationError::InvalidEndpoint);
        }
        if let SocketAddr::V6(address) = self.relay_address
            && (address.flowinfo() != 0
                || address.scope_id() != 0
                || address.ip().to_ipv4_mapped().is_some())
        {
            return Err(PairingInvitationError::InvalidEndpoint);
        }
        if self.route.iter().all(|byte| *byte == 0) {
            return Err(PairingInvitationError::InvalidRoute);
        }
        Ok(())
    }
}

impl fmt::Debug for PairingInvitationFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInvitationFields([redacted], shape_only)")
    }
}

/// Canonically validated public invitation SHAPE only. Copying this value does
/// not mint consent, provenance, freshness, key possession or a pairing grant.
/// Explicit wire/text access only; no serde or Display conversion is supplied.
/// ```compile_fail
/// fn implicit_display(value: service_protocol::PairingInvitation) {
///     let _text = format!("{value}");
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PairingInvitation {
    fields: PairingInvitationFields,
}

impl PairingInvitation {
    pub fn new(fields: PairingInvitationFields) -> Result<Self, PairingInvitationError> {
        fields.validate()?;
        Ok(Self { fields })
    }

    pub const fn fields(&self) -> &PairingInvitationFields {
        &self.fields
    }

    /// Check exact permitted lengths before key parsing or any allocation. The
    /// common header and endpoint family determine one unique v1 interpretation.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, PairingInvitationError> {
        if bytes.len() != MIN_PAIRING_INVITATION_BYTES
            && bytes.len() != MAX_PAIRING_INVITATION_BYTES
        {
            return Err(PairingInvitationError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        if array::<8>(&mut reader)? != *MAGIC {
            return Err(PairingInvitationError::InvalidEncoding);
        }
        if u16::from_be_bytes(array(&mut reader)?) != VERSION {
            return Err(PairingInvitationError::UnsupportedVersion);
        }
        if array::<1>(&mut reader)? != [KIND] {
            return Err(PairingInvitationError::UnsupportedKind);
        }
        if array::<1>(&mut reader)? != [0] {
            return Err(PairingInvitationError::InvalidEncoding);
        }
        let ceremony_nonce = PairingNonce::from_bytes(array(&mut reader)?)
            .map_err(|_| PairingInvitationError::InvalidFields)?;
        let attestation_challenge = PairingChallenge::from_bytes(array(&mut reader)?)
            .map_err(|_| PairingInvitationError::InvalidFields)?;
        let pc = PcIdentity::from_bytes(array(&mut reader)?)
            .map_err(|_| PairingInvitationError::InvalidFields)?;
        let recipient_device = DeviceId::from_bytes(array(&mut reader)?)
            .map_err(|_| PairingInvitationError::InvalidFields)?;
        let pc_signing_key =
            super::key(&mut reader).map_err(|_| PairingInvitationError::InvalidKey)?;
        let pc_transport_key =
            super::key(&mut reader).map_err(|_| PairingInvitationError::InvalidKey)?;
        let family = array::<1>(&mut reader)?[0];
        let port = u16::from_be_bytes(array(&mut reader)?);
        let ip = match family {
            4 => IpAddr::V4(Ipv4Addr::from(array::<4>(&mut reader)?)),
            6 => IpAddr::V6(Ipv6Addr::from(array::<16>(&mut reader)?)),
            _ => return Err(PairingInvitationError::InvalidEndpoint),
        };
        let route = array(&mut reader)?;
        reader
            .finish()
            .map_err(|_| PairingInvitationError::InvalidLength)?;
        Self::new(PairingInvitationFields {
            ceremony_nonce,
            attestation_challenge,
            pc,
            recipient_device,
            pc_signing_key,
            pc_transport_key,
            relay_address: SocketAddr::new(ip, port),
            route,
        })
    }

    /// Canonical body: header; nonce; challenge; PC ID; original recipient ID;
    /// PC signing/transport SPKIs; family; BE port; address octets; public route.
    pub fn to_wire(&self) -> Vec<u8> {
        let fields = &self.fields;
        let capacity = match fields.relay_address {
            SocketAddr::V4(_) => MIN_PAIRING_INVITATION_BYTES,
            SocketAddr::V6(_) => MAX_PAIRING_INVITATION_BYTES,
        };
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[KIND, 0]);
        bytes.extend_from_slice(fields.ceremony_nonce.as_bytes());
        bytes.extend_from_slice(fields.attestation_challenge.as_bytes());
        bytes.extend_from_slice(fields.pc.as_bytes());
        bytes.extend_from_slice(fields.recipient_device.as_bytes());
        bytes.extend_from_slice(fields.pc_signing_key.as_spki_der());
        bytes.extend_from_slice(fields.pc_transport_key.as_spki_der());
        match fields.relay_address {
            SocketAddr::V4(address) => {
                bytes.push(4);
                bytes.extend_from_slice(&address.port().to_be_bytes());
                bytes.extend_from_slice(&address.ip().octets());
            }
            SocketAddr::V6(address) => {
                bytes.push(6);
                bytes.extend_from_slice(&address.port().to_be_bytes());
                bytes.extend_from_slice(&address.ip().octets());
            }
        }
        bytes.extend_from_slice(&fields.route);
        bytes
    }

    /// Exact ASCII prefix and canonical unpadded URL-safe base64 only. No URL
    /// parser, trimming, case folding, percent decoding or relaxed base64 mode.
    /// Bound text before decoding into a fixed stack buffer, then reuse the wire
    /// parser. The decoded bytes confer no scanner/native provenance.
    pub fn from_qr_text(text: &str) -> Result<Self, PairingInvitationError> {
        if text.len() != MIN_PAIRING_INVITATION_QR_TEXT_BYTES
            && text.len() != MAX_PAIRING_INVITATION_QR_TEXT_BYTES
        {
            return Err(PairingInvitationError::InvalidLength);
        }
        let payload = text
            .strip_prefix(PAIRING_INVITATION_QR_PREFIX)
            .filter(|payload| {
                payload
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
            .ok_or(PairingInvitationError::InvalidQrText)?;
        // URL_SAFE_NO_PAD requires no padding and rejects noncanonical trailing
        // bits. The explicit alphabet check also excludes whitespace/non-ASCII.
        let mut bytes = [0u8; MAX_PAIRING_INVITATION_BYTES];
        let length = URL_SAFE_NO_PAD
            .decode_slice(payload, &mut bytes)
            .map_err(|_| PairingInvitationError::InvalidQrText)?;
        Self::from_wire(&bytes[..length])
    }

    /// Explicit public QR payload, not a QR image or a trusted-display result.
    pub fn to_qr_text(&self) -> String {
        let wire = self.to_wire();
        let mut text =
            String::with_capacity(PAIRING_INVITATION_QR_PREFIX.len() + wire.len() / 3 * 4);
        text.push_str(PAIRING_INVITATION_QR_PREFIX);
        URL_SAFE_NO_PAD.encode_string(&wire, &mut text);
        text
    }

    /// SHA-256 of the distinct invitation domain followed by the FULL canonical
    /// original body (including header, endpoint and route). Native PC/phone
    /// owners independently call this on their retained ORIGINAL invitation,
    /// never on a digest or reconstructed context learned from a frozen reply.
    pub fn context_digest(&self) -> InvitationContextDigest {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(self.to_wire());
        InvitationContextDigest::from_bytes(digest.finalize().into())
    }
}

impl fmt::Debug for PairingInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInvitation([redacted], shape_only)")
    }
}

fn array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], PairingInvitationError> {
    super::array(reader).map_err(|_| PairingInvitationError::InvalidLength)
}

/// Fixed categories with no input-bearing payload or implicit text conversion.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PairingInvitationError {
    InvalidLength,
    InvalidEncoding,
    UnsupportedVersion,
    UnsupportedKind,
    InvalidFields,
    InvalidKey,
    InvalidEndpoint,
    InvalidRoute,
    InvalidQrText,
}

impl fmt::Debug for PairingInvitationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingInvitationError([redacted])")
    }
}

#[cfg(test)]
mod tests;
