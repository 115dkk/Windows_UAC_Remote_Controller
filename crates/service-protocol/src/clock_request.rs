// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed phone-to-PC clock request. Transport authentication remains required.
#![forbid(unsafe_code)]

use std::fmt;

use approval_protocol::PcIdentity;

use crate::{ClockProbe, ClockProbeNonce, PcEventError};

pub const CLOCK_REQUEST_BYTES: usize = 80;
const MAGIC: &[u8; 8] = b"UACCLCK\0";

/// Only a PC identity and a new probe challenge; no command, key selector,
/// claimed timestamp, signing payload or enrollment operation can be encoded.
/// The PC must accept it only from its authenticated enrolled transport owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ClockProbeRequest {
    pc: PcIdentity,
    nonce: ClockProbeNonce,
}

impl ClockProbeRequest {
    pub(crate) const fn from_probe(pc: PcIdentity, probe: &ClockProbe) -> Self {
        Self {
            pc,
            nonce: probe.nonce(),
        }
    }

    pub const fn pc(self) -> PcIdentity {
        self.pc
    }
    pub const fn nonce(self) -> ClockProbeNonce {
        self.nonce
    }

    pub fn to_wire(self) -> [u8; CLOCK_REQUEST_BYTES] {
        let mut bytes = [0; CLOCK_REQUEST_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..44].copy_from_slice(self.pc.as_bytes());
        bytes[44..76].copy_from_slice(self.nonce.as_bytes());
        bytes
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, PcEventError> {
        if bytes.len() != CLOCK_REQUEST_BYTES {
            return Err(PcEventError::InvalidLength);
        }
        if &bytes[..8] != MAGIC || bytes[10..12] != [0; 2] || bytes[76..80] != [0; 4] {
            return Err(PcEventError::InvalidEncoding);
        }
        if bytes[8..10] != 1_u16.to_be_bytes() {
            return Err(PcEventError::UnsupportedVersion);
        }
        Ok(Self {
            pc: PcIdentity::from_bytes(
                bytes[12..44]
                    .try_into()
                    .map_err(|_| PcEventError::InvalidLength)?,
            )
            .map_err(|_| PcEventError::InvalidFields)?,
            nonce: ClockProbeNonce::from_bytes(
                bytes[44..76]
                    .try_into()
                    .map_err(|_| PcEventError::InvalidLength)?,
            )?,
        })
    }
}

impl fmt::Debug for ClockProbeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClockProbeRequest([redacted], transport_required)")
    }
}
