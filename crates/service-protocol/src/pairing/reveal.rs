// SPDX-License-Identifier: GPL-2.0-or-later
//! Commitment opening sent only after the signed frozen candidate is matched.

use std::fmt;

use sha2::{Digest, Sha256};

use super::{InvitationContextDigest, PairingError, PairingNonce, PhoneKeyDigest};
use crate::codec::Reader;

const MAGIC: &[u8; 8] = b"WUACRVL\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;
const COMMITMENT_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pairing-sas-commitment/v1\0";

pub const PAIRING_REVEAL_BYTES: usize = 140;

/// Random opening retained privately until the original frozen candidate matches.
/// Construction proves width only; the phone owner must supply fresh CSPRNG bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct PhoneReveal([u8; 32]);

impl PhoneReveal {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PhoneReveal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PhoneReveal([redacted])")
    }
}

pub fn sas_commitment(
    ceremony_nonce: PairingNonce,
    invitation_context: InvitationContextDigest,
    phone_keys: PhoneKeyDigest,
    reveal: &PhoneReveal,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COMMITMENT_DOMAIN);
    digest.update(ceremony_nonce.as_bytes());
    digest.update(invitation_context.as_bytes());
    digest.update(phone_keys.as_bytes());
    digest.update(reveal.as_bytes());
    digest.finalize().into()
}

/// Shape-only fields; the PC must match all bindings and open the commitment.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingRevealFields {
    pub ceremony_nonce: PairingNonce,
    pub phone_keys: PhoneKeyDigest,
    pub candidate_digest: [u8; 32],
    pub phone_reveal: PhoneReveal,
}

impl fmt::Debug for PairingRevealFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingRevealFields([redacted], shape_only)")
    }
}

pub struct PairingReveal {
    fields: PairingRevealFields,
}

impl PairingReveal {
    pub fn new(fields: PairingRevealFields) -> Result<Self, PairingError> {
        if fields.candidate_digest == [0; 32] {
            return Err(PairingError::InvalidFields);
        }
        Ok(Self { fields })
    }

    pub const fn fields(&self) -> &PairingRevealFields {
        &self.fields
    }

    pub fn to_wire(&self) -> [u8; PAIRING_REVEAL_BYTES] {
        let mut bytes = [0; PAIRING_REVEAL_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = KIND;
        bytes[12..44].copy_from_slice(self.fields.ceremony_nonce.as_bytes());
        bytes[44..76].copy_from_slice(self.fields.phone_keys.as_bytes());
        bytes[76..108].copy_from_slice(&self.fields.candidate_digest);
        bytes[108..140].copy_from_slice(self.fields.phone_reveal.as_bytes());
        bytes
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() != PAIRING_REVEAL_BYTES {
            return Err(PairingError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        if super::array::<8>(&mut reader)? != *MAGIC {
            return Err(PairingError::InvalidEncoding);
        }
        if u16::from_be_bytes(super::array(&mut reader)?) != VERSION {
            return Err(PairingError::UnsupportedVersion);
        }
        if super::array::<1>(&mut reader)? != [KIND] {
            return Err(PairingError::UnsupportedKind);
        }
        if super::array::<1>(&mut reader)? != [0] {
            return Err(PairingError::InvalidEncoding);
        }
        let ceremony_nonce = PairingNonce::from_bytes(super::array(&mut reader)?)?;
        let phone_keys = PhoneKeyDigest::from_bytes(super::array(&mut reader)?);
        let candidate_digest = super::array(&mut reader)?;
        let phone_reveal = PhoneReveal::from_bytes(super::array(&mut reader)?);
        reader.finish().map_err(|_| PairingError::InvalidLength)?;
        Self::new(PairingRevealFields {
            ceremony_nonce,
            phone_keys,
            candidate_digest,
            phone_reveal,
        })
    }
}

impl fmt::Debug for PairingReveal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingReveal([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> PairingRevealFields {
        PairingRevealFields {
            ceremony_nonce: PairingNonce::from_bytes([1; 32]).unwrap(),
            phone_keys: PhoneKeyDigest::from_bytes([2; 32]),
            candidate_digest: [3; 32],
            phone_reveal: PhoneReveal::from_bytes([4; 32]),
        }
    }

    #[test]
    fn exact_layout_roundtrips_and_classifies() {
        let value = PairingReveal::new(fields()).unwrap();
        let wire = value.to_wire();
        assert_eq!(wire.len(), 140);
        assert_eq!(&wire[..12], b"WUACRVL\0\x00\x01\x01\x00");
        assert_eq!(&wire[12..44], &[1; 32]);
        assert_eq!(&wire[44..76], &[2; 32]);
        assert_eq!(&wire[76..108], &[3; 32]);
        assert_eq!(&wire[108..140], &[4; 32]);
        assert_eq!(PairingReveal::from_wire(&wire).unwrap().fields(), &fields());
        assert_eq!(
            super::super::ceremony_message_kind(&wire),
            Some(super::super::CeremonyMessageKind::Reveal)
        );
    }

    #[test]
    fn malformed_reveals_reject() {
        let wire = PairingReveal::new(fields()).unwrap().to_wire();
        for length in 0..wire.len() {
            assert!(PairingReveal::from_wire(&wire[..length]).is_err());
        }
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert!(PairingReveal::from_wire(&trailing).is_err());
        for (offset, value, error) in [
            (0, b'X', PairingError::InvalidEncoding),
            (9, 2, PairingError::UnsupportedVersion),
            (10, 2, PairingError::UnsupportedKind),
            (11, 1, PairingError::InvalidEncoding),
        ] {
            let mut bad = wire;
            bad[offset] = value;
            assert_eq!(PairingReveal::from_wire(&bad).unwrap_err(), error);
        }
        for range in [12..44, 76..108] {
            let mut bad = wire;
            bad[range].fill(0);
            assert_eq!(
                PairingReveal::from_wire(&bad).unwrap_err(),
                PairingError::InvalidFields
            );
        }
    }

    #[test]
    fn commitment_uses_exact_domain_and_all_inputs() {
        let value = fields();
        let context = InvitationContextDigest::from_bytes([5; 32]);
        let mut oracle = b"Windows-UAC-Remote-Controller/pairing-sas-commitment/v1\0".to_vec();
        oracle.extend_from_slice(&[1; 32]);
        oracle.extend_from_slice(&[5; 32]);
        oracle.extend_from_slice(&[2; 32]);
        oracle.extend_from_slice(&[4; 32]);
        let expected: [u8; 32] = Sha256::digest(oracle).into();
        assert_eq!(
            sas_commitment(
                value.ceremony_nonce,
                context,
                value.phone_keys,
                &value.phone_reveal
            ),
            expected
        );
        for index in 0..4 {
            let mut nonce = value.ceremony_nonce;
            let mut context = context;
            let mut keys = value.phone_keys;
            let mut reveal = value.phone_reveal.clone();
            match index {
                0 => nonce = PairingNonce::from_bytes([9; 32]).unwrap(),
                1 => context = InvitationContextDigest::from_bytes([9; 32]),
                2 => keys = PhoneKeyDigest::from_bytes([9; 32]),
                _ => reveal = PhoneReveal::from_bytes([9; 32]),
            }
            assert_ne!(sas_commitment(nonce, context, keys, &reveal), expected);
        }
        assert_eq!(
            format!("{:?}", value.phone_reveal),
            "PhoneReveal([redacted])"
        );
        assert_eq!(
            format!("{:?}", PairingReveal::new(value).unwrap()),
            "PairingReveal([redacted])"
        );
    }
}
