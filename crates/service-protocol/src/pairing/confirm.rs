// SPDX-License-Identifier: GPL-2.0-or-later
//! TLS-protected phone confirmation for one exact frozen-candidate wire.

use std::fmt;

use sha2::{Digest, Sha256};

use super::{PairingError, PairingNonce, PhoneKeyDigest};
use crate::codec::Reader;

const MAGIC: &[u8; 8] = b"WUACCFM\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;

pub const PAIRING_CONFIRMATION_BYTES: usize = 109;

/// Shape-only confirmation fields. The ceremony owner must compare every value
/// with its retained candidate and live state before accepting the result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairingConfirmationFields {
    pub ceremony_nonce: PairingNonce,
    pub phone_keys: PhoneKeyDigest,
    pub candidate_digest: [u8; 32],
    pub confirmed: bool,
}

impl fmt::Debug for PairingConfirmationFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingConfirmationFields([redacted], shape_only)")
    }
}

/// Unsigned confirmation sent only inside the mutually authenticated, pinned TLS
/// channel. Parsing alone proves neither channel provenance nor enrollment intent.
pub struct PairingConfirmation {
    fields: PairingConfirmationFields,
}

impl PairingConfirmation {
    pub fn new(fields: PairingConfirmationFields) -> Result<Self, PairingError> {
        if fields.candidate_digest.iter().all(|byte| *byte == 0) {
            return Err(PairingError::InvalidFields);
        }
        Ok(Self { fields })
    }

    pub const fn fields(&self) -> &PairingConfirmationFields {
        &self.fields
    }

    pub fn to_wire(&self) -> [u8; PAIRING_CONFIRMATION_BYTES] {
        let mut bytes = [0u8; PAIRING_CONFIRMATION_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[10] = KIND;
        bytes[12..44].copy_from_slice(self.fields.ceremony_nonce.as_bytes());
        bytes[44..76].copy_from_slice(self.fields.phone_keys.as_bytes());
        bytes[76..108].copy_from_slice(&self.fields.candidate_digest);
        bytes[108] = u8::from(self.fields.confirmed);
        bytes
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, PairingError> {
        if bytes.len() != PAIRING_CONFIRMATION_BYTES {
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
        let confirmed = match super::array::<1>(&mut reader)?[0] {
            0 => false,
            1 => true,
            _ => return Err(PairingError::InvalidEncoding),
        };
        reader.finish().map_err(|_| PairingError::InvalidLength)?;
        Self::new(PairingConfirmationFields {
            ceremony_nonce,
            phone_keys,
            candidate_digest,
            confirmed,
        })
    }
}

impl fmt::Debug for PairingConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingConfirmation(redacted)")
    }
}

/// SHA-256 of the exact signed frozen-candidate wire matched by both peers.
pub fn candidate_digest(frozen_wire: &[u8]) -> [u8; 32] {
    Sha256::digest(frozen_wire).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(confirmed: bool) -> PairingConfirmationFields {
        PairingConfirmationFields {
            ceremony_nonce: PairingNonce::from_bytes([1; 32]).unwrap(),
            phone_keys: PhoneKeyDigest::from_bytes([2; 32]),
            candidate_digest: [3; 32],
            confirmed,
        }
    }

    #[test]
    fn true_and_false_roundtrip_in_exact_fixed_layout() {
        assert_eq!(PAIRING_CONFIRMATION_BYTES, 109);
        for confirmed in [false, true] {
            let original = fields(confirmed);
            let confirmation = PairingConfirmation::new(original).unwrap();
            let wire = confirmation.to_wire();
            assert_eq!(&wire[..12], b"WUACCFM\0\x00\x01\x01\x00");
            assert_eq!(&wire[12..44], &[1; 32]);
            assert_eq!(&wire[44..76], &[2; 32]);
            assert_eq!(&wire[76..108], &[3; 32]);
            assert_eq!(wire[108], u8::from(confirmed));
            let decoded = PairingConfirmation::from_wire(&wire).unwrap();
            assert_eq!(decoded.fields(), &original);
            assert_eq!(decoded.to_wire(), wire);
        }
    }

    #[test]
    fn malformed_length_header_boolean_and_zero_fields_reject() {
        let wire = PairingConfirmation::new(fields(true)).unwrap().to_wire();
        assert!(PairingConfirmation::from_wire(&wire[..108]).is_err());
        let mut trailing = wire.to_vec();
        trailing.push(0);
        assert_eq!(
            PairingConfirmation::from_wire(&trailing).unwrap_err(),
            PairingError::InvalidLength
        );
        for (offset, value, expected) in [
            (0, b'X', PairingError::InvalidEncoding),
            (9, 2, PairingError::UnsupportedVersion),
            (10, 2, PairingError::UnsupportedKind),
            (11, 1, PairingError::InvalidEncoding),
            (108, 2, PairingError::InvalidEncoding),
        ] {
            let mut bad = wire;
            bad[offset] = value;
            assert_eq!(PairingConfirmation::from_wire(&bad).unwrap_err(), expected);
        }
        let mut zero_nonce = wire;
        zero_nonce[12..44].fill(0);
        assert_eq!(
            PairingConfirmation::from_wire(&zero_nonce).unwrap_err(),
            PairingError::InvalidFields
        );
        let mut zero_digest = wire;
        zero_digest[76..108].fill(0);
        assert_eq!(
            PairingConfirmation::from_wire(&zero_digest).unwrap_err(),
            PairingError::InvalidFields
        );
        let mut invalid = fields(false);
        invalid.candidate_digest = [0; 32];
        assert!(matches!(
            PairingConfirmation::new(invalid),
            Err(PairingError::InvalidFields)
        ));
    }

    #[test]
    fn candidate_digest_hashes_exact_supplied_wire() {
        let wire = b"synthetic signed frozen candidate";
        let expected: [u8; 32] = Sha256::digest(wire).into();
        assert_eq!(candidate_digest(wire), expected);
        let mut changed = wire.to_vec();
        changed.push(0);
        assert_ne!(candidate_digest(&changed), expected);
    }

    #[test]
    fn debug_output_is_redacted() {
        let confirmation = PairingConfirmation::new(fields(true)).unwrap();
        assert_eq!(
            format!("{:?}", confirmation.fields()),
            "PairingConfirmationFields([redacted], shape_only)"
        );
        assert_eq!(format!("{confirmation:?}"), "PairingConfirmation(redacted)");
    }
}
