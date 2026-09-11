// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded plaintext candidate submission for the first enrollment phase.
//!
//! This codec proves message shape only. Attestation verification, key possession,
//! ceremony freshness, candidate freezing, TLS upgrade and enrollment remain with
//! their native owners. Certificate chains are retained leaf first as supplied.

use std::fmt;

use approval_protocol::{DeviceId, PcIdentity};
use secure_channel::TlsPublicKey;
use sha2::{Digest, Sha256};

use super::{
    InvitationContextDigest, PairingChallenge, PairingError, PairingNonce, PhoneKeyDigest,
};
use crate::codec::Reader;

const MAGIC: &[u8; 8] = b"WUACSUB\0";
const VERSION: u16 = 1;
const KIND: u8 = 1;
const FIXED_BYTES: usize = 429;
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/candidate-submission/v1";

pub const MAX_SUBMISSION_CERTIFICATES: usize = 8;
pub const MAX_SUBMISSION_CERTIFICATE_BYTES: usize = 8 * 1024;
pub const MAX_SUBMISSION_CHAIN_BYTES: usize = 32 * 1024;
pub const MIN_CANDIDATE_SUBMISSION_BYTES: usize = FIXED_BYTES + 3 * (1 + 2 + 1);
pub const MAX_CANDIDATE_SUBMISSION_BYTES: usize =
    FIXED_BYTES + 3 * (1 + MAX_SUBMISSION_CERTIFICATES * 2 + MAX_SUBMISSION_CHAIN_BYTES);
pub const PLAINTEXT_LENGTH_PREFIX_BYTES: usize = 4;

/// Public candidate fields supplied before TLS. They do not prove provenance,
/// possession, attestation validity or permission to enroll.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateSubmissionFields {
    pub ceremony_nonce: PairingNonce,
    pub attestation_challenge: PairingChallenge,
    pub pc: PcIdentity,
    pub recipient_device: DeviceId,
    pub invitation_context: InvitationContextDigest,
    pub approval_key: TlsPublicKey,
    pub denial_key: TlsPublicKey,
    pub transport_key: TlsPublicKey,
}

impl fmt::Debug for CandidateSubmissionFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateSubmissionFields([redacted], shape_only)")
    }
}

/// Canonically validated phase-one submission. Explicit wire access is required;
/// no Display or serde conversion is supplied.
/// ```compile_fail
/// fn implicit_display(value: service_protocol::CandidateSubmission) {
///     let _text = format!("{value}");
/// }
/// ```
pub struct CandidateSubmission {
    fields: CandidateSubmissionFields,
    approval_chain: Vec<Vec<u8>>,
    denial_chain: Vec<Vec<u8>>,
    transport_chain: Vec<Vec<u8>>,
    phone_keys: PhoneKeyDigest,
}

impl CandidateSubmission {
    pub fn new(
        fields: CandidateSubmissionFields,
        approval_chain: Vec<Vec<u8>>,
        denial_chain: Vec<Vec<u8>>,
        transport_chain: Vec<Vec<u8>>,
    ) -> Result<Self, PairingError> {
        validate_chain(&approval_chain)?;
        validate_chain(&denial_chain)?;
        validate_chain(&transport_chain)?;
        let phone_keys = PhoneKeyDigest::from_keys(
            &fields.approval_key,
            &fields.denial_key,
            &fields.transport_key,
        )?;
        Ok(Self {
            fields,
            approval_chain,
            denial_chain,
            transport_chain,
            phone_keys,
        })
    }

    pub const fn fields(&self) -> &CandidateSubmissionFields {
        &self.fields
    }

    pub fn approval_chain(&self) -> &[Vec<u8>] {
        &self.approval_chain
    }

    pub fn denial_chain(&self) -> &[Vec<u8>] {
        &self.denial_chain
    }

    pub fn transport_chain(&self) -> &[Vec<u8>] {
        &self.transport_chain
    }

    /// Construction has already validated that the three role keys are distinct.
    pub fn phone_keys(&self) -> PhoneKeyDigest {
        self.phone_keys
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(encoded_length(self));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[KIND, 0]);
        bytes.extend_from_slice(self.fields.ceremony_nonce.as_bytes());
        bytes.extend_from_slice(self.fields.attestation_challenge.as_bytes());
        bytes.extend_from_slice(self.fields.pc.as_bytes());
        bytes.extend_from_slice(self.fields.recipient_device.as_bytes());
        bytes.extend_from_slice(self.fields.invitation_context.as_bytes());
        bytes.extend_from_slice(self.fields.approval_key.as_spki_der());
        bytes.extend_from_slice(self.fields.denial_key.as_spki_der());
        bytes.extend_from_slice(self.fields.transport_key.as_spki_der());
        encode_chain(&mut bytes, &self.approval_chain);
        encode_chain(&mut bytes, &self.denial_chain);
        encode_chain(&mut bytes, &self.transport_chain);
        bytes
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, PairingError> {
        if !(MIN_CANDIDATE_SUBMISSION_BYTES..=MAX_CANDIDATE_SUBMISSION_BYTES).contains(&bytes.len())
        {
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
        let attestation_challenge = PairingChallenge::from_bytes(super::array(&mut reader)?)?;
        let pc = PcIdentity::from_bytes(super::array(&mut reader)?)
            .map_err(|_| PairingError::InvalidFields)?;
        let recipient_device = DeviceId::from_bytes(super::array(&mut reader)?)
            .map_err(|_| PairingError::InvalidFields)?;
        let invitation_context = InvitationContextDigest::from_bytes(super::array(&mut reader)?);

        // The full body bound was checked before canonical key decoding.
        let approval_key = super::key(&mut reader)?;
        let denial_key = super::key(&mut reader)?;
        let transport_key = super::key(&mut reader)?;
        let approval_chain = decode_chain(&mut reader)?;
        let denial_chain = decode_chain(&mut reader)?;
        let transport_chain = decode_chain(&mut reader)?;
        reader.finish().map_err(|_| PairingError::InvalidLength)?;

        Self::new(
            CandidateSubmissionFields {
                ceremony_nonce,
                attestation_challenge,
                pc,
                recipient_device,
                invitation_context,
                approval_key,
                denial_key,
                transport_key,
            },
            approval_chain,
            denial_chain,
            transport_chain,
        )
    }

    /// Hashes the exact canonical wire under the candidate-submission v1 domain.
    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update([0]);
        digest.update(self.to_wire());
        digest.finalize().into()
    }
}

impl fmt::Debug for CandidateSubmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateSubmission(redacted)")
    }
}

/// Big-endian u32 body length prefix followed by the canonical body.
pub fn frame_plaintext_submission(submission: &CandidateSubmission) -> Vec<u8> {
    let body = submission.to_wire();
    let mut frame = Vec::with_capacity(PLAINTEXT_LENGTH_PREFIX_BYTES + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Parses a body length and rejects values outside the exact submission bounds.
pub fn plaintext_submission_length(prefix: [u8; 4]) -> Result<usize, PairingError> {
    let length = u32::from_be_bytes(prefix) as usize;
    if !(MIN_CANDIDATE_SUBMISSION_BYTES..=MAX_CANDIDATE_SUBMISSION_BYTES).contains(&length) {
        return Err(PairingError::InvalidLength);
    }
    Ok(length)
}

fn encoded_length(submission: &CandidateSubmission) -> usize {
    FIXED_BYTES
        + encoded_chain_length(&submission.approval_chain)
        + encoded_chain_length(&submission.denial_chain)
        + encoded_chain_length(&submission.transport_chain)
}

fn encoded_chain_length(chain: &[Vec<u8>]) -> usize {
    1 + chain
        .iter()
        .map(|certificate| 2 + certificate.len())
        .sum::<usize>()
}

fn encode_chain(bytes: &mut Vec<u8>, chain: &[Vec<u8>]) {
    bytes.push(chain.len() as u8);
    for certificate in chain {
        bytes.extend_from_slice(&(certificate.len() as u16).to_be_bytes());
        bytes.extend_from_slice(certificate);
    }
}

fn decode_chain(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, PairingError> {
    let count = usize::from(super::array::<1>(reader)?[0]);
    if !(1..=MAX_SUBMISSION_CERTIFICATES).contains(&count) {
        return Err(PairingError::InvalidLength);
    }
    let mut chain = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(super::array(reader)?));
        if !(1..=MAX_SUBMISSION_CERTIFICATE_BYTES).contains(&length) {
            return Err(PairingError::InvalidLength);
        }
        total = total
            .checked_add(length)
            .ok_or(PairingError::InvalidLength)?;
        if total > MAX_SUBMISSION_CHAIN_BYTES {
            return Err(PairingError::InvalidLength);
        }
        let certificate = reader
            .take(length)
            .map_err(|_| PairingError::InvalidLength)?;
        validate_certificate(certificate)?;
        chain.push(certificate.to_vec());
    }
    Ok(chain)
}

fn validate_chain(chain: &[Vec<u8>]) -> Result<(), PairingError> {
    if !(1..=MAX_SUBMISSION_CERTIFICATES).contains(&chain.len()) {
        return Err(PairingError::InvalidLength);
    }
    let mut total = 0usize;
    for certificate in chain {
        if !(1..=MAX_SUBMISSION_CERTIFICATE_BYTES).contains(&certificate.len()) {
            return Err(PairingError::InvalidLength);
        }
        total = total
            .checked_add(certificate.len())
            .ok_or(PairingError::InvalidLength)?;
        if total > MAX_SUBMISSION_CHAIN_BYTES {
            return Err(PairingError::InvalidLength);
        }
        validate_certificate(certificate)?;
    }
    Ok(())
}

fn validate_certificate(certificate: &[u8]) -> Result<(), PairingError> {
    if certificate.first() != Some(&0x30) {
        return Err(PairingError::InvalidEncoding);
    }
    let length_octet = *certificate.get(1).ok_or(PairingError::InvalidEncoding)?;
    let (header_bytes, content_bytes) = match length_octet {
        0x00..=0x7f => (2, usize::from(length_octet)),
        0x81 => {
            let length = usize::from(*certificate.get(2).ok_or(PairingError::InvalidEncoding)?);
            if length < 128 {
                return Err(PairingError::InvalidEncoding);
            }
            (3, length)
        }
        0x82 => {
            let length = usize::from(u16::from_be_bytes([
                *certificate.get(2).ok_or(PairingError::InvalidEncoding)?,
                *certificate.get(3).ok_or(PairingError::InvalidEncoding)?,
            ]));
            if length <= 255 {
                return Err(PairingError::InvalidEncoding);
            }
            (4, length)
        }
        _ => return Err(PairingError::InvalidEncoding),
    };
    if certificate.len().checked_sub(header_bytes) != Some(content_bytes) {
        return Err(PairingError::InvalidEncoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

    use super::*;

    fn public(seed: u8) -> TlsPublicKey {
        let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = p256::PublicKey::from_sec1_bytes(
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
    }

    fn fields() -> CandidateSubmissionFields {
        CandidateSubmissionFields {
            ceremony_nonce: PairingNonce::from_bytes([1; 32]).unwrap(),
            attestation_challenge: PairingChallenge::from_bytes([2; 32]).unwrap(),
            pc: PcIdentity::from_bytes([3; 32]).unwrap(),
            recipient_device: DeviceId::from_bytes([4; 16]).unwrap(),
            invitation_context: InvitationContextDigest::from_bytes([5; 32]),
            approval_key: public(6),
            denial_key: public(7),
            transport_key: public(8),
        }
    }

    fn certificate(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x30);
        match payload.len() {
            0..=127 => bytes.push(payload.len() as u8),
            128..=255 => {
                bytes.push(0x81);
                bytes.push(payload.len() as u8);
            }
            _ => {
                bytes.push(0x82);
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
        }
        bytes.extend_from_slice(payload);
        bytes
    }

    fn chain(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| certificate(&[index as u8]))
            .collect()
    }

    fn submission(count: usize) -> CandidateSubmission {
        CandidateSubmission::new(fields(), chain(count), chain(count), chain(count)).unwrap()
    }

    #[test]
    fn one_and_eight_certificate_chains_roundtrip_with_exact_layout() {
        assert_eq!(MIN_CANDIDATE_SUBMISSION_BYTES, 441);
        assert_eq!(MAX_CANDIDATE_SUBMISSION_BYTES, 98_784);
        for count in [1, 8] {
            let original = submission(count);
            let wire = original.to_wire();
            assert_eq!(&wire[..12], b"WUACSUB\0\x00\x01\x01\x00");
            assert_eq!(&wire[12..44], &[1; 32]);
            assert_eq!(&wire[44..76], &[2; 32]);
            assert_eq!(&wire[76..108], &[3; 32]);
            assert_eq!(&wire[108..124], &[4; 16]);
            assert_eq!(&wire[124..156], &[5; 32]);
            assert_eq!(&wire[156..247], public(6).as_spki_der());
            assert_eq!(&wire[247..338], public(7).as_spki_der());
            assert_eq!(&wire[338..429], public(8).as_spki_der());
            let decoded = CandidateSubmission::from_wire(&wire).unwrap();
            assert_eq!(decoded.fields(), original.fields());
            assert_eq!(decoded.approval_chain(), original.approval_chain());
            assert_eq!(decoded.denial_chain(), original.denial_chain());
            assert_eq!(decoded.transport_chain(), original.transport_chain());
            assert_eq!(decoded.phone_keys(), original.phone_keys());
            assert_eq!(decoded.to_wire(), wire);
        }
    }

    #[test]
    fn digest_uses_independent_domain_separator_and_exact_wire() {
        let submission = submission(1);
        let wire = submission.to_wire();
        let mut oracle = b"Windows-UAC-Remote-Controller/candidate-submission/v1".to_vec();
        oracle.push(0);
        oracle.extend_from_slice(&wire);
        let expected: [u8; 32] = Sha256::digest(&oracle).into();
        assert_eq!(submission.digest(), expected);
        let body_only: [u8; 32] = Sha256::digest(&wire).into();
        assert_ne!(submission.digest(), body_only);
    }

    #[test]
    fn every_truncation_and_trailing_byte_rejects() {
        let wire = submission(1).to_wire();
        for length in 0..wire.len() {
            assert!(
                CandidateSubmission::from_wire(&wire[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = wire;
        trailing.push(0);
        assert_eq!(
            CandidateSubmission::from_wire(&trailing).unwrap_err(),
            PairingError::InvalidLength
        );
    }

    #[test]
    fn chain_counts_and_certificate_lengths_are_bounded() {
        let wire = submission(1).to_wire();
        for count in [0, 9] {
            let mut bad = wire.clone();
            bad[429] = count;
            assert!(CandidateSubmission::from_wire(&bad).is_err());
        }
        let mut zero = wire.clone();
        zero[430..432].fill(0);
        assert!(CandidateSubmission::from_wire(&zero).is_err());
        let mut oversized = wire;
        oversized[430..432].copy_from_slice(&8193u16.to_be_bytes());
        assert!(CandidateSubmission::from_wire(&oversized).is_err());

        assert!(CandidateSubmission::new(fields(), vec![], chain(1), chain(1)).is_err());
        assert!(CandidateSubmission::new(fields(), chain(9), chain(1), chain(1)).is_err());
        assert!(
            CandidateSubmission::new(fields(), vec![vec![0x30; 8193]], chain(1), chain(1)).is_err()
        );
    }

    #[test]
    fn per_role_der_total_cannot_exceed_thirty_two_kibibytes() {
        let payload = vec![0; MAX_SUBMISSION_CERTIFICATE_BYTES - 4];
        let maximum = certificate(&payload);
        assert_eq!(maximum.len(), MAX_SUBMISSION_CERTIFICATE_BYTES);
        let exact = vec![maximum.clone(); 4];
        assert!(CandidateSubmission::new(fields(), exact, chain(1), chain(1)).is_ok());
        let mut too_large = vec![maximum; 4];
        too_large.push(certificate(&[0]));
        assert!(CandidateSubmission::new(fields(), too_large, chain(1), chain(1)).is_err());
    }

    #[test]
    fn certificate_outer_sequence_and_length_must_match_exactly() {
        let mut not_sequence = certificate(&[1]);
        not_sequence[0] = 0x31;
        assert!(
            CandidateSubmission::new(fields(), vec![not_sequence], chain(1), chain(1)).is_err()
        );
        for invalid in [
            vec![0x30],
            vec![0x30, 2, 1],
            vec![0x30, 0x80],
            vec![0x30, 0x81, 1, 0],
            vec![0x30, 0x82, 0, 1, 0],
            vec![0x30, 0x83, 0, 0, 1, 0],
        ] {
            assert!(CandidateSubmission::new(fields(), vec![invalid], chain(1), chain(1)).is_err());
        }
    }

    #[test]
    fn reused_role_keys_reject_on_construction_and_wire_decoding() {
        let mut reused = fields();
        reused.denial_key = reused.approval_key.clone();
        assert!(matches!(
            CandidateSubmission::new(reused, chain(1), chain(1), chain(1)),
            Err(PairingError::KeyReuse)
        ));

        let mut wire = submission(1).to_wire();
        let approval = wire[156..247].to_vec();
        wire[247..338].copy_from_slice(&approval);
        assert!(matches!(
            CandidateSubmission::from_wire(&wire),
            Err(PairingError::KeyReuse)
        ));
    }

    #[test]
    fn malformed_header_and_required_identifiers_reject() {
        let wire = submission(1).to_wire();
        for (offset, value, expected) in [
            (0, b'X', PairingError::InvalidEncoding),
            (9, 2, PairingError::UnsupportedVersion),
            (10, 2, PairingError::UnsupportedKind),
            (11, 1, PairingError::InvalidEncoding),
        ] {
            let mut bad = wire.clone();
            bad[offset] = value;
            assert_eq!(CandidateSubmission::from_wire(&bad).unwrap_err(), expected);
        }
        for range in [12..44, 44..76, 76..108, 108..124] {
            let mut bad = wire.clone();
            bad[range].fill(0);
            assert_eq!(
                CandidateSubmission::from_wire(&bad).unwrap_err(),
                PairingError::InvalidFields
            );
        }
    }

    #[test]
    fn malformed_keys_reject_after_whole_body_length_check() {
        let wire = submission(1).to_wire();
        for offset in [156, 247, 338] {
            let mut bad = wire.clone();
            bad[offset] = 0x31;
            assert_eq!(
                CandidateSubmission::from_wire(&bad).unwrap_err(),
                PairingError::InvalidKey
            );
        }
    }

    #[test]
    fn plaintext_prefix_is_big_endian_and_strictly_bounded() {
        let submission = submission(1);
        let wire = submission.to_wire();
        let frame = frame_plaintext_submission(&submission);
        assert_eq!(frame.len(), PLAINTEXT_LENGTH_PREFIX_BYTES + wire.len());
        assert_eq!(
            &frame[..PLAINTEXT_LENGTH_PREFIX_BYTES],
            &(wire.len() as u32).to_be_bytes()
        );
        assert_eq!(&frame[PLAINTEXT_LENGTH_PREFIX_BYTES..], wire);
        for valid in [
            MIN_CANDIDATE_SUBMISSION_BYTES,
            MAX_CANDIDATE_SUBMISSION_BYTES,
        ] {
            assert_eq!(
                plaintext_submission_length((valid as u32).to_be_bytes()).unwrap(),
                valid
            );
        }
        // u16::MAX (65535) lies inside the legal range and must be accepted.
        assert_eq!(
            plaintext_submission_length(u32::from(u16::MAX).to_be_bytes()).unwrap(),
            usize::from(u16::MAX)
        );
        for invalid in [
            0,
            MIN_CANDIDATE_SUBMISSION_BYTES - 1,
            MAX_CANDIDATE_SUBMISSION_BYTES + 1,
            u32::MAX as usize,
        ] {
            assert_eq!(
                plaintext_submission_length((invalid as u32).to_be_bytes()).unwrap_err(),
                PairingError::InvalidLength
            );
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let submission = submission(1);
        assert_eq!(
            format!("{:?}", submission.fields()),
            "CandidateSubmissionFields([redacted], shape_only)"
        );
        assert_eq!(format!("{submission:?}"), "CandidateSubmission(redacted)");
    }
}
