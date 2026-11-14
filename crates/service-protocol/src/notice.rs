// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed PC-origin notices. These report display-only state and carry no request
//! binding, decision, approval, denial, lease, or authorization capability.

use std::fmt;

use approval_protocol::{BootEpoch, MAX_DER_SIGNATURE_BYTES, MIN_DER_SIGNATURE_BYTES, PcIdentity};
use secure_channel::CertificateVerifySignature;
use thiserror::Error;

use crate::{PcPublicKey, codec::Reader};

const MAGIC: &[u8; 8] = b"WUACNTC\0";
const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/pc-notice/v1\0";
const BODY_BYTES: usize = 8 + 4 + 32 + 32 + 8 + 1;
pub const MAX_PARKED_PROMPTS: u8 = 16;
pub const MAX_NOTICE_BYTES: usize = BODY_BYTES + 2 + MAX_DER_SIGNATURE_BYTES;
const _: () = assert!(MAX_NOTICE_BYTES <= crate::MAX_PC_EVENT_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoticeKind {
    ParkedPrompts,
}

/// Classification only, not validation. Once classified as a notice, malformed
/// bytes must fail closed in the notice parser rather than reach another codec.
pub fn notice_kind(bytes: &[u8]) -> Option<NoticeKind> {
    if bytes.get(..8)? != MAGIC {
        return None;
    }
    match bytes.get(10) {
        Some(1) => Some(NoticeKind::ParkedPrompts),
        _ => None,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ParkedPromptsNotice {
    pub pc: PcIdentity,
    pub boot_epoch: BootEpoch,
    pub sequence: u64,
    pub count: u8,
}

impl ParkedPromptsNotice {
    pub fn new(
        pc: PcIdentity,
        boot_epoch: BootEpoch,
        sequence: u64,
        count: u8,
    ) -> Result<Self, NoticeError> {
        let notice = Self {
            pc,
            boot_epoch,
            sequence,
            count,
        };
        notice.validate()?;
        Ok(notice)
    }

    fn validate(self) -> Result<(), NoticeError> {
        if self.sequence == 0 || self.count > MAX_PARKED_PROMPTS {
            return Err(NoticeError::InvalidFields);
        }
        Ok(())
    }
}

pub struct UnsignedParkedPromptsNotice {
    notice: ParkedPromptsNotice,
}

impl UnsignedParkedPromptsNotice {
    pub fn new(notice: ParkedPromptsNotice) -> Result<Self, NoticeError> {
        notice.validate()?;
        Ok(Self { notice })
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        signing_bytes(self.notice)
    }

    pub fn with_der_signature(self, der: &[u8]) -> Result<SignedParkedPromptsNotice, NoticeError> {
        validate_signature(der)?;
        Ok(SignedParkedPromptsNotice {
            notice: self.notice,
            der: der.to_vec(),
        })
    }
}

#[derive(Clone)]
pub struct SignedParkedPromptsNotice {
    notice: ParkedPromptsNotice,
    der: Vec<u8>,
}

impl SignedParkedPromptsNotice {
    pub fn from_wire(bytes: &[u8]) -> Result<Self, NoticeError> {
        if !(BODY_BYTES + 2 + MIN_DER_SIGNATURE_BYTES..=MAX_NOTICE_BYTES).contains(&bytes.len()) {
            return Err(NoticeError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        read_header(&mut reader)?;
        let notice = ParkedPromptsNotice::new(
            PcIdentity::from_bytes(array(&mut reader)?).map_err(|_| NoticeError::InvalidFields)?,
            BootEpoch::from_bytes(array(&mut reader)?).map_err(|_| NoticeError::InvalidFields)?,
            u64::from_be_bytes(array(&mut reader)?),
            array::<1>(&mut reader)?[0],
        )?;
        let length = usize::from(u16::from_be_bytes(array(&mut reader)?));
        let der = reader
            .take(length)
            .map_err(|_| NoticeError::InvalidLength)?;
        reader.finish().map_err(|_| NoticeError::InvalidLength)?;
        validate_signature(der)?;
        Ok(Self {
            notice,
            der: der.to_vec(),
        })
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let mut bytes = body(self.notice);
        bytes.extend_from_slice(&(self.der.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.der);
        bytes
    }

    pub fn verify(
        &self,
        pc: &PcIdentity,
        key: &PcPublicKey,
    ) -> Result<ParkedPromptsNotice, NoticeError> {
        if self.notice.pc != *pc {
            return Err(NoticeError::WrongPc);
        }
        key.verify_transcript(&signing_bytes(self.notice), &self.der)
            .map_err(|_| NoticeError::InvalidSignature)?;
        Ok(self.notice)
    }
}

pub fn verify_parked_prompts_notice(
    bytes: &[u8],
    pc: &PcIdentity,
    key: &PcPublicKey,
) -> Result<ParkedPromptsNotice, NoticeError> {
    SignedParkedPromptsNotice::from_wire(bytes)?.verify(pc, key)
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
    ParkedPromptsNotice,
    UnsignedParkedPromptsNotice,
    SignedParkedPromptsNotice
);

fn header() -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&[0, 1, 1, 0]);
    bytes
}

fn read_header(reader: &mut Reader<'_>) -> Result<(), NoticeError> {
    if array::<8>(reader)? != *MAGIC || array::<4>(reader)? != [0, 1, 1, 0] {
        return Err(NoticeError::InvalidEncoding);
    }
    Ok(())
}

fn body(notice: ParkedPromptsNotice) -> Vec<u8> {
    let mut bytes = header();
    bytes.extend_from_slice(notice.pc.as_bytes());
    bytes.extend_from_slice(notice.boot_epoch.as_bytes());
    bytes.extend_from_slice(&notice.sequence.to_be_bytes());
    bytes.push(notice.count);
    bytes
}

fn signing_bytes(notice: ParkedPromptsNotice) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&body(notice));
    bytes
}

fn array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], NoticeError> {
    reader
        .take(N)
        .map_err(|_| NoticeError::InvalidLength)?
        .try_into()
        .map_err(|_| NoticeError::InvalidLength)
}

fn validate_signature(der: &[u8]) -> Result<(), NoticeError> {
    if !(MIN_DER_SIGNATURE_BYTES..=MAX_DER_SIGNATURE_BYTES).contains(&der.len()) {
        return Err(NoticeError::InvalidSignature);
    }
    CertificateVerifySignature::from_der(der)
        .map(|_| ())
        .map_err(|_| NoticeError::InvalidSignature)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum NoticeError {
    #[error("invalid notice length")]
    InvalidLength,
    #[error("invalid notice encoding")]
    InvalidEncoding,
    #[error("invalid notice fields")]
    InvalidFields,
    #[error("notice belongs to another PC")]
    WrongPc,
    #[error("invalid notice signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    use super::*;
    use crate::{
        AddressQuery, ClockProbeNonce, PcEvent, ServiceTick, SignedPcEvent, UnsignedPcEvent,
        VerifiedPcEvent, address_control_kind,
    };

    fn notice() -> ParkedPromptsNotice {
        ParkedPromptsNotice::new(
            PcIdentity::from_bytes([1; 32]).unwrap(),
            BootEpoch::from_bytes([2; 32]).unwrap(),
            7,
            3,
        )
        .unwrap()
    }

    fn key(seed: u8) -> (SigningKey, PcPublicKey) {
        let signer = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public =
            PcPublicKey::from_sec1_bytes(signer.verifying_key().to_sec1_point(false).as_bytes())
                .unwrap();
        (signer, public)
    }

    fn signed() -> SignedParkedPromptsNotice {
        let unsigned = UnsignedParkedPromptsNotice::new(notice()).unwrap();
        let signature: Signature = key(7).0.sign(&unsigned.signing_bytes());
        unsigned
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap()
    }

    #[test]
    fn parked_notice_round_trips_and_verifies() {
        let wire = signed().to_wire();
        assert_eq!(notice_kind(&wire), Some(NoticeKind::ParkedPrompts));
        assert!(wire.len() <= MAX_NOTICE_BYTES);
        assert_eq!(
            verify_parked_prompts_notice(&wire, &notice().pc, &key(7).1),
            Ok(notice())
        );
    }

    #[test]
    fn parked_notice_rejects_every_required_malformed_form() {
        let wire = signed().to_wire();
        for length in 0..wire.len() {
            assert!(SignedParkedPromptsNotice::from_wire(&wire[..length]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(SignedParkedPromptsNotice::from_wire(&trailing).is_err());
        for index in [0, 8, 9, 10, 11] {
            let mut changed = wire.clone();
            changed[index] ^= 1;
            assert!(SignedParkedPromptsNotice::from_wire(&changed).is_err());
        }
        let mut count = wire.clone();
        count[BODY_BYTES - 1] = MAX_PARKED_PROMPTS + 1;
        assert!(SignedParkedPromptsNotice::from_wire(&count).is_err());
        assert_eq!(
            verify_parked_prompts_notice(
                &wire,
                &PcIdentity::from_bytes([9; 32]).unwrap(),
                &key(7).1,
            ),
            Err(NoticeError::WrongPc)
        );
        assert_eq!(
            verify_parked_prompts_notice(&wire, &notice().pc, &key(8).1),
            Err(NoticeError::InvalidSignature)
        );
        assert!(ParkedPromptsNotice::new(notice().pc, notice().boot_epoch, 0, 1).is_err());
        assert!(
            ParkedPromptsNotice::new(notice().pc, notice().boot_epoch, 1, MAX_PARKED_PROMPTS + 1,)
                .is_err()
        );
    }

    #[test]
    fn notice_pc_event_and_address_codecs_are_disjoint() {
        let notice_wire = signed().to_wire();
        let pc = notice().pc;
        assert!(VerifiedPcEvent::from_wire(&notice_wire, pc, &key(7).1).is_err());
        assert!(AddressQuery::from_wire(&notice_wire).is_err());
        assert!(address_control_kind(&notice_wire).is_none());

        let query = AddressQuery::new(
            pc,
            approval_protocol::DeviceId::from_bytes([3; 16]).unwrap(),
            [4; 32],
            ClockProbeNonce::from_bytes([5; 32]).unwrap(),
        )
        .unwrap()
        .to_wire();
        assert!(notice_kind(&query).is_none());
        assert!(verify_parked_prompts_notice(&query, &pc, &key(7).1).is_err());

        let unsigned = UnsignedPcEvent::new(PcEvent::Clock {
            pc,
            epoch: notice().boot_epoch,
            probe: ClockProbeNonce::from_bytes([6; 32]).unwrap(),
            sampled_at: ServiceTick::from_nanos_since_epoch(1),
        })
        .unwrap();
        let signature: Signature = key(7).0.sign(&unsigned.signing_bytes());
        let event: SignedPcEvent = unsigned
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap();
        let event_wire = event.to_wire();
        assert!(notice_kind(&event_wire).is_none());
        assert!(verify_parked_prompts_notice(&event_wire, &pc, &key(7).1).is_err());
    }
}
