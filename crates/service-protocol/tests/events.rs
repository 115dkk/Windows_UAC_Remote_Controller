// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic keys and request text. No OS, network, enrollment or credentials.
use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, ExpiryTick, MAX_DETAILS_BYTES, MAX_PATH_BYTES,
    MAX_PROGRAM_NAME_BYTES, OsSession, PcIdentity, RequestBinding, RequestContent, RequestId,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use service_protocol::{
    ClockProbeNonce, MAX_PC_EVENT_BYTES, MAX_REQUEST_LIFETIME_NANOS, PcEvent, PcEventError,
    PcPublicKey, RequestResolution, ServiceTick, UnsignedPcEvent, VerifiedPcEvent,
};
use std::sync::Arc;

fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).unwrap()
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[3; 32]).unwrap()
}
fn public(key: &SigningKey) -> PcPublicKey {
    PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes()).unwrap()
}
fn binding(content: &RequestContent, expiry: u64) -> RequestBinding {
    RequestBinding::new(
        pc(),
        BootEpoch::from_bytes([2; 32]).unwrap(),
        OsSession::new(1, 7),
        RequestId::from_bytes([4; 32]).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry).unwrap(),
    )
}
fn opened() -> PcEvent {
    let content = Arc::new(
        RequestContent::new(
            "예시 앱",
            "C:\\Example\\app.exe",
            "synthetic --example-only",
        )
        .unwrap(),
    );
    PcEvent::Opened {
        binding: binding(&content, 10_000),
        content,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
    }
}
fn signed(event: PcEvent) -> service_protocol::SignedPcEvent {
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key().sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
}
fn resign_body(body: &[u8]) -> Vec<u8> {
    let mut record = b"Windows-UAC-Remote-Controller/pc-event/v1\0".to_vec();
    record.extend_from_slice(body);
    let signature: Signature = key().sign(&record);
    let der = signature.to_der();
    let mut result = b"WUACSRV\0".to_vec();
    result.extend_from_slice(&(body.len() as u32).to_be_bytes());
    result.extend_from_slice(body);
    result.extend_from_slice(&(der.as_bytes().len() as u16).to_be_bytes());
    result.extend_from_slice(der.as_bytes());
    result
}
fn payload(wire: &[u8]) -> &[u8] {
    let len = u32::from_be_bytes(wire[8..12].try_into().unwrap()) as usize;
    &wire[12..12 + len]
}

#[test]
fn exact_request_round_trip_and_owned_verification() {
    let original = opened();
    let signed = signed(original.clone());
    assert_eq!(
        signed.verify(pc(), &public(&key())).unwrap().event(),
        &original
    );
    assert_eq!(
        VerifiedPcEvent::from_wire(&signed.to_wire(), pc(), &public(&key()))
            .unwrap()
            .event(),
        &original
    );
}

#[test]
fn all_actual_outcomes_and_clock_probe_round_trip() {
    let PcEvent::Opened {
        binding, issued_at, ..
    } = opened()
    else {
        unreachable!()
    };
    for outcome in [
        RequestResolution::Approved,
        RequestResolution::Denied,
        RequestResolution::Cancelled,
        RequestResolution::Expired,
        RequestResolution::Failed,
    ] {
        let event = PcEvent::Resolved {
            binding,
            issued_at,
            outcome,
        };
        assert_eq!(
            VerifiedPcEvent::from_wire(&signed(event.clone()).to_wire(), pc(), &public(&key()))
                .unwrap()
                .event(),
            &event
        );
    }
    let event = PcEvent::Clock {
        pc: pc(),
        epoch: binding.epoch(),
        probe: ClockProbeNonce::from_bytes([17; 32]).unwrap(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    };
    assert_eq!(
        VerifiedPcEvent::from_wire(&signed(event.clone()).to_wire(), pc(), &public(&key()))
            .unwrap()
            .event(),
        &event
    );
    assert!(ClockProbeNonce::from_bytes([0; 32]).is_err());
}

#[test]
fn wrong_enrolled_pc_or_key_is_rejected() {
    let wire = signed(opened()).to_wire();
    let other = SigningKey::from_slice(&[7; 32]).unwrap();
    assert_eq!(
        VerifiedPcEvent::from_wire(&wire, pc(), &public(&other)),
        Err(PcEventError::InvalidSignature)
    );
    assert_eq!(
        VerifiedPcEvent::from_wire(
            &wire,
            PcIdentity::from_bytes([8; 32]).unwrap(),
            &public(&key())
        ),
        Err(PcEventError::WrongPc)
    );
}

#[test]
fn maximum_unicode_content_is_not_truncated() {
    let name = "한".repeat(MAX_PROGRAM_NAME_BYTES / 3);
    let path = "길".repeat(MAX_PATH_BYTES / 3);
    let details = "명".repeat(MAX_DETAILS_BYTES / 3);
    let content = Arc::new(RequestContent::new(&name, &path, &details).unwrap());
    let event = PcEvent::Opened {
        binding: binding(&content, MAX_REQUEST_LIFETIME_NANOS),
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content,
    };
    let wire = signed(event.clone()).to_wire();
    assert!(wire.len() <= MAX_PC_EVENT_BYTES);
    assert_eq!(
        VerifiedPcEvent::from_wire(&wire, pc(), &public(&key()))
            .unwrap()
            .event(),
        &event
    );
}

#[test]
fn every_truncation_trailing_data_and_oversized_record_is_rejected() {
    let wire = signed(opened()).to_wire();
    for end in 0..wire.len() {
        assert!(
            VerifiedPcEvent::from_wire(&wire[..end], pc(), &public(&key())).is_err(),
            "truncation {end}"
        );
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(VerifiedPcEvent::from_wire(&extra, pc(), &public(&key())).is_err());
    assert!(
        VerifiedPcEvent::from_wire(&vec![0; MAX_PC_EVENT_BYTES + 1], pc(), &public(&key()))
            .is_err()
    );
    let mut length = wire;
    length[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(VerifiedPcEvent::from_wire(&length, pc(), &public(&key())).is_err());
}

#[test]
fn every_authenticated_body_byte_is_bound_by_the_signature() {
    let wire = signed(opened()).to_wire();
    let length = payload(&wire).len();
    for offset in 12..12 + length {
        let mut modified = wire.clone();
        modified[offset] ^= 1;
        assert_eq!(
            VerifiedPcEvent::from_wire(&modified, pc(), &public(&key())),
            Err(PcEventError::InvalidSignature),
            "offset {offset}"
        );
    }
}

#[test]
fn a_valid_signature_does_not_bypass_strict_schema_or_content_validation() {
    let wire = signed(opened()).to_wire();
    let body = payload(&wire);
    let mut version = body.to_vec();
    version[1] = 2;
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&version), pc(), &public(&key())),
        Err(PcEventError::UnsupportedVersion)
    );
    let mut kind = body.to_vec();
    kind[2] = 255;
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&kind), pc(), &public(&key())),
        Err(PcEventError::UnsupportedKind)
    );
    let mut digest = body.to_vec();
    digest[3 + 32 + 32 + 4 + 8 + 32 + 32] ^= 1;
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&digest), pc(), &public(&key())),
        Err(PcEventError::ContentMismatch)
    );
    let mut text_length = body.to_vec();
    text_length[191..195].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&text_length), pc(), &public(&key())),
        Err(PcEventError::InvalidLength)
    );
    let mut invalid_utf8 = body.to_vec();
    invalid_utf8[195] = 0xff;
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&invalid_utf8), pc(), &public(&key())),
        Err(PcEventError::InvalidText)
    );
    let mut nul = body.to_vec();
    *nul.last_mut().unwrap() = 0;
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&nul), pc(), &public(&key())),
        Err(PcEventError::InvalidFields)
    );
    let mut extra = body.to_vec();
    extra.push(0);
    assert_eq!(
        VerifiedPcEvent::from_wire(&resign_body(&extra), pc(), &public(&key())),
        Err(PcEventError::InvalidLength)
    );
}

#[test]
fn invalid_windows_and_mismatched_capture_fail_before_signing() {
    let PcEvent::Opened {
        binding: original,
        content,
        ..
    } = opened()
    else {
        unreachable!()
    };
    for issue in [10_000, 10_001, u64::MAX] {
        assert_eq!(
            UnsignedPcEvent::new(PcEvent::Opened {
                binding: original,
                issued_at: ServiceTick::from_nanos_since_epoch(issue),
                content: Arc::clone(&content)
            }),
            Err(PcEventError::InvalidLifetime)
        );
    }
    let too_long = binding(&content, MAX_REQUEST_LIFETIME_NANOS + 1);
    assert_eq!(
        UnsignedPcEvent::new(PcEvent::Resolved {
            binding: too_long,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            outcome: RequestResolution::Expired
        }),
        Err(PcEventError::InvalidLifetime)
    );
    let other_digest = RequestBinding::new(
        original.pc(),
        original.epoch(),
        original.session(),
        original.request_id(),
        original.nonce(),
        ContentDigest::from_bytes([0; 32]),
        original.expiry(),
    );
    assert_eq!(
        UnsignedPcEvent::new(PcEvent::Opened {
            binding: other_digest,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            content
        }),
        Err(PcEventError::ContentMismatch)
    );
}

#[test]
fn signed_wire_rejects_equal_reversed_and_overlong_lifetimes() {
    let wire = signed(opened()).to_wire();
    let original = payload(&wire);
    for (issue, expiry) in [
        (10_000_u64, 10_000_u64),
        (10_001, 10_000),
        (0, MAX_REQUEST_LIFETIME_NANOS + 1),
    ] {
        let mut body = original.to_vec();
        body[175..183].copy_from_slice(&expiry.to_be_bytes());
        body[183..191].copy_from_slice(&issue.to_be_bytes());
        assert_eq!(
            VerifiedPcEvent::from_wire(&resign_body(&body), pc(), &public(&key())),
            Err(PcEventError::InvalidLifetime)
        );
    }
}

#[test]
fn expired_resolution_retains_original_request_issuance_not_resolution_time() {
    let PcEvent::Opened {
        binding, issued_at, ..
    } = opened()
    else {
        unreachable!()
    };
    // Actual observation happens later at the native owner. The wire retains
    // only the original signed request window, even after that window expired.
    let resolved = PcEvent::Resolved {
        binding,
        issued_at,
        outcome: RequestResolution::Expired,
    };
    let parsed =
        VerifiedPcEvent::from_wire(&signed(resolved.clone()).to_wire(), pc(), &public(&key()))
            .unwrap();
    assert_eq!(parsed.event(), &resolved);
    assert_eq!(
        UnsignedPcEvent::new(PcEvent::Resolved {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(50_000),
            outcome: RequestResolution::Expired
        }),
        Err(PcEventError::InvalidLifetime)
    );
}

#[test]
fn key_and_signature_formats_are_strict_and_diagnostics_are_redacted() {
    for bytes in [vec![], vec![4; 65], vec![2; 32], vec![0; 91]] {
        assert!(PcPublicKey::from_sec1_bytes(&bytes).is_err());
    }
    for der in [
        vec![],
        vec![0; 8],
        vec![0; 73],
        vec![0x30, 6, 2, 1, 0, 2, 1, 0],
    ] {
        assert!(
            UnsignedPcEvent::new(opened())
                .unwrap()
                .with_der_signature(&der)
                .is_err()
        );
    }
    let signed = signed(opened());
    let verified = signed.verify(pc(), &public(&key())).unwrap();
    for text in [
        format!("{signed:?}"),
        format!("{verified:?}"),
        format!("{:?}", verified.event()),
    ] {
        assert!(!text.contains("synthetic"));
        assert!(!text.contains("app.exe"));
    }
}
