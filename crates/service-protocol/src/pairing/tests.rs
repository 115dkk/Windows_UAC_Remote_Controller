// SPDX-License-Identifier: GPL-2.0-or-later
//! Real P-256 signatures with explicitly synthetic software keys only. No QR,
//! attestation, registry write, platform key or native enrollment is exercised.
use super::*;
use crate::{ClockProbeNonce, PcEvent, ServiceTick, UnsignedPcEvent};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DecisionPurpose, ExpiryTick, OsSession, RequestBinding,
    RequestContent, RequestId, UnsignedDecision,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn public(seed: u8) -> TlsPublicKey {
    let key = p256::PublicKey::from_sec1_bytes(
        signer(seed)
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(key.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn fields() -> EnrollmentAcceptanceFields {
    EnrollmentAcceptanceFields {
        ceremony_nonce: PairingNonce::from_bytes([6; 32]).unwrap(),
        attestation_challenge: PairingChallenge::from_bytes([7; 32]).unwrap(),
        pc: PcIdentity::from_bytes([4; 32]).unwrap(),
        recipient_device: DeviceId::from_bytes([5; 16]).unwrap(),
        registry_revision: 17,
        phone_keys: PhoneKeyDigest::from_keys(&public(1), &public(2), &public(3)).unwrap(),
        pc_signing_key: public(10),
        pc_transport_key: public(11),
    }
}
fn signed(value: EnrollmentAcceptanceFields, seed: u8) -> SignedEnrollmentAcceptance {
    let unsigned = UnsignedEnrollmentAcceptance::new(value).unwrap();
    let signature: Signature = signer(seed).sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
}

#[test]
fn canonical_signed_wire_roundtrip_verifies_only_the_independent_pc_pin() {
    let original = fields();
    let statement = signed(original.clone(), 10);
    let wire = statement.to_wire();
    assert_eq!(&wire[..8], b"WUACENR\0");
    assert_eq!(&wire[8..12], &[0, 1, 1, 0]);
    assert_eq!(
        wire.len(),
        BODY_BYTES
            + 2
            + usize::from(u16::from_be_bytes(
                wire[BODY_BYTES..BODY_BYTES + 2].try_into().unwrap()
            ))
    );
    assert!(wire.len() <= MAX_ENROLLMENT_ACCEPTANCE_BYTES);
    let decoded = SignedEnrollmentAcceptance::from_wire(&wire).unwrap();
    assert_eq!(decoded.to_wire(), wire);
    let verified = decoded.verify(&public(10)).unwrap();
    assert_eq!(verified.fields(), &original);
    assert!(matches!(
        decoded.verify(&public(12)),
        Err(PairingError::UntrustedPcKey)
    ));
    let unsigned = UnsignedEnrollmentAcceptance::new(original).unwrap();
    assert_eq!(
        &unsigned.signing_bytes()[DOMAIN.len()..],
        &wire[..BODY_BYTES]
    );
}

#[test]
fn nonce_and_challenge_are_nonzero_but_digest_decoding_is_only_width() {
    assert!(PairingNonce::from_bytes([0; 32]).is_err());
    assert!(PairingChallenge::from_bytes([0; 32]).is_err());
    assert_eq!(
        PairingNonce::from_bytes([1; 32]).unwrap().as_bytes(),
        &[1; 32]
    );
    assert_eq!(
        PairingChallenge::from_bytes([2; 32]).unwrap().as_bytes(),
        &[2; 32]
    );
    assert_eq!(PhoneKeyDigest::from_bytes([0; 32]).as_bytes(), &[0; 32]);
    let mut value = fields();
    value.registry_revision = 0;
    assert!(matches!(
        UnsignedEnrollmentAcceptance::new(value),
        Err(PairingError::InvalidFields)
    ));
}

#[test]
fn phone_digest_binds_canonical_keys_to_fixed_roles_and_rejects_any_reuse() {
    let (approval, denial, transport) = (public(1), public(2), public(3));
    let digest = PhoneKeyDigest::from_keys(&approval, &denial, &transport).unwrap();
    let mut expected = Sha256::new();
    expected.update(b"Windows-UAC-Remote-Controller/pairing-phone-key-digest/v1\0");
    for (role, key) in [(1u8, &approval), (2, &denial), (3, &transport)] {
        assert_eq!(key.as_spki_der().len(), 91);
        expected.update([role]);
        expected.update(key.as_spki_der());
    }
    let expected: [u8; 32] = expected.finalize().into();
    assert_eq!(digest.as_bytes(), &expected);
    assert_ne!(
        digest,
        PhoneKeyDigest::from_keys(&denial, &approval, &transport).unwrap()
    );
    assert_ne!(
        digest,
        PhoneKeyDigest::from_keys(&approval, &transport, &denial).unwrap()
    );
    for keys in [
        (&approval, &approval, &transport),
        (&approval, &denial, &approval),
        (&approval, &denial, &denial),
    ] {
        assert!(matches!(
            PhoneKeyDigest::from_keys(keys.0, keys.1, keys.2),
            Err(PairingError::KeyReuse)
        ));
    }
}

#[test]
fn all_acceptance_fields_are_signed_without_self_authorizing_a_replacement_pin() {
    let original = fields();
    let unsigned = UnsignedEnrollmentAcceptance::new(original.clone()).unwrap();
    let signature: Signature = signer(10).sign(&unsigned.signing_bytes());
    let mut changed = Vec::new();
    let mut value = original.clone();
    value.ceremony_nonce = PairingNonce::from_bytes([8; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.attestation_challenge = PairingChallenge::from_bytes([8; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.pc = PcIdentity::from_bytes([8; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.recipient_device = DeviceId::from_bytes([8; 16]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.registry_revision += 1;
    changed.push(value);
    let mut value = original.clone();
    value.phone_keys = PhoneKeyDigest::from_keys(&public(1), &public(2), &public(4)).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.pc_signing_key = public(12);
    changed.push(value);
    let mut value = original;
    value.pc_transport_key = public(12);
    changed.push(value);
    for value in changed {
        let altered = UnsignedEnrollmentAcceptance::new(value)
            .unwrap()
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap();
        assert!(altered.verify(&public(10)).is_err());
    }
    let mut attacker_fields = fields();
    attacker_fields.pc_signing_key = public(12);
    let attacker = signed(attacker_fields, 12);
    assert!(matches!(
        attacker.verify(&public(10)),
        Err(PairingError::UntrustedPcKey)
    ));
}

#[test]
fn pc_identity_key_can_have_both_pc_roles_without_merging_phone_roles() {
    let mut value = fields();
    value.pc_transport_key = value.pc_signing_key.clone();
    assert!(signed(value, 10).verify(&public(10)).is_ok());
}

#[test]
fn event_and_decision_signatures_cannot_cross_acceptance_domains_even_with_same_fixture_key() {
    let acceptance_fields = fields();
    let acceptance = UnsignedEnrollmentAcceptance::new(acceptance_fields.clone()).unwrap();
    let acceptance_signature: Signature = signer(10).sign(&acceptance.signing_bytes());
    let event = UnsignedPcEvent::new(PcEvent::Clock {
        pc: acceptance_fields.pc,
        epoch: BootEpoch::from_bytes([20; 32]).unwrap(),
        probe: ClockProbeNonce::from_bytes([21; 32]).unwrap(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    })
    .unwrap();
    let event_signature: Signature = signer(10).sign(&event.signing_bytes());
    assert!(matches!(
        acceptance
            .with_der_signature(event_signature.to_der().as_bytes())
            .unwrap()
            .verify(&public(10)),
        Err(PairingError::InvalidSignature)
    ));
    assert!(
        event
            .with_der_signature(acceptance_signature.to_der().as_bytes())
            .unwrap()
            .verify(
                acceptance_fields.pc,
                &PcPublicKey::from_spki_der(public(10).as_spki_der()).unwrap()
            )
            .is_err()
    );
    let content =
        RequestContent::new("Synthetic application", "C:\\synthetic.exe", "fixture only").unwrap();
    let binding = RequestBinding::new(
        acceptance_fields.pc,
        BootEpoch::from_bytes([20; 32]).unwrap(),
        OsSession::new(1, 2),
        RequestId::from_bytes([22; 32]).unwrap(),
        ChallengeNonce::from_bytes([23; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(100).unwrap(),
    );
    for purpose in [DecisionPurpose::Approve, DecisionPurpose::Deny] {
        let decision = UnsignedDecision::new(binding, acceptance_fields.recipient_device, purpose);
        // Intentionally reuse ONLY the synthetic key to isolate domain binding.
        let signature: Signature = signer(10).sign(&decision.signing_bytes());
        let statement = UnsignedEnrollmentAcceptance::new(acceptance_fields.clone())
            .unwrap()
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap();
        assert!(matches!(
            statement.verify(&public(10)),
            Err(PairingError::InvalidSignature)
        ));
    }
}

#[test]
fn unknown_headers_noncanonical_keys_and_zero_required_fields_are_rejected() {
    let wire = signed(fields(), 10).to_wire();
    for (offset, byte) in [(0, b'X'), (9, 2), (10, 2), (11, 1)] {
        let mut changed = wire.clone();
        changed[offset] = byte;
        assert!(SignedEnrollmentAcceptance::from_wire(&changed).is_err());
    }
    for range in [12..44, 44..76, 76..108, 108..124, 124..132] {
        let mut changed = wire.clone();
        changed[range].fill(0);
        assert!(matches!(
            SignedEnrollmentAcceptance::from_wire(&changed),
            Err(PairingError::InvalidFields)
        ));
    }
    for offset in [164, 255] {
        let mut changed = wire.clone();
        changed[offset] = 0x31;
        assert!(matches!(
            SignedEnrollmentAcceptance::from_wire(&changed),
            Err(PairingError::InvalidKey)
        ));
    }
}

#[test]
fn fixed_wire_bounds_truncation_trailing_and_declared_signature_lengths_are_strict() {
    let wire = signed(fields(), 10).to_wire();
    for size in 0..wire.len() {
        assert!(SignedEnrollmentAcceptance::from_wire(&wire[..size]).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(SignedEnrollmentAcceptance::from_wire(&extra).is_err());
    assert!(
        SignedEnrollmentAcceptance::from_wire(&vec![0; MAX_ENROLLMENT_ACCEPTANCE_BYTES + 1])
            .is_err()
    );
    for length in [0u16, 7, 73, u16::MAX] {
        let mut changed = wire.clone();
        changed[BODY_BYTES..BODY_BYTES + 2].copy_from_slice(&length.to_be_bytes());
        assert!(SignedEnrollmentAcceptance::from_wire(&changed).is_err());
    }
    let maximum = Signature::from_scalars([0x80; 32], [0x80; 32])
        .unwrap()
        .to_der();
    assert_eq!(maximum.as_bytes().len(), 72);
    let maximum = UnsignedEnrollmentAcceptance::new(fields())
        .unwrap()
        .with_der_signature(maximum.as_bytes())
        .unwrap()
        .to_wire();
    assert_eq!(MAX_ENROLLMENT_ACCEPTANCE_BYTES, 420);
    assert_eq!(maximum.len(), MAX_ENROLLMENT_ACCEPTANCE_BYTES);
    assert_eq!(
        SignedEnrollmentAcceptance::from_wire(&maximum)
            .unwrap()
            .to_wire(),
        maximum
    );
}

#[test]
fn der_validation_is_not_a_signature_or_a_freshness_replay_commit_check() {
    for invalid in [vec![], vec![0; 72], vec![0; 73], vec![0x30, 0x80, 0, 0]] {
        assert!(matches!(
            UnsignedEnrollmentAcceptance::new(fields())
                .unwrap()
                .with_der_signature(&invalid),
            Err(PairingError::InvalidSignature)
        ));
    }
    let signed = signed(fields(), 10);
    let mut der = signed.der.clone();
    der.push(0);
    assert!(
        UnsignedEnrollmentAcceptance::new(fields())
            .unwrap()
            .with_der_signature(&der)
            .is_err()
    );
    // Verifying the same bytes twice is possible; the native owner must retain
    // and enforce the original live ceremony, exact candidate and commit state.
    assert!(signed.verify(&public(10)).is_ok());
    assert!(signed.verify(&public(10)).is_ok());
}

#[test]
fn ceremony_inner_message_magic_is_classified_without_parsing() {
    assert_eq!(
        ceremony_message_kind(b"WUACFRZ\0trailing bytes need not parse"),
        Some(CeremonyMessageKind::FrozenCandidate)
    );
    assert_eq!(
        ceremony_message_kind(b"WUACCFM\0"),
        Some(CeremonyMessageKind::Confirmation)
    );
    assert_eq!(
        ceremony_message_kind(b"WUACENR\0anything"),
        Some(CeremonyMessageKind::EnrollmentAcceptance)
    );
    assert_eq!(ceremony_message_kind(b"WUACSUB\0"), None);
    assert_eq!(ceremony_message_kind(b"garbage!"), None);
    assert_eq!(ceremony_message_kind(b"short"), None);
}

#[test]
fn diagnostics_do_not_render_nonces_keys_or_statement_bytes() {
    let value = fields();
    assert_eq!(
        format!("{:?}", value.ceremony_nonce),
        "PairingNonce([redacted])"
    );
    assert_eq!(
        format!("{:?}", value.attestation_challenge),
        "PairingChallenge([redacted])"
    );
    assert_eq!(
        format!("{:?}", value.phone_keys),
        "PhoneKeyDigest([redacted])"
    );
    assert_eq!(
        format!("{value:?}"),
        "EnrollmentAcceptanceFields([redacted], shape_only)"
    );
    let signed = signed(value, 10);
    assert_eq!(
        format!("{signed:?}"),
        "SignedEnrollmentAcceptance([redacted])"
    );
    assert_eq!(
        format!("{:?}", signed.verify(&public(10)).unwrap()),
        "VerifiedEnrollmentAcceptance([redacted], signature_only)"
    );
}
