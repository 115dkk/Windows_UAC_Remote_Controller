// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic software P-256 signatures only. No attestation, proof of phone-key
//! possession, native ceremony, trusted display, UAC or durable commit is tested.

use super::*;
use crate::{EnrollmentAcceptanceFields, SignedEnrollmentAcceptance, UnsignedEnrollmentAcceptance};
use approval_core::{DeviceKeys, EnrollmentError, PrivilegedDeviceRegistry, RegistryCheckpoint};
use approval_protocol::DecisionPublicKey;
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

fn context() -> FrozenCandidateContext {
    FrozenCandidateContext {
        ceremony_nonce: PairingNonce::from_bytes([6; 32]).unwrap(),
        attestation_challenge: PairingChallenge::from_bytes([7; 32]).unwrap(),
        pc: PcIdentity::from_bytes([4; 32]).unwrap(),
        recipient_device: DeviceId::from_bytes([5; 16]).unwrap(),
        phone_keys: PhoneKeyDigest::from_keys(&public(1), &public(2), &public(3)).unwrap(),
        pc_signing_key: public(10),
        pc_transport_key: public(11),
        invitation_context: InvitationContextDigest::from_bytes([9; 32]),
    }
}

fn fields() -> FrozenCandidateFields {
    FrozenCandidateFields {
        context: context(),
        intended_registry_revision: 17,
    }
}

fn signed(fields: FrozenCandidateFields, seed: u8) -> SignedFrozenCandidate {
    let unsigned = UnsignedFrozenCandidate::new(fields).unwrap();
    let signature: Signature = signer(seed).sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
}

fn context_mutations(original: &FrozenCandidateContext) -> Vec<FrozenCandidateContext> {
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
    value.phone_keys = PhoneKeyDigest::from_keys(&public(1), &public(2), &public(4)).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.phone_keys = PhoneKeyDigest::from_keys(&public(2), &public(1), &public(3)).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.pc_signing_key = public(12);
    changed.push(value);
    let mut value = original.clone();
    value.pc_transport_key = public(12);
    changed.push(value);
    let mut value = original.clone();
    value.invitation_context = InvitationContextDigest::from_bytes([8; 32]);
    changed.push(value);
    changed
}

fn fixture_body(value: &FrozenCandidateFields) -> Vec<u8> {
    // Independent fixed-layout oracle, deliberately not the production body().
    let original = &value.context;
    let mut bytes = b"WUACFRZ\0\0\x01\x01\0".to_vec();
    bytes.extend_from_slice(original.ceremony_nonce.as_bytes());
    bytes.extend_from_slice(original.attestation_challenge.as_bytes());
    bytes.extend_from_slice(original.pc.as_bytes());
    bytes.extend_from_slice(original.recipient_device.as_bytes());
    bytes.extend_from_slice(&value.intended_registry_revision.to_be_bytes());
    bytes.extend_from_slice(original.phone_keys.as_bytes());
    bytes.extend_from_slice(original.pc_signing_key.as_spki_der());
    bytes.extend_from_slice(original.pc_transport_key.as_spki_der());
    bytes.extend_from_slice(original.invitation_context.as_bytes());
    bytes
}

#[test]
fn genuine_signature_roundtrip_uses_exact_fixed_body_and_independent_pc_pin() {
    let value = fields();
    let statement = signed(value.clone(), 10);
    let wire = statement.to_wire();
    assert_eq!(BODY_BYTES, 378);
    assert_eq!(MAX_FROZEN_CANDIDATE_BYTES, 452);
    assert_eq!(&wire[..BODY_BYTES], fixture_body(&value));
    assert_eq!(&wire[..12], b"WUACFRZ\0\0\x01\x01\0");
    assert_eq!(
        wire.len(),
        BODY_BYTES
            + 2
            + usize::from(u16::from_be_bytes(
                wire[BODY_BYTES..BODY_BYTES + 2].try_into().unwrap()
            ))
    );
    assert!(wire.len() <= MAX_FROZEN_CANDIDATE_BYTES);
    let decoded = SignedFrozenCandidate::from_wire(&wire).unwrap();
    assert_eq!(decoded.to_wire(), wire);
    let verified = decoded.verify(&public(10)).unwrap();
    assert_eq!(verified.fields(), &value);
    let matched = verified.match_original(&value.context).unwrap();
    assert_eq!(matched.fields(), &value);
    let mut expected_signing = b"Windows-UAC-Remote-Controller/candidate-frozen/v1\0".to_vec();
    expected_signing.extend_from_slice(&fixture_body(&value));
    assert_eq!(
        UnsignedFrozenCandidate::new(value).unwrap().signing_bytes(),
        expected_signing
    );
    assert!(matches!(
        decoded.verify(&public(12)),
        Err(FrozenCandidateError::UntrustedPcKey)
    ));
}

#[test]
fn all_context_fields_and_intended_revision_are_covered_by_the_pc_signature() {
    let original = fields();
    let unsigned = UnsignedFrozenCandidate::new(original.clone()).unwrap();
    let signature: Signature = signer(10).sign(&unsigned.signing_bytes());
    let mut mutations = context_mutations(&original.context)
        .into_iter()
        .map(|context| FrozenCandidateFields {
            context,
            intended_registry_revision: original.intended_registry_revision,
        })
        .collect::<Vec<_>>();
    let mut revision = original.clone();
    revision.intended_registry_revision += 1;
    mutations.push(revision);
    for changed in mutations {
        let altered = UnsignedFrozenCandidate::new(changed)
            .unwrap()
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap();
        assert!(altered.verify(&public(10)).is_err());
    }
    let mut tampered = signed(original, 10).to_wire();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        SignedFrozenCandidate::from_wire(&tampered)
            .unwrap()
            .verify(&public(10))
            .is_err()
    );
}

#[test]
fn every_original_context_field_must_match_even_after_a_genuine_signature_verifies() {
    let original = context();
    for changed in context_mutations(&original) {
        let seed = if changed.pc_signing_key == public(12) {
            12
        } else {
            10
        };
        let statement = signed(
            FrozenCandidateFields {
                context: changed.clone(),
                intended_registry_revision: 17,
            },
            seed,
        );
        let verified = statement.verify(&changed.pc_signing_key).unwrap();
        assert!(matches!(
            verified.match_original(&original),
            Err(FrozenCandidateError::OriginalContextMismatch)
        ));
    }
    let value = fields();
    let statement = signed(value.clone(), 10);
    for wrong_original in context_mutations(&value.context) {
        assert!(matches!(
            statement
                .verify(&public(10))
                .unwrap()
                .match_original(&wrong_original),
            Err(FrozenCandidateError::OriginalContextMismatch)
        ));
    }
}

#[test]
fn attacker_selected_pin_and_wrong_signer_do_not_authorize_a_candidate() {
    let mut attacker = fields();
    attacker.context.pc_signing_key = public(12);
    assert!(matches!(
        signed(attacker, 12).verify(&public(10)),
        Err(FrozenCandidateError::UntrustedPcKey)
    ));
    assert!(matches!(
        signed(fields(), 12).verify(&public(10)),
        Err(FrozenCandidateError::InvalidSignature)
    ));
}

#[test]
fn width_only_invitation_digest_and_pc_role_reuse_do_not_claim_provenance() {
    let mut value = fields();
    value.context.invitation_context = InvitationContextDigest::from_bytes([0; 32]);
    value.context.pc_transport_key = value.context.pc_signing_key.clone();
    assert_eq!(value.context.invitation_context.as_bytes(), &[0; 32]);
    assert!(
        signed(value.clone(), 10)
            .verify(&public(10))
            .unwrap()
            .match_original(&value.context)
            .is_ok()
    );
    assert!(PhoneKeyDigest::from_keys(&public(1), &public(1), &public(3)).is_err());
}

#[test]
fn intended_revision_matches_the_actual_allocator_and_rejects_exhaustion_without_plus_one() {
    let mut registry = PrivilegedDeviceRegistry::initialize_for_privileged_host(2).unwrap();
    let mut value = fields();
    value.intended_registry_revision = registry.checkpoint_for_privileged_host().next_revision();
    assert_eq!(value.intended_registry_revision, 1);
    let keys = DeviceKeys::new(
        DecisionPublicKey::from_sec1_bytes(
            signer(1).verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        DecisionPublicKey::from_sec1_bytes(
            signer(2).verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    let matched = signed(value.clone(), 10)
        .verify(&public(10))
        .unwrap()
        .match_original(&value.context)
        .unwrap();
    registry
        .enroll_from_privileged_host(value.context.recipient_device, keys.clone())
        .unwrap();
    let checkpoint = registry.checkpoint_for_privileged_host();
    assert_eq!(
        checkpoint.entries()[0].revision(),
        matched.fields().intended_registry_revision
    );
    assert_eq!(checkpoint.next_revision(), 2);

    let checkpoint = RegistryCheckpoint::new(2, u64::MAX - 1, []).unwrap();
    let mut registry = PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint).unwrap();
    value.intended_registry_revision = registry.checkpoint_for_privileged_host().next_revision();
    assert!(UnsignedFrozenCandidate::new(value.clone()).is_ok());
    registry
        .enroll_from_privileged_host(value.context.recipient_device, keys.clone())
        .unwrap();
    assert_eq!(
        registry.checkpoint_for_privileged_host().next_revision(),
        u64::MAX
    );
    registry
        .revoke_from_privileged_host(value.context.recipient_device)
        .unwrap();
    assert!(matches!(
        registry.enroll_from_privileged_host(value.context.recipient_device, keys),
        Err(EnrollmentError::RevisionExhausted)
    ));
    for revision in [0, registry.checkpoint_for_privileged_host().next_revision()] {
        value.intended_registry_revision = revision;
        assert!(matches!(
            UnsignedFrozenCandidate::new(value.clone()),
            Err(FrozenCandidateError::InvalidRevision)
        ));
    }
}

#[test]
fn unknown_headers_zero_identifiers_bad_keys_and_exhausted_wire_revision_reject() {
    let wire = signed(fields(), 10).to_wire();
    for (offset, replacement) in [(0, b'X'), (9, 2), (10, 2), (11, 1)] {
        let mut changed = wire.clone();
        changed[offset] = replacement;
        assert!(SignedFrozenCandidate::from_wire(&changed).is_err());
    }
    for range in [12..44, 44..76, 76..108, 108..124] {
        let mut changed = wire.clone();
        changed[range].fill(0);
        assert!(matches!(
            SignedFrozenCandidate::from_wire(&changed),
            Err(FrozenCandidateError::InvalidFields)
        ));
    }
    for revision in [0u64, u64::MAX] {
        let mut changed = wire.clone();
        changed[124..132].copy_from_slice(&revision.to_be_bytes());
        assert!(matches!(
            SignedFrozenCandidate::from_wire(&changed),
            Err(FrozenCandidateError::InvalidRevision)
        ));
    }
    for offset in [164, 255] {
        let mut changed = wire.clone();
        changed[offset] = 0x31;
        assert!(matches!(
            SignedFrozenCandidate::from_wire(&changed),
            Err(FrozenCandidateError::InvalidKey)
        ));
    }
}

#[test]
fn exact_minimum_maximum_lengths_and_every_truncation_or_trailing_byte_are_checked() {
    let wire = signed(fields(), 10).to_wire();
    for length in 0..wire.len() {
        assert!(SignedFrozenCandidate::from_wire(&wire[..length]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(SignedFrozenCandidate::from_wire(&trailing).is_err());
    assert!(SignedFrozenCandidate::from_wire(&vec![0; MAX_FROZEN_CANDIDATE_BYTES + 1]).is_err());
    for length in [0u16, 7, 73, u16::MAX] {
        let mut changed = wire.clone();
        changed[BODY_BYTES..BODY_BYTES + 2].copy_from_slice(&length.to_be_bytes());
        assert!(SignedFrozenCandidate::from_wire(&changed).is_err());
    }
    let mut one = [0u8; 32];
    one[31] = 1;
    for (r, s, expected) in [(one, one, 388), ([0x80; 32], [0x80; 32], 452)] {
        let der = Signature::from_scalars(r, s).unwrap().to_der();
        let structural = UnsignedFrozenCandidate::new(fields())
            .unwrap()
            .with_der_signature(der.as_bytes())
            .unwrap();
        let wire = structural.to_wire();
        assert_eq!(wire.len(), expected);
        assert_eq!(
            SignedFrozenCandidate::from_wire(&wire).unwrap().to_wire(),
            wire
        );
        // Shape-only DER fixtures are not presented as genuine signatures.
        assert!(structural.verify(&public(10)).is_err());
    }
}

#[test]
fn malformed_noncanonical_negative_zero_and_out_of_range_der_are_rejected() {
    let mut overflow = vec![0x30, 0x26, 0x02, 0x21, 0x00];
    overflow.extend_from_slice(&[0xff; 32]);
    overflow.extend_from_slice(&[0x02, 0x01, 0x01]);
    for invalid in [
        vec![],
        vec![0; 72],
        vec![0; 73],
        vec![0x30, 0x80, 0, 0],
        vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
        vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
        vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
        overflow,
    ] {
        assert!(matches!(
            UnsignedFrozenCandidate::new(fields())
                .unwrap()
                .with_der_signature(&invalid),
            Err(FrozenCandidateError::InvalidSignature)
        ));
    }
    let mut appended = signed(fields(), 10).der;
    appended.push(0);
    assert!(
        UnsignedFrozenCandidate::new(fields())
            .unwrap()
            .with_der_signature(&appended)
            .is_err()
    );
}

#[test]
fn acceptance_wire_and_signatures_are_not_frozen_candidates_and_remain_unchanged() {
    let frozen_fields = fields();
    let original = &frozen_fields.context;
    let acceptance_fields = EnrollmentAcceptanceFields {
        ceremony_nonce: original.ceremony_nonce,
        attestation_challenge: original.attestation_challenge,
        pc: original.pc,
        recipient_device: original.recipient_device,
        registry_revision: frozen_fields.intended_registry_revision,
        phone_keys: original.phone_keys,
        pc_signing_key: original.pc_signing_key.clone(),
        pc_transport_key: original.pc_transport_key.clone(),
    };
    let acceptance_unsigned = UnsignedEnrollmentAcceptance::new(acceptance_fields.clone()).unwrap();
    let acceptance_signature: Signature = signer(10).sign(&acceptance_unsigned.signing_bytes());
    let acceptance = acceptance_unsigned
        .with_der_signature(acceptance_signature.to_der().as_bytes())
        .unwrap();
    let frozen = signed(frozen_fields.clone(), 10);
    assert_eq!(crate::MAX_ENROLLMENT_ACCEPTANCE_BYTES, 420);
    assert_eq!(&acceptance.to_wire()[..12], b"WUACENR\0\0\x01\x01\0");
    assert!(acceptance.verify(&public(10)).is_ok());
    assert!(SignedFrozenCandidate::from_wire(&acceptance.to_wire()).is_err());
    assert!(SignedEnrollmentAcceptance::from_wire(&frozen.to_wire()).is_err());
    assert!(matches!(
        UnsignedFrozenCandidate::new(frozen_fields)
            .unwrap()
            .with_der_signature(acceptance_signature.to_der().as_bytes())
            .unwrap()
            .verify(&public(10)),
        Err(FrozenCandidateError::InvalidSignature)
    ));
    assert!(
        UnsignedEnrollmentAcceptance::new(acceptance_fields)
            .unwrap()
            .with_der_signature(&frozen.der)
            .unwrap()
            .verify(&public(10))
            .is_err()
    );
}

#[test]
fn comparison_code_uses_full_sha256_over_sas_domain_and_entire_canonical_body() {
    for value in
        std::iter::once(fields()).chain(context_mutations(&context()).into_iter().map(|context| {
            FrozenCandidateFields {
                context,
                intended_registry_revision: 18,
            }
        }))
    {
        let seed = if value.context.pc_signing_key == public(12) {
            12
        } else {
            10
        };
        let matched = signed(value.clone(), seed)
            .verify(&value.context.pc_signing_key)
            .unwrap()
            .match_original(&value.context)
            .unwrap();
        let code = matched.comparison_code();
        assert_eq!(code.as_str().len(), 6);
        assert!(code.as_str().bytes().all(|byte| byte.is_ascii_digit()));
        let mut oracle = Sha256::new();
        oracle.update(b"Windows-UAC-Remote-Controller/pairing-sas/v1\0");
        oracle.update(fixture_body(&value));
        let hash = oracle.finalize();
        // Independent bit-at-a-time remainder, not production's base-256 loop.
        let mut expected = 0u64;
        for byte in hash {
            for bit in (0..8).rev() {
                expected = (expected * 2 + u64::from((byte >> bit) & 1)) % 1_000_000;
            }
        }
        assert_eq!(code.as_str(), format!("{expected:06}"));
    }
}

#[test]
fn decimal_reduction_keeps_low_bits_and_zero_padding_instead_of_truncating_the_digest() {
    assert_eq!(decimal_code([0; 32]).as_str(), "000000");
    let mut last_byte = [0; 32];
    last_byte[31] = 42;
    assert_eq!(decimal_code(last_byte).as_str(), "000042");
    // (2^256 - 1) mod 1,000,000: all 256 bits participate.
    assert_eq!(decimal_code([0xff; 32]).as_str(), "639935");
}

#[test]
fn signed_revision_is_retained_while_original_context_stays_independent_and_replay_is_external() {
    let original = context();
    for revision in [1, 17, u64::MAX - 1] {
        let statement = signed(
            FrozenCandidateFields {
                context: original.clone(),
                intended_registry_revision: revision,
            },
            10,
        );
        let first = statement
            .verify(&public(10))
            .unwrap()
            .match_original(&original)
            .unwrap();
        let replayed = statement
            .verify(&public(10))
            .unwrap()
            .match_original(&original)
            .unwrap();
        assert_eq!(first.fields().intended_registry_revision, revision);
        assert_eq!(first.comparison_code(), replayed.comparison_code());
    }
}

#[test]
fn every_public_debug_view_is_redacted() {
    let value = fields();
    assert_eq!(
        format!("{:?}", value.context.invitation_context),
        "InvitationContextDigest([redacted], width_only)"
    );
    assert_eq!(
        format!("{:?}", value.context),
        "FrozenCandidateContext([redacted], shape_only)"
    );
    assert_eq!(
        format!("{value:?}"),
        "FrozenCandidateFields([redacted], not_committed)"
    );
    let unsigned = UnsignedFrozenCandidate::new(value.clone()).unwrap();
    assert_eq!(
        format!("{unsigned:?}"),
        "UnsignedFrozenCandidate([redacted])"
    );
    let statement = signed(value.clone(), 10);
    assert_eq!(
        format!("{statement:?}"),
        "SignedFrozenCandidate([redacted])"
    );
    let verified = statement.verify(&public(10)).unwrap();
    assert_eq!(
        format!("{verified:?}"),
        "VerifiedFrozenCandidate([redacted], signature_only)"
    );
    let matched = verified.match_original(&value.context).unwrap();
    assert_eq!(
        format!("{matched:?}"),
        "MatchedFrozenCandidate([redacted], context_match_only)"
    );
    assert_eq!(
        format!("{:?}", matched.comparison_code()),
        "PairingComparisonCode([redacted], public_comparison_only)"
    );
    assert_eq!(
        format!("{:?}", FrozenCandidateError::OriginalContextMismatch),
        "FrozenCandidateError([redacted])"
    );
}
