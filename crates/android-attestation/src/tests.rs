// SPDX-License-Identifier: GPL-2.0-or-later
//! Software-signed, process-local composition tests. No Android/UAC/HTTPS proof.
use super::*;
use crate::{description::KeyRole, policy::StatusFetchStarted, test_fixture::SyntheticRkp};

fn status(body: &[u8]) -> TrustedStatusSnapshot {
    TrustedStatusSnapshot::from_authenticated_google_response(
        StatusFetchStarted::capture().unwrap(),
        body,
        Duration::from_secs(600),
    )
    .unwrap()
}

fn fresh_status() -> TrustedStatusSnapshot {
    status(br#"{"entries":{}}"#)
}

fn verify(
    fixture: &SyntheticRkp,
    status: &TrustedStatusSnapshot,
) -> Result<VerifiedKeyBundle, VerificationError> {
    let borrowed = fixture
        .chains
        .each_ref()
        .map(|chain| chain.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let candidate = CandidateEvidence::new(&borrowed[0], &borrowed[1], &borrowed[2]).unwrap();
    verify_key_bundle_with_test_anchors(
        &candidate,
        &fixture.expected,
        &fixture.policy,
        status,
        std::slice::from_ref(&fixture.anchor),
    )
}

fn replace_exact(bytes: &mut [u8], original: &[u8], replacement: &[u8]) {
    assert_eq!(original.len(), replacement.len());
    let positions = bytes
        .windows(original.len())
        .enumerate()
        .filter_map(|(index, window)| (window == original).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(
        positions.len(),
        1,
        "fixture replacement must be unambiguous"
    );
    bytes[positions[0]..positions[0] + original.len()].copy_from_slice(replacement);
}

#[test]
fn genuine_software_signatures_compose_only_under_the_private_test_anchor() {
    let fixture = SyntheticRkp::new();
    let status = fresh_status();
    let proof = verify(&fixture, &status).unwrap();
    assert_eq!(proof.challenge(), fixture.expected.challenge.as_ref());
    assert!(proof.deadline <= status.deadline);
    assert!(proof.deadline <= Instant::now() + Duration::from_secs(30));
    assert!(proof.utc_deadline.is_some());
    assert_eq!(
        proof.into_current_keys(&fixture.policy, &status).unwrap(),
        fixture.expected.keys
    );

    let borrowed = fixture
        .chains
        .each_ref()
        .map(|chain| chain.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let candidate = CandidateEvidence::new(&borrowed[0], &borrowed[1], &borrowed[2]).unwrap();
    assert!(matches!(
        verify_key_bundle(&candidate, &fixture.expected, &fixture.policy, &status),
        Err(VerificationError::UntrustedRoot)
    ));
}

#[test]
fn approval_requires_per_operation_authentication_even_with_valid_signatures() {
    let mut fixture = SyntheticRkp::new();
    fixture.replace_leaf_description(0, &SyntheticRkp::default_description(KeyRole::Denial));
    assert!(matches!(
        verify(&fixture, &fresh_status()),
        Err(VerificationError::KeyPolicy)
    ));
    for index in [1, 2] {
        let mut fixture = SyntheticRkp::new();
        fixture
            .replace_leaf_description(index, &SyntheticRkp::default_description(KeyRole::Approval));
        assert!(matches!(
            verify(&fixture, &fresh_status()),
            Err(VerificationError::KeyPolicy)
        ));
    }
}

#[test]
fn each_role_must_carry_the_exact_live_challenge() {
    for (index, role) in [KeyRole::Approval, KeyRole::Denial, KeyRole::Transport]
        .into_iter()
        .enumerate()
    {
        let mut fixture = SyntheticRkp::new();
        let mut description = SyntheticRkp::default_description(role);
        replace_exact(&mut description, &[7; 32], &[9; 32]);
        fixture.replace_leaf_description(index, &description);
        assert!(matches!(
            verify(&fixture, &fresh_status()),
            Err(VerificationError::ChallengeMismatch)
        ));
    }
}

#[test]
fn resigned_claims_cannot_substitute_the_release_app_or_signing_certificate() {
    for signer in [false, true] {
        let mut fixture = SyntheticRkp::new();
        let mut description = SyntheticRkp::default_description(KeyRole::Approval);
        if signer {
            replace_exact(&mut description, &[8; 32], &[9; 32]);
        } else {
            replace_exact(
                &mut description,
                b"dev.dkk115.uacremote",
                b"dev.dkk115.other_app",
            );
        }
        fixture.replace_leaf_description(0, &description);
        assert!(matches!(
            verify(&fixture, &fresh_status()),
            Err(VerificationError::AppIdentity)
        ));
    }
}

#[test]
fn rkp_attester_level_must_match_both_attested_security_levels() {
    let mut fixture = SyntheticRkp::new();
    let mut description = SyntheticRkp::default_description(KeyRole::Approval);
    // Both version/security-level prefixes occur once as one adjacent block.
    replace_exact(
        &mut description,
        &[2, 2, 1, 0x90, 0x0a, 1, 1, 2, 2, 1, 0x90, 0x0a, 1, 1],
        &[2, 2, 1, 0x90, 0x0a, 1, 2, 2, 2, 1, 0x90, 0x0a, 1, 2],
    );
    fixture.replace_leaf_description(0, &description);
    assert!(matches!(
        verify(&fixture, &fresh_status()),
        Err(VerificationError::PlatformPolicy)
    ));
}

#[test]
fn swapped_or_distinct_unexpected_public_keys_fail_before_trust_output() {
    let mut fixture = SyntheticRkp::new();
    fixture.expected.keys.swap(0, 1);
    assert!(matches!(
        verify(&fixture, &fresh_status()),
        Err(VerificationError::KeyMismatch)
    ));
    let other = SyntheticRkp::new();
    fixture.expected = other.expected;
    assert!(matches!(
        verify(&fixture, &fresh_status()),
        Err(VerificationError::KeyMismatch)
    ));
}

#[test]
fn revoked_and_suspended_serials_at_every_path_position_block_the_bundle() {
    let fixture = SyntheticRkp::new();
    // Shared root/issuers1..4 and three distinct direct leaves5..7.
    for serial in 1..=7 {
        for state in ["REVOKED", "SUSPENDED"] {
            let body = format!(r#"{{"entries":{{"{serial:x}":{{"status":"{state}"}}}}}}"#);
            let current = status(body.as_bytes());
            assert!(
                matches!(verify(&fixture, &current), Err(VerificationError::Revoked)),
                "serial {serial}, {state}"
            );
        }
    }
}

#[test]
fn consumption_rejects_even_equal_content_from_a_replacement_status_snapshot() {
    let fixture = SyntheticRkp::new();
    let original = fresh_status();
    let proof = verify(&fixture, &original).unwrap();
    let replacement = fresh_status();
    assert!(matches!(
        proof.into_current_keys(&fixture.policy, &replacement),
        Err(VerificationError::StaleStatus)
    ));
}

#[test]
fn consumption_rechecks_current_release_policy_instead_of_the_old_configuration() {
    let fixture = SyntheticRkp::new();
    let status = fresh_status();
    let proof = verify(&fixture, &status).unwrap();
    let changed = VerificationPolicy::from_trusted_host(
        vec![[8; 32]],
        3,
        PlatformMinimums {
            os_version: 110000,
            os_patch: 202601,
            vendor_patch: Some(20260101),
            boot_patch: Some(20260101),
        },
    )
    .unwrap();
    assert!(matches!(
        proof.into_current_keys(&changed, &status),
        Err(VerificationError::InvalidPolicy)
    ));
}

#[test]
fn consumption_rechecks_all_independent_expiry_and_clock_conditions_without_sleeping() {
    let fixture = SyntheticRkp::new();
    for condition in 0..5 {
        let mut status = fresh_status();
        let mut proof = verify(&fixture, &status).unwrap();
        match condition {
            0 => proof.deadline = Instant::now(),
            1 => proof.utc_deadline = Some(Duration::ZERO),
            2 => proof.checked_utc = Duration::MAX,
            3 => status.deadline = Instant::now(),
            4 => status.received_clock.utc = Duration::MAX,
            _ => unreachable!(),
        }
        assert!(matches!(
            proof.into_current_keys(&fixture.policy, &status),
            Err(VerificationError::StaleStatus)
        ));
    }
    let mut stale = fresh_status();
    stale.deadline = Instant::now();
    assert!(matches!(
        verify(&fixture, &stale),
        Err(VerificationError::StaleStatus)
    ));
}

#[test]
fn evidence_bounds_and_role_uniqueness_precede_any_certificate_parsing() {
    let one = [1u8];
    let minimum = [&one[..]];
    let empty_cert = [&[][..]];
    let too_big = [0; 8193];
    let large_cert = [&too_big[..]];
    let nine = [&one[..]; 9];
    let quarter = [0; 8192];
    let too_much = [&quarter[..]; 5];
    for bad in [
        &[][..],
        &empty_cert[..],
        &large_cert[..],
        &nine[..],
        &too_much[..],
    ] {
        assert!(matches!(
            CandidateEvidence::new(bad, &minimum, &minimum),
            Err(VerificationError::Bounds)
        ));
    }
    let fixture = SyntheticRkp::new();
    let [a, b, c] = fixture.expected.keys;
    assert!(matches!(
        ExpectedKeyBundle::from_trusted_host([0; 32], a.clone(), b.clone(), c.clone()),
        Err(VerificationError::ChallengeMismatch)
    ));
    for keys in [
        [a.clone(), a.clone(), c.clone()],
        [a.clone(), b.clone(), a.clone()],
        [a, b.clone(), b],
    ] {
        let [a, b, c] = keys;
        assert!(matches!(
            ExpectedKeyBundle::from_trusted_host([7; 32], a, b, c),
            Err(VerificationError::KeyReuse)
        ));
    }
}

#[test]
fn public_evidence_and_proof_debug_never_expose_attestation_data() {
    let fixture = SyntheticRkp::new();
    let status = fresh_status();
    let proof = verify(&fixture, &status).unwrap();
    assert_eq!(
        format!("{:?}", fixture.expected),
        "ExpectedKeyBundle([redacted])"
    );
    assert_eq!(
        format!("{proof:?}"),
        "VerifiedKeyBundle([redacted], not_enrollment_authority)"
    );
    let one = [&[1u8][..]];
    let candidate = CandidateEvidence::new(&one, &one, &one).unwrap();
    assert_eq!(format!("{candidate:?}"), "CandidateEvidence([redacted])");
}
