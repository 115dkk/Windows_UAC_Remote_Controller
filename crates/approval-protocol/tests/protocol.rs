// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic test keys only. These tests are not Android/Windows device evidence.

#![forbid(unsafe_code)]

use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, ContentError, DecisionPublicKey, DecisionPurpose,
    DeviceId, ExpiryTick, MAX_DER_SIGNATURE_BYTES, MAX_DETAILS_BYTES, MAX_PATH_BYTES,
    MAX_PROGRAM_NAME_BYTES, MAX_REQUEST_CONTENT_BYTES, MAX_WINDOWS_TEXT_CODE_UNITS,
    MAX_WIRE_DECISION_BYTES, OsSession, PcIdentity, RequestBinding, RequestContent, RequestId,
    SignatureError, SignedDecision, UnsignedDecision, WireError,
};
use p256::{
    Scalar,
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::PrimeField,
};
use sha2::{Digest, Sha256};

fn fixture_key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("synthetic scalar fixture")
}

fn public_key(key: &SigningKey) -> DecisionPublicKey {
    DecisionPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(true).as_bytes())
        .expect("fixture public key")
}

fn binding() -> RequestBinding {
    RequestBinding::new(
        PcIdentity::from_bytes([1; 32]).unwrap(),
        BootEpoch::from_bytes([2; 32]).unwrap(),
        OsSession::new(3, 4),
        RequestId::from_bytes([5; 32]).unwrap(),
        ChallengeNonce::from_bytes([6; 32]).unwrap(),
        ContentDigest::from_bytes([7; 32]),
        ExpiryTick::from_nanos_since_epoch(8).unwrap(),
    )
}

fn statement(purpose: DecisionPurpose) -> UnsignedDecision {
    UnsignedDecision::new(binding(), DeviceId::from_bytes([9; 16]).unwrap(), purpose)
}

fn sign(statement: UnsignedDecision, key: &SigningKey) -> SignedDecision {
    let signature: Signature = key.sign(&statement.signing_bytes());
    SignedDecision::from_der(statement, signature.to_der().as_bytes()).unwrap()
}

#[test]
fn strict_der_round_trip_verifies_both_purposes_with_the_matching_key() {
    for purpose in [DecisionPurpose::Approve, DecisionPurpose::Deny] {
        let key = fixture_key(1);
        let response = sign(statement(purpose), &key);
        response.verify(&public_key(&key)).unwrap();
        let wire = response.to_wire();
        assert!(wire.len() <= MAX_WIRE_DECISION_BYTES);
        let decoded = SignedDecision::from_wire(&wire).unwrap();
        assert_eq!(decoded.statement(), response.statement());
        assert_eq!(decoded.to_wire(), wire);
        decoded.verify(&public_key(&key)).unwrap();
    }
}

#[test]
fn wrong_curve_key_cannot_verify_a_well_formed_signature() {
    let response = sign(statement(DecisionPurpose::Approve), &fixture_key(1));
    assert_eq!(
        response.verify(&public_key(&fixture_key(2))),
        Err(SignatureError::VerificationFailed)
    );
}

#[test]
fn approval_and_denial_have_explicit_different_domains_and_discriminants() {
    let approve = statement(DecisionPurpose::Approve).signing_bytes();
    let deny = statement(DecisionPurpose::Deny).signing_bytes();
    assert!(approve.starts_with(b"Windows-UAC-Remote-Controller/approve/v1\0"));
    assert!(deny.starts_with(b"Windows-UAC-Remote-Controller/deny/v1\0"));
    assert_ne!(approve, deny);

    let key = fixture_key(1);
    let signature: Signature = key.sign(&approve);
    let substituted = SignedDecision::from_der(
        statement(DecisionPurpose::Deny),
        signature.to_der().as_bytes(),
    )
    .unwrap();
    assert_eq!(
        substituted.verify(&public_key(&key)),
        Err(SignatureError::VerificationFailed)
    );
}

#[test]
fn signing_record_is_a_documented_fixed_width_big_endian_vector() {
    let mut expected = b"Windows-UAC-Remote-Controller/approve/v1\0".to_vec();
    expected.extend_from_slice(&[0, 1]);
    expected.extend_from_slice(&[9; 16]);
    expected.push(1);
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[2; 32]);
    expected.extend_from_slice(&[0, 0, 0, 3]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 4]);
    expected.extend_from_slice(&[5; 32]);
    expected.extend_from_slice(&[6; 32]);
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 8]);
    assert_eq!(
        statement(DecisionPurpose::Approve).signing_bytes(),
        expected
    );
}

#[test]
fn every_identity_binding_and_expiry_field_is_covered_by_the_signature() {
    let key = fixture_key(1);
    let original = sign(statement(DecisionPurpose::Approve), &key).to_wire();
    // Offsets are pinned to the documented wire record, not inferred from parser internals.
    for offset in [25, 58, 90, 94, 102, 134, 166, 198, 206] {
        let mut mutated = original.clone();
        mutated[offset] ^= 1;
        let decoded = SignedDecision::from_wire(&mutated).unwrap();
        assert_eq!(
            decoded.verify(&public_key(&key)),
            Err(SignatureError::VerificationFailed),
            "offset {offset}"
        );
    }
    let mut changed_purpose = original;
    changed_purpose[26] = 2;
    assert_eq!(
        SignedDecision::from_wire(&changed_purpose)
            .unwrap()
            .verify(&public_key(&key)),
        Err(SignatureError::VerificationFailed)
    );
}

#[test]
fn parser_rejects_unknown_version_magic_purpose_zero_ids_and_expiry() {
    let original = sign(statement(DecisionPurpose::Approve), &fixture_key(1)).to_wire();
    let mut changed = original.clone();
    changed[0] ^= 1;
    assert_eq!(
        SignedDecision::from_wire(&changed).unwrap_err(),
        WireError::InvalidMagic
    );
    changed = original.clone();
    changed[9] = 2;
    assert_eq!(
        SignedDecision::from_wire(&changed).unwrap_err(),
        WireError::UnsupportedVersion
    );
    for value in [0, 3, 255] {
        changed = original.clone();
        changed[26] = value;
        assert_eq!(
            SignedDecision::from_wire(&changed).unwrap_err(),
            WireError::InvalidPurpose
        );
    }
    for range in [10..26, 27..59, 59..91, 103..135, 135..167, 199..207] {
        changed = original.clone();
        changed[range].fill(0);
        assert_eq!(
            SignedDecision::from_wire(&changed).unwrap_err(),
            WireError::InvalidField
        );
    }
}

#[test]
fn wire_parser_rejects_every_truncated_prefix_trailing_bytes_and_forged_lengths() {
    let original = sign(statement(DecisionPurpose::Approve), &fixture_key(1)).to_wire();
    for length in 0..original.len() {
        assert!(
            SignedDecision::from_wire(&original[..length]).is_err(),
            "truncation {length}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(SignedDecision::from_wire(&trailing).is_err());
    for declared_length in [0_u16, 7, 73, 255, u16::MAX] {
        let mut changed = original.clone();
        changed[207..209].copy_from_slice(&declared_length.to_be_bytes());
        assert!(SignedDecision::from_wire(&changed).is_err());
    }
    assert!(SignedDecision::from_wire(&[0; MAX_WIRE_DECISION_BYTES + 1]).is_err());
}

#[test]
fn der_parser_rejects_noncanonical_negative_zero_indefinite_and_raw_forms() {
    let bad_der = [
        vec![],
        vec![0; 7],
        vec![0; MAX_DER_SIGNATURE_BYTES + 1],
        vec![0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00],
        vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
        vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
        vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00],
        vec![1; 64],
    ];
    for der in bad_der {
        assert_eq!(
            SignedDecision::from_der(statement(DecisionPurpose::Approve), &der).unwrap_err(),
            SignatureError::MalformedSignature
        );
    }
    let signature: Signature =
        fixture_key(1).sign(&statement(DecisionPurpose::Approve).signing_bytes());
    let mut trailing = signature.to_der().as_bytes().to_vec();
    trailing.push(0);
    assert!(SignedDecision::from_der(statement(DecisionPurpose::Approve), &trailing).is_err());
}

#[test]
fn both_s_representatives_interoperate_without_becoming_replay_identities() {
    let key = fixture_key(1);
    let statement = statement(DecisionPurpose::Approve);
    let signature: Signature = key.sign(&statement.signing_bytes());
    let low = signature.normalize_s().unwrap_or(signature);
    let (r, s) = low.split_bytes();
    let s_scalar = Option::<Scalar>::from(Scalar::from_repr(s)).unwrap();
    let high = Signature::from_scalars(r, (-s_scalar).to_bytes()).unwrap();
    assert_ne!(low.to_der().as_bytes(), high.to_der().as_bytes());
    for variant in [low, high] {
        SignedDecision::from_der(statement, variant.to_der().as_bytes())
            .unwrap()
            .verify(&public_key(&key))
            .unwrap();
    }
}

#[test]
fn sec1_keys_have_one_equality_representation_and_invalid_points_fail() {
    let key = fixture_key(1);
    let compressed =
        DecisionPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(true).as_bytes())
            .unwrap();
    let uncompressed =
        DecisionPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    assert_eq!(compressed, uncompressed);
    for bad in [vec![], vec![0], vec![4; 33], vec![4; 64], vec![0xff; 65]] {
        assert_eq!(
            DecisionPublicKey::from_sec1_bytes(&bad).unwrap_err(),
            SignatureError::MalformedPublicKey
        );
    }
    let mut out_of_field = [0xff; 33];
    out_of_field[0] = 2;
    assert!(DecisionPublicKey::from_sec1_bytes(&out_of_field).is_err());
}

#[test]
fn content_hash_is_length_prefixed_domain_separated_and_field_ordered() {
    let content = RequestContent::new("A", "B", "C").unwrap();
    let canonical = b"Windows-UAC-Remote-Controller/request-content/v1\0\x00\x01\x01\x00\x00\x00\x01A\x02\x00\x00\x00\x01B\x03\x00\x00\x00\x01C";
    let expected: [u8; 32] = Sha256::digest(canonical).into();
    assert_eq!(content.digest().as_bytes(), &expected);
    let a = RequestContent::new("ab", "c", "d").unwrap();
    let b = RequestContent::new("a", "bc", "d").unwrap();
    let swapped = RequestContent::new("c", "ab", "d").unwrap();
    assert_ne!(a.digest(), b.digest());
    assert_ne!(a.digest(), swapped.digest());
    assert_ne!(
        RequestContent::new("App", "file", "").unwrap().digest(),
        RequestContent::new("app", "file", "").unwrap().digest()
    );
    assert_ne!(
        RequestContent::new("é", "file", "").unwrap().digest(),
        RequestContent::new("e\u{301}", "file", "")
            .unwrap()
            .digest()
    );
}

#[test]
fn content_is_bounded_in_utf8_bytes_and_never_debug_printed() {
    let maximum = RequestContent::new(
        &"a".repeat(MAX_PROGRAM_NAME_BYTES),
        &"b".repeat(MAX_PATH_BYTES),
        &"c".repeat(MAX_DETAILS_BYTES),
    )
    .unwrap();
    assert_eq!(maximum.details().len(), MAX_DETAILS_BYTES);
    assert_eq!(
        maximum.program_name().len() + maximum.path().len() + maximum.details().len(),
        MAX_REQUEST_CONTENT_BYTES
    );
    // A consent prompt does not always show a file path: the empty path is legal.
    let no_path = RequestContent::new("name", "", "").unwrap();
    assert_eq!(no_path.path(), "");
    assert_ne!(
        no_path.digest(),
        RequestContent::new("name", "x", "").unwrap().digest()
    );
    for fields in [
        ("".to_owned(), "path".to_owned(), String::new()),
        (
            "a".repeat(MAX_PROGRAM_NAME_BYTES + 1),
            "path".to_owned(),
            String::new(),
        ),
        (
            "name".to_owned(),
            "b".repeat(MAX_PATH_BYTES + 1),
            String::new(),
        ),
        (
            "name".to_owned(),
            "path".to_owned(),
            "c".repeat(MAX_DETAILS_BYTES + 1),
        ),
        (
            "가".repeat(MAX_PROGRAM_NAME_BYTES / 3 + 1),
            "path".to_owned(),
            String::new(),
        ),
    ] {
        assert_eq!(
            RequestContent::new(&fields.0, &fields.1, &fields.2),
            Err(ContentError::InvalidLength)
        );
    }
    for fields in [
        ("n\0ame", "path", ""),
        ("name", "pa\0th", ""),
        ("name", "path", "de\0tails"),
    ] {
        assert_eq!(
            RequestContent::new(fields.0, fields.1, fields.2),
            Err(ContentError::EmbeddedNul)
        );
    }
    let content = RequestContent::new(
        "sensitive fixture name",
        "fixture-only path",
        "fixture-only details",
    )
    .unwrap();
    let debug = format!("{content:?}");
    assert!(!debug.contains(content.program_name()));
    assert!(!debug.contains(content.path()));
    assert!(!debug.contains(content.details()));
    assert!(debug.contains("redacted"));
}

#[test]
fn gui_and_shell_names_have_the_same_generic_exact_content_contract() {
    let application = RequestContent::new(
        "설치 도우미",
        r"C:\fixture\setup.exe",
        "fixture-only GUI details",
    )
    .unwrap();
    let shell = RequestContent::new(
        "Windows PowerShell",
        r"C:\fixture\powershell.exe",
        "fixture-only shell details",
    )
    .unwrap();
    assert_eq!(application.program_name(), "설치 도우미");
    assert_eq!(shell.program_name(), "Windows PowerShell");
    assert_ne!(application.digest(), shell.digest());
}

#[test]
fn full_length_non_ascii_windows_text_is_retained_without_truncation() {
    // Synthetic text only. Three UTF-8 bytes per one UTF-16 code unit is the
    // worst expansion; a supplementary scalar uses four bytes for two units.
    let bmp = "界".repeat(MAX_WINDOWS_TEXT_CODE_UNITS);
    let supplementary = "🦀".repeat(MAX_WINDOWS_TEXT_CODE_UNITS / 2);
    assert_eq!(bmp.encode_utf16().count(), MAX_WINDOWS_TEXT_CODE_UNITS);
    assert_eq!(
        supplementary.encode_utf16().count(),
        MAX_WINDOWS_TEXT_CODE_UNITS
    );
    let content = RequestContent::new("GUI fixture", &bmp, &supplementary).unwrap();
    assert_eq!(content.path(), bmp);
    assert_eq!(content.details(), supplementary);
    assert_eq!(content.path().len(), MAX_PATH_BYTES);
    let with_bmp_details = RequestContent::new("GUI fixture", "fixture path", &bmp).unwrap();
    assert_eq!(with_bmp_details.details().len(), MAX_DETAILS_BYTES);
    assert_ne!(content.digest(), with_bmp_details.digest());
}

#[test]
fn der_rejects_long_form_lengths_and_out_of_range_positive_scalars() {
    let nonminimal_length = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    assert!(
        SignedDecision::from_der(statement(DecisionPurpose::Approve), &nonminimal_length).is_err()
    );
    // Positive 2^256 - 1 is outside the P-256 scalar range. The leading zero
    // encodes the sign correctly so rejection must not rely on negativity.
    let mut out_of_range = vec![0x30, 0x26, 0x02, 0x21, 0x00];
    out_of_range.extend_from_slice(&[0xff; 32]);
    out_of_range.extend_from_slice(&[0x02, 0x01, 0x01]);
    assert_eq!(
        SignedDecision::from_der(statement(DecisionPurpose::Approve), &out_of_range).unwrap_err(),
        SignatureError::MalformedSignature
    );
}

#[test]
fn zero_identifier_constructors_and_zero_expiry_fail() {
    assert!(PcIdentity::from_bytes([0; 32]).is_err());
    assert!(BootEpoch::from_bytes([0; 32]).is_err());
    assert!(RequestId::from_bytes([0; 32]).is_err());
    assert!(ChallengeNonce::from_bytes([0; 32]).is_err());
    assert!(DeviceId::from_bytes([0; 16]).is_err());
    assert!(ExpiryTick::from_nanos_since_epoch(0).is_err());
}
