// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure fixture boundary tests; not native or Android end-to-end evidence.

use approval_protocol::{
    BootEpoch, ChallengeNonce, DecisionPublicKey, DecisionPurpose, DeviceId, ExpiryTick, OsSession,
    PcIdentity, RequestBinding, RequestContent, RequestId,
};

use super::*;

fn parse(bytes: &[u8]) -> Result<Command> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(command(&mut tokio::io::BufReader::new(bytes)))
}

#[test]
fn bounded_control_rejects_approval_unknown_fields_and_truncated_input() {
    assert!(parse(b"{\"command\":\"approve\"}\n").is_err());
    assert!(parse(b"{\"command\":\"prepare\",\"sign\":\"bytes\"}\n").is_err());
    assert!(parse(b"{\"command\":\"prepare\"}").is_err());
    assert!(parse(&vec![b'a'; MAX_COMMAND_BYTES + 1]).is_err());
    let oversized = format!(
        "{{\"command\":\"enroll\",\"qr\":\"{}\"}}\n",
        "a".repeat(MAX_COMMAND_BYTES)
    );
    assert!(matches!(
        parse(oversized.as_bytes()),
        Err("command_too_large")
    ));
    assert!(matches!(
        parse(b"{\"command\":\"prepare\"}\n"),
        Ok(Command::Prepare {
            expected_relay_ip: None
        })
    ));
}

#[test]
fn pixel_input_rejects_non_png_and_non_base64_without_echoing_data() {
    assert!(matches!(
        pixels::decode(Zeroizing::new("not base64".to_owned())),
        Err("invalid_png_base64")
    ));
    assert!(matches!(
        pixels::decode(Zeroizing::new(STANDARD.encode(b"not a PNG"))),
        Err("invalid_png")
    ));
}

#[test]
fn challenge_reissue_preserves_ephemeral_root_and_separate_role_keys() {
    let mut candidate = SyntheticRkp::new();
    let root = candidate.chains[0].last().unwrap().clone();
    let leaf = candidate.chains[0][0].clone();
    let keys = candidate.public_keys();
    assert!(candidate.reissue_for_challenge([0; 32]).is_err());
    candidate.reissue_for_challenge([19; 32]).unwrap();
    assert_eq!(candidate.chains[0].last().unwrap(), &root);
    assert_ne!(candidate.chains[0][0], leaf);
    assert_eq!(candidate.public_keys(), keys);
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[1], keys[2]);
    assert_ne!(keys[0], keys[2]);
}

#[test]
fn fixture_signature_verifies_only_with_enrolled_denial_key() {
    let candidate = SyntheticRkp::new();
    let binding = RequestBinding::new(
        PcIdentity::from_bytes([1; 32]).unwrap(),
        BootEpoch::from_bytes([2; 32]).unwrap(),
        OsSession::new(1, 2),
        RequestId::from_bytes([3; 32]).unwrap(),
        ChallengeNonce::from_bytes([4; 32]).unwrap(),
        RequestContent::new("Synthetic CI test", "C:/ci-fixture.exe", "")
            .unwrap()
            .digest(),
        ExpiryTick::from_nanos_since_epoch(1_000_000).unwrap(),
    );
    let signed = candidate
        .sign_denial(binding, DeviceId::from_bytes([5; 16]).unwrap())
        .unwrap();
    let keys = candidate
        .public_keys()
        .map(|key| DecisionPublicKey::from_sec1_bytes(&key.as_spki_der()[26..]).unwrap());
    assert_eq!(signed.statement().purpose(), DecisionPurpose::Deny);
    signed.verify(&keys[1]).unwrap();
    assert!(signed.verify(&keys[0]).is_err());
    assert!(signed.verify(&keys[2]).is_err());
}

fn binding_for(content: &RequestContent) -> RequestBinding {
    RequestBinding::new(
        PcIdentity::from_bytes([1; 32]).unwrap(),
        BootEpoch::from_bytes([2; 32]).unwrap(),
        OsSession::new(1, 2),
        RequestId::from_bytes([3; 32]).unwrap(),
        ChallengeNonce::from_bytes([4; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(1_000_000).unwrap(),
    )
}

#[test]
fn deny_command_accepts_omitted_optional_details_hash() {
    let command = parse(
        br#"{"command":"deny_next","expected_program_name":"uac-ci-request.exe","expected_path":"C:/ci-fixture.exe"}
"#,
    );
    assert!(matches!(
        command,
        Ok(Command::DenyNext {
            expected_details_sha256: None,
            ..
        })
    ));
}

#[test]
fn ci_marker_requires_exact_visible_path_or_marker_in_collapsed_details() {
    const MARKER: &str = "uac-ci-request.exe";
    const PATH: &str = "C:/ci-fixture.exe";
    for (name, path, details, accepted) in [
        ("권한 요청 uac-ci-request.exe 앱", PATH, "publisher", true),
        ("권한 요청", PATH, "application: uac-ci-request.exe", true),
        ("다른 프로그램", PATH, "publisher", false),
        (MARKER, "C:/wrong.exe", MARKER, false),
        (MARKER, "", "publisher only", false),
        ("권한 요청", "", "application: uac-ci-request.exe", true),
    ] {
        let content = RequestContent::new(name, path, details).unwrap();
        assert_eq!(
            session::match_metadata(&content, binding_for(&content), MARKER, PATH, None).is_ok(),
            accepted
        );
    }
    let content = RequestContent::new(MARKER, PATH, "publisher").unwrap();
    assert!(session::match_metadata(&content, binding_for(&content), "", PATH, None).is_err());
    assert!(session::match_metadata(&content, binding_for(&content), "Other", PATH, None).is_err());
}

#[test]
fn optional_details_hash_never_replaces_full_binding_digest_check() {
    use sha2::{Digest, Sha256};

    const MARKER: &str = "uac-ci-request.exe";
    const PATH: &str = "C:/ci-fixture.exe";
    let original = RequestContent::new(MARKER, PATH, "publisher").unwrap();
    let binding = binding_for(&original);
    let correct_hash = hex(&Sha256::digest(original.details().as_bytes()));
    session::match_metadata(&original, binding, MARKER, PATH, Some(&correct_hash)).unwrap();
    assert!(
        session::match_metadata(&original, binding, MARKER, PATH, Some(&"0".repeat(64))).is_err()
    );
    let tampered = RequestContent::new(MARKER, PATH, "changed details").unwrap();
    assert_eq!(
        session::match_metadata(&tampered, binding, MARKER, PATH, None),
        Err("request_content_digest_mismatch")
    );
}

#[test]
fn pc_wire_rejects_tampered_content_even_with_a_valid_test_pc_signature() {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use service_protocol::{
        PcEvent, PcEventError, PcPublicKey, ServiceTick, UnsignedPcEvent, VerifiedPcEvent,
    };

    // Fresh ephemeral SOFTWARE test key; never a persisted service identity.
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).unwrap();
    let signer = SigningKey::from_bytes((&*secret).into()).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(signer.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let content =
        RequestContent::new("uac-ci-request.exe", "C:/ci-fixture.exe", "publisher").unwrap();
    let binding = binding_for(&content);
    let unsigned = UnsignedPcEvent::new(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content: Arc::new(content),
    })
    .unwrap();
    let mut transcript = unsigned.signing_bytes();
    let signature: Signature = signer.sign(&transcript);
    let mut wire = unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .to_wire();
    VerifiedPcEvent::from_wire(&wire, binding.pc(), &public).unwrap();

    let marker = b"uac-ci-request.exe";
    let wire_index = wire
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    wire[wire_index] = b'X';
    assert!(VerifiedPcEvent::from_wire(&wire, binding.pc(), &public).is_err());

    // Deliberately resign the mutated content with the genuine ephemeral test
    // key while retaining the original binding digest. Signature verification
    // now succeeds; the protocol's recomputed content digest MUST still reject.
    let transcript_index = transcript
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    transcript[transcript_index] = b'X';
    let signature: Signature = signer.sign(&transcript);
    let der = signature.to_der();
    let body_length = u32::from_be_bytes(wire[8..12].try_into().unwrap()) as usize;
    wire.truncate(12 + body_length);
    wire.extend_from_slice(&u16::try_from(der.as_bytes().len()).unwrap().to_be_bytes());
    wire.extend_from_slice(der.as_bytes());
    assert_eq!(
        VerifiedPcEvent::from_wire(&wire, binding.pc(), &public).unwrap_err(),
        PcEventError::ContentMismatch
    );
}
