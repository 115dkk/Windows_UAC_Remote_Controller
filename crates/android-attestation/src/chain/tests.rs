// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;
use crate::roots;
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

const FIXTURES: [(&str, &str, ChainProfile); 4] = [
    (
        "sony-sdk33",
        include_str!("../../testdata/sony-sdk33-factory.pem"),
        ChainProfile::Factory4,
    ),
    (
        "caiman-sdk36",
        include_str!("../../testdata/caiman-sdk36-rkp.pem"),
        ChainProfile::Rkp5(HardwareLevel::Tee),
    ),
    (
        "tegu-2026-tee",
        include_str!("../../testdata/tegu-sdk36-tee-2026.pem"),
        ChainProfile::Rkp5(HardwareLevel::Tee),
    ),
    (
        "tegu-2026-strongbox",
        include_str!("../../testdata/tegu-sdk36-strongbox-2026.pem"),
        ChainProfile::Rkp5(HardwareLevel::StrongBox),
    ),
];

fn decode(input: &str) -> Vec<Vec<u8>> {
    input
        .split_inclusive("-----END CERTIFICATE-----")
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let (label, bytes) = der::pem::decode_vec(part.trim().as_bytes()).unwrap();
            assert_eq!(label, "CERTIFICATE");
            bytes
        })
        .collect()
}

fn empty_status() -> RevocationList {
    RevocationList::parse(br#"{"entries":{}}"#).unwrap()
}

// Fixture-selected historical time is TEST INPUT ONLY. Public verify_key_bundle
// always captures the actual PC clock; it has no supplied-time parameter.
fn reference_time(bytes: &[Vec<u8>]) -> (Duration, Duration) {
    let mut before = Duration::ZERO;
    let mut after = Duration::MAX;
    for bytes in &bytes[1..bytes.len() - 1] {
        let cert = Certificate::parse(bytes).unwrap();
        let validity = cert.parsed.tbs_certificate().validity();
        before = before.max(validity.not_before.to_unix_duration());
        after = after.min(validity.not_after.to_unix_duration());
    }
    (before, after)
}

fn expected(bytes: &[u8]) -> TlsPublicKey {
    TlsPublicKey::from_spki_der(Certificate::parse(bytes).unwrap().spki()).unwrap()
}

#[test]
fn public_factory_and_both_google_root_rkp_fixtures_verify_real_signatures() {
    assert_eq!(roots::google().unwrap().len(), 2);
    for (name, pem, profile) in FIXTURES {
        let bytes = decode(pem);
        let (before, after) = reference_time(&bytes);
        let now = before + Duration::from_secs(1);
        assert!(now < after, "fixture has no issuer-valid interval: {name}");
        let borrowed: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let result = verify_with_anchors(
            &borrowed,
            &expected(&bytes[0]),
            now,
            &empty_status(),
            roots::google().unwrap(),
        )
        .unwrap_or_else(|error| panic!("fixture {name}: {error:?}"));
        assert_eq!(result.profile, profile);
        assert!(!result.description.is_empty());
        eprintln!(
            "public chain fixture {name}: {} certificates, issuer interval {}..{}, reference {}",
            bytes.len(),
            before.as_secs(),
            after.as_secs(),
            now.as_secs()
        );
    }
}

#[test]
fn factory_expiry_exception_does_not_cover_rkp_or_not_yet_valid_issuers() {
    for (name, pem, profile) in FIXTURES {
        let bytes = decode(pem);
        let (before, after) = reference_time(&bytes);
        let borrowed: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let key = expected(&bytes[0]);
        assert!(
            verify_with_anchors(
                &borrowed,
                &key,
                before - Duration::from_secs(1),
                &empty_status(),
                roots::google().unwrap()
            )
            .is_err(),
            "{name}"
        );
        let expired = verify_with_anchors(
            &borrowed,
            &key,
            after + Duration::from_secs(1),
            &empty_status(),
            roots::google().unwrap(),
        );
        assert_eq!(expired.is_ok(), profile == ChainProfile::Factory4, "{name}");
    }
}

#[test]
fn public_chain_rejects_changed_signature_wrong_key_and_added_certificate() {
    let original = decode(FIXTURES[1].1);
    let now = reference_time(&original).0 + Duration::from_secs(1);
    let key = expected(&original[0]);
    let mut changed = original.clone();
    let last = changed[0].len() - 1;
    changed[0][last] ^= 1;
    let borrowed: Vec<&[u8]> = changed.iter().map(Vec::as_slice).collect();
    assert!(matches!(
        verify_with_anchors(
            &borrowed,
            &key,
            now,
            &empty_status(),
            roots::google().unwrap()
        ),
        Err(Error::Signature)
    ));
    let wrong = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let point = wrong.verifying_key().to_encoded_point(false);
    let public = p256::PublicKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let wrong =
        TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap();
    let borrowed: Vec<&[u8]> = original.iter().map(Vec::as_slice).collect();
    assert!(matches!(
        verify_with_anchors(
            &borrowed,
            &wrong,
            now,
            &empty_status(),
            roots::google().unwrap()
        ),
        Err(Error::KeyMismatch)
    ));
    let mut appended = borrowed.clone();
    appended.insert(0, borrowed[0]);
    assert!(
        verify_with_anchors(
            &appended,
            &key,
            now,
            &empty_status(),
            roots::google().unwrap()
        )
        .is_err()
    );
}

#[test]
fn every_link_including_root_and_intermediate_is_checked_for_revocation() {
    let bytes = decode(FIXTURES[0].1);
    let now = reference_time(&bytes).0 + Duration::from_secs(1);
    let key = expected(&bytes[0]);
    let borrowed: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    for bytes in &bytes {
        let cert = Certificate::parse(bytes).unwrap();
        let hex = cert
            .serial()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let serial = hex.trim_start_matches('0');
        let json = format!(r#"{{"entries":{{"{serial}":{{"status":"SUSPENDED"}}}}}}"#);
        let status = RevocationList::parse(json.as_bytes()).unwrap();
        assert!(matches!(
            verify_with_anchors(&borrowed, &key, now, &status, roots::google().unwrap()),
            Err(Error::Revoked)
        ));
    }
}
