// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic public invitation/software-key codec fixtures only. These tests
//! do not scan/display a QR, prove native provenance/consent, contact a relay,
//! attest hardware, establish freshness or execute a Windows/Android ceremony.

use std::net::SocketAddrV6;

use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};

use super::*;
use crate::{
    EnrollmentAcceptanceFields, FrozenCandidateContext, FrozenCandidateFields, PhoneKeyDigest,
    SignedEnrollmentAcceptance, SignedFrozenCandidate, UnsignedEnrollmentAcceptance,
    UnsignedFrozenCandidate,
};

fn public(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn fields() -> PairingInvitationFields {
    PairingInvitationFields {
        ceremony_nonce: PairingNonce::from_bytes([1; 32]).unwrap(),
        attestation_challenge: PairingChallenge::from_bytes([2; 32]).unwrap(),
        pc: PcIdentity::from_bytes([3; 32]).unwrap(),
        recipient_device: DeviceId::from_bytes([4; 16]).unwrap(),
        pc_signing_key: public(5),
        pc_transport_key: public(6),
        relay_address: SocketAddr::from(([192, 0, 2, 42], 7443)),
        route: [7; 32],
    }
}

fn ipv6_address() -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42)),
        7443,
    )
}

fn fixture_body(fields: &PairingInvitationFields) -> Vec<u8> {
    // Independent layout oracle: literal header and explicit typed fields,
    // without invoking production to_wire or sharing its body builder.
    let mut bytes = b"WUACQRI\0\x00\x01\x01\x00".to_vec();
    bytes.extend_from_slice(fields.ceremony_nonce.as_bytes());
    bytes.extend_from_slice(fields.attestation_challenge.as_bytes());
    bytes.extend_from_slice(fields.pc.as_bytes());
    bytes.extend_from_slice(fields.recipient_device.as_bytes());
    bytes.extend_from_slice(fields.pc_signing_key.as_spki_der());
    bytes.extend_from_slice(fields.pc_transport_key.as_spki_der());
    bytes.push(if fields.relay_address.is_ipv4() { 4 } else { 6 });
    bytes.extend_from_slice(&fields.relay_address.port().to_be_bytes());
    match fields.relay_address.ip() {
        IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => bytes.extend_from_slice(&ip.octets()),
    }
    bytes.extend_from_slice(&fields.route);
    bytes
}

fn reference_base64_url(bytes: &[u8]) -> String {
    // Test-only RFC4648 bit oracle, independent of the production base64 engine.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for group in bytes.chunks(3) {
        let first = group[0];
        let second = group.get(1).copied().unwrap_or(0);
        text.push(char::from(ALPHABET[usize::from(first >> 2)]));
        text.push(char::from(
            ALPHABET[usize::from((first & 3) << 4 | second >> 4)],
        ));
        if group.len() > 1 {
            let third = group.get(2).copied().unwrap_or(0);
            text.push(char::from(
                ALPHABET[usize::from((second & 15) << 2 | third >> 6)],
            ));
            if group.len() > 2 {
                text.push(char::from(ALPHABET[usize::from(third & 63)]));
            }
        }
    }
    text
}

fn fixture_text(bytes: &[u8]) -> String {
    format!("uac-remote:v1:{}", reference_base64_url(bytes))
}

#[test]
fn independent_base64_oracle_matches_known_padding_free_vectors() {
    for (bytes, text) in [
        (b"".as_slice(), ""),
        (b"f".as_slice(), "Zg"),
        (b"fo".as_slice(), "Zm8"),
        (b"foo".as_slice(), "Zm9v"),
        (b"foob".as_slice(), "Zm9vYg"),
        (b"fooba".as_slice(), "Zm9vYmE"),
        (b"foobar".as_slice(), "Zm9vYmFy"),
        (b"\xfb\xff\xff".as_slice(), "-___"),
    ] {
        assert_eq!(reference_base64_url(bytes), text);
    }
}

#[test]
fn ipv4_and_ipv6_roundtrip_exact_binary_and_ascii_layout() {
    assert_eq!(MIN_PAIRING_INVITATION_BYTES, 345);
    assert_eq!(MAX_PAIRING_INVITATION_BYTES, 357);
    assert_eq!(PAIRING_INVITATION_QR_PREFIX, "uac-remote:v1:");
    assert_eq!(MIN_PAIRING_INVITATION_QR_TEXT_BYTES, 474);
    assert_eq!(MAX_PAIRING_INVITATION_QR_TEXT_BYTES, 490);
    for address in [fields().relay_address, ipv6_address()] {
        let mut original = fields();
        original.relay_address = address;
        let invitation = PairingInvitation::new(original.clone()).unwrap();
        let wire = invitation.to_wire();
        assert_eq!(wire, fixture_body(&original));
        assert_eq!(&wire[..12], b"WUACQRI\0\x00\x01\x01\x00");
        assert_eq!(&wire[12..44], &[1; 32]);
        assert_eq!(&wire[44..76], &[2; 32]);
        assert_eq!(&wire[76..108], &[3; 32]);
        assert_eq!(&wire[108..124], &[4; 16]);
        assert_eq!(&wire[124..215], public(5).as_spki_der());
        assert_eq!(&wire[215..306], public(6).as_spki_der());
        if address.is_ipv4() {
            assert_eq!(wire.len(), 345);
            assert_eq!(&wire[306..313], &[4, 0x1d, 0x13, 192, 0, 2, 42]);
            assert_eq!(&wire[313..], &[7; 32]);
        } else {
            assert_eq!(wire.len(), 357);
            assert_eq!(
                &wire[306..325],
                &[
                    6, 0x1d, 0x13, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42
                ]
            );
            assert_eq!(&wire[325..], &[7; 32]);
        }
        let decoded = PairingInvitation::from_wire(&wire).unwrap();
        assert_eq!(decoded.fields(), &original);
        assert_eq!(decoded.to_wire(), wire);
        let text = invitation.to_qr_text();
        assert_eq!(text, fixture_text(&fixture_body(&original)));
        assert!(text.is_ascii());
        assert!(!text.contains('='));
        assert_eq!(text.len(), if address.is_ipv4() { 474 } else { 490 });
        let decoded_text = PairingInvitation::from_qr_text(&text).unwrap();
        assert_eq!(decoded_text.fields(), &original);
        assert_eq!(decoded_text.to_qr_text(), text);
        assert_eq!(decoded_text.context_digest(), decoded.context_digest());
    }
}

#[test]
fn context_digest_uses_independent_domain_and_full_original_body_oracle() {
    for address in [fields().relay_address, ipv6_address()] {
        let mut original = fields();
        original.relay_address = address;
        let body = fixture_body(&original);
        let mut oracle = b"Windows-UAC-Remote-Controller/pairing-invitation/v1\0".to_vec();
        oracle.extend_from_slice(&body);
        let expected: [u8; 32] = Sha256::digest(&oracle).into();
        let invitation = PairingInvitation::new(original).unwrap();
        assert_eq!(invitation.context_digest().as_bytes(), &expected);
        let body_only: [u8; 32] = Sha256::digest(&body).into();
        assert_ne!(expected, body_only);
        let text_hash: [u8; 32] = Sha256::digest(fixture_text(&body).as_bytes()).into();
        assert_ne!(expected, text_hash);
        for other_domain in [
            b"Windows-UAC-Remote-Controller/candidate-frozen/v1\0".as_slice(),
            b"Windows-UAC-Remote-Controller/pairing-sas/v1\0".as_slice(),
            b"Windows-UAC-Remote-Controller/enrollment-acceptance/v1\0".as_slice(),
            b"Windows-UAC-Remote-Controller/pairing-invitation/v1".as_slice(),
        ] {
            let mut wrong = other_domain.to_vec();
            wrong.extend_from_slice(&body);
            let wrong_hash: [u8; 32] = Sha256::digest(&wrong).into();
            assert_ne!(expected, wrong_hash);
        }
        let mut missing_header = b"Windows-UAC-Remote-Controller/pairing-invitation/v1\0".to_vec();
        missing_header.extend_from_slice(&body[12..]);
        let missing_header_hash: [u8; 32] = Sha256::digest(&missing_header).into();
        assert_ne!(expected, missing_header_hash);
    }
}

#[test]
fn every_original_field_and_each_relay_component_changes_the_digest() {
    let original = fields();
    let expected = PairingInvitation::new(original.clone())
        .unwrap()
        .context_digest();
    let mut changed = Vec::new();
    let mut value = original.clone();
    value.ceremony_nonce = PairingNonce::from_bytes([10; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.attestation_challenge = PairingChallenge::from_bytes([11; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.pc = PcIdentity::from_bytes([12; 32]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.recipient_device = DeviceId::from_bytes([13; 16]).unwrap();
    changed.push(value);
    let mut value = original.clone();
    value.pc_signing_key = public(14);
    changed.push(value);
    let mut value = original.clone();
    value.pc_transport_key = public(15);
    changed.push(value);
    let mut value = original.clone();
    std::mem::swap(&mut value.pc_signing_key, &mut value.pc_transport_key);
    changed.push(value);
    let mut value = original.clone();
    value.relay_address.set_port(7444);
    changed.push(value);
    let mut value = original.clone();
    value
        .relay_address
        .set_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43)));
    changed.push(value);
    let mut value = original.clone();
    value.relay_address = ipv6_address();
    changed.push(value);
    let mut value = original;
    value.route[31] ^= 1;
    changed.push(value);
    for value in changed {
        let invitation = PairingInvitation::new(value).unwrap();
        assert_ne!(invitation.context_digest(), expected);
        assert_eq!(
            PairingInvitation::from_qr_text(&invitation.to_qr_text())
                .unwrap()
                .context_digest(),
            invitation.context_digest()
        );
    }
    let mut ipv6 = fields();
    ipv6.relay_address = ipv6_address();
    let original_v6 = PairingInvitation::new(ipv6.clone())
        .unwrap()
        .context_digest();
    ipv6.relay_address.set_ip(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x43,
    )));
    assert_ne!(
        PairingInvitation::new(ipv6).unwrap().context_digest(),
        original_v6
    );
}

#[test]
fn malformed_headers_are_rejected_without_version_or_kind_fallback() {
    let wire = PairingInvitation::new(fields()).unwrap().to_wire();
    for index in 0..8 {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::InvalidEncoding
        );
    }
    for version in [0u16, 2, u16::MAX] {
        let mut bad = wire.clone();
        bad[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::UnsupportedVersion
        );
    }
    for kind in [0, 2, 255] {
        let mut bad = wire.clone();
        bad[10] = kind;
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::UnsupportedKind
        );
    }
    for reserved in [1, 255] {
        let mut bad = wire.clone();
        bad[11] = reserved;
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::InvalidEncoding
        );
    }
}

#[test]
fn zero_identifiers_and_public_route_are_rejected_but_entropy_is_not_invented() {
    let wire = PairingInvitation::new(fields()).unwrap().to_wire();
    for range in [12..44, 44..76, 76..108, 108..124] {
        let mut bad = wire.clone();
        bad[range].fill(0);
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::InvalidFields
        );
    }
    let mut bad_route = wire.clone();
    bad_route[313..345].fill(0);
    assert_eq!(
        PairingInvitation::from_wire(&bad_route).unwrap_err(),
        PairingInvitationError::InvalidRoute
    );
    let mut original = fields();
    original.route = [0; 32];
    assert_eq!(
        PairingInvitation::new(original).unwrap_err(),
        PairingInvitationError::InvalidRoute
    );
    // Minimal nonzero bytes meet SHAPE requirements, not fresh/random entropy.
    let mut minimal = wire;
    for range in [12..44, 44..76, 76..108, 108..124, 313..345] {
        let last = range.end - 1;
        minimal[range].fill(0);
        minimal[last] = 1;
    }
    assert_eq!(
        PairingInvitation::from_wire(&minimal).unwrap().to_wire(),
        minimal
    );
}

#[test]
fn both_pc_keys_require_the_existing_canonical_p256_spki_codec() {
    let wire = PairingInvitation::new(fields()).unwrap().to_wire();
    for start in [124, 215] {
        for mutation in 0..5 {
            let mut bad = wire.clone();
            match mutation {
                0 => bad[start] = 0x31,                   // Not a DER sequence.
                1 => bad[start + 1] = 0x58,               // Wrong sequence length/trailing bytes.
                2 => bad[start + 22] ^= 1,                // Different curve OID.
                3 => bad[start + 26] = 0x02, // Compressed marker in fixed uncompressed SPKI.
                4 => bad[start + 27..start + 91].fill(0), // Invalid curve point.
                _ => unreachable!(),
            }
            assert_eq!(
                PairingInvitation::from_wire(&bad).unwrap_err(),
                PairingInvitationError::InvalidKey
            );
        }
    }
    let mut original = fields();
    original.pc_transport_key = original.pc_signing_key.clone();
    let same_pc_key = PairingInvitation::new(original.clone()).unwrap();
    assert_eq!(
        PairingInvitation::from_wire(&same_pc_key.to_wire())
            .unwrap()
            .fields(),
        &original
    );
    // Reusing the PC's existing domain-separated key for its two PC roles is
    // deliberate; this does not introduce another phone key or attestation.
}

#[test]
fn endpoint_family_port_scope_flow_and_mapped_ipv6_policy_are_explicit() {
    let wire = PairingInvitation::new(fields()).unwrap().to_wire();
    for family in [0, 1, 5, 7, 255] {
        let mut bad = wire.clone();
        bad[306] = family;
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::InvalidEndpoint
        );
    }
    let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
    let mapped = Ipv4Addr::new(192, 0, 2, 42).to_ipv6_mapped();
    for address in [
        SocketAddr::from(([192, 0, 2, 42], 0)),
        SocketAddr::V6(SocketAddrV6::new(ip, 0, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new(ip, 7443, 1, 0)),
        SocketAddr::V6(SocketAddrV6::new(ip, 7443, 0, 1)),
        SocketAddr::V6(SocketAddrV6::new(mapped, 7443, 0, 0)),
    ] {
        let mut original = fields();
        original.relay_address = address;
        assert_eq!(
            PairingInvitation::new(original).unwrap_err(),
            PairingInvitationError::InvalidEndpoint
        );
    }
    for address in [fields().relay_address, ipv6_address()] {
        let mut original = fields();
        original.relay_address = address;
        let mut bad = fixture_body(&original);
        bad[307..309].fill(0);
        assert_eq!(
            PairingInvitation::from_wire(&bad).unwrap_err(),
            PairingInvitationError::InvalidEndpoint
        );
    }
    let mut original = fields();
    original.relay_address = ipv6_address();
    let mut bad_mapped = fixture_body(&original);
    bad_mapped[309..325].copy_from_slice(&mapped.octets());
    assert_eq!(
        PairingInvitation::from_wire(&bad_mapped).unwrap_err(),
        PairingInvitationError::InvalidEndpoint
    );
    // Scope and flow cannot be smuggled as extra bytes: family6 encodes exactly
    // sixteen octets, no variable suffix. Such input is covered by length tests.
}

#[test]
fn equivalent_numeric_ipv6_notation_has_one_body_and_usability_is_not_a_codec_claim() {
    let mut compressed = fields();
    compressed.relay_address = "[2001:db8::42]:7443".parse().unwrap();
    let mut expanded = fields();
    expanded.relay_address = "[2001:0db8:0000:0000:0000:0000:0000:0042]:7443"
        .parse()
        .unwrap();
    let first = PairingInvitation::new(compressed).unwrap();
    let second = PairingInvitation::new(expanded).unwrap();
    assert_eq!(first.to_wire(), second.to_wire());
    assert_eq!(first.to_qr_text(), second.to_qr_text());
    assert_eq!(first.context_digest(), second.context_digest());
    for address in [
        SocketAddr::from(([0, 0, 0, 0], 1)),
        SocketAddr::from(([127, 0, 0, 1], u16::MAX)),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), u16::MAX),
    ] {
        let mut original = fields();
        original.relay_address = address;
        let invitation = PairingInvitation::new(original).unwrap();
        assert_eq!(
            PairingInvitation::from_wire(&invitation.to_wire())
                .unwrap()
                .fields()
                .relay_address,
            address
        );
    }
    // No name resolution or permissive URL parsing is performed by this codec.
    for address_text in [
        "relay.example:7443",
        "https://192.0.2.42:7443",
        "192.0.2.42:7443/path?x=1",
    ] {
        assert!(address_text.parse::<SocketAddr>().is_err());
        assert!(PairingInvitation::from_qr_text(address_text).is_err());
    }
}

#[test]
fn every_truncation_and_trailing_data_including_the_other_permitted_size_is_rejected() {
    for address in [fields().relay_address, ipv6_address()] {
        let mut original = fields();
        original.relay_address = address;
        let invitation = PairingInvitation::new(original).unwrap();
        let wire = invitation.to_wire();
        let mut mismatched_family = wire.clone();
        mismatched_family[306] = if address.is_ipv4() { 6 } else { 4 };
        assert_eq!(
            PairingInvitation::from_wire(&mismatched_family).unwrap_err(),
            PairingInvitationError::InvalidLength
        );
        for length in 0..wire.len() {
            assert!(
                PairingInvitation::from_wire(&wire[..length]).is_err(),
                "length {length}"
            );
        }
        for extra in 1..=16 {
            let mut trailing = wire.clone();
            trailing.extend_from_slice(&vec![0; extra]);
            assert!(
                PairingInvitation::from_wire(&trailing).is_err(),
                "extra {extra}"
            );
            assert!(PairingInvitation::from_qr_text(&fixture_text(&trailing)).is_err());
        }
        let text = invitation.to_qr_text();
        for length in 0..text.len() {
            assert!(PairingInvitation::from_qr_text(&text[..length]).is_err());
        }
    }
    for length in [
        MIN_PAIRING_INVITATION_BYTES - 1,
        MAX_PAIRING_INVITATION_BYTES + 1,
        16 * 1024,
    ] {
        assert_eq!(
            PairingInvitation::from_wire(&vec![0; length]).unwrap_err(),
            PairingInvitationError::InvalidLength
        );
    }
    for length in [
        MIN_PAIRING_INVITATION_QR_TEXT_BYTES - 1,
        MAX_PAIRING_INVITATION_QR_TEXT_BYTES + 1,
        16 * 1024,
    ] {
        assert_eq!(
            PairingInvitation::from_qr_text(&"A".repeat(length)).unwrap_err(),
            PairingInvitationError::InvalidLength
        );
    }
}

#[test]
fn text_requires_exact_ascii_prefix_url_alphabet_no_padding_or_whitespace() {
    let invitation = PairingInvitation::new(fields()).unwrap();
    let text = invitation.to_qr_text();
    for prefix in [
        "UAC-remote:v1:",
        "uac-REMOTE:v1:",
        "uac-remote:V1:",
        "uac-remote:v2:",
        "uac_remote:v1:",
    ] {
        let bad = format!("{prefix}{}", &text[14..]);
        assert!(PairingInvitation::from_qr_text(&bad).is_err());
    }
    for invalid in [
        b' ', b'\t', b'\n', b'\r', b'=', b'+', b'/', b'%', b'?', b'#', 0, 0x7f,
    ] {
        for at in [14, text.len() / 2, text.len() - 1] {
            let mut bad = text.as_bytes().to_vec();
            bad[at] = invalid;
            assert_eq!(
                PairingInvitation::from_qr_text(std::str::from_utf8(&bad).unwrap()).unwrap_err(),
                PairingInvitationError::InvalidQrText
            );
        }
    }
    let mut unicode = text.clone();
    unicode.replace_range(14..16, "é");
    assert_eq!(unicode.len(), text.len());
    assert_eq!(
        PairingInvitation::from_qr_text(&unicode).unwrap_err(),
        PairingInvitationError::InvalidQrText
    );
    for bad in [
        format!(" {text}"),
        format!("{text}\n"),
        format!("{text}="),
        format!("{text}=="),
        format!("{text}AAAA"),
        format!("{text}AAAAAAAAAAAAAAAA"),
        text.replacen(':', "%3A", 1),
    ] {
        assert!(PairingInvitation::from_qr_text(&bad).is_err());
    }
    // Permitted v1 bodies are both divisible by three. Short final groups and
    // their nonzero unused bits cannot be alternate representations of either
    // body; text bounds reject them and the engine also uses strict NO_PAD.
    let wire = invitation.to_wire();
    let mut noncanonical = fixture_text(&wire[..344]);
    let last = noncanonical.len() - 1;
    noncanonical.replace_range(last.., "B");
    assert!(PairingInvitation::from_qr_text(&noncanonical).is_err());
}

#[test]
fn signed_frozen_and_acceptance_wire_cannot_be_reinterpreted_as_an_invitation() {
    let original = fields();
    let invitation = PairingInvitation::new(original.clone()).unwrap();
    let context = FrozenCandidateContext {
        ceremony_nonce: original.ceremony_nonce,
        attestation_challenge: original.attestation_challenge,
        pc: original.pc,
        recipient_device: original.recipient_device,
        phone_keys: PhoneKeyDigest::from_keys(&public(8), &public(9), &public(10)).unwrap(),
        pc_signing_key: original.pc_signing_key,
        pc_transport_key: original.pc_transport_key,
        invitation_context: invitation.context_digest(),
    };
    let frozen = UnsignedFrozenCandidate::new(FrozenCandidateFields {
        context: context.clone(),
        intended_registry_revision: 17,
    })
    .unwrap();
    let signing = SigningKey::from_slice(&[5; 32]).unwrap();
    let frozen_signature: Signature = signing.sign(&frozen.signing_bytes());
    let frozen = frozen
        .with_der_signature(frozen_signature.to_der().as_bytes())
        .unwrap();
    let acceptance = UnsignedEnrollmentAcceptance::new(EnrollmentAcceptanceFields {
        ceremony_nonce: context.ceremony_nonce,
        attestation_challenge: context.attestation_challenge,
        pc: context.pc,
        recipient_device: context.recipient_device,
        registry_revision: 17,
        phone_keys: context.phone_keys,
        pc_signing_key: context.pc_signing_key,
        pc_transport_key: context.pc_transport_key,
    })
    .unwrap();
    let acceptance_signature: Signature = signing.sign(&acceptance.signing_bytes());
    let acceptance = acceptance
        .with_der_signature(acceptance_signature.to_der().as_bytes())
        .unwrap();
    for mut other in [frozen.to_wire(), acceptance.to_wire()] {
        assert!(PairingInvitation::from_wire(&other).is_err());
        assert!(PairingInvitation::from_qr_text(&fixture_text(&other)).is_err());
        other.truncate(MIN_PAIRING_INVITATION_BYTES);
        assert_eq!(
            PairingInvitation::from_wire(&other).unwrap_err(),
            PairingInvitationError::InvalidEncoding
        );
    }
    assert!(SignedFrozenCandidate::from_wire(&invitation.to_wire()).is_err());
    assert!(SignedEnrollmentAcceptance::from_wire(&invitation.to_wire()).is_err());
}

#[test]
fn debug_is_redacted_and_shape_copy_does_not_assert_single_use_or_native_provenance() {
    let original = fields();
    assert_eq!(
        format!("{original:?}"),
        "PairingInvitationFields([redacted], shape_only)"
    );
    let invitation = PairingInvitation::new(original).unwrap();
    assert_eq!(
        format!("{invitation:?}"),
        "PairingInvitation([redacted], shape_only)"
    );
    assert_eq!(
        format!("{:?}", invitation.context_digest()),
        "InvitationContextDigest([redacted], width_only)"
    );
    for error in [
        PairingInvitationError::InvalidLength,
        PairingInvitationError::InvalidEncoding,
        PairingInvitationError::UnsupportedVersion,
        PairingInvitationError::UnsupportedKind,
        PairingInvitationError::InvalidFields,
        PairingInvitationError::InvalidKey,
        PairingInvitationError::InvalidEndpoint,
        PairingInvitationError::InvalidRoute,
        PairingInvitationError::InvalidQrText,
    ] {
        assert_eq!(format!("{error:?}"), "PairingInvitationError([redacted])");
    }
    let copied = invitation.clone();
    assert_eq!(copied.to_wire(), invitation.to_wire());
    assert_eq!(
        PairingInvitation::from_qr_text(&copied.to_qr_text()).unwrap(),
        invitation
    );
    // Repeated decoding is intentionally possible: only the real live native
    // ceremony/handshake/nonce owner can reject replay and grant registration.
}
