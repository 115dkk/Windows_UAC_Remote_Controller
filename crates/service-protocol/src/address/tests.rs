// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic codec/signature tests, not native reachability or user approval.
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use super::*;

fn fields() -> AddressAdvertisementFields {
    AddressAdvertisementFields {
        pc: PcIdentity::from_bytes([1; 32]).unwrap(),
        epoch: BootEpoch::from_bytes([2; 32]).unwrap(),
        device: DeviceId::from_bytes([3; 16]).unwrap(),
        route: [4; 32],
        nonce: ClockProbeNonce::from_bytes([5; 32]).unwrap(),
        valid_for_seconds: 300,
        endpoints: vec![
            "192.168.1.50:7443".parse().unwrap(),
            "[2001:db8::50]:7443".parse().unwrap(),
        ],
    }
}

fn key(seed: u8) -> (SigningKey, PcPublicKey) {
    let signer = SigningKey::from_slice(&[seed; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(signer.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    (signer, public)
}

fn sign(fields: AddressAdvertisementFields) -> SignedAddressAdvertisement {
    let unsigned = UnsignedAddressAdvertisement::new(fields).unwrap();
    let signature: Signature = key(7).0.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
}

#[test]
fn query_exact_canonical_layout_and_rejection() {
    let fields = fields();
    let query = AddressQuery::new(fields.pc, fields.device, fields.route, fields.nonce).unwrap();
    let mut expected = b"WUACADR\0\x00\x02\x01\x00".to_vec();
    expected.extend_from_slice(&[1; 32]);
    expected.extend_from_slice(&[3; 16]);
    expected.extend_from_slice(&[4; 32]);
    expected.extend_from_slice(&[5; 32]);
    assert_eq!(query.to_wire(), expected);
    assert_eq!(expected.len(), ADDRESS_QUERY_BYTES);
    assert_eq!(AddressQuery::from_wire(&expected).unwrap(), query);
    assert_eq!(
        address_control_kind(&expected),
        Some(AddressControlKind::Query)
    );
    for length in 0..expected.len() {
        assert!(AddressQuery::from_wire(&expected[..length]).is_err());
    }
    let mut trailing = expected.clone();
    trailing.push(0);
    assert!(AddressQuery::from_wire(&trailing).is_err());
    for (start, end) in [(12, 44), (44, 60), (60, 92), (92, 124)] {
        let mut bad = expected.clone();
        bad[start..end].fill(0);
        assert!(AddressQuery::from_wire(&bad).is_err());
    }
    for index in 0..12 {
        let mut bad = expected.clone();
        bad[index] ^= 1;
        assert!(AddressQuery::from_wire(&bad).is_err());
    }
}

#[test]
fn advertisement_binds_all_context_and_endpoints_with_distinct_domain() {
    let fields = fields();
    let signed = sign(fields.clone());
    let wire = signed.to_wire();
    assert_eq!(
        address_control_kind(&wire),
        Some(AddressControlKind::Advertisement)
    );
    let parsed = SignedAddressAdvertisement::from_wire(&wire).unwrap();
    assert_eq!(parsed.verify(&key(7).1).unwrap().fields(), &fields);
    assert!(parsed.verify(&key(8).1).is_err());
    // Context substitutions remain structurally valid, but the original
    // signature must fail for each PC/device/route/nonce/epoch/TTL/address byte.
    for index in [12, 44, 60, 92, 124, 159, 166, 182] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        let changed = SignedAddressAdvertisement::from_wire(&changed).unwrap();
        assert!(changed.verify(&key(7).1).is_err(), "mutated index {index}");
    }
    // Same signature still verifies when replayed: verification is explicitly
    // signature-only, so receivers must consume the pending nonce themselves.
    assert_eq!(
        parsed.verify(&key(7).1).unwrap().fields().nonce,
        fields.nonce
    );
    let fresh = ClockProbeNonce::from_bytes([9; 32]).unwrap();
    assert_ne!(parsed.verify(&key(7).1).unwrap().fields().nonce, fresh);
    let unsigned = UnsignedAddressAdvertisement::new(fields).unwrap();
    let bad_signature: Signature = key(7).0.sign(&body(&unsigned.fields));
    assert!(
        unsigned
            .with_der_signature(bad_signature.to_der().as_bytes())
            .unwrap()
            .verify(&key(7).1)
            .is_err()
    );
}

#[test]
fn advertisement_rejects_truncation_trailing_noncanonical_and_oversized_data() {
    let wire = sign(fields()).to_wire();
    for length in 0..wire.len() {
        assert!(SignedAddressAdvertisement::from_wire(&wire[..length]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(SignedAddressAdvertisement::from_wire(&trailing).is_err());
    for index in 0..12 {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        assert!(SignedAddressAdvertisement::from_wire(&bad).is_err());
    }
    let mut too_many = wire.clone();
    too_many[160] = 5;
    assert!(SignedAddressAdvertisement::from_wire(&too_many).is_err());
    let mut zero_epoch = wire;
    zero_epoch[124..156].fill(0);
    assert!(SignedAddressAdvertisement::from_wire(&zero_epoch).is_err());
    assert!(
        SignedAddressAdvertisement::from_wire(&vec![0; MAX_ADDRESS_ADVERTISEMENT_BYTES + 1])
            .is_err()
    );
}

#[test]
fn canonical_ttl_withdrawal_and_endpoint_bounds() {
    let mut fields = fields();
    fields.valid_for_seconds = 3600;
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_ok());
    fields.valid_for_seconds = 3601;
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_err());
    fields.valid_for_seconds = 0;
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_err());
    fields.endpoints.clear();
    let wire = sign(fields.clone()).to_wire();
    let verified = SignedAddressAdvertisement::from_wire(&wire)
        .unwrap()
        .verify(&key(7).1)
        .unwrap();
    assert!(verified.fields().endpoints.is_empty());
    assert_eq!(verified.fields().valid_for_seconds, 0);
    fields.valid_for_seconds = 1;
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_err());
    fields.endpoints = vec!["10.0.0.1:7443".parse().unwrap(); 2];
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_err());
    fields.endpoints = (1..=4)
        .map(|last| SocketAddr::from(([10, 0, 0, last], 7443)))
        .collect();
    assert!(UnsignedAddressAdvertisement::new(fields.clone()).is_ok());
    fields.endpoints.push("10.0.0.5:7443".parse().unwrap());
    assert!(UnsignedAddressAdvertisement::new(fields).is_err());
}

#[test]
fn prohibited_endpoints_and_scope_are_rejected_but_private_lan_is_supported() {
    for endpoint in [
        "0.0.0.0:1",
        "0.1.2.3:1",
        "127.0.0.1:1",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "240.0.0.1:1",
        "10.0.0.1:0",
        "[::]:1",
        "[::1]:1",
        "[ff02::1]:1",
        "[::ffff:192.168.0.1]:1",
        "[fe80::1]:1",
    ] {
        assert!(
            validate_endpoint(endpoint.parse().unwrap()).is_err(),
            "{endpoint}"
        );
    }
    for endpoint in [
        "10.0.0.1:7443",
        "172.16.0.1:7443",
        "192.168.0.1:7443",
        "[fd00::1]:7443",
        "[2001:db8::1]:7443",
    ] {
        assert!(validate_endpoint(endpoint.parse().unwrap()).is_ok());
    }
    let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
    for (flow, scope) in [(1, 0), (0, 1)] {
        let endpoint = SocketAddr::V6(std::net::SocketAddrV6::new(ip, 7443, flow, scope));
        assert!(validate_endpoint(endpoint).is_err());
    }
}
