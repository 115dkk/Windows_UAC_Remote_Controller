// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic association metadata only, not a real enrolled device or PC grant.

use android_controller::{
    LocalAttestationChallenge, LocalKeyHandle, LocalKeyLedger, LocalKeySetDescriptor,
    MAX_PEER_ASSOCIATION_LEDGER_BYTES, MAX_PEER_ASSOCIATIONS, PeerAssociationDescriptor,
    PeerAssociationError, PeerAssociationLedger, PeerAssociationMutation, PeerAssociationRef,
    PeerAssociationRemoval,
};
use approval_protocol::{DeviceId, PcIdentity};
use p256::{PublicKey, ecdsa::SigningKey, pkcs8::EncodePublicKey};
use secure_channel::TlsPublicKey;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const HEADER_BYTES: usize = 24;
const LEGACY_RECORD_BYTES: usize = 278;
const RECORD_BYTES: usize = 330;
const SIGNING_OFFSET: usize = 88;
const TRANSPORT_OFFSET: usize = 179;
const GENERATION_OFFSET: usize = 270;
const RELAY_OFFSET: usize = 278;

fn pc(value: u8) -> PcIdentity {
    PcIdentity::from_bytes([value; 32]).unwrap()
}
fn device(value: u8) -> DeviceId {
    DeviceId::from_bytes([value; 16]).unwrap()
}
fn handle(value: u8) -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([value; 32]).unwrap()
}
fn key(seed: u8) -> TlsPublicKey {
    let synthetic = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point =
        PublicKey::from_sec1_bytes(synthetic.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn local_keys(count: u8) -> LocalKeyLedger {
    let mut ledger = LocalKeyLedger::new();
    for index in 1..=count {
        let challenge = LocalAttestationChallenge::from_bytes([index + 100; 32]).unwrap();
        ledger.begin_creation(handle(index), challenge).unwrap();
        let first = (index - 1) * 3 + 1;
        ledger
            .record_created(
                LocalKeySetDescriptor::new(
                    handle(index),
                    challenge,
                    key(first),
                    key(first + 1),
                    key(first + 2),
                )
                .unwrap(),
            )
            .unwrap();
    }
    ledger
}
fn descriptor(index: u8, revision: u64) -> PeerAssociationDescriptor {
    PeerAssociationDescriptor::new(
        pc(index),
        device(index),
        revision,
        handle(index),
        key(128 + index),
        key(128 + index),
    )
    .unwrap()
}
fn relay_v4(value: u8) -> (SocketAddr, [u8; 32]) {
    (
        SocketAddr::new(
            Ipv4Addr::new(127, 0, 0, value).into(),
            4100 + u16::from(value),
        ),
        [value; 32],
    )
}
fn relay_v6(value: u8) -> (SocketAddr, [u8; 32]) {
    (
        SocketAddr::new(Ipv6Addr::from([value; 16]).into(), 5100 + u16::from(value)),
        [value; 32],
    )
}
fn record(
    ledger: &mut PeerAssociationLedger,
    value: PeerAssociationDescriptor,
    locals: &LocalKeyLedger,
) -> PeerAssociationRef {
    match ledger.record_from_trusted_host(value, locals).unwrap() {
        PeerAssociationMutation::Recorded(reference) => reference,
        PeerAssociationMutation::AlreadyRecorded(_) => panic!("fixture expected new membership"),
    }
}
fn one() -> (LocalKeyLedger, PeerAssociationLedger) {
    let locals = local_keys(1);
    let mut ledger = PeerAssociationLedger::new();
    record(&mut ledger, descriptor(1, 7), &locals);
    (locals, ledger)
}

#[test]
fn relation_roundtrips_and_remove_readd_preserves_highwater_and_rejects_stale_refs() {
    let locals = local_keys(1);
    let mut ledger = PeerAssociationLedger::new();
    let value = descriptor(1, 7);
    let PeerAssociationMutation::Recorded(original) = ledger
        .record_from_trusted_host(value.clone(), &locals)
        .unwrap()
    else {
        panic!("first record must be new")
    };
    assert_eq!(original.generation(), 1);
    assert_eq!(ledger.next_generation(), 2);
    let mut restored = PeerAssociationLedger::from_bytes(&ledger.to_bytes().unwrap()).unwrap();
    restored.validate_relationships(&locals).unwrap();
    assert_eq!(restored.resolve(original).unwrap().descriptor(), &value);
    assert_eq!(
        restored
            .record_from_trusted_host(value.clone(), &locals)
            .unwrap(),
        PeerAssociationMutation::AlreadyRecorded(original)
    );
    assert_eq!(restored.next_generation(), 2);
    assert_eq!(
        restored.remove_from_trusted_host(original),
        PeerAssociationRemoval::Removed
    );
    assert_eq!(
        restored.remove_from_trusted_host(original),
        PeerAssociationRemoval::NotCurrent
    );
    let empty = restored.to_bytes().unwrap();
    let mut reopened = PeerAssociationLedger::from_bytes(&empty).unwrap();
    assert!(reopened.is_empty());
    assert_eq!(reopened.next_generation(), 2);
    let PeerAssociationMutation::Recorded(replacement) =
        reopened.record_from_trusted_host(value, &locals).unwrap()
    else {
        panic!("removed membership needs new generation")
    };
    assert_eq!(replacement.generation(), 2);
    assert!(reopened.resolve(original).is_none());
    assert_eq!(
        reopened.remove_from_trusted_host(original),
        PeerAssociationRemoval::NotCurrent
    );
    assert!(reopened.resolve(replacement).is_some());
}

#[test]
fn identical_pc_signing_and_transport_keys_are_allowed_but_revision_is_nonzero() {
    let (locals, ledger) = one();
    let value = ledger.lookup_current(pc(1)).unwrap().descriptor();
    assert_eq!(value.pc_signing_key(), value.pc_transport_key());
    assert_eq!(value.pc(), pc(1));
    assert_eq!(value.recipient_device_id(), device(1));
    assert_eq!(value.pc_registry_revision(), 7);
    assert_eq!(value.local_key_handle(), handle(1));
    ledger.validate_relationships(&locals).unwrap();
    assert_eq!(
        PeerAssociationDescriptor::new(pc(2), device(2), 0, handle(2), key(130), key(130)),
        Err(PeerAssociationError::InvalidPcRegistryRevision)
    );
    assert!(
        PeerAssociationDescriptor::new(pc(2), device(2), u64::MAX, handle(2), key(130), key(130))
            .is_ok()
    );
}

#[test]
fn missing_and_preparing_local_keys_never_create_membership_or_consume_generation() {
    let mut locals = LocalKeyLedger::new();
    let mut ledger = PeerAssociationLedger::new();
    let before = ledger.to_bytes().unwrap();
    for preparing in [false, true] {
        if preparing {
            locals
                .begin_creation(
                    handle(1),
                    LocalAttestationChallenge::from_bytes([11; 32]).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            ledger.record_from_trusted_host(descriptor(1, 1), &locals),
            Err(PeerAssociationError::LocalKeyUnavailable)
        );
        assert!(ledger.to_bytes().unwrap() == before);
        assert_eq!(ledger.next_generation(), 1);
    }
}

#[test]
fn conflicting_current_pc_fields_require_removal_and_preserve_prior_state() {
    let locals = local_keys(2);
    let mut ledger = PeerAssociationLedger::new();
    record(&mut ledger, descriptor(1, 7), &locals);
    let before = ledger.to_bytes().unwrap();
    for (recipient, revision, local_handle, signing, transport) in [
        (2, 7, 1, 129, 129),
        (1, 8, 1, 129, 129),
        (1, 7, 2, 129, 129),
        (1, 7, 1, 200, 129),
        (1, 7, 1, 129, 200),
    ] {
        let changed = PeerAssociationDescriptor::new(
            pc(1),
            device(recipient),
            revision,
            handle(local_handle),
            key(signing),
            key(transport),
        )
        .unwrap();
        assert_eq!(
            ledger.record_from_trusted_host(changed, &locals),
            Err(PeerAssociationError::ConflictRequiresRemoval)
        );
        assert!(ledger.to_bytes().unwrap() == before);
    }
}

#[test]
fn cross_pc_device_handle_and_all_key_role_reuse_combinations_are_rejected_atomically() {
    let locals = local_keys(2);
    let mut ledger = PeerAssociationLedger::new();
    record(
        &mut ledger,
        PeerAssociationDescriptor::new(pc(1), device(1), 1, handle(1), key(129), key(130)).unwrap(),
        &locals,
    );
    let before = ledger.to_bytes().unwrap();
    for (recipient, local_handle, expected) in [
        (2, 1, PeerAssociationError::LocalHandleAlreadyAssociated),
        (1, 2, PeerAssociationError::DeviceAlreadyAssociated),
    ] {
        let value = PeerAssociationDescriptor::new(
            pc(2),
            device(recipient),
            1,
            handle(local_handle),
            key(200),
            key(201),
        )
        .unwrap();
        assert_eq!(
            ledger.record_from_trusted_host(value, &locals),
            Err(expected)
        );
        assert!(ledger.to_bytes().unwrap() == before);
    }
    for (signing, transport) in [(129, 200), (200, 129), (130, 200), (200, 130)] {
        let value = PeerAssociationDescriptor::new(
            pc(2),
            device(2),
            1,
            handle(2),
            key(signing),
            key(transport),
        )
        .unwrap();
        assert_eq!(
            ledger.record_from_trusted_host(value, &locals),
            Err(PeerAssociationError::PcKeyReuse)
        );
        assert!(ledger.to_bytes().unwrap() == before);
    }
}

#[test]
fn either_pc_key_must_differ_from_every_created_local_role_including_unreferenced_sets() {
    let locals = local_keys(2);
    let mut ledger = PeerAssociationLedger::new();
    let before = ledger.to_bytes().unwrap();
    for reused in 1..=6 {
        for (signing, transport) in [(reused, 200), (200, reused)] {
            let value = PeerAssociationDescriptor::new(
                pc(1),
                device(1),
                1,
                handle(1),
                key(signing),
                key(transport),
            )
            .unwrap();
            assert_eq!(
                ledger.record_from_trusted_host(value, &locals),
                Err(PeerAssociationError::PcKeyMatchesLocalKey)
            );
            assert!(ledger.to_bytes().unwrap() == before);
        }
    }
}

#[test]
fn future_local_key_collision_invalidates_relationships_and_downward_removal_still_works() {
    let (mut locals, mut ledger) = one();
    let reference = ledger.lookup_current(pc(1)).unwrap().reference();
    let before = ledger.to_bytes().unwrap();
    let challenge = LocalAttestationChallenge::from_bytes([12; 32]).unwrap();
    locals.begin_creation(handle(2), challenge).unwrap();
    locals
        .record_created(
            LocalKeySetDescriptor::new(handle(2), challenge, key(129), key(200), key(201)).unwrap(),
        )
        .unwrap();
    assert_eq!(
        ledger.validate_relationships(&locals),
        Err(PeerAssociationError::PcKeyMatchesLocalKey)
    );
    assert_eq!(
        ledger.record_from_trusted_host(descriptor(1, 7), &locals),
        Err(PeerAssociationError::PcKeyMatchesLocalKey)
    );
    assert!(ledger.to_bytes().unwrap() == before);
    assert_eq!(
        ledger.validate_relationships(&LocalKeyLedger::new()),
        Err(PeerAssociationError::LocalKeyUnavailable)
    );
    assert_eq!(
        ledger.remove_from_trusted_host(reference),
        PeerAssociationRemoval::Removed
    );
    assert!(ledger.validate_relationships(&locals).is_ok());
    assert_eq!(ledger.next_generation(), 2);
}

#[test]
fn canonical_pc_order_does_not_reassign_generations_or_fill_removed_highwater_gaps() {
    let locals = local_keys(3);
    let mut ledger = PeerAssociationLedger::new();
    let second = record(&mut ledger, descriptor(2, 9), &locals);
    let first = record(&mut ledger, descriptor(1, 8), &locals);
    assert_eq!(
        ledger
            .entries()
            .map(|entry| entry.descriptor().pc())
            .collect::<Vec<_>>(),
        vec![pc(1), pc(2)]
    );
    assert_eq!(first.generation(), 2);
    assert_eq!(second.generation(), 1);
    let mut restored = PeerAssociationLedger::from_bytes(&ledger.to_bytes().unwrap()).unwrap();
    assert_eq!(restored, ledger);
    assert_eq!(
        restored.remove_from_trusted_host(first),
        PeerAssociationRemoval::Removed
    );
    let mut reopened = PeerAssociationLedger::from_bytes(&restored.to_bytes().unwrap()).unwrap();
    assert_eq!(reopened.next_generation(), 3);
    assert_eq!(
        record(&mut reopened, descriptor(3, 1), &locals).generation(),
        3
    );
}

#[test]
fn generation_exhaustion_preserves_state_and_does_not_block_idempotency_or_removal() {
    let locals = local_keys(2);
    let mut bytes = PeerAssociationLedger::new().to_bytes().unwrap();
    bytes[12..20].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
    let mut ledger = PeerAssociationLedger::from_bytes(&bytes).unwrap();
    let original = record(&mut ledger, descriptor(1, 1), &locals);
    assert_eq!(original.generation(), u64::MAX - 1);
    assert_eq!(ledger.next_generation(), u64::MAX);
    let before = ledger.to_bytes().unwrap();
    assert_eq!(
        ledger
            .record_from_trusted_host(descriptor(1, 1), &locals)
            .unwrap(),
        PeerAssociationMutation::AlreadyRecorded(original)
    );
    assert_eq!(
        ledger.record_from_trusted_host(descriptor(2, 1), &locals),
        Err(PeerAssociationError::GenerationExhausted)
    );
    assert!(ledger.to_bytes().unwrap() == before);
    assert_eq!(
        ledger.remove_from_trusted_host(original),
        PeerAssociationRemoval::Removed
    );
    let mut reopened = PeerAssociationLedger::from_bytes(&ledger.to_bytes().unwrap()).unwrap();
    assert_eq!(reopened.next_generation(), u64::MAX);
    assert_eq!(
        reopened.record_from_trusted_host(descriptor(1, 1), &locals),
        Err(PeerAssociationError::GenerationExhausted)
    );
    assert!(reopened.is_empty());
}

#[test]
fn all_32_active_associations_fit_the_exact_bound_and_no_entry_is_evicted() {
    assert_eq!(MAX_PEER_ASSOCIATIONS, 32);
    assert_eq!(MAX_PEER_ASSOCIATION_LEDGER_BYTES, 10_584);
    let locals = local_keys(32);
    let mut ledger = PeerAssociationLedger::new();
    for index in 1..=32 {
        record(&mut ledger, descriptor(index, u64::from(index)), &locals);
    }
    let bytes = ledger.to_bytes().unwrap();
    assert_eq!(ledger.len(), 32);
    assert_eq!(ledger.next_generation(), 33);
    assert_eq!(bytes.len(), HEADER_BYTES + 32 * RECORD_BYTES);
    assert_eq!(bytes.len(), MAX_PEER_ASSOCIATION_LEDGER_BYTES);
    let restored = PeerAssociationLedger::from_bytes(&bytes).unwrap();
    restored.validate_relationships(&locals).unwrap();
    assert_eq!(restored, ledger);
    let extra =
        PeerAssociationDescriptor::new(pc(33), device(33), 1, handle(1), key(200), key(201))
            .unwrap();
    assert_eq!(
        ledger.record_from_trusted_host(extra, &locals),
        Err(PeerAssociationError::CapacityReached)
    );
    assert!(ledger.to_bytes().unwrap() == bytes);
}

#[test]
fn v2_roundtrips_canonical_ipv4_ipv6_and_absent_relay_endpoints() {
    let locals = local_keys(3);
    let mut ledger = PeerAssociationLedger::new();
    let ipv4 = descriptor(1, 1)
        .with_relay(relay_v4(1).0, relay_v4(1).1)
        .unwrap();
    let ipv6 = descriptor(2, 2)
        .with_relay(relay_v6(2).0, relay_v6(2).1)
        .unwrap();
    let absent = descriptor(3, 3);
    record(&mut ledger, ipv4.clone(), &locals);
    record(&mut ledger, ipv6.clone(), &locals);
    record(&mut ledger, absent.clone(), &locals);
    let bytes = ledger.to_bytes().unwrap();
    assert_eq!(u16::from_be_bytes(bytes[8..10].try_into().unwrap()), 2);
    let restored = PeerAssociationLedger::from_bytes(&bytes).unwrap();
    assert_eq!(restored.lookup_current(pc(1)).unwrap().descriptor(), &ipv4);
    assert_eq!(restored.lookup_current(pc(2)).unwrap().descriptor(), &ipv6);
    assert_eq!(
        restored.lookup_current(pc(3)).unwrap().descriptor(),
        &absent
    );
    assert_eq!(ipv4.relay(), Some(relay_v4(1)));
    assert_eq!(ipv6.relay(), Some(relay_v6(2)));
    assert_eq!(absent.relay(), None);
    restored.validate_relationships(&locals).unwrap();
}

#[test]
fn legacy_v1_record_decodes_without_endpoint_and_rewrites_as_v2() {
    let (_, ledger) = one();
    let current = ledger.to_bytes().unwrap();
    let mut legacy = Vec::with_capacity(HEADER_BYTES + LEGACY_RECORD_BYTES);
    legacy.extend_from_slice(&current[..8]);
    legacy.extend_from_slice(&1_u16.to_be_bytes());
    legacy.extend_from_slice(&current[10..HEADER_BYTES + LEGACY_RECORD_BYTES]);
    assert_eq!(legacy.len(), HEADER_BYTES + LEGACY_RECORD_BYTES);
    let restored = PeerAssociationLedger::from_bytes(&legacy).unwrap();
    assert_eq!(
        restored.lookup_current(pc(1)).unwrap().descriptor().relay(),
        None
    );
    let rewritten = restored.to_bytes().unwrap();
    assert_eq!(u16::from_be_bytes(rewritten[8..10].try_into().unwrap()), 2);
    assert_eq!(rewritten.len(), HEADER_BYTES + RECORD_BYTES);
    assert_eq!(
        &rewritten[HEADER_BYTES + RELAY_OFFSET..HEADER_BYTES + RECORD_BYTES],
        &[0; 52]
    );
}

#[test]
fn relay_constructor_rejects_zero_port_and_route() {
    assert_eq!(
        descriptor(1, 1).with_relay(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0), [1; 32]),
        Err(PeerAssociationError::InvalidRelayPort)
    );
    assert_eq!(
        descriptor(1, 1).with_relay(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1), [0; 32]),
        Err(PeerAssociationError::InvalidRelayRoute)
    );
}

#[test]
fn codec_rejects_noncanonical_or_invalid_relay_fields() {
    let (_, ledger) = one();
    let base = HEADER_BYTES + RELAY_OFFSET;
    let bytes = ledger.to_bytes().unwrap();
    for (offset, value, expected) in [
        (0, 2, PeerAssociationError::InvalidRelayEncoding),
        (1, 5, PeerAssociationError::InvalidRelayEncoding),
        (2, 0, PeerAssociationError::InvalidRelayEncoding),
        (4, 1, PeerAssociationError::InvalidRelayEncoding),
        (20, 1, PeerAssociationError::InvalidRelayEncoding),
    ] {
        let mut invalid = bytes.clone();
        invalid[base + offset] = value;
        assert_eq!(PeerAssociationLedger::from_bytes(&invalid), Err(expected));
    }

    let (_, mut endpoint_ledger) = one();
    let reference = endpoint_ledger.lookup_current(pc(1)).unwrap().reference();
    assert_eq!(
        endpoint_ledger.remove_from_trusted_host(reference),
        PeerAssociationRemoval::Removed
    );
    let locals = local_keys(1);
    record(
        &mut endpoint_ledger,
        descriptor(1, 7)
            .with_relay(relay_v4(1).0, relay_v4(1).1)
            .unwrap(),
        &locals,
    );
    let endpoint_bytes = endpoint_ledger.to_bytes().unwrap();
    for (mutate, expected) in [
        (0_u8, PeerAssociationError::InvalidRelayPort),
        (1, PeerAssociationError::InvalidRelayRoute),
        (2, PeerAssociationError::InvalidRelayFamily),
        (3, PeerAssociationError::InvalidRelayEncoding),
    ] {
        let mut invalid = endpoint_bytes.clone();
        match mutate {
            0 => invalid[base + 2..base + 4].fill(0),
            1 => invalid[base + 20..base + 52].fill(0),
            2 => invalid[base + 1] = 5,
            3 => invalid[base + 8] = 1,
            _ => unreachable!(),
        }
        assert_eq!(PeerAssociationLedger::from_bytes(&invalid), Err(expected));
    }
}

#[test]
fn endpoint_differences_require_removal_but_relationship_checks_are_unchanged() {
    let locals = local_keys(1);
    let mut ledger = PeerAssociationLedger::new();
    let first = descriptor(1, 7)
        .with_relay(relay_v4(1).0, relay_v4(1).1)
        .unwrap();
    record(&mut ledger, first.clone(), &locals);
    assert_eq!(
        ledger
            .record_from_trusted_host(first.clone(), &locals)
            .unwrap(),
        PeerAssociationMutation::AlreadyRecorded(ledger.lookup_current(pc(1)).unwrap().reference())
    );
    let changed = descriptor(1, 7)
        .with_relay(relay_v6(1).0, relay_v6(1).1)
        .unwrap();
    assert_eq!(
        ledger.record_from_trusted_host(changed, &locals),
        Err(PeerAssociationError::ConflictRequiresRemoval)
    );
    ledger.validate_relationships(&locals).unwrap();
}

#[test]
fn codec_rejects_all_truncations_trailing_reserved_version_count_and_size_mutations() {
    let (_, ledger) = one();
    let bytes = ledger.to_bytes().unwrap();
    for length in 0..bytes.len() {
        assert!(
            PeerAssociationLedger::from_bytes(&bytes[..length]).is_err(),
            "truncated length {length}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PeerAssociationLedger::from_bytes(&trailing),
        Err(PeerAssociationError::InvalidEncoding)
    );
    for offset in [0, 10, 11, 22, 23] {
        let mut invalid = bytes.clone();
        invalid[offset] ^= 1;
        assert_eq!(
            PeerAssociationLedger::from_bytes(&invalid),
            Err(PeerAssociationError::InvalidEncoding)
        );
    }
    for version in [0_u16, 3, u16::MAX] {
        let mut invalid = bytes.clone();
        invalid[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            PeerAssociationLedger::from_bytes(&invalid),
            Err(PeerAssociationError::UnsupportedVersion)
        );
    }
    let mut count = bytes;
    count[20..22].copy_from_slice(&33_u16.to_be_bytes());
    assert_eq!(
        PeerAssociationLedger::from_bytes(&count),
        Err(PeerAssociationError::CapacityReached)
    );
    assert_eq!(
        PeerAssociationLedger::from_bytes(&vec![0; MAX_PEER_ASSOCIATION_LEDGER_BYTES + 1]),
        Err(PeerAssociationError::TooLarge)
    );
}

#[test]
fn codec_rejects_zero_identifiers_revisions_invalid_generations_and_invalid_public_keys() {
    let (_, ledger) = one();
    let bytes = ledger.to_bytes().unwrap();
    for (start, length) in [(0, 32), (32, 16), (56, 32)] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES + start..HEADER_BYTES + start + length].fill(0);
        assert_eq!(
            PeerAssociationLedger::from_bytes(&invalid),
            Err(PeerAssociationError::InvalidIdentity)
        );
    }
    let mut zero_revision = bytes.clone();
    zero_revision[HEADER_BYTES + 48..HEADER_BYTES + 56].fill(0);
    assert_eq!(
        PeerAssociationLedger::from_bytes(&zero_revision),
        Err(PeerAssociationError::InvalidPcRegistryRevision)
    );
    let mut zero_next = bytes.clone();
    zero_next[12..20].fill(0);
    assert_eq!(
        PeerAssociationLedger::from_bytes(&zero_next),
        Err(PeerAssociationError::InvalidGeneration)
    );
    for generation in [0_u64, 2, u64::MAX] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES + GENERATION_OFFSET..HEADER_BYTES + GENERATION_OFFSET + 8]
            .copy_from_slice(&generation.to_be_bytes());
        assert_eq!(
            PeerAssociationLedger::from_bytes(&invalid),
            Err(PeerAssociationError::InvalidGeneration)
        );
    }
    for start in [SIGNING_OFFSET, TRANSPORT_OFFSET] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES + start] ^= 1;
        assert_eq!(
            PeerAssociationLedger::from_bytes(&invalid),
            Err(PeerAssociationError::InvalidPublicKey)
        );
    }
}

#[test]
fn codec_rejects_unsorted_duplicate_pc_generation_device_handle_and_pc_key_records() {
    let locals = local_keys(2);
    let mut ledger = PeerAssociationLedger::new();
    record(&mut ledger, descriptor(1, 1), &locals);
    record(&mut ledger, descriptor(2, 1), &locals);
    let bytes = ledger.to_bytes().unwrap();
    let second = HEADER_BYTES + RECORD_BYTES;
    let mut swapped = bytes.clone();
    swapped[HEADER_BYTES..second].copy_from_slice(&bytes[second..]);
    swapped[second..].copy_from_slice(&bytes[HEADER_BYTES..second]);
    assert_eq!(
        PeerAssociationLedger::from_bytes(&swapped),
        Err(PeerAssociationError::NonCanonicalOrder)
    );
    for (offset, length, expected) in [
        (0, 32, PeerAssociationError::DuplicatePcIdentity),
        (32, 16, PeerAssociationError::DeviceAlreadyAssociated),
        (56, 32, PeerAssociationError::LocalHandleAlreadyAssociated),
        (SIGNING_OFFSET, 91, PeerAssociationError::PcKeyReuse),
        (
            GENERATION_OFFSET,
            8,
            PeerAssociationError::DuplicateGeneration,
        ),
    ] {
        let mut duplicate = bytes.clone();
        duplicate[second + offset..second + offset + length]
            .copy_from_slice(&bytes[HEADER_BYTES + offset..HEADER_BYTES + offset + length]);
        assert_eq!(PeerAssociationLedger::from_bytes(&duplicate), Err(expected));
    }
}

#[test]
fn own_shape_decoding_never_substitutes_for_composite_local_key_relationship_checks() {
    let (locals, ledger) = one();
    let mut bytes = ledger.to_bytes().unwrap();
    bytes[HEADER_BYTES + SIGNING_OFFSET..HEADER_BYTES + SIGNING_OFFSET + 91]
        .copy_from_slice(key(1).as_spki_der());
    let decoded = PeerAssociationLedger::from_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.validate_relationships(&locals),
        Err(PeerAssociationError::PcKeyMatchesLocalKey)
    );
    assert_eq!(
        decoded.validate_relationships(&LocalKeyLedger::new()),
        Err(PeerAssociationError::LocalKeyUnavailable)
    );
}

#[test]
fn debug_redacts_device_pc_handle_and_key_values() {
    let (_, ledger) = one();
    let current = ledger.lookup_current(pc(1)).unwrap();
    let text = format!(
        "{ledger:?} {current:?} {:?} {:?}",
        current.descriptor(),
        current.reference()
    );
    assert!(!text.contains(&format!("{:?}", pc(1).as_bytes())));
    assert!(!text.contains(&format!("{:?}", device(1).as_bytes())));
    assert!(!text.contains(&format!("{:?}", handle(1).as_bytes())));
    assert!(!text.contains(&format!(
        "{:?}",
        current.descriptor().pc_signing_key().as_spki_der()
    )));
}
