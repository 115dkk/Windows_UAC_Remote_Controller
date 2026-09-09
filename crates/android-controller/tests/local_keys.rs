// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic public-key metadata fixtures only. No AndroidKeyStore operation,
//! native authentication, attestation verification or enrollment is performed.

use android_controller::{
    LocalAttestationChallenge, LocalKeyError, LocalKeyHandle, LocalKeyLedger, LocalKeyObservation,
    LocalKeySetDescriptor, LocalKeySetPhase, MAX_LOCAL_KEY_LEDGER_BYTES, MAX_LOCAL_KEY_SETS,
};
use p256::{PublicKey, ecdsa::SigningKey, pkcs8::EncodePublicKey};
use secure_channel::TlsPublicKey;

// Documented v1 wire sizes, not private implementation access.
const HEADER_BYTES: usize = 12;
const PREPARING_BYTES: usize = 65;
const CREATED_BYTES: usize = 338;
const SPKI_BYTES: usize = 91;

fn handle(value: u8) -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([value; 32]).unwrap()
}

fn challenge(value: u8) -> LocalAttestationChallenge {
    LocalAttestationChallenge::from_bytes([value; 32]).unwrap()
}

fn public_key(seed: u8) -> TlsPublicKey {
    let synthetic = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point =
        PublicKey::from_sec1_bytes(synthetic.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn descriptor(id: u8, challenge_seed: u8, first_key: u8) -> LocalKeySetDescriptor {
    LocalKeySetDescriptor::new(
        handle(id),
        challenge(challenge_seed),
        public_key(first_key),
        public_key(first_key + 1),
        public_key(first_key + 2),
    )
    .unwrap()
}

#[test]
fn pending_creation_roundtrips_without_retry_permission_then_records_unverified_pins() {
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    let pending = ledger.to_bytes().unwrap();
    let mut reopened = LocalKeyLedger::from_bytes(&pending).unwrap();
    assert!(matches!(
        reopened.get(handle(1)),
        Some(LocalKeySetPhase::Preparing { .. })
    ));
    assert_eq!(
        reopened.begin_creation(handle(1), challenge(11)),
        Err(LocalKeyError::HandleAlreadyTracked)
    );
    assert_eq!(reopened.to_bytes().unwrap(), pending);

    let observed = descriptor(1, 11, 1);
    assert_eq!(
        reopened.record_created(observed.clone()).unwrap(),
        LocalKeyObservation::RecordedUnverified
    );
    let bytes = reopened.to_bytes().unwrap();
    let mut restored = LocalKeyLedger::from_bytes(&bytes).unwrap();
    assert_eq!(
        restored.get(handle(1)).unwrap().descriptor(),
        Some(&observed)
    );
    assert_eq!(
        restored.record_created(observed).unwrap(),
        LocalKeyObservation::AlreadyRecordedUnverified
    );
    assert_eq!(
        restored.begin_creation(handle(1), challenge(11)),
        Err(LocalKeyError::HandleAlreadyTracked)
    );
    assert_eq!(restored.to_bytes().unwrap(), bytes);
}

#[test]
fn identifiers_are_nonzero_and_tracked_handles_and_challenges_never_become_new_attempts() {
    assert_eq!(
        LocalKeyHandle::from_bytes([0; 32]),
        Err(LocalKeyError::InvalidHandle)
    );
    assert_eq!(
        LocalAttestationChallenge::from_bytes([0; 32]),
        Err(LocalKeyError::InvalidChallenge)
    );
    assert!(LocalKeyHandle::from_bytes([u8::MAX; 32]).is_ok());
    assert!(LocalAttestationChallenge::from_bytes([u8::MAX; 32]).is_ok());
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    for created in [false, true] {
        if created {
            ledger.record_created(descriptor(1, 11, 1)).unwrap();
        }
        let before = ledger.to_bytes().unwrap();
        assert_eq!(
            ledger.begin_creation(handle(1), challenge(12)),
            Err(LocalKeyError::HandleAlreadyTracked)
        );
        assert_eq!(
            ledger.begin_creation(handle(2), challenge(11)),
            Err(LocalKeyError::ChallengeAlreadyTracked)
        );
        assert_eq!(ledger.to_bytes().unwrap(), before);
    }
}

#[test]
fn created_observation_requires_exact_preparation_and_conflicts_never_replace_it() {
    let mut ledger = LocalKeyLedger::new();
    assert_eq!(
        ledger.record_created(descriptor(1, 11, 1)),
        Err(LocalKeyError::MissingPreparation)
    );
    assert!(ledger.is_empty());
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    let pending = ledger.to_bytes().unwrap();
    assert_eq!(
        ledger.record_created(descriptor(1, 12, 1)),
        Err(LocalKeyError::ChallengeMismatch)
    );
    assert_eq!(
        ledger.record_created(descriptor(2, 11, 1)),
        Err(LocalKeyError::MissingPreparation)
    );
    assert_eq!(ledger.to_bytes().unwrap(), pending);
    let observed = descriptor(1, 11, 1);
    ledger.record_created(observed.clone()).unwrap();
    let before = ledger.to_bytes().unwrap();
    for changed in [
        descriptor(1, 11, 4),
        descriptor(1, 12, 1),
        LocalKeySetDescriptor::new(
            handle(1),
            challenge(11),
            observed.denial_key().clone(),
            observed.approval_key().clone(),
            observed.transport_key().clone(),
        )
        .unwrap(),
    ] {
        assert_eq!(
            ledger.record_created(changed),
            Err(LocalKeyError::ConflictingObservation)
        );
        assert_eq!(ledger.to_bytes().unwrap(), before);
    }
}

#[test]
fn descriptor_rejects_each_pair_of_reused_role_keys() {
    for (approval, denial, transport) in [(1, 1, 2), (1, 2, 1), (1, 2, 2)] {
        assert_eq!(
            LocalKeySetDescriptor::new(
                handle(1),
                challenge(11),
                public_key(approval),
                public_key(denial),
                public_key(transport)
            ),
            Err(LocalKeyError::KeyReuse)
        );
    }
}

#[test]
fn all_nine_cross_set_role_key_reuses_reject_without_changing_pending_state() {
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    let first = descriptor(1, 11, 1);
    ledger.record_created(first.clone()).unwrap();
    ledger.begin_creation(handle(2), challenge(12)).unwrap();
    let before = ledger.to_bytes().unwrap();
    for reused in [
        first.approval_key(),
        first.denial_key(),
        first.transport_key(),
    ] {
        for slot in 0..3 {
            let mut roles = [public_key(4), public_key(5), public_key(6)];
            roles[slot] = reused.clone();
            let [approval, denial, transport] = roles;
            let second =
                LocalKeySetDescriptor::new(handle(2), challenge(12), approval, denial, transport)
                    .unwrap();
            assert_eq!(ledger.record_created(second), Err(LocalKeyError::KeyReuse));
            assert_eq!(ledger.to_bytes().unwrap(), before);
            assert!(ledger.get(handle(2)).unwrap().descriptor().is_none());
        }
    }
}

#[test]
fn empty_and_mixed_phases_roundtrip_in_canonical_handle_order_without_phase_promotion() {
    let empty = LocalKeyLedger::new();
    assert_eq!(empty.to_bytes().unwrap().len(), HEADER_BYTES);
    assert!(
        LocalKeyLedger::from_bytes(&empty.to_bytes().unwrap())
            .unwrap()
            .is_empty()
    );
    let mut ledger = LocalKeyLedger::new();
    for (id, challenge_seed) in [(9, 19), (1, 11), (5, 15)] {
        ledger
            .begin_creation(handle(id), challenge(challenge_seed))
            .unwrap();
    }
    ledger.record_created(descriptor(9, 19, 7)).unwrap();
    ledger.record_created(descriptor(5, 15, 4)).unwrap();
    let bytes = ledger.to_bytes().unwrap();
    assert_eq!(
        bytes.len(),
        HEADER_BYTES + PREPARING_BYTES + 2 * CREATED_BYTES
    );
    let restored = LocalKeyLedger::from_bytes(&bytes).unwrap();
    assert_eq!(restored, ledger);
    assert_eq!(
        restored
            .entries()
            .map(LocalKeySetPhase::handle)
            .collect::<Vec<_>>(),
        vec![handle(1), handle(5), handle(9)]
    );
    assert_eq!(
        restored
            .entries()
            .rev()
            .map(LocalKeySetPhase::handle)
            .collect::<Vec<_>>(),
        vec![handle(9), handle(5), handle(1)]
    );
    let pending = restored.get(handle(1)).unwrap();
    assert!(matches!(pending, LocalKeySetPhase::Preparing { .. }));
    assert_eq!(pending.challenge(), challenge(11));
    assert!(pending.descriptor().is_none());
}

#[test]
fn all_32_sets_fit_the_exact_10828_byte_cap_and_no_set_is_evicted_for_an_extra_creation() {
    assert_eq!(MAX_LOCAL_KEY_SETS, 32);
    assert_eq!(MAX_LOCAL_KEY_LEDGER_BYTES, 10_828);
    let mut ledger = LocalKeyLedger::new();
    for id in 1..=32_u8 {
        ledger
            .begin_creation(handle(id), challenge(id + 100))
            .unwrap();
    }
    assert_eq!(ledger.len(), 32);
    assert_eq!(
        ledger.to_bytes().unwrap().len(),
        HEADER_BYTES + 32 * PREPARING_BYTES
    );
    for created in [false, true] {
        if created {
            for id in 1..=32_u8 {
                ledger
                    .record_created(descriptor(id, id + 100, (id - 1) * 3 + 1))
                    .unwrap();
            }
        }
        let before = ledger.to_bytes().unwrap();
        assert_eq!(
            ledger.begin_creation(handle(33), challenge(133)),
            Err(LocalKeyError::CapacityReached)
        );
        assert_eq!(ledger.to_bytes().unwrap(), before);
        assert_eq!(ledger.len(), 32);
    }
    let bytes = ledger.to_bytes().unwrap();
    assert_eq!(bytes.len(), MAX_LOCAL_KEY_LEDGER_BYTES);
    let mut restored = LocalKeyLedger::from_bytes(&bytes).unwrap();
    assert_eq!(restored, ledger);
    assert_eq!(
        restored
            .entries()
            .filter(|phase| phase.descriptor().is_some())
            .count(),
        32
    );
    assert_eq!(
        restored.record_created(descriptor(1, 101, 1)).unwrap(),
        LocalKeyObservation::AlreadyRecordedUnverified
    );
    assert_eq!(restored.to_bytes().unwrap(), bytes);
}

fn preparing_pair() -> Vec<u8> {
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    ledger.begin_creation(handle(2), challenge(12)).unwrap();
    ledger.to_bytes().unwrap()
}

fn created_bytes() -> Vec<u8> {
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    ledger.record_created(descriptor(1, 11, 1)).unwrap();
    ledger.to_bytes().unwrap()
}

#[test]
fn codec_rejects_each_partial_created_state_trailing_data_and_bad_magic() {
    let bytes = created_bytes();
    for end in 0..bytes.len() {
        assert!(
            LocalKeyLedger::from_bytes(&bytes[..end]).is_err(),
            "partial byte length {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        LocalKeyLedger::from_bytes(&trailing),
        Err(LocalKeyError::InvalidEncoding)
    );
    let mut magic = bytes;
    magic[0] ^= 1;
    assert_eq!(
        LocalKeyLedger::from_bytes(&magic),
        Err(LocalKeyError::InvalidEncoding)
    );
}

#[test]
fn codec_declared_count_mismatch_never_returns_a_partial_ledger() {
    let bytes = preparing_pair();
    for count in [0_u16, 1, 3] {
        let mut mismatch = bytes.clone();
        mismatch[10..12].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            LocalKeyLedger::from_bytes(&mismatch),
            Err(LocalKeyError::InvalidEncoding)
        );
    }
}

#[test]
fn codec_rejects_unknown_versions_phases_excess_count_and_hard_oversize() {
    let bytes = preparing_pair();
    for version in [0_u16, 2, u16::MAX] {
        let mut invalid = bytes.clone();
        invalid[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            LocalKeyLedger::from_bytes(&invalid),
            Err(LocalKeyError::UnsupportedVersion)
        );
    }
    for phase in [0, 3, u8::MAX] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES] = phase;
        assert_eq!(
            LocalKeyLedger::from_bytes(&invalid),
            Err(LocalKeyError::InvalidEncoding)
        );
    }
    for count in [33_u16, u16::MAX] {
        let mut invalid = bytes.clone();
        invalid[10..12].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            LocalKeyLedger::from_bytes(&invalid),
            Err(LocalKeyError::TooManySets)
        );
    }
    assert_eq!(
        LocalKeyLedger::from_bytes(&vec![0; MAX_LOCAL_KEY_LEDGER_BYTES + 1]),
        Err(LocalKeyError::TooLarge)
    );
}

#[test]
fn codec_rejects_unsorted_duplicate_and_zero_handles_and_reused_or_zero_challenges() {
    let bytes = preparing_pair();
    let second = HEADER_BYTES + PREPARING_BYTES;
    let mut swapped = bytes.clone();
    swapped[HEADER_BYTES..second].copy_from_slice(&bytes[second..]);
    swapped[second..].copy_from_slice(&bytes[HEADER_BYTES..second]);
    assert_eq!(
        LocalKeyLedger::from_bytes(&swapped),
        Err(LocalKeyError::NonCanonicalOrder)
    );

    let mut duplicate = bytes.clone();
    duplicate[second + 1..second + 33].copy_from_slice(&bytes[HEADER_BYTES + 1..HEADER_BYTES + 33]);
    assert_eq!(
        LocalKeyLedger::from_bytes(&duplicate),
        Err(LocalKeyError::HandleAlreadyTracked)
    );
    let mut reused = bytes.clone();
    reused[second + 33..second + 65].copy_from_slice(&bytes[HEADER_BYTES + 33..HEADER_BYTES + 65]);
    assert_eq!(
        LocalKeyLedger::from_bytes(&reused),
        Err(LocalKeyError::ChallengeAlreadyTracked)
    );
    let mut zero_handle = bytes.clone();
    zero_handle[HEADER_BYTES + 1..HEADER_BYTES + 33].fill(0);
    assert_eq!(
        LocalKeyLedger::from_bytes(&zero_handle),
        Err(LocalKeyError::InvalidHandle)
    );
    let mut zero_challenge = bytes;
    zero_challenge[HEADER_BYTES + 33..HEADER_BYTES + 65].fill(0);
    assert_eq!(
        LocalKeyLedger::from_bytes(&zero_challenge),
        Err(LocalKeyError::InvalidChallenge)
    );
}

#[test]
fn codec_uses_strict_spki_parsing_and_rejects_invalid_or_reused_role_points() {
    let bytes = created_bytes();
    let key_start = HEADER_BYTES + PREPARING_BYTES;
    for offset in [0, 26] {
        let mut noncanonical = bytes.clone();
        noncanonical[key_start + offset] ^= 1;
        assert_eq!(
            LocalKeyLedger::from_bytes(&noncanonical),
            Err(LocalKeyError::InvalidPublicKey)
        );
    }
    let mut invalid_point = bytes.clone();
    invalid_point[key_start + 27..key_start + SPKI_BYTES].fill(0);
    assert_eq!(
        LocalKeyLedger::from_bytes(&invalid_point),
        Err(LocalKeyError::InvalidPublicKey)
    );
    let mut reused = bytes.clone();
    reused[key_start + SPKI_BYTES..key_start + 2 * SPKI_BYTES]
        .copy_from_slice(&bytes[key_start..key_start + SPKI_BYTES]);
    assert_eq!(
        LocalKeyLedger::from_bytes(&reused),
        Err(LocalKeyError::KeyReuse)
    );
}

#[test]
fn codec_rejects_cross_set_key_reuse_instead_of_promoting_the_second_descriptor() {
    let mut ledger = LocalKeyLedger::new();
    for (id, challenge_seed, first_key) in [(1, 11, 1), (2, 12, 4)] {
        ledger
            .begin_creation(handle(id), challenge(challenge_seed))
            .unwrap();
        ledger
            .record_created(descriptor(id, challenge_seed, first_key))
            .unwrap();
    }
    let bytes = ledger.to_bytes().unwrap();
    let first_approval = HEADER_BYTES + PREPARING_BYTES;
    let second_transport = HEADER_BYTES + CREATED_BYTES + PREPARING_BYTES + 2 * SPKI_BYTES;
    let mut reused = bytes.clone();
    reused[second_transport..second_transport + SPKI_BYTES]
        .copy_from_slice(&bytes[first_approval..first_approval + SPKI_BYTES]);
    assert_eq!(
        LocalKeyLedger::from_bytes(&reused),
        Err(LocalKeyError::KeyReuse)
    );
    assert_eq!(ledger.to_bytes().unwrap(), bytes);
}

#[test]
fn debug_redacts_public_identifiers_challenges_and_key_bytes() {
    let id = handle(1);
    let nonce = challenge(11);
    let observed = descriptor(1, 11, 1);
    let mut ledger = LocalKeyLedger::new();
    ledger.begin_creation(handle(1), challenge(11)).unwrap();
    ledger.record_created(observed.clone()).unwrap();
    let debug = format!(
        "{ledger:?} {observed:?} {:?} {:?} {:?}",
        handle(1),
        challenge(11),
        ledger.get(handle(1))
    );
    for bytes in [
        id.as_bytes().as_slice(),
        nonce.as_bytes().as_slice(),
        observed.approval_key().as_spki_der(),
    ] {
        assert!(!debug.contains(&format!("{bytes:?}")));
    }
    assert!(debug.contains("unverified") || debug.contains("Unverified"));
}
