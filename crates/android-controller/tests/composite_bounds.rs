// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure maximum-occupancy composite codec test. PC signing material, identities
//! and clock observations are synthetic; no enrollment, native authentication,
//! file commit, notification delivery or Windows result is proven here.

use std::{collections::BTreeSet, sync::Arc};

use activity_journal::{
    MAX_OUTCOME_HISTORY_BYTES, MAX_OUTCOME_HISTORY_RECORDS, OutcomeHistory, OutcomeHistoryError,
    OutcomeHistoryLimits,
};
use android_controller::{
    ControllerCheckpoint, ControllerCheckpointError, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeyLedger, LocalKeySetDescriptor, MAX_LOCAL_KEY_LEDGER_BYTES,
    MAX_PEER_ASSOCIATION_LEDGER_BYTES, PeerAssociationDescriptor, PeerAssociationLedger,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DeviceId, ExpiryTick, OsSession, PcIdentity, RequestBinding,
    RequestContent, RequestId,
};
use notification_policy::Weekday;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::EncodePublicKey;
use phone_request_core::{
    CapacityLimits, ClockReading, Effect, InboxClock, LocalTime, MonotonicTime, NotificationPolicy,
    PhoneBootId, PhoneInbox, ReceivingGeneration,
};
use phone_state_store::MAX_SNAPSHOT_BYTES;
use secure_channel::TlsPublicKey;
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};

const MILLI: u64 = 1_000_000;
const RECORD_CAP: usize = 512;
const BODY_MARKER: &str = "SYNTHETIC_COMPOSITE_BODY_NOT_PERSISTED";
// Published v3 format sizes; no access to private constructors or state fields.
const COMPOSITE_HEADER_BYTES: usize = 26;
const HISTORY_HEADER_BYTES: usize = 22;

fn pc(peer: u16) -> PcIdentity {
    let mut bytes = [0; 32];
    bytes[..2].copy_from_slice(&peer.to_be_bytes());
    PcIdentity::from_bytes(bytes).expect("nonzero synthetic PC identity")
}

fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
}

fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(7).unwrap()
}

fn clock(ms: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        ms * MILLI,
    )
    .unwrap()
}

fn verified(event: PcEvent) -> VerifiedPcEvent {
    let expected = event.pc();
    // One explicitly synthetic fixture key for all peers is NOT an enrollment
    // registry. Signatures exercise the real verified-event parsing boundary.
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(expected, &public)
        .unwrap()
}

fn source(peer: u16) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(peer), 0).unwrap();
    let response = verified(PcEvent::Clock {
        pc: pc(peer),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    });
    probe.complete(&response, 0).unwrap()
}

fn opened(peer: u16) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic composite app",
            "C:\\Synthetic\\composite.exe",
            BODY_MARKER,
        )
        .unwrap(),
    );
    let binding = RequestBinding::new(
        pc(peer),
        epoch(),
        OsSession::new(3, 9),
        RequestId::from_bytes([3; 32]).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(60_000 * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content,
    })
}

fn full_inbox() -> PhoneInbox {
    full_inbox_with_sources(false)
}

fn full_inbox_with_sources(with_sources: bool) -> PhoneInbox {
    let mut inbox = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::new(32, RECORD_CAP).unwrap(),
        boot(),
    );
    for peer in 1..=RECORD_CAP as u16 {
        let event = opened(peer);
        let mut correlation = source(peer);
        let generation = ReceivingGeneration::from_trusted_owner(u64::from(peer)).unwrap();
        let opened = if with_sources {
            inbox.receive_opened_from(&event, generation, &mut correlation, clock(0))
        } else {
            inbox.receive_opened(&event, &mut correlation, clock(0))
        };
        assert!(
            opened
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Show(_)))
        );
        let PcEvent::Opened {
            binding, issued_at, ..
        } = event.event()
        else {
            panic!("opened fixture")
        };
        let resolution = verified(PcEvent::Resolved {
            binding: *binding,
            issued_at: *issued_at,
            outcome: RequestResolution::Cancelled,
        });
        let resolved = if with_sources {
            inbox.resolve_pc_from(&resolution, generation, &mut correlation, clock(0))
        } else {
            inbox.resolve_pc(&resolution, &mut correlation, clock(0))
        };
        assert!(resolved.issue().is_none());
    }
    assert_eq!(inbox.pending_outcomes().len(), RECORD_CAP);
    assert_eq!(inbox.retained_count(), RECORD_CAP);
    assert_eq!(inbox.source_count(), RECORD_CAP);
    assert_eq!(inbox.active_count(), 0);
    assert_eq!(inbox.retained_body_count(), 0);
    inbox
}

fn full_disjoint_history(pending_ids: &BTreeSet<[u8; 32]>) -> OutcomeHistory {
    // These are synthetic persisted display projections, not PendingOutcome
    // values or proof of earlier native delivery. The public history codec
    // validates the fixed format; the public composite codec checks separation.
    let mut bytes = OutcomeHistory::new(OutcomeHistoryLimits::default())
        .to_bytes()
        .unwrap();
    assert_eq!(bytes.len(), HISTORY_HEADER_BYTES);
    bytes[20..22].copy_from_slice(&(RECORD_CAP as u16).to_be_bytes());
    for index in 1..=RECORD_CAP {
        let mut id = [0; 32];
        id[..8].copy_from_slice(b"HISTORY\0");
        id[24..].copy_from_slice(&(index as u64).to_be_bytes());
        assert!(
            !pending_ids.contains(&id),
            "synthetic history ID must be disjoint"
        );
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&(10_000 + index as u64).to_be_bytes());
        bytes.push(1); // Exact CancelledByPc tag; never an approval claim.
    }
    assert_eq!(bytes.len(), MAX_OUTCOME_HISTORY_BYTES);
    let history = OutcomeHistory::from_bytes(&bytes).unwrap();
    assert_eq!(history.records().len(), RECORD_CAP);
    assert_eq!(history.to_bytes().unwrap(), bytes);
    history
}

fn public(seed: u8) -> TlsPublicKey {
    let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
    let key = p256::PublicKey::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap();
    TlsPublicKey::from_spki_der(key.to_public_key_der().unwrap().as_bytes()).unwrap()
}

fn full_local_keys() -> LocalKeyLedger {
    let mut keys = LocalKeyLedger::default();
    for index in 0..32_u8 {
        let handle = LocalKeyHandle::from_bytes([index + 1; 32]).unwrap();
        let challenge = LocalAttestationChallenge::from_bytes([index + 64; 32]).unwrap();
        keys.begin_creation(handle, challenge).unwrap();
        keys.record_created(
            LocalKeySetDescriptor::new(
                handle,
                challenge,
                public(2 + index * 3),
                public(3 + index * 3),
                public(4 + index * 3),
            )
            .unwrap(),
        )
        .unwrap();
    }
    keys
}

fn full_peer_associations(keys: &LocalKeyLedger) -> PeerAssociationLedger {
    let mut peers = PeerAssociationLedger::new();
    for index in 0..32u8 {
        let descriptor = PeerAssociationDescriptor::new(
            pc(u16::from(index) + 1),
            DeviceId::from_bytes([index + 1; 16]).unwrap(),
            1,
            LocalKeyHandle::from_bytes([index + 1; 32]).unwrap(),
            public(128 + index * 2),
            public(129 + index * 2),
        )
        .unwrap();
        // Synthetic structural relationship only, never enrollment evidence.
        peers.record_from_trusted_host(descriptor, keys).unwrap();
    }
    peers
}

fn envelope(inbox: &[u8], history: &[u8], keys: &[u8], peers: &[u8]) -> Vec<u8> {
    // ControllerCheckpoint::new remains native-private. Supplying the published
    // envelope to its public strict decoder tests the same boundary as a load.
    let mut bytes = Vec::with_capacity(
        COMPOSITE_HEADER_BYTES + inbox.len() + history.len() + keys.len() + peers.len(),
    );
    bytes.extend_from_slice(b"UACOWNR\0");
    bytes.extend_from_slice(&3_u16.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(inbox.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(history.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(keys.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(peers.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(inbox);
    bytes.extend_from_slice(history);
    bytes.extend_from_slice(keys);
    bytes.extend_from_slice(peers);
    bytes
}

#[test]
fn all_512_original_sources_and_four_maximum_components_fit_without_new_cap() {
    let inbox = full_inbox_with_sources(true);
    let checkpoint = inbox.checkpoint().unwrap();
    assert_eq!(checkpoint.receiving_sources().count(), RECORD_CAP);
    let inbox_bytes = checkpoint.to_bytes().unwrap();
    let pending_ids = inbox
        .pending_outcomes()
        .iter()
        .map(|row| *row.delivery_id().as_bytes())
        .collect();
    let history_bytes = full_disjoint_history(&pending_ids).to_bytes().unwrap();
    let keys = full_local_keys();
    let templates = full_peer_associations(&keys);
    let template = templates.entries().next().unwrap().descriptor().clone();
    let mut peers = PeerAssociationLedger::new();
    // Explicit synthetic native-host history: each old association really used
    // its retained generation, then was removed before the current 32 records.
    for index in 1..=RECORD_CAP as u16 {
        let descriptor = PeerAssociationDescriptor::new(
            pc(index),
            template.recipient_device_id(),
            template.pc_registry_revision(),
            template.local_key_handle(),
            template.pc_signing_key().clone(),
            template.pc_transport_key().clone(),
        )
        .unwrap();
        let created = peers.record_from_trusted_host(descriptor, &keys).unwrap();
        let reference = match created {
            android_controller::PeerAssociationMutation::Recorded(reference) => reference,
            other => panic!("unexpected synthetic generation result: {other:?}"),
        };
        assert_eq!(reference.generation(), u64::from(index));
        assert_eq!(
            peers.remove_from_trusted_host(reference),
            android_controller::PeerAssociationRemoval::Removed
        );
    }
    for current in templates.entries() {
        assert!(matches!(
            peers
                .record_from_trusted_host(current.descriptor().clone(), &keys)
                .unwrap(),
            android_controller::PeerAssociationMutation::Recorded(_)
        ));
    }
    let key_bytes = keys.to_bytes().unwrap();
    let peer_bytes = peers.to_bytes().unwrap();
    assert_eq!(peer_bytes.len(), MAX_PEER_ASSOCIATION_LEDGER_BYTES);
    let bytes = envelope(&inbox_bytes, &history_bytes, &key_bytes, &peer_bytes);
    assert!(bytes.len() <= MAX_SNAPSHOT_BYTES);
    let restored = ControllerCheckpoint::from_bytes(&bytes).unwrap();
    assert_eq!(restored.inbox().receiving_sources().count(), RECORD_CAP);
    assert_eq!(restored.to_bytes().unwrap(), bytes);

    // Keep a sufficiently high allocator ceiling, but assign an active peer a
    // generation already retained by a different historical PC. The independent
    // peer codec is valid; only the cross-component relationship is invalid.
    let mut active_alias = peer_bytes.clone();
    const PEER_HEADER_BYTES: usize = 24;
    const PEER_ROW_BYTES: usize = 278;
    // The first row is PC1, which legitimately owns historical generation1.
    // Assign that generation to the SECOND row (PC2) to create a real conflict.
    active_alias
        [PEER_HEADER_BYTES + 2 * PEER_ROW_BYTES - 8..PEER_HEADER_BYTES + 2 * PEER_ROW_BYTES]
        .copy_from_slice(&1_u64.to_be_bytes());
    let aliased = PeerAssociationLedger::from_bytes(&active_alias).unwrap();
    assert_eq!(aliased.lookup_current(pc(2)).unwrap().generation(), 1);
    assert!(
        checkpoint
            .receiving_sources()
            .any(|(source_pc, generation)| source_pc == pc(1) && generation.get() == 1)
    );
    assert!(matches!(
        ControllerCheckpoint::from_bytes(&envelope(
            &inbox_bytes,
            &history_bytes,
            &key_bytes,
            &active_alias
        )),
        Err(ControllerCheckpointError::ReceivingSourceMismatch)
    ));

    // Two historical PCs cannot claim the same generation even if neither
    // remains active in the peer ledger and the highwater itself is sufficient.
    let mut conflicting = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
    );
    for peer in [701, 702] {
        let mut correlation = source(peer);
        let accepted = conflicting.receive_opened_from(
            &opened(peer),
            ReceivingGeneration::from_trusted_owner(1).unwrap(),
            &mut correlation,
            clock(0),
        );
        assert!(accepted.issue().is_none());
    }
    let conflicting_bytes = conflicting.checkpoint().unwrap().to_bytes().unwrap();
    let empty_history = OutcomeHistory::new(OutcomeHistoryLimits::default())
        .to_bytes()
        .unwrap();
    assert!(matches!(
        ControllerCheckpoint::from_bytes(&envelope(
            &conflicting_bytes,
            &empty_history,
            &key_bytes,
            &peer_bytes
        )),
        Err(ControllerCheckpointError::ReceivingSourceMismatch)
    ));

    // A valid independent peer ledger cannot erase issued generations merely by
    // resetting its highwater or assign a retained generation to a different PC.
    let reset = full_peer_associations(&keys).to_bytes().unwrap();
    assert!(matches!(
        ControllerCheckpoint::from_bytes(&envelope(
            &inbox_bytes,
            &history_bytes,
            &key_bytes,
            &reset
        )),
        Err(ControllerCheckpointError::ReceivingSourceMismatch)
    ));
}

#[test]
fn maximum_four_components_roundtrip_within_the_unchanged_snapshot_cap() {
    // This tests maximum record occupancy using default policy. It does not
    // assert every optional field or policy encoding has its maximum byte size.
    assert_eq!(MAX_SNAPSHOT_BYTES, 384 * 1024);
    assert_eq!(MAX_OUTCOME_HISTORY_RECORDS, RECORD_CAP);
    let inbox = full_inbox();
    let inbox_bytes = inbox.checkpoint().unwrap().to_bytes().unwrap();
    let pending_ids: BTreeSet<_> = inbox
        .pending_outcomes()
        .iter()
        .map(|pending| *pending.delivery_id().as_bytes())
        .collect();
    assert_eq!(pending_ids.len(), RECORD_CAP);
    let history = full_disjoint_history(&pending_ids);
    let history_bytes = history.to_bytes().unwrap();
    let keys = full_local_keys();
    let key_bytes = keys.to_bytes().unwrap();
    assert_eq!(key_bytes.len(), MAX_LOCAL_KEY_LEDGER_BYTES);
    let peers = full_peer_associations(&keys);
    let peer_bytes = peers.to_bytes().unwrap();
    assert_eq!(peer_bytes.len(), MAX_PEER_ASSOCIATION_LEDGER_BYTES);
    let bytes = envelope(&inbox_bytes, &history_bytes, &key_bytes, &peer_bytes);
    assert_eq!(
        bytes.len(),
        COMPOSITE_HEADER_BYTES
            + inbox_bytes.len()
            + history_bytes.len()
            + key_bytes.len()
            + peer_bytes.len()
    );
    assert!(
        bytes.len() <= MAX_SNAPSHOT_BYTES,
        "actual maximum-occupancy composite length {} exceeds unchanged cap {}",
        bytes.len(),
        MAX_SNAPSHOT_BYTES
    );
    assert!(
        !bytes
            .windows(BODY_MARKER.len())
            .any(|part| part == BODY_MARKER.as_bytes())
    );

    let composite = ControllerCheckpoint::from_bytes(&bytes).unwrap();
    assert_eq!(
        composite.inbox().pending_outcomes(),
        inbox.pending_outcomes()
    );
    assert_eq!(composite.history().records(), history.records());
    assert_eq!(composite.local_keys(), &keys);
    assert_eq!(composite.peer_associations(), &peers);
    let encoded = composite.to_bytes().unwrap();
    assert_eq!(encoded, bytes);
    assert!(encoded.len() <= MAX_SNAPSHOT_BYTES);
    let reread = ControllerCheckpoint::from_bytes(&encoded).unwrap();
    let (restored, update) =
        PhoneInbox::restore_checkpoint(reread.inbox().clone(), boot(), clock(1)).unwrap();
    assert_eq!(restored.retained_count(), RECORD_CAP);
    assert_eq!(restored.source_count(), RECORD_CAP);
    assert_eq!(restored.pending_outcomes(), inbox.pending_outcomes());
    assert_eq!(restored.active_count(), 0);
    assert_eq!(restored.recovering_count(), 0);
    assert_eq!(restored.retained_body_count(), 0);
    assert!(update.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert_eq!(reread.history().records().len(), RECORD_CAP);
    assert_eq!(reread.peer_associations(), &peers);

    // Each malformed candidate retains the same valid full inbox fixture; no
    // producer fields, replay guards or record limits are weakened to fit it.
    let mut overlapping_history = history_bytes.clone();
    overlapping_history[HISTORY_HEADER_BYTES..HISTORY_HEADER_BYTES + 32]
        .copy_from_slice(inbox.pending_outcomes()[0].delivery_id().as_bytes());
    assert!(OutcomeHistory::from_bytes(&overlapping_history).is_ok());
    assert_eq!(
        ControllerCheckpoint::from_bytes(&envelope(
            &inbox_bytes,
            &overlapping_history,
            &key_bytes,
            &peer_bytes
        ))
        .unwrap_err(),
        ControllerCheckpointError::RecordedPendingOverlap
    );

    let mut excessive_count = history_bytes;
    excessive_count[20..22].copy_from_slice(&513_u16.to_be_bytes());
    assert_eq!(
        ControllerCheckpoint::from_bytes(&envelope(
            &inbox_bytes,
            &excessive_count,
            &key_bytes,
            &peer_bytes
        ))
        .unwrap_err(),
        ControllerCheckpointError::History(OutcomeHistoryError::TooManyRecords)
    );
    for (start, claimed_length) in [
        (10, MAX_SNAPSHOT_BYTES + 1),
        (14, MAX_OUTCOME_HISTORY_BYTES + 1),
        (18, MAX_LOCAL_KEY_LEDGER_BYTES + 1),
        (22, MAX_PEER_ASSOCIATION_LEDGER_BYTES + 1),
    ] {
        let mut excess_nested = bytes.clone();
        excess_nested[start..start + 4]
            .copy_from_slice(&u32::try_from(claimed_length).unwrap().to_be_bytes());
        assert_eq!(
            ControllerCheckpoint::from_bytes(&excess_nested).unwrap_err(),
            ControllerCheckpointError::TooLarge
        );
    }
    let mut excess_total = bytes;
    excess_total.resize(MAX_SNAPSHOT_BYTES + 1, 0);
    assert_eq!(
        ControllerCheckpoint::from_bytes(&excess_total).unwrap_err(),
        ControllerCheckpointError::TooLarge
    );
}
