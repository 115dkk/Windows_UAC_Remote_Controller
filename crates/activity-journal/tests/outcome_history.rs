// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure history/inbox fixtures with a synthetic signing key. These tests neither
//! commit a durable owner nor exercise native notifications or Windows results.

use std::sync::Arc;

use activity_journal::{
    HistoryInsert, HistoryPruneReport, MAX_OUTCOME_HISTORY_BYTES, MAX_OUTCOME_HISTORY_RECORDS,
    MAX_RETENTION_MS, MAX_UNIX_MILLIS, OutcomeHistory, OutcomeHistoryError, OutcomeHistoryLimits,
    UnixMillis,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use notification_policy::{RequestOutcome, Schedule, Weekday};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use phone_request_core::{
    AlertMode, CapacityLimits, ClockReading, Effect, InboxClock, LocalTime, MonotonicTime,
    NotificationPolicy, OutcomeAcknowledgment, PendingOutcome, PhoneBootId, PhoneInbox,
};
use service_protocol::{
    ClockCorrelation, ClockProbe, PcEvent, PcPublicKey, RequestResolution, ServiceTick,
    UnsignedPcEvent, VerifiedPcEvent,
};

const MILLI: u64 = 1_000_000;
const BODY_MARKER: &str = "SYNTHETIC_BODY_NOT_HISTORY";
// Published v1 wire sizes, used only for adversarial stored-projection fixtures.
const HEADER_BYTES: usize = 22;
const ROW_BYTES: usize = 41;

fn timestamp(value: u64) -> UnixMillis {
    UnixMillis::new(value).expect("bounded synthetic native timestamp")
}

fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).unwrap()
}

fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).unwrap()
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
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public =
        PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = key.sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .unwrap()
        .verify(pc(), &public)
        .unwrap()
}

fn source() -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), 0).unwrap();
    let response = verified(PcEvent::Clock {
        pc: pc(),
        epoch: epoch(),
        probe: probe.nonce(),
        sampled_at: ServiceTick::from_nanos_since_epoch(0),
    });
    probe.complete(&response, 0).unwrap()
}

fn opened(id: u64) -> VerifiedPcEvent {
    let content = Arc::new(
        RequestContent::new(
            "Synthetic history app",
            "C:\\Synthetic\\history.exe",
            BODY_MARKER,
        )
        .unwrap(),
    );
    let mut request = [0; 32];
    request[..8].copy_from_slice(&id.to_be_bytes());
    let binding = RequestBinding::new(
        pc(),
        epoch(),
        OsSession::new(3, 9),
        RequestId::from_bytes(request).unwrap(),
        ChallengeNonce::from_bytes([5; 32]).unwrap(),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(1_000 * MILLI).unwrap(),
    );
    verified(PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(0),
        content,
    })
}

fn pending(id: u64, resolution: Option<RequestResolution>) -> PendingOutcome {
    let mut inbox = PhoneInbox::new(NotificationPolicy::default(), CapacityLimits::default());
    let event = opened(id);
    let mut correlation = source();
    inbox.receive_opened(&event, &mut correlation, clock(0));
    if let Some(outcome) = resolution {
        let PcEvent::Opened {
            binding, issued_at, ..
        } = event.event()
        else {
            panic!("opened fixture")
        };
        let resolution = verified(PcEvent::Resolved {
            binding: *binding,
            issued_at: *issued_at,
            outcome,
        });
        inbox.resolve_pc(&resolution, &mut correlation, clock(1));
    } else {
        inbox.poll(clock(1_000));
    }
    assert_eq!(inbox.pending_outcomes().len(), 1);
    inbox.pending_outcomes()[0]
}

#[test]
fn terminal_outcome_roundtrips_without_changing_its_first_recorded_time() {
    let pending = pending(1, Some(RequestResolution::Cancelled));
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    assert!(matches!(
        history.record_pending(&pending, timestamp(1_000)).unwrap(),
        HistoryInsert::Inserted(_)
    ));
    let mut restored = OutcomeHistory::from_bytes(&history.to_bytes().unwrap()).unwrap();
    assert_eq!(
        restored.record_pending(&pending, timestamp(2_000)).unwrap(),
        HistoryInsert::AlreadyRecorded
    );
    assert_eq!(restored.records().len(), 1);
    let record = restored.records()[0];
    assert_eq!(record.delivery_id(), pending.delivery_id().as_bytes());
    assert_eq!(record.timestamp(), timestamp(1_000));
    assert_eq!(record.outcome(), RequestOutcome::CancelledByPc);
}

#[test]
fn all_terminal_kinds_preserve_the_producers_coarse_meaning() {
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    for (index, (resolution, expected)) in [
        (
            Some(RequestResolution::Cancelled),
            RequestOutcome::CancelledByPc,
        ),
        (
            Some(RequestResolution::Expired),
            RequestOutcome::ExpiredByPc,
        ),
        (None, RequestOutcome::ExpiredLocally),
        (
            Some(RequestResolution::Approved),
            RequestOutcome::CompletedByPc,
        ),
        (
            Some(RequestResolution::Denied),
            RequestOutcome::CompletedByPc,
        ),
        (
            Some(RequestResolution::Failed),
            RequestOutcome::CompletedByPc,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let row = pending(index as u64 + 1, resolution);
        history
            .record_pending(&row, timestamp(100 + index as u64))
            .unwrap();
        assert_eq!(history.records()[index].outcome(), expected);
    }
    let restored = OutcomeHistory::from_bytes(&history.to_bytes().unwrap()).unwrap();
    assert_eq!(restored, history);
    assert_eq!(restored.records().len(), 6);
}

#[test]
fn backward_native_time_keeps_actual_timestamps_and_insertion_order_count_bounds() {
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::new(3, 100).unwrap());
    let rows: Vec<_> = (1..=4).map(|id| pending(id, None)).collect();
    for (row, now) in rows.iter().zip([1_000, 900, 850, 840]) {
        history.record_pending(row, timestamp(now)).unwrap();
    }
    // Oldest insertion (1_000), not the oldest timestamp (840), was evicted.
    assert_eq!(
        history
            .records()
            .iter()
            .map(|row| row.timestamp().get())
            .collect::<Vec<_>>(),
        vec![900, 850, 840]
    );
    assert_eq!(
        history.records()[0].delivery_id(),
        rows[1].delivery_id().as_bytes()
    );
    assert_eq!(history.prune(timestamp(800)).expired_records, 0);
    // Equality at 100 ms is retained; only 840 is strictly too old here.
    assert_eq!(
        history.prune(timestamp(950)),
        HistoryPruneReport {
            expired_records: 1,
            capacity_records: 0,
            remaining_records: 2,
        }
    );
    let before = history.to_bytes().unwrap();
    assert_eq!(history.prune(timestamp(800)).remaining_records, 2);
    assert_eq!(history.to_bytes().unwrap(), before);
}

#[test]
fn retained_duplicate_never_refreshes_reorders_or_prunes_other_rows() {
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::new(3, 100).unwrap());
    let first = pending(1, None);
    let second = pending(2, None);
    history.record_pending(&first, timestamp(100)).unwrap();
    history.record_pending(&second, timestamp(120)).unwrap();
    let before = history.to_bytes().unwrap();
    for now in [0, 1_000_000] {
        assert_eq!(
            history.record_pending(&first, timestamp(now)).unwrap(),
            HistoryInsert::AlreadyRecorded
        );
        assert_eq!(history.to_bytes().unwrap(), before);
    }
}

#[test]
fn retained_id_with_a_conflicting_loaded_outcome_fails_before_any_mutation() {
    let first = pending(1, Some(RequestResolution::Cancelled));
    let second = pending(2, Some(RequestResolution::Cancelled));
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::new(3, 100).unwrap());
    history.record_pending(&first, timestamp(100)).unwrap();
    history.record_pending(&second, timestamp(120)).unwrap();
    let mut bytes = history.to_bytes().unwrap();
    // A projection stores no binding and cannot authenticate an ID/outcome pair.
    // A structurally valid conflicting stored tag must still reject a real retry.
    bytes[HEADER_BYTES + ROW_BYTES - 1] = 2;
    let mut conflicting = OutcomeHistory::from_bytes(&bytes).unwrap();
    assert_eq!(
        conflicting.record_pending(&first, timestamp(1_000_000)),
        Err(OutcomeHistoryError::OutcomeConflict)
    );
    assert_eq!(conflicting.to_bytes().unwrap(), bytes);
}

#[test]
fn age_cutoff_saturates_and_accepts_the_entire_bounded_native_timestamp_range() {
    let first = pending(1, None);
    let second = pending(2, None);
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::new(3, 100).unwrap());
    history.record_pending(&first, timestamp(0)).unwrap();
    assert_eq!(history.prune(timestamp(100)).expired_records, 0);
    assert_eq!(history.prune(timestamp(101)).expired_records, 1);
    history
        .record_pending(&first, timestamp(MAX_UNIX_MILLIS - 101))
        .unwrap();
    history
        .record_pending(&second, timestamp(MAX_UNIX_MILLIS - 100))
        .unwrap();
    assert_eq!(
        history.prune(timestamp(MAX_UNIX_MILLIS)),
        HistoryPruneReport {
            expired_records: 1,
            capacity_records: 0,
            remaining_records: 1,
        }
    );
    assert_eq!(
        history.records()[0].timestamp(),
        timestamp(MAX_UNIX_MILLIS - 100)
    );
}

#[test]
fn clear_and_prune_do_not_touch_producer_outcomes_or_replay_guards() {
    let mut inbox = PhoneInbox::with_phone_boot(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        PhoneBootId::from_native_boot_count(7).unwrap(),
    );
    let event = opened(1);
    inbox.receive_opened(&event, &mut source(), clock(0));
    inbox.poll(clock(1_000));
    let pending = inbox.pending_outcomes()[0];
    let before = inbox.checkpoint().unwrap().to_bytes().unwrap();
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::new(3, 100).unwrap());
    history.record_pending(&pending, timestamp(100)).unwrap();
    assert_eq!(history.clear(), 1);
    assert_eq!(inbox.checkpoint().unwrap().to_bytes().unwrap(), before);
    // Deliberately show the model's boundary: it can reinsert a cleared ID.
    assert!(matches!(
        history.record_pending(&pending, timestamp(200)).unwrap(),
        HistoryInsert::Inserted(_)
    ));
    assert_eq!(history.prune(timestamp(301)).expired_records, 1);
    assert_eq!(inbox.checkpoint().unwrap().to_bytes().unwrap(), before);
    assert!(matches!(
        history.record_pending(&pending, timestamp(302)).unwrap(),
        HistoryInsert::Inserted(_)
    ));
    // This in-memory ACK is only a synthetic consumer. The durable owner must
    // commit ACK+history together; this test is not evidence of such a commit.
    assert_eq!(
        inbox.acknowledge_outcome(pending.delivery_id()),
        OutcomeAcknowledgment::Removed
    );
    let retry = inbox.receive_opened(&event, &mut source(), clock(1_000));
    assert!(retry.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert!(inbox.pending_outcomes().is_empty());
}

#[test]
fn off_hours_drop_has_no_pending_outcome_and_creates_no_history() {
    let mut inbox = PhoneInbox::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        CapacityLimits::default(),
    );
    let update = inbox.receive_opened(&opened(1), &mut source(), clock(0));
    assert!(update.effects().iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert!(inbox.pending_outcomes().is_empty());
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    for row in inbox.pending_outcomes() {
        history.record_pending(row, timestamp(100)).unwrap();
    }
    assert!(history.records().is_empty());
    assert_eq!(history.to_bytes().unwrap().len(), HEADER_BYTES);
}

fn one_record_bytes() -> Vec<u8> {
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    history
        .record_pending(&pending(1, None), timestamp(100))
        .unwrap();
    history.to_bytes().unwrap()
}

#[test]
fn codec_rejects_truncation_trailing_data_bad_magic_and_hard_oversize() {
    let bytes = one_record_bytes();
    for end in 0..bytes.len() {
        assert!(
            OutcomeHistory::from_bytes(&bytes[..end]).is_err(),
            "truncated length {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        OutcomeHistory::from_bytes(&trailing),
        Err(OutcomeHistoryError::MalformedEncoding)
    );
    let mut bad_magic = bytes;
    bad_magic[0] ^= 1;
    assert_eq!(
        OutcomeHistory::from_bytes(&bad_magic),
        Err(OutcomeHistoryError::MalformedEncoding)
    );
    assert_eq!(
        OutcomeHistory::from_bytes(&vec![0; MAX_OUTCOME_HISTORY_BYTES + 1]),
        Err(OutcomeHistoryError::TooLarge)
    );
}

#[test]
fn codec_rejects_unknown_versions_tags_and_out_of_range_timestamps() {
    let bytes = one_record_bytes();
    for version in [0_u16, 2, u16::MAX] {
        let mut invalid = bytes.clone();
        invalid[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            OutcomeHistory::from_bytes(&invalid),
            Err(OutcomeHistoryError::UnsupportedVersion)
        );
    }
    for tag in [0, 5, u8::MAX] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES + ROW_BYTES - 1] = tag;
        assert_eq!(
            OutcomeHistory::from_bytes(&invalid),
            Err(OutcomeHistoryError::MalformedEncoding)
        );
    }
    for time in [MAX_UNIX_MILLIS + 1, u64::MAX] {
        let mut invalid = bytes.clone();
        invalid[HEADER_BYTES + 32..HEADER_BYTES + 40].copy_from_slice(&time.to_be_bytes());
        assert_eq!(
            OutcomeHistory::from_bytes(&invalid),
            Err(OutcomeHistoryError::MalformedEncoding)
        );
    }
}

#[test]
fn codec_rejects_invalid_limits_and_declared_excess_count_before_row_allocation() {
    let bytes = OutcomeHistory::new(OutcomeHistoryLimits::default())
        .to_bytes()
        .unwrap();
    for count in [0_usize, 513, usize::MAX] {
        assert_eq!(
            OutcomeHistoryLimits::new(count, 100),
            Err(OutcomeHistoryError::InvalidLimits)
        );
    }
    for count in [0_u16, 513, u16::MAX] {
        let mut invalid = bytes.clone();
        invalid[10..12].copy_from_slice(&count.to_be_bytes());
        assert_eq!(
            OutcomeHistory::from_bytes(&invalid),
            Err(OutcomeHistoryError::InvalidLimits)
        );
    }
    for age in [0, MAX_RETENTION_MS + 1, u64::MAX] {
        assert_eq!(
            OutcomeHistoryLimits::new(1, age),
            Err(OutcomeHistoryError::InvalidLimits)
        );
        let mut invalid = bytes.clone();
        invalid[12..20].copy_from_slice(&age.to_be_bytes());
        assert_eq!(
            OutcomeHistory::from_bytes(&invalid),
            Err(OutcomeHistoryError::InvalidLimits)
        );
    }
    let mut excessive = bytes.clone();
    excessive[20..22].copy_from_slice(&513_u16.to_be_bytes());
    assert_eq!(
        OutcomeHistory::from_bytes(&excessive),
        Err(OutcomeHistoryError::TooManyRecords)
    );
    let mut configured = bytes;
    configured[10..12].copy_from_slice(&1_u16.to_be_bytes());
    configured[20..22].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        OutcomeHistory::from_bytes(&configured),
        Err(OutcomeHistoryError::TooManyRecords)
    );
}

#[test]
fn codec_rejects_every_duplicate_id_including_identical_and_conflicting_rows() {
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    history
        .record_pending(&pending(1, None), timestamp(100))
        .unwrap();
    history
        .record_pending(&pending(2, None), timestamp(200))
        .unwrap();
    let bytes = history.to_bytes().unwrap();
    for tag in [1, 3] {
        let mut duplicate = bytes.clone();
        duplicate[HEADER_BYTES + ROW_BYTES..HEADER_BYTES + 2 * ROW_BYTES]
            .copy_from_slice(&bytes[HEADER_BYTES..HEADER_BYTES + ROW_BYTES]);
        duplicate[HEADER_BYTES + 2 * ROW_BYTES - 1] = tag;
        assert_eq!(
            OutcomeHistory::from_bytes(&duplicate),
            Err(OutcomeHistoryError::DuplicateDeliveryId)
        );
    }
}

#[test]
fn maximum_projection_has_the_exact_fixed_budget_and_evicts_only_oldest_insertion() {
    // These are synthetic persisted projection IDs, NOT valid enrolled requests
    // or fabricated PendingOutcome values. The codec intentionally knows no key.
    let limits = OutcomeHistoryLimits::default();
    let mut bytes = OutcomeHistory::new(limits).to_bytes().unwrap();
    bytes[20..22].copy_from_slice(&(MAX_OUTCOME_HISTORY_RECORDS as u16).to_be_bytes());
    for id in 1..=MAX_OUTCOME_HISTORY_RECORDS {
        let mut identity = [0; 32];
        identity[..8].copy_from_slice(&(id as u64).to_be_bytes());
        bytes.extend_from_slice(&identity);
        bytes.extend_from_slice(&(1_000 + id as u64).to_be_bytes());
        bytes.push(1 + (id % 4) as u8);
    }
    assert_eq!(bytes.len(), MAX_OUTCOME_HISTORY_BYTES);
    assert_eq!(
        MAX_OUTCOME_HISTORY_BYTES,
        HEADER_BYTES + ROW_BYTES * MAX_OUTCOME_HISTORY_RECORDS
    );
    let mut history = OutcomeHistory::from_bytes(&bytes).unwrap();
    assert_eq!(history.limits(), limits);
    assert_eq!(history.to_bytes().unwrap(), bytes);
    assert_eq!(history.clone(), history);
    let former_second = history.records()[1];
    assert_eq!(
        history
            .record_pending(&pending(900, None), timestamp(10_000))
            .unwrap(),
        HistoryInsert::Inserted(HistoryPruneReport {
            expired_records: 0,
            capacity_records: 1,
            remaining_records: MAX_OUTCOME_HISTORY_RECORDS,
        })
    );
    assert_eq!(history.records()[0], former_second);
    assert_eq!(history.to_bytes().unwrap().len(), MAX_OUTCOME_HISTORY_BYTES);
}

#[test]
fn codec_preserves_valid_custom_limits_and_backward_timestamp_order_without_pruning() {
    let limits = OutcomeHistoryLimits::new(2, MAX_RETENTION_MS).unwrap();
    let mut history = OutcomeHistory::new(limits);
    history
        .record_pending(&pending(1, None), timestamp(MAX_UNIX_MILLIS))
        .unwrap();
    history
        .record_pending(&pending(2, None), timestamp(0))
        .unwrap();
    let restored = OutcomeHistory::from_bytes(&history.to_bytes().unwrap()).unwrap();
    assert_eq!(restored.limits(), limits);
    assert_eq!(restored.records().len(), 2);
    assert_eq!(
        restored.records()[0].timestamp(),
        timestamp(MAX_UNIX_MILLIS)
    );
    assert_eq!(restored.records()[1].timestamp(), timestamp(0));
}

#[test]
fn state_debug_and_encoding_do_not_retain_request_body_or_print_ids_and_times() {
    let pending = pending(1, Some(RequestResolution::Cancelled));
    let mut history = OutcomeHistory::new(OutcomeHistoryLimits::default());
    history
        .record_pending(&pending, timestamp(1_234_567_890_123))
        .unwrap();
    let debug = format!("{history:?} {:?}", history.records()[0]);
    assert!(!debug.contains(&format!("{:?}", pending.delivery_id().as_bytes())));
    assert!(!debug.contains("1234567890123"));
    assert!(!debug.contains(BODY_MARKER));
    let bytes = history.to_bytes().unwrap();
    assert!(
        !bytes
            .windows(BODY_MARKER.len())
            .any(|part| part == BODY_MARKER.as_bytes())
    );
    assert_eq!(bytes.len(), HEADER_BYTES + ROW_BYTES);
}
