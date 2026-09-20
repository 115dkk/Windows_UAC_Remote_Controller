use std::fs;
use std::path::Path;

use activity_journal::{
    ActivityEvent, ActivityRecord, ConnectionOutcome, Decision, FailureKind, FileTarget,
    IoOperation, Journal, JournalError, Limits, LimitsError, MAX_FILE_BYTES, MAX_LINE_BYTES,
    MAX_RECORDS, MAX_RETENTION_MS, MAX_UNIX_MILLIS, MIN_LINE_BYTES, RequestOutcome, ServiceOutcome,
    UnixMillis,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const CURRENT: &str = "activity.jsonl";
const STAGING: &str = "activity.staging";

fn private_directory() -> TempDir {
    // tempfile exclusively owns this unique directory and its scoped cleanup.
    // Tests never recursively remove a computed user-supplied path.
    tempfile::Builder::new()
        .prefix("activity-journal-test-")
        .tempdir()
        .expect("private test directory")
}

fn timestamp(value: u64) -> UnixMillis {
    UnixMillis::new(value).expect("synthetic trusted timestamp")
}

fn limits(count: usize, bytes: usize, age: u64) -> Limits {
    Limits::new(count, bytes, MIN_LINE_BYTES, age).expect("test limits")
}

fn standard_limits() -> Limits {
    limits(16, 8_192, 1_000)
}

fn event() -> ActivityEvent {
    ActivityEvent::Service(ServiceOutcome::Started)
}

fn header(time: u64) -> Value {
    json!({"format_version": 1, "last_observed_unix_ms": time})
}

fn record(time: u64) -> Value {
    json!({"timestamp_unix_ms": time, "event": event()})
}

fn fixture_bytes(header: Value, records: &[Value]) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&header).expect("serialize fixture header");
    bytes.push(b'\n');
    for record in records {
        bytes.extend_from_slice(&serde_json::to_vec(record).expect("serialize fixture record"));
        bytes.push(b'\n');
    }
    bytes
}

fn install_fixture(directory: &Path, bytes: &[u8]) {
    fs::write(directory.join(CURRENT), bytes).expect("write synthetic fixture");
}

fn stored_bytes(directory: &Path) -> Vec<u8> {
    fs::read(directory.join(CURRENT)).expect("read fixture current file")
}

fn retained_times(records: &[ActivityRecord]) -> Vec<u64> {
    records
        .iter()
        .map(|record| record.timestamp().get())
        .collect()
}

#[test]
fn persists_all_event_categories_and_reopens() {
    let directory = private_directory();
    let events = [
        ActivityEvent::Connection(ConnectionOutcome::PairedDeviceConnected),
        ActivityEvent::Service(ServiceOutcome::Started),
        ActivityEvent::Failure(FailureKind::ReplayRejected),
        ActivityEvent::Request(RequestOutcome::PhoneDecisionVerified {
            decision: Decision::Approve,
        }),
        ActivityEvent::Request(RequestOutcome::DecisionSentToWindows {
            decision: Decision::Approve,
        }),
        ActivityEvent::Request(RequestOutcome::WindowsApplied {
            decision: Decision::Approve,
        }),
    ];
    {
        let mut journal = Journal::open(directory.path(), standard_limits(), timestamp(100))
            .expect("open journal");
        for (index, event) in events.iter().copied().enumerate() {
            journal
                .append(timestamp(100 + index as u64), event)
                .expect("append event");
        }
    }
    let mut reopened =
        Journal::open(directory.path(), standard_limits(), timestamp(106)).expect("reopen journal");
    let actual = reopened.recent(timestamp(106), 100).expect("recent events");
    assert_eq!(
        actual
            .iter()
            .map(|record| record.event())
            .collect::<Vec<_>>(),
        events.into_iter().rev().collect::<Vec<_>>()
    );
    assert_eq!(retained_times(&actual), vec![105, 104, 103, 102, 101, 100]);
    assert!(!directory.path().join(STAGING).exists());
}

#[test]
fn every_fixed_event_fits_the_minimum_line_budget_at_the_largest_timestamp() {
    let directory = private_directory();
    let config = limits(100, 65_536, MAX_RETENTION_MS);
    let largest = timestamp(MAX_UNIX_MILLIS);
    let mut journal =
        Journal::open(directory.path(), config, largest).expect("open at upper time bound");
    let mut events = vec![
        ActivityEvent::Connection(ConnectionOutcome::PairedDeviceConnected),
        ActivityEvent::Connection(ConnectionOutcome::PairedDeviceDisconnected),
        ActivityEvent::Connection(ConnectionOutcome::RelayConnected),
        ActivityEvent::Connection(ConnectionOutcome::RelayDisconnected),
        ActivityEvent::Service(ServiceOutcome::Started),
        ActivityEvent::Service(ServiceOutcome::Stopping),
        ActivityEvent::Service(ServiceOutcome::RecoveryRequired),
        ActivityEvent::Failure(FailureKind::AuthenticationRejected),
        ActivityEvent::Failure(FailureKind::MalformedProtocolMessage),
        ActivityEvent::Failure(FailureKind::ReplayRejected),
        ActivityEvent::Failure(FailureKind::TransportUnavailable),
        ActivityEvent::Failure(FailureKind::PlatformUnavailable),
        ActivityEvent::Failure(FailureKind::RequestValidationFailed),
        ActivityEvent::Failure(FailureKind::DeliveryFailed),
        ActivityEvent::Request(RequestOutcome::Observed),
        ActivityEvent::Request(RequestOutcome::NotificationSent),
        ActivityEvent::Request(RequestOutcome::WindowsRejected),
        ActivityEvent::Request(RequestOutcome::WindowsOutcomeUnknown),
        ActivityEvent::Request(RequestOutcome::Expired),
        ActivityEvent::Request(RequestOutcome::Cancelled),
    ];
    for decision in [Decision::Approve, Decision::Deny] {
        events.extend([
            ActivityEvent::Request(RequestOutcome::PhoneDecisionVerified { decision }),
            ActivityEvent::Request(RequestOutcome::DecisionSentToWindows { decision }),
            ActivityEvent::Request(RequestOutcome::WindowsApplied { decision }),
        ]);
    }
    for event in events.iter().copied() {
        journal
            .append(largest, event)
            .expect("schema fits minimum line limit");
    }
    assert_eq!(
        journal.recent(largest, usize::MAX).expect("read all").len(),
        events.len()
    );
    assert!(
        stored_bytes(directory.path())
            .split(|byte| *byte == b'\n')
            .all(|line| line.len() <= MIN_LINE_BYTES)
    );
}

#[test]
fn exact_age_boundary_survives_and_the_next_millisecond_expires() {
    let directory = private_directory();
    let config = limits(16, 8_192, 100);
    let mut journal = Journal::open(directory.path(), config, timestamp(100)).expect("open");
    journal
        .append(timestamp(100), event())
        .expect("append older");
    journal
        .append(timestamp(200), event())
        .expect("append newer");
    let boundary = journal.purge(timestamp(200)).expect("purge at boundary");
    assert_eq!(boundary.expired_records, 0);
    assert_eq!(boundary.remaining_records, 2);
    let after = journal.purge(timestamp(201)).expect("purge past boundary");
    assert_eq!(after.expired_records, 1);
    assert_eq!(after.remaining_records, 1);
    assert_eq!(
        retained_times(&journal.recent(timestamp(201), 20).expect("read")),
        vec![200]
    );
}

#[test]
fn open_enforces_age_retention_and_persists_the_purge() {
    let directory = private_directory();
    let config = limits(16, 8_192, 100);
    {
        let mut journal = Journal::open(directory.path(), config, timestamp(100)).expect("open");
        journal.append(timestamp(100), event()).expect("append");
    }
    {
        let mut boundary = Journal::open(directory.path(), config, timestamp(200)).expect("open");
        assert_eq!(boundary.recent(timestamp(200), 10).expect("read").len(), 1);
    }
    {
        let mut expired = Journal::open(directory.path(), config, timestamp(201)).expect("open");
        assert!(expired.recent(timestamp(201), 10).expect("read").is_empty());
    }
    let bytes = stored_bytes(directory.path());
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
}

#[test]
fn append_and_recent_both_enforce_age_without_an_explicit_purge() {
    let directory = private_directory();
    let config = limits(16, 8_192, 100);
    let mut journal = Journal::open(directory.path(), config, timestamp(0)).expect("open");
    journal.append(timestamp(0), event()).expect("append first");
    let report = journal
        .append(timestamp(101), event())
        .expect("append next");
    assert_eq!(report.expired_records, 1);
    assert_eq!(report.remaining_records, 1);
    assert!(journal.recent(timestamp(202), 10).expect("read").is_empty());
}

#[test]
fn count_bound_keeps_only_the_newest_records() {
    let directory = private_directory();
    let config = limits(3, 8_192, 1_000);
    let mut journal = Journal::open(directory.path(), config, timestamp(0)).expect("open");
    for value in 0..10 {
        let report = journal.append(timestamp(value), event()).expect("append");
        assert!(report.remaining_records <= 3);
        assert_eq!(report.capacity_records, usize::from(value >= 3));
    }
    assert_eq!(
        retained_times(&journal.recent(timestamp(9), usize::MAX).expect("read")),
        vec![9, 8, 7]
    );
    assert_eq!(
        stored_bytes(directory.path())
            .iter()
            .filter(|byte| **byte == b'\n')
            .count(),
        4
    );
}

#[test]
fn byte_bound_includes_header_and_newlines_and_evicts_oldest_records() {
    let directory = private_directory();
    let config = limits(100, 2 * (MIN_LINE_BYTES + 1), 1_000);
    let mut journal = Journal::open(directory.path(), config, timestamp(0)).expect("open");
    let mut evicted = 0;
    for value in 0..20 {
        let report = journal
            .append(
                timestamp(value),
                ActivityEvent::Request(RequestOutcome::DecisionSentToWindows {
                    decision: Decision::Approve,
                }),
            )
            .expect("append bounded event");
        evicted += report.capacity_records;
        let bytes = stored_bytes(directory.path());
        assert!(bytes.len() <= config.max_file_bytes());
        assert!(
            bytes
                .split(|byte| *byte == b'\n')
                .all(|line| line.len() <= config.max_line_bytes())
        );
    }
    assert!(evicted > 0);
    let records = journal.recent(timestamp(19), usize::MAX).expect("read");
    assert!(!records.is_empty());
    assert!(records.len() < 20);
    assert_eq!(records[0].timestamp(), timestamp(19));
    let times = retained_times(&records);
    assert!(times.windows(2).all(|pair| pair[0] == pair[1] + 1));
    drop(journal);
    Journal::open(directory.path(), config, timestamp(19)).expect("reopen bounded file");
}

#[test]
fn recent_respects_zero_small_and_extreme_requested_limits() {
    let directory = private_directory();
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(100)).expect("open");
    for value in 100..103 {
        journal.append(timestamp(value), event()).expect("append");
    }
    assert!(
        journal
            .recent(timestamp(102), 0)
            .expect("zero read")
            .is_empty()
    );
    assert_eq!(
        retained_times(&journal.recent(timestamp(102), 2).expect("small read")),
        vec![102, 101]
    );
    assert_eq!(
        journal
            .recent(timestamp(102), usize::MAX)
            .expect("bounded read")
            .len(),
        3
    );
}

#[test]
fn clear_is_explicit_and_resets_clock_baseline() {
    let directory = private_directory();
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(1_000)).expect("open");
    journal.append(timestamp(1_000), event()).expect("append");
    journal.clear(timestamp(1)).expect("explicit clear");
    assert!(journal.recent(timestamp(1), 10).expect("read").is_empty());
    journal
        .append(timestamp(2), event())
        .expect("append after explicit baseline reset");
    drop(journal);
    let mut reopened =
        Journal::open(directory.path(), standard_limits(), timestamp(2)).expect("reopen");
    assert_eq!(
        retained_times(&reopened.recent(timestamp(2), 10).expect("read")),
        vec![2]
    );
}

#[test]
fn writer_lock_is_exclusive_and_released_on_drop() {
    let directory = private_directory();
    let first =
        Journal::open(directory.path(), standard_limits(), timestamp(0)).expect("first owner");
    assert!(matches!(
        Journal::open(directory.path(), standard_limits(), timestamp(0)),
        Err(JournalError::WriterLocked)
    ));
    assert!(matches!(
        Journal::clear_storage(directory.path(), standard_limits(), timestamp(0)),
        Err(JournalError::WriterLocked)
    ));
    assert!(matches!(
        Journal::discard_staging(directory.path()),
        Err(JournalError::WriterLocked)
    ));
    drop(first);
    Journal::open(directory.path(), standard_limits(), timestamp(0)).expect("lock released");
    assert!(directory.path().join("journal.lock").is_file());
}

#[test]
fn failed_open_does_not_leak_the_writer_lock() {
    let directory = private_directory();
    install_fixture(directory.path(), b"malformed synthetic file\n");
    assert!(matches!(
        Journal::open(directory.path(), standard_limits(), timestamp(0)),
        Err(JournalError::CorruptStorage)
    ));
    Journal::clear_storage(directory.path(), standard_limits(), timestamp(0))
        .expect("explicit recovery can acquire released lock");
}

#[test]
fn config_rejects_every_unsupported_bound() {
    assert_eq!(Limits::new(0, 8_192, 256, 1), Err(LimitsError::RecordCount));
    assert_eq!(
        Limits::new(MAX_RECORDS + 1, 8_192, 256, 1),
        Err(LimitsError::RecordCount)
    );
    assert_eq!(
        Limits::new(1, 8_192, MIN_LINE_BYTES - 1, 1),
        Err(LimitsError::LineBytes)
    );
    assert_eq!(
        Limits::new(1, 8_192, MAX_LINE_BYTES + 1, 1),
        Err(LimitsError::LineBytes)
    );
    assert_eq!(Limits::new(1, 513, 256, 1), Err(LimitsError::FileBytes));
    assert_eq!(
        Limits::new(1, MAX_FILE_BYTES + 1, 256, 1),
        Err(LimitsError::FileBytes)
    );
    assert_eq!(Limits::new(1, 8_192, 256, 0), Err(LimitsError::Age));
    assert_eq!(
        Limits::new(1, 8_192, 256, MAX_RETENTION_MS + 1),
        Err(LimitsError::Age)
    );
    assert_eq!(
        Limits::new(1, 8_192, usize::MAX, 1),
        Err(LimitsError::LineBytes)
    );
    let default = Limits::default();
    assert_eq!(
        Limits::new(
            default.max_records(),
            default.max_file_bytes(),
            default.max_line_bytes(),
            default.max_age_ms()
        ),
        Ok(default)
    );
}

#[test]
fn config_and_timestamp_invariants_also_apply_to_deserialization() {
    assert!(UnixMillis::new(MAX_UNIX_MILLIS + 1).is_err());
    assert!(serde_json::from_value::<UnixMillis>(json!(MAX_UNIX_MILLIS + 1)).is_err());
    assert_eq!(
        serde_json::from_value::<UnixMillis>(json!(0)).expect("epoch"),
        timestamp(0)
    );
    assert_eq!(
        serde_json::from_value::<UnixMillis>(json!(MAX_UNIX_MILLIS)).expect("upper bound"),
        timestamp(MAX_UNIX_MILLIS)
    );
    let mut config = serde_json::to_value(standard_limits()).expect("config JSON");
    config["max_records"] = json!(0);
    assert!(serde_json::from_value::<Limits>(config).is_err());
    let mut config = serde_json::to_value(standard_limits()).expect("config JSON");
    config["arbitrary_payload"] = json!("synthetic-marker");
    assert!(serde_json::from_value::<Limits>(config).is_err());
    assert_eq!(
        serde_json::from_value::<Limits>(
            serde_json::to_value(standard_limits()).expect("serialize")
        )
        .expect("round trip"),
        standard_limits()
    );
}

#[test]
fn corrupt_and_partial_files_are_not_truncated() {
    let cases = [
        Vec::new(),
        b"not JSON\n".to_vec(),
        b"\n".to_vec(),
        serde_json::to_vec(&header(100)).expect("missing-newline fixture"),
        [fixture_bytes(header(100), &[]), b"partial record".to_vec()].concat(),
        [fixture_bytes(header(100), &[]), b"\n".to_vec()].concat(),
    ];
    for bytes in cases {
        let directory = private_directory();
        install_fixture(directory.path(), &bytes);
        assert!(matches!(
            Journal::open(directory.path(), standard_limits(), timestamp(100)),
            Err(JournalError::CorruptStorage)
        ));
        assert_eq!(stored_bytes(directory.path()), bytes);
        assert!(!directory.path().join(STAGING).exists());
    }
}

#[test]
fn oversized_file_is_rejected_without_modifying_it() {
    let directory = private_directory();
    let config = limits(16, 514, 1_000);
    let bytes = vec![b' '; config.max_file_bytes() + 1];
    install_fixture(directory.path(), &bytes);
    assert!(matches!(
        Journal::open(directory.path(), config, timestamp(0)),
        Err(JournalError::StorageTooLarge)
    ));
    assert_eq!(stored_bytes(directory.path()), bytes);
    let mut recovered = Journal::clear_storage(directory.path(), config, timestamp(0))
        .expect("explicit oversized-storage clear");
    assert!(
        recovered
            .recent(timestamp(0), 1)
            .expect("empty read")
            .is_empty()
    );
}

#[test]
fn oversized_record_line_is_rejected_without_modifying_it() {
    let directory = private_directory();
    let config = standard_limits();
    let mut oversized_line = serde_json::to_vec(&record(100)).expect("record fixture");
    oversized_line.resize(config.max_line_bytes() + 1, b' ');
    oversized_line.push(b'\n');
    let bytes = [fixture_bytes(header(100), &[]), oversized_line].concat();
    install_fixture(directory.path(), &bytes);
    assert!(matches!(
        Journal::open(directory.path(), config, timestamp(100)),
        Err(JournalError::LineTooLarge)
    ));
    assert_eq!(stored_bytes(directory.path()), bytes);
}

#[test]
fn oversized_header_line_and_excess_record_count_are_rejected() {
    let directory = private_directory();
    let config = standard_limits();
    let mut bytes = serde_json::to_vec(&header(100)).expect("header fixture");
    bytes.resize(config.max_line_bytes() + 1, b' ');
    bytes.push(b'\n');
    install_fixture(directory.path(), &bytes);
    assert!(matches!(
        Journal::open(directory.path(), config, timestamp(100)),
        Err(JournalError::LineTooLarge)
    ));
    assert_eq!(stored_bytes(directory.path()), bytes);
    let bytes = fixture_bytes(header(100), &[record(100), record(100)]);
    install_fixture(directory.path(), &bytes);
    assert!(matches!(
        Journal::open(directory.path(), limits(1, 8_192, 1_000), timestamp(100)),
        Err(JournalError::TooManyRecords)
    ));
    assert_eq!(stored_bytes(directory.path()), bytes);
}

#[test]
fn unknown_fields_versions_events_and_invalid_record_metadata_are_rejected() {
    let mut extra_header = header(100);
    extra_header["extra"] = json!(true);
    let mut extra_record = record(100);
    extra_record["payload"] = json!("synthetic-private-marker");
    let mut extra_event = record(100);
    extra_event["event"]["payload"] = json!("synthetic-private-marker");
    let cases = [
        fixture_bytes(
            json!({"format_version": 2, "last_observed_unix_ms": 100}),
            &[],
        ),
        fixture_bytes(
            json!({"format_version": 1, "last_observed_unix_ms": MAX_UNIX_MILLIS + 1}),
            &[],
        ),
        fixture_bytes(extra_header, &[]),
        fixture_bytes(header(100), &[extra_record]),
        fixture_bytes(header(100), &[extra_event]),
        fixture_bytes(header(100), &[record(MAX_UNIX_MILLIS + 1)]),
        fixture_bytes(header(100), &[record(101)]),
        fixture_bytes(header(100), &[record(100), record(99)]),
        fixture_bytes(
            header(100),
            &[
                json!({"timestamp_unix_ms": 100, "event": {"category": "request", "outcome": {"state": "off_hours_dropped"}}}),
            ],
        ),
        fixture_bytes(
            header(100),
            &[
                json!({"timestamp_unix_ms": 100, "event": {"category": "request", "outcome": {"state": "observed", "payload": "synthetic-private-marker"}}}),
            ],
        ),
        fixture_bytes(
            header(100),
            &[
                json!({"timestamp_unix_ms": 100, "event": {"category": "request", "outcome": {"state": "observed", "detail": "synthetic-private-marker"}}}),
            ],
        ),
        fixture_bytes(
            header(100),
            &[
                json!({"timestamp_unix_ms": 100, "event": {"category": "request", "outcome": {"state": "phone_decision_verified", "detail": {"decision": "approve", "payload": "synthetic-private-marker"}}}}),
            ],
        ),
    ];
    for bytes in cases {
        let directory = private_directory();
        install_fixture(directory.path(), &bytes);
        let error = Journal::open(directory.path(), standard_limits(), timestamp(100))
            .expect_err("reject invalid metadata or unexpected payload");
        assert!(matches!(error, JournalError::CorruptStorage));
        assert!(!format!("{error:?} {error}").contains("synthetic-private-marker"));
        assert_eq!(stored_bytes(directory.path()), bytes);
    }
}

#[test]
fn duplicate_header_metadata_is_rejected() {
    let directory = private_directory();
    let bytes = b"{\"format_version\":1,\"format_version\":1,\"last_observed_unix_ms\":100}\n";
    install_fixture(directory.path(), bytes);
    assert!(matches!(
        Journal::open(directory.path(), standard_limits(), timestamp(100)),
        Err(JournalError::CorruptStorage)
    ));
    assert_eq!(stored_bytes(directory.path()), bytes);
}

#[test]
fn rollback_never_rewinds_retention_or_allows_backdated_append() {
    let directory = private_directory();
    let config = limits(16, 8_192, 100);
    {
        let mut journal = Journal::open(directory.path(), config, timestamp(100)).expect("open");
        journal.append(timestamp(100), event()).expect("first");
        journal.append(timestamp(150), event()).expect("second");
        assert_eq!(
            journal
                .purge(timestamp(201))
                .expect("purge")
                .expired_records,
            1
        );
    }
    let before = stored_bytes(directory.path());
    let mut journal =
        Journal::open(directory.path(), config, timestamp(50)).expect("rollback open");
    assert_eq!(stored_bytes(directory.path()), before);
    assert_eq!(
        retained_times(&journal.recent(timestamp(50), 10).expect("rollback read")),
        vec![150]
    );
    assert!(matches!(
        journal.append(timestamp(200), event()),
        Err(JournalError::ClockRollback)
    ));
    assert_eq!(stored_bytes(directory.path()), before);
    assert_eq!(
        journal
            .purge(timestamp(40))
            .expect("rollback purge")
            .remaining_records,
        1
    );
    journal
        .append(timestamp(201), event())
        .expect("clock catches up");
}

#[test]
fn unused_newer_clock_observation_is_persisted() {
    let directory = private_directory();
    {
        let mut journal =
            Journal::open(directory.path(), standard_limits(), timestamp(10)).expect("open");
        journal
            .recent(timestamp(20), 0)
            .expect("observe newer time without events");
    }
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(10)).expect("rollback reopen");
    assert!(matches!(
        journal.append(timestamp(19), event()),
        Err(JournalError::ClockRollback)
    ));
    journal
        .append(timestamp(20), event())
        .expect("equal high-water timestamp");
}

#[test]
fn crash_staging_requires_explicit_disposal_and_preserves_current() {
    let directory = private_directory();
    {
        let mut journal =
            Journal::open(directory.path(), standard_limits(), timestamp(100)).expect("open");
        journal.append(timestamp(100), event()).expect("append");
    }
    let before = stored_bytes(directory.path());
    fs::write(
        directory.path().join(STAGING),
        b"synthetic incomplete staging",
    )
    .expect("stage fixture");
    assert!(matches!(
        Journal::open(directory.path(), standard_limits(), timestamp(101)),
        Err(JournalError::StagingRecoveryRequired)
    ));
    assert_eq!(stored_bytes(directory.path()), before);
    assert!(directory.path().join(STAGING).is_file());
    Journal::discard_staging(directory.path()).expect("explicit staging disposal");
    assert_eq!(stored_bytes(directory.path()), before);
    assert!(!directory.path().join(STAGING).exists());
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(100)).expect("recover open");
    assert_eq!(journal.recent(timestamp(100), 10).expect("read").len(), 1);
}

#[test]
fn fixed_staging_name_prevents_accumulation_and_blocks_new_mutation() {
    let directory = private_directory();
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(100)).expect("open");
    journal.append(timestamp(100), event()).expect("append");
    let before = stored_bytes(directory.path());
    fs::write(directory.path().join(STAGING), b"synthetic crash remainder").expect("stage fixture");
    for _ in 0..3 {
        assert!(matches!(
            journal.append(timestamp(101), event()),
            Err(JournalError::StagingRecoveryRequired)
        ));
        assert!(matches!(
            journal.purge(timestamp(101)),
            Err(JournalError::StagingRecoveryRequired)
        ));
        assert!(matches!(
            journal.recent(timestamp(101), 10),
            Err(JournalError::StagingRecoveryRequired)
        ));
    }
    assert_eq!(stored_bytes(directory.path()), before);
    let names: Vec<_> = fs::read_dir(directory.path())
        .expect("list private fixture")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(names.len(), 3);
    journal
        .clear(timestamp(101))
        .expect("explicit clear also disposes stage");
    assert!(!directory.path().join(STAGING).exists());
    assert!(journal.recent(timestamp(101), 10).expect("read").is_empty());
}

#[test]
fn clear_and_recovery_preserve_unrelated_files_and_directories() {
    let directory = private_directory();
    fs::write(
        directory.path().join("unrelated.txt"),
        b"synthetic unrelated file",
    )
    .expect("unrelated fixture");
    fs::create_dir(directory.path().join("unrelated-directory")).expect("unrelated directory");
    fs::write(
        directory.path().join("activity.staging.other"),
        b"synthetic unrelated staged name",
    )
    .expect("similar name fixture");
    install_fixture(directory.path(), b"synthetic corrupt current\n");
    fs::write(
        directory.path().join(STAGING),
        b"synthetic incomplete stage",
    )
    .expect("stage fixture");
    let mut journal = Journal::clear_storage(directory.path(), standard_limits(), timestamp(0))
        .expect("explicit clear");
    journal.append(timestamp(1), event()).expect("append");
    journal.clear(timestamp(2)).expect("clear again");
    assert_eq!(
        fs::read(directory.path().join("unrelated.txt")).expect("unrelated retained"),
        b"synthetic unrelated file"
    );
    assert_eq!(
        fs::read(directory.path().join("activity.staging.other")).expect("similar name retained"),
        b"synthetic unrelated staged name"
    );
    assert!(directory.path().join("unrelated-directory").is_dir());
    assert!(directory.path().join("journal.lock").is_file());
}

#[test]
fn corrupt_storage_is_revalidated_before_every_operation() {
    let directory = private_directory();
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(100)).expect("open");
    let corrupt = b"synthetic malformed replacement\n";
    install_fixture(directory.path(), corrupt);
    assert!(matches!(
        journal.append(timestamp(101), event()),
        Err(JournalError::CorruptStorage)
    ));
    assert!(matches!(
        journal.recent(timestamp(101), 10),
        Err(JournalError::CorruptStorage)
    ));
    assert!(matches!(
        journal.purge(timestamp(101)),
        Err(JournalError::CorruptStorage)
    ));
    assert_eq!(stored_bytes(directory.path()), corrupt);
    journal
        .clear(timestamp(101))
        .expect("explicit corruption recovery");
    assert!(
        journal
            .recent(timestamp(101), 10)
            .expect("read empty")
            .is_empty()
    );
}

#[test]
fn missing_current_after_open_is_not_silently_recreated() {
    let directory = private_directory();
    let mut journal =
        Journal::open(directory.path(), standard_limits(), timestamp(0)).expect("open");
    fs::remove_file(directory.path().join(CURRENT)).expect("explicit fixture removal");
    assert!(matches!(
        journal.append(timestamp(0), event()),
        Err(JournalError::MissingStorage)
    ));
    assert!(!directory.path().join(CURRENT).exists());
}

#[test]
fn missing_private_directory_is_not_created_with_implicit_permissions() {
    let directory = private_directory();
    let absent = directory.path().join("not-provisioned");
    assert!(matches!(
        Journal::open(&absent, standard_limits(), timestamp(0)),
        Err(JournalError::Io {
            operation: IoOperation::InspectDirectory,
            ..
        })
    ));
    assert!(!absent.exists());
}

#[test]
fn owned_directories_and_nonempty_lock_are_not_clobbered() {
    let directory = private_directory();
    fs::create_dir(directory.path().join(CURRENT)).expect("directory current fixture");
    assert!(matches!(
        Journal::clear_storage(directory.path(), standard_limits(), timestamp(0)),
        Err(JournalError::UnsafeEntry(FileTarget::Current))
    ));
    assert!(directory.path().join(CURRENT).is_dir());
    let directory = private_directory();
    fs::create_dir(directory.path().join(STAGING)).expect("directory staging fixture");
    assert!(matches!(
        Journal::discard_staging(directory.path()),
        Err(JournalError::UnsafeEntry(FileTarget::Staging))
    ));
    assert!(directory.path().join(STAGING).is_dir());
    let directory = private_directory();
    fs::write(
        directory.path().join("journal.lock"),
        b"synthetic unrelated lock contents",
    )
    .expect("lock fixture");
    assert!(matches!(
        Journal::open(directory.path(), standard_limits(), timestamp(0)),
        Err(JournalError::UnexpectedLockContent)
    ));
    assert_eq!(
        fs::read(directory.path().join("journal.lock")).expect("retained lock"),
        b"synthetic unrelated lock contents"
    );
}

#[test]
fn debug_omits_the_trusted_directory_and_has_no_record_payload() {
    let directory = private_directory();
    let journal = Journal::open(directory.path(), standard_limits(), timestamp(0)).expect("open");
    let debug = format!("{journal:?}");
    assert!(!debug.contains(&directory.path().display().to_string()));
    assert!(!debug.contains("activity-journal-test-"));
    assert!(!debug.contains("timestamp_unix_ms"));
}

#[cfg(unix)]
#[test]
fn symlink_inputs_and_explicit_recovery_never_follow_or_remove_targets() {
    use std::os::unix::fs::symlink;

    let target = private_directory();
    let target_file = target.path().join("unrelated.txt");
    fs::write(&target_file, b"synthetic protected target").expect("target fixture");
    for (name, target_kind) in [
        (CURRENT, FileTarget::Current),
        (STAGING, FileTarget::Staging),
        ("journal.lock", FileTarget::Lock),
    ] {
        let directory = private_directory();
        symlink(&target_file, directory.path().join(name)).expect("safe private fixture symlink");
        assert!(matches!(
            Journal::open(directory.path(), standard_limits(), timestamp(0)),
            Err(JournalError::UnsafeEntry(actual)) if actual == target_kind
        ));
        assert!(matches!(
            Journal::clear_storage(directory.path(), standard_limits(), timestamp(0)),
            Err(JournalError::UnsafeEntry(actual)) if actual == target_kind
        ));
        if name == STAGING {
            assert!(matches!(
                Journal::discard_staging(directory.path()),
                Err(JournalError::UnsafeEntry(FileTarget::Staging))
            ));
        }
        assert_eq!(
            fs::read(&target_file).expect("target retained"),
            b"synthetic protected target"
        );
    }
    let parent = private_directory();
    let link = parent.path().join("linked-directory");
    symlink(target.path(), &link).expect("directory symlink");
    assert!(matches!(
        Journal::open(&link, standard_limits(), timestamp(0)),
        Err(JournalError::UnsafeEntry(FileTarget::Directory))
    ));
}
