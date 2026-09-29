// SPDX-License-Identifier: GPL-2.0-or-later
//! The activity journal is diagnostic history, never authorization state.
//! A torn write after power loss must not keep the service down, so recovery is
//! limited to the journal crate's explicit staging discard and storage clear.
#![forbid(unsafe_code)]

use crate::public_diagnostics::{Event, JournalFault, JournalIoStep, JournalRecovery};
use activity_journal::{Journal, JournalError, Limits, UnixMillis};
use std::path::Path;

pub(crate) fn open(
    directory: &Path,
    limits: Limits,
    now: UnixMillis,
    mut report: impl FnMut(Event),
) -> Result<Journal, JournalFault> {
    let mut staging_discarded = false;
    loop {
        match Journal::open(directory, limits, now) {
            Ok(journal) => return Ok(journal),
            Err(error) => {
                let fault = JournalFault::from(&error);
                match recovery_for(&error, staging_discarded) {
                    Some(JournalRecovery::DiscardedStaging) => {
                        if let Err(error) = Journal::discard_staging(directory) {
                            return Err(report_unusable(&error, &mut report));
                        }
                        report(Event::JournalRecovered {
                            fault,
                            action: JournalRecovery::DiscardedStaging,
                        });
                        staging_discarded = true;
                    }
                    Some(JournalRecovery::Cleared) => {
                        let journal = match Journal::clear_storage(directory, limits, now) {
                            Ok(journal) => journal,
                            Err(error) => return Err(report_unusable(&error, &mut report)),
                        };
                        report(Event::JournalRecovered {
                            fault,
                            action: JournalRecovery::Cleared,
                        });
                        return Ok(journal);
                    }
                    None => return Err(report_unusable(&error, &mut report)),
                }
            }
        }
    }
}

fn recovery_for(error: &JournalError, staging_discarded: bool) -> Option<JournalRecovery> {
    match error {
        JournalError::StagingRecoveryRequired => {
            (!staging_discarded).then_some(JournalRecovery::DiscardedStaging)
        }
        JournalError::CorruptStorage
        | JournalError::StorageTooLarge
        | JournalError::TooManyRecords
        | JournalError::LineTooLarge => Some(JournalRecovery::Cleared),
        JournalError::WriterLocked
        | JournalError::UnexpectedLockContent
        | JournalError::UnsafeEntry(_)
        | JournalError::MissingStorage
        | JournalError::EncodingFailed
        | JournalError::ClockRollback
        | JournalError::Io { .. } => None,
    }
}

fn report_unusable(error: &JournalError, report: &mut impl FnMut(Event)) -> JournalFault {
    let fault = JournalFault::from(error);
    let io_step = match error {
        JournalError::Io { operation, .. } => Some(JournalIoStep::from(*operation)),
        JournalError::WriterLocked
        | JournalError::UnexpectedLockContent
        | JournalError::UnsafeEntry(_)
        | JournalError::StagingRecoveryRequired
        | JournalError::MissingStorage
        | JournalError::CorruptStorage
        | JournalError::StorageTooLarge
        | JournalError::TooManyRecords
        | JournalError::LineTooLarge
        | JournalError::EncodingFailed
        | JournalError::ClockRollback => None,
    };
    report(Event::JournalUnusable { fault, io_step });
    fault
}

#[cfg(test)]
mod tests {
    use super::*;
    use activity_journal::{ActivityEvent, FileTarget, IoOperation, ServiceOutcome};
    use serde_json::{Value, json};
    use std::{fs, io};

    const CURRENT: &str = "activity.jsonl";
    const STAGING: &str = "activity.staging";
    const LOCK: &str = "journal.lock";
    const UNRELATED: &str = "activity.jsonl.bak";
    const UNRELATED_BYTES: &[u8] = b"unrelated diagnostic backup";

    fn timestamp(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("synthetic trusted timestamp")
    }

    fn event() -> ActivityEvent {
        ActivityEvent::Service(ServiceOutcome::Started)
    }

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("service-journal-recovery-test-")
            .tempdir()
            .expect("private test directory")
    }

    fn install_valid_journal(directory: &Path) {
        let mut journal = Journal::open(directory, Limits::default(), timestamp(100))
            .expect("create journal fixture");
        journal
            .append(timestamp(100), event())
            .expect("append journal fixture");
    }

    fn install_unrelated_file(directory: &Path) {
        fs::write(directory.join(UNRELATED), UNRELATED_BYTES).expect("write unrelated fixture");
    }

    fn assert_unrelated_file(directory: &Path) {
        assert_eq!(
            fs::read(directory.join(UNRELATED)).expect("read unrelated fixture"),
            UNRELATED_BYTES
        );
    }

    fn event_values(events: &[Event]) -> Vec<Value> {
        events
            .iter()
            .map(|event| serde_json::to_value(event).expect("serialize diagnostic event"))
            .collect()
    }

    #[test]
    fn healthy_journal_opens_without_a_recovery_event() {
        let directory = private_directory();
        install_valid_journal(directory.path());
        let mut events = Vec::new();

        let mut journal = open(
            directory.path(),
            Limits::default(),
            timestamp(100),
            |event| events.push(event),
        )
        .expect("open healthy journal");

        let recent = journal
            .recent(timestamp(100), 10)
            .expect("read healthy journal");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event(), event());
        assert!(events.is_empty());
    }

    #[test]
    fn leftover_staging_is_discarded_without_losing_current_history() {
        let directory = private_directory();
        install_valid_journal(directory.path());
        install_unrelated_file(directory.path());
        fs::write(directory.path().join(STAGING), b"arbitrary torn bytes")
            .expect("write staging fixture");
        let mut events = Vec::new();

        let mut journal = open(
            directory.path(),
            Limits::default(),
            timestamp(100),
            |event| events.push(event),
        )
        .expect("recover staging remainder");

        let recent = journal
            .recent(timestamp(100), 10)
            .expect("read recovered journal");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event(), event());
        assert!(!directory.path().join(STAGING).exists());
        assert_eq!(
            event_values(&events),
            vec![json!({
                "kind": "journal_recovered",
                "fault": "staging_left",
                "action": "discarded_staging"
            })]
        );
        assert_unrelated_file(directory.path());
    }

    #[test]
    fn corrupt_current_storage_is_cleared() {
        let directory = private_directory();
        install_unrelated_file(directory.path());
        fs::write(directory.path().join(CURRENT), b"{not json\n").expect("write corrupt fixture");
        let mut events = Vec::new();

        let mut journal = open(
            directory.path(),
            Limits::default(),
            timestamp(100),
            |event| events.push(event),
        )
        .expect("clear corrupt journal");

        assert!(
            journal
                .recent(timestamp(100), 10)
                .expect("read cleared journal")
                .is_empty()
        );
        assert_eq!(
            event_values(&events),
            vec![json!({
                "kind": "journal_recovered",
                "fault": "corrupt_storage",
                "action": "cleared"
            })]
        );
        assert_unrelated_file(directory.path());
    }

    #[test]
    fn staging_is_discarded_before_corrupt_current_storage_is_cleared() {
        let directory = private_directory();
        install_unrelated_file(directory.path());
        fs::write(directory.path().join(CURRENT), b"{not json\n").expect("write corrupt fixture");
        fs::write(directory.path().join(STAGING), b"arbitrary torn bytes")
            .expect("write staging fixture");
        let mut events = Vec::new();

        let mut journal = open(
            directory.path(),
            Limits::default(),
            timestamp(100),
            |event| events.push(event),
        )
        .expect("recover staging and corrupt current storage");

        assert!(
            journal
                .recent(timestamp(100), 10)
                .expect("read cleared journal")
                .is_empty()
        );
        assert_eq!(
            event_values(&events),
            vec![
                json!({
                    "kind": "journal_recovered",
                    "fault": "staging_left",
                    "action": "discarded_staging"
                }),
                json!({
                    "kind": "journal_recovered",
                    "fault": "corrupt_storage",
                    "action": "cleared"
                }),
            ]
        );
        assert_unrelated_file(directory.path());
    }

    #[test]
    fn nonempty_lock_is_reported_without_changing_current_storage() {
        let directory = private_directory();
        let current = b"unchanged current bytes";
        fs::write(directory.path().join(CURRENT), current).expect("write current fixture");
        fs::write(directory.path().join(LOCK), b"unexpected lock owner bytes")
            .expect("write lock fixture");
        let mut events = Vec::new();

        let result = open(
            directory.path(),
            Limits::default(),
            timestamp(100),
            |event| events.push(event),
        );

        assert!(matches!(result, Err(JournalFault::UnexpectedLockContent)));
        assert_eq!(
            event_values(&events),
            vec![json!({
                "kind": "journal_unusable",
                "fault": "unexpected_lock_content"
            })]
        );
        assert_eq!(
            fs::read(directory.path().join(CURRENT)).expect("read unchanged current fixture"),
            current
        );
    }

    #[test]
    fn recovery_policy_covers_every_journal_error_for_both_staging_states() {
        let cases: [(
            JournalError,
            Option<JournalRecovery>,
            Option<JournalRecovery>,
        ); 12] = [
            (JournalError::WriterLocked, None, None),
            (JournalError::UnexpectedLockContent, None, None),
            (JournalError::UnsafeEntry(FileTarget::Current), None, None),
            (
                JournalError::StagingRecoveryRequired,
                Some(JournalRecovery::DiscardedStaging),
                None,
            ),
            (JournalError::MissingStorage, None, None),
            (
                JournalError::CorruptStorage,
                Some(JournalRecovery::Cleared),
                Some(JournalRecovery::Cleared),
            ),
            (
                JournalError::StorageTooLarge,
                Some(JournalRecovery::Cleared),
                Some(JournalRecovery::Cleared),
            ),
            (
                JournalError::TooManyRecords,
                Some(JournalRecovery::Cleared),
                Some(JournalRecovery::Cleared),
            ),
            (
                JournalError::LineTooLarge,
                Some(JournalRecovery::Cleared),
                Some(JournalRecovery::Cleared),
            ),
            (JournalError::EncodingFailed, None, None),
            (JournalError::ClockRollback, None, None),
            (
                JournalError::Io {
                    operation: IoOperation::AcquireLock,
                    kind: io::ErrorKind::Other,
                },
                None,
                None,
            ),
        ];

        for (error, before_discard, after_discard) in cases {
            assert_eq!(recovery_for(&error, false), before_discard);
            assert_eq!(recovery_for(&error, true), after_discard);
        }
    }
}
