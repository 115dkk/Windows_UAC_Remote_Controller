// SPDX-License-Identifier: GPL-2.0-or-later
//! Readable diagnostics, never authorization state. Producers supply closed
//! variants/numbers and sanitized listener image basenames only. No request
//! text, identities, keys, command lines or directory paths.
use crate::ProbeSupervisorError;
use activity_journal::ActivityEvent;
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
};
use windows_prompt_probe::supervision::RefusalReason;

pub(crate) const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Event {
    Activity {
        event: ActivityEvent,
    },
    StartupFailure {
        stage: u8,
        code: u32,
    },
    // The activity journal could not be opened as stored (a write torn by a
    // power loss leaves exactly these); the service repaired it and kept starting.
    JournalRecovered {
        fault: JournalFault,
        action: JournalRecovery,
    },
    // The activity journal could not be opened and no recovery applies; the
    // startup_failure row with stage 3 follows.
    JournalUnusable {
        fault: JournalFault,
        #[serde(skip_serializing_if = "Option::is_none")]
        io_step: Option<JournalIoStep>,
    },
    // A post-Ready activity append failed. The service keeps running and rate
    // limits this fixed fault category in the runtime owner.
    JournalAppendFailed {
        fault: JournalFault,
    },
    // An hourly activity purge failed. The service keeps running and rate
    // limits this fixed fault category in the runtime owner.
    JournalPurgeFailed {
        fault: JournalFault,
    },
    StartupGuard {
        phase: u8,
        policy: u8,
        code: u32,
    },
    PromptRefused {
        reason: PromptRefusal,
    },
    // An optional setting read at this fixed startup stage was unusable; the
    // service kept running with that setting's default.
    ConfigurationIgnored {
        stage: u8,
    },
    // Only changes, including recovery. Names pass the listener codec's validator.
    RelayListenerChanged {
        fault: Option<crate::management_protocol::ListenerFault>,
    },
    // The embedded relay's cumulative counters of registrations that evicted a
    // pair or were refused. Written only when a counter moved, at most once a
    // minute. Counts only: no address and no route.
    RelayAbuse {
        evicted_pairs: u64,
        rejected_duplicates: u64,
        rejected_pc_sources: u64,
        rejected_evictions: u64,
    },
    // One embedded relay worker finished. Its report omits the four counters in
    // `relay_abuse`; all fields are aggregate counts with no address or route.
    RelayWorkerStopped {
        outcome: RelayWorkerOutcome,
    },
    // Joined peer workers grouped by a closed cause. Counts accumulated during
    // the reporting interval contain no device or connection identity.
    PeerWorkerExited {
        cause: crate::peer_runtime::PeerExitCause,
        count: u64,
    },
    // A connected phone's routing hints lacked the external address the PC now
    // publishes, so its connection was ended for it to reconnect and ask again.
    HintsRefreshed {
        reason: HintRefresh,
    },
    // The UAC watcher could not start; the service keeps running and retries.
    WatcherStartFailed {
        error: ProbeSupervisorError,
    },
    // Local discovery failed; the service keeps running and retries. No address.
    LanAnnounceFailed {
        code: u32,
    },
    // The worker stopped with an error (or a caught panic) after SCM Ready, at
    // this fixed step. `code` is the SCM diagnostic code; 0 for a panic.
    RuntimeFailure {
        step: u8,
        cause: RuntimeFailureCause,
        panicked: bool,
        code: u32,
    },
    // A signed phone decision was refused before any Windows action. The reason
    // is a closed category with no request, device, key or signature material.
    DecisionRejected {
        reason: DecisionRejectionReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum RelayWorkerOutcome {
    Clean { report: RelayWorkerReport },
    Error { error: RelayWorkerError },
    Panicked,
}

impl From<relay_service::HostedRelayExit> for RelayWorkerOutcome {
    fn from(exit: relay_service::HostedRelayExit) -> Self {
        match exit {
            relay_service::HostedRelayExit::Clean(report) => Self::Clean {
                report: report.into(),
            },
            relay_service::HostedRelayExit::Error(error) => Self::Error {
                error: error.into(),
            },
            relay_service::HostedRelayExit::Panicked => Self::Panicked,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RelayWorkerError {
    AcceptFailed,
    TaskFailed,
    IdentifierExhausted,
    ShutdownIncomplete,
}

impl From<relay_service::RelayError> for RelayWorkerError {
    fn from(error: relay_service::RelayError) -> Self {
        match error {
            relay_service::RelayError::AcceptFailed => Self::AcceptFailed,
            relay_service::RelayError::TaskFailed => Self::TaskFailed,
            relay_service::RelayError::IdentifierExhausted => Self::IdentifierExhausted,
            relay_service::RelayError::ShutdownIncomplete => Self::ShutdownIncomplete,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct RelayWorkerReport {
    pub(crate) accepted: u64,
    pub(crate) accept_failures: u64,
    pub(crate) rejected_capacity: u64,
    pub(crate) rejected_waiting_rooms: u64,
    pub(crate) paired: u64,
    pub(crate) invalid_registrations: u64,
    pub(crate) header_timeouts: u64,
    pub(crate) waiting_timeouts: u64,
    pub(crate) rendezvous_timeouts: u64,
    pub(crate) idle_timeouts: u64,
    pub(crate) absolute_timeouts: u64,
    pub(crate) disconnected: u64,
    pub(crate) io_failures: u64,
    pub(crate) cancelled: u64,
    pub(crate) task_failures: u64,
    pub(crate) peak_connections: usize,
    pub(crate) peak_waiting_rooms: usize,
    pub(crate) remaining_connections: usize,
}

impl From<relay_service::RelayReport> for RelayWorkerReport {
    fn from(report: relay_service::RelayReport) -> Self {
        Self {
            accepted: report.accepted,
            accept_failures: report.accept_failures,
            rejected_capacity: report.rejected_capacity,
            rejected_waiting_rooms: report.rejected_waiting_rooms,
            paired: report.paired,
            invalid_registrations: report.invalid_registrations,
            header_timeouts: report.header_timeouts,
            waiting_timeouts: report.waiting_timeouts,
            rendezvous_timeouts: report.rendezvous_timeouts,
            idle_timeouts: report.idle_timeouts,
            absolute_timeouts: report.absolute_timeouts,
            disconnected: report.disconnected,
            io_failures: report.io_failures,
            cancelled: report.cancelled,
            task_failures: report.task_failures,
            peak_connections: report.peak_connections,
            peak_waiting_rooms: report.peak_waiting_rooms,
            remaining_connections: report.remaining_connections,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeFailureCause {
    Service,
    SessionClosed,
    Registry,
    PeerChanged,
    Identity,
    Clock,
    Capacity,
    Protocol,
    Io,
    Panicked,
    CleanupPending,
    Signing,
    Watcher,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionRejectionReason {
    Clock,
    WrongPc,
    WrongEpoch,
    UnknownOrCompleted,
    Expired,
    BindingMismatch,
    NotEligible,
    EnrollmentChanged,
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalFault {
    /// Another process owns the journal's exclusive writer lock.
    WriterLocked,
    /// The fixed lock file unexpectedly contained data.
    UnexpectedLockContent,
    /// A journal pathname named a link, reparse point or wrong entry type.
    UnsafeEntry,
    /// A prior write left the fixed staging file behind.
    StagingLeft,
    /// Current storage disappeared after the journal opened.
    MissingStorage,
    /// Current storage was malformed or used unsupported metadata.
    CorruptStorage,
    /// Current storage exceeded its configured byte limit.
    StorageTooLarge,
    /// Current storage exceeded its configured record limit.
    TooManyRecords,
    /// A stored JSON line exceeded its configured byte limit.
    LineTooLarge,
    /// The fixed journal schema could not be encoded.
    EncodingFailed,
    /// An append timestamp preceded the persisted clock observation.
    ClockRollback,
    /// The bounded journal-worker queue was full; this operation was dropped.
    QueueFull,
    /// A filesystem operation failed.
    Io,
}

impl From<&activity_journal::JournalError> for JournalFault {
    fn from(error: &activity_journal::JournalError) -> Self {
        match error {
            activity_journal::JournalError::WriterLocked => Self::WriterLocked,
            activity_journal::JournalError::UnexpectedLockContent => Self::UnexpectedLockContent,
            activity_journal::JournalError::UnsafeEntry(_) => Self::UnsafeEntry,
            activity_journal::JournalError::StagingRecoveryRequired => Self::StagingLeft,
            activity_journal::JournalError::MissingStorage => Self::MissingStorage,
            activity_journal::JournalError::CorruptStorage => Self::CorruptStorage,
            activity_journal::JournalError::StorageTooLarge => Self::StorageTooLarge,
            activity_journal::JournalError::TooManyRecords => Self::TooManyRecords,
            activity_journal::JournalError::LineTooLarge => Self::LineTooLarge,
            activity_journal::JournalError::EncodingFailed => Self::EncodingFailed,
            activity_journal::JournalError::ClockRollback => Self::ClockRollback,
            activity_journal::JournalError::Io { .. } => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalIoStep {
    /// Inspect the trusted journal directory.
    InspectDirectory,
    /// Resolve the trusted journal directory.
    ResolveDirectory,
    /// Inspect a fixed journal entry.
    InspectEntry,
    /// Open the fixed lock file.
    OpenLock,
    /// Acquire the exclusive writer lock.
    AcquireLock,
    /// Read current journal storage.
    ReadCurrent,
    /// Create the fixed staging file.
    CreateStaging,
    /// Write the fixed staging file.
    WriteStaging,
    /// Sync the fixed staging file.
    SyncStaging,
    /// Replace current storage with the staged write.
    ReplaceCurrent,
    /// Remove the fixed staging file.
    RemoveStaging,
}

impl From<activity_journal::IoOperation> for JournalIoStep {
    fn from(operation: activity_journal::IoOperation) -> Self {
        match operation {
            activity_journal::IoOperation::InspectDirectory => Self::InspectDirectory,
            activity_journal::IoOperation::ResolveDirectory => Self::ResolveDirectory,
            activity_journal::IoOperation::InspectEntry => Self::InspectEntry,
            activity_journal::IoOperation::OpenLock => Self::OpenLock,
            activity_journal::IoOperation::AcquireLock => Self::AcquireLock,
            activity_journal::IoOperation::ReadCurrent => Self::ReadCurrent,
            activity_journal::IoOperation::CreateStaging => Self::CreateStaging,
            activity_journal::IoOperation::WriteStaging => Self::WriteStaging,
            activity_journal::IoOperation::SyncStaging => Self::SyncStaging,
            activity_journal::IoOperation::ReplaceCurrent => Self::ReplaceCurrent,
            activity_journal::IoOperation::RemoveStaging => Self::RemoveStaging,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JournalRecovery {
    /// Removed a fixed staging file left by an interrupted write.
    DiscardedStaging,
    /// Replaced unusable diagnostic history with an empty journal.
    Cleared,
}

/// Why a connected phone's routing hints were refreshed. Never an address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HintRefresh {
    /// Its last address query lapsed unanswered while the owner was not ready.
    QueryLapsed,
    /// Its last answer did not list the external address published now.
    WithoutExternal,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptRefusal {
    UnknownTarget,
    TargetChanged,
    ContentChanged,
    UnrecognizedButtons,
    AmbiguousButtons,
    PatternUnavailable,
    InvokeFailed,
}
impl From<RefusalReason> for PromptRefusal {
    fn from(reason: RefusalReason) -> Self {
        match reason {
            RefusalReason::UnknownTarget => Self::UnknownTarget,
            RefusalReason::TargetChanged => Self::TargetChanged,
            RefusalReason::ContentChanged => Self::ContentChanged,
            RefusalReason::UnrecognizedButtons => Self::UnrecognizedButtons,
            RefusalReason::AmbiguousButtons => Self::AmbiguousButtons,
            RefusalReason::PatternUnavailable => Self::PatternUnavailable,
            RefusalReason::InvokeFailed => Self::InvokeFailed,
        }
    }
}

#[derive(Serialize)]
struct Record {
    schema: u8,
    version: &'static str,
    unix_millis: Option<u64>,
    pid: u32,
    #[serde(flatten)]
    event: Event,
}

/// Lock contention or any IO error drops this diagnostic only. No wait loop,
/// recovery of authority, interpretation of old contents or service failure.
fn append(file: &mut File, record: &Record) -> io::Result<()> {
    let mut line = serde_json::to_vec(record)?;
    if line.len() > 512 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    line.push(b'\n');
    file.try_lock()
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
    let result = (|| {
        let size = file.metadata()?.len();
        if size > MAX_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if size + line.len() as u64 > MAX_BYTES {
            // Bounded diagnostic rollover only. The protected activity journal
            // remains the independent source of history and retention policy.
            file.set_len(0)?;
        }
        file.seek(SeekFrom::End(0))?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_data()
    })();
    let unlocked = file.unlock();
    result.and(unlocked)
}

#[cfg(windows)]
pub(crate) fn record(event: Event) {
    // Unit tests reach this through the refusal and startup paths; the
    // installed product's journal in ProgramData is not theirs to append to.
    if cfg!(test) {
        return;
    }
    let Ok(mut opened) = crate::ffi::public_diagnostics::open_file() else {
        return;
    };
    let unix_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok());
    let _ = append(
        &mut opened.file,
        &Record {
            schema: 1,
            version: env!("CARGO_PKG_VERSION"),
            unix_millis,
            pid: std::process::id(),
            event,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn row(event: Event) -> Record {
        Record {
            schema: 1,
            version: "test",
            unix_millis: Some(123),
            pid: 7,
            event,
        }
    }

    #[test]
    fn closed_records_have_no_request_or_key_fields() {
        let events = [
            Event::Activity {
                event: ActivityEvent::Service(activity_journal::ServiceOutcome::Started),
            },
            Event::StartupFailure { stage: 7, code: 5 },
            Event::JournalRecovered {
                fault: JournalFault::StagingLeft,
                action: JournalRecovery::DiscardedStaging,
            },
            Event::JournalUnusable {
                fault: JournalFault::Io,
                io_step: Some(JournalIoStep::AcquireLock),
            },
            Event::JournalAppendFailed {
                fault: JournalFault::MissingStorage,
            },
            Event::JournalPurgeFailed {
                fault: JournalFault::CorruptStorage,
            },
            Event::StartupGuard {
                phase: 2,
                policy: 1,
                code: 5,
            },
            Event::PromptRefused {
                reason: RefusalReason::ContentChanged.into(),
            },
            Event::ConfigurationIgnored { stage: 8 },
            Event::RelayListenerChanged {
                fault: Some(crate::management_protocol::ListenerFault::InUse {
                    pid: 1234,
                    program: Some("veraport.exe".into()),
                }),
            },
            Event::RelayListenerChanged { fault: None },
            Event::RelayAbuse {
                evicted_pairs: 3,
                rejected_duplicates: 2,
                rejected_pc_sources: 1,
                rejected_evictions: 4,
            },
            Event::RelayWorkerStopped {
                outcome: RelayWorkerOutcome::Panicked,
            },
            Event::PeerWorkerExited {
                cause: crate::peer_runtime::PeerExitCause::Timeout,
                count: 2,
            },
            Event::HintsRefreshed {
                reason: HintRefresh::QueryLapsed,
            },
            Event::HintsRefreshed {
                reason: HintRefresh::WithoutExternal,
            },
            Event::WatcherStartFailed {
                error: ProbeSupervisorError::Native {
                    stage: crate::SupervisorStage::CreateChild,
                    hresult: -2147024891,
                },
            },
            Event::WatcherStartFailed {
                error: ProbeSupervisorError::HelperDamaged,
            },
            Event::LanAnnounceFailed { code: 5 },
            Event::RuntimeFailure {
                step: 4,
                cause: RuntimeFailureCause::Service,
                panicked: false,
                code: 1,
            },
            Event::DecisionRejected {
                reason: DecisionRejectionReason::InvalidSignature,
            },
        ];
        for event in events {
            let value = serde_json::to_value(row(event)).unwrap();
            let fields = value.as_object().unwrap();
            assert!(fields.keys().all(|key| {
                [
                    "schema",
                    "version",
                    "unix_millis",
                    "pid",
                    "kind",
                    "event",
                    "stage",
                    "code",
                    "phase",
                    "policy",
                    "reason",
                    "error",
                    "step",
                    "cause",
                    "panicked",
                    "fault",
                    "action",
                    "io_step",
                    "evicted_pairs",
                    "rejected_duplicates",
                    "rejected_pc_sources",
                    "rejected_evictions",
                    "outcome",
                    "count",
                ]
                .contains(&key.as_str())
            }));
        }
    }

    #[test]
    fn peer_worker_exit_rows_have_fixed_cause_names_and_counts() {
        for (cause, name) in [
            (crate::peer_runtime::PeerExitCause::LocallyClosed, "locally_closed"),
            (crate::peer_runtime::PeerExitCause::PeerClosed, "peer_closed"),
            (crate::peer_runtime::PeerExitCause::TlsFailure, "tls_failure"),
            (crate::peer_runtime::PeerExitCause::Timeout, "timeout"),
            (
                crate::peer_runtime::PeerExitCause::ProtocolViolation,
                "protocol_violation",
            ),
            (crate::peer_runtime::PeerExitCause::ClockFailure, "clock_failure"),
            (crate::peer_runtime::PeerExitCause::IoFailure, "io_failure"),
            (crate::peer_runtime::PeerExitCause::Panic, "panic"),
        ] {
            assert_eq!(
                serde_json::to_value(row(Event::PeerWorkerExited { cause, count: 7 })).unwrap(),
                serde_json::json!({
                    "schema": 1,
                    "version": "test",
                    "unix_millis": 123,
                    "pid": 7,
                    "kind": "peer_worker_exited",
                    "cause": name,
                    "count": 7,
                })
            );
        }
    }

    #[test]
    fn relay_worker_outcomes_have_closed_fixed_schema() {
        let report = RelayWorkerReport {
            accepted: 1,
            accept_failures: 2,
            rejected_capacity: 3,
            rejected_waiting_rooms: 4,
            paired: 5,
            invalid_registrations: 6,
            header_timeouts: 7,
            waiting_timeouts: 8,
            rendezvous_timeouts: 9,
            idle_timeouts: 10,
            absolute_timeouts: 11,
            disconnected: 12,
            io_failures: 13,
            cancelled: 14,
            task_failures: 15,
            peak_connections: 16,
            peak_waiting_rooms: 17,
            remaining_connections: 18,
        };
        assert_eq!(
            serde_json::to_value(row(Event::RelayWorkerStopped {
                outcome: RelayWorkerOutcome::Clean { report },
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "relay_worker_stopped",
                "outcome": {
                    "status": "clean",
                    "report": {
                        "accepted": 1,
                        "accept_failures": 2,
                        "rejected_capacity": 3,
                        "rejected_waiting_rooms": 4,
                        "paired": 5,
                        "invalid_registrations": 6,
                        "header_timeouts": 7,
                        "waiting_timeouts": 8,
                        "rendezvous_timeouts": 9,
                        "idle_timeouts": 10,
                        "absolute_timeouts": 11,
                        "disconnected": 12,
                        "io_failures": 13,
                        "cancelled": 14,
                        "task_failures": 15,
                        "peak_connections": 16,
                        "peak_waiting_rooms": 17,
                        "remaining_connections": 18,
                    },
                },
            })
        );

        for (error, name) in [
            (RelayWorkerError::AcceptFailed, "accept_failed"),
            (RelayWorkerError::TaskFailed, "task_failed"),
            (RelayWorkerError::IdentifierExhausted, "identifier_exhausted"),
            (RelayWorkerError::ShutdownIncomplete, "shutdown_incomplete"),
        ] {
            assert_eq!(
                serde_json::to_value(row(Event::RelayWorkerStopped {
                    outcome: RelayWorkerOutcome::Error { error },
                }))
                .unwrap(),
                serde_json::json!({
                    "schema": 1,
                    "version": "test",
                    "unix_millis": 123,
                    "pid": 7,
                    "kind": "relay_worker_stopped",
                    "outcome": {"status": "error", "error": name},
                })
            );
        }

        assert_eq!(
            serde_json::to_value(row(Event::RelayWorkerStopped {
                outcome: RelayWorkerOutcome::Panicked,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "relay_worker_stopped",
                "outcome": {"status": "panicked"},
            })
        );
    }

    #[test]
    fn signed_decision_rejections_have_distinct_closed_reason_names() {
        let reasons = [
            (DecisionRejectionReason::Clock, "clock"),
            (DecisionRejectionReason::WrongPc, "wrong_pc"),
            (DecisionRejectionReason::WrongEpoch, "wrong_epoch"),
            (
                DecisionRejectionReason::UnknownOrCompleted,
                "unknown_or_completed",
            ),
            (DecisionRejectionReason::Expired, "expired"),
            (DecisionRejectionReason::BindingMismatch, "binding_mismatch"),
            (DecisionRejectionReason::NotEligible, "not_eligible"),
            (
                DecisionRejectionReason::EnrollmentChanged,
                "enrollment_changed",
            ),
            (
                DecisionRejectionReason::InvalidSignature,
                "invalid_signature",
            ),
        ];

        for (reason, name) in reasons {
            assert_eq!(
                serde_json::to_value(row(Event::DecisionRejected { reason })).unwrap(),
                serde_json::json!({
                    "schema": 1,
                    "version": "test",
                    "unix_millis": 123,
                    "pid": 7,
                    "kind": "decision_rejected",
                    "reason": name,
                })
            );
        }
    }

    #[test]
    fn runtime_failure_row_names_the_fixed_cause_and_caught_panic() {
        assert_eq!(
            serde_json::to_value(row(Event::RuntimeFailure {
                step: 5,
                cause: RuntimeFailureCause::Panicked,
                panicked: true,
                code: 0,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "runtime_failure",
                "step": 5,
                "cause": "panicked",
                "panicked": true,
                "code": 0,
            })
        );
    }

    #[test]
    fn damaged_helper_has_a_distinct_closed_diagnostic_kind() {
        assert_eq!(
            serde_json::to_value(row(Event::WatcherStartFailed {
                error: ProbeSupervisorError::HelperDamaged,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "watcher_start_failed",
                "error": {"kind": "helper_damaged"}
            })
        );
    }

    #[test]
    fn lan_announcement_failure_has_only_a_numeric_code() {
        assert_eq!(
            serde_json::to_value(row(Event::LanAnnounceFailed { code: 9505 })).unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "lan_announce_failed",
                "code": 9505
            })
        );
    }

    #[test]
    fn journal_recovery_rows_pin_the_public_schema() {
        assert_eq!(
            serde_json::to_value(row(Event::JournalRecovered {
                fault: JournalFault::StagingLeft,
                action: JournalRecovery::DiscardedStaging,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_recovered",
                "fault": "staging_left",
                "action": "discarded_staging"
            })
        );
        assert_eq!(
            serde_json::to_value(row(Event::JournalUnusable {
                fault: JournalFault::Io,
                io_step: Some(JournalIoStep::AcquireLock),
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_unusable",
                "fault": "io",
                "io_step": "acquire_lock"
            })
        );
        assert_eq!(
            serde_json::to_value(row(Event::JournalUnusable {
                fault: JournalFault::UnexpectedLockContent,
                io_step: None,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_unusable",
                "fault": "unexpected_lock_content"
            })
        );
        assert_eq!(
            serde_json::to_value(row(Event::JournalAppendFailed {
                fault: JournalFault::MissingStorage,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_append_failed",
                "fault": "missing_storage"
            })
        );
        assert_eq!(
            serde_json::to_value(row(Event::JournalAppendFailed {
                fault: JournalFault::QueueFull,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_append_failed",
                "fault": "queue_full"
            })
        );
        assert_eq!(
            serde_json::to_value(row(Event::JournalPurgeFailed {
                fault: JournalFault::CorruptStorage,
            }))
            .unwrap(),
            serde_json::json!({
                "schema": 1,
                "version": "test",
                "unix_millis": 123,
                "pid": 7,
                "kind": "journal_purge_failed",
                "fault": "corrupt_storage"
            })
        );
    }

    #[test]
    fn file_is_bounded_and_contention_never_waits_or_writes() {
        let mut file = tempfile::tempfile().unwrap();
        let record = row(Event::StartupFailure { stage: 7, code: 5 });
        file.set_len(MAX_BYTES).unwrap();
        append(&mut file, &record).unwrap();
        assert!(file.metadata().unwrap().len() < 513);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap()["kind"],
            "startup_failure"
        );
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(append(&mut file, &record).is_err());
        assert_eq!(file.metadata().unwrap().len(), MAX_BYTES + 1);
    }

    #[test]
    fn an_independent_open_lock_rejects_without_changing_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("diagnostics.jsonl");
        let first = File::create(&path).unwrap();
        first.lock().unwrap();
        let mut second = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(
            append(
                &mut second,
                &row(Event::StartupFailure { stage: 7, code: 5 })
            )
            .is_err()
        );
        assert_eq!(first.metadata().unwrap().len(), 0);
    }
}
