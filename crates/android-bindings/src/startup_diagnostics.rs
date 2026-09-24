// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed startup failure projection; never an owner or storage authority.

use android_controller::{ControllerCheckpointError, DurableFault};
use phone_request_core::InboxCheckpointError;
use phone_state_store::StoreError;

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Directory,
    Bootstrap,
    OpenExisting,
    CreateFresh,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Directory => "DIRECTORY",
            Self::Bootstrap => "BOOTSTRAP",
            Self::OpenExisting => "OPEN_EXISTING",
            Self::CreateFresh => "CREATE_FRESH",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BootstrapFailure {
    TooManyEntries,
    NonUnicodeEntry,
    UnknownEntry,
    ExistingKeys,
    LegacyPolicy,
    MarkerLength,
    MarkerContents,
    UnsafeFile,
    #[cfg(unix)]
    LinkCount,
    #[cfg(windows)]
    ReparsePoint,
    Io(std::io::ErrorKind),
}

impl BootstrapFailure {
    fn label(self) -> &'static str {
        match self {
            Self::TooManyEntries => "BOOTSTRAP_TOO_MANY_ENTRIES",
            Self::NonUnicodeEntry => "BOOTSTRAP_NON_UNICODE_ENTRY",
            Self::UnknownEntry => "BOOTSTRAP_UNKNOWN_ENTRY",
            Self::ExistingKeys => "BOOTSTRAP_EXISTING_KEYS",
            Self::LegacyPolicy => "BOOTSTRAP_LEGACY_POLICY",
            Self::MarkerLength => "BOOTSTRAP_MARKER_LENGTH",
            Self::MarkerContents => "BOOTSTRAP_MARKER_CONTENTS",
            Self::UnsafeFile => "BOOTSTRAP_UNSAFE_FILE",
            #[cfg(unix)]
            Self::LinkCount => "BOOTSTRAP_LINK_COUNT",
            #[cfg(windows)]
            Self::ReparsePoint => "BOOTSTRAP_REPARSE_POINT",
            Self::Io(std::io::ErrorKind::PermissionDenied) => "BOOTSTRAP_IO_PERMISSION_DENIED",
            Self::Io(std::io::ErrorKind::NotFound) => "BOOTSTRAP_IO_NOT_FOUND",
            Self::Io(std::io::ErrorKind::AlreadyExists) => "BOOTSTRAP_IO_ALREADY_EXISTS",
            Self::Io(_) => "BOOTSTRAP_IO_OTHER",
        }
    }
}

/// What an explicit startup resolution actually cleared. It is a record of work
/// already completed, never a claim about the domain effects the interrupted
/// operation did or did not release.
#[derive(Clone, Copy)]
pub(crate) enum Resolution {
    InterruptedCommit,
    AbandonedPreparations,
}

impl Resolution {
    fn label(self) -> &'static str {
        match self {
            Self::InterruptedCommit => "RESOLVED_INTERRUPTED_COMMIT",
            Self::AbandonedPreparations => "RESOLVED_ABANDONED_PREPARATIONS",
        }
    }
}

pub(crate) fn bootstrap(failure: BootstrapFailure) {
    emit(Stage::Bootstrap, failure.label());
}

pub(crate) fn resolved(stage: Stage, resolution: Resolution) {
    emit(stage, resolution.label());
}

pub(crate) fn storage(stage: Stage, error: StoreError) {
    emit(stage, storage_label(error));
}

pub(crate) fn durable(stage: Stage, error: DurableFault) {
    emit(stage, durable_label(error));
}

fn storage_label(error: StoreError) -> &'static str {
    match error {
        StoreError::DirectoryUnavailable => "STORE_DIRECTORY_UNAVAILABLE",
        StoreError::UnsupportedPlatform => "STORE_UNSUPPORTED_PLATFORM",
        StoreError::UnsafeEntry => "STORE_UNSAFE_ENTRY",
        StoreError::StateAlreadyExists => "STORE_STATE_ALREADY_EXISTS",
        StoreError::MissingState => "STORE_MISSING_STATE",
        StoreError::WriterLocked => "STORE_WRITER_LOCKED",
        StoreError::RecoveryRequired => "STORE_RECOVERY_REQUIRED",
        StoreError::InterruptedCommit => "STORE_INTERRUPTED_COMMIT",
        StoreError::CorruptSnapshot => "STORE_CORRUPT_SNAPSHOT",
        StoreError::UnsupportedVersion => "STORE_UNSUPPORTED_VERSION",
        StoreError::SnapshotTooLarge => "STORE_SNAPSHOT_TOO_LARGE",
        StoreError::ExternalChange => "STORE_EXTERNAL_CHANGE",
        StoreError::ReadFailed => "STORE_READ_FAILED",
        StoreError::WriteFailed => "STORE_WRITE_FAILED",
        StoreError::CommitUncertain => "STORE_COMMIT_UNCERTAIN",
        StoreError::Poisoned => "STORE_POISONED",
        StoreError::GenerationExhausted => "STORE_GENERATION_EXHAUSTED",
    }
}

fn durable_label(error: DurableFault) -> &'static str {
    match error {
        DurableFault::Storage(error) => storage_label(error),
        DurableFault::Checkpoint(error) => checkpoint_label(error),
        DurableFault::Composite(error) => match error {
            ControllerCheckpointError::InvalidEncoding => "COMPOSITE_INVALID_ENCODING",
            ControllerCheckpointError::UnsupportedVersion => "COMPOSITE_UNSUPPORTED_VERSION",
            ControllerCheckpointError::TooLarge => "COMPOSITE_TOO_LARGE",
            ControllerCheckpointError::LegacyHistoryReconciliationRequired => {
                "COMPOSITE_LEGACY_HISTORY"
            }
            ControllerCheckpointError::HistoryProfileMismatch => "COMPOSITE_HISTORY_PROFILE",
            ControllerCheckpointError::RecordedPendingOverlap => {
                "COMPOSITE_RECORDED_PENDING_OVERLAP"
            }
            ControllerCheckpointError::Inbox(error) => checkpoint_label(error),
            ControllerCheckpointError::History(_) => "COMPOSITE_HISTORY",
            ControllerCheckpointError::LocalKeys(_) => "COMPOSITE_LOCAL_KEYS",
            ControllerCheckpointError::PeerAssociations(_) => "COMPOSITE_PEER_ASSOCIATIONS",
            ControllerCheckpointError::ReceivingSourceMismatch => "COMPOSITE_RECEIVING_SOURCE",
            ControllerCheckpointError::RoutingCandidates => "COMPOSITE_ROUTING_CANDIDATES",
        },
        DurableFault::History(_) => "DURABLE_HISTORY",
        DurableFault::LifecycleIntegrationRequired => "DURABLE_LIFECYCLE_INTEGRATION",
        DurableFault::LocalKeyReconciliationRequired => "DURABLE_LOCAL_KEY_RECONCILIATION",
        DurableFault::NativeLocalKeysUnavailable => "DURABLE_NATIVE_LOCAL_KEYS",
        DurableFault::LocalKeys(_) => "DURABLE_LOCAL_KEYS",
        DurableFault::DirectorySynchronizationRequired => "DURABLE_DIRECTORY_SYNCHRONIZATION",
        DurableFault::TransitionIncomplete => "DURABLE_TRANSITION_INCOMPLETE",
    }
}

fn checkpoint_label(error: InboxCheckpointError) -> &'static str {
    match error {
        InboxCheckpointError::InvalidBoot => "CHECKPOINT_INVALID_BOOT",
        InboxCheckpointError::MissingBoot => "CHECKPOINT_MISSING_BOOT",
        InboxCheckpointError::ClockRegressed => "CHECKPOINT_CLOCK_REGRESSED",
        InboxCheckpointError::InvalidState => "CHECKPOINT_INVALID_STATE",
        InboxCheckpointError::UnsupportedVersion => "CHECKPOINT_UNSUPPORTED_VERSION",
        InboxCheckpointError::TooLarge => "CHECKPOINT_TOO_LARGE",
        InboxCheckpointError::LegacyOutcomeReconciliationRequired => "CHECKPOINT_LEGACY_OUTCOME",
        InboxCheckpointError::OutcomeRetentionFailed => "CHECKPOINT_OUTCOME_RETENTION",
    }
}

// Only private callers above supply labels selected by exhaustive enum matches.
// No generated ABI, paths, errno prose, nested Debug values or caller strings
// cross this projection. A missing/broken sink cannot change the primary failure.
//
// Two sinks, because they fail in different places. The RustStdoutStderr pipe is
// what lifecycle CI already greps, but it only exists once an Activity has
// created it, and this projection reports a startup that can happen in the
// foreground service with no Activity at all. The logcat sink does not depend on
// a window. Neither is load-bearing; both are best effort.
fn emit(stage: Stage, reason: &'static str) {
    let stage = stage.label();
    crate::native_log::write(&format!(
        "UAC_NATIVE_STARTUP_V1 stage={stage} reason={reason}"
    ));
    #[cfg(target_os = "android")]
    {
        use std::io::Write;
        use std::sync::atomic::{AtomicU8, Ordering};
        static COUNT: AtomicU8 = AtomicU8::new(0);
        if COUNT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < 8).then_some(count + 1)
            })
            .is_err()
        {
            return;
        }
        let _ = writeln!(
            std::io::stderr().lock(),
            "UAC_NATIVE_STARTUP_V1 stage={stage} reason={reason}"
        );
    }
    #[cfg(not(target_os = "android"))]
    let _ = (stage, reason);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_failure_has_a_distinct_closed_label() {
        let errors = [
            StoreError::DirectoryUnavailable,
            StoreError::UnsupportedPlatform,
            StoreError::UnsafeEntry,
            StoreError::StateAlreadyExists,
            StoreError::MissingState,
            StoreError::WriterLocked,
            StoreError::RecoveryRequired,
            StoreError::InterruptedCommit,
            StoreError::CorruptSnapshot,
            StoreError::UnsupportedVersion,
            StoreError::SnapshotTooLarge,
            StoreError::ExternalChange,
            StoreError::ReadFailed,
            StoreError::WriteFailed,
            StoreError::CommitUncertain,
            StoreError::Poisoned,
            StoreError::GenerationExhausted,
        ];
        let mut labels = std::collections::BTreeSet::new();
        for error in errors {
            let label = storage_label(error);
            assert!(label.len() <= 64);
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            );
            assert!(labels.insert(label));
            assert_eq!(durable_label(DurableFault::Storage(error)), label);
        }
    }

    #[test]
    fn nested_clock_and_recovery_failures_remain_distinct() {
        assert_eq!(
            durable_label(DurableFault::Checkpoint(
                InboxCheckpointError::ClockRegressed
            )),
            "CHECKPOINT_CLOCK_REGRESSED"
        );
        assert_eq!(
            durable_label(DurableFault::Storage(StoreError::RecoveryRequired)),
            "STORE_RECOVERY_REQUIRED"
        );
        assert_eq!(
            BootstrapFailure::Io(std::io::ErrorKind::PermissionDenied).label(),
            "BOOTSTRAP_IO_PERMISSION_DENIED"
        );
    }
}
