// SPDX-License-Identifier: GPL-2.0-or-later
//! One bounded logcat sink for closed native diagnostic lines, plus the panic
//! hook that names where a native task died.
//!
//! This is not a capability, a key, a store or an authorization step. It reads
//! and writes no request, notification or key material, decides nothing about
//! an approval or a denial, and changes no generated interface. It only writes
//! fixed diagnostic tokens to the device log.
//!
//! **Where the line goes.** [`android_log_sink`] owns the one `liblog` call and
//! the shape check. It is a separate crate because the workspace forbids unsafe
//! here on purpose, and this crate holds the phone's requests, leases and key
//! references. A log line is not worth weakening that.

use crate::BridgeError;
use std::{panic::Location, sync::Once};

/// Fixed tag for every line this module writes, beside the `UacBoot` tag the
/// Kotlin side already uses, so one logcat filter catches both.
const TAG: &[u8] = b"UacNative\0";

pub(crate) fn write(line: &str) {
    android_log_sink::write(TAG, line);
}

/// The panic line, built apart from the hook so it can be tested without
/// panicking a test process.
///
/// **The payload never appears here.** A panic message is developer prose, but
/// it is prose an author can interpolate a value into, and this crate handles
/// requests, leases and key references. A location names the site exactly and
/// can carry nothing that was not already in the source tree. The thread name
/// is admitted under the same closed rule so a runtime-supplied name cannot
/// widen the line either.
fn panic_line(location: Option<&Location<'_>>, thread: Option<&str>) -> Option<String> {
    let location = location?;
    let file = location.file();
    // The compiler wrote this path, not a caller, so the check is only what the
    // line's own shape needs: bounded, and no space to break `key=value`. It
    // deliberately does not enumerate separators. A Windows build reports
    // backslashes, and an over-tight check dropped the whole line rather than
    // the path, which is the one outcome worse than a slightly wider one.
    if file.len() > 128 || file.contains(' ') {
        return None;
    }
    let thread = thread
        .filter(|name| {
            name.len() <= 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .unwrap_or("unnamed");
    let line = format!(
        "UAC_NATIVE_PANIC_V1 file={file} line={} column={} thread={thread}",
        location.line(),
        location.column()
    );
    android_log_sink::admissible(&line).then_some(line)
}

/// Installs the panic hook once per process. Chains to the previous hook rather
/// than replacing it, so whatever the platform or a test harness already does
/// with a panic keeps happening; this only adds a line naming the site.
///
/// Without this, a panicking task inside the intake reactor leaves no trace at
/// all: `tokio` converts it to a `JoinError` the reactor answers by retiring the
/// owner, and the default hook's stderr output goes nowhere in a service with no
/// Activity. The failure was visible only as a closed owner minutes later.
pub(crate) fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            if let Some(line) = panic_line(info.location(), thread.name()) {
                write(&line);
            }
            previous(info);
        }));
    });
}

/// Where the intake reactor decided the owner was finished. One arm per site
/// that sets `intake.failed`, so the log says which of them fired instead of
/// leaving ten candidates and one closed owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RetireSite {
    RuntimeJoin,
    Reactor,
    Maintenance,
    PresentationPause,
    PeerWork,
    NativeProgress,
    DialJoin,
    PeerJoin,
    PeerBudget,
    Clock,
}

impl RetireSite {
    fn label(self) -> &'static str {
        match self {
            Self::RuntimeJoin => "RUNTIME_JOIN",
            Self::Reactor => "REACTOR",
            Self::Maintenance => "MAINTENANCE",
            Self::PresentationPause => "PRESENTATION_PAUSE",
            Self::PeerWork => "PEER_WORK",
            Self::NativeProgress => "NATIVE_PROGRESS",
            Self::DialJoin => "DIAL_JOIN",
            Self::PeerJoin => "PEER_JOIN",
            Self::PeerBudget => "PEER_BUDGET",
            Self::Clock => "CLOCK",
        }
    }
}

/// Written as an exhaustive match with no wildcard arm, so a variant added to
/// `BridgeError` later has to be given a name here rather than quietly becoming
/// whatever the catch-all said.
fn error_label(error: BridgeError) -> &'static str {
    match error {
        BridgeError::LifecycleIntegrationRequired => "LIFECYCLE_INTEGRATION_REQUIRED",
        BridgeError::OwnerFaulted => "OWNER_FAULTED",
        BridgeError::NativeUnavailable => "NATIVE_UNAVAILABLE",
        BridgeError::InvalidObservation => "INVALID_OBSERVATION",
        BridgeError::Busy => "BUSY",
        BridgeError::StorageUnavailable => "STORAGE_UNAVAILABLE",
        BridgeError::InvalidPolicy => "INVALID_POLICY",
        BridgeError::Closed => "CLOSED",
        BridgeError::HistoryTimeUnavailable => "HISTORY_TIME_UNAVAILABLE",
        BridgeError::LocalKeysReconciliationRequired => "LOCAL_KEYS_RECONCILIATION_REQUIRED",
        BridgeError::LocalKeysUnavailable => "LOCAL_KEYS_UNAVAILABLE",
        BridgeError::ApprovalRejected => "APPROVAL_REJECTED",
        BridgeError::DenialRejected => "DENIAL_REJECTED",
        BridgeError::RequestUnavailable => "REQUEST_UNAVAILABLE",
        BridgeError::PresentationRefreshRequired => "PRESENTATION_REFRESH_REQUIRED",
    }
}

/// Which statement produced a bridge error, for the paths where the reactor's
/// own site still leaves more than one candidate. `PEER_WORK` alone covers a
/// socket being attached, a clock read, an inbox write, a probe deadline and a
/// whole notification dispatch; naming the site told us which of ten reactor
/// arms fired and then stopped being able to help.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Step {
    AttachSocket,
    ReadyProbe,
    MessageClock,
    MessageApply,
    MessageProbe,
    MessageEffects,
    DecisionDeliver,
    EffectPrune,
    EffectWithdraw,
    EffectReconcile,
    EffectPublish,
    EffectDeadline,
}

impl Step {
    fn label(self) -> &'static str {
        match self {
            Self::AttachSocket => "ATTACH_SOCKET",
            Self::ReadyProbe => "READY_PROBE",
            Self::MessageClock => "MESSAGE_CLOCK",
            Self::MessageApply => "MESSAGE_APPLY",
            Self::MessageProbe => "MESSAGE_PROBE",
            Self::MessageEffects => "MESSAGE_EFFECTS",
            Self::DecisionDeliver => "DECISION_DELIVER",
            Self::EffectPrune => "EFFECT_PRUNE",
            Self::EffectWithdraw => "EFFECT_WITHDRAW",
            Self::EffectReconcile => "EFFECT_RECONCILE",
            Self::EffectPublish => "EFFECT_PUBLISH",
            Self::EffectDeadline => "EFFECT_DEADLINE",
        }
    }
}

/// Names the step an error came from and hands the result straight back, so a
/// caller reads `note(Step::X, expr)?` exactly where it read `expr?` and the
/// control flow is unchanged.
///
/// `Busy` and `PresentationRefreshRequired` are ordinary control flow on these
/// paths, retried or awaited by design rather than failures anyone is hunting.
/// Emitting them would spend the per-process budget on the answer nobody asked
/// for and bury the one line that matters.
pub(crate) fn note<T>(step: Step, result: Result<T, BridgeError>) -> Result<T, BridgeError> {
    if let Err(error) = result
        && !matches!(
            error,
            BridgeError::Busy | BridgeError::PresentationRefreshRequired
        )
    {
        write(&format!(
            "UAC_NATIVE_STEP_V1 step={} error={}",
            step.label(),
            error_label(error)
        ));
    }
    result
}

/// One retire decision, named. `None` is for the sites that carry no bridge
/// error of their own: a joined task that panicked, or an exhausted peer slot.
pub(crate) fn intake_retire(site: RetireSite, error: Option<BridgeError>) {
    let error = error.map_or("NONE", error_label);
    write(&format!(
        "UAC_NATIVE_INTAKE_V1 site={} error={error}",
        site.label()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITES: [RetireSite; 10] = [
        RetireSite::RuntimeJoin,
        RetireSite::Reactor,
        RetireSite::Maintenance,
        RetireSite::PresentationPause,
        RetireSite::PeerWork,
        RetireSite::NativeProgress,
        RetireSite::DialJoin,
        RetireSite::PeerJoin,
        RetireSite::PeerBudget,
        RetireSite::Clock,
    ];
    const STEPS: [Step; 12] = [
        Step::AttachSocket,
        Step::ReadyProbe,
        Step::MessageClock,
        Step::MessageApply,
        Step::MessageProbe,
        Step::MessageEffects,
        Step::DecisionDeliver,
        Step::EffectPrune,
        Step::EffectWithdraw,
        Step::EffectReconcile,
        Step::EffectPublish,
        Step::EffectDeadline,
    ];
    const ERRORS: [BridgeError; 15] = [
        BridgeError::LifecycleIntegrationRequired,
        BridgeError::OwnerFaulted,
        BridgeError::NativeUnavailable,
        BridgeError::InvalidObservation,
        BridgeError::Busy,
        BridgeError::StorageUnavailable,
        BridgeError::InvalidPolicy,
        BridgeError::Closed,
        BridgeError::HistoryTimeUnavailable,
        BridgeError::LocalKeysReconciliationRequired,
        BridgeError::LocalKeysUnavailable,
        BridgeError::ApprovalRejected,
        BridgeError::DenialRejected,
        BridgeError::RequestUnavailable,
        BridgeError::PresentationRefreshRequired,
    ];

    #[test]
    fn every_site_and_every_error_has_its_own_name_and_composes_an_admissible_line() {
        let mut names = std::collections::BTreeSet::new();
        for site in SITES {
            assert!(names.insert(site.label()));
        }
        for error in ERRORS {
            assert!(names.insert(error_label(error)));
        }
        for step in STEPS {
            assert!(names.insert(step.label()));
        }
        for site in SITES {
            for error in ERRORS.map(Some).into_iter().chain([None]) {
                let error = error.map_or("NONE", error_label);
                let line = format!("UAC_NATIVE_INTAKE_V1 site={} error={error}", site.label());
                assert!(android_log_sink::admissible(&line), "{line}");
            }
        }
        for step in STEPS {
            for error in ERRORS {
                let line = format!(
                    "UAC_NATIVE_STEP_V1 step={} error={}",
                    step.label(),
                    error_label(error)
                );
                assert!(android_log_sink::admissible(&line), "{line}");
            }
        }
    }

    /// The list above is the crate's one enumeration of every `BridgeError`, so
    /// it is also the place to state which of them end an owner. A variant added
    /// later fails to compile in `error_label` and `retires_the_owner` both, and
    /// this pins the answer for the ones that exist.
    #[test]
    fn only_the_five_errors_that_end_an_owner_retire_it() {
        let retiring: Vec<&str> = ERRORS
            .into_iter()
            .filter(|error| error.retires_the_owner())
            .map(error_label)
            .collect();
        assert_eq!(
            retiring,
            [
                "LIFECYCLE_INTEGRATION_REQUIRED",
                "OWNER_FAULTED",
                "CLOSED",
                "LOCAL_KEYS_RECONCILIATION_REQUIRED",
                "LOCAL_KEYS_UNAVAILABLE",
            ]
        );
        // The ones a real consent prompt produced on a real phone, each of which
        // used to cost the whole owner.
        for survivable in [
            BridgeError::NativeUnavailable,
            BridgeError::InvalidObservation,
            BridgeError::StorageUnavailable,
            BridgeError::RequestUnavailable,
        ] {
            assert!(
                !survivable.retires_the_owner(),
                "{}",
                error_label(survivable)
            );
        }
    }

    #[test]
    fn a_panic_line_names_the_site_and_never_the_payload() {
        let line = panic_line(Some(Location::caller()), Some("tokio-worker")).unwrap();
        assert!(line.starts_with("UAC_NATIVE_PANIC_V1 file="));
        assert!(line.contains("native_log.rs"));
        assert!(line.contains("thread=tokio-worker"));
        assert!(android_log_sink::admissible(&line));
    }

    #[test]
    fn a_runtime_supplied_thread_name_cannot_widen_the_line() {
        for hostile in [
            "name with spaces",
            "name\nwith\nnewlines",
            "요청식별자",
            "a-very-long-thread-name-that-runs-past-the-fixed-bound",
        ] {
            let line = panic_line(Some(Location::caller()), Some(hostile)).unwrap();
            assert!(line.ends_with("thread=unnamed"), "{line}");
        }
    }

    #[test]
    fn a_line_that_is_not_the_closed_shape_is_never_written() {
        assert!(!android_log_sink::admissible(""));
        assert!(!android_log_sink::admissible("has\na newline"));
        assert!(!android_log_sink::admissible("한글"));
        assert!(!android_log_sink::admissible(&"x".repeat(257)));
        assert!(android_log_sink::admissible(
            "UAC_NATIVE_INTAKE_V1 site=PEER_WORK error=NATIVE_UNAVAILABLE"
        ));
    }
}
