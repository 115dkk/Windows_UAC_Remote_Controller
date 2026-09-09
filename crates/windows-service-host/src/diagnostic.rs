// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded read-only probe admission and body-free diagnostics. No target,
//! command, input injection, user authentication or approval capability.
#![forbid(unsafe_code)]

use serde::Serialize;

pub const PROBE_CONTROL_CODE: u32 = 128;
pub const MAX_PROBE_DIAGNOSTIC_BYTES: usize = 4096;
pub const PROBE_DIAGNOSTIC_FILES: [&str; 8] = [
    "probe-once-01.json",
    "probe-once-02.json",
    "probe-once-03.json",
    "probe-once-04.json",
    "probe-once-05.json",
    "probe-once-06.json",
    "probe-once-07.json",
    "probe-once-08.json",
];

/// SCM accepted the one-slot request only. No probe, result-file or UAC success
/// is asserted. Use the matching service PID and immutable result slot record.
#[derive(Clone, Copy, Debug)]
pub struct ProbeRequestAccepted {
    service_pid: u32,
}
impl ProbeRequestAccepted {
    #[cfg(any(windows, test))]
    pub(crate) fn new(service_pid: u32) -> Self {
        Self { service_pid }
    }
}
impl Serialize for ProbeRequestAccepted {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut record = serializer.serialize_struct("ProbeRequestAccepted", 2)?;
        record.serialize_field("status", "requested")?;
        record.serialize_field("service_pid", &self.service_pid)?;
        record.end()
    }
}

#[cfg(any(windows, test))]
mod owned {
    use super::*;
    use crate::{ProbeSupervisorError, ServiceError};
    use serde::ser::SerializeStruct;
    use std::sync::atomic::{AtomicU8, Ordering};
    use windows_prompt_probe::{
        NativeOperation, ProbeCounts, ProbeFailure, supervision::ReportOutcome,
    };

    const DORMANT: u8 = 0;
    const PREPARED: u8 = 1;
    const IDLE: u8 = 2;
    const PENDING: u8 = 3;
    const RUNNING: u8 = 4;
    const FULL: u8 = 5;
    const UNAVAILABLE: u8 = 6;
    const CLOSED: u8 = 7;

    #[derive(Debug)]
    pub(crate) struct ProbeAdmission {
        state: AtomicU8,
    }
    impl ProbeAdmission {
        pub(crate) const fn new() -> Self {
            Self {
                state: AtomicU8::new(DORMANT),
            }
        }
        /// Read-only storage preflight; does not enable controls before SCM Running.
        pub(crate) fn prepare(&self, storage: Result<bool, ServiceError>) {
            let next = match storage {
                Ok(true) => PREPARED,
                Ok(false) => FULL,
                Err(_) => UNAVAILABLE,
            };
            let _ = self
                .state
                .compare_exchange(DORMANT, next, Ordering::AcqRel, Ordering::Acquire);
        }
        pub(crate) fn enable_after_scm_running(&self) {
            let _ =
                self.state
                    .compare_exchange(PREPARED, IDLE, Ordering::AcqRel, Ordering::Acquire);
        }
        pub(crate) fn request(&self) -> Result<(), ServiceError> {
            self.state
                .compare_exchange(IDLE, PENDING, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| ())
                .map_err(|state| match state {
                    PENDING | RUNNING => ServiceError::ProbeBusy,
                    FULL => ServiceError::ProbeSlotsFull,
                    _ => ServiceError::ProbeUnavailable,
                })
        }
        pub(crate) fn take(&self) -> Option<ProbeRun<'_>> {
            self.state
                .compare_exchange(PENDING, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                .ok()
                .map(|_| ProbeRun {
                    owner: self,
                    finished: false,
                })
        }
        pub(crate) fn close(&self) {
            self.state.store(CLOSED, Ordering::Release);
        }
    }
    #[derive(Debug)]
    pub(crate) struct ProbeRun<'a> {
        owner: &'a ProbeAdmission,
        finished: bool,
    }
    impl ProbeRun<'_> {
        pub(crate) fn cancelled(&self) -> bool {
            self.owner.state.load(Ordering::Acquire) == CLOSED
        }
        pub(crate) fn finish(mut self, storage: Result<bool, ServiceError>, quarantine: bool) {
            let next = if quarantine {
                UNAVAILABLE
            } else {
                match storage {
                    Ok(true) => IDLE,
                    Ok(false) => FULL,
                    Err(_) => UNAVAILABLE,
                }
            };
            let _ = self.owner.state.compare_exchange(
                RUNNING,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            self.finished = true;
        }
    }
    impl Drop for ProbeRun<'_> {
        fn drop(&mut self) {
            if !self.finished {
                let _ = self.owner.state.compare_exchange(
                    RUNNING,
                    UNAVAILABLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }

    #[derive(Clone, Copy, Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum CleanupObservation {
        ReportAndExitConfirmed,
        NoRetainedRun,
        Quarantined,
        Unknown,
    }
    #[derive(Clone, Copy, Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum HelperExitObservation {
        Observed,
        Unavailable,
        NotStarted,
        Unknown,
    }

    #[derive(Debug, Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub(crate) enum ProbeObservation {
        Observed { counts: Counts },
        Unavailable { failure: ProbeFailureSummary },
        SupervisorFailure { failure: ProbeSupervisorError },
        CancelledBeforeProbe,
    }
    impl ProbeObservation {
        pub(crate) fn from_report(report: ReportOutcome) -> (Self, HelperExitObservation) {
            match report {
                ReportOutcome::Observed(report) => {
                    let counts = Counts(report.counts());
                    // Caption, labels and RuntimeId are intentionally destroyed
                    // here; neither serialization nor Debug receives them.
                    drop(report);
                    (Self::Observed { counts }, HelperExitObservation::Observed)
                }
                ReportOutcome::Unavailable(failure) => (
                    Self::Unavailable {
                        failure: failure.into(),
                    },
                    HelperExitObservation::Unavailable,
                ),
            }
        }
    }

    #[derive(Debug, Serialize)]
    pub(crate) struct ProbeDiagnosticRecord {
        schema: u8,
        service_pid: u32,
        correlation_slot: u8,
        started_unix_millis: Option<u64>,
        finished_unix_millis: Option<u64>,
        outcome: ProbeObservation,
        cleanup: CleanupObservation,
        helper_exit: HelperExitObservation,
    }
    impl ProbeDiagnosticRecord {
        pub(crate) fn new(
            slot: u8,
            service_pid: u32,
            started: Option<u64>,
            finished: Option<u64>,
            outcome: ProbeObservation,
            cleanup: CleanupObservation,
            helper_exit: HelperExitObservation,
        ) -> Self {
            Self {
                schema: 1,
                service_pid,
                correlation_slot: slot,
                started_unix_millis: started,
                finished_unix_millis: finished,
                outcome,
                cleanup,
                helper_exit,
            }
        }
        pub(crate) fn encode(&self) -> Result<Vec<u8>, ServiceError> {
            if self.service_pid == 0 || !(1..=8).contains(&self.correlation_slot) {
                return Err(ServiceError::ProbeUnavailable);
            }
            let mut bytes = serde_json::to_vec(self).map_err(|_| ServiceError::ProbeUnavailable)?;
            bytes.push(b'\n');
            if bytes.len() > MAX_PROBE_DIAGNOSTIC_BYTES {
                return Err(ServiceError::ProbeUnavailable);
            }
            Ok(bytes)
        }
    }

    #[derive(Debug)]
    pub(crate) struct Counts(ProbeCounts);
    impl Serialize for Counts {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut out = serializer.serialize_struct("ProbeCounts", 12)?;
            macro_rules! field {
                ($name:ident) => {
                    out.serialize_field(stringify!($name), &self.0.$name)?
                };
            }
            field!(top_level_windows);
            field!(qualified_candidates);
            field!(elements);
            field!(password_nodes_skipped);
            field!(enabled_elements);
            field!(offscreen_elements);
            field!(native_window_elements);
            field!(button_elements);
            field!(invoke_pattern_available);
            field!(value_pattern_available);
            field!(legacy_accessible_pattern_available);
            field!(maximum_depth);
            out.end()
        }
    }

    #[derive(Clone, Copy, Debug, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum ProbeFailureCategory {
        UnsupportedPlatform,
        Native64Unsupported,
        ThreadImpersonationPresent,
        SystemUserRequired,
        SystemIntegrityRequired,
        InteractiveSessionRequired,
        InteractiveWindowStationRequired,
        SecureInputDesktopProfileRequired,
        NoQualifiedConsentWindow,
        AmbiguousConsentWindows,
        TopLevelWindowLimit,
        ElementLimit,
        DepthLimit,
        CooperativeBudgetExceeded,
        ObservationChanged,
        ProviderOwnerMismatch,
        WorkerUnavailable,
        WorkerPanicked,
        ContentLimit,
        UnsupportedContent,
        CleanupFailed,
        MalformedNativeData,
        NativeCall,
    }
    #[derive(Debug, Serialize)]
    pub(crate) struct ProbeFailureSummary {
        category: ProbeFailureCategory,
        operation: Option<OperationLabel>,
        hresult: Option<i32>,
    }
    impl From<ProbeFailure> for ProbeFailureSummary {
        fn from(failure: ProbeFailure) -> Self {
            use ProbeFailure as P;
            use ProbeFailureCategory as C;
            let (category, operation, hresult) = match failure {
                P::UnsupportedPlatform => (C::UnsupportedPlatform, None, None),
                P::Native64Unsupported => (C::Native64Unsupported, None, None),
                P::ThreadImpersonationPresent => (C::ThreadImpersonationPresent, None, None),
                P::SystemUserRequired => (C::SystemUserRequired, None, None),
                P::SystemIntegrityRequired => (C::SystemIntegrityRequired, None, None),
                P::InteractiveSessionRequired => (C::InteractiveSessionRequired, None, None),
                P::InteractiveWindowStationRequired => {
                    (C::InteractiveWindowStationRequired, None, None)
                }
                P::SecureInputDesktopProfileRequired => {
                    (C::SecureInputDesktopProfileRequired, None, None)
                }
                P::NoQualifiedConsentWindow => (C::NoQualifiedConsentWindow, None, None),
                P::AmbiguousConsentWindows => (C::AmbiguousConsentWindows, None, None),
                P::TopLevelWindowLimit => (C::TopLevelWindowLimit, None, None),
                P::ElementLimit => (C::ElementLimit, None, None),
                P::DepthLimit => (C::DepthLimit, None, None),
                P::CooperativeBudgetExceeded => (C::CooperativeBudgetExceeded, None, None),
                P::ObservationChanged => (C::ObservationChanged, None, None),
                P::ProviderOwnerMismatch => (C::ProviderOwnerMismatch, None, None),
                P::WorkerUnavailable => (C::WorkerUnavailable, None, None),
                P::WorkerPanicked => (C::WorkerPanicked, None, None),
                P::ContentLimit => (C::ContentLimit, None, None),
                P::UnsupportedContent => (C::UnsupportedContent, None, None),
                P::CleanupFailed => (C::CleanupFailed, None, None),
                P::MalformedNativeData(operation) => (
                    C::MalformedNativeData,
                    Some(OperationLabel(operation)),
                    None,
                ),
                P::NativeCall { operation, hresult } => (
                    C::NativeCall,
                    Some(OperationLabel(operation)),
                    Some(hresult),
                ),
            };
            Self {
                category,
                operation,
                hresult,
            }
        }
    }
    #[derive(Debug)]
    struct OperationLabel(NativeOperation);
    impl Serialize for OperationLabel {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use NativeOperation as N;
            serializer.serialize_str(match self.0 {
                N::NativeArchitecture => "native_architecture",
                N::OpenThreadToken => "open_thread_token",
                N::OpenProcessToken => "open_process_token",
                N::TokenUser => "token_user",
                N::TokenIntegrity => "token_integrity",
                N::TokenSession => "token_session",
                N::ProcessSession => "process_session",
                N::WindowStation => "window_station",
                N::DesktopName => "desktop_name",
                N::DesktopInput => "desktop_input",
                N::OpenInputDesktop => "open_input_desktop",
                N::CloseDesktop => "close_desktop",
                N::CloseToken => "close_token",
                N::CloseProcess => "close_process",
                N::EnumerateWindows => "enumerate_windows",
                N::WindowOwner => "window_owner",
                N::OpenProcess => "open_process",
                N::ProcessImage => "process_image",
                N::SystemDirectory => "system_directory",
                N::ProcessTimes => "process_times",
                N::ProcessLiveness => "process_liveness",
                N::CompareImagePath => "compare_image_path",
                N::AttachWorkerDesktop => "attach_worker_desktop",
                N::ComInitialize => "com_initialize",
                N::CreateAutomation => "create_automation",
                N::ConfigureAutomationTimeout => "configure_automation_timeout",
                N::ElementFromWindow => "element_from_window",
                N::TreeWalker => "tree_walker",
                N::ElementProperty => "element_property",
                N::PatternAvailability => "pattern_availability",
                N::ClearProperty => "clear_property",
                N::RuntimeId => "runtime_id",
                N::ClearRuntimeId => "clear_runtime_id",
                N::Caption => "caption",
                N::Label => "label",
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{Command, ServiceControlIntent, SupervisorStage};
        use windows_prompt_probe::{LabelKind, ProbeReport, PromptContentObservation, PromptLabel};

        #[test]
        fn fixed_cli_diagnostic_is_not_a_renderer_intent_or_freeform_payload() {
            assert_eq!(Command::parse(["probe-once"]), Ok(Command::ProbeOnce));
            for args in [
                vec!["probe-once", "anything"],
                vec!["probe-once", "1"],
                vec!["probe-once=1"],
                vec!["approve"],
            ] {
                assert_eq!(Command::parse(args), Err(ServiceError::InvalidArguments));
            }
            assert!(serde_json::from_str::<ServiceControlIntent>("\"probe_once\"").is_err());
            let value = serde_json::to_value(ProbeRequestAccepted::new(42)).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"status":"requested", "service_pid":42})
            );
        }

        #[test]
        fn one_slot_is_disabled_until_scm_running_and_covers_pending_and_running() {
            let slot = ProbeAdmission::new();
            assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));
            slot.prepare(Ok(true));
            assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));
            slot.enable_after_scm_running();
            assert_eq!(slot.request(), Ok(()));
            assert_eq!(slot.request(), Err(ServiceError::ProbeBusy));
            let run = slot.take().unwrap();
            assert!(slot.take().is_none());
            assert_eq!(slot.request(), Err(ServiceError::ProbeBusy));
            assert!(!run.cancelled());
            run.finish(Ok(true), false);
            assert_eq!(slot.request(), Ok(()));
        }

        #[test]
        fn stop_cancels_pending_and_cannot_be_undone_by_running_completion() {
            let slot = ProbeAdmission::new();
            slot.prepare(Ok(true));
            slot.enable_after_scm_running();
            slot.request().unwrap();
            slot.close();
            assert!(slot.take().is_none());
            slot.enable_after_scm_running();
            assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));

            let slot = ProbeAdmission::new();
            slot.prepare(Ok(true));
            slot.enable_after_scm_running();
            slot.request().unwrap();
            let run = slot.take().unwrap();
            slot.close();
            assert!(run.cancelled());
            run.finish(Ok(true), false);
            assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));
        }

        #[test]
        fn full_storage_failure_and_unfinished_or_quarantined_run_fail_closed() {
            let full = ProbeAdmission::new();
            full.prepare(Ok(false));
            full.enable_after_scm_running();
            assert_eq!(full.request(), Err(ServiceError::ProbeSlotsFull));
            for storage in [Err(ServiceError::ProbeUnavailable), Ok(true)] {
                let slot = ProbeAdmission::new();
                slot.prepare(storage);
                slot.enable_after_scm_running();
                if storage.is_ok() {
                    slot.request().unwrap();
                    drop(slot.take().unwrap());
                }
                assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));
            }
            let slot = ProbeAdmission::new();
            slot.prepare(Ok(true));
            slot.enable_after_scm_running();
            slot.request().unwrap();
            slot.take().unwrap().finish(Ok(true), true);
            assert_eq!(slot.request(), Err(ServiceError::ProbeUnavailable));
        }

        #[test]
        fn exhausted_slots_are_reported_immediately_after_last_completed_record() {
            let slot = ProbeAdmission::new();
            slot.prepare(Ok(true));
            slot.enable_after_scm_running();
            slot.request().unwrap();
            slot.take().unwrap().finish(Ok(false), false);
            assert_eq!(slot.request(), Err(ServiceError::ProbeSlotsFull));
        }

        #[test]
        fn observation_projection_discards_all_synthetic_content_before_serialization() {
            let counts = ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 2,
                enabled_elements: 2,
                maximum_depth: 2,
                ..ProbeCounts::default()
            };
            let content = PromptContentObservation::from_parts(
                vec![739_251],
                "DO_NOT_EXPORT_SYNTHETIC_CAPTION".into(),
                vec![
                    PromptLabel::new(
                        1,
                        2,
                        LabelKind::Text,
                        true,
                        "DO_NOT_EXPORT_SYNTHETIC_LABEL".into(),
                    )
                    .unwrap(),
                ],
            )
            .unwrap();
            let report = ProbeReport::from_observation(counts, content).unwrap();
            let (observation, helper_exit) =
                ProbeObservation::from_report(ReportOutcome::Observed(report));
            let record = ProbeDiagnosticRecord::new(
                1,
                42,
                Some(1),
                Some(2),
                observation,
                CleanupObservation::ReportAndExitConfirmed,
                helper_exit,
            );
            let text = String::from_utf8(record.encode().unwrap()).unwrap();
            for forbidden in [
                "DO_NOT_EXPORT",
                "739251",
                "caption",
                "labels",
                "runtime_id",
                "content",
                "signature",
                "challenge",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "sensitive field reached metadata-only record"
                );
                assert!(!format!("{record:?}").contains("DO_NOT_EXPORT"));
            }
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["outcome"]["kind"], "observed");
            assert_eq!(value["outcome"]["counts"]["elements"], 2);
            assert_eq!(value["helper_exit"], "observed");
            assert_eq!(value.as_object().unwrap().len(), 8);
        }

        #[test]
        fn fixed_schema_bounds_pid_slot_and_numeric_error_details() {
            let make = |slot, pid| {
                ProbeDiagnosticRecord::new(
                    slot,
                    pid,
                    Some(u64::MAX),
                    Some(u64::MAX),
                    ProbeObservation::SupervisorFailure {
                        failure: ProbeSupervisorError::Native {
                            stage: SupervisorStage::CleanupWait,
                            hresult: i32::MIN,
                        },
                    },
                    CleanupObservation::Quarantined,
                    HelperExitObservation::Unknown,
                )
            };
            for (slot, pid) in [(0, 1), (9, 1), (1, 0)] {
                assert!(make(slot, pid).encode().is_err());
            }
            let bytes = make(8, u32::MAX).encode().unwrap();
            assert!(bytes.len() <= MAX_PROBE_DIAGNOSTIC_BYTES);
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["outcome"]["failure"]["kind"], "native");
            assert_eq!(
                value["outcome"]["failure"]["detail"]["stage"],
                "cleanup_wait"
            );
            assert_eq!(value["outcome"]["failure"]["detail"]["hresult"], i32::MIN);
            let (unavailable, exit) = ProbeObservation::from_report(ReportOutcome::Unavailable(
                ProbeFailure::NativeCall {
                    operation: NativeOperation::ConfigureAutomationTimeout,
                    hresult: i32::MAX,
                },
            ));
            let record = ProbeDiagnosticRecord::new(
                2,
                1,
                None,
                None,
                unavailable,
                CleanupObservation::ReportAndExitConfirmed,
                exit,
            );
            assert!(record.encode().unwrap().len() <= MAX_PROBE_DIAGNOSTIC_BYTES);
            for cleanup in [
                CleanupObservation::NoRetainedRun,
                CleanupObservation::Unknown,
            ] {
                let record = ProbeDiagnosticRecord::new(
                    3,
                    1,
                    None,
                    None,
                    ProbeObservation::CancelledBeforeProbe,
                    cleanup,
                    HelperExitObservation::NotStarted,
                );
                assert!(record.encode().unwrap().len() <= MAX_PROBE_DIAGNOSTIC_BYTES);
            }
        }

        #[test]
        fn diagnostic_names_and_control_are_closed_fixed_sets() {
            assert_eq!(PROBE_CONTROL_CODE, 128);
            assert_eq!(PROBE_DIAGNOSTIC_FILES.len(), 8);
            let unique: std::collections::BTreeSet<_> =
                PROBE_DIAGNOSTIC_FILES.into_iter().collect();
            assert_eq!(unique.len(), 8);
            for name in unique {
                assert!(name.starts_with("probe-once-") && name.ends_with(".json"));
                assert!(!name.contains(['/', '\\', ':']) && !name.contains(".."));
                assert!(name.len() < 64);
            }
        }
    }
}

#[cfg(any(windows, test))]
pub(crate) use owned::*;
