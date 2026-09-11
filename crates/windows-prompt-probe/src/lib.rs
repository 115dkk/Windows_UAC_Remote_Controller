// SPDX-License-Identifier: GPL-2.0-or-later
//! Supervised consent-UI observation and exact-target watch support.
//!
//! The argument-free one-shot observation remains read-only. Watch mode accepts
//! actions only from the authenticated service channel and invokes one matching
//! UIA button after target and content checks. Native/UIA calls may still block
//! despite configured timeouts, so the service must supervise this process.
//! Owned handles and interfaces remain scoped, and cleanup uncertainty changes a
//! would-be successful result into failure.
#![deny(unsafe_code)]

use std::{ffi::OsStr, fmt};

mod action;
pub use action::{ActionSelectionError, ActionTarget, PromptAction, select_action_target};
mod content;
pub use content::{
    LabelKind, MAX_BUTTON_METADATA_UTF16_UNITS, MAX_PROMPT_CONTENT_UTF8_BYTES,
    MAX_PROMPT_FIELD_UTF16_UNITS, MAX_PROMPT_LABELS, MAX_RUNTIME_ID_VALUES, PromptContentError,
    PromptContentObservation, PromptLabel, prompt_text_from_utf16,
};
pub mod supervision;

pub fn run_watch_helper() -> supervision::HelperExit {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        ffi::pipe_client::run_watch()
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        supervision::HelperExit::Rejected
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[allow(unsafe_code)]
mod ffi;
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
mod policy;

pub const MAX_TOP_LEVEL_WINDOWS: usize = 128;
pub const MAX_UIA_ELEMENTS: usize = 128;
pub const MAX_UIA_DEPTH: u8 = 16;
pub const SUPERVISOR_BUDGET_MILLIS: u64 = 5_000;
pub const UIA_TIMEOUT_MILLIS: u32 = 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    ObserveOnce,
    Watch,
}
impl Command {
    pub fn parse<I, S>(arguments: I) -> Result<Self, CommandParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut arguments = arguments.into_iter();
        match (arguments.next(), arguments.next()) {
            (None, None) => Ok(Self::ObserveOnce),
            (Some(argument), None) if argument.as_ref() == OsStr::new("watch") => Ok(Self::Watch),
            _ => Err(CommandParseError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandParseError;
impl fmt::Display for CommandParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid helper command")
    }
}
impl std::error::Error for CommandParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOperation {
    NativeArchitecture,
    OpenThreadToken,
    OpenProcessToken,
    TokenUser,
    TokenIntegrity,
    TokenSession,
    ProcessSession,
    WindowStation,
    DesktopName,
    DesktopInput,
    OpenInputDesktop,
    CloseDesktop,
    CloseToken,
    CloseProcess,
    EnumerateWindows,
    WindowOwner,
    OpenProcess,
    ProcessImage,
    SystemDirectory,
    ProcessTimes,
    ProcessLiveness,
    CompareImagePath,
    AttachWorkerDesktop,
    ComInitialize,
    CreateAutomation,
    ConfigureAutomationTimeout,
    ElementFromWindow,
    TreeWalker,
    ElementProperty,
    PatternAvailability,
    ClearProperty,
    RuntimeId,
    ClearRuntimeId,
    Caption,
    Label,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeFailure {
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
    MalformedNativeData(NativeOperation),
    NativeCall {
        operation: NativeOperation,
        hresult: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupFailure {
    pub failures: u16,
    pub first_operation: NativeOperation,
    pub first_hresult: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeError {
    failure: ProbeFailure,
    cleanup: Option<CleanupFailure>,
}

impl ProbeError {
    pub const fn failure(self) -> ProbeFailure {
        self.failure
    }
    pub const fn cleanup(self) -> Option<CleanupFailure> {
        self.cleanup
    }
    pub(crate) const fn new(failure: ProbeFailure) -> Self {
        Self {
            failure,
            cleanup: None,
        }
    }
}
impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}; cleanup={:?}", self.failure, self.cleanup)
    }
}
impl std::error::Error for ProbeError {}

/// Counts only. None of these fields conveys authentication or permission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProbeCounts {
    pub top_level_windows: u16,
    pub qualified_candidates: u16,
    pub elements: u16,
    pub password_nodes_skipped: u16,
    pub enabled_elements: u16,
    pub offscreen_elements: u16,
    pub native_window_elements: u16,
    pub button_elements: u16,
    pub invoke_pattern_available: u16,
    pub value_pattern_available: u16,
    pub legacy_accessible_pattern_available: u16,
    pub maximum_depth: u8,
}

/// Bounded read-only observation, not recognized operation or live target proof.
/// Success always contains content; counts alone cannot construct this report.
#[derive(Clone, Eq, PartialEq)]
pub struct ProbeReport {
    counts: ProbeCounts,
    content: PromptContentObservation,
}
impl ProbeReport {
    pub fn from_observation(
        counts: ProbeCounts,
        content: PromptContentObservation,
    ) -> Result<Self, PromptContentError> {
        content.validate_counts(counts)?;
        Ok(Self { counts, content })
    }
    pub const fn counts(&self) -> ProbeCounts {
        self.counts
    }
    pub const fn content(&self) -> &PromptContentObservation {
        &self.content
    }
}
impl fmt::Debug for ProbeReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeReport")
            .field("counts", &self.counts)
            .field("content", &self.content)
            .finish()
    }
}

/// Own SYSTEM/system IL/nonzero session/interactive-station checks precede any
/// bounded UIA traversal. The candidate's OS-resolved System32 image-path match
/// is NOT mapped-image, Authenticode, requested-executable or atomic identity proof.
/// No caller-supplied process, window, desktop, session, text or action is accepted.
pub fn probe_once() -> Result<ProbeReport, ProbeError> {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        ffi::probe()
    }
    #[cfg(all(windows, not(target_pointer_width = "64")))]
    {
        Err(ProbeError::new(ProbeFailure::Native64Unsupported))
    }
    #[cfg(not(windows))]
    {
        Err(ProbeError::new(ProbeFailure::UnsupportedPlatform))
    }
}

#[cfg(any(all(windows, target_pointer_width = "64"), test))]
pub(crate) fn finish_with_cleanup<T>(
    result: Result<T, ProbeError>,
    cleanup: Option<CleanupFailure>,
) -> Result<T, ProbeError> {
    match (result, cleanup) {
        (Ok(value), None) => Ok(value),
        (Err(error), None) => Err(error),
        (result, Some(cleanup)) => Err(ProbeError {
            failure: result
                .err()
                .map_or(ProbeFailure::CleanupFailed, |error| error.failure),
            cleanup: Some(cleanup),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_parser_accepts_only_no_arguments_or_exact_watch() {
        assert_eq!(Command::parse(Vec::<&str>::new()), Ok(Command::ObserveOnce));
        assert_eq!(Command::parse(["watch"]), Ok(Command::Watch));
        for arguments in [
            vec!["WATCH"],
            vec!["watch", "extra"],
            vec!["observe"],
            vec![""],
        ] {
            assert_eq!(Command::parse(arguments), Err(CommandParseError));
        }
    }

    #[test]
    fn primary_failure_is_preserved_alongside_cleanup_failure() {
        let cleanup = CleanupFailure {
            failures: 2,
            first_operation: NativeOperation::CloseDesktop,
            first_hresult: -1,
        };
        let result = finish_with_cleanup::<()>(
            Err(ProbeError::new(ProbeFailure::ThreadImpersonationPresent)),
            Some(cleanup),
        )
        .unwrap_err();
        assert_eq!(result.failure(), ProbeFailure::ThreadImpersonationPresent);
        assert_eq!(result.cleanup(), Some(cleanup));
        assert_eq!(
            finish_with_cleanup(Ok(()), Some(cleanup))
                .unwrap_err()
                .failure(),
            ProbeFailure::CleanupFailed
        );
    }

    #[test]
    fn clean_result_stays_clean_and_diagnostics_contain_fixed_metadata_only() {
        assert_eq!(finish_with_cleanup(Ok(7), None), Ok(7));
        let error = ProbeError::new(ProbeFailure::NoQualifiedConsentWindow);
        assert_eq!(format!("{error}"), "NoQualifiedConsentWindow; cleanup=None");
        assert_eq!(finish_with_cleanup::<()>(Err(error), None), Err(error));
    }
}
