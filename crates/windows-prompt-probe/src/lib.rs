// SPDX-License-Identifier: GPL-2.0-or-later
//! Supervised consent-UI observation and exact-target watch support.
//!
//! The one-shot observation remains read-only. Watch mode accepts
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
    LabelKind, MAX_LABEL_METADATA_UTF16_UNITS, MAX_PROMPT_CONTENT_UTF8_BYTES,
    MAX_PROMPT_FIELD_UTF16_UNITS, MAX_PROMPT_LABELS, MAX_RUNTIME_ID_VALUES, PromptContentError,
    PromptContentObservation, PromptLabel, prompt_text_from_utf16,
};
pub mod pairing_inspection;
pub mod supervision;

pub fn run_pairing_inspector(
    mut inspector: impl pairing_inspection::Inspector,
) -> supervision::HelperExit {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        ffi::pipe_client::run_pairing_inspector(&mut inspector)
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        let _ = &mut inspector;
        supervision::HelperExit::Rejected
    }
}

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
#[cfg(any(all(windows, target_pointer_width = "64"), test))]
mod settle;

pub const MAX_TOP_LEVEL_WINDOWS: usize = 128;
pub const MAX_UIA_ELEMENTS: usize = 128;
pub const MAX_UIA_DEPTH: u8 = 16;
pub const SUPERVISOR_BUDGET_MILLIS: u64 = 5_000;
pub const UIA_TIMEOUT_MILLIS: u32 = 1_000;

/// A validated pipe-name suffix, not an authentication credential. Both peers
/// still authenticate the connected process independently of this argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionPipeToken(String);
impl SupervisionPipeToken {
    pub fn parse(value: &OsStr) -> Result<Self, CommandParseError> {
        let value = value.to_str().ok_or(CommandParseError)?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CommandParseError);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn argument(&self) -> &str {
        &self.0
    }

    pub fn pipe_name(&self) -> String {
        format!(r"\\.\pipe\UacRemoteController.PromptProbe.v4.{}", self.0)
    }
}

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
        match (arguments.next(), arguments.next(), arguments.next()) {
            (Some(token), None, None) => {
                SupervisionPipeToken::parse(token.as_ref())?;
                Ok(Self::ObserveOnce)
            }
            (Some(mode), Some(token), None) if mode.as_ref() == OsStr::new("watch") => {
                SupervisionPipeToken::parse(token.as_ref())?;
                Ok(Self::Watch)
            }
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

impl ProbeCounts {
    /// Equality for the prompt a census found, not for the desktop it stood on.
    /// Every field here describes the observed prompt except `top_level_windows`,
    /// which counts every top-level window on the secure desktop including the
    /// hidden ones that are never candidates. Winlogon creates and destroys those
    /// while a prompt is up, so comparing that number turns unrelated desktop
    /// activity into a refused decision, and refusing the user's own approval is
    /// the expensive way to be wrong. Whether this prompt is still the only
    /// candidate is a different question, asked separately and answered first.
    /// Written as a field override rather than a list so a field added later is
    /// compared by default instead of silently dropping out of the comparison.
    #[must_use]
    pub fn describes_the_same_prompt(self, other: Self) -> bool {
        Self {
            top_level_windows: 0,
            ..self
        } == Self {
            top_level_windows: 0,
            ..other
        }
    }
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
    fn command_parser_requires_token_for_one_shot_and_exact_watch() {
        let token = "0123456789abcdef0123456789abcdef";
        assert_eq!(Command::parse([token]), Ok(Command::ObserveOnce));
        assert_eq!(Command::parse(["watch", token]), Ok(Command::Watch));
        for arguments in [
            vec![],
            vec!["watch"],
            vec!["WATCH", token],
            vec!["watch", "extra"],
            vec!["observe", token],
            vec![""],
            vec![token, "extra"],
            vec!["watch", token, "extra"],
        ] {
            assert_eq!(Command::parse(arguments), Err(CommandParseError));
        }
    }

    #[test]
    fn supervision_pipe_token_round_trips_and_rejects_noncanonical_arguments() {
        let text = "0123456789abcdef0123456789abcdef";
        let token = SupervisionPipeToken::parse(OsStr::new(text)).unwrap();
        assert_eq!(token.argument(), text);
        assert_eq!(
            SupervisionPipeToken::parse(OsStr::new(token.argument())),
            Ok(token.clone())
        );
        assert_eq!(
            token.pipe_name(),
            format!(r"\\.\pipe\UacRemoteController.PromptProbe.v4.{text}")
        );
        for invalid in [
            "".to_owned(),
            text[..31].to_owned(),
            format!("{text}0"),
            text.to_uppercase(),
            "g".repeat(32),
            "é".repeat(16),
            format!("{} ", &text[..31]),
            format!("{}\0", &text[..31]),
        ] {
            assert_eq!(
                SupervisionPipeToken::parse(OsStr::new(&invalid)),
                Err(CommandParseError)
            );
            assert_eq!(Command::parse([invalid.as_str()]), Err(CommandParseError));
            assert_eq!(
                Command::parse(["watch", invalid.as_str()]),
                Err(CommandParseError)
            );
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
