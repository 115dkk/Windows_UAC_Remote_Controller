// SPDX-License-Identifier: GPL-2.0-or-later
//! Single live consent-prompt state and bounded content projection.
#![forbid(unsafe_code)]

use std::{fmt, sync::Arc, time::Instant};

use approval_core::{AuthorizedDecision, PendingChallenge, RequestTtl};
use approval_protocol::{DecisionPurpose, DeviceId, RequestBinding, RequestContent, RequestId};
use service_protocol::{PcEvent, RequestResolution, ServiceTick};
use windows_prompt_probe::{LabelKind, ProbeReport};

use crate::{ProbeSupervisorError, PromptAction, TargetIdentity};

pub(super) fn request_ttl() -> RequestTtl {
    RequestTtl::from_millis(110_000).expect("fixed request TTL must be valid")
}
const MAX_PROGRAM_NAME_BYTES: usize = 512;
const MAX_DETAILS_BYTES: usize = 8_192;

pub(crate) trait PromptApply {
    fn apply_prompt(
        &mut self,
        target: TargetIdentity,
        action: PromptAction,
        content_digest: [u8; 32],
    ) -> Result<(), ProbeSupervisorError>;
}

pub(super) struct LivePrompt {
    pub(super) target: TargetIdentity,
    pub(super) content: Arc<RequestContent>,
    pub(super) content_digest: [u8; 32],
    lease: LiveLease,
    applying: Option<(DeviceId, DecisionPurpose)>,
}

/// One immutable signed lease and the immediate predecessor needed on reconnect.
/// Only LivePrompt replaces these facts together. This is presentation state,
/// not an authorization owner; the engine alone creates replacement challenges.
struct LiveLease {
    binding: RequestBinding,
    issued_at: ServiceTick,
    deadline: Instant,
    predecessor: Option<(RequestBinding, ServiceTick)>,
}

impl LivePrompt {
    pub(super) fn opened(
        target: TargetIdentity,
        challenge: &PendingChallenge,
        content: Arc<RequestContent>,
        content_digest: [u8; 32],
        issued_at: ServiceTick,
        deadline: Instant,
    ) -> Self {
        Self {
            target,
            content,
            content_digest,
            lease: LiveLease {
                binding: challenge.binding(),
                issued_at,
                deadline,
                predecessor: None,
            },
            applying: None,
        }
    }

    pub(super) fn binding(&self) -> RequestBinding {
        self.lease.binding
    }

    pub(super) fn request_id(&self) -> RequestId {
        self.lease.binding.request_id()
    }

    pub(super) fn deadline(&self) -> Instant {
        self.lease.deadline
    }

    pub(super) fn is_applying(&self) -> bool {
        self.applying.is_some()
    }

    pub(super) fn applying_purpose(&self) -> Option<DecisionPurpose> {
        self.applying.map(|(_, purpose)| purpose)
    }

    /// A fresh same-content native observation is required by the caller.
    /// This gate only narrows when that observation may renew a signed lease.
    pub(super) fn can_renew(&self, target: TargetIdentity, now: Instant) -> bool {
        self.target == target
            && !self.is_applying()
            && now < self.deadline()
            && self.deadline().duration_since(now) <= std::time::Duration::from_secs(30)
    }

    /// Called only with the engine's exact-binding renewal result. It preserves
    /// the native target/content and decision state, replacing lease facts once.
    pub(super) fn renew(
        &mut self,
        challenge: &PendingChallenge,
        issued_at: ServiceTick,
        deadline: Instant,
    ) {
        self.lease = LiveLease {
            binding: challenge.binding(),
            issued_at,
            deadline,
            predecessor: Some((self.lease.binding, self.lease.issued_at)),
        };
    }

    /// Both initial publication and reconnect use the retained signed kind.
    /// A renewed lease must never masquerade as an original Opened request.
    pub(super) fn publication(&self) -> PcEvent {
        match self.lease.predecessor {
            Some((previous_binding, previous_issued_at)) => PcEvent::Renewed {
                previous_binding,
                previous_issued_at,
                binding: self.lease.binding,
                issued_at: self.lease.issued_at,
                content: Arc::clone(&self.content),
            },
            None => PcEvent::Opened {
                binding: self.lease.binding,
                issued_at: self.lease.issued_at,
                content: Arc::clone(&self.content),
            },
        }
    }

    pub(super) fn resolution(&self, result: PromptResult) -> PcEvent {
        PcEvent::Resolved {
            binding: self.lease.binding,
            issued_at: self.lease.issued_at,
            outcome: result.resolution(),
        }
    }

    pub(super) fn matches_authorized(&self, authorized: &AuthorizedDecision, now: Instant) -> bool {
        self.binding() == authorized.binding()
            && authorized.binding().session().logon_id() == 0
            && self.content.as_ref() == authorized.content()
            && now < self.deadline()
            && !self.is_applying()
    }

    /// Record only an already-dispatched native action for this exact lease.
    pub(super) fn mark_applying(
        &mut self,
        target: TargetIdentity,
        binding: RequestBinding,
        device: DeviceId,
        purpose: DecisionPurpose,
    ) -> bool {
        if self.target != target || self.binding() != binding || self.is_applying() {
            return false;
        }
        self.applying = Some((device, purpose));
        true
    }
}

impl fmt::Debug for LivePrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LivePrompt([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WithdrawnPrompt {
    pub(super) binding: RequestBinding,
    pub(super) deadline: Instant,
}

#[derive(Default)]
pub(super) struct PromptState {
    live: Option<LivePrompt>,
    withdrawn: Option<WithdrawnPrompt>,
}

impl PromptState {
    pub(super) fn live(&self) -> Option<&LivePrompt> {
        self.live.as_ref()
    }

    pub(super) fn live_mut(&mut self) -> Option<&mut LivePrompt> {
        self.live.as_mut()
    }

    pub(super) fn replace(&mut self, prompt: LivePrompt) {
        self.live = Some(prompt);
    }

    pub(super) fn take(&mut self) -> Option<LivePrompt> {
        self.live.take()
    }

    pub(super) fn is_live(&self) -> bool {
        self.live.is_some()
    }

    pub(super) fn remember_withdrawn(&mut self, binding: RequestBinding, deadline: Instant) {
        self.withdrawn = Some(WithdrawnPrompt { binding, deadline });
    }

    pub(super) fn withdrawn(&self) -> Option<WithdrawnPrompt> {
        self.withdrawn
    }

    pub(super) fn take_withdrawn(&mut self) -> Option<WithdrawnPrompt> {
        self.withdrawn.take()
    }

    pub(super) fn clear_withdrawn_if_expired(&mut self, now: Instant) {
        if self
            .withdrawn
            .is_some_and(|withdrawn| now >= withdrawn.deadline)
        {
            self.withdrawn = None;
        }
    }
}

impl fmt::Debug for PromptState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptState")
            .field("live", &self.live.is_some())
            .field("withdrawn", &self.withdrawn.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptResult {
    Approved,
    Denied,
    Cancelled,
    Expired,
    FailedRejected,
    FailedUnknown,
}

impl PromptResult {
    pub(super) const fn resolution(self) -> RequestResolution {
        match self {
            Self::Approved => RequestResolution::Approved,
            Self::Denied => RequestResolution::Denied,
            Self::Cancelled => RequestResolution::Cancelled,
            Self::Expired => RequestResolution::Expired,
            Self::FailedRejected | Self::FailedUnknown => RequestResolution::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PromptProgress {
    observed: bool,
    queued_opened: usize,
    result: Option<PromptResult>,
}

impl PromptProgress {
    pub(super) const fn opened(queued_opened: usize, result: Option<PromptResult>) -> Self {
        Self {
            observed: true,
            queued_opened,
            result,
        }
    }

    pub(super) const fn resolved(result: PromptResult) -> Self {
        Self {
            observed: false,
            queued_opened: 0,
            result: Some(result),
        }
    }

    pub const fn observed(self) -> bool {
        self.observed
    }

    pub const fn queued_opened(self) -> usize {
        self.queued_opened
    }
    pub const fn delivery_failed(self) -> bool {
        self.observed && self.queued_opened == 0
    }

    pub const fn result(self) -> Option<PromptResult> {
        self.result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PromptContentMappingError {
    #[error("a mapped prompt field exceeds its fixed UTF-8 limit")]
    FieldTooLong,
    #[error("the mapped prompt content is invalid")]
    InvalidContent,
}

pub(super) fn map_content(
    report: &ProbeReport,
) -> Result<Arc<RequestContent>, PromptContentMappingError> {
    let observation = report.content();
    // Only a provider-authored LabeledBy relationship identifies a field. A
    // caption is the neutral fallback; text order and path-looking values do
    // not prove that a string is the program, publisher, command or location.
    let caption = replace_controls(observation.caption());
    let program_name = provider_field(observation.labels(), ProviderField::Program)
        .map(replace_controls)
        .unwrap_or(caption);
    if program_name.is_empty() || program_name.len() > MAX_PROGRAM_NAME_BYTES {
        return Err(PromptContentMappingError::FieldTooLong);
    }

    let mapped_labels: Vec<String> = observation
        .labels()
        .iter()
        .map(|label| {
            let value = replace_controls(label.text());
            if label.provider_label().is_empty() {
                value
            } else {
                format!(
                    "{}: {value}",
                    replace_controls(label.provider_label()).trim_end_matches([':', '：'])
                )
            }
        })
        .collect();
    let path = provider_field(observation.labels(), ProviderField::Location)
        .filter(|value| is_path(value))
        .map(replace_controls)
        .unwrap_or_default();
    let details = mapped_labels.join("\n");
    if details.len() > MAX_DETAILS_BYTES {
        return Err(PromptContentMappingError::FieldTooLong);
    }
    // The dialog's shape, so a later rule can name the program, the publisher
    // and the details control without reading the language they are written in.
    // Identifiers and positions only; the text is what this is careful not to
    // write, and it is the only part that carries the request.
    // Windows only. The sink is this machine's own event log and the rows can
    // only ever describe a dialog the probe met on the secure desktop; every
    // other target reaches this function with a report built by a test.
    #[cfg(windows)]
    crate::ffi::prompt_diagnostics::begin();
    #[cfg(windows)]
    for label in observation.labels() {
        crate::ffi::prompt_diagnostics::label(
            label.ordinal(),
            label.depth(),
            match label.kind() {
                LabelKind::Text => "Text",
                LabelKind::Button => "Button",
                LabelKind::Hyperlink => "Hyperlink",
            },
            label.enabled(),
            label.automation_id(),
            label.class_name(),
        );
    }
    // Disposable lab builds only, where the only prompt is the harness's own
    // synthetic request. The harness asserts on the program name and the
    // location, so the mapped fields and the labels they come from have to be
    // readable. Release packaging rejects any binary carrying a lab marker.
    #[cfg(all(windows, feature = "lab-software-identity"))]
    {
        crate::lab::record_note(&format!(
            "prompt content: program_name={program_name:?} path={path:?} labels={}",
            mapped_labels.len()
        ));
        for (index, label) in observation.labels().iter().enumerate() {
            crate::lab::record_note(&format!(
                "prompt label {index}: kind={:?} text={:?}",
                label.kind(),
                replace_controls(label.text())
            ));
        }
    }
    RequestContent::new(&program_name, &path, &details)
        .map(Arc::new)
        .map_err(|_| PromptContentMappingError::InvalidContent)
}

fn replace_controls(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character != '\n' && character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
enum ProviderField {
    Program,
    Location,
}

fn provider_field(
    labels: &[windows_prompt_probe::PromptLabel],
    field: ProviderField,
) -> Option<&str> {
    let names: &[&str] = match field {
        ProviderField::Program => &["Program name", "App name", "프로그램 이름", "앱 이름"],
        ProviderField::Location => &[
            "Program location",
            "File location",
            "프로그램 위치",
            "파일 위치",
        ],
    };
    let mut fields = labels.iter().filter(|label| {
        label.kind() == LabelKind::Text
            && names.iter().any(|name| {
                label
                    .provider_label()
                    .trim()
                    .trim_end_matches([':', '：'])
                    .trim()
                    .eq_ignore_ascii_case(name)
            })
    });
    match (fields.next(), fields.next()) {
        (Some(label), None) if !label.text().trim().is_empty() => Some(label.text()),
        _ => None,
    }
}

fn is_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('\\')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\')
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_phone_is_one_delivery_failure_not_a_periodic_poll_event() {
        assert!(super::PromptProgress::opened(0, None).delivery_failed());
        assert!(!super::PromptProgress::opened(1, None).delivery_failed());
        assert!(!super::PromptProgress::default().delivery_failed());
        assert!(!super::PromptProgress::resolved(super::PromptResult::Cancelled).delivery_failed());
    }
    use super::*;
    use windows_prompt_probe::{ProbeCounts, PromptContentObservation, PromptLabel};

    fn report(caption: &str, texts: &[(&str, LabelKind)]) -> ProbeReport {
        let labels = texts
            .iter()
            .enumerate()
            .map(|(index, (text, kind))| {
                PromptLabel::new(
                    u16::try_from(index).unwrap(),
                    1,
                    *kind,
                    true,
                    (*text).into(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let content =
            PromptContentObservation::from_parts(vec![1], caption.into(), labels).unwrap();
        ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: u16::try_from(texts.len()).unwrap(),
                enabled_elements: u16::try_from(texts.len()).unwrap(),
                button_elements: u16::try_from(
                    texts
                        .iter()
                        .filter(|(_, kind)| *kind == LabelKind::Button)
                        .count(),
                )
                .unwrap(),
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            content,
        )
        .unwrap()
    }

    #[test]
    fn provider_relationships_distinguish_program_location_and_publisher() {
        let base = report(
            "Consent",
            &[
                ("C:\\Misleading\\program-name.exe", LabelKind::Text),
                ("C:\\Actual\\program.exe", LabelKind::Text),
                ("Example publisher", LabelKind::Text),
                ("C:\\Actual\\program.exe --inert", LabelKind::Text),
            ],
        );
        let labels = base
            .content()
            .labels()
            .iter()
            .cloned()
            .zip([
                "Program name:",
                "Program location:",
                "Publisher:",
                "Command line:",
            ])
            .map(|(label, name)| label.with_provider_label(name.into()).unwrap())
            .collect();
        let observed =
            PromptContentObservation::from_parts(vec![1], "Consent".into(), labels).unwrap();
        let mapped =
            map_content(&ProbeReport::from_observation(base.counts(), observed).unwrap()).unwrap();
        assert_eq!(mapped.program_name(), "C:\\Misleading\\program-name.exe");
        assert_eq!(mapped.path(), "C:\\Actual\\program.exe");
        assert!(mapped.details().contains("Publisher: Example publisher"));
        assert!(
            mapped
                .details()
                .contains("Command line: C:\\Actual\\program.exe --inert")
        );
    }

    #[test]
    fn ambiguous_provider_program_names_use_neutral_caption() {
        let base = report(
            "Consent",
            &[("first", LabelKind::Text), ("second", LabelKind::Text)],
        );
        let labels = base
            .content()
            .labels()
            .iter()
            .cloned()
            .map(|label| label.with_provider_label("프로그램 이름:".into()).unwrap())
            .collect();
        let observed =
            PromptContentObservation::from_parts(vec![1], "Consent".into(), labels).unwrap();
        let mapped =
            map_content(&ProbeReport::from_observation(base.counts(), observed).unwrap()).unwrap();
        assert_eq!(mapped.program_name(), "Consent");
        assert_eq!(mapped.path(), "");
    }

    #[test]
    fn mapping_preserves_details_without_guessing_program_or_path_from_position() {
        let value = report(
            "Caption\t",
            &[
                ("First\rtext", LabelKind::Text),
                ("\\\\server\\tool.exe", LabelKind::Hyperlink),
                ("C:\\later.exe", LabelKind::Text),
                ("Yes", LabelKind::Button),
            ],
        );
        let mapped = map_content(&value).unwrap();
        assert_eq!(mapped.program_name(), "Caption ");
        assert_eq!(mapped.path(), "");
        assert_eq!(
            mapped.details(),
            "First text\n\\\\server\\tool.exe\nC:\\later.exe\nYes"
        );
    }

    #[test]
    fn unlabelled_program_and_icon_remain_details_not_guessed_identity() {
        // The shape the current Windows consent dialog presents: its own title
        // as a text element, then the shield glyph, and only then the question
        // and the program. Both leading labels used to fill the two naming
        // places, so the phone was told the dialog's name instead of the app's.
        let value = report(
            "User Account Control",
            &[
                ("User Account Control", LabelKind::Text),
                ("Close", LabelKind::Button),
                ("\u{e8bb}", LabelKind::Text),
                ("Do you want to allow this app?", LabelKind::Text),
                ("uac-ci-request.exe", LabelKind::Text),
                ("Publisher: Unknown", LabelKind::Text),
                ("Yes", LabelKind::Button),
            ],
        );
        let mapped = map_content(&value).unwrap();
        assert_eq!(mapped.program_name(), "User Account Control");
        assert!(mapped.details().contains("uac-ci-request.exe"));
        assert_eq!(mapped.path(), ""); // A collapsed dialog shows no location.
    }

    #[test]
    fn mapping_accepts_exact_byte_bounds_and_never_truncates_over_limit_values() {
        let caption = "a".repeat(MAX_PROGRAM_NAME_BYTES);
        let exact = report(&caption, &[("C:\\x", LabelKind::Hyperlink)]);
        assert_eq!(map_content(&exact).unwrap().program_name().len(), 512);
        let over = report(
            &"a".repeat(MAX_PROGRAM_NAME_BYTES + 1),
            &[("C:\\x", LabelKind::Hyperlink)],
        );
        assert_eq!(
            map_content(&over),
            Err(PromptContentMappingError::FieldTooLong)
        );

        let path = "C:\\x";
        let suffix = "d".repeat(MAX_DETAILS_BYTES - path.len() - 1);
        let exact = report("x", &[(path, LabelKind::Text), (&suffix, LabelKind::Text)]);
        assert_eq!(
            map_content(&exact).unwrap().details().len(),
            MAX_DETAILS_BYTES
        );
        let suffix = format!("{suffix}d");
        let over = report("x", &[(path, LabelKind::Text), (&suffix, LabelKind::Text)]);
        assert_eq!(
            map_content(&over),
            Err(PromptContentMappingError::FieldTooLong)
        );
    }

    #[test]
    fn absent_path_maps_to_an_empty_legal_path() {
        let value = report("caption", &[("publisher", LabelKind::Text)]);
        let mapped = map_content(&value).unwrap();
        assert_eq!(mapped.program_name(), "caption");
        assert_eq!(mapped.path(), "");
        assert_eq!(mapped.details(), "publisher");
    }

    #[test]
    fn oversized_text_label_is_left_out_of_the_program_name_but_kept_whole_in_details() {
        let long = "d".repeat(MAX_PROGRAM_NAME_BYTES);
        let value = report(
            "caption",
            &[(&long, LabelKind::Text), ("C:\\tool.exe", LabelKind::Text)],
        );
        let mapped = map_content(&value).unwrap();
        assert_eq!(mapped.program_name(), "caption");
        assert_eq!(mapped.details(), format!("{long}\nC:\\tool.exe"));
    }
}
