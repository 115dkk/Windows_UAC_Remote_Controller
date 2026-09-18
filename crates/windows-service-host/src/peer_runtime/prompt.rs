// SPDX-License-Identifier: GPL-2.0-or-later
//! Single live consent-prompt state and bounded content projection.
#![forbid(unsafe_code)]

use std::{fmt, sync::Arc, time::Instant};

use approval_core::RequestTtl;
use approval_protocol::{DecisionPurpose, DeviceId, RequestBinding, RequestContent, RequestId};
use service_protocol::{RequestResolution, ServiceTick};
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
    pub(super) session_id: u32,
    pub(super) binding: RequestBinding,
    pub(super) request_id: RequestId,
    pub(super) content: Arc<RequestContent>,
    pub(super) content_digest: [u8; 32],
    pub(super) issued_at: ServiceTick,
    pub(super) deadline: Instant,
    pub(super) applying: Option<(DeviceId, DecisionPurpose)>,
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

const PROGRAM_NAME_SEPARATOR: &str = " · ";

pub(super) fn map_content(
    report: &ProbeReport,
) -> Result<Arc<RequestContent>, PromptContentMappingError> {
    let observation = report.content();
    // The caption followed by the first two naming Text labels names the
    // program. A dialog that repeats its own title as a text element, or that
    // draws its shield from a private-use icon font, names nothing: skipping
    // those keeps the two places that carry the request and the program. A
    // label that would push the name over its byte bound is left out whole;
    // the labels themselves are never cut, and every label stays in details.
    let caption = replace_controls(observation.caption());
    let mut program_name = caption.clone();
    let mut considered = 0_u8;
    for label in observation
        .labels()
        .iter()
        .filter(|label| label.kind() == LabelKind::Text)
    {
        if considered == 2 {
            break;
        }
        let part = replace_controls(label.text());
        if !names_program(&part, &caption) {
            continue;
        }
        considered += 1;
        let separator = if program_name.is_empty() {
            ""
        } else {
            PROGRAM_NAME_SEPARATOR
        };
        if program_name.len() + separator.len() + part.len() > MAX_PROGRAM_NAME_BYTES {
            continue;
        }
        program_name.push_str(separator);
        program_name.push_str(&part);
    }
    if program_name.is_empty() || program_name.len() > MAX_PROGRAM_NAME_BYTES {
        return Err(PromptContentMappingError::FieldTooLong);
    }

    let mapped_labels: Vec<String> = observation
        .labels()
        .iter()
        .map(|label| replace_controls(label.text()))
        .collect();
    let path = mapped_labels
        .iter()
        .find(|text| is_path(text))
        .map_or("", String::as_str);
    let details = mapped_labels.join("\n");
    if details.len() > MAX_DETAILS_BYTES {
        return Err(PromptContentMappingError::FieldTooLong);
    }
    // The dialog's shape, so a later rule can name the program, the publisher
    // and the details control without reading the language they are written in.
    // Identifiers and positions only; the text is what this is careful not to
    // write, and it is the only part that carries the request.
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
    RequestContent::new(&program_name, path, &details)
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

/// Whether a text label can carry the program's identity at all. A label that
/// repeats the window title says only what the title already said, and one
/// drawn entirely from an icon font carries no readable name. Both appear in
/// the current Windows consent dialog ahead of the program it is asking about.
fn names_program(part: &str, caption: &str) -> bool {
    let trimmed = part.trim();
    !trimmed.is_empty()
        && trimmed != caption.trim()
        && trimmed.chars().any(|character| !is_private_use(character))
}

fn is_private_use(character: char) -> bool {
    matches!(character,
        '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{ffffd}' | '\u{100000}'..='\u{10fffd}')
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
    fn mapping_preserves_order_replaces_controls_and_selects_first_drive_or_unc_path() {
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
        assert_eq!(
            mapped.program_name(),
            "Caption  · First text · C:\\later.exe"
        );
        assert_eq!(mapped.path(), "\\\\server\\tool.exe");
        assert_eq!(
            mapped.details(),
            "First text\n\\\\server\\tool.exe\nC:\\later.exe\nYes"
        );
    }

    #[test]
    fn a_repeated_title_and_an_icon_glyph_never_take_the_naming_places() {
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
        assert_eq!(
            mapped.program_name(),
            "User Account Control · Do you want to allow this app? · uac-ci-request.exe"
        );
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
        assert_eq!(mapped.program_name(), "caption · publisher");
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
        assert_eq!(mapped.program_name(), "caption · C:\\tool.exe");
        assert_eq!(mapped.details(), format!("{long}\nC:\\tool.exe"));
    }
}
