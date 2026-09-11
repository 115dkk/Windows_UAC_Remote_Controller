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
    // The caption followed by the first two Text labels names the program. A
    // label that would push the name over its byte bound is left out whole;
    // the labels themselves are never cut, and every label stays in details.
    let mut program_name = replace_controls(observation.caption());
    for label in observation
        .labels()
        .iter()
        .filter(|label| label.kind() == LabelKind::Text)
        .take(2)
    {
        let part = replace_controls(label.text());
        if part.is_empty() {
            continue;
        }
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
