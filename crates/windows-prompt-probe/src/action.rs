// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed consent-button recognition. No native handle or action is accepted here.
#![forbid(unsafe_code)]

use std::fmt;

use crate::{LabelKind, PromptContentObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptAction {
    Approve,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionTarget {
    pub ordinal: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionSelectionError {
    AmbiguousButtons,
    UnrecognizedButtons,
}
impl fmt::Display for ActionSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "consent button selection failed: {self:?}")
    }
}
impl std::error::Error for ActionSelectionError {}

pub fn select_action_target(
    observation: &PromptContentObservation,
    action: PromptAction,
) -> Result<ActionTarget, ActionSelectionError> {
    let buttons: Vec<_> = observation
        .labels()
        .iter()
        .filter(|label| label.kind() == LabelKind::Button && label.enabled())
        .collect();
    if buttons.len() != 2 {
        return Err(ActionSelectionError::AmbiguousButtons);
    }
    let affirmative = buttons
        .iter()
        .copied()
        .filter(|label| matches_name(label.text(), &AFFIRMATIVE_NAMES))
        .collect::<Vec<_>>();
    let negative = buttons
        .iter()
        .copied()
        .filter(|label| matches_name(label.text(), &NEGATIVE_NAMES))
        .collect::<Vec<_>>();
    if affirmative.len() != 1
        || negative.len() != 1
        || affirmative[0].ordinal() == negative[0].ordinal()
    {
        return Err(ActionSelectionError::UnrecognizedButtons);
    }
    let selected = match action {
        PromptAction::Approve => affirmative[0],
        PromptAction::Deny => negative[0],
    };
    Ok(ActionTarget {
        ordinal: selected.ordinal(),
    })
}

const AFFIRMATIVE_NAMES: [&str; 7] = ["예", "Yes", "&Yes", "허용", "Allow", "확인", "OK"];
const NEGATIVE_NAMES: [&str; 8] = [
    "아니요",
    "아니오",
    "No",
    "&No",
    "취소",
    "Cancel",
    "차단",
    "Block",
];

fn matches_name(name: &str, table: &[&str]) -> bool {
    let name = name.trim();
    table.iter().any(|candidate| {
        if candidate.is_ascii() && name.is_ascii() {
            name.eq_ignore_ascii_case(candidate)
        } else {
            name == *candidate
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PromptContentObservation, PromptLabel};

    fn label(ordinal: u16, name: &str, enabled: bool) -> PromptLabel {
        PromptLabel::new_with_metadata(
            ordinal,
            2,
            LabelKind::Button,
            enabled,
            name.into(),
            format!("button-{ordinal}"),
            "Button".into(),
        )
        .unwrap()
    }

    fn observation(labels: Vec<PromptLabel>) -> PromptContentObservation {
        PromptContentObservation::from_parts(vec![1], "caption".into(), labels).unwrap()
    }

    #[test]
    fn every_fixed_pair_selects_the_requested_distinct_ordinal() {
        for affirmative in AFFIRMATIVE_NAMES {
            for negative in NEGATIVE_NAMES {
                let value =
                    observation(vec![label(2, affirmative, true), label(7, negative, true)]);
                assert_eq!(
                    select_action_target(&value, PromptAction::Approve),
                    Ok(ActionTarget { ordinal: 2 })
                );
                assert_eq!(
                    select_action_target(&value, PromptAction::Deny),
                    Ok(ActionTarget { ordinal: 7 })
                );
            }
        }
    }

    #[test]
    fn latin_names_ignore_case_and_all_names_trim_outer_whitespace_only() {
        let latin = observation(vec![label(1, "  &yEs\t", true), label(2, " cAnCeL ", true)]);
        assert_eq!(
            select_action_target(&latin, PromptAction::Approve),
            Ok(ActionTarget { ordinal: 1 })
        );
        let korean = observation(vec![label(1, "\n허용 ", true), label(2, " 아니요\t", true)]);
        assert_eq!(
            select_action_target(&korean, PromptAction::Deny),
            Ok(ActionTarget { ordinal: 2 })
        );
    }

    #[test]
    fn only_enabled_buttons_count_toward_the_exact_pair() {
        let value = observation(vec![
            label(1, "Yes", true),
            label(2, "No", true),
            label(3, "Cancel", false),
            PromptLabel::new(4, 2, LabelKind::Text, true, "Yes".into()).unwrap(),
        ]);
        assert_eq!(
            select_action_target(&value, PromptAction::Approve),
            Ok(ActionTarget { ordinal: 1 })
        );
        for labels in [
            vec![label(1, "Yes", true)],
            vec![label(1, "Yes", true), label(2, "No", false)],
            vec![
                label(1, "Yes", true),
                label(2, "No", true),
                label(3, "Cancel", true),
            ],
        ] {
            assert_eq!(
                select_action_target(&observation(labels), PromptAction::Deny),
                Err(ActionSelectionError::AmbiguousButtons)
            );
        }
    }

    #[test]
    fn unknown_duplicate_or_cross_role_names_are_refused() {
        for labels in [
            vec![label(1, "Continue", true), label(2, "No", true)],
            vec![label(1, "Yes", true), label(2, "Later", true)],
            vec![label(1, "Yes", true), label(2, "Allow", true)],
            vec![label(1, "No", true), label(2, "Cancel", true)],
            vec![label(1, "Y es", true), label(2, "No", true)],
        ] {
            assert_eq!(
                select_action_target(&observation(labels), PromptAction::Approve),
                Err(ActionSelectionError::UnrecognizedButtons)
            );
        }
    }
}
