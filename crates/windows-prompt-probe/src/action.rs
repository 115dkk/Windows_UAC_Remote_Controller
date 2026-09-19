// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed consent-button recognition. No native handle or action is accepted here.
#![forbid(unsafe_code)]

use std::fmt;

use crate::{LabelKind, PromptContentObservation, PromptLabel};

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
    if buttons.len() < 2 || buttons.len() > MAX_ENABLED_BUTTONS {
        return Err(ActionSelectionError::AmbiguousButtons);
    }
    // What the dialog's own author named the buttons, and only if that does not
    // single out one of each, what they say.
    let (affirmative, negative) = named(&buttons, |label| label.automation_id())
        .or_else(|| named(&buttons, |label| label.text()))
        .ok_or(ActionSelectionError::UnrecognizedButtons)?;
    let selected = match action {
        PromptAction::Approve => affirmative,
        PromptAction::Deny => negative,
    };
    Ok(ActionTarget {
        ordinal: selected.ordinal(),
    })
}

/// Returns the one affirmative and the one negative button under `value`, or
/// nothing at all when that does not single out exactly one of each.
///
/// Both readings run through here so the requirement is written once: exactly
/// one button says yes, exactly one says no, and they are not the same button.
/// A button that answers neither table cannot be mistaken for either, which is
/// what lets the dialog carry a close button without confusing this.
fn named<'a>(
    buttons: &[&'a PromptLabel],
    value: impl Fn(&'a PromptLabel) -> &'a str,
) -> Option<(&'a PromptLabel, &'a PromptLabel)> {
    let pick = |table: &[&str]| {
        let mut matched = buttons
            .iter()
            .copied()
            .filter(|label| matches_name(value(label), table));
        match (matched.next(), matched.next()) {
            (Some(only), None) => Some(only),
            _ => None,
        }
    };
    let affirmative = pick(&AFFIRMATIVE_NAMES)?;
    let negative = pick(&NEGATIVE_NAMES)?;
    (affirmative.ordinal() != negative.ordinal()).then_some((affirmative, negative))
}

/// The current consent dialog also exposes its title bar's close button, so a
/// pair of choices is not the only thing an honest prompt presents. A button
/// naming neither choice cannot be mistaken for one, and the requirement that
/// exactly one button names each choice is what keeps the selection closed.
/// The bound stays small so an unfamiliar prompt is refused rather than read.
const MAX_ENABLED_BUTTONS: usize = 4;

/// `OkButton` and `CancelButton` are what consent.exe calls them, measured on
/// this product's own prompts. They matter because the words below were only
/// ever Korean and English: this installer ships eleven languages, and on a
/// German or a Japanese Windows the product refused a prompt it could read
/// perfectly well. An identifier the dialog's author chose reads the same
/// everywhere. `CloseButton` deliberately appears in neither table.
const AFFIRMATIVE_NAMES: [&str; 8] = [
    "OkButton", "예", "Yes", "&Yes", "허용", "Allow", "확인", "OK",
];
const NEGATIVE_NAMES: [&str; 9] = [
    "CancelButton",
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

    fn identified(ordinal: u16, automation_id: &str, name: &str) -> PromptLabel {
        PromptLabel::new_with_metadata(
            ordinal,
            2,
            LabelKind::Button,
            true,
            name.into(),
            automation_id.into(),
            "Button".into(),
        )
        .unwrap()
    }

    #[test]
    fn the_dialogs_own_identifiers_decide_in_a_language_the_words_never_covered() {
        // German. Neither word appears in either table, and before the dialog's
        // identifiers were read this prompt was refused outright.
        let value = observation(vec![
            identified(1, "CloseButton", "Schließen"),
            identified(4, "OkButton", "Ja"),
            identified(6, "CancelButton", "Nein"),
        ]);
        assert_eq!(
            select_action_target(&value, PromptAction::Approve),
            Ok(ActionTarget { ordinal: 4 })
        );
        assert_eq!(
            select_action_target(&value, PromptAction::Deny),
            Ok(ActionTarget { ordinal: 6 })
        );
    }

    #[test]
    fn a_dialog_that_identifies_only_one_choice_falls_back_to_what_the_buttons_say() {
        // One identifier alone does not single out a pair, so the words decide;
        // that is what keeps a dialog naming its buttons some other way working.
        let value = observation(vec![
            identified(1, "OkButton", "Yes"),
            identified(2, "SomethingElse", "No"),
        ]);
        assert_eq!(
            select_action_target(&value, PromptAction::Deny),
            Ok(ActionTarget { ordinal: 2 })
        );
    }

    #[test]
    fn the_close_button_is_never_either_choice() {
        // Its identifier is in neither table and its word is in neither table,
        // so a prompt offering only it and one real choice is refused.
        for labels in [
            vec![
                identified(1, "CloseButton", "닫기"),
                identified(2, "OkButton", "예"),
            ],
            vec![
                identified(1, "CloseButton", "Close"),
                identified(2, "CancelButton", "No"),
            ],
        ] {
            let value = observation(labels);
            assert_eq!(
                select_action_target(&value, PromptAction::Approve),
                Err(ActionSelectionError::UnrecognizedButtons)
            );
        }
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
                label(1, "Close", true),
                label(2, "Yes", true),
                label(3, "No", true),
                label(4, "Help", true),
                label(5, "More", true),
            ],
        ] {
            assert_eq!(
                select_action_target(&observation(labels), PromptAction::Deny),
                Err(ActionSelectionError::AmbiguousButtons)
            );
        }
    }

    #[test]
    fn window_chrome_beside_the_pair_still_selects_the_named_choice() {
        // The shape the current consent dialog presents: a title bar close
        // button that names neither choice, then the two that do.
        let value = observation(vec![
            label(1, "Close", true),
            label(9, "Yes", true),
            label(11, "No", true),
        ]);
        assert_eq!(
            select_action_target(&value, PromptAction::Deny),
            Ok(ActionTarget { ordinal: 11 })
        );
        assert_eq!(
            select_action_target(&value, PromptAction::Approve),
            Ok(ActionTarget { ordinal: 9 })
        );
    }

    #[test]
    fn unknown_duplicate_or_cross_role_names_are_refused() {
        for labels in [
            vec![label(1, "Continue", true), label(2, "No", true)],
            vec![label(1, "Yes", true), label(2, "Later", true)],
            vec![label(1, "Yes", true), label(2, "Allow", true)],
            vec![label(1, "No", true), label(2, "Cancel", true)],
            vec![label(1, "Y es", true), label(2, "No", true)],
            // A third button that names a choice again leaves it unrecognized.
            vec![
                label(1, "Yes", true),
                label(2, "No", true),
                label(3, "Cancel", true),
            ],
        ] {
            assert_eq!(
                select_action_target(&observation(labels), PromptAction::Approve),
                Err(ActionSelectionError::UnrecognizedButtons)
            );
        }
    }
}
