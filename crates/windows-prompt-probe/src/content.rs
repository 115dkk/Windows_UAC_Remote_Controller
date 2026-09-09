// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact bounded read-only provider observations. No semantic field recognition,
//! action target, authorization, arbitrary property selection or text logging.
#![forbid(unsafe_code)]

use std::fmt;

use crate::{MAX_TOP_LEVEL_WINDOWS, MAX_UIA_DEPTH, MAX_UIA_ELEMENTS, ProbeCounts};

pub const MAX_RUNTIME_ID_VALUES: usize = 32;
pub const MAX_PROMPT_FIELD_UTF16_UNITS: usize = 32_768;
pub const MAX_PROMPT_CONTENT_UTF8_BYTES: usize = 384 * 1024;
pub const MAX_PROMPT_LABELS: usize = MAX_UIA_ELEMENTS;
const MAX_FIELD_UTF8_BYTES: usize = MAX_PROMPT_FIELD_UTF16_UNITS * 3;

/// Closed read-only label kinds, not a UI action or operation classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelKind {
    Text,
    Button,
    Hyperlink,
}

/// A producer-selected nonpassword, on-screen label. These fields do not prove
/// native visibility/origin; the supervised native reader must establish that.
/// Ordinal is zero-based traversal order, including skipped/other visited nodes.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptLabel {
    ordinal: u16,
    depth: u8,
    kind: LabelKind,
    enabled: bool,
    text: String,
}
impl PromptLabel {
    pub fn new(
        ordinal: u16,
        depth: u8,
        kind: LabelKind,
        enabled: bool,
        text: String,
    ) -> Result<Self, PromptContentError> {
        if usize::from(ordinal) >= MAX_UIA_ELEMENTS || depth == 0 || depth > MAX_UIA_DEPTH {
            return Err(PromptContentError::InvalidLabel);
        }
        validate_text(&text)?;
        Ok(Self {
            ordinal,
            depth,
            kind,
            enabled,
            text,
        })
    }
    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }
    pub const fn depth(&self) -> u8 {
        self.depth
    }
    pub const fn kind(&self) -> LabelKind {
        self.kind
    }
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn text(&self) -> &str {
        &self.text
    }
}
impl fmt::Debug for PromptLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptLabel")
            .field("ordinal", &self.ordinal)
            .field("depth", &self.depth)
            .field("kind", &self.kind)
            .field("enabled", &self.enabled)
            .field("text", &"[redacted]")
            .finish()
    }
}

/// One owned exact snapshot. RuntimeId is opaque comparison data and can be
/// reused by Windows; equality is change detection, NOT atomic UAC identity.
/// No caption/label is interpreted as program/path/publisher/command or trusted
/// Windows outcome. The caller must not persist these potentially sensitive
/// strings as activity history or expose Debug/Display text. No Display/serde
/// implementation is provided. Native capture must skip password/edit/value
/// content and compare two observations with target rechecks before reporting.
#[derive(Clone, Eq, PartialEq)]
pub struct PromptContentObservation {
    root_runtime_id: Vec<i32>,
    caption: String,
    labels: Vec<PromptLabel>,
}
impl PromptContentObservation {
    pub fn from_parts(
        root_runtime_id: Vec<i32>,
        caption: String,
        labels: Vec<PromptLabel>,
    ) -> Result<Self, PromptContentError> {
        if root_runtime_id.is_empty() || root_runtime_id.len() > MAX_RUNTIME_ID_VALUES {
            return Err(PromptContentError::InvalidRuntimeId);
        }
        if labels.len() > MAX_PROMPT_LABELS {
            return Err(PromptContentError::LabelLimit);
        }
        validate_text(&caption)?;
        let mut total = caption.len();
        let mut previous = None;
        let mut nonempty = false;
        for label in &labels {
            if previous.is_some_and(|ordinal| label.ordinal <= ordinal) {
                return Err(PromptContentError::LabelOrder);
            }
            previous = Some(label.ordinal);
            // PromptLabel fields are immutable/validated; no text is normalized.
            total = total
                .checked_add(label.text.len())
                .ok_or(PromptContentError::TotalLimit)?;
            if total > MAX_PROMPT_CONTENT_UTF8_BYTES {
                return Err(PromptContentError::TotalLimit);
            }
            nonempty |= !label.text.is_empty();
        }
        if !nonempty {
            return Err(PromptContentError::NoVisibleLabel);
        }
        Ok(Self {
            root_runtime_id,
            caption,
            labels,
        })
    }
    pub fn root_runtime_id(&self) -> &[i32] {
        &self.root_runtime_id
    }
    pub fn caption(&self) -> &str {
        &self.caption
    }
    pub fn labels(&self) -> &[PromptLabel] {
        &self.labels
    }
    pub fn utf8_bytes(&self) -> usize {
        self.caption.len()
            + self
                .labels
                .iter()
                .map(|label| label.text.len())
                .sum::<usize>()
    }

    pub(crate) fn validate_counts(&self, counts: ProbeCounts) -> Result<(), PromptContentError> {
        if !valid_counts(counts) {
            return Err(PromptContentError::InvalidCounts);
        }
        let visible = counts.elements - counts.password_nodes_skipped - counts.offscreen_elements;
        if self.labels.len() > usize::from(visible)
            || self
                .labels
                .iter()
                .any(|label| label.ordinal >= counts.elements || label.depth > counts.maximum_depth)
            || self.labels.iter().filter(|label| label.enabled).count()
                > usize::from(counts.enabled_elements)
            || self.labels.iter().filter(|label| !label.enabled).count()
                > usize::from(
                    counts.elements - counts.password_nodes_skipped - counts.enabled_elements,
                )
            || self
                .labels
                .iter()
                .filter(|label| label.kind == LabelKind::Button)
                .count()
                > usize::from(counts.button_elements)
            || self
                .labels
                .iter()
                .filter(|label| label.kind != LabelKind::Button)
                .count()
                > usize::from(
                    counts.elements - counts.password_nodes_skipped - counts.button_elements,
                )
        {
            return Err(PromptContentError::CountsMismatch);
        }
        Ok(())
    }

    pub(crate) fn encoded_len(&self) -> usize {
        1 + self.root_runtime_id.len() * 4
            + 4
            + self.caption.len()
            + 2
            + self
                .labels
                .iter()
                .map(|label| 9 + label.text.len())
                .sum::<usize>()
    }

    pub(crate) fn append_encoded(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.root_runtime_id.len() as u8);
        for value in &self.root_runtime_id {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        append_text(bytes, &self.caption);
        bytes.extend_from_slice(&(self.labels.len() as u16).to_be_bytes());
        for label in &self.labels {
            bytes.extend_from_slice(&label.ordinal.to_be_bytes());
            bytes.push(label.depth);
            bytes.push(match label.kind {
                LabelKind::Text => 1,
                LabelKind::Button => 2,
                LabelKind::Hyperlink => 3,
            });
            bytes.push(u8::from(label.enabled));
            append_text(bytes, &label.text);
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PromptContentError> {
        let mut input = Input {
            bytes,
            offset: 0,
            text_bytes: 0,
        };
        let runtime_count = usize::from(input.take::<1>()?[0]);
        if runtime_count == 0 || runtime_count > MAX_RUNTIME_ID_VALUES {
            return Err(PromptContentError::InvalidRuntimeId);
        }
        let mut runtime = Vec::with_capacity(runtime_count);
        for _ in 0..runtime_count {
            runtime.push(i32::from_be_bytes(input.take()?));
        }
        let caption = input.text()?;
        let count = usize::from(u16::from_be_bytes(input.take()?));
        if count > MAX_PROMPT_LABELS {
            return Err(PromptContentError::LabelLimit);
        }
        let mut labels = Vec::with_capacity(count);
        for _ in 0..count {
            let ordinal = u16::from_be_bytes(input.take()?);
            let depth = input.take::<1>()?[0];
            let kind = match input.take::<1>()?[0] {
                1 => LabelKind::Text,
                2 => LabelKind::Button,
                3 => LabelKind::Hyperlink,
                _ => return Err(PromptContentError::InvalidEncoding),
            };
            let enabled = match input.take::<1>()?[0] {
                0 => false,
                1 => true,
                _ => return Err(PromptContentError::InvalidEncoding),
            };
            labels.push(PromptLabel::new(
                ordinal,
                depth,
                kind,
                enabled,
                input.text()?,
            )?);
        }
        if input.offset != bytes.len() {
            return Err(PromptContentError::InvalidEncoding);
        }
        Self::from_parts(runtime, caption, labels)
    }
}
impl fmt::Debug for PromptContentObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptContentObservation")
            .field("runtime_id_values", &self.root_runtime_id.len())
            .field("label_count", &self.labels.len())
            .field("utf8_bytes", &self.utf8_bytes())
            .field("content", &"[redacted], observation_not_operation")
            .finish()
    }
}

/// Strict native UTF-16 conversion after the native owner bounds its allocation.
/// No replacement characters, trimming, truncation or NUL acceptance. Rust String
/// constructors use the same field limit; invalid UTF-8 is rejected by the codec.
pub fn prompt_text_from_utf16(value: &[u16]) -> Result<String, PromptContentError> {
    if value.len() > MAX_PROMPT_FIELD_UTF16_UNITS {
        return Err(PromptContentError::FieldLimit);
    }
    if value.contains(&0) {
        return Err(PromptContentError::InvalidText);
    }
    String::from_utf16(value).map_err(|_| PromptContentError::InvalidText)
}

fn validate_text(value: &str) -> Result<(), PromptContentError> {
    if value.len() > MAX_FIELD_UTF8_BYTES
        || value.encode_utf16().count() > MAX_PROMPT_FIELD_UTF16_UNITS
    {
        return Err(PromptContentError::FieldLimit);
    }
    if value.contains('\0') {
        return Err(PromptContentError::InvalidText);
    }
    Ok(())
}

pub(crate) fn valid_counts(c: ProbeCounts) -> bool {
    c.top_level_windows > 0
        && usize::from(c.top_level_windows) <= MAX_TOP_LEVEL_WINDOWS
        && c.qualified_candidates == 1
        && c.elements > 0
        && usize::from(c.elements) <= MAX_UIA_ELEMENTS
        && c.maximum_depth > 0
        && c.maximum_depth <= MAX_UIA_DEPTH
        && u16::from(c.maximum_depth) <= c.elements
        && c.password_nodes_skipped <= c.elements
        && [
            c.enabled_elements,
            c.offscreen_elements,
            c.native_window_elements,
            c.button_elements,
            c.invoke_pattern_available,
            c.value_pattern_available,
            c.legacy_accessible_pattern_available,
        ]
        .iter()
        .all(|count| *count <= c.elements - c.password_nodes_skipped)
}

fn append_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
    text_bytes: usize,
}
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PromptContentError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PromptContentError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PromptContentError::InvalidEncoding)?
            .try_into()
            .map_err(|_| PromptContentError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
    fn text(&mut self) -> Result<String, PromptContentError> {
        let count = usize::try_from(u32::from_be_bytes(self.take()?))
            .map_err(|_| PromptContentError::FieldLimit)?;
        if count > MAX_FIELD_UTF8_BYTES {
            return Err(PromptContentError::FieldLimit);
        }
        self.text_bytes = self
            .text_bytes
            .checked_add(count)
            .ok_or(PromptContentError::TotalLimit)?;
        if self.text_bytes > MAX_PROMPT_CONTENT_UTF8_BYTES {
            return Err(PromptContentError::TotalLimit);
        }
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PromptContentError::InvalidEncoding)?;
        let value = std::str::from_utf8(
            self.bytes
                .get(self.offset..end)
                .ok_or(PromptContentError::InvalidEncoding)?,
        )
        .map_err(|_| PromptContentError::InvalidText)?;
        validate_text(value)?;
        self.offset = end;
        Ok(value.to_owned())
    }
}

/// Fixed categories only; no provider text or original encoding-error payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptContentError {
    InvalidRuntimeId,
    InvalidLabel,
    LabelLimit,
    LabelOrder,
    InvalidText,
    FieldLimit,
    TotalLimit,
    NoVisibleLabel,
    InvalidEncoding,
    InvalidCounts,
    CountsMismatch,
}
impl fmt::Display for PromptContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid bounded prompt observation: {self:?}")
    }
}
impl std::error::Error for PromptContentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProbeReport;

    fn label(ordinal: u16, text: &str) -> PromptLabel {
        PromptLabel::new(ordinal, 2, LabelKind::Text, true, text.into()).unwrap()
    }
    fn observation() -> PromptContentObservation {
        PromptContentObservation::from_parts(
            vec![1, -2, 3],
            "synthetic caption".into(),
            vec![label(1, "synthetic label")],
        )
        .unwrap()
    }
    fn counts() -> ProbeCounts {
        ProbeCounts {
            top_level_windows: 1,
            qualified_candidates: 1,
            elements: 8,
            enabled_elements: 8,
            maximum_depth: 3,
            ..ProbeCounts::default()
        }
    }

    #[test]
    fn empty_caption_and_exact_whitespace_are_preserved_but_a_nonempty_label_is_required() {
        let value =
            PromptContentObservation::from_parts(vec![0], String::new(), vec![label(1, " \t ")])
                .unwrap();
        assert_eq!(value.caption(), "");
        assert_eq!(value.labels()[0].text(), " \t ");
        assert_eq!(value.utf8_bytes(), 3);
        for labels in [vec![], vec![label(1, "")]] {
            assert_eq!(
                PromptContentObservation::from_parts(vec![1], "caption alone".into(), labels),
                Err(PromptContentError::NoVisibleLabel)
            );
        }
    }

    #[test]
    fn runtime_ids_are_bounded_opaque_integers_not_semantically_interpreted_identifiers() {
        for runtime in [vec![], vec![1; MAX_RUNTIME_ID_VALUES + 1]] {
            assert_eq!(
                PromptContentObservation::from_parts(runtime, String::new(), vec![label(1, "x")]),
                Err(PromptContentError::InvalidRuntimeId)
            );
        }
        let runtime = vec![i32::MIN; MAX_RUNTIME_ID_VALUES];
        let value = PromptContentObservation::from_parts(
            runtime.clone(),
            String::new(),
            vec![label(1, "x")],
        )
        .unwrap();
        assert_eq!(value.root_runtime_id(), runtime);
    }

    #[test]
    fn label_bounds_and_order_are_strict_without_reordering_or_duplicate_elision() {
        for (ordinal, depth) in [(128, 1), (0, 0), (0, 17)] {
            assert_eq!(
                PromptLabel::new(ordinal, depth, LabelKind::Text, true, "x".into()),
                Err(PromptContentError::InvalidLabel)
            );
        }
        assert!(PromptLabel::new(127, 16, LabelKind::Hyperlink, false, "x".into()).is_ok());
        for labels in [
            vec![label(3, "x"), label(1, "y")],
            vec![label(1, "x"), label(1, "y")],
        ] {
            assert_eq!(
                PromptContentObservation::from_parts(vec![1], String::new(), labels),
                Err(PromptContentError::LabelOrder)
            );
        }
        let oversized = (0..129).map(|_| label(1, "x")).collect();
        assert_eq!(
            PromptContentObservation::from_parts(vec![1], String::new(), oversized),
            Err(PromptContentError::LabelLimit)
        );
    }

    #[test]
    fn utf16_conversion_is_strict_and_limits_count_code_units_not_utf8_or_scalars() {
        assert_eq!(
            prompt_text_from_utf16(&[0xd800]),
            Err(PromptContentError::InvalidText)
        );
        assert_eq!(
            prompt_text_from_utf16(&[0xdc00]),
            Err(PromptContentError::InvalidText)
        );
        assert_eq!(
            prompt_text_from_utf16(&[65, 0, 66]),
            Err(PromptContentError::InvalidText)
        );
        assert_eq!(
            prompt_text_from_utf16(&vec![65; MAX_PROMPT_FIELD_UTF16_UNITS + 1]),
            Err(PromptContentError::FieldLimit)
        );
        let exact = "🔒".repeat(MAX_PROMPT_FIELD_UTF16_UNITS / 2);
        let units: Vec<_> = exact.encode_utf16().collect();
        assert_eq!(prompt_text_from_utf16(&units).unwrap(), exact);
        assert!(PromptLabel::new(1, 2, LabelKind::Text, true, exact.clone()).is_ok());
        assert_eq!(
            PromptLabel::new(1, 2, LabelKind::Text, true, format!("{exact}a")),
            Err(PromptContentError::FieldLimit)
        );
        assert_eq!(
            PromptLabel::new(1, 2, LabelKind::Text, true, "x\0y".into()),
            Err(PromptContentError::InvalidText)
        );
        assert_eq!(
            PromptContentObservation::from_parts(vec![1], "x\0y".into(), vec![label(1, "x")]),
            Err(PromptContentError::InvalidText)
        );
    }

    #[test]
    fn aggregate_utf8_budget_accepts_exact_boundary_and_rejects_one_extra_byte() {
        let field = "界".repeat(MAX_PROMPT_FIELD_UTF16_UNITS);
        let labels: Vec<_> = (1..=3).map(|ordinal| label(ordinal, &field)).collect();
        let exact =
            PromptContentObservation::from_parts(vec![1], field.clone(), labels.clone()).unwrap();
        assert_eq!(exact.utf8_bytes(), MAX_PROMPT_CONTENT_UTF8_BYTES);
        let mut over = labels;
        over.push(label(4, "a"));
        assert_eq!(
            PromptContentObservation::from_parts(vec![1], field, over),
            Err(PromptContentError::TotalLimit)
        );
    }

    #[test]
    fn maximum_label_count_remains_owned_and_ordered() {
        let labels = (0..128)
            .map(|ordinal| PromptLabel::new(ordinal, 1, LabelKind::Text, true, "x".into()).unwrap())
            .collect();
        let value = PromptContentObservation::from_parts(vec![1], String::new(), labels).unwrap();
        assert_eq!(value.labels().len(), MAX_PROMPT_LABELS);
        let c = ProbeCounts {
            top_level_windows: 1,
            qualified_candidates: 1,
            elements: 128,
            enabled_elements: 128,
            maximum_depth: 1,
            ..ProbeCounts::default()
        };
        assert!(ProbeReport::from_observation(c, value).is_ok());
    }

    #[test]
    fn report_rejects_label_and_counter_inconsistency_before_any_success_can_be_encoded() {
        let content = observation();
        assert!(ProbeReport::from_observation(counts(), content.clone()).is_ok());
        for c in [
            ProbeCounts::default(),
            ProbeCounts {
                maximum_depth: 1,
                ..counts()
            },
            ProbeCounts {
                elements: 1,
                enabled_elements: 1,
                maximum_depth: 1,
                ..counts()
            },
            ProbeCounts {
                offscreen_elements: 8,
                ..counts()
            },
            ProbeCounts {
                enabled_elements: 0,
                ..counts()
            },
            ProbeCounts {
                button_elements: 8,
                ..counts()
            },
        ] {
            assert!(ProbeReport::from_observation(c, content.clone()).is_err());
        }
        let disabled = PromptContentObservation::from_parts(
            vec![1],
            String::new(),
            vec![PromptLabel::new(1, 2, LabelKind::Text, false, "x".into()).unwrap()],
        )
        .unwrap();
        assert!(ProbeReport::from_observation(counts(), disabled).is_err());
        let button = PromptContentObservation::from_parts(
            vec![1],
            String::new(),
            vec![PromptLabel::new(1, 2, LabelKind::Button, true, "x".into()).unwrap()],
        )
        .unwrap();
        assert!(ProbeReport::from_observation(counts(), button).is_err());
    }

    #[test]
    fn snapshot_equality_includes_caption_runtime_order_kind_depth_enabled_and_exact_text() {
        let original = observation();
        let mut variants = vec![
            PromptContentObservation::from_parts(
                vec![1, -2, 4],
                original.caption().into(),
                original.labels().to_vec(),
            )
            .unwrap(),
            PromptContentObservation::from_parts(
                original.root_runtime_id().to_vec(),
                "different caption".into(),
                original.labels().to_vec(),
            )
            .unwrap(),
        ];
        for changed in [
            PromptLabel::new(2, 2, LabelKind::Text, true, "synthetic label".into()).unwrap(),
            PromptLabel::new(1, 3, LabelKind::Text, true, "synthetic label".into()).unwrap(),
            PromptLabel::new(1, 2, LabelKind::Hyperlink, true, "synthetic label".into()).unwrap(),
            PromptLabel::new(1, 2, LabelKind::Text, false, "synthetic label".into()).unwrap(),
            label(1, "synthetic label "),
        ] {
            variants.push(
                PromptContentObservation::from_parts(
                    original.root_runtime_id().to_vec(),
                    original.caption().into(),
                    vec![changed],
                )
                .unwrap(),
            );
        }
        for changed in variants {
            assert_ne!(original, changed);
        }
        assert_eq!(original, original.clone());
    }

    #[test]
    fn debug_output_contains_no_caption_label_or_runtime_identifier_values() {
        let value = observation();
        let report = ProbeReport::from_observation(counts(), value.clone()).unwrap();
        let text = format!("{report:?} {value:?} {:?}", value.labels()[0]);
        assert!(!text.contains("synthetic caption"));
        assert!(!text.contains("synthetic label"));
        assert!(!text.contains("[1, -2, 3]"));
    }
}
