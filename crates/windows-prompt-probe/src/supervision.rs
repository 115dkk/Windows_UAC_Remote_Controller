// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded observation protocol, NOT authentication by itself. The native endpoints
//! must first authenticate the exact retained child/service process handles.
#![forbid(unsafe_code)]
use crate::{
    NativeOperation, ProbeCounts, ProbeError, ProbeFailure, ProbeReport, PromptContentObservation,
    content::valid_counts,
};
use std::fmt;

pub const SERVICE_NAME: &str = "UacRemoteController";
pub const INSTALLATION_FOLDER: &str = "휴대폰 승인";
pub const SERVICE_EXECUTABLE: &str = "uac-service.exe";
pub const PROBE_EXECUTABLE: &str = "uac-prompt-probe.exe";
pub const PIPE_PREFIX: &str = r"\\.\pipe\UacRemoteController.PromptProbe.v2.";
pub const CHALLENGE_BYTES: usize = 40;
pub const REPORT_HEADER_BYTES: usize = 80;
pub const MAX_REPORT_BYTES: usize = 512 * 1024;
pub const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const CHALLENGE_MAGIC: &[u8; 8] = b"WPRBC002";
const REPORT_MAGIC: &[u8; 8] = b"WPRBR002";

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Challenge([u8; 32]);
impl Challenge {
    /// The service supplies fresh CSPRNG bytes. Shape is not entropy/provenance.
    pub fn new(bytes: [u8; 32]) -> Result<Self, ReportProtocolError> {
        if bytes == [0; 32] {
            return Err(ReportProtocolError);
        }
        Ok(Self(bytes))
    }
    pub fn encode(self) -> [u8; CHALLENGE_BYTES] {
        let mut output = [0; CHALLENGE_BYTES];
        output[..8].copy_from_slice(CHALLENGE_MAGIC);
        output[8..].copy_from_slice(&self.0);
        output
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ReportProtocolError> {
        if bytes.len() != CHALLENGE_BYTES || &bytes[..8] != CHALLENGE_MAGIC {
            return Err(ReportProtocolError);
        }
        Self::new(bytes[8..].try_into().map_err(|_| ReportProtocolError)?)
    }
}
impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportProtocolError;
impl fmt::Display for ReportProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid bounded probe report")
    }
}
impl std::error::Error for ReportProtocolError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportOutcome {
    Observed(ProbeReport),
    Unavailable(ProbeFailure),
}

/// Helper process result only. A caller cannot supply an endpoint, target,
/// session, command, challenge or native handle through this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperExit {
    Observed,
    Unavailable,
    Rejected,
    CleanupUnconfirmed,
}
impl HelperExit {
    pub const fn code(self) -> u8 {
        match self {
            Self::Observed => 0,
            Self::Unavailable => 1,
            Self::Rejected => 2,
            Self::CleanupUnconfirmed => 3,
        }
    }
}

/// Argument-free private-pipe client. Authenticate the actual running fixed SCM
/// service before probing; never an unsupervised stdout or elevation fallback.
/// This may block: the service process supervisor must enforce the 5s lifetime.
pub fn run_supervised_helper() -> HelperExit {
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        crate::ffi::pipe_client::run()
    }
    #[cfg(not(all(windows, target_pointer_width = "64")))]
    {
        HelperExit::Rejected
    }
}

const OPERATIONS: [NativeOperation; 35] = [
    NativeOperation::NativeArchitecture,
    NativeOperation::OpenThreadToken,
    NativeOperation::OpenProcessToken,
    NativeOperation::TokenUser,
    NativeOperation::TokenIntegrity,
    NativeOperation::TokenSession,
    NativeOperation::ProcessSession,
    NativeOperation::WindowStation,
    NativeOperation::DesktopName,
    NativeOperation::DesktopInput,
    NativeOperation::OpenInputDesktop,
    NativeOperation::CloseDesktop,
    NativeOperation::CloseToken,
    NativeOperation::CloseProcess,
    NativeOperation::EnumerateWindows,
    NativeOperation::WindowOwner,
    NativeOperation::OpenProcess,
    NativeOperation::ProcessImage,
    NativeOperation::SystemDirectory,
    NativeOperation::ProcessTimes,
    NativeOperation::ProcessLiveness,
    NativeOperation::CompareImagePath,
    NativeOperation::AttachWorkerDesktop,
    NativeOperation::ComInitialize,
    NativeOperation::CreateAutomation,
    NativeOperation::ConfigureAutomationTimeout,
    NativeOperation::ElementFromWindow,
    NativeOperation::TreeWalker,
    NativeOperation::ElementProperty,
    NativeOperation::PatternAvailability,
    NativeOperation::ClearProperty,
    NativeOperation::RuntimeId,
    NativeOperation::ClearRuntimeId,
    NativeOperation::Caption,
    NativeOperation::Label,
];
const FAILURES: [ProbeFailure; 20] = [
    ProbeFailure::UnsupportedPlatform,
    ProbeFailure::Native64Unsupported,
    ProbeFailure::ThreadImpersonationPresent,
    ProbeFailure::SystemUserRequired,
    ProbeFailure::SystemIntegrityRequired,
    ProbeFailure::InteractiveSessionRequired,
    ProbeFailure::InteractiveWindowStationRequired,
    ProbeFailure::SecureInputDesktopProfileRequired,
    ProbeFailure::NoQualifiedConsentWindow,
    ProbeFailure::AmbiguousConsentWindows,
    ProbeFailure::TopLevelWindowLimit,
    ProbeFailure::ElementLimit,
    ProbeFailure::DepthLimit,
    ProbeFailure::CooperativeBudgetExceeded,
    ProbeFailure::ObservationChanged,
    ProbeFailure::ProviderOwnerMismatch,
    ProbeFailure::WorkerUnavailable,
    ProbeFailure::WorkerPanicked,
    ProbeFailure::ContentLimit,
    ProbeFailure::UnsupportedContent,
];

/// One v2 message. Observed requires content; ordinary failures remain exactly
/// 80 bytes with no text. Cleanup uncertainty can never encode a completed report.
pub fn encode_report(
    challenge: Challenge,
    result: Result<ProbeReport, ProbeError>,
) -> Result<Vec<u8>, ReportProtocolError> {
    let size = REPORT_HEADER_BYTES
        .checked_add(
            result
                .as_ref()
                .map_or(0, |report| report.content().encoded_len()),
        )
        .filter(|length| *length <= MAX_REPORT_BYTES)
        .ok_or(ReportProtocolError)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ReportProtocolError)?;
    bytes.resize(REPORT_HEADER_BYTES, 0);
    bytes[..8].copy_from_slice(REPORT_MAGIC);
    bytes[8..40].copy_from_slice(&challenge.0);
    bytes[42] = 255;
    match result {
        Ok(report) => {
            let c = report.counts();
            report
                .content()
                .validate_counts(c)
                .map_err(|_| ReportProtocolError)?;
            let counts = [
                c.top_level_windows,
                c.qualified_candidates,
                c.elements,
                c.password_nodes_skipped,
                c.enabled_elements,
                c.offscreen_elements,
                c.native_window_elements,
                c.button_elements,
                c.invoke_pattern_available,
                c.value_pattern_available,
                c.legacy_accessible_pattern_available,
            ];
            for (index, count) in counts.into_iter().enumerate() {
                bytes[48 + index * 2..50 + index * 2].copy_from_slice(&count.to_be_bytes());
            }
            bytes[70] = c.maximum_depth;
            bytes[72..76].copy_from_slice(&(report.content().encoded_len() as u32).to_be_bytes());
            report.content().append_encoded(&mut bytes);
        }
        Err(error) => {
            if error.cleanup().is_some() {
                return Err(ReportProtocolError);
            }
            bytes[40] = 1;
            match error.failure() {
                ProbeFailure::MalformedNativeData(operation) => {
                    bytes[41] = 30;
                    bytes[42] = OPERATIONS
                        .iter()
                        .position(|value| *value == operation)
                        .ok_or(ReportProtocolError)? as u8;
                }
                ProbeFailure::NativeCall { operation, hresult } => {
                    if hresult >= 0 {
                        return Err(ReportProtocolError);
                    }
                    bytes[41] = 31;
                    bytes[42] = OPERATIONS
                        .iter()
                        .position(|value| *value == operation)
                        .ok_or(ReportProtocolError)? as u8;
                    bytes[44..48].copy_from_slice(&hresult.to_be_bytes());
                }
                failure => {
                    bytes[41] = (FAILURES
                        .iter()
                        .position(|value| *value == failure)
                        .ok_or(ReportProtocolError)?
                        + 1) as u8
                }
            }
        }
    }
    Ok(bytes)
}

/// Validate EXACTLY the first 80 bytes before the native reader allocates the
/// remaining message. Returns bounded TOTAL bytes including the header. It is
/// not content acceptance: decode_report must still parse the full exact message
/// and the supervisor must still require EOF/child-exit/cleanup confirmation.
/// Payload length is u32 BE at 72..76; 43, 71 and 76..80 remain reserved zero.
pub fn report_total_bytes(
    header: &[u8],
    expected: Challenge,
) -> Result<usize, ReportProtocolError> {
    if header.len() != REPORT_HEADER_BYTES
        || &header[..8] != REPORT_MAGIC
        || header[8..40] != expected.0
        || header[43] != 0
        || header[71] != 0
        || header[76..80].iter().any(|byte| *byte != 0)
    {
        return Err(ReportProtocolError);
    }
    let payload = usize::try_from(u32::from_be_bytes(
        header[72..76].try_into().map_err(|_| ReportProtocolError)?,
    ))
    .map_err(|_| ReportProtocolError)?;
    let total = REPORT_HEADER_BYTES
        .checked_add(payload)
        .filter(|length| *length <= MAX_REPORT_BYTES)
        .ok_or(ReportProtocolError)?;
    let code = i32::from_be_bytes(header[44..48].try_into().map_err(|_| ReportProtocolError)?);
    match header[40] {
        0 => {
            // One runtime ID, caption length, label count and one nonempty
            // label require at least 21 bytes. Counts-only success is forbidden.
            if header[41] != 0 || header[42] != 255 || code != 0 || payload < 21 {
                return Err(ReportProtocolError);
            }
            if !valid_counts(decode_counts(header)?) {
                return Err(ReportProtocolError);
            }
        }
        1 => {
            if payload != 0 || header[48..71].iter().any(|byte| *byte != 0) {
                return Err(ReportProtocolError);
            }
            let _ = decode_failure(header)?;
        }
        _ => return Err(ReportProtocolError),
    }
    Ok(total)
}

pub fn decode_report(
    bytes: &[u8],
    expected: Challenge,
) -> Result<ReportOutcome, ReportProtocolError> {
    let header = bytes
        .get(..REPORT_HEADER_BYTES)
        .ok_or(ReportProtocolError)?;
    if report_total_bytes(header, expected)? != bytes.len() {
        return Err(ReportProtocolError);
    }
    match header[40] {
        0 => {
            let content = PromptContentObservation::decode(&bytes[REPORT_HEADER_BYTES..])
                .map_err(|_| ReportProtocolError)?;
            let report = ProbeReport::from_observation(decode_counts(header)?, content)
                .map_err(|_| ReportProtocolError)?;
            Ok(ReportOutcome::Observed(report))
        }
        1 => Ok(ReportOutcome::Unavailable(decode_failure(header)?)),
        _ => Err(ReportProtocolError),
    }
}

fn decode_counts(bytes: &[u8]) -> Result<ProbeCounts, ReportProtocolError> {
    let mut c = [0u16; 11];
    for (index, value) in c.iter_mut().enumerate() {
        *value = u16::from_be_bytes(
            bytes[48 + index * 2..50 + index * 2]
                .try_into()
                .map_err(|_| ReportProtocolError)?,
        );
    }
    Ok(ProbeCounts {
        top_level_windows: c[0],
        qualified_candidates: c[1],
        elements: c[2],
        password_nodes_skipped: c[3],
        enabled_elements: c[4],
        offscreen_elements: c[5],
        native_window_elements: c[6],
        button_elements: c[7],
        invoke_pattern_available: c[8],
        value_pattern_available: c[9],
        legacy_accessible_pattern_available: c[10],
        maximum_depth: bytes[70],
    })
}

fn decode_failure(bytes: &[u8]) -> Result<ProbeFailure, ReportProtocolError> {
    let code = i32::from_be_bytes(bytes[44..48].try_into().map_err(|_| ReportProtocolError)?);
    match bytes[41] {
        1..=20 if bytes[42] == 255 && code == 0 => Ok(FAILURES[usize::from(bytes[41] - 1)]),
        30 if code == 0 => Ok(ProbeFailure::MalformedNativeData(
            *OPERATIONS
                .get(usize::from(bytes[42]))
                .ok_or(ReportProtocolError)?,
        )),
        31 if code < 0 => Ok(ProbeFailure::NativeCall {
            operation: *OPERATIONS
                .get(usize::from(bytes[42]))
                .ok_or(ReportProtocolError)?,
            hresult: code,
        }),
        _ => Err(ReportProtocolError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic protocol metadata only. Never invoke probe_once, a helper,
    // service, token, desktop, GUI, native process or Windows API in these tests.
    fn challenge() -> Challenge {
        Challenge::new([0x42; 32]).unwrap()
    }
    fn counts() -> ProbeCounts {
        ProbeCounts {
            top_level_windows: 8,
            qualified_candidates: 1,
            elements: 128,
            password_nodes_skipped: 4,
            enabled_elements: 124,
            offscreen_elements: 10,
            native_window_elements: 1,
            button_elements: 3,
            invoke_pattern_available: 3,
            value_pattern_available: 2,
            legacy_accessible_pattern_available: 5,
            maximum_depth: 16,
        }
    }
    fn content() -> crate::PromptContentObservation {
        crate::PromptContentObservation::from_parts(
            vec![1, -2, 3],
            "Synthetic consent caption".into(),
            vec![
                crate::PromptLabel::new(
                    1,
                    2,
                    crate::LabelKind::Text,
                    true,
                    "Synthetic operation label".into(),
                )
                .unwrap(),
                crate::PromptLabel::new(
                    2,
                    2,
                    crate::LabelKind::Button,
                    true,
                    "Synthetic button".into(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }
    fn report() -> ProbeReport {
        ProbeReport::from_observation(counts(), content()).unwrap()
    }
    #[test]
    fn synthetic_challenge_is_exact_versioned_and_redacted() {
        let value = challenge();
        assert_eq!(Challenge::decode(&value.encode()), Ok(value));
        assert_eq!(format!("{value:?}"), "Challenge([redacted])");
        assert!(Challenge::new([0; 32]).is_err());
        assert!(Challenge::decode(&value.encode()[..39]).is_err());
        let mut extended = value.encode().to_vec();
        extended.push(0);
        assert!(Challenge::decode(&extended).is_err());
        let mut version = value.encode();
        version[7] ^= 1;
        assert!(Challenge::decode(&version).is_err());
    }
    #[test]
    fn synthetic_content_round_trips_exactly_and_does_not_become_authorization() {
        let observed = report();
        let bytes = encode_report(challenge(), Ok(observed.clone())).unwrap();
        assert!(bytes.len() > REPORT_HEADER_BYTES);
        assert!(bytes.len() < PIPE_BUFFER_BYTES as usize);
        assert_eq!(
            report_total_bytes(&bytes[..REPORT_HEADER_BYTES], challenge()).unwrap(),
            bytes.len()
        );
        assert_eq!(
            decode_report(&bytes, challenge()),
            Ok(ReportOutcome::Observed(observed))
        );
        assert!(decode_report(&bytes, Challenge::new([0x24; 32]).unwrap()).is_err());
    }
    #[test]
    fn synthetic_failure_variants_and_operations_round_trip_without_strings() {
        for failure in FAILURES {
            let bytes = encode_report(challenge(), Err(ProbeError::new(failure))).unwrap();
            assert_eq!(bytes.len(), REPORT_HEADER_BYTES);
            assert_eq!(
                report_total_bytes(&bytes, challenge()),
                Ok(REPORT_HEADER_BYTES)
            );
            assert_eq!(
                decode_report(&bytes, challenge()),
                Ok(ReportOutcome::Unavailable(failure))
            );
        }
        for operation in OPERATIONS {
            for failure in [
                ProbeFailure::MalformedNativeData(operation),
                ProbeFailure::NativeCall {
                    operation,
                    hresult: -2147024891,
                },
            ] {
                let bytes = encode_report(challenge(), Err(ProbeError::new(failure))).unwrap();
                assert_eq!(
                    decode_report(&bytes, challenge()),
                    Ok(ReportOutcome::Unavailable(failure))
                );
            }
        }
    }
    #[test]
    fn every_truncation_trailing_byte_and_reserved_field_is_rejected() {
        let bytes = encode_report(challenge(), Ok(report())).unwrap();
        for length in 0..bytes.len() {
            assert!(decode_report(&bytes[..length], challenge()).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode_report(&trailing, challenge()).is_err());
        for offset in [
            0, 7, 40, 41, 42, 43, 44, 45, 46, 47, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        ] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 0x80;
            assert!(
                decode_report(&invalid, challenge()).is_err(),
                "offset={offset}"
            );
        }
    }
    #[test]
    fn synthetic_out_of_range_or_incoherent_counts_fail_closed() {
        for invalid in [
            ProbeCounts {
                elements: 129,
                ..counts()
            },
            ProbeCounts {
                qualified_candidates: 2,
                ..counts()
            },
            ProbeCounts {
                top_level_windows: 129,
                ..counts()
            },
            ProbeCounts {
                maximum_depth: 17,
                ..counts()
            },
            ProbeCounts {
                maximum_depth: 0,
                ..counts()
            },
            ProbeCounts {
                password_nodes_skipped: 129,
                ..counts()
            },
            ProbeCounts {
                enabled_elements: 125,
                ..counts()
            },
            ProbeCounts::default(),
        ] {
            assert!(ProbeReport::from_observation(invalid, content()).is_err());
        }
        let mut bytes = encode_report(challenge(), Ok(report())).unwrap();
        bytes[52..54].copy_from_slice(&129u16.to_be_bytes());
        assert!(decode_report(&bytes, challenge()).is_err());
    }
    #[test]
    fn cleanup_failure_never_encodes_as_a_completed_report() {
        let error = ProbeError {
            failure: ProbeFailure::ObservationChanged,
            cleanup: Some(crate::CleanupFailure {
                failures: 1,
                first_operation: NativeOperation::CloseDesktop,
                first_hresult: -2147024891,
            }),
        };
        assert!(encode_report(challenge(), Err(error)).is_err());
        assert!(
            encode_report(
                challenge(),
                Err(ProbeError::new(ProbeFailure::CleanupFailed))
            )
            .is_err()
        );
        let mut bytes = encode_report(
            challenge(),
            Err(ProbeError::new(ProbeFailure::ObservationChanged)),
        )
        .unwrap();
        bytes[41] = 21; // Unassigned in v2; CleanupFailed has no encodable tag.
        assert!(decode_report(&bytes, challenge()).is_err());
    }
    #[test]
    fn malformed_native_tags_and_nonfailure_hresult_are_rejected() {
        let failure = ProbeFailure::NativeCall {
            operation: NativeOperation::OpenProcess,
            hresult: -1,
        };
        let bytes = encode_report(challenge(), Err(ProbeError::new(failure))).unwrap();
        let mut invalid = bytes.clone();
        invalid[42] = 255;
        assert!(decode_report(&invalid, challenge()).is_err());
        let mut invalid = bytes.clone();
        invalid[48] = 1;
        assert!(decode_report(&invalid, challenge()).is_err());
        for code in [0i32, 1] {
            let mut invalid = bytes.clone();
            invalid[44..48].copy_from_slice(&code.to_be_bytes());
            assert!(decode_report(&invalid, challenge()).is_err());
            assert!(
                encode_report(
                    challenge(),
                    Err(ProbeError::new(ProbeFailure::NativeCall {
                        operation: NativeOperation::OpenProcess,
                        hresult: code
                    }))
                )
                .is_err()
            );
        }
    }
    #[test]
    fn v1_or_unknown_protocols_and_counts_only_success_are_never_accepted() {
        let mut old_challenge = challenge().encode();
        old_challenge[..8].copy_from_slice(b"WPRBC001");
        assert!(Challenge::decode(&old_challenge).is_err());
        let bytes = encode_report(challenge(), Ok(report())).unwrap();
        for magic in [b"WPRBR001", b"WPRBR003"] {
            let mut invalid = bytes.clone();
            invalid[..8].copy_from_slice(magic);
            assert!(decode_report(&invalid, challenge()).is_err());
            assert!(report_total_bytes(&invalid[..REPORT_HEADER_BYTES], challenge()).is_err());
        }
        let mut counts_only = bytes[..REPORT_HEADER_BYTES].to_vec();
        counts_only[72..76].fill(0);
        assert!(decode_report(&counts_only, challenge()).is_err());
        assert!(report_total_bytes(&counts_only, challenge()).is_err());
    }

    #[test]
    fn header_preflight_checks_bounded_lengths_without_treating_a_header_as_a_report() {
        let bytes = encode_report(challenge(), Ok(report())).unwrap();
        let header = &bytes[..REPORT_HEADER_BYTES];
        for end in 0..REPORT_HEADER_BYTES {
            assert!(report_total_bytes(&header[..end], challenge()).is_err());
        }
        assert!(report_total_bytes(&bytes, challenge()).is_err());
        for payload in [
            0_u32,
            20,
            (MAX_REPORT_BYTES - REPORT_HEADER_BYTES + 1) as u32,
            u32::MAX,
        ] {
            let mut invalid = header.to_vec();
            invalid[72..76].copy_from_slice(&payload.to_be_bytes());
            assert!(report_total_bytes(&invalid, challenge()).is_err());
        }
        let mut maximum_claim = header.to_vec();
        maximum_claim[72..76]
            .copy_from_slice(&((MAX_REPORT_BYTES - REPORT_HEADER_BYTES) as u32).to_be_bytes());
        assert_eq!(
            report_total_bytes(&maximum_claim, challenge()),
            Ok(MAX_REPORT_BYTES)
        );
        assert!(decode_report(&maximum_claim, challenge()).is_err());
        maximum_claim.resize(MAX_REPORT_BYTES, 0);
        assert!(decode_report(&maximum_claim, challenge()).is_err());
        maximum_claim.push(0);
        assert!(decode_report(&maximum_claim, challenge()).is_err());

        let mut failure = encode_report(
            challenge(),
            Err(ProbeError::new(ProbeFailure::ContentLimit)),
        )
        .unwrap();
        failure[72..76].copy_from_slice(&21_u32.to_be_bytes());
        failure.extend_from_slice(&[0; 21]);
        assert!(report_total_bytes(&failure[..REPORT_HEADER_BYTES], challenge()).is_err());
        assert!(decode_report(&failure, challenge()).is_err());
    }

    #[test]
    fn content_parser_rejects_invalid_utf8_nul_runtime_label_order_tags_and_lengths() {
        let sample = content();
        let bytes = encode_report(challenge(), Ok(report())).unwrap();
        let caption_length = REPORT_HEADER_BYTES + 1 + sample.root_runtime_id().len() * 4;
        let caption_start = caption_length + 4;
        let label_count = caption_start + sample.caption().len();
        let first_label = label_count + 2;
        let first_text = first_label + 9;
        let second_label = first_text + sample.labels()[0].text().len();
        for runtime_count in [0, 33, u8::MAX] {
            let mut invalid = bytes.clone();
            invalid[REPORT_HEADER_BYTES] = runtime_count;
            assert!(decode_report(&invalid, challenge()).is_err());
        }
        for offset in [caption_length, first_label + 5] {
            let mut invalid = bytes.clone();
            invalid[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(decode_report(&invalid, challenge()).is_err());
        }
        for offset in [caption_start, first_text] {
            for value in [0, 0xff] {
                let mut invalid = bytes.clone();
                invalid[offset] = value;
                assert!(decode_report(&invalid, challenge()).is_err());
            }
        }
        for count in [0_u16, 1, 129, u16::MAX] {
            let mut invalid = bytes.clone();
            invalid[label_count..label_count + 2].copy_from_slice(&count.to_be_bytes());
            assert!(decode_report(&invalid, challenge()).is_err());
        }
        for (offset, value) in [
            (first_label + 2, 0),
            (first_label + 2, 17),
            (first_label + 3, 0),
            (first_label + 3, 4),
            (first_label + 4, 2),
            (first_label + 4, 255),
        ] {
            let mut invalid = bytes.clone();
            invalid[offset] = value;
            assert!(decode_report(&invalid, challenge()).is_err());
        }
        let mut invalid_ordinal = bytes.clone();
        invalid_ordinal[first_label..first_label + 2].copy_from_slice(&128_u16.to_be_bytes());
        assert!(decode_report(&invalid_ordinal, challenge()).is_err());
        for ordinal in [0_u16, 1] {
            let mut unordered = bytes.clone();
            unordered[second_label..second_label + 2].copy_from_slice(&ordinal.to_be_bytes());
            assert!(decode_report(&unordered, challenge()).is_err());
        }
    }

    #[test]
    fn valid_utf8_caption_above_utf16_field_limit_is_rejected_on_the_wire() {
        let sample = content();
        let bytes = encode_report(challenge(), Ok(report())).unwrap();
        let length_offset = REPORT_HEADER_BYTES + 1 + sample.root_runtime_id().len() * 4;
        let old_caption_end = length_offset + 4 + sample.caption().len();
        let count = crate::MAX_PROMPT_FIELD_UTF16_UNITS + 1;
        let mut invalid = bytes[..length_offset].to_vec();
        invalid.extend_from_slice(&(count as u32).to_be_bytes());
        invalid.extend(std::iter::repeat_n(b'A', count));
        invalid.extend_from_slice(&bytes[old_caption_end..]);
        let payload_length = (invalid.len() - REPORT_HEADER_BYTES) as u32;
        invalid[72..76].copy_from_slice(&payload_length.to_be_bytes());
        assert_eq!(
            report_total_bytes(&invalid[..REPORT_HEADER_BYTES], challenge()),
            Ok(invalid.len())
        );
        assert!(decode_report(&invalid, challenge()).is_err());
    }

    #[test]
    fn maximum_content_and_label_metadata_fit_large_bounded_v2_message() {
        use crate::{
            LabelKind, MAX_PROMPT_CONTENT_UTF8_BYTES, MAX_PROMPT_FIELD_UTF16_UNITS,
            MAX_PROMPT_LABELS, MAX_RUNTIME_ID_VALUES, PromptLabel,
        };
        let field = "界".repeat(MAX_PROMPT_FIELD_UTF16_UNITS);
        let labels = (0..MAX_PROMPT_LABELS)
            .map(|ordinal| {
                PromptLabel::new(
                    ordinal as u16,
                    1,
                    LabelKind::Text,
                    true,
                    if ordinal < 3 {
                        field.clone()
                    } else {
                        String::new()
                    },
                )
                .unwrap()
            })
            .collect();
        let content = PromptContentObservation::from_parts(
            vec![i32::MIN; MAX_RUNTIME_ID_VALUES],
            field,
            labels,
        )
        .unwrap();
        assert_eq!(content.utf8_bytes(), MAX_PROMPT_CONTENT_UTF8_BYTES);
        let counts = ProbeCounts {
            top_level_windows: 1,
            qualified_candidates: 1,
            elements: 128,
            enabled_elements: 128,
            maximum_depth: 1,
            ..ProbeCounts::default()
        };
        let report = ProbeReport::from_observation(counts, content).unwrap();
        let bytes = encode_report(challenge(), Ok(report.clone())).unwrap();
        assert!(bytes.len() > PIPE_BUFFER_BYTES as usize);
        assert!(bytes.len() <= MAX_REPORT_BYTES);
        assert_eq!(
            bytes.len(),
            REPORT_HEADER_BYTES
                + 1
                + 4 * MAX_RUNTIME_ID_VALUES
                + 4
                + 2
                + 9 * MAX_PROMPT_LABELS
                + MAX_PROMPT_CONTENT_UTF8_BYTES
        );
        assert_eq!(
            report_total_bytes(&bytes[..REPORT_HEADER_BYTES], challenge()),
            Ok(bytes.len())
        );
        assert_eq!(
            decode_report(&bytes, challenge()),
            Ok(ReportOutcome::Observed(report))
        );
        // The final empty label becomes one ASCII byte: its field/count/tags
        // remain valid, while aggregate text alone exceeds 384 KiB by one.
        let mut over = bytes;
        let final_text_length = over.len() - 4;
        over[final_text_length..].copy_from_slice(&1_u32.to_be_bytes());
        over.push(b'a');
        let payload_length = (over.len() - REPORT_HEADER_BYTES) as u32;
        over[72..76].copy_from_slice(&payload_length.to_be_bytes());
        assert!(over.len() < MAX_REPORT_BYTES);
        assert!(decode_report(&over, challenge()).is_err());
    }

    #[test]
    fn report_outcome_debug_never_prints_observed_provider_text_or_runtime_values() {
        let observed = ReportOutcome::Observed(report());
        let text = format!("{observed:?}");
        assert!(!text.contains("Synthetic consent caption"));
        assert!(!text.contains("Synthetic operation label"));
        assert!(!text.contains("Synthetic button"));
        assert!(!text.contains("[1, -2, 3]"));
    }
    #[test]
    fn helper_entry_has_no_target_endpoint_or_action_arguments() {
        let _entry: fn() -> HelperExit = run_supervised_helper;
        assert_eq!(HelperExit::Observed.code(), 0);
        assert_eq!(HelperExit::Unavailable.code(), 1);
        assert_eq!(HelperExit::Rejected.code(), 2);
        assert_eq!(HelperExit::CleanupUnconfirmed.code(), 3);
    }
}
