// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed metadata protocol, NOT authentication by itself. The native endpoints
//! must first authenticate the exact retained child/service process handles.
#![forbid(unsafe_code)]
use crate::{NativeOperation, ProbeCounts, ProbeError, ProbeFailure, ProbeReport};
use std::fmt;

pub const SERVICE_NAME: &str = "UacRemoteController";
pub const INSTALLATION_FOLDER: &str = "휴대폰 승인";
pub const SERVICE_EXECUTABLE: &str = "uac-service.exe";
pub const PROBE_EXECUTABLE: &str = "uac-prompt-probe.exe";
pub const PIPE_PREFIX: &str = r"\\.\pipe\UacRemoteController.PromptProbe.v1.";
pub const CHALLENGE_BYTES: usize = 40;
pub const REPORT_BYTES: usize = 80;
pub const PIPE_BUFFER_BYTES: u32 = 512;
const CHALLENGE_MAGIC: &[u8; 8] = b"WPRBC001";
const REPORT_MAGIC: &[u8; 8] = b"WPRBR001";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportOutcome {
    Observed(ProbeCounts),
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

const OPERATIONS: [NativeOperation; 31] = [
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
];
const FAILURES: [ProbeFailure; 18] = [
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
];

fn valid_counts(c: ProbeCounts) -> bool {
    c.top_level_windows > 0
        && c.top_level_windows <= 128
        && c.qualified_candidates == 1
        && c.elements > 0
        && c.elements <= 128
        && c.maximum_depth > 0
        && c.maximum_depth <= 16
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

pub fn encode_report(
    challenge: Challenge,
    result: Result<ProbeReport, ProbeError>,
) -> Result<[u8; REPORT_BYTES], ReportProtocolError> {
    let mut bytes = [0; REPORT_BYTES];
    bytes[..8].copy_from_slice(REPORT_MAGIC);
    bytes[8..40].copy_from_slice(&challenge.0);
    bytes[42] = 255;
    match result {
        Ok(report) => {
            let c = report.counts();
            if !valid_counts(c) {
                return Err(ReportProtocolError);
            }
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
        }
        Err(error) => {
            if error.cleanup().is_some() {
                return Err(ReportProtocolError);
            }
            bytes[40] = 1;
            match error.failure() {
                ProbeFailure::MalformedNativeData(operation) => {
                    bytes[41] = 20;
                    bytes[42] = OPERATIONS
                        .iter()
                        .position(|value| *value == operation)
                        .ok_or(ReportProtocolError)? as u8;
                }
                ProbeFailure::NativeCall { operation, hresult } => {
                    if hresult >= 0 {
                        return Err(ReportProtocolError);
                    }
                    bytes[41] = 21;
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

pub fn decode_report(
    bytes: &[u8],
    expected: Challenge,
) -> Result<ReportOutcome, ReportProtocolError> {
    if bytes.len() != REPORT_BYTES
        || &bytes[..8] != REPORT_MAGIC
        || bytes[8..40] != expected.0
        || bytes[43] != 0
        || bytes[71..].iter().any(|byte| *byte != 0)
    {
        return Err(ReportProtocolError);
    }
    let code = i32::from_be_bytes(bytes[44..48].try_into().map_err(|_| ReportProtocolError)?);
    match bytes[40] {
        0 => {
            if bytes[41] != 0 || bytes[42] != 255 || code != 0 {
                return Err(ReportProtocolError);
            }
            let mut c = [0u16; 11];
            for (index, value) in c.iter_mut().enumerate() {
                *value = u16::from_be_bytes(
                    bytes[48 + index * 2..50 + index * 2]
                        .try_into()
                        .map_err(|_| ReportProtocolError)?,
                );
            }
            let counts = ProbeCounts {
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
            };
            if !valid_counts(counts) {
                return Err(ReportProtocolError);
            }
            Ok(ReportOutcome::Observed(counts))
        }
        1 => {
            if bytes[48..71].iter().any(|byte| *byte != 0) {
                return Err(ReportProtocolError);
            }
            let failure = match bytes[41] {
                1..=18 if bytes[42] == 255 && code == 0 => FAILURES[usize::from(bytes[41] - 1)],
                20 if code == 0 => ProbeFailure::MalformedNativeData(
                    *OPERATIONS
                        .get(usize::from(bytes[42]))
                        .ok_or(ReportProtocolError)?,
                ),
                21 if code < 0 => ProbeFailure::NativeCall {
                    operation: *OPERATIONS
                        .get(usize::from(bytes[42]))
                        .ok_or(ReportProtocolError)?,
                    hresult: code,
                },
                _ => return Err(ReportProtocolError),
            };
            Ok(ReportOutcome::Unavailable(failure))
        }
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
    fn synthetic_counts_round_trip_exactly_and_do_not_become_authorization() {
        let bytes = encode_report(challenge(), Ok(ProbeReport { counts: counts() })).unwrap();
        assert_eq!(bytes.len(), 80);
        assert!(bytes.len() < PIPE_BUFFER_BYTES as usize);
        assert_eq!(
            decode_report(&bytes, challenge()),
            Ok(ReportOutcome::Observed(counts()))
        );
        assert!(decode_report(&bytes, Challenge::new([0x24; 32]).unwrap()).is_err());
    }
    #[test]
    fn synthetic_failure_variants_and_operations_round_trip_without_strings() {
        for failure in FAILURES {
            let bytes = encode_report(challenge(), Err(ProbeError::new(failure))).unwrap();
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
        let bytes = encode_report(challenge(), Ok(ProbeReport { counts: counts() })).unwrap();
        for length in 0..REPORT_BYTES {
            assert!(decode_report(&bytes[..length], challenge()).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode_report(&trailing, challenge()).is_err());
        for offset in [
            0, 7, 40, 41, 42, 43, 44, 45, 46, 47, 71, 72, 73, 74, 75, 76, 77, 78, 79,
        ] {
            let mut invalid = bytes;
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
            assert!(encode_report(challenge(), Ok(ProbeReport { counts: invalid })).is_err());
        }
        let mut bytes = encode_report(challenge(), Ok(ProbeReport { counts: counts() })).unwrap();
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
        bytes[41] = 19;
        assert!(decode_report(&bytes, challenge()).is_err());
    }
    #[test]
    fn malformed_native_tags_and_nonfailure_hresult_are_rejected() {
        let failure = ProbeFailure::NativeCall {
            operation: NativeOperation::OpenProcess,
            hresult: -1,
        };
        let bytes = encode_report(challenge(), Err(ProbeError::new(failure))).unwrap();
        let mut invalid = bytes;
        invalid[42] = 255;
        assert!(decode_report(&invalid, challenge()).is_err());
        let mut invalid = bytes;
        invalid[48] = 1;
        assert!(decode_report(&invalid, challenge()).is_err());
        for code in [0i32, 1] {
            let mut invalid = bytes;
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
    fn helper_entry_has_no_target_endpoint_or_action_arguments() {
        let _entry: fn() -> HelperExit = run_supervised_helper;
        assert_eq!(HelperExit::Observed.code(), 0);
        assert_eq!(HelperExit::Unavailable.code(), 1);
        assert_eq!(HelperExit::Rejected.code(), 2);
        assert_eq!(HelperExit::CleanupUnconfirmed.code(), 3);
    }
}
