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
pub const MAX_WATCH_MESSAGE_BYTES: usize = PIPE_BUFFER_BYTES as usize;
const CHALLENGE_MAGIC: &[u8; 8] = b"WPRBC002";
const REPORT_MAGIC: &[u8; 8] = b"WPRBR002";
const HELPER_MESSAGE_MAGIC: &[u8; 8] = b"WPHM0001";
const SERVICE_MESSAGE_MAGIC: &[u8; 8] = b"WPSM0001";
const WATCH_REPORT_CHALLENGE: [u8; 32] = [0x57; 32];
const WATCH_HEADER_BYTES: usize = 16;
const TARGET_BYTES: usize = 24;

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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TargetIdentity {
    pub hwnd: u64,
    pub pid: u32,
    pub created: u64,
    pub sequence: u32,
}
impl fmt::Debug for TargetIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetIdentity([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoneReason {
    Closed,
    Replaced,
    DesktopChanged,
    Ambiguous,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    UnknownTarget,
    TargetChanged,
    ContentChanged,
    UnrecognizedButtons,
    AmbiguousButtons,
    PatternUnavailable,
    InvokeFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Gone,
    StillPresent,
    Refused(RefusalReason),
}

#[derive(Clone, Eq, PartialEq)]
pub enum HelperMessage {
    Appeared {
        target: TargetIdentity,
        report: ProbeReport,
    },
    Gone {
        target: TargetIdentity,
        reason: GoneReason,
    },
    Applied {
        target: TargetIdentity,
        outcome: ApplyOutcome,
    },
    Heartbeat {
        sequence: u32,
    },
}
impl fmt::Debug for HelperMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Appeared { report, .. } => formatter
                .debug_struct("Appeared")
                .field("target", &"[redacted]")
                .field("report", report)
                .finish(),
            Self::Gone { reason, .. } => formatter
                .debug_struct("Gone")
                .field("target", &"[redacted]")
                .field("reason", reason)
                .finish(),
            Self::Applied { outcome, .. } => formatter
                .debug_struct("Applied")
                .field("target", &"[redacted]")
                .field("outcome", outcome)
                .finish(),
            Self::Heartbeat { sequence } => formatter
                .debug_struct("Heartbeat")
                .field("sequence", sequence)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ServiceMessage {
    Apply {
        target: TargetIdentity,
        action: crate::PromptAction,
        content_digest: [u8; 32],
    },
    Stop,
}
impl fmt::Debug for ServiceMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apply { action, .. } => formatter
                .debug_struct("Apply")
                .field("target", &"[redacted]")
                .field("action", action)
                .field("content_digest", &"[redacted]")
                .finish(),
            Self::Stop => formatter.write_str("Stop"),
        }
    }
}

impl HelperMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, ReportProtocolError> {
        let mut payload = Vec::new();
        let tag = match self {
            Self::Appeared { target, report } => {
                append_target(&mut payload, *target);
                let challenge = Challenge::new(WATCH_REPORT_CHALLENGE)?;
                payload.extend_from_slice(&encode_report(challenge, Ok(report.clone()))?);
                1
            }
            Self::Gone { target, reason } => {
                append_target(&mut payload, *target);
                payload.push(gone_reason_tag(*reason));
                2
            }
            Self::Applied { target, outcome } => {
                append_target(&mut payload, *target);
                append_apply_outcome(&mut payload, *outcome);
                3
            }
            Self::Heartbeat { sequence } => {
                payload.extend_from_slice(&sequence.to_be_bytes());
                4
            }
        };
        frame(HELPER_MESSAGE_MAGIC, tag, &payload)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, ReportProtocolError> {
        let (tag, payload) = unframe(bytes, HELPER_MESSAGE_MAGIC)?;
        match tag {
            1 => {
                if payload.len() <= TARGET_BYTES {
                    return Err(ReportProtocolError);
                }
                let (target, report) = split_target(payload)?;
                let challenge = Challenge::new(WATCH_REPORT_CHALLENGE)?;
                match decode_report(report, challenge)? {
                    ReportOutcome::Observed(report) => Ok(Self::Appeared { target, report }),
                    ReportOutcome::Unavailable(_) => Err(ReportProtocolError),
                }
            }
            2 if payload.len() == TARGET_BYTES + 1 => {
                let (target, rest) = split_target(payload)?;
                Ok(Self::Gone {
                    target,
                    reason: decode_gone_reason(rest[0])?,
                })
            }
            3 if [TARGET_BYTES + 1, TARGET_BYTES + 2].contains(&payload.len()) => {
                let (target, rest) = split_target(payload)?;
                Ok(Self::Applied {
                    target,
                    outcome: decode_apply_outcome(rest)?,
                })
            }
            4 if payload.len() == 4 => Ok(Self::Heartbeat {
                sequence: u32::from_be_bytes(payload.try_into().map_err(|_| ReportProtocolError)?),
            }),
            _ => Err(ReportProtocolError),
        }
    }
}

impl ServiceMessage {
    pub fn to_wire(&self) -> Result<Vec<u8>, ReportProtocolError> {
        let mut payload = Vec::new();
        let tag = match self {
            Self::Apply {
                target,
                action,
                content_digest,
            } => {
                append_target(&mut payload, *target);
                payload.push(match action {
                    crate::PromptAction::Approve => 1,
                    crate::PromptAction::Deny => 2,
                });
                payload.extend_from_slice(content_digest);
                1
            }
            Self::Stop => 2,
        };
        frame(SERVICE_MESSAGE_MAGIC, tag, &payload)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, ReportProtocolError> {
        let (tag, payload) = unframe(bytes, SERVICE_MESSAGE_MAGIC)?;
        match tag {
            1 if payload.len() == TARGET_BYTES + 33 => {
                let (target, rest) = split_target(payload)?;
                let action = match rest[0] {
                    1 => crate::PromptAction::Approve,
                    2 => crate::PromptAction::Deny,
                    _ => return Err(ReportProtocolError),
                };
                Ok(Self::Apply {
                    target,
                    action,
                    content_digest: rest[1..].try_into().map_err(|_| ReportProtocolError)?,
                })
            }
            2 if payload.is_empty() => Ok(Self::Stop),
            _ => Err(ReportProtocolError),
        }
    }
}

fn frame(magic: &[u8; 8], tag: u8, payload: &[u8]) -> Result<Vec<u8>, ReportProtocolError> {
    let length = WATCH_HEADER_BYTES
        .checked_add(payload.len())
        .filter(|value| *value <= MAX_WATCH_MESSAGE_BYTES)
        .ok_or(ReportProtocolError)?;
    let payload_length = u32::try_from(payload.len()).map_err(|_| ReportProtocolError)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReportProtocolError)?;
    bytes.extend_from_slice(magic);
    bytes.push(tag);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn unframe<'a>(bytes: &'a [u8], magic: &[u8; 8]) -> Result<(u8, &'a [u8]), ReportProtocolError> {
    if bytes.len() < WATCH_HEADER_BYTES
        || bytes.len() > MAX_WATCH_MESSAGE_BYTES
        || &bytes[..8] != magic
        || bytes[8] == 0
        || bytes[9..12] != [0; 3]
    {
        return Err(ReportProtocolError);
    }
    let payload_length = usize::try_from(u32::from_be_bytes(
        bytes[12..16].try_into().map_err(|_| ReportProtocolError)?,
    ))
    .map_err(|_| ReportProtocolError)?;
    if WATCH_HEADER_BYTES.checked_add(payload_length) != Some(bytes.len()) {
        return Err(ReportProtocolError);
    }
    Ok((bytes[8], &bytes[WATCH_HEADER_BYTES..]))
}

fn append_target(bytes: &mut Vec<u8>, target: TargetIdentity) {
    bytes.extend_from_slice(&target.hwnd.to_be_bytes());
    bytes.extend_from_slice(&target.pid.to_be_bytes());
    bytes.extend_from_slice(&target.created.to_be_bytes());
    bytes.extend_from_slice(&target.sequence.to_be_bytes());
}

fn split_target(bytes: &[u8]) -> Result<(TargetIdentity, &[u8]), ReportProtocolError> {
    if bytes.len() < TARGET_BYTES {
        return Err(ReportProtocolError);
    }
    let target = TargetIdentity {
        hwnd: u64::from_be_bytes(bytes[0..8].try_into().map_err(|_| ReportProtocolError)?),
        pid: u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| ReportProtocolError)?),
        created: u64::from_be_bytes(bytes[12..20].try_into().map_err(|_| ReportProtocolError)?),
        sequence: u32::from_be_bytes(bytes[20..24].try_into().map_err(|_| ReportProtocolError)?),
    };
    if target.hwnd == 0 || target.pid == 0 || target.created == 0 || target.sequence == 0 {
        return Err(ReportProtocolError);
    }
    Ok((target, &bytes[TARGET_BYTES..]))
}

fn gone_reason_tag(reason: GoneReason) -> u8 {
    match reason {
        GoneReason::Closed => 1,
        GoneReason::Replaced => 2,
        GoneReason::DesktopChanged => 3,
        GoneReason::Ambiguous => 4,
        GoneReason::VerificationFailed => 5,
    }
}
fn decode_gone_reason(value: u8) -> Result<GoneReason, ReportProtocolError> {
    match value {
        1 => Ok(GoneReason::Closed),
        2 => Ok(GoneReason::Replaced),
        3 => Ok(GoneReason::DesktopChanged),
        4 => Ok(GoneReason::Ambiguous),
        5 => Ok(GoneReason::VerificationFailed),
        _ => Err(ReportProtocolError),
    }
}
fn refusal_tag(reason: RefusalReason) -> u8 {
    match reason {
        RefusalReason::UnknownTarget => 1,
        RefusalReason::TargetChanged => 2,
        RefusalReason::ContentChanged => 3,
        RefusalReason::UnrecognizedButtons => 4,
        RefusalReason::AmbiguousButtons => 5,
        RefusalReason::PatternUnavailable => 6,
        RefusalReason::InvokeFailed => 7,
    }
}
fn decode_refusal(value: u8) -> Result<RefusalReason, ReportProtocolError> {
    match value {
        1 => Ok(RefusalReason::UnknownTarget),
        2 => Ok(RefusalReason::TargetChanged),
        3 => Ok(RefusalReason::ContentChanged),
        4 => Ok(RefusalReason::UnrecognizedButtons),
        5 => Ok(RefusalReason::AmbiguousButtons),
        6 => Ok(RefusalReason::PatternUnavailable),
        7 => Ok(RefusalReason::InvokeFailed),
        _ => Err(ReportProtocolError),
    }
}
fn append_apply_outcome(bytes: &mut Vec<u8>, outcome: ApplyOutcome) {
    match outcome {
        ApplyOutcome::Gone => bytes.push(1),
        ApplyOutcome::StillPresent => bytes.push(2),
        ApplyOutcome::Refused(reason) => {
            bytes.push(3);
            bytes.push(refusal_tag(reason));
        }
    }
}
fn decode_apply_outcome(bytes: &[u8]) -> Result<ApplyOutcome, ReportProtocolError> {
    match bytes {
        [1] => Ok(ApplyOutcome::Gone),
        [2] => Ok(ApplyOutcome::StillPresent),
        [3, reason] => Ok(ApplyOutcome::Refused(decode_refusal(*reason)?)),
        _ => Err(ReportProtocolError),
    }
}

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
            // One runtime ID, caption length, label count and one nonempty label
            // with both metadata lengths require 29 bytes. Counts-only success fails.
            if header[41] != 0 || header[42] != 255 || code != 0 || payload < 29 {
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
    use crate::{LabelKind, PromptLabel};

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
            28,
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
        failure[72..76].copy_from_slice(&29_u32.to_be_bytes());
        failure.extend_from_slice(&[0; 29]);
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
        let first_automation_id = first_text + sample.labels()[0].text().len();
        let first_class_name = first_automation_id + 4;
        let second_label = first_class_name + 4;
        for runtime_count in [0, 33, u8::MAX] {
            let mut invalid = bytes.clone();
            invalid[REPORT_HEADER_BYTES] = runtime_count;
            assert!(decode_report(&invalid, challenge()).is_err());
        }
        for offset in [
            caption_length,
            first_label + 5,
            first_automation_id,
            first_class_name,
        ] {
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
                + 17 * MAX_PROMPT_LABELS
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
        // Add one ASCII byte to the final label's empty ClassName. Its field and
        // label remain valid, while aggregate text exceeds 384 KiB by one.
        let mut over = bytes;
        let final_class_name_length = over.len() - 4;
        over[final_class_name_length..].copy_from_slice(&1_u32.to_be_bytes());
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
    fn watch_messages_round_trip_with_exact_targets_and_redacted_debug() {
        let target = TargetIdentity {
            hwnd: 0x1234,
            pid: 77,
            created: 88,
            sequence: 1,
        };
        let messages = [
            HelperMessage::Appeared {
                target,
                report: report(),
            },
            HelperMessage::Gone {
                target,
                reason: GoneReason::Ambiguous,
            },
            HelperMessage::Applied {
                target,
                outcome: ApplyOutcome::Gone,
            },
            HelperMessage::Applied {
                target,
                outcome: ApplyOutcome::Refused(RefusalReason::ContentChanged),
            },
            HelperMessage::Heartbeat { sequence: 9 },
        ];
        for message in messages {
            let wire = message.to_wire().unwrap();
            assert!(wire.len() <= MAX_WATCH_MESSAGE_BYTES);
            assert_eq!(HelperMessage::from_wire(&wire), Ok(message.clone()));
        }
        let service = [
            ServiceMessage::Apply {
                target,
                action: crate::PromptAction::Approve,
                content_digest: [3; 32],
            },
            ServiceMessage::Apply {
                target,
                action: crate::PromptAction::Deny,
                content_digest: [4; 32],
            },
            ServiceMessage::Stop,
        ];
        for message in service {
            assert_eq!(
                ServiceMessage::from_wire(&message.to_wire().unwrap()),
                Ok(message)
            );
        }
        let debug = format!(
            "{:?} {:?}",
            TargetIdentity {
                hwnd: 0xfeed,
                ..target
            },
            ServiceMessage::Apply {
                target,
                action: crate::PromptAction::Approve,
                content_digest: [0xaa; 32],
            }
        );
        assert!(!debug.contains("feed"));
        assert!(!debug.contains("170"));
    }

    #[test]
    fn watch_codecs_reject_every_truncation_extension_reserved_byte_and_wrong_magic() {
        let target = TargetIdentity {
            hwnd: 1,
            pid: 2,
            created: 3,
            sequence: 4,
        };
        let helper = HelperMessage::Gone {
            target,
            reason: GoneReason::Closed,
        }
        .to_wire()
        .unwrap();
        for end in 0..helper.len() {
            assert!(HelperMessage::from_wire(&helper[..end]).is_err());
        }
        let mut invalid = helper.clone();
        invalid.push(0);
        assert!(HelperMessage::from_wire(&invalid).is_err());
        for offset in [0, 7, 9, 10, 11, 12, 13, 14, 15] {
            let mut invalid = helper.clone();
            invalid[offset] ^= 1;
            assert!(
                HelperMessage::from_wire(&invalid).is_err(),
                "offset={offset}"
            );
        }
        let service = ServiceMessage::Apply {
            target,
            action: crate::PromptAction::Approve,
            content_digest: [7; 32],
        }
        .to_wire()
        .unwrap();
        assert!(HelperMessage::from_wire(&service).is_err());
        assert!(ServiceMessage::from_wire(&helper).is_err());
        let mut unknown_tag = service.clone();
        unknown_tag[8] = 99;
        assert!(ServiceMessage::from_wire(&unknown_tag).is_err());
        let mut unknown_action = service;
        unknown_action[WATCH_HEADER_BYTES + TARGET_BYTES] = 3;
        assert!(ServiceMessage::from_wire(&unknown_action).is_err());
    }

    #[test]
    fn watch_codecs_reject_zero_target_fields_unknown_outcomes_and_oversize_reports() {
        let target = TargetIdentity {
            hwnd: 1,
            pid: 2,
            created: 3,
            sequence: 4,
        };
        let sample = HelperMessage::Gone {
            target,
            reason: GoneReason::Closed,
        }
        .to_wire()
        .unwrap();
        for range in [16..24, 24..28, 28..36, 36..40] {
            let mut invalid = sample.clone();
            invalid[range].fill(0);
            assert!(HelperMessage::from_wire(&invalid).is_err());
        }
        let mut invalid_reason = sample;
        invalid_reason[WATCH_HEADER_BYTES + TARGET_BYTES] = 0;
        assert!(HelperMessage::from_wire(&invalid_reason).is_err());
        let oversized_label = "界".repeat(22_000);
        let content = PromptContentObservation::from_parts(
            vec![1],
            String::new(),
            vec![PromptLabel::new(1, 1, LabelKind::Text, true, oversized_label).unwrap()],
        )
        .unwrap();
        let report = ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 2,
                enabled_elements: 2,
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            content,
        )
        .unwrap();
        assert!(
            HelperMessage::Appeared { target, report }
                .to_wire()
                .is_err()
        );
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
