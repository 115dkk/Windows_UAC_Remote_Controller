// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]
use crate::{
    MAX_UIA_DEPTH, MAX_UIA_ELEMENTS, ProbeCounts, ProbeError, ProbeFailure,
    SUPERVISOR_BUDGET_MILLIS,
};
use std::time::Duration;

pub(crate) fn unique_candidate(count: usize) -> Result<(), ProbeError> {
    match count {
        0 => Err(ProbeError::new(ProbeFailure::NoQualifiedConsentWindow)),
        1 => Ok(()),
        _ => Err(ProbeError::new(ProbeFailure::AmbiguousConsentWindows)),
    }
}

pub(crate) fn budget(elapsed: Duration) -> Result<(), ProbeError> {
    if elapsed >= Duration::from_millis(SUPERVISOR_BUDGET_MILLIS) {
        Err(ProbeError::new(ProbeFailure::CooperativeBudgetExceeded))
    } else {
        Ok(())
    }
}

pub(crate) fn visit(counts: &mut ProbeCounts, depth: u8) -> Result<(), ProbeError> {
    if depth == 0 || depth > MAX_UIA_DEPTH {
        return Err(ProbeError::new(ProbeFailure::DepthLimit));
    }
    if usize::from(counts.elements) >= MAX_UIA_ELEMENTS {
        return Err(ProbeError::new(ProbeFailure::ElementLimit));
    }
    counts.elements += 1;
    counts.maximum_depth = counts.maximum_depth.max(depth);
    Ok(())
}

/// SID data remains inside a successfully filled native buffer. This helper
/// only validates the SID's bounded prefix; it does not authenticate bytes.
pub(crate) fn sid_prefix(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
        return None;
    }
    bytes.get(..8 + usize::from(bytes[1]) * 4)
}

pub(crate) fn strict_name(units: &[u16], returned_bytes: u32) -> Option<String> {
    let length = usize::try_from(returned_bytes).ok()?;
    if length == 0 || length % 2 != 0 {
        return None;
    }
    let units = units.get(..length / 2)?;
    let (&last, body) = units.split_last()?;
    if last != 0 || body.is_empty() || body.contains(&0) {
        return None;
    }
    String::from_utf16(body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_candidate_or_multiple_candidates_never_selects_a_target() {
        assert_eq!(
            unique_candidate(0).unwrap_err().failure(),
            ProbeFailure::NoQualifiedConsentWindow
        );
        assert!(unique_candidate(1).is_ok());
        for count in [2, 128, usize::MAX] {
            assert_eq!(
                unique_candidate(count).unwrap_err().failure(),
                ProbeFailure::AmbiguousConsentWindows
            );
        }
    }

    #[test]
    fn element_and_depth_limits_reject_without_incrementing() {
        let mut counts = ProbeCounts::default();
        for _ in 0..128 {
            visit(&mut counts, 16).unwrap();
        }
        assert_eq!(counts.elements, 128);
        assert_eq!(
            visit(&mut counts, 16).unwrap_err().failure(),
            ProbeFailure::ElementLimit
        );
        assert_eq!(counts.elements, 128);
        for depth in [0, 17, u8::MAX] {
            let mut counts = ProbeCounts::default();
            assert_eq!(
                visit(&mut counts, depth).unwrap_err().failure(),
                ProbeFailure::DepthLimit
            );
            assert_eq!(counts.elements, 0);
        }
    }

    #[test]
    fn cooperative_budget_is_end_exclusive_not_a_thread_kill() {
        assert!(budget(Duration::from_millis(4_999)).is_ok());
        assert_eq!(
            budget(Duration::from_millis(5_000)).unwrap_err().failure(),
            ProbeFailure::CooperativeBudgetExceeded
        );
    }

    #[test]
    fn sid_prefix_never_reads_a_declared_out_of_buffer_subauthority() {
        let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(sid_prefix(&system), Some(system.as_slice()));
        assert!(sid_prefix(&system[..11]).is_none());
        assert!(sid_prefix(&[1, 16, 0, 0, 0, 0, 0, 5]).is_none());
        assert!(sid_prefix(&[2, 0, 0, 0, 0, 0, 0, 5]).is_none());
    }

    #[test]
    fn native_names_require_exact_terminated_valid_utf16() {
        let valid: Vec<u16> = "Winlogon\0".encode_utf16().collect();
        assert_eq!(strict_name(&valid, 18).as_deref(), Some("Winlogon"));
        for size in [0, 1, 16, 17, 20, u32::MAX] {
            assert!(strict_name(&valid, size).is_none());
        }
        assert!(strict_name(&[0], 2).is_none());
        assert!(strict_name(&[65, 0, 66, 0], 8).is_none());
        assert!(strict_name(&[0xd800, 0], 4).is_none());
    }
}
