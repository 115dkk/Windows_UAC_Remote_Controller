// SPDX-License-Identifier: GPL-2.0-or-later
//! API/constant assertions only; Windows probe is never invoked by these tests.
use windows_prompt_probe::{
    MAX_TOP_LEVEL_WINDOWS, MAX_UIA_DEPTH, MAX_UIA_ELEMENTS, ProbeError, ProbeReport,
    SUPERVISOR_BUDGET_MILLIS, UIA_TIMEOUT_MILLIS, probe_once,
};

#[test]
fn outward_api_has_no_target_or_action_parameters() {
    let _probe: fn() -> Result<ProbeReport, ProbeError> = probe_once;
    assert_eq!(MAX_TOP_LEVEL_WINDOWS, 128);
    assert_eq!(MAX_UIA_ELEMENTS, 128);
    assert_eq!(MAX_UIA_DEPTH, 16);
    assert_eq!(SUPERVISOR_BUDGET_MILLIS, 5_000);
    assert_eq!(UIA_TIMEOUT_MILLIS, 1_000);
}

#[cfg(not(windows))]
#[test]
fn other_platform_does_not_fabricate_an_observation() {
    assert_eq!(
        probe_once().unwrap_err().failure(),
        windows_prompt_probe::ProbeFailure::UnsupportedPlatform
    );
}
