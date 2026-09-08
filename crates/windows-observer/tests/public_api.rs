// SPDX-License-Identifier: GPL-2.0-or-later
//! These tests do not call Windows APIs or induce UAC. Root owns real observation.

#![deny(unsafe_code)]

use windows_observer::{
    DesktopCategory, DesktopNameError, DesktopObservation, DesktopTarget, ObserveError,
    ObserveOperation, observe_current_input_desktop,
};

#[test]
fn observation_function_has_a_safe_owned_result_interface() {
    let function: fn() -> Result<DesktopObservation, ObserveError> = observe_current_input_desktop;
    let _ = function;
}

#[test]
fn error_and_category_diagnostics_have_only_fixed_metadata() {
    assert_eq!(format!("{:?}", DesktopCategory::Other), "Other(redacted)");
    assert_eq!(format!("{}", DesktopCategory::Winlogon), "Winlogon");
    let failed = ObserveError::WindowsCall {
        operation: ObserveOperation::OpenInputDesktop,
        hresult: -2_147_024_891, // Synthetic HRESULT fixture: access denied.
    };
    let text = failed.to_string();
    assert!(text.contains("read-only input desktop open"));
    assert!(text.contains("0x80070005"));
    let malformed = ObserveError::DesktopName {
        target: DesktopTarget::Input,
        reason: DesktopNameError::InvalidUtf16,
    };
    assert!(malformed.to_string().contains("invalid UTF-16"));
}

#[cfg(not(windows))]
#[test]
fn unsupported_platform_returns_an_explicit_error_not_a_noop_success() {
    assert_eq!(
        observe_current_input_desktop(),
        Err(ObserveError::UnsupportedPlatform)
    );
}
