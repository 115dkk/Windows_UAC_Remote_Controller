// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded local diagnostics, never authentication evidence. The public-to-crate
//! surface accepts only closed error/point enums; no frames, IDs or secret text.
use super::pairing_client::{PairingClientError, PairingLaunchError};
use crate::{PairingPeerError, ServiceError};
use std::sync::atomic::{AtomicU32, Ordering};
use windows::{
    Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
    },
    core::{PCWSTR, w},
};

static COUNT: AtomicU32 = AtomicU32::new(0);
#[derive(Clone, Copy, Debug)]
pub(crate) enum Point {
    HelperEnter,
    HelperConnected,
    RendezvousBound,
    HelperFailure,
    RendererCreate,
    RendererCreated,
    RendererResume,
    RendererEnter,
    RendererConnected,
    RendererObjectsReady,
    RendererBound,
    WindowOpened,
    RendererFailure,
    ServiceFailure,
}
pub(crate) fn milestone(point: Point) {
    emit(point, "ok", "none", 0);
}
pub(crate) fn service_failure_kind(code: u32) {
    emit(Point::ServiceFailure, "service-pairing", "fixed-code", code);
}
pub(crate) fn launch_failure(point: Point, error: PairingLaunchError) {
    match error {
        PairingLaunchError::Client(PairingClientError::Native { stage, hresult }) => emit(
            point,
            "client-native",
            &format!("{stage:?}"),
            hresult as u32,
        ),
        PairingLaunchError::Client(PairingClientError::Service(error)) => {
            service_failure(point, error)
        }
        PairingLaunchError::Native { operation, hresult } => emit(
            point,
            "launch-native",
            &format!("{operation:?}"),
            hresult as u32,
        ),
        PairingLaunchError::HelperExited { exit_code } => {
            emit(point, "helper-exit", "process", exit_code)
        }
        // Remaining variants contain no payload. Never Debug-format the entire
        // graph: future payload-bearing additions must be explicitly handled.
        PairingLaunchError::Client(error) => {
            let code = match error {
                PairingClientError::Busy => 1,
                PairingClientError::Closed => 2,
                PairingClientError::InvalidPhase => 3,
                PairingClientError::InvalidMessage => 4,
                PairingClientError::InvalidDeadline => 5,
                PairingClientError::DeadlineElapsed => 6,
                PairingClientError::Cancelled => 7,
                PairingClientError::EndOfStream => 8,
                PairingClientError::Rejected => 9,
                PairingClientError::Malformed => 10,
                PairingClientError::CleanupUnconfirmed => 11,
                PairingClientError::Native { .. } | PairingClientError::Service(_) => return,
            };
            emit(point, "client", "fixed-code", code);
        }
        PairingLaunchError::Protocol => emit(point, "launch", "protocol", 0),
        PairingLaunchError::InvalidPhase => emit(point, "launch", "phase", 0),
        PairingLaunchError::UserCancelled => emit(point, "launch", "user-cancelled", 0),
        PairingLaunchError::LaunchUnconfirmed => emit(point, "launch", "unconfirmed", 0),
        PairingLaunchError::Cancelled => emit(point, "launch", "cancelled", 0),
        PairingLaunchError::CleanupUnconfirmed => emit(point, "launch", "cleanup", 0),
    }
}
pub(crate) fn peer_failure(error: PairingPeerError) {
    match error {
        PairingPeerError::Native { stage, hresult } => emit(
            Point::ServiceFailure,
            "peer-native",
            &format!("{stage:?}"),
            hresult as u32,
        ),
        PairingPeerError::Service(error) => service_failure(Point::ServiceFailure, error),
        error => {
            let code = match error {
                PairingPeerError::Busy => 1,
                PairingPeerError::Closed => 2,
                PairingPeerError::InvalidPhase => 3,
                PairingPeerError::InvalidMessage => 4,
                PairingPeerError::InvalidDeadline => 5,
                PairingPeerError::DeadlineElapsed => 6,
                PairingPeerError::Cancelled => 7,
                PairingPeerError::EndOfStream => 8,
                PairingPeerError::Rejected => 9,
                PairingPeerError::Malformed => 10,
                PairingPeerError::CleanupUnconfirmed => 11,
                PairingPeerError::Native { .. } | PairingPeerError::Service(_) => return,
            };
            emit(Point::ServiceFailure, "peer", "fixed-code", code);
        }
    }
}
fn service_failure(point: Point, error: ServiceError) {
    match error {
        ServiceError::PairingClientNative { stage, hresult } => {
            emit(point, "client-native", &stage.to_string(), hresult as u32)
        }
        ServiceError::RendererNative { stage, hresult } => {
            emit(point, "renderer-native", &stage.to_string(), hresult as u32)
        }
        ServiceError::WindowsCall { operation, code } => {
            emit(point, "windows", &format!("{operation:?}"), code)
        }
        _ => emit(
            point,
            "service",
            "fixed-code",
            error.service_diagnostic_code(),
        ),
    }
}
fn reserve(counter: &AtomicU32) -> bool {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            if n < 32 { Some(n + 1) } else { None }
        })
        .is_ok()
}

fn record_text(point: Point, class: &'static str, stage: &str, code: u32) -> Option<String> {
    if stage.is_empty()
        || stage.len() > 64
        || !stage
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-'))
    {
        return None;
    }
    let message = format!(
        "UAC_PAIR_V1 version={} pid={} point={point:?} class={class} stage={stage} code={code:08x}",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );
    (message.is_ascii() && message.len() <= 256).then_some(message)
}

fn emit(point: Point, class: &'static str, stage: &str, code: u32) {
    if !reserve(&COUNT) {
        return;
    }
    let Some(message) = record_text(point, class, stage, code) else {
        return;
    };
    let wide: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed local source. One bounded owned NUL-terminated insertion;
    // synchronous calls, no raw data/user SID; release only the acquired handle.
    // Failure is best effort and never changes the original result/admission.
    unsafe {
        if let Ok(handle) = RegisterEventSourceW(PCWSTR::null(), w!("UACRemoteController.Pairing"))
        {
            let _ = ReportEventW(
                handle,
                EVENTLOG_INFORMATION_TYPE,
                0,
                1,
                None,
                0,
                Some(&[PCWSTR(wide.as_ptr())]),
                None,
            );
            let _ = DeregisterEventSource(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_budget_is_fixed_without_wrapping() {
        let counter = AtomicU32::new(0);
        for _ in 0..32 {
            assert!(reserve(&counter));
        }
        assert!(!reserve(&counter));
        assert_eq!(counter.load(Ordering::Relaxed), 32);
        assert!(!reserve(&AtomicU32::new(u32::MAX)));
    }
    #[test]
    fn diagnostic_text_rejects_non_token_stage_data() {
        let text =
            record_text(Point::RendererFailure, "renderer-native", "20", 0x80070005).unwrap();
        assert!(text.ends_with("class=renderer-native stage=20 code=80070005"));
        for value in [
            "private/path",
            "payload(text)",
            "line\nbreak",
            "\u{202e}",
            "",
        ] {
            assert!(record_text(Point::HelperFailure, "client", value, 0).is_none());
        }
        assert!(record_text(Point::HelperFailure, "client", &"x".repeat(65), 0).is_none());
    }
}
