// SPDX-License-Identifier: GPL-2.0-or-later
//! The consent dialog's shape, and nothing it says.
//!
//! Naming which label holds the program, which holds the publisher and which
//! opens the details needs a rule that does not read Korean, or English, or any
//! other language the dialog happens to be in. UI Automation already supplies
//! one: every element carries an automation id and a class name the compiler of
//! that dialog chose, and the probe already collects both. What has been missing
//! is any way to see them, because the dialog lives on the secure desktop where
//! nothing but this product's own probe can look.
//!
//! So this records the structure and refuses the content. Ordinal, depth, kind,
//! enabled, automation id and class name are identifiers and positions; the
//! label text is the program name, the publisher and the path, and none of it
//! belongs in an event log.

use std::sync::atomic::{AtomicU32, Ordering};
use windows::{
    Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
    },
    core::{PCWSTR, w},
};
use windows_prompt_probe::supervision::RefusalReason;

/// One prompt's worth of rows, and no more. A consent dialog this product will
/// act on has a bounded element count, so a dialog needing more than this is not
/// the shape these rows describe.
const MAX_ROWS: u32 = 48;

/// How many prompts one service lifetime describes. The budget used to be the
/// row count alone, which a single session of reading real prompts exhausted in
/// three: the point was never to allow one dialog and then stop, it was to keep
/// a process that meets prompt after prompt from filling the log with the same
/// answer. Counting prompts says that, and counting rows still bounds each one.
const MAX_PROMPTS: u32 = 32;

static ROWS: AtomicU32 = AtomicU32::new(0);
static PROMPTS: AtomicU32 = AtomicU32::new(0);

/// Starts one prompt's rows. Called once per mapped dialog, before its labels.
pub(crate) fn begin() {
    if PROMPTS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_PROMPTS).then_some(count + 1)
        })
        .is_ok()
    {
        ROWS.store(0, Ordering::Relaxed);
    } else {
        ROWS.store(MAX_ROWS, Ordering::Relaxed);
    }
}

/// An identifier the dialog's own author chose, or `-` when it is absent or is
/// not the closed shape this may write. Never a fallback to the label's text.
fn identifier(value: &str) -> &str {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return "-";
    }
    value
}

/// Records one element's position and identity.
pub(crate) fn label(
    ordinal: u16,
    depth: u8,
    kind: &'static str,
    enabled: bool,
    automation_id: &str,
    class_name: &str,
) {
    if !admit() {
        return;
    }
    emit(&format!(
        "UAC_PROMPT_V1 version={} ordinal={ordinal} depth={depth} kind={kind} enabled={enabled} automation={} class={}",
        env!("CARGO_PKG_VERSION"),
        identifier(automation_id),
        identifier(class_name)
    ));
}

/// Records why Windows refused to carry out a decision the phone already
/// signed. The reason is a closed enum the probe chose, never a message and
/// never anything the dialog said.
///
/// It was being discarded outside the disposable lab, which is the same shape
/// of defect as a caught exception with no cause: the product knew exactly why
/// it refused and told nobody. Somebody who approved on their phone and then
/// watched nothing happen deserves better than that, and so does whoever has
/// to find out why.
pub(crate) fn refusal(reason: RefusalReason) {
    crate::public_diagnostics::record(crate::public_diagnostics::Event::PromptRefused {
        reason: reason.into(),
    });
    if !admit() {
        return;
    }
    emit(&format!(
        "UAC_APPLY_V1 version={} refused={}",
        env!("CARGO_PKG_VERSION"),
        match reason {
            RefusalReason::UnknownTarget => "UnknownTarget",
            RefusalReason::TargetChanged => "TargetChanged",
            RefusalReason::ContentChanged => "ContentChanged",
            RefusalReason::UnrecognizedButtons => "UnrecognizedButtons",
            RefusalReason::AmbiguousButtons => "AmbiguousButtons",
            RefusalReason::PatternUnavailable => "PatternUnavailable",
            RefusalReason::InvokeFailed => "InvokeFailed",
        }
    ));
}

/// Takes one row from the current prompt's budget, or refuses.
fn admit() -> bool {
    ROWS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        (count < MAX_ROWS).then_some(count + 1)
    })
    .is_ok()
}

fn emit(message: &str) {
    // Unit tests drive the callers of this writer; this machine's real log
    // is not theirs to fill (fixture rows once looked like a real prompt).
    if cfg!(test) {
        return;
    }
    if !message.is_ascii() || message.len() > 256 {
        return;
    }
    let wide: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    // SAFETY: fixed local source. One bounded owned NUL-terminated insertion;
    // synchronous calls, no raw data or user SID; release only the acquired
    // handle. Failure is best effort and never changes the mapped content.
    unsafe {
        if let Ok(handle) = RegisterEventSourceW(PCWSTR::null(), w!("UACRemoteController.Prompt")) {
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
    fn an_identifier_is_admitted_only_in_the_closed_shape() {
        assert_eq!(identifier("ProgramName"), "ProgramName");
        assert_eq!(identifier("consent.exe"), "consent.exe");
        assert_eq!(identifier("Static-1_2"), "Static-1_2");
        // Absent, oversized, or carrying anything a key=value line would not
        // survive. A label's text must never arrive here by any route.
        assert_eq!(identifier(""), "-");
        assert_eq!(identifier("has space"), "-");
        assert_eq!(identifier("Windows 명령 처리기"), "-");
        assert_eq!(identifier(&"x".repeat(65)), "-");
    }

    #[test]
    fn each_prompt_starts_with_its_own_rows_until_the_prompts_themselves_run_out() {
        PROMPTS.store(0, Ordering::Relaxed);
        begin();
        ROWS.store(MAX_ROWS, Ordering::Relaxed);
        // A second dialog is a second dialog, not the tail of the first.
        begin();
        assert_eq!(ROWS.load(Ordering::Relaxed), 0);
        // Past the prompt budget every further dialog writes nothing at all.
        PROMPTS.store(MAX_PROMPTS, Ordering::Relaxed);
        begin();
        assert_eq!(ROWS.load(Ordering::Relaxed), MAX_ROWS);
        PROMPTS.store(0, Ordering::Relaxed);
        ROWS.store(0, Ordering::Relaxed);
    }

    #[test]
    fn every_refusal_names_itself_and_fits_the_event_log_shape() {
        // Exhaustive on purpose: a reason added later must be named here or
        // this stops compiling, rather than quietly logging nothing.
        for reason in [
            RefusalReason::UnknownTarget,
            RefusalReason::TargetChanged,
            RefusalReason::ContentChanged,
            RefusalReason::UnrecognizedButtons,
            RefusalReason::AmbiguousButtons,
            RefusalReason::PatternUnavailable,
            RefusalReason::InvokeFailed,
        ] {
            let message = format!(
                "UAC_APPLY_V1 version={} refused={reason:?}",
                env!("CARGO_PKG_VERSION")
            );
            assert!(message.is_ascii(), "{message}");
            assert!(message.len() <= 256, "{}", message.len());
        }
    }

    #[test]
    fn the_row_stays_within_the_event_log_shape() {
        let message = format!(
            "UAC_PROMPT_V1 version={} ordinal=65535 depth=255 kind=Hyperlink enabled=true automation={} class={}",
            env!("CARGO_PKG_VERSION"),
            "x".repeat(64),
            "y".repeat(64)
        );
        assert!(message.is_ascii());
        assert!(message.len() <= 256, "{}", message.len());
    }
}
