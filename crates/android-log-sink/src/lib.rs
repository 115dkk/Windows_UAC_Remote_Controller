// SPDX-License-Identifier: GPL-2.0-or-later
//! One bounded device-log sink for closed diagnostic tokens.
//!
//! This is not a capability, a key, a store or an authorization step. It reads
//! and writes no request, notification or key material, and decides nothing
//! about an approval or a denial. It writes fixed tokens to the device log and
//! returns.
//!
//! **Why it is its own crate.** The caller is the crate that holds the phone's
//! requests, leases and key references, and the workspace forbids every unsafe
//! block there on purpose. Reaching `liblog` needs one `extern` declaration and
//! one call. Weakening the lint across a crate of that size to buy one log line
//! is a bad trade, so the opt-out lives here, in a crate whose whole surface is
//! [`write`], and [`ffi`] is the only module allowed to use it.
//!
//! **Why not stderr.** `tao`'s Android glue pipes stdout and stderr into logcat
//! under `RustStdoutStderr`, but it installs that pipe inside the window's own
//! `create`. The work worth diagnosing here runs in a foreground service, which
//! starts without an Activity and keeps running after one is destroyed, so that
//! pipe is often simply absent. `liblog` does not care whether a window exists.

#[allow(unsafe_code)]
mod ffi;

use std::sync::atomic::{AtomicU32, Ordering};

/// Total lines one process may write. A retiring owner emits a handful; an
/// unbounded sink lets a spinning loop bury the line that matters under its own
/// repetitions. Every caller shares this budget deliberately, because the first
/// few lines of any kind are what name a failure.
const MAX_LINES: u32 = 64;
static WRITTEN: AtomicU32 = AtomicU32::new(0);

/// Accepts a line only if it is the closed shape callers are expected to build:
/// printable ASCII, no control bytes, bounded. A caller that somehow assembles
/// anything else writes nothing rather than having it widened for them.
#[must_use]
pub fn admissible(line: &str) -> bool {
    !line.is_empty()
        && line.len() <= 256
        && line
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

/// Writes one bounded line under `tag`, which must be a NUL-terminated literal.
///
/// Best effort in every sense: a refused line, an exhausted budget and a
/// missing sink all leave the caller's own result untouched. Nothing here is
/// allowed to become a reason an owner, a request or a decision changes.
pub fn write(tag: &'static [u8], line: &str) {
    if !admissible(line) || !tag.ends_with(&[0]) {
        return;
    }
    if WRITTEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_LINES).then_some(count + 1)
        })
        .is_err()
    {
        return;
    }
    ffi::write(tag, line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_closed_shape_is_admitted() {
        assert!(admissible("UAC_NATIVE_INTAKE_V1 site=PEER_WORK error=BUSY"));
        assert!(!admissible(""));
        assert!(!admissible("has\na newline"));
        assert!(!admissible("has\ta tab"));
        assert!(!admissible("한글"));
        assert!(!admissible(&"x".repeat(257)));
        assert!(admissible(&"x".repeat(256)));
    }

    #[test]
    fn a_tag_that_is_not_nul_terminated_is_refused_before_the_boundary() {
        let before = WRITTEN.load(Ordering::Relaxed);
        write(b"NoNulHere", "UAC_NATIVE_INTAKE_V1 site=CLOCK error=BUSY");
        assert_eq!(WRITTEN.load(Ordering::Relaxed), before);
    }

    #[test]
    fn the_budget_stops_a_repeating_caller_instead_of_following_it() {
        WRITTEN.store(MAX_LINES - 1, Ordering::Relaxed);
        write(b"UacNative\0", "UAC_NATIVE_INTAKE_V1 site=CLOCK error=BUSY");
        assert_eq!(WRITTEN.load(Ordering::Relaxed), MAX_LINES);
        write(b"UacNative\0", "UAC_NATIVE_INTAKE_V1 site=CLOCK error=BUSY");
        assert_eq!(WRITTEN.load(Ordering::Relaxed), MAX_LINES);
        WRITTEN.store(0, Ordering::Relaxed);
    }
}
