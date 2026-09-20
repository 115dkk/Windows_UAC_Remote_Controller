// SPDX-License-Identifier: GPL-2.0-or-later
//! The one `liblog` call. Nothing else belongs in this file.

/// Android's `ANDROID_LOG_INFO`. Fixed by the platform header, not a choice
/// this crate gets to revisit.
const ANDROID_LOG_INFO: i32 = 4;

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_write(
        priority: i32,
        tag: *const std::ffi::c_char,
        text: *const std::ffi::c_char,
    ) -> i32;
}

/// Writes one already-vetted line under the given already-NUL-terminated tag.
///
/// The caller owns every precondition worth stating: `line` has been checked to
/// be bounded printable ASCII, and `tag` is a `b"...\0"` literal. Both are
/// therefore representable as C strings, and neither can be built from anything
/// a peer sent.
pub(crate) fn write(tag: &'static [u8], line: &str) {
    #[cfg(target_os = "android")]
    {
        let Ok(text) = std::ffi::CString::new(line) else {
            return;
        };
        // SAFETY: `liblog` is linked into every Android process, so the symbol
        // resolves. `tag` is a NUL-terminated literal with static lifetime and
        // `text` is an owned NUL-terminated buffer; both outlive the call. The
        // callee reads them and retains neither, and the returned count is not
        // information this crate acts on.
        unsafe {
            __android_log_write(
                ANDROID_LOG_INFO,
                tag.as_ptr().cast::<std::ffi::c_char>(),
                text.as_ptr(),
            );
        }
    }
    // Off Android the line is built and vetted exactly as it would be, then
    // goes nowhere. That keeps the checks under test on every host.
    #[cfg(not(target_os = "android"))]
    let _ = (tag, line, ANDROID_LOG_INFO);
}
