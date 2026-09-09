// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed argument-free helper. No stdout/stdio inheritance, target arguments,
//! unsupervised probe, elevation or local input/approval interface.
#![forbid(unsafe_code)]
use std::process::ExitCode;
use windows_prompt_probe::supervision::run_supervised_helper;

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        return ExitCode::from(2);
    }
    // This dedicated helper must never print arbitrary panic payloads while a
    // native scope is live. The library does not replace its caller's global hook.
    std::panic::set_hook(Box::new(|_| {}));
    ExitCode::from(run_supervised_helper().code())
}
