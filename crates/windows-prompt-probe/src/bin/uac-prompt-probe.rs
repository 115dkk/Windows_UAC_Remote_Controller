// SPDX-License-Identifier: GPL-2.0-or-later
//! Argument-free developer helper. The future privileged supervisor must enforce
//! a five-second process budget. No service/launch/elevation fallback lives here.
#![forbid(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
use windows_prompt_probe::probe_once;

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        let _ = writeln!(
            io::stderr().lock(),
            "status=invalid_arguments; helper_accepts_no_arguments=true"
        );
        return ExitCode::from(2);
    }
    // This dedicated helper must never print arbitrary panic payloads while a
    // native scope is live. The library does not replace its caller's global hook.
    std::panic::set_hook(Box::new(|_| {}));
    // No output is produced while the worker or scoped native resources remain.
    let result = probe_once();
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.cleanup().is_some())
    {
        // Native cleanup did not establish release. Exit without a report;
        // the OS tears down this helper. The library still preserves both
        // fixed-metadata causes for its trusted supervisor integration.
        return ExitCode::from(3);
    }
    let mut output = io::stdout().lock();
    if writeln!(output, "scope=read_only_consent_ui_capabilities; supervisor_required=true; hard_timeout_guaranteed=false; request_identity_proven=false").is_err() {
        return ExitCode::FAILURE;
    }
    match result {
        Ok(report) => {
            if writeln!(
                output,
                "status=capabilities_observed; counts={:?}",
                report.counts()
            )
            .is_ok()
            {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            let _ = writeln!(output, "status=unavailable; failure={error}");
            ExitCode::FAILURE
        }
    }
}
