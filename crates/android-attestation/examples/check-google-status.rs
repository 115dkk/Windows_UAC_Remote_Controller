// SPDX-License-Identifier: GPL-2.0-or-later
//! Explicit diagnostic: one fixed public HTTPS GET, no device or registry access.
#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 {
        eprintln!("This diagnostic accepts no arguments.");
        return std::process::ExitCode::FAILURE;
    }
    match android_attestation::fetch_google_status() {
        Ok(_snapshot) => {
            println!(
                "Fixed Google status fetch and bounded parsing succeeded; no device was verified or enrolled."
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Fixed Google status fetch failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
