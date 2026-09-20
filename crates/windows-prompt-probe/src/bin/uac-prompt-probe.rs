// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed supervised helper. It accepts no arguments for one-shot observation or
//! the exact `watch` argument for the authenticated long-running service channel.
#![forbid(unsafe_code)]
use std::process::ExitCode;
use windows_prompt_probe::{Command, run_watch_helper, supervision::run_supervised_helper};

fn main() -> ExitCode {
    let command = match Command::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(_) => return ExitCode::from(2),
    };
    // This dedicated helper must never print arbitrary panic payloads while a
    // native scope is live. The library does not replace its caller's global hook.
    std::panic::set_hook(Box::new(|_| {}));
    let exit = match command {
        Command::ObserveOnce => run_supervised_helper(),
        Command::Watch => run_watch_helper(),
    };
    ExitCode::from(exit.code())
}
