// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot developer diagnostic, not a user-facing product UI or UAC detector.

#![deny(unsafe_code)]

use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

use windows_observer::{DesktopCategory, observe_current_input_desktop};

const DESCRIPTION: &str =
    "uac-observe: developer diagnostic; read-only; not UAC detection or approval";
const USAGE: &str = "usage: uac-observe [--once | --help]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Once,
    Help,
}

fn parse_arguments(mut arguments: impl Iterator<Item = OsString>) -> Option<Mode> {
    let first = arguments.next();
    if arguments.next().is_some() {
        return None;
    }
    match first {
        None => Some(Mode::Once),
        Some(value) if value == "--once" => Some(Mode::Once),
        Some(value) if value == "--help" || value == "-h" => Some(Mode::Help),
        Some(_) => None,
    }
}

fn write_report(
    writer: &mut impl Write,
    session: u32,
    thread_desktop: DesktopCategory,
    input_desktop: DesktopCategory,
) -> io::Result<()> {
    writeln!(writer, "{DESCRIPTION}")?;
    writeln!(writer, "platform=windows")?;
    writeln!(writer, "process_session_id={session}")?;
    writeln!(writer, "thread_desktop={thread_desktop}")?;
    writeln!(writer, "input_desktop={input_desktop}")
}

fn write_error(message: impl std::fmt::Display) {
    // stderr may itself be unavailable; the caller still returns failure. Never
    // echo argument values, which could have accidentally contained a secret.
    let _ = writeln!(io::stderr().lock(), "uac-observe: {message}");
}

fn main() -> ExitCode {
    match parse_arguments(std::env::args_os().skip(1)) {
        None => {
            write_error(format_args!("invalid arguments; {USAGE}"));
            ExitCode::from(2)
        }
        Some(Mode::Help) => {
            let mut stdout = io::stdout().lock();
            if writeln!(stdout, "{DESCRIPTION}\n{USAGE}").is_err() {
                write_error("diagnostic output could not be written");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Some(Mode::Once) => {
            let observation = match observe_current_input_desktop() {
                Ok(observation) => observation,
                Err(error) => {
                    write_error(error);
                    return ExitCode::FAILURE;
                }
            };
            let mut stdout = io::stdout().lock();
            if write_report(
                &mut stdout,
                observation.process_session_id(),
                observation.thread_desktop(),
                observation.input_desktop(),
            )
            .is_err()
            {
                write_error("diagnostic output could not be written");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(arguments: &[&str]) -> Option<Mode> {
        parse_arguments(arguments.iter().map(|value| OsString::from(*value)))
    }

    #[test]
    fn no_arguments_and_once_are_one_shot_modes() {
        assert_eq!(mode(&[]), Some(Mode::Once));
        assert_eq!(mode(&["--once"]), Some(Mode::Once));
    }

    #[test]
    fn help_does_not_select_an_observation() {
        assert_eq!(mode(&["--help"]), Some(Mode::Help));
        assert_eq!(mode(&["-h"]), Some(Mode::Help));
    }

    #[test]
    fn unknown_repeated_and_combined_arguments_fail_without_echoing_values() {
        for arguments in [
            vec!["--poll"],
            vec!["--approve"],
            vec!["--once", "--once"],
            vec!["--once", "--help"],
            vec!["--once", "fixture-private-argument"],
            vec![""],
            vec!["--once=1"],
        ] {
            assert_eq!(mode(&arguments), None);
        }
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_arguments_are_rejected_without_lossy_conversion() {
        use std::os::windows::ffi::OsStringExt;
        let argument = OsString::from_wide(&[0xd800]);
        assert_eq!(parse_arguments([argument].into_iter()), None);
    }

    #[test]
    fn output_contains_only_diagnostic_label_session_and_categories() {
        let mut output = Vec::new();
        write_report(
            &mut output,
            42,
            DesktopCategory::Default,
            DesktopCategory::Other,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "uac-observe: developer diagnostic; read-only; not UAC detection or approval\n",
                "platform=windows\n",
                "process_session_id=42\n",
                "thread_desktop=Default\n",
                "input_desktop=Other(redacted)\n",
            )
        );
    }

    #[test]
    fn output_failure_is_returned_instead_of_reporting_success() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic output failure",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(
            write_report(
                &mut FailedWriter,
                1,
                DesktopCategory::Default,
                DesktopCategory::Winlogon
            )
            .is_err()
        );
    }
}
