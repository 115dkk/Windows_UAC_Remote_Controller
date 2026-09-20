// SPDX-License-Identifier: GPL-2.0-or-later
//! ROOT-approved help/invalid-argument subprocesses only. No bind path is invoked.

use std::{
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct HelpOnlyChild(Option<Child>);

impl Drop for HelpOnlyChild {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn help_only_process(arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_relay-service"));
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW for this help-only child.
    }
    let mut child = HelpOnlyChild(Some(
        command.spawn().expect("start bounded help-only fixture"),
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child
            .0
            .as_mut()
            .expect("owned child")
            .try_wait()
            .expect("read owned child status")
            .is_some()
        {
            let output = child
                .0
                .take()
                .expect("completed child")
                .wait_with_output()
                .expect("fixed CLI output");
            assert!(
                output.stdout.len() <= 4_096 && output.stderr.len() <= 4_096,
                "CLI diagnostic is unexpectedly large"
            );
            return output;
        }
        assert!(
            Instant::now() < deadline,
            "help/invalid-argument command unexpectedly kept running"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn help_documents_loopback_default_and_untrusted_carrier_without_starting_a_listener() {
    let output = help_only_process(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("fixed UTF-8 help");
    assert!(text.contains("127.0.0.1:7443"));
    assert!(text.contains("explicit --listen"));
    assert!(text.contains("not an approval/authentication server"));
    assert!(text.contains("no plaintext fallback"));
    assert!(output.stderr.is_empty());
}

#[test]
fn invalid_cli_arguments_never_echo_input_or_fall_back_to_default_binding() {
    for arguments in [
        vec!["--listen"],
        vec!["--listen", "SYNTHETIC-DO-NOT-ECHO"],
        vec!["--listen", "example.invalid:7443"],
        vec!["--unknown"],
        vec!["--help", "SYNTHETIC-DO-NOT-ECHO"],
        vec!["--listen", "127.0.0.1:0", "--unexpected"],
    ] {
        let output = help_only_process(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).expect("fixed UTF-8 rejection");
        assert!(!text.contains("SYNTHETIC-DO-NOT-ECHO"));
        assert!(!text.contains("example.invalid"));
        assert!(!text.contains("127.0.0.1:0"));
    }
}
