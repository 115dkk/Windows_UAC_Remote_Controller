// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg(windows)]

use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use windows_port_owner::listener_owner;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn skips_this_process() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let listener = TcpListener::bind(address).unwrap();
        assert_eq!(
            listener_owner(listener.local_addr().unwrap().port()).unwrap(),
            None
        );
    }
}

#[test]
fn identifies_child_listener_on_ipv4_and_ipv6() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "child_listener", "--ignored", "--nocapture"])
                .env("PORT_OWNER_TEST_ADDRESS", address)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let output = child.0.stdout.take().unwrap();
        let mut lines = BufReader::new(output).lines();
        let endpoint: SocketAddr = lines
            .find_map(|line| {
                line.unwrap()
                    .strip_prefix("PORT_OWNER_TEST_ENDPOINT=")
                    .map(str::to_owned)
            })
            .expect("listener child exited before reporting its endpoint")
            .parse()
            .unwrap();
        assert!(endpoint.ip().is_loopback() && endpoint.port() != 0);
        assert_eq!(endpoint.is_ipv4(), address.starts_with("127."));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(owner) = listener_owner(endpoint.port()).unwrap() {
                assert_eq!(owner.pid, child.0.id());
                assert!(owner.image_name.unwrap().ends_with(".exe"));
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "listener child exited before observation"
            );
            assert!(Instant::now() < deadline, "child listener was not observed");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

// Invoked only by the parent test with one fixed loopback family. The child
// chooses and retains port 0, then reports that owned endpoint to the parent.
// Even if the parent exits unexpectedly, the listener closes after ten seconds.
#[test]
#[ignore = "bounded helper invoked by identifies_child_listener_on_ipv4_and_ipv6"]
fn child_listener() {
    let address = std::env::var("PORT_OWNER_TEST_ADDRESS").unwrap();
    assert!(matches!(address.as_str(), "127.0.0.1:0" | "[::1]:0"));
    let listener = TcpListener::bind(address).unwrap();
    let endpoint = listener.local_addr().unwrap();
    println!("PORT_OWNER_TEST_ENDPOINT={endpoint}");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(10));
}
