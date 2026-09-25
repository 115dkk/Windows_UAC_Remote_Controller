// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg(windows)]

use std::{
    net::TcpListener,
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
        let reserved = TcpListener::bind(address).unwrap();
        let endpoint = reserved.local_addr().unwrap();
        drop(reserved);
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "child_listener", "--ignored", "--nocapture"])
                .env("PORT_OWNER_TEST_ENDPOINT", endpoint.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
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

// Invoked only by the parent test with a numeric loopback endpoint. Even if the
// parent exits unexpectedly, this child drops its listener after ten seconds.
#[test]
#[ignore = "bounded helper invoked by identifies_child_listener_on_ipv4_and_ipv6"]
fn child_listener() {
    let endpoint: std::net::SocketAddr = std::env::var("PORT_OWNER_TEST_ENDPOINT")
        .unwrap()
        .parse()
        .unwrap();
    assert!(endpoint.ip().is_loopback());
    let _listener = TcpListener::bind(endpoint).unwrap();
    std::thread::sleep(Duration::from_secs(10));
}
