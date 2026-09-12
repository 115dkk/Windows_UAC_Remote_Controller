// SPDX-License-Identifier: GPL-2.0-or-later
//! In-process opaque relay owner. No keys, signing or approval capabilities.
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    thread::{self, JoinHandle},
};

use crate::{CancellationToken, RelayLimits};

pub const EMBEDDED_RELAY_PORT: u16 = 7443;

/// An actual listener and bounded worker, owned by the desktop service lifecycle.
#[derive(Debug)]
pub struct HostedRelay {
    stop: CancellationToken,
    worker: Option<JoinHandle<()>>,
}

impl HostedRelay {
    pub fn start(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Conversion happens while the matching reactor is entered, before a
        // successful start is returned. Failure closes the original listener.
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("embedded-relay".into())
            .spawn(move || {
                let _ = runtime.block_on(crate::run(listener, RelayLimits::default(), worker_stop));
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    pub fn is_running(&self) -> bool {
        !self.stop.is_cancelled()
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    pub fn cancel(&self) {
        self.stop.cancel();
    }

    /// Nonblocking join: a cancellation request is not a completed shutdown.
    pub fn drain(&mut self) -> bool {
        self.cancel();
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            return false;
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        true
    }

    pub fn remaining_owners(&self) -> usize {
        usize::from(self.worker.is_some())
    }
}

impl Drop for HostedRelay {
    fn drop(&mut self) {
        self.cancel();
        // The relay has bounded cancellation/drain deadlines and owns no
        // privileged state. Never leave a detached listener after owner exit.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Ask the local routing table for its default IPv4 source address. UDP connect
/// sets a destination only: no send, DNS lookup or public-IP service is used.
/// This is a LAN address, not proof of NAT traversal or mobile-network reachability.
pub fn local_endpoint() -> io::Result<SocketAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
    let address = socket.local_addr()?.ip();
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no LAN address",
        ));
    }
    Ok(SocketAddr::new(address, EMBEDDED_RELAY_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn occupied_port_is_not_reported_as_started() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(HostedRelay::start(occupied.local_addr().unwrap()).is_err());
    }

    #[test]
    fn service_owned_listener_stops_and_releases_its_port() {
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut host = HostedRelay::start(address).unwrap();
        assert!(host.is_running());
        let client = std::net::TcpStream::connect(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !host.drain() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(!host.is_running());
        assert_eq!(host.remaining_owners(), 0);
        drop(client);
        assert!(TcpListener::bind(address).is_ok());
    }
}
