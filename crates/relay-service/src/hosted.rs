// SPDX-License-Identifier: GPL-2.0-or-later
//! In-process opaque relay owner. No keys, signing or approval capabilities.
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket},
    thread::{self, JoinHandle},
};

use crate::{CancellationToken, RelayLimits};

pub const EMBEDDED_RELAY_PORT: u16 = 7443;

/// An actual listener and bounded worker, owned by the desktop service lifecycle.
#[derive(Debug)]
pub struct HostedRelay {
    stop: CancellationToken,
    worker: Option<JoinHandle<()>>,
    supports_ipv6: bool,
}

impl HostedRelay {
    pub fn start(address: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(address)?;
        Self::from_listener(listener, address.is_ipv6())
    }

    /// A single dual-stack socket feeds a single rendezvous room owner. If the
    /// OS cannot provide dual stack, use IPv4 only, never two isolated relays.
    pub fn start_embedded(port: u16) -> io::Result<Self> {
        let dual_stack = (|| {
            let socket = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.set_only_v6(false)?;
            socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
            socket.listen(128)?;
            Ok::<TcpListener, io::Error>(socket.into())
        })();
        match dual_stack {
            Ok(listener) => Self::from_listener(listener, true),
            Err(_) => Self::from_listener(TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?, false),
        }
    }

    pub fn supports_ipv6(&self) -> bool {
        self.supports_ipv6
    }

    fn from_listener(listener: TcpListener, supports_ipv6: bool) -> io::Result<Self> {
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
            supports_ipv6,
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

/// Ask the local routing table for IPv4, then a global IPv6 source. UDP connect
/// sets a destination only: no send, DNS lookup or public-IP service is used.
/// This is a LAN address, not proof of NAT traversal or mobile-network reachability.
pub fn local_endpoint() -> io::Result<SocketAddr> {
    let ipv4 = (|| {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
        socket.local_addr()
    })();
    if let Ok(address) = ipv4 {
        if !address.ip().is_unspecified()
            && !address.ip().is_loopback()
            && !address.ip().is_multicast()
        {
            return Ok(SocketAddr::new(address.ip(), EMBEDDED_RELAY_PORT));
        }
    }
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9))?;
    let address = socket.local_addr()?.ip();
    if !crate::direct::global(address) {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no routed address",
        ));
    }
    Ok(SocketAddr::new(address, EMBEDDED_RELAY_PORT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn embedded_dual_stack_uses_one_rendezvous_room_owner() {
        use crate::{READY_MARKER, Registration, Role, RouteId};
        use std::io::{Read, Write};
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let host = HostedRelay::start_embedded(port).unwrap();
        assert!(
            host.supports_ipv6(),
            "dual-stack listener required by this native loopback test"
        );
        let mut pc = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut phone = std::net::TcpStream::connect((Ipv6Addr::LOCALHOST, port)).unwrap();
        pc.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        phone
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let route = RouteId::new([17; 32]).unwrap();
        pc.write_all(&Registration::new(Role::Pc, route).to_wire())
            .unwrap();
        phone
            .write_all(&Registration::new(Role::Phone, route).to_wire())
            .unwrap();
        let mut marker = [0; READY_MARKER.len()];
        pc.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, READY_MARKER);
        phone.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, READY_MARKER);
        // Synthetic opaque bytes, not application authentication/UAC evidence.
        pc.write_all(b"synthetic").unwrap();
        let mut payload = [0; 9];
        phone.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"synthetic");
        drop(host);
    }

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
