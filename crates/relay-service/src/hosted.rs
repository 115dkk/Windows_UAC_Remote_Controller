// SPDX-License-Identifier: GPL-2.0-or-later
//! In-process opaque relay owner. No keys, signing or approval capabilities.
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    sync::Arc,
    thread::{self, JoinHandle},
};

use crate::{
    CancellationToken, PcRoleSource, RelayAbuseCounters, RelayError, RelayLimits, RelayPolicy,
    RelayReport,
    relay::{RelayAbuseCounterStore, run_with_policy_and_counters},
};

pub const EMBEDDED_RELAY_PORT: u16 = 7443;

/// Closed result of a finished embedded relay worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedRelayExit {
    Clean(RelayReport),
    Error(RelayError),
    Panicked,
}

/// An actual listener and bounded worker, owned by the desktop service lifecycle.
#[derive(Debug)]
pub struct HostedRelay {
    stop: CancellationToken,
    worker: Option<JoinHandle<Result<RelayReport, RelayError>>>,
    exit: Option<HostedRelayExit>,
    supports_ipv6: bool,
    abuse: Arc<RelayAbuseCounterStore>,
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
            #[cfg(windows)]
            windows_port_owner::set_exclusive_address_use(&socket)?;
            socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
            socket.listen(128)?;
            Ok::<TcpListener, io::Error>(socket.into())
        })();
        match dual_stack {
            Ok(listener) => Self::from_listener(listener, true),
            Err(_) => {
                #[cfg(windows)]
                let listener = {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )?;
                    // Windows otherwise allows a wildcard listener beside an
                    // existing loopback listener (or a later loopback hijack).
                    windows_port_owner::set_exclusive_address_use(&socket)?;
                    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
                    socket.listen(128)?;
                    TcpListener::from(socket)
                };
                #[cfg(not(windows))]
                let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
                Self::from_listener(listener, false)
            }
        }
    }

    pub fn supports_ipv6(&self) -> bool {
        self.supports_ipv6
    }

    /// Read live aggregate abuse counters without stopping or locking the relay.
    pub fn abuse_counters(&self) -> RelayAbuseCounters {
        self.abuse.snapshot()
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
        let abuse = Arc::new(RelayAbuseCounterStore::default());
        let worker_abuse = Arc::clone(&abuse);
        let worker = thread::Builder::new()
            .name("embedded-relay".into())
            .spawn(move || {
                runtime.block_on(run_with_policy_and_counters(
                    listener,
                    RelayLimits::default(),
                    RelayPolicy::new(PcRoleSource::LoopbackOnly),
                    worker_stop,
                    worker_abuse,
                ))
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            exit: None,
            supports_ipv6,
            abuse,
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

    fn collect_exit(&mut self) {
        if !self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            return;
        }
        let worker = self.worker.take().expect("finished worker exists");
        self.exit = Some(match worker.join() {
            Ok(Ok(report)) => HostedRelayExit::Clean(report),
            Ok(Err(error)) => HostedRelayExit::Error(error),
            Err(_) => HostedRelayExit::Panicked,
        });
    }

    /// Takes the closed result once the worker has finished. This never stops it.
    pub fn take_exit(&mut self) -> Option<HostedRelayExit> {
        self.collect_exit();
        self.exit.take()
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
        self.collect_exit();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn host_with_worker(worker: JoinHandle<Result<RelayReport, RelayError>>) -> HostedRelay {
        HostedRelay {
            stop: CancellationToken::new(),
            worker: Some(worker),
            exit: None,
            supports_ipv6: false,
            abuse: Arc::new(RelayAbuseCounterStore::default()),
        }
    }

    fn wait_for_exit(host: &mut HostedRelay) -> HostedRelayExit {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(exit) = host.take_exit() {
                return exit;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }

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

    #[cfg(windows)]
    #[test]
    fn embedded_listener_rejects_an_existing_loopback_listener() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let result = HostedRelay::start_embedded(occupied.local_addr().unwrap().port());
        assert!(
            result.is_err(),
            "wildcard relay must not coexist with a loopback listener"
        );
    }

    #[cfg(windows)]
    #[test]
    fn embedded_listener_prevents_a_later_loopback_bind() {
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let _host = HostedRelay::start_embedded(port).unwrap();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err());
    }

    #[test]
    fn abuse_counters_reads_all_shared_atomic_indicators() {
        let abuse = Arc::new(RelayAbuseCounterStore::default());
        abuse.count_evicted_pair();
        abuse.count_rejected_duplicate();
        abuse.count_rejected_pc_source();
        abuse.count_rejected_eviction();
        let host = HostedRelay {
            stop: CancellationToken::new(),
            worker: None,
            exit: None,
            supports_ipv6: false,
            abuse,
        };
        assert_eq!(
            host.abuse_counters(),
            RelayAbuseCounters {
                evicted_pairs: 1,
                rejected_duplicates: 1,
                rejected_pc_sources: 1,
                rejected_evictions: 1,
            }
        );
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

    #[test]
    fn finished_worker_exposes_clean_report_once() {
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let mut host = HostedRelay::start(address).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !host.drain() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(
            host.take_exit(),
            Some(HostedRelayExit::Clean(RelayReport::default()))
        );
        assert_eq!(host.take_exit(), None);
    }

    #[test]
    fn finished_worker_exposes_error_kind_once() {
        let mut host = host_with_worker(thread::spawn(|| Err(RelayError::TaskFailed)));
        assert_eq!(
            wait_for_exit(&mut host),
            HostedRelayExit::Error(RelayError::TaskFailed)
        );
        assert_eq!(host.take_exit(), None);
    }

    #[test]
    fn finished_worker_exposes_panicked_join_once() {
        let mut host = host_with_worker(thread::spawn(|| panic!("synthetic worker panic")));
        assert_eq!(wait_for_exit(&mut host), HostedRelayExit::Panicked);
        assert_eq!(host.take_exit(), None);
    }
}
