// SPDX-License-Identifier: GPL-2.0-or-later
//! Router discovery is a routing hint, never peer authentication. All remote
//! traffic still requires the existing end-to-end pinned encrypted protocol.
//! No cloud, STUN, credentials, router-wide changes or arbitrary URL interface.
mod igd;
mod obligations;
mod pcp;

use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::CancellationToken;

const LEASE_SECONDS: u32 = 600;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const CANDIDATE_SECONDS: u32 = 60;

/// These states deliberately contain no claim of external reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectGatewayState {
    Discovering,
    LanOnly,
    MappedCandidate,
    Ipv6Candidate,
    PublicIpv4Candidate,
    Unavailable,
    Stopped,
}

#[derive(Clone)]
pub struct DirectGatewaySnapshot {
    pub state: DirectGatewayState,
    candidates: Vec<SocketAddr>,
    /// Maximum remaining publication lifetime, not proof of reachability.
    pub validity_seconds: u32,
    expires: Instant,
}

impl DirectGatewaySnapshot {
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    pub fn remaining_validity_seconds(&self) -> u32 {
        self.validity_seconds.min(
            u32::try_from(
                self.expires
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
            )
            .unwrap_or(0),
        )
    }

    fn empty(state: DirectGatewayState) -> Self {
        Self {
            state,
            candidates: Vec::new(),
            validity_seconds: 0,
            expires: Instant::now(),
        }
    }

    fn new(state: DirectGatewayState, candidates: Vec<SocketAddr>, seconds: u32) -> Self {
        debug_assert!(candidates.len() <= 4);
        Self {
            state,
            candidates,
            validity_seconds: seconds,
            expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
        }
    }
}

impl fmt::Debug for DirectGatewaySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectGatewaySnapshot")
            .field("state", &self.state)
            .field("candidate_count", &self.candidates.len())
            .field("validity_seconds", &self.validity_seconds)
            .finish_non_exhaustive()
    }
}

/// One thread, one current-thread reactor, no detached discovery or I/O tasks.
/// `drain` is nonblocking; dropping cancels and joins the bounded I/O owner.
pub struct DirectGatewayOwner {
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
    worker: Option<JoinHandle<()>>,
}

impl fmt::Debug for DirectGatewayOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectGatewayOwner")
            .field("cancelled", &self.stop.is_cancelled())
            .field("remaining_owners", &self.remaining_owners())
            .finish_non_exhaustive()
    }
}

impl DirectGatewayOwner {
    /// Call only while the matching TCP relay listener is alive. `internal`
    /// must be its selected routed address, not wildcard or loopback. IPv6-only
    /// hosts publish a global address candidate without inventing a NAT mapping.
    pub fn start(internal: SocketAddr) -> io::Result<Self> {
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| io::Error::other("mapping nonce unavailable"))?;
        Self::start_with_mapping_nonce(internal, nonce)
    }

    /// Optional service-owned persistence seam for PCP restart continuity.
    /// The argument is a protected, OS-random base seed, not a wire nonce,
    /// password or peer key. The wire nonce is domain-separated per numeric
    /// PCP server and local tuple; a different gateway uses a different nonce.
    /// This seed is used only for router mapping ownership, never authorization.
    pub fn start_with_mapping_nonce(internal: SocketAddr, nonce: [u8; 12]) -> io::Result<Self> {
        let valid = match internal {
            SocketAddr::V4(address) => usable_local(*address.ip()),
            SocketAddr::V6(address) => address.scope_id() == 0 && global((*address.ip()).into()),
        };
        if internal.port() == 0 || !valid || nonce == [0; 12] {
            return Err(invalid_input());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let stop = CancellationToken::new();
        let shared = Arc::new(Mutex::new(DirectGatewaySnapshot::empty(
            DirectGatewayState::Discovering,
        )));
        let worker_stop = stop.clone();
        let worker_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("direct-gateway".into())
            .spawn(move || {
                runtime.block_on(async move {
                    match internal {
                        SocketAddr::V4(address) => {
                            run(address, nonce, worker_stop, worker_shared).await
                        }
                        SocketAddr::V6(_) => run_ipv6(internal, worker_stop, worker_shared).await,
                    }
                })
            })?;
        Ok(Self {
            stop,
            shared,
            worker: Some(worker),
        })
    }

    /// Never waits for discovery or a mutex. On contention/staleness publish no
    /// candidates; the next application poll may use the refreshed snapshot.
    pub fn snapshot(&self) -> DirectGatewaySnapshot {
        if self.stop.is_cancelled() {
            return DirectGatewaySnapshot::empty(DirectGatewayState::Stopped);
        }
        if self.worker.as_ref().is_none_or(JoinHandle::is_finished) {
            return DirectGatewaySnapshot::empty(DirectGatewayState::Unavailable);
        }
        let Ok(value) = self.shared.try_lock() else {
            return DirectGatewaySnapshot::empty(DirectGatewayState::Discovering);
        };
        if value.candidates.is_empty() {
            return value.clone();
        }
        let seconds = value
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        if seconds == 0 {
            return DirectGatewaySnapshot::empty(DirectGatewayState::Discovering);
        }
        let mut result = value.clone();
        result.validity_seconds = u32::try_from(seconds).unwrap_or(CANDIDATE_SECONDS);
        result
    }

    pub fn cancel(&self) {
        self.stop.cancel();
    }

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

impl Drop for DirectGatewayOwner {
    fn drop(&mut self) {
        self.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Network {
    internal: SocketAddrV4,
    gateway: Ipv4Addr,
    // Only globally routable addresses from the SAME selected adapter.
    ipv6: Vec<IpAddr>,
}

impl Network {
    fn same_mapping_path(&self, other: &Self) -> bool {
        self.internal == other.internal && self.gateway == other.gateway
    }
}

fn publish(shared: &Mutex<DirectGatewaySnapshot>, snapshot: DirectGatewaySnapshot) {
    if let Ok(mut value) = shared.lock() {
        *value = snapshot;
    }
}

async fn run(
    internal: SocketAddrV4,
    nonce: [u8; 12],
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
) {
    let mut mappings = obligations::MappingObligations::new();
    loop {
        if stop.is_cancelled() {
            break;
        }
        let network = discover(internal);
        mappings.poll(network.as_ref(), &stop, nonce).await;
        let Some(network) = network else {
            let snapshot = if crate::local_endpoint()
                .is_ok_and(|address| address.ip() == IpAddr::V4(*internal.ip()))
            {
                DirectGatewaySnapshot::new(
                    local_ipv4_state(*internal.ip()),
                    vec![internal.into()],
                    CANDIDATE_SECONDS,
                )
            } else {
                DirectGatewaySnapshot::empty(DirectGatewayState::Unavailable)
            };
            publish(&shared, snapshot);
            if pause(&stop, REFRESH_INTERVAL).await {
                break;
            }
            continue;
        };
        let mut candidates = vec![SocketAddr::V4(internal)];
        candidates.extend(
            network
                .ipv6
                .iter()
                .take(2)
                .map(|ip| SocketAddr::new(*ip, internal.port())),
        );
        let mut seconds = CANDIDATE_SECONDS;
        let state = if let Some((endpoint, remaining)) = mappings.candidate() {
            if !candidates.contains(&endpoint) {
                candidates.push(endpoint);
            }
            seconds = seconds.min(remaining);
            DirectGatewayState::MappedCandidate
        } else if global(IpAddr::V4(*internal.ip())) {
            DirectGatewayState::PublicIpv4Candidate
        } else if !network.ipv6.is_empty() {
            DirectGatewayState::Ipv6Candidate
        } else {
            DirectGatewayState::LanOnly
        };
        publish(
            &shared,
            DirectGatewaySnapshot::new(state, candidates, seconds),
        );
        // Bounded retry backoff, while candidate validity remains short. With
        // no successful mapping this retries at 30, 60, then 120 seconds.
        if pause(&stop, REFRESH_INTERVAL).await {
            break;
        }
    }
    publish(
        &shared,
        DirectGatewaySnapshot::empty(DirectGatewayState::Stopped),
    );
    mappings.shutdown(discover(internal).as_ref()).await;
}

async fn run_ipv6(
    internal: SocketAddr,
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
) {
    loop {
        if stop.is_cancelled() {
            break;
        }
        let snapshot = if selected_ipv6(internal) {
            DirectGatewaySnapshot::new(
                DirectGatewayState::Ipv6Candidate,
                vec![internal],
                CANDIDATE_SECONDS,
            )
        } else {
            DirectGatewaySnapshot::empty(DirectGatewayState::Unavailable)
        };
        publish(&shared, snapshot);
        if pause(&stop, REFRESH_INTERVAL).await {
            break;
        }
    }
    publish(
        &shared,
        DirectGatewaySnapshot::empty(DirectGatewayState::Stopped),
    );
}

#[cfg(windows)]
fn selected_ipv6(internal: SocketAddr) -> bool {
    if !global(internal.ip())
        || !crate::local_endpoint().is_ok_and(|address| address.ip() == internal.ip())
    {
        return false;
    }
    ipconfig::get_adapters().is_ok_and(|adapters| {
        adapters
            .iter()
            .filter(|adapter| {
                adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp
                    && adapter.ip_addresses().contains(&internal.ip())
            })
            .count()
            == 1
    })
}

#[cfg(not(windows))]
fn selected_ipv6(_internal: SocketAddr) -> bool {
    false
}

async fn pause(stop: &CancellationToken, delay: Duration) -> bool {
    tokio::select! {
        biased;
        () = stop.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

async fn bounded<T>(
    stop: &CancellationToken,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        biased;
        () = stop.cancelled() => Err(io::Error::from(io::ErrorKind::Interrupted)),
        result = tokio::time::timeout(IO_TIMEOUT, operation) => {
            result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        }
    }
}

fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid local relay endpoint")
}

fn local_ipv4_state(ip: Ipv4Addr) -> DirectGatewayState {
    if global(IpAddr::V4(ip)) {
        DirectGatewayState::PublicIpv4Candidate
    } else {
        DirectGatewayState::LanOnly
    }
}

fn invalid_response() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "gateway response rejected")
}

fn usable_local(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
        && ip.octets()[0] != 0
        && ip.octets()[0] < 224
}

/// Conservative allow-list: reserved/documentation/translation/CGN ranges are
/// not Internet candidates. This is address classification, not a connectivity test.
pub(super) fn global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            usable_local(ip)
                && !ip.is_private()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && (b == 0 || (b == 88 && c == 99)))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Global unicast 2000::/3, excluding IETF special assignments,
            // documentation 2001:db8::/32 and 3fff::/20, and 6to4 2002::/16.
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(windows)]
fn discover(internal: SocketAddrV4) -> Option<Network> {
    // The selected default-route source may be a VPN/tunnel. Do not skip it
    // and map a physical adapter, which would bypass the selected route.
    if crate::local_endpoint().ok()?.ip() != IpAddr::V4(*internal.ip()) {
        return None;
    }
    let adapters = ipconfig::get_adapters().ok()?;
    let mut matching = adapters.iter().filter(|adapter| {
        adapter.oper_status() == ipconfig::OperStatus::IfOperStatusUp
            && adapter.ip_addresses().contains(&IpAddr::V4(*internal.ip()))
    });
    let adapter = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    let gateways: Vec<_> = adapter
        .gateways()
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(ip) if usable_local(*ip) && ip != internal.ip() => Some(*ip),
            _ => None,
        })
        .collect();
    // Ambiguous multi-gateway configurations fail closed, not arbitrary first.
    if gateways.len() != 1 {
        return None;
    }
    let gateway = gateways[0];
    let on_link = adapter.prefixes().iter().any(|(prefix, bits)| {
        let IpAddr::V4(prefix) = prefix else {
            return false;
        };
        if *bits == 0 || *bits > 32 {
            return false;
        }
        let mask = u32::MAX << (32 - *bits);
        (u32::from(*prefix) & mask) == (u32::from(gateway) & mask)
            && (u32::from(*prefix) & mask) == (u32::from(*internal.ip()) & mask)
    });
    if !on_link {
        return None;
    }
    Some(Network {
        internal,
        gateway,
        ipv6: adapter
            .ip_addresses()
            .iter()
            .copied()
            .filter(|ip| ip.is_ipv6() && global(*ip))
            .take(2)
            .collect(),
    })
}

#[cfg(not(windows))]
fn discover(_internal: SocketAddrV4) -> Option<Network> {
    // Desktop Windows owns automatic router discovery. Other targets do not
    // guess a gateway, shell out, or select an unrelated physical interface.
    None
}

#[cfg(test)]
mod tests;
