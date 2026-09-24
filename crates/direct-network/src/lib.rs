// SPDX-License-Identifier: GPL-2.0-or-later
//! Direct relay candidates are routing hints, never peer authentication. All
//! remote traffic still requires the existing end-to-end pinned encrypted
//! protocol. No cloud account, credentials, router-wide changes or arbitrary
//! URL interface. STUN runs only in `RouterForward` mode, against two fixed
//! public servers, and learns nothing but this home's public IPv4.
#![forbid(unsafe_code)]

mod igd;
mod lease;
mod obligations;
mod pcp;
mod stun;

use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;

const LEASE_SECONDS: u32 = 600;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const CANDIDATE_SECONDS: u32 = 60;

/// How the PC obtains an address that reaches its relay from outside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalAccess {
    /// PCP, then UPnP IGD, on the default gateway. The default.
    Automatic,
    /// The user forwarded `external_port` (or set a DMZ) on the router to this
    /// PC's relay port. The public IPv4 comes from STUN.
    RouterForward { external_port: u16 },
    /// A public address the user typed. Published as given.
    Fixed { address: SocketAddr },
}

impl ExternalAccess {
    /// Rejects port 0 and, for Fixed, any address `global()` rejects. A scoped
    /// or flow-labelled IPv6 address is not a publishable endpoint either.
    pub fn validated(self) -> Result<Self, InvalidExternalAccess> {
        match self {
            Self::Automatic => Ok(self),
            Self::RouterForward { external_port: 0 } => Err(InvalidExternalAccess::ZeroPort),
            Self::RouterForward { .. } => Ok(self),
            Self::Fixed { address } if address.port() == 0 => Err(InvalidExternalAccess::ZeroPort),
            Self::Fixed { address } => {
                let unscoped = match address {
                    SocketAddr::V4(_) => true,
                    SocketAddr::V6(address) => address.scope_id() == 0 && address.flowinfo() == 0,
                };
                if unscoped && global(address.ip()) {
                    Ok(self)
                } else {
                    Err(InvalidExternalAccess::NotPublic)
                }
            }
        }
    }
}

/// Why an `ExternalAccess` cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidExternalAccess {
    /// Port 0 cannot be forwarded to or published.
    ZeroPort,
    /// A Fixed address that is not a global unicast address.
    NotPublic,
}

impl fmt::Display for InvalidExternalAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroPort => "the external port must be between 1 and 65535",
            Self::NotPublic => "the external address must be a public unicast address",
        })
    }
}

impl error::Error for InvalidExternalAccess {}

/// Where the published external candidate came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateSource {
    Pcp,
    Upnp,
    Stun,
    Fixed,
    /// This PC's own routed address is already global.
    PublicInterface,
}

/// Why no external candidate is published. Reported only while there is none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectFailure {
    /// Automatic: neither PCP nor UPnP produced a mapping.
    NoMappingProtocol,
    /// Automatic: the router reported a non-global external address (double NAT, CGNAT).
    PrivateExternalAddress,
    /// RouterForward: STUN gave no usable public IPv4.
    PublicAddressUnavailable,
}

/// These states deliberately contain no claim of external reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectGatewayState {
    Discovering,
    /// Only the LAN address is published.
    LanOnly,
    /// An external IPv4 endpoint other than the LAN address is published:
    /// a router mapping, a STUN-derived forward, or a typed address.
    /// `DirectGatewaySnapshot::source` says which.
    MappedCandidate,
    /// A global IPv6 address is published and no external IPv4 endpoint is.
    Ipv6Candidate,
    /// This PC's routed IPv4 address is itself global.
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
    external: Option<SocketAddr>,
    source: Option<CandidateSource>,
    failure: Option<DirectFailure>,
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

    /// The published external candidate, also listed in `candidates`. A
    /// candidate, not proof that anything outside can reach it.
    pub fn external(&self) -> Option<SocketAddr> {
        self.external
    }

    pub fn source(&self) -> Option<CandidateSource> {
        self.source
    }

    pub fn failure(&self) -> Option<DirectFailure> {
        self.failure
    }

    fn empty(state: DirectGatewayState) -> Self {
        Self {
            state,
            candidates: Vec::new(),
            validity_seconds: 0,
            expires: Instant::now(),
            external: None,
            source: None,
            failure: None,
        }
    }

    fn new(state: DirectGatewayState, candidates: Vec<SocketAddr>, seconds: u32) -> Self {
        debug_assert!(candidates.len() <= 4);
        Self {
            state,
            candidates,
            validity_seconds: seconds,
            expires: Instant::now() + Duration::from_secs(u64::from(seconds)),
            external: None,
            source: None,
            failure: None,
        }
    }

    fn with_external(mut self, external: Result<External, Option<DirectFailure>>) -> Self {
        match external {
            Ok(external) => {
                self.external = Some(external.endpoint);
                self.source = Some(external.source);
            }
            Err(failure) => self.failure = failure,
        }
        self
    }
}

impl fmt::Debug for DirectGatewaySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectGatewaySnapshot")
            .field("state", &self.state)
            .field("candidate_count", &self.candidates.len())
            .field("validity_seconds", &self.validity_seconds)
            .field("source", &self.source)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

/// The external candidate one mode produced this round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct External {
    endpoint: SocketAddr,
    seconds: u32,
    source: CandidateSource,
}

impl External {
    fn new(endpoint: SocketAddr, source: CandidateSource) -> Self {
        Self {
            endpoint,
            seconds: CANDIDATE_SECONDS,
            source,
        }
    }
}

/// One thread, one current-thread reactor, no detached discovery or I/O tasks.
/// `drain` is nonblocking; dropping cancels and joins the bounded I/O owner.
/// An owner never changes mode: to switch, drain it and start another.
pub struct DirectGatewayOwner {
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
    worker: Option<JoinHandle<()>>,
    access: ExternalAccess,
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
    pub fn start(internal: SocketAddr, access: ExternalAccess) -> io::Result<Self> {
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| io::Error::other("mapping nonce unavailable"))?;
        Self::start_with_mapping_nonce(internal, access, nonce)
    }

    /// Optional service-owned persistence seam for PCP restart continuity.
    /// The argument is a protected, OS-random base seed, not a wire nonce,
    /// password or peer key. The wire nonce is domain-separated per numeric
    /// PCP server and local tuple; a different gateway uses a different nonce.
    /// This seed is used only for router mapping ownership, never authorization.
    pub fn start_with_mapping_nonce(
        internal: SocketAddr,
        access: ExternalAccess,
        nonce: [u8; 12],
    ) -> io::Result<Self> {
        let valid = match internal {
            SocketAddr::V4(address) => usable_local(*address.ip()),
            SocketAddr::V6(address) => address.scope_id() == 0 && global((*address.ip()).into()),
        };
        let access = access.validated().map_err(|_| invalid_input())?;
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
                            run(address, access, nonce, worker_stop, worker_shared).await
                        }
                        SocketAddr::V6(_) => {
                            run_ipv6(internal, access, worker_stop, worker_shared).await
                        }
                    }
                })
            })?;
        Ok(Self {
            stop,
            shared,
            worker: Some(worker),
            access,
        })
    }

    pub fn access(&self) -> ExternalAccess {
        self.access
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
    access: ExternalAccess,
    nonce: [u8; 12],
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
) {
    let mut mappings = obligations::MappingObligations::new();
    let mut public = stun::PublicAddress::new();
    loop {
        if stop.is_cancelled() {
            break;
        }
        let network = discover(internal);
        // Router mapping is Automatic's alone. The other modes never create a
        // mapping, so they never owe the router a cleanup either.
        if access == ExternalAccess::Automatic {
            mappings.poll(network.as_ref(), &stop, nonce).await;
        }
        let routed = network.is_some()
            || local_endpoint(internal.port())
                .is_ok_and(|address| address.ip() == IpAddr::V4(*internal.ip()));
        let snapshot = if routed {
            let external = match access {
                ExternalAccess::Automatic => automatic(internal, &mappings, network.is_some()),
                ExternalAccess::RouterForward { external_port } => {
                    forwarded(
                        internal,
                        external_port,
                        network.as_ref(),
                        &mut public,
                        &stop,
                    )
                    .await
                }
                ExternalAccess::Fixed { address } => {
                    Ok(External::new(address, CandidateSource::Fixed))
                }
            };
            let ipv6 = network.as_ref().map_or(&[][..], |network| &network.ipv6);
            compose(internal, ipv6, external)
        } else {
            DirectGatewaySnapshot::empty(DirectGatewayState::Unavailable)
        };
        publish(&shared, snapshot);
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

/// A router mapping first, else this PC's own global IPv4. The mapping failure
/// is reported only when a gateway was actually selected and asked.
fn automatic(
    internal: SocketAddrV4,
    mappings: &obligations::MappingObligations,
    observed: bool,
) -> Result<External, Option<DirectFailure>> {
    if let Some((endpoint, seconds, source)) = mappings.candidate() {
        return Ok(External {
            endpoint,
            seconds,
            source,
        });
    }
    if global(IpAddr::V4(*internal.ip())) {
        return Ok(External::new(
            internal.into(),
            CandidateSource::PublicInterface,
        ));
    }
    Err(observed.then(|| mappings.failure()).flatten())
}

/// The router already forwards `external_port`; only the public IPv4 is
/// unknown. A PC holding a global IPv4 itself needs no STUN query.
async fn forwarded(
    internal: SocketAddrV4,
    external_port: u16,
    network: Option<&Network>,
    public: &mut stun::PublicAddress,
    stop: &CancellationToken,
) -> Result<External, Option<DirectFailure>> {
    let ip = *internal.ip();
    if global(IpAddr::V4(ip)) {
        return Ok(External::new(
            SocketAddr::new(IpAddr::V4(ip), external_port),
            CandidateSource::PublicInterface,
        ));
    }
    public
        .poll(ip, network.map(|network| network.gateway), stop)
        .await;
    public
        .current(Instant::now())
        .map(|public_ip| {
            External::new(
                SocketAddr::new(IpAddr::V4(public_ip), external_port),
                CandidateSource::Stun,
            )
        })
        .ok_or(Some(DirectFailure::PublicAddressUnavailable))
}

/// The LAN candidate, same-adapter global IPv6 candidates, then the external
/// candidate of the selected mode. At most four, as before.
fn compose(
    internal: SocketAddrV4,
    ipv6: &[IpAddr],
    external: Result<External, Option<DirectFailure>>,
) -> DirectGatewaySnapshot {
    let mut candidates = vec![SocketAddr::V4(internal)];
    candidates.extend(
        ipv6.iter()
            .take(2)
            .map(|ip| SocketAddr::new(*ip, internal.port())),
    );
    let mut seconds = CANDIDATE_SECONDS;
    if let Ok(external) = &external {
        if !candidates.contains(&external.endpoint) {
            candidates.push(external.endpoint);
        }
        seconds = seconds.min(external.seconds);
    }
    let public_interface = global(IpAddr::V4(*internal.ip()));
    let state = match external.as_ref().map(|external| external.endpoint) {
        Ok(SocketAddr::V4(endpoint)) if endpoint != internal => DirectGatewayState::MappedCandidate,
        _ if public_interface => DirectGatewayState::PublicIpv4Candidate,
        Ok(SocketAddr::V6(_)) => DirectGatewayState::Ipv6Candidate,
        _ if !ipv6.is_empty() => DirectGatewayState::Ipv6Candidate,
        _ => local_ipv4_state(*internal.ip()),
    };
    DirectGatewaySnapshot::new(state, candidates, seconds).with_external(external)
}

async fn run_ipv6(
    internal: SocketAddr,
    access: ExternalAccess,
    stop: CancellationToken,
    shared: Arc<Mutex<DirectGatewaySnapshot>>,
) {
    loop {
        if stop.is_cancelled() {
            break;
        }
        let snapshot = if selected_ipv6(internal) {
            compose_ipv6(internal, access)
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

/// An IPv6-only host has no NAT to map and no IPv4 to ask STUN about. Its own
/// global address is the Automatic external candidate.
fn compose_ipv6(internal: SocketAddr, access: ExternalAccess) -> DirectGatewaySnapshot {
    let external = match access {
        ExternalAccess::Automatic => Ok(External::new(internal, CandidateSource::PublicInterface)),
        ExternalAccess::RouterForward { .. } => Err(Some(DirectFailure::PublicAddressUnavailable)),
        ExternalAccess::Fixed { address } => Ok(External::new(address, CandidateSource::Fixed)),
    };
    let mut candidates = vec![internal];
    let mut state = DirectGatewayState::Ipv6Candidate;
    if let Ok(external) = &external
        && !candidates.contains(&external.endpoint)
    {
        candidates.push(external.endpoint);
        if external.endpoint.is_ipv4() {
            state = DirectGatewayState::MappedCandidate;
        }
    }
    DirectGatewaySnapshot::new(state, candidates, CANDIDATE_SECONDS).with_external(external)
}

#[cfg(windows)]
fn selected_ipv6(internal: SocketAddr) -> bool {
    if !global(internal.ip())
        || !local_endpoint(internal.port()).is_ok_and(|address| address.ip() == internal.ip())
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
pub fn global(ip: IpAddr) -> bool {
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

/// Ask the local routing table for IPv4, then a global IPv6 source. UDP connect
/// sets a destination only: no send, DNS lookup or public-IP service is used.
/// This is a LAN address, not proof of NAT traversal or mobile-network reachability.
pub fn local_endpoint(port: u16) -> io::Result<SocketAddr> {
    let ipv4 = (|| {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9))?;
        socket.local_addr()
    })();
    if let Ok(address) = ipv4
        && !address.ip().is_unspecified()
        && !address.ip().is_loopback()
        && !address.ip().is_multicast()
    {
        return Ok(SocketAddr::new(address.ip(), port));
    }
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    socket.connect((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9))?;
    let address = socket.local_addr()?.ip();
    if !global(address) {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no routed address",
        ));
    }
    Ok(SocketAddr::new(address, port))
}

#[cfg(windows)]
fn discover(internal: SocketAddrV4) -> Option<Network> {
    // The selected default-route source may be a VPN/tunnel. Do not skip it
    // and map a physical adapter, which would bypass the selected route.
    if local_endpoint(internal.port()).ok()?.ip() != IpAddr::V4(*internal.ip()) {
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
