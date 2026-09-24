// SPDX-License-Identifier: GPL-2.0-or-later
//! UPnP IGD v1/v2 TCP port mapping to this PC's own relay listener. Discovery
//! and control stay on the selected numeric gateway origin. The mapping only
//! reaches a listener that authenticates every peer with pinned keys, and a
//! same-host process able to race IGD could already map ports for itself.
mod http;
mod xml;

use std::{
    error, fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use super::{
    CancellationToken, LEASE_SECONDS, Network, bounded, global, invalid_response, usable_local,
};
use http::{Soap, Target, fault_code};
use xml::Node;

/// Preference order; a v2 device also answers the v1 device search.
const SERVICES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];
const DEVICES: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];
const SSDP_PORT: u16 = 1900;
const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_ERRORS: u32 = 8;
const SSDP_ROUNDS: usize = 2;
const SSDP_REPEAT: Duration = Duration::from_secs(1);
const MAX_CONTROLS: usize = 3;
const DESCRIPTION: &str = "UAC Remote Controller";
const RANDOM_PORTS: usize = 3;
const NO_SUCH_ENTRY: u16 = 714;
const ONLY_PERMANENT_LEASES: u16 = 725;
/// Conflict, same-port-required, wildcard-only and no-free-ports: next port.
const PORT_FAULTS: [u16; 4] = [718, 724, 727, 728];

struct Control {
    target: Target,
    service: &'static str,
}

/// GetExternalIPAddress named a unicast address that is not global: another
/// NAT (a second router, or the carrier's CGNAT) sits above this gateway.
#[derive(Debug)]
struct PrivateExternal;

impl fmt::Display for PrivateExternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway external address is not global")
    }
}

impl error::Error for PrivateExternal {}

pub(super) fn private_external_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, PrivateExternal)
}

/// True for `map`'s error when no connection had a global external address
/// and at least one reported a private or shared one.
pub(super) fn private_external(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<PrivateExternal>())
}

enum Entry {
    Ours,
    Foreign,
}

pub(super) struct Lease {
    pub(super) external: SocketAddr,
    /// For a permanent-only gateway this is the renewal horizon, not a lease.
    pub(super) expires: Instant,
    permanent: bool,
    cleanup_only: bool,
    control: Control,
}

impl Lease {
    pub(super) fn is_candidate(&self) -> bool {
        !self.cleanup_only && self.remaining() > 0
    }

    pub(super) fn require_cleanup(&mut self) {
        self.cleanup_only = true;
    }

    pub(super) fn remaining(&self) -> u32 {
        u32::try_from(
            self.expires
                .saturating_duration_since(Instant::now())
                .as_secs(),
        )
        .unwrap_or(0)
    }

    pub(super) async fn renew(
        &mut self,
        network: &Network,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        let begun = Instant::now();
        let port = self.external.port();
        let lease = if self.permanent { 0 } else { LEASE_SECONDS };
        add(&self.control, port, lease, network, stop).await?;
        self.expires = begun + Duration::from_secs(u64::from(LEASE_SECONDS));
        match external_ip(&self.control, network, stop).await {
            Ok(ip) => {
                self.external = SocketAddr::new(IpAddr::V4(ip), port);
                Ok(())
            }
            Err(error) => {
                self.cleanup_only = true;
                Err(error)
            }
        }
    }

    pub(super) async fn release(mut self, network: &Network) {
        let _ = self.cleanup(network).await;
    }

    pub(super) async fn cleanup(&mut self, network: &Network) -> bool {
        // One bounded attempt with a distinct cleanup cancellation token. Only
        // an entry still naming this client and port is deleted.
        self.cleanup_only = true;
        let cleanup = CancellationToken::new();
        let confirmed = bounded(&cleanup, async {
            Ok::<_, io::Error>(remove(&self.control, self.external.port(), network, &cleanup).await)
        })
        .await
        .unwrap_or(false);
        if confirmed {
            self.expires = Instant::now();
        }
        confirmed
    }
}

/// True once nothing of ours remains on the port.
async fn remove(control: &Control, port: u16, network: &Network, stop: &CancellationToken) -> bool {
    match entry(control, port, network, stop).await {
        Ok(Entry::Foreign) => true,
        Err(error) if fault_code(&error) == Some(NO_SUCH_ENTRY) => true,
        // A gateway without readback gets the delete its accepted add implies.
        Ok(Entry::Ours) => delete(control, port, network, stop).await,
        Err(error) if fault_code(&error).is_some() => delete(control, port, network, stop).await,
        Err(_) => false,
    }
}

pub(super) async fn map(network: &Network, stop: &CancellationToken) -> io::Result<Lease> {
    map_at(network, stop, SSDP_PORT).await
}

async fn map_at(network: &Network, stop: &CancellationToken, ssdp_port: u16) -> io::Result<Lease> {
    let root = search(network, stop, ssdp_port).await?;
    let controls = describe(root, network, stop).await?;
    let (control, external) = connection(controls, network, stop).await?;
    claim(control, external, network, stop).await
}

/// The first of at most three services whose connection has a public address.
async fn connection(
    controls: Vec<Control>,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<(Control, Ipv4Addr)> {
    let mut private = false;
    for control in controls {
        match external_ip(&control, network, stop).await {
            Ok(ip) => return Ok((control, ip)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(error) => private |= private_external(&error),
        }
    }
    Err(if private {
        private_external_error()
    } else {
        invalid_response()
    })
}

async fn claim(
    control: Control,
    external: Ipv4Addr,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Lease> {
    for port in ports(network.internal.port())? {
        // Readback first: an entry visibly owned by another client or internal
        // port is never overwritten. Any fault, 714 included, means free.
        match entry(&control, port, network, stop).await {
            Ok(Entry::Foreign) => continue,
            Ok(Entry::Ours) => {}
            Err(error) if fault_code(&error).is_some() => {}
            Err(error) => return Err(error),
        }
        let begun = Instant::now();
        let permanent = match add_lease(&control, port, network, stop).await {
            Ok(permanent) => permanent,
            Err(error) if fault_code(&error).is_some_and(|code| PORT_FAULTS.contains(&code)) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        // A gateway without readback is trusted, and a cancelled readback keeps
        // the cleanup obligation; only a visibly different owner is a failure.
        if matches!(
            entry(&control, port, network, stop).await,
            Ok(Entry::Foreign)
        ) {
            return Err(invalid_response());
        }
        return Ok(Lease {
            external: SocketAddr::new(IpAddr::V4(external), port),
            expires: begun + Duration::from_secs(u64::from(LEASE_SECONDS)),
            permanent,
            cleanup_only: false,
            control,
        });
    }
    Err(io::Error::from(io::ErrorKind::AddrInUse))
}

/// The listener's own port first, then OS-random ports in 20000..=60999.
fn ports(internal: u16) -> io::Result<Vec<u16>> {
    let mut random = [0_u8; 2 * RANDOM_PORTS];
    getrandom::fill(&mut random).map_err(|_| io::Error::other("port choice unavailable"))?;
    let mut ports = vec![internal];
    for pair in random.chunks_exact(2) {
        let port = 20000 + u16::from_be_bytes([pair[0], pair[1]]) % 41000;
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    Ok(ports)
}

/// Many consumer gateways refuse finite leases with 725; retry once permanent.
async fn add_lease(
    control: &Control,
    port: u16,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<bool> {
    match add(control, port, LEASE_SECONDS, network, stop).await {
        Err(error) if fault_code(&error) == Some(ONLY_PERMANENT_LEASES) => {
            add(control, port, 0, network, stop).await.map(|()| true)
        }
        result => result.map(|()| false),
    }
}

async fn add(
    control: &Control,
    port: u16,
    lease: u32,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<()> {
    let arguments = format!(
        "{}<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient>\
         <NewEnabled>1</NewEnabled><NewPortMappingDescription>{DESCRIPTION}</NewPortMappingDescription>\
         <NewLeaseDuration>{lease}</NewLeaseDuration>",
        key(port),
        network.internal.port(),
        network.internal.ip(),
    );
    let reply = soap(control, "AddPortMapping", &arguments, network, stop).await?;
    response(&reply, "AddPortMappingResponse").map(|_| ())
}

async fn delete(control: &Control, port: u16, network: &Network, stop: &CancellationToken) -> bool {
    match soap(control, "DeletePortMapping", &key(port), network, stop).await {
        Ok(reply) => response(&reply, "DeletePortMappingResponse").is_ok(),
        Err(error) => fault_code(&error) == Some(NO_SUCH_ENTRY),
    }
}

/// Readback of one TCP entry. Faults are returned for the caller to classify.
async fn entry(
    control: &Control,
    port: u16,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Entry> {
    let reply = soap(
        control,
        "GetSpecificPortMappingEntry",
        &key(port),
        network,
        stop,
    )
    .await?;
    owner(&reply, network)
}

fn owner(reply: &Node, network: &Network) -> io::Result<Entry> {
    let entry = response(reply, "GetSpecificPortMappingEntryResponse")?;
    let client: Ipv4Addr = entry
        .value("NewInternalClient")?
        .parse()
        .map_err(|_| invalid_response())?;
    let port: u16 = entry
        .value("NewInternalPort")?
        .parse()
        .map_err(|_| invalid_response())?;
    Ok(
        if client == *network.internal.ip() && port == network.internal.port() {
            Entry::Ours
        } else {
            Entry::Foreign
        },
    )
}

fn key(port: u16) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>TCP</NewProtocol>"
    )
}

/// Double NAT and CGNAT report a non-global address: nothing to publish. A
/// disconnected connection's 0.0.0.0 is an ordinary rejection, not a NAT.
async fn external_ip(
    control: &Control,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Ipv4Addr> {
    let reply = soap(control, "GetExternalIPAddress", "", network, stop).await?;
    let ip: Ipv4Addr = response(&reply, "GetExternalIPAddressResponse")?
        .value("NewExternalIPAddress")?
        .parse()
        .map_err(|_| invalid_response())?;
    if !global(IpAddr::V4(ip)) {
        return Err(if usable_local(ip) {
            private_external_error()
        } else {
            invalid_response()
        });
    }
    Ok(ip)
}

fn response<'a>(reply: &'a Node, action: &str) -> io::Result<&'a Node> {
    if reply.name != "Envelope" {
        return Err(invalid_response());
    }
    let body = reply.child("Body")?;
    if body.children.len() != 1 {
        return Err(invalid_response());
    }
    body.child(action)
}

async fn soap(
    control: &Control,
    action: &str,
    arguments: &str,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Node> {
    let service = control.service;
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service}\">{arguments}</u:{action}></s:Body></s:Envelope>"
    );
    let soap = Soap {
        service,
        action,
        body: &body,
    };
    let result = http::request(&control.target, Some(soap), network, stop).await?;
    xml::parse(&result)
}

/// SSDP from the selected adapter only. A datagram counts only when its source
/// is the default gateway and its LOCATION names that same numeric gateway.
async fn search(network: &Network, stop: &CancellationToken, port: u16) -> io::Result<Target> {
    bounded(stop, async {
        let (socket, multicast) = ssdp_socket(*network.internal.ip())?;
        let replies = gateway_reply(&socket, network.gateway);
        tokio::pin!(replies);
        // UDP may drop a search; UDA 1.1 asks control points to repeat M-SEARCH.
        for _ in 0..SSDP_ROUNDS {
            send_searches(&socket, network.gateway, port, multicast).await?;
            if let Ok(result) = tokio::time::timeout(SSDP_REPEAT, &mut replies).await {
                return result;
            }
        }
        replies.await
    })
    .await
}

async fn send_searches(
    socket: &UdpSocket,
    gateway: Ipv4Addr,
    port: u16,
    multicast: bool,
) -> io::Result<()> {
    let unicast = SocketAddrV4::new(gateway, port);
    let group = SocketAddrV4::new(SSDP_GROUP, port);
    for device in DEVICES {
        socket
            .send_to(m_search(unicast, device).as_bytes(), unicast)
            .await?;
        if multicast {
            // Many routers answer only multicast; loopback cannot send it.
            let _ = socket
                .send_to(m_search(group, device).as_bytes(), group)
                .await;
        }
    }
    Ok(())
}

async fn gateway_reply(socket: &UdpSocket, gateway: Ipv4Addr) -> io::Result<Target> {
    let mut bytes = [0; 4096];
    let mut errors = 0;
    loop {
        match socket.recv_from(&mut bytes).await {
            Ok((count, source)) => {
                if source.ip() == IpAddr::V4(gateway)
                    && count < bytes.len()
                    && let Ok(target) = reply_target(&bytes[..count], gateway)
                {
                    return Ok(target);
                }
            }
            // Windows surfaces an ICMP unreachable for the unicast search here.
            Err(error) => {
                errors += 1;
                if errors >= SSDP_ERRORS {
                    return Err(error);
                }
            }
        }
    }
}

fn ssdp_socket(ip: Ipv4Addr) -> io::Result<(UdpSocket, bool)> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind(&SocketAddr::from((ip, 0)).into())?;
    // Multicast leaves through the selected adapter or is not sent at all.
    let multicast = socket
        .set_multicast_if_v4(&ip)
        .and_then(|()| socket.set_multicast_ttl_v4(2))
        .is_ok();
    socket.set_nonblocking(true)?;
    Ok((UdpSocket::from_std(socket.into())?, multicast))
}

fn m_search(host: SocketAddrV4, device: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {host}\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {device}\r\n\r\n"
    )
}

fn reply_target(bytes: &[u8], gateway: Ipv4Addr) -> io::Result<Target> {
    Target::absolute(&location(bytes)?, gateway)
}

fn location(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_response())?;
    let mut lines = text.split("\r\n");
    if lines.next().and_then(http::status) != Some(200) {
        return Err(invalid_response());
    }
    let mut location = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':').ok_or_else(invalid_response)?;
        if key.eq_ignore_ascii_case("location") {
            if location.is_some() {
                return Err(invalid_response());
            }
            location = Some(value.trim().to_owned());
        }
    }
    location.ok_or_else(invalid_response)
}

async fn describe(
    mut root: Target,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Vec<Control>> {
    let body = http::request(&root, None, network, stop).await?;
    let document = xml::parse(&body)?;
    if document.name != "root" {
        return Err(invalid_response());
    }
    rebase(&document, &mut root)?;
    let controls = controls(&document, &root);
    if controls.is_empty() {
        return Err(invalid_response());
    }
    Ok(controls)
}

/// URLBase can only restate the already vetted descriptor origin. Reject
/// alternate bases instead of fetching attacker-selected destinations.
fn rebase(document: &Node, root: &mut Target) -> io::Result<()> {
    let base_count = document
        .children
        .iter()
        .filter(|node| node.name == "URLBase")
        .count();
    if base_count > 1 {
        return Err(invalid_response());
    }
    if base_count == 1 {
        let base = document.child("URLBase")?.text.trim();
        // Routers often write an origin-only base without its root slash.
        let base = if base
            .strip_prefix("http://")
            .is_some_and(|rest| !rest.contains('/'))
        {
            format!("{base}/")
        } else {
            base.to_owned()
        };
        let target = Target::absolute(&base, *root.address.ip())?;
        if target.address != root.address || target.path != "/" {
            return Err(invalid_response());
        }
        root.path = target.path;
    }
    Ok(())
}

/// At most three connections in preference order. An unusable control URL
/// disqualifies only its own service, never redirects to another origin.
fn controls(document: &Node, root: &Target) -> Vec<Control> {
    let mut controls = Vec::new();
    for service in SERVICES {
        let mut found = Vec::new();
        find_services(document, service, &mut found);
        controls.extend(found.into_iter().filter_map(|node| {
            let target = root.resolve(node.value("controlURL").ok()?).ok()?;
            Some(Control { target, service })
        }));
    }
    controls.truncate(MAX_CONTROLS);
    controls
}

fn find_services<'a>(node: &'a Node, service: &str, found: &mut Vec<&'a Node>) {
    if node.name == "service"
        && node
            .value("serviceType")
            .is_ok_and(|value| value == service)
    {
        found.push(node);
    }
    for child in &node.children {
        find_services(child, service, found);
    }
}

#[cfg(test)]
mod tests {
    use super::super::IO_TIMEOUT;
    use super::*;
    use std::cell::RefCell;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    const IP1: &str = SERVICES[1];
    const PPP1: &str = SERVICES[2];
    const STRANGER: &str = "192.168.1.50";

    fn network() -> Network {
        Network {
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7443),
            gateway: Ipv4Addr::LOCALHOST,
            ipv6: vec![],
        }
    }

    fn field<'a>(request: &'a str, name: &str) -> &'a str {
        request
            .split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0
    }

    fn ssdp_reply(location: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: {}\r\nUSN: uuid:fixture\r\nEXT:\r\n\
             SERVER: Fixture/1.0 UPnP/1.0\r\nLocation: {location}\r\n\r\n",
            DEVICES[0]
        )
    }

    /// A v1 tree nested the way consumer routers publish it, plus unrelated services.
    fn description(services: &[(&str, &str)]) -> String {
        let service = |path: &str, kind: &str| {
            format!(
                "<service><serviceType>{kind}</serviceType><serviceId>urn:upnp-org:serviceId:x</serviceId>\
                 <controlURL>{path}</controlURL><eventSubURL>/evt</eventSubURL><SCPDURL>/x.xml</SCPDURL></service>"
            )
        };
        let listed: String = services
            .iter()
            .map(|(path, kind)| service(path, kind))
            .collect();
        format!(
            "<?xml version=\"1.0\"?>\r\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
             <specVersion><major>1</major><minor>0</minor></specVersion><device>\
             <deviceType>{}</deviceType><friendlyName>Fixture</friendlyName><serviceList>{}</serviceList>\
             <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
             <serviceList>{}</serviceList><deviceList><device>\
             <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
             <serviceList>{listed}</serviceList></device></deviceList></device></deviceList></device></root>",
            DEVICES[0],
            service(
                "/ctl/l3f",
                "urn:schemas-upnp-org:service:Layer3Forwarding:1"
            ),
            service(
                "/ctl/cmn",
                "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
            ),
        )
    }

    /// A consumer gateway's TCP port table.
    struct Router {
        external: &'static str,
        disconnected: &'static str,
        permanent_only: bool,
        conflicts: Vec<u16>,
        foreign: Vec<u16>,
        ours: RefCell<Vec<u16>>,
    }

    impl Router {
        fn new(external: &'static str) -> Self {
            Self {
                external,
                disconnected: "",
                permanent_only: false,
                conflicts: Vec::new(),
                foreign: Vec::new(),
                ours: RefCell::new(Vec::new()),
            }
        }

        fn answer(&self, path: &str, action: &str, request: &str) -> Result<String, u16> {
            let port = || field(request, "NewExternalPort").parse::<u16>().unwrap();
            match action {
                "GetExternalIPAddress" => {
                    let ip = if path == self.disconnected {
                        "0.0.0.0"
                    } else {
                        self.external
                    };
                    Ok(format!("<NewExternalIPAddress>{ip}</NewExternalIPAddress>"))
                }
                "GetSpecificPortMappingEntry" => {
                    let client = if self.foreign.contains(&port()) {
                        STRANGER
                    } else if self.ours.borrow().contains(&port()) {
                        "127.0.0.1"
                    } else {
                        return Err(NO_SUCH_ENTRY);
                    };
                    Ok(format!(
                        "<NewInternalPort>7443</NewInternalPort><NewInternalClient>{client}</NewInternalClient>\
                         <NewEnabled>1</NewEnabled><NewPortMappingDescription>x</NewPortMappingDescription>\
                         <NewLeaseDuration>0</NewLeaseDuration>"
                    ))
                }
                "AddPortMapping" => {
                    if self.permanent_only && field(request, "NewLeaseDuration") != "0" {
                        return Err(ONLY_PERMANENT_LEASES);
                    }
                    if self.conflicts.contains(&port()) || self.foreign.contains(&port()) {
                        return Err(718);
                    }
                    let mut ours = self.ours.borrow_mut();
                    if !ours.contains(&port()) {
                        ours.push(port());
                    }
                    Ok(String::new())
                }
                "DeletePortMapping" => {
                    let mut ours = self.ours.borrow_mut();
                    let index = ours
                        .iter()
                        .position(|owned| *owned == port())
                        .ok_or(NO_SUCH_ENTRY)?;
                    ours.remove(index);
                    Ok(String::new())
                }
                _ => Err(401),
            }
        }
    }

    struct Call {
        path: String,
        service: String,
        action: String,
        request: String,
    }

    /// Real loopback SSDP responder and HTTP gateway around one `Router`.
    struct Fixture {
        router: Router,
        description: String,
        ssdp: UdpSocket,
        http: TcpListener,
        log: RefCell<Vec<Call>>,
    }

    impl Fixture {
        async fn new(router: Router, services: &[(&str, &str)]) -> Self {
            Self {
                router,
                description: description(services),
                ssdp: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
                http: TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
                log: RefCell::new(Vec::new()),
            }
        }

        fn ssdp_port(&self) -> u16 {
            self.ssdp.local_addr().unwrap().port()
        }

        fn actions(&self) -> Vec<String> {
            self.log
                .borrow()
                .iter()
                .map(|call| call.action.clone())
                .collect()
        }

        fn requests(&self, action: &str) -> Vec<String> {
            self.log
                .borrow()
                .iter()
                .filter(|call| call.action == action)
                .map(|call| call.request.clone())
                .collect()
        }

        fn lease(&self) -> Lease {
            let url = format!("http://{}/ctl/ip", self.http.local_addr().unwrap());
            Lease {
                external: "8.8.8.8:7443".parse().unwrap(),
                expires: Instant::now() + Duration::from_secs(600),
                permanent: false,
                cleanup_only: false,
                control: Control {
                    target: Target::absolute(&url, Ipv4Addr::LOCALHOST).unwrap(),
                    service: IP1,
                },
            }
        }

        async fn run<T>(&self, client: impl Future<Output = T>) -> T {
            tokio::select! {
                value = client => value,
                () = self.answer_search() => unreachable!(),
                () = self.serve() => unreachable!(),
            }
        }

        /// Answers every search like a router does. A reply to a searcher that
        /// already left may surface later as a Windows receive error; skip it.
        async fn answer_search(&self) {
            let location = format!("http://{}/desc/root.xml", self.http.local_addr().unwrap());
            let mut bytes = [0; 2048];
            loop {
                let Ok((count, peer)) = self.ssdp.recv_from(&mut bytes).await else {
                    continue;
                };
                assert!(bytes[..count].starts_with(b"M-SEARCH * HTTP/1.1\r\n"));
                let _ = self
                    .ssdp
                    .send_to(ssdp_reply(&location).as_bytes(), peer)
                    .await;
            }
        }

        async fn serve(&self) {
            loop {
                let (mut stream, _) = self.http.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                let (status, body) = if request.starts_with("GET /desc/root.xml ") {
                    ("200 OK", self.description.clone())
                } else {
                    self.soap(request)
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                // The client closes first once its Content-Length is met, so
                // this side never races a reset against unread reply bytes.
                let _ = stream.read(&mut [0; 1]).await;
            }
        }

        fn soap(&self, request: String) -> (&'static str, String) {
            let path = request.split(' ').nth(1).unwrap().to_owned();
            let (service, action) = request
                .lines()
                .find_map(|line| line.strip_prefix("SOAPAction: \""))
                .unwrap()
                .trim_end_matches('"')
                .split_once('#')
                .unwrap();
            let (service, action) = (service.to_owned(), action.to_owned());
            let answer = self.router.answer(&path, &action, &request);
            self.log.borrow_mut().push(Call {
                path,
                service: service.clone(),
                action: action.clone(),
                request,
            });
            match answer {
                Ok(fields) => (
                    "200 OK",
                    format!(
                        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
                         <s:Body><u:{action}Response xmlns:u=\"{service}\">{fields}</u:{action}Response>\
                         </s:Body></s:Envelope>"
                    ),
                ),
                Err(code) => (
                    "500 Internal Server Error",
                    format!(
                        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
                         <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
                         <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
                         <errorDescription>fixture</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                    ),
                ),
            }
        }
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut bytes = [0; 4096];
        loop {
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0 && request.len() + count < 16384);
            request.extend_from_slice(&bytes[..count]);
            if let Some(split) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let header = std::str::from_utf8(&request[..split]).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .map_or(0, |value| value.parse().unwrap());
                if request.len() >= split + 4 + length {
                    break;
                }
            }
        }
        String::from_utf8(request).unwrap()
    }

    async fn map_with(fixture: &Fixture) -> io::Result<Lease> {
        fixture
            .run(map_at(
                &network(),
                &CancellationToken::new(),
                fixture.ssdp_port(),
            ))
            .await
    }

    #[test]
    fn ssdp_location_must_be_one_numeric_gateway_url() {
        assert!(location(b"HTTP/1.1 200 OK\r\nLOCATION: a\r\nlocation: b\r\n\r\n").is_err());
        assert!(location(b"HTTP/1.1 302 Found\r\nLOCATION: a\r\n\r\n").is_err());
        assert!(location(b"NOTIFY * HTTP/1.1\r\nLOCATION: a\r\n\r\n").is_err());
        for status in ["HTTP/1.1 200 OK", "HTTP/1.1 200", "HTTP/1.1 200 ok"] {
            let reply =
                format!("{status}\r\nEXT:\r\nlocation: http://192.168.1.1:5000/root.xml\r\n\r\n");
            assert_eq!(
                location(reply.as_bytes()).unwrap(),
                "http://192.168.1.1:5000/root.xml"
            );
        }
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let target = reply_target(
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/root.xml\r\n\r\n",
            gateway,
        )
        .unwrap();
        assert_eq!(target.address, SocketAddrV4::new(gateway, 5000));
        for host in ["192.168.1.2:5000", "127.0.0.1", "router.local:5000"] {
            let reply = format!("HTTP/1.1 200 OK\r\nLOCATION: http://{host}/root.xml\r\n\r\n");
            assert!(reply_target(reply.as_bytes(), gateway).is_err());
        }
    }

    #[tokio::test]
    async fn real_loopback_ssdp_searches_both_versions_and_trusts_only_the_gateway() {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        // Another loopback source stands in for an unrelated LAN device when
        // this host can bind one; otherwise that assertion is skipped.
        let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).await.ok();
        let port = gateway.local_addr().unwrap().port();
        let server = async {
            let mut bytes = [0; 2048];
            let mut targets = std::collections::BTreeSet::new();
            let mut peer = None;
            // Both device versions are searched, whichever round delivers them.
            while targets.len() < DEVICES.len() {
                let (count, source) = gateway.recv_from(&mut bytes).await.unwrap();
                let search = std::str::from_utf8(&bytes[..count]).unwrap();
                assert!(search.contains(&format!("HOST: 127.0.0.1:{port}\r\n")));
                assert!(search.contains("MAN: \"ssdp:discover\"\r\n"));
                let target = search.split_once("\r\nST: ").unwrap().1.trim().to_owned();
                assert!(DEVICES.contains(&target.as_str()));
                targets.insert(target);
                peer = Some(source);
            }
            let peer = peer.unwrap();
            if let Some(stranger) = &stranger {
                let decoy = ssdp_reply("http://127.0.0.1:5000/stranger.xml");
                stranger.send_to(decoy.as_bytes(), peer).await.unwrap();
            }
            let elsewhere = ssdp_reply("http://127.0.0.2:5000/root.xml");
            gateway.send_to(elsewhere.as_bytes(), peer).await.unwrap();
            let genuine = ssdp_reply("http://127.0.0.1:5000/root.xml");
            gateway.send_to(genuine.as_bytes(), peer).await.unwrap();
        };
        let client = async {
            search(&network(), &CancellationToken::new(), port)
                .await
                .unwrap()
        };
        let ((), target) = tokio::join!(server, client);
        assert_eq!(target.address, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000));
        assert_eq!(target.path, "/root.xml");
    }

    #[test]
    fn url_base_may_only_restate_the_description_origin() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let document = |base: &str| xml::parse(&format!("<root>{base}<device/></root>")).unwrap();
        for base in [
            "",
            "<URLBase>http://192.168.1.1:5000/</URLBase>",
            "<URLBase>http://192.168.1.1:5000</URLBase>",
        ] {
            let mut root =
                Target::absolute("http://192.168.1.1:5000/desc/root.xml", gateway).unwrap();
            rebase(&document(base), &mut root).unwrap();
            let expected = if base.is_empty() {
                "/desc/root.xml"
            } else {
                "/"
            };
            assert_eq!(root.path, expected);
        }
        for base in [
            "<URLBase>http://192.168.1.1:5001/</URLBase>",
            "<URLBase>http://192.168.1.2:5000/</URLBase>",
            "<URLBase>http://192.168.1.1:5000/other/</URLBase>",
            "<URLBase>http://192.168.1.1:5000/</URLBase><URLBase>http://192.168.1.1:5000/</URLBase>",
        ] {
            let mut root =
                Target::absolute("http://192.168.1.1:5000/desc/root.xml", gateway).unwrap();
            assert!(rebase(&document(base), &mut root).is_err());
        }
    }

    #[test]
    fn services_are_collected_in_preference_order_up_to_three() {
        let root =
            Target::absolute("http://127.0.0.1:5000/desc/root.xml", Ipv4Addr::LOCALHOST).unwrap();
        let document = xml::parse(&description(&[
            ("/ppp", PPP1),
            ("/ip1", IP1),
            ("http://127.0.0.1:5001/elsewhere", SERVICES[0]),
            ("relative", SERVICES[0]),
            ("/ip1b", IP1),
            ("/ppp2", PPP1),
        ]))
        .unwrap();
        let found: Vec<_> = controls(&document, &root)
            .into_iter()
            .map(|control| (control.target.path, control.service))
            .collect();
        assert_eq!(
            found,
            [
                ("/desc/relative".to_owned(), SERVICES[0]),
                ("/ip1".to_owned(), IP1),
                ("/ip1b".to_owned(), IP1),
            ]
        );
        let unrelated = xml::parse(&description(&[])).unwrap();
        assert!(controls(&unrelated, &root).is_empty());
    }

    #[test]
    fn readback_owner_requires_this_client_and_internal_port() {
        let network = Network {
            internal: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 7443),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            ipv6: vec![],
        };
        let entry = |client: &str, port: &str| {
            xml::parse(&format!(
                "<Envelope><Body><GetSpecificPortMappingEntryResponse><NewInternalPort>{port}</NewInternalPort>\
                 <NewInternalClient>{client}</NewInternalClient></GetSpecificPortMappingEntryResponse></Body></Envelope>"
            ))
            .unwrap()
        };
        assert!(matches!(
            owner(&entry("192.168.1.2", "7443"), &network),
            Ok(Entry::Ours)
        ));
        for (client, port) in [("192.168.1.3", "7443"), ("192.168.1.2", "7444")] {
            assert!(matches!(
                owner(&entry(client, port), &network),
                Ok(Entry::Foreign)
            ));
        }
        for (client, port) in [("router.local", "7443"), ("192.168.1.2", "")] {
            assert!(owner(&entry(client, port), &network).is_err());
        }
    }

    #[test]
    fn port_choice_starts_at_the_listener_port_then_random_high_ports() {
        let ports = ports(7443).unwrap();
        assert_eq!(ports[0], 7443);
        assert!((2..=1 + RANDOM_PORTS).contains(&ports.len()));
        assert!(ports[1..].iter().all(|port| (20000..=60999).contains(port)));
    }

    #[tokio::test]
    async fn v1_gateway_maps_the_listener_port_under_the_v1_namespace() {
        let fixture = Fixture::new(Router::new("8.8.8.8"), &[("/ctl/ip", IP1)]).await;
        let lease = map_with(&fixture).await.unwrap();
        assert_eq!(lease.external, "8.8.8.8:7443".parse().unwrap());
        assert!(lease.is_candidate() && !lease.permanent);
        assert!(lease.remaining() + 5 >= LEASE_SECONDS);
        assert_eq!(
            fixture.actions(),
            [
                "GetExternalIPAddress",
                "GetSpecificPortMappingEntry",
                "AddPortMapping",
                "GetSpecificPortMappingEntry",
            ]
        );
        for call in fixture.log.borrow().iter() {
            assert_eq!(
                (call.path.as_str(), call.service.as_str()),
                ("/ctl/ip", IP1)
            );
            assert!(call.request.contains(&format!("xmlns:u=\"{IP1}\"")));
        }
        let add = &fixture.requests("AddPortMapping")[0];
        for (name, value) in [
            ("NewRemoteHost", ""),
            ("NewExternalPort", "7443"),
            ("NewProtocol", "TCP"),
            ("NewInternalPort", "7443"),
            ("NewInternalClient", "127.0.0.1"),
            ("NewEnabled", "1"),
            ("NewPortMappingDescription", "UAC Remote Controller"),
            ("NewLeaseDuration", "600"),
        ] {
            assert_eq!(field(add, name), value);
        }
    }

    #[tokio::test]
    async fn ppp_only_gateway_is_controlled_under_the_ppp_namespace() {
        let fixture = Fixture::new(Router::new("8.8.8.8"), &[("ppp", PPP1)]).await;
        let lease = map_with(&fixture).await.unwrap();
        assert_eq!(lease.external, "8.8.8.8:7443".parse().unwrap());
        assert_eq!(fixture.requests("AddPortMapping").len(), 1);
        for call in fixture.log.borrow().iter() {
            assert_eq!(
                (call.path.as_str(), call.service.as_str()),
                ("/desc/ppp", PPP1)
            );
            assert!(call.request.contains(&format!("xmlns:u=\"{PPP1}\"")));
        }
    }

    #[tokio::test]
    async fn disconnected_preferred_service_falls_through_to_a_public_connection() {
        let mut router = Router::new("8.8.8.8");
        router.disconnected = "/ctl/ip";
        let fixture = Fixture::new(router, &[("/ctl/ppp", PPP1), ("/ctl/ip", IP1)]).await;
        let lease = map_with(&fixture).await.unwrap();
        assert_eq!(lease.external, "8.8.8.8:7443".parse().unwrap());
        let log = fixture.log.borrow();
        assert_eq!(
            (log[0].action.as_str(), log[0].path.as_str()),
            ("GetExternalIPAddress", "/ctl/ip")
        );
        assert_eq!(
            (log[1].action.as_str(), log[1].path.as_str()),
            ("GetExternalIPAddress", "/ctl/ppp")
        );
        assert!(
            log[2..]
                .iter()
                .all(|call| call.path == "/ctl/ppp" && call.service == PPP1)
        );
    }

    #[tokio::test]
    async fn permanent_only_gateway_gets_one_retry_with_lease_zero_and_renews_it() {
        let mut router = Router::new("8.8.8.8");
        router.permanent_only = true;
        let fixture = Fixture::new(router, &[("/ctl/ip", IP1)]).await;
        let mut lease = map_with(&fixture).await.unwrap();
        assert!(lease.permanent && lease.is_candidate());
        assert_eq!(lease.external, "8.8.8.8:7443".parse().unwrap());
        let leases = |fixture: &Fixture| {
            fixture
                .requests("AddPortMapping")
                .iter()
                .map(|request| field(request, "NewLeaseDuration").to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(leases(&fixture), ["600", "0"]);
        fixture
            .run(lease.renew(&network(), &CancellationToken::new()))
            .await
            .unwrap();
        assert_eq!(leases(&fixture), ["600", "0", "0"]);
        assert!(lease.is_candidate() && lease.remaining() + 5 >= LEASE_SECONDS);
    }

    #[tokio::test]
    async fn preferred_port_owned_by_another_client_is_never_added() {
        let mut router = Router::new("8.8.8.8");
        router.foreign.push(7443);
        let fixture = Fixture::new(router, &[("/ctl/ip", IP1)]).await;
        let lease = map_with(&fixture).await.unwrap();
        let port = lease.external.port();
        assert!((20000..=60999).contains(&port));
        let adds = fixture.requests("AddPortMapping");
        assert_eq!(adds.len(), 1);
        assert_eq!(field(&adds[0], "NewExternalPort"), port.to_string());
        let reads = fixture.requests("GetSpecificPortMappingEntry");
        assert_eq!(field(&reads[0], "NewExternalPort"), "7443");
        assert_eq!(fixture.router.foreign, [7443]);
    }

    #[tokio::test]
    async fn conflict_on_the_preferred_port_moves_to_another_port() {
        let mut router = Router::new("8.8.8.8");
        router.conflicts.push(7443);
        let fixture = Fixture::new(router, &[("/ctl/ip", IP1)]).await;
        let lease = map_with(&fixture).await.unwrap();
        let port = lease.external.port();
        assert!((20000..=60999).contains(&port));
        let adds = fixture.requests("AddPortMapping");
        assert_eq!(adds.len(), 2);
        assert_eq!(field(&adds[0], "NewExternalPort"), "7443");
        assert_eq!(field(&adds[1], "NewExternalPort"), port.to_string());
        assert_eq!(*fixture.router.ours.borrow(), [port]);
    }

    #[tokio::test]
    async fn private_or_shared_external_address_is_never_mapped() {
        for external in ["10.0.0.2", "100.64.0.1"] {
            let fixture = Fixture::new(Router::new(external), &[("/ctl/ip", IP1)]).await;
            let error = map_with(&fixture).await.err().unwrap();
            assert!(private_external(&error));
            assert_eq!(fixture.actions(), ["GetExternalIPAddress"]);
        }
    }

    #[tokio::test]
    async fn only_a_private_answer_reports_another_nat_above_the_gateway() {
        // One disconnected connection beside one behind CGNAT: another NAT.
        let mut router = Router::new("100.64.0.1");
        router.disconnected = "/ctl/ip";
        let fixture = Fixture::new(router, &[("/ctl/ppp", PPP1), ("/ctl/ip", IP1)]).await;
        let error = map_with(&fixture).await.err().unwrap();
        assert!(private_external(&error));
        assert_eq!(
            fixture.actions(),
            ["GetExternalIPAddress", "GetExternalIPAddress"]
        );
        // Only disconnected connections: no mapping, but no NAT claim either.
        let fixture = Fixture::new(Router::new("0.0.0.0"), &[("/ctl/ip", IP1)]).await;
        let error = map_with(&fixture).await.err().unwrap();
        assert!(!private_external(&error));
        assert!(!private_external(&invalid_response()));
    }

    #[tokio::test]
    async fn cleanup_deletes_only_an_entry_that_still_names_this_listener() {
        for (ours, foreign) in [(true, false), (false, true), (false, false)] {
            let mut router = Router::new("8.8.8.8");
            if ours {
                router.ours.borrow_mut().push(7443);
            }
            if foreign {
                router.foreign.push(7443);
            }
            let fixture = Fixture::new(router, &[]).await;
            let mut lease = fixture.lease();
            assert!(fixture.run(lease.cleanup(&network())).await);
            assert!(!lease.is_candidate());
            assert_eq!(lease.remaining(), 0);
            let deletes = fixture.requests("DeletePortMapping");
            assert_eq!(deletes.len(), usize::from(ours));
            for delete in &deletes {
                assert_eq!(field(delete, "NewRemoteHost"), "");
                assert_eq!(field(delete, "NewExternalPort"), "7443");
                assert_eq!(field(delete, "NewProtocol"), "TCP");
            }
            assert!(fixture.router.ours.borrow().is_empty());
            assert_eq!(fixture.router.foreign.len(), usize::from(foreign));
        }
    }

    #[tokio::test]
    async fn cleanup_against_a_silent_gateway_fails_within_one_bound() {
        let fixture = Fixture::new(Router::new("8.8.8.8"), &[]).await;
        let mut lease = fixture.lease();
        let begun = Instant::now();
        // Nothing accepts: the kernel completes the handshake and no reply follows.
        assert!(!lease.cleanup(&network()).await);
        assert!(begun.elapsed() < IO_TIMEOUT + Duration::from_secs(2));
        assert!(!lease.is_candidate());
        assert!(lease.remaining() > 0);
    }
}
