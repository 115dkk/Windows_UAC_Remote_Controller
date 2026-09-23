// SPDX-License-Identifier: GPL-2.0-or-later
//! RFC 8489 Binding over UDP/IPv4 to learn this home's public IPv4 when the
//! user forwarded a router port by hand. The answer is an address hint for
//! the published candidate, never peer authentication: every connection
//! through it still runs the end-to-end pinned protocol.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

use super::{CancellationToken, bounded, global, invalid_response};

/// Queried in this order; the first global answer wins.
const SERVERS: [(&str, u16); 2] = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)];
const MAX_ADDRESSES: usize = 4;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_BYTES: usize = 20;
const MAX_DATAGRAM: usize = 548;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;
const MAX_ATTRIBUTES: usize = 32;
/// Datagrams read per server before giving up on it, whatever they carry.
const MAX_DATAGRAMS: usize = 16;
const RESEND: Duration = Duration::from_secs(1);
const REFRESH: Duration = Duration::from_secs(5 * 60);
/// How long the last good address outlives failed refreshes.
const GRACE: Duration = Duration::from_secs(15 * 60);

/// The public IPv4 as last observed, refreshed on a schedule. Owned by one
/// `RouterForward` gateway owner; a new owner starts with nothing.
pub(super) struct PublicAddress {
    last: Option<(Ipv4Addr, Instant)>,
    /// The default gateway the last answer was observed behind.
    gateway: Option<Ipv4Addr>,
    next_query: Instant,
    failures: u32,
}

impl PublicAddress {
    pub(super) fn new() -> Self {
        Self {
            last: None,
            gateway: None,
            next_query: Instant::now(),
            failures: 0,
        }
    }

    /// Queries only when due: five minutes after a success, 30, 60, then 120
    /// seconds after failures. A different gateway means a different network,
    /// so the old answer is dropped and the query runs at once.
    pub(super) async fn poll(
        &mut self,
        internal: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        stop: &CancellationToken,
    ) {
        self.observe_gateway(gateway, Instant::now());
        if Instant::now() < self.next_query {
            return;
        }
        match public_ipv4(internal, &SERVERS, stop).await {
            Ok(Some(ip)) => self.succeeded(ip, Instant::now()),
            Ok(None) => self.failed(Instant::now()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => self.failed(Instant::now()),
        }
    }

    /// The last good address while it is younger than the grace period.
    pub(super) fn current(&self, now: Instant) -> Option<Ipv4Addr> {
        self.last
            .filter(|(_, observed)| now.saturating_duration_since(*observed) < GRACE)
            .map(|(ip, _)| ip)
    }

    fn observe_gateway(&mut self, gateway: Option<Ipv4Addr>, now: Instant) {
        if let (Some(previous), Some(current)) = (self.gateway, gateway)
            && previous != current
        {
            self.last = None;
            self.failures = 0;
            self.next_query = now;
        }
        if gateway.is_some() {
            self.gateway = gateway;
        }
    }

    fn succeeded(&mut self, ip: Ipv4Addr, now: Instant) {
        self.last = Some((ip, now));
        self.failures = 0;
        self.next_query = now + REFRESH;
    }

    fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.next_query =
            now + Duration::from_secs(30_u64 << self.failures.saturating_sub(1).min(2));
    }
}

/// Servers in order, at most four IPv4 addresses each. `Ok(None)` when none
/// gave a global answer; `Err` only for cancellation.
async fn public_ipv4(
    internal: Ipv4Addr,
    servers: &[(&str, u16)],
    stop: &CancellationToken,
) -> io::Result<Option<Ipv4Addr>> {
    for (name, port) in servers {
        let addresses = match resolve(name, *port, stop).await {
            Ok(addresses) => addresses,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(_) => continue,
        };
        if let Some(ip) = first_public(internal, &addresses, stop).await? {
            return Ok(Some(ip));
        }
    }
    Ok(None)
}

/// A name that resolves to a non-global address is not a public STUN server.
async fn resolve(name: &str, port: u16, stop: &CancellationToken) -> io::Result<Vec<SocketAddrV4>> {
    bounded(stop, async {
        Ok(tokio::net::lookup_host((name, port))
            .await?
            .filter_map(|address| match address {
                SocketAddr::V4(address) if global(IpAddr::V4(*address.ip())) => Some(address),
                _ => None,
            })
            .take(MAX_ADDRESSES)
            .collect())
    })
    .await
}

async fn first_public(
    internal: Ipv4Addr,
    servers: &[SocketAddrV4],
    stop: &CancellationToken,
) -> io::Result<Option<Ipv4Addr>> {
    for server in servers {
        match query(internal, *server, stop).await {
            Ok(ip) if global(IpAddr::V4(ip)) => return Ok(Some(ip)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            // A private answer means this server sits inside some NAT too.
            Ok(_) | Err(_) => {}
        }
    }
    Ok(None)
}

/// One Binding transaction from the selected adapter, sent twice at most and
/// bounded to three seconds in total.
async fn query(
    internal: Ipv4Addr,
    server: SocketAddrV4,
    stop: &CancellationToken,
) -> io::Result<Ipv4Addr> {
    let mut transaction = [0_u8; 12];
    getrandom::fill(&mut transaction)
        .map_err(|_| io::Error::other("transaction id unavailable"))?;
    let request = request(&transaction);
    bounded(stop, async {
        let socket = UdpSocket::bind((internal, 0)).await?;
        // Connected UDP: the kernel admits only this exact server address.
        socket.connect(server).await?;
        socket.send(&request).await?;
        let answer = answer(&socket, server, &transaction);
        tokio::pin!(answer);
        if let Ok(result) = tokio::time::timeout(RESEND, &mut answer).await {
            return result;
        }
        socket.send(&request).await?;
        answer.await
    })
    .await
}

async fn answer(
    socket: &UdpSocket,
    server: SocketAddrV4,
    transaction: &[u8; 12],
) -> io::Result<Ipv4Addr> {
    let mut bytes = [0_u8; 1500];
    for _ in 0..MAX_DATAGRAMS {
        let (count, source) = socket.recv_from(&mut bytes).await?;
        if source == SocketAddr::V4(server)
            && let Ok(ip) = parse(&bytes[..count], transaction)
        {
            return Ok(ip);
        }
    }
    Err(invalid_response())
}

fn request(transaction: &[u8; 12]) -> [u8; HEADER_BYTES] {
    let mut data = [0_u8; HEADER_BYTES];
    data[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    data[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    data[8..20].copy_from_slice(transaction);
    data
}

/// The mapped IPv4 of a Binding success answering exactly `transaction`,
/// global or not. XOR-MAPPED-ADDRESS wins over MAPPED-ADDRESS; only the first
/// of each is read, and any malformed one rejects the whole message.
fn parse(data: &[u8], transaction: &[u8; 12]) -> io::Result<Ipv4Addr> {
    if data.len() < HEADER_BYTES || data.len() > MAX_DATAGRAM {
        return Err(invalid_response());
    }
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if u16::from_be_bytes([data[0], data[1]]) != BINDING_SUCCESS
        || length % 4 != 0
        || HEADER_BYTES + length != data.len()
        || data[4..8] != MAGIC_COOKIE.to_be_bytes()
        || data[8..20] != *transaction
    {
        return Err(invalid_response());
    }
    let mut rest = &data[HEADER_BYTES..];
    let mut xor = None;
    let mut plain = None;
    for _ in 0..MAX_ATTRIBUTES {
        let Some((header, tail)) = rest.split_first_chunk::<4>() else {
            break;
        };
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let padded = size.div_ceil(4) * 4;
        if padded > tail.len() {
            return Err(invalid_response());
        }
        let value = &tail[..size];
        match kind {
            XOR_MAPPED_ADDRESS if xor.is_none() => xor = Some(address(value, true)?),
            MAPPED_ADDRESS if plain.is_none() => plain = Some(address(value, false)?),
            _ => {}
        }
        rest = &tail[padded..];
    }
    if !rest.is_empty() {
        return Err(invalid_response());
    }
    xor.flatten()
        .or(plain.flatten())
        .ok_or_else(invalid_response)
}

/// `Ok(None)` for a well-formed IPv6 value, which this IPv4 query cannot use.
fn address(value: &[u8], xor: bool) -> io::Result<Option<Ipv4Addr>> {
    match (value.get(1), value.len()) {
        (Some(&FAMILY_IPV4), 8) => {
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                for (octet, mask) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *octet ^= mask;
                }
            }
            Ok(Some(Ipv4Addr::from(octets)))
        }
        (Some(&FAMILY_IPV6), 20) => Ok(None),
        _ => Err(invalid_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSACTION: [u8; 12] = [7; 12];

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(bytes.len().div_ceil(4) * 4, 0);
        bytes
    }

    fn mapped(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut value = vec![0, FAMILY_IPV4];
        value.extend_from_slice(&port.to_be_bytes());
        value.extend_from_slice(&ip.octets());
        attribute(MAPPED_ADDRESS, &value)
    }

    fn xor_mapped(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let port = port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
        let mut value = vec![0, FAMILY_IPV4];
        value.extend_from_slice(&port.to_be_bytes());
        value.extend(
            ip.octets()
                .iter()
                .zip(cookie)
                .map(|(octet, mask)| octet ^ mask),
        );
        attribute(XOR_MAPPED_ADDRESS, &value)
    }

    fn success(transaction: &[u8; 12], attributes: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = attributes.concat();
        let mut data = BINDING_SUCCESS.to_be_bytes().to_vec();
        data.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        data.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(transaction);
        data.extend_from_slice(&body);
        data
    }

    fn public() -> Ipv4Addr {
        Ipv4Addr::new(8, 8, 8, 8)
    }

    #[test]
    fn binding_request_is_a_bare_header_with_cookie_and_transaction() {
        let data = request(&TRANSACTION);
        assert_eq!(&data[0..2], &[0x00, 0x01]);
        assert_eq!(&data[2..4], &[0, 0]);
        assert_eq!(&data[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&data[8..20], &TRANSACTION);
    }

    #[test]
    fn xor_mapped_address_is_decoded_and_preferred_over_mapped_address() {
        let software = attribute(0x8022, b"fixture");
        let data = success(
            &TRANSACTION,
            &[
                software,
                mapped(Ipv4Addr::new(1, 1, 1, 1), 1),
                xor_mapped(public(), 45000),
            ],
        );
        assert_eq!(parse(&data, &TRANSACTION).unwrap(), public());
        // RFC 5769 2.2: the IPv4 response's value, 192.0.2.1 XOR the cookie.
        let vector = success(
            &TRANSACTION,
            &[attribute(
                XOR_MAPPED_ADDRESS,
                &[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43],
            )],
        );
        assert_eq!(
            parse(&vector, &TRANSACTION).unwrap(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
    }

    #[test]
    fn plain_mapped_address_is_the_fallback() {
        let data = success(&TRANSACTION, &[mapped(public(), 45000)]);
        assert_eq!(parse(&data, &TRANSACTION).unwrap(), public());
        let mut ipv6 = vec![0, FAMILY_IPV6, 0, 1];
        ipv6.extend_from_slice(&[0x20; 16]);
        let data = success(
            &TRANSACTION,
            &[
                attribute(XOR_MAPPED_ADDRESS, &ipv6),
                mapped(public(), 45000),
            ],
        );
        assert_eq!(parse(&data, &TRANSACTION).unwrap(), public());
        let data = success(&TRANSACTION, &[attribute(XOR_MAPPED_ADDRESS, &ipv6)]);
        assert!(parse(&data, &TRANSACTION).is_err());
        assert!(parse(&success(&TRANSACTION, &[]), &TRANSACTION).is_err());
    }

    #[test]
    fn header_must_answer_this_exact_transaction() {
        let data = success(&TRANSACTION, &[xor_mapped(public(), 45000)]);
        assert!(parse(&data, &[8; 12]).is_err());
        let mut wrong_cookie = data.clone();
        wrong_cookie[4] ^= 1;
        assert!(parse(&wrong_cookie, &TRANSACTION).is_err());
        for kind in [[0x01, 0x11], [0x00, 0x01], [0x01, 0x00]] {
            let mut changed = data.clone();
            changed[0..2].copy_from_slice(&kind);
            assert!(parse(&changed, &TRANSACTION).is_err());
        }
        for length in 0..data.len() {
            assert!(parse(&data[..length], &TRANSACTION).is_err());
        }
        let mut longer = data.clone();
        longer.extend_from_slice(&[0; 4]);
        assert!(parse(&longer, &TRANSACTION).is_err());
        let mut unaligned = data;
        unaligned[3] -= 2;
        unaligned.truncate(unaligned.len() - 2);
        assert!(parse(&unaligned, &TRANSACTION).is_err());
    }

    #[test]
    fn truncated_or_malformed_address_attribute_rejects_the_message() {
        let good = xor_mapped(public(), 45000);
        // The attribute claims more bytes than the message carries.
        let mut overlong = good.clone();
        overlong[3] = 12;
        assert!(parse(&success(&TRANSACTION, &[overlong]), &TRANSACTION).is_err());
        // Consistent lengths, but a four-byte IPv4 value.
        let short = attribute(XOR_MAPPED_ADDRESS, &good[4..8]);
        assert!(parse(&success(&TRANSACTION, &[short]), &TRANSACTION).is_err());
        let mut family = good.clone();
        family[5] = 3;
        assert!(parse(&success(&TRANSACTION, &[family]), &TRANSACTION).is_err());
        // A trailing attribute header whose value the message does not carry.
        let mut data = success(&TRANSACTION, &[good]);
        data.extend_from_slice(&[0x80, 0x22, 0x00, 0x04]);
        data[3] += 4;
        assert!(parse(&data, &TRANSACTION).is_err());
    }

    #[test]
    fn oversize_or_attribute_flooded_datagram_is_rejected() {
        let filler = attribute(0x8022, &[b'x'; 64]);
        let mut attributes = vec![filler; 8];
        attributes.push(xor_mapped(public(), 45000));
        let data = success(&TRANSACTION, &attributes);
        assert!(data.len() > MAX_DATAGRAM);
        assert!(parse(&data, &TRANSACTION).is_err());
        let mut many = vec![attribute(0x8022, &[]); MAX_ATTRIBUTES];
        many.push(xor_mapped(public(), 45000));
        let data = success(&TRANSACTION, &many);
        assert!(data.len() <= MAX_DATAGRAM);
        assert!(parse(&data, &TRANSACTION).is_err());
    }

    #[test]
    fn non_global_mapped_address_parses_but_is_not_public() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::UNSPECIFIED,
        ] {
            let data = success(&TRANSACTION, &[xor_mapped(ip, 45000)]);
            let parsed = parse(&data, &TRANSACTION).unwrap();
            assert_eq!(parsed, ip);
            assert!(!global(IpAddr::V4(parsed)));
        }
    }

    #[test]
    fn schedule_refreshes_after_five_minutes_and_keeps_an_answer_fifteen() {
        let now = Instant::now();
        let mut address = PublicAddress::new();
        assert_eq!(address.current(now), None);
        address.failed(now);
        assert_eq!(address.current(now), None);
        assert_eq!(address.next_query, now + Duration::from_secs(30));
        address.succeeded(public(), now);
        assert_eq!(address.next_query, now + REFRESH);
        let refresh = now + REFRESH;
        address.failed(refresh);
        assert_eq!(address.next_query, refresh + Duration::from_secs(30));
        address.failed(refresh);
        assert_eq!(address.next_query, refresh + Duration::from_secs(60));
        address.failed(refresh);
        address.failed(refresh);
        assert_eq!(address.next_query, refresh + Duration::from_secs(120));
        assert_eq!(
            address.current(now + GRACE - Duration::from_secs(1)),
            Some(public())
        );
        assert_eq!(address.current(now + GRACE), None);
    }

    #[test]
    fn a_different_gateway_drops_the_answer_and_queries_at_once() {
        let now = Instant::now();
        let first = Ipv4Addr::new(192, 168, 1, 1);
        let mut address = PublicAddress::new();
        address.observe_gateway(Some(first), now);
        address.succeeded(public(), now);
        // A gateway that is momentarily unknown is not a different network.
        address.observe_gateway(None, now);
        address.observe_gateway(Some(first), now);
        assert_eq!(address.current(now), Some(public()));
        assert_eq!(address.next_query, now + REFRESH);
        address.observe_gateway(Some(Ipv4Addr::new(192, 168, 0, 1)), now);
        assert_eq!(address.current(now), None);
        assert_eq!(address.next_query, now);
    }

    #[tokio::test]
    async fn cancelled_lookup_sends_nothing_and_records_no_failure() {
        let stop = CancellationToken::new();
        stop.cancel();
        let error = public_ipv4(Ipv4Addr::LOCALHOST, &[("127.0.0.1", 9)], &stop)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let mut address = PublicAddress::new();
        let due = address.next_query;
        address.poll(Ipv4Addr::LOCALHOST, None, &stop).await;
        assert_eq!(address.failures, 0);
        assert_eq!(address.next_query, due);
    }

    /// Real loopback UDP. The first server answers with a private address; the
    /// second ignores the first send, then answers the resend after a stray
    /// datagram for another transaction. A lost datagram fails, never hangs.
    #[tokio::test]
    async fn loopback_servers_private_answer_moves_on_and_resend_is_answered() {
        let host = Ipv4Addr::LOCALHOST;
        let private = UdpSocket::bind((host, 0)).await.unwrap();
        let public_server = UdpSocket::bind((host, 0)).await.unwrap();
        let address = |socket: &UdpSocket| match socket.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        };
        let servers = [address(&private), address(&public_server)];
        let private_task = async {
            let mut bytes = [0; 64];
            let (count, peer) = private.recv_from(&mut bytes).await.unwrap();
            assert_eq!(count, HEADER_BYTES);
            let transaction: [u8; 12] = bytes[8..20].try_into().unwrap();
            let reply = success(&transaction, &[xor_mapped(Ipv4Addr::new(10, 0, 0, 1), 1)]);
            private.send_to(&reply, peer).await.unwrap();
        };
        let public_task = async {
            let mut bytes = [0; 64];
            let (count, _) = public_server.recv_from(&mut bytes).await.unwrap();
            let first = bytes[..count].to_vec();
            let (count, peer) = public_server.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], &first[..]);
            assert_eq!(&first[0..8], &request(&[0; 12])[0..8]);
            let transaction: [u8; 12] = first[8..20].try_into().unwrap();
            let stray = success(&[9; 12], &[xor_mapped(Ipv4Addr::new(1, 1, 1, 1), 1)]);
            public_server.send_to(&stray, peer).await.unwrap();
            let reply = success(&transaction, &[xor_mapped(public(), 45000)]);
            public_server.send_to(&reply, peer).await.unwrap();
        };
        let client = async {
            first_public(host, &servers, &CancellationToken::new())
                .await
                .unwrap()
        };
        let exchange = async { tokio::join!(private_task, public_task, client) };
        let ((), (), found) = tokio::time::timeout(Duration::from_secs(15), exchange)
            .await
            .expect("a loopback datagram was lost");
        assert_eq!(found, Some(public()));
    }
}
