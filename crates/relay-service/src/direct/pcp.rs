// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed-size RFC 6887 MAP subset (TCP, no THIRD_PARTY/options). The mapping
//! nonce is ownership for router operations, not authentication of any peer.
use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

use super::{CancellationToken, LEASE_SECONDS, Network, bounded, global, invalid_response, pause};

const PCP_PORT: u16 = 5351;
const MAP_BYTES: usize = 60;

pub(super) struct Lease {
    pub(super) external: SocketAddr,
    pub(super) expires: Instant,
    nonce: [u8; 12],
    epoch: u32,
    cleanup_only: bool,
}

impl Lease {
    /// Synthetic ownership state only; wire behavior uses real UDP fixtures.
    #[cfg(test)]
    pub(super) fn ownership_fixture(expires: Instant) -> Self {
        Self {
            external: "8.8.8.8:45000".parse().unwrap(),
            expires,
            nonce: [1; 12],
            epoch: 1,
            cleanup_only: false,
        }
    }

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
        let request = request(network, self.nonce, LEASE_SECONDS, Some(self.external));
        let response = exchange(network, &request, stop, PCP_PORT).await?;
        let parsed = parse(&response, network.internal.port(), &self.nonce)?;
        let epoch_regressed = parsed.epoch < self.epoch;
        self.external = parsed.external;
        self.expires = begun + Duration::from_secs(u64::from(parsed.lifetime));
        self.epoch = parsed.epoch;
        self.cleanup_only = epoch_regressed || !parsed.within_candidate_policy();
        Ok(())
    }

    pub(super) async fn release(mut self, network: &Network) {
        let _ = self.cleanup(network).await;
    }

    pub(super) async fn cleanup(&mut self, network: &Network) -> bool {
        self.cleanup_at(network, PCP_PORT).await
    }

    async fn cleanup_at(&mut self, network: &Network, port: u16) -> bool {
        // One bounded attempt with a distinct cleanup cancellation token. Exact
        // nonce + client IP + protocol + internal port; never a wildcard delete.
        // RFC 6887 15.1 requires BOTH external suggestion fields to be zero.
        self.cleanup_only = true;
        let request = request(network, self.nonce, 0, None);
        let cleanup = CancellationToken::new();
        let confirmed = exchange(network, &request, &cleanup, port)
            .await
            .is_ok_and(|reply| deletion_ack(&reply, network.internal.port(), &self.nonce));
        if confirmed {
            self.expires = Instant::now();
        }
        confirmed
    }
}

pub(super) async fn map(
    network: &Network,
    stop: &CancellationToken,
    seed: [u8; 12],
) -> io::Result<Lease> {
    map_at(network, stop, scoped_nonce(network, seed), PCP_PORT).await
}

/// A server-specific, opaque mapping nonce. Reusing a persisted base seed on a
/// different numeric PCP server never reuses its wire nonce (RFC 6887 11.2).
/// Bind the local tuple too, so distinct local mappings have distinct nonces.
fn scoped_nonce(network: &Network, seed: [u8; 12]) -> [u8; 12] {
    let mut hash = Sha256::new();
    hash.update(b"remote-uac/pcp-map-nonce/v1\0");
    hash.update(seed);
    hash.update(network.gateway.octets());
    hash.update(PCP_PORT.to_be_bytes());
    hash.update(network.internal.ip().octets());
    hash.update(network.internal.port().to_be_bytes());
    let digest = hash.finalize();
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

async fn map_at(
    network: &Network,
    stop: &CancellationToken,
    nonce: [u8; 12],
    port: u16,
) -> io::Result<Lease> {
    let request = request(network, nonce, LEASE_SECONDS, None);
    // Retransmit the identical nonce/request, never allocate one mapping per
    // retry. Bounded delays and per-attempt deadlines are cancellation-aware.
    for attempt in 0..3 {
        let begun = Instant::now();
        match exchange(network, &request, stop, port).await {
            Ok(response) => {
                let parsed = parse(&response, network.internal.port(), &nonce)?;
                return Ok(Lease {
                    external: parsed.external,
                    expires: begun + Duration::from_secs(u64::from(parsed.lifetime)),
                    nonce,
                    epoch: parsed.epoch,
                    cleanup_only: !parsed.within_candidate_policy(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(_) => {
                if attempt < 2 && pause(stop, Duration::from_secs(1 << attempt)).await {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
            }
        }
    }
    Err(io::Error::from(io::ErrorKind::TimedOut))
}

fn request(
    network: &Network,
    nonce: [u8; 12],
    lifetime: u32,
    external: Option<SocketAddr>,
) -> [u8; MAP_BYTES] {
    let mut data = [0_u8; MAP_BYTES];
    data[0] = 2;
    data[1] = 1;
    data[4..8].copy_from_slice(&lifetime.to_be_bytes());
    data[8..24].copy_from_slice(&network.internal.ip().to_ipv6_mapped().octets());
    data[24..36].copy_from_slice(&nonce);
    data[36] = 6; // TCP, not UDP or an arbitrary protocol.
    data[40..42].copy_from_slice(&network.internal.port().to_be_bytes());
    if lifetime != 0 {
        // A preference, not an overwrite: PCP nonce ownership governs conflicts.
        data[42..44].copy_from_slice(&network.internal.port().to_be_bytes());
        if let Some(external) = external {
            data[42..44].copy_from_slice(&external.port().to_be_bytes());
            let address = match external.ip() {
                IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                IpAddr::V6(ip) => ip,
            };
            data[44..60].copy_from_slice(&address.octets());
        }
    }
    data
}

struct Response {
    external: SocketAddr,
    lifetime: u32,
    epoch: u32,
}

impl Response {
    fn within_candidate_policy(&self) -> bool {
        self.lifetime <= LEASE_SECONDS && global(self.external.ip())
    }
}

fn deletion_ack(data: &[u8], internal_port: u16, nonce: &[u8; 12]) -> bool {
    header_matches(data, internal_port, nonce) && data[4..8] == [0; 4]
}

fn parse(data: &[u8], internal_port: u16, nonce: &[u8; 12]) -> io::Result<Response> {
    if !header_matches(data, internal_port, nonce) {
        return Err(invalid_response());
    }
    let lifetime = u32::from_be_bytes(data[4..8].try_into().map_err(|_| invalid_response())?);
    // RFC 6887 15 permits a server to grant more than the requested duration.
    // Retain such a valid owned map for cleanup, never forget it as malformed.
    if lifetime == 0 {
        return Err(invalid_response());
    }
    let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(&data[44..60]).map_err(|_| invalid_response())?);
    let ip = ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4);
    let port = u16::from_be_bytes([data[42], data[43]]);
    if port == 0 {
        return Err(invalid_response());
    }
    Ok(Response {
        external: SocketAddr::new(ip, port),
        lifetime,
        epoch: u32::from_be_bytes(data[8..12].try_into().map_err(|_| invalid_response())?),
    })
}

fn header_matches(data: &[u8], internal_port: u16, nonce: &[u8; 12]) -> bool {
    !(data.len() != MAP_BYTES
        || data[0] != 2
        || data[1] != 0x81
        || data[2] != 0
        || data[3] != 0
        || data[12..24] != [0; 12]
        || &data[24..36] != nonce
        || data[36] != 6
        || data[37..40] != [0; 3]
        || data[40..42] != internal_port.to_be_bytes())
}

async fn exchange(
    network: &Network,
    data: &[u8],
    stop: &CancellationToken,
    port: u16,
) -> io::Result<Vec<u8>> {
    bounded(stop, async {
        let socket = UdpSocket::bind((*network.internal.ip(), 0)).await?;
        // Connected UDP accepts only this exact default-gateway IP and port.
        socket.connect((network.gateway, port)).await?;
        socket.send(data).await?;
        let mut response = [0_u8; 1100];
        let count = socket.recv(&mut response).await?;
        Ok(response[..count].to_vec())
    })
    .await
}

pub(super) async fn probe_nat_pmp(network: &Network, stop: &CancellationToken) {
    // RFC 6886 public-address query is read-only. NAT-PMP cannot prove mapping
    // ownership; no MAP (opcode 1/2) or deletion is ever sent on this path.
    let _ = exchange(network, &[0, 0], stop, PCP_PORT).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn network() -> Network {
        Network {
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7443),
            gateway: Ipv4Addr::LOCALHOST,
            ipv6: vec![],
        }
    }

    fn response(nonce: [u8; 12]) -> [u8; MAP_BYTES] {
        let mut data = [0; MAP_BYTES];
        data[0] = 2;
        data[1] = 0x81;
        data[4..8].copy_from_slice(&600_u32.to_be_bytes());
        data[8..12].copy_from_slice(&10_u32.to_be_bytes());
        data[24..36].copy_from_slice(&nonce);
        data[36] = 6;
        data[40..42].copy_from_slice(&7443_u16.to_be_bytes());
        data[42..44].copy_from_slice(&45000_u16.to_be_bytes());
        data[44..60].copy_from_slice(&Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped().octets());
        data
    }

    #[test]
    fn map_is_owned_tcp_finite_and_not_third_party() {
        let data = request(&network(), [7; 12], LEASE_SECONDS, None);
        assert_eq!(data.len(), 60);
        assert_eq!(&data[8..24], &Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
        assert_eq!(&data[24..36], &[7; 12]);
        assert_eq!(data[36], 6);
        assert_eq!(&data[42..44], &7443_u16.to_be_bytes());
        assert_eq!(&data[44..60], &[0; 16]);
        assert_eq!(&data[4..8], &600_u32.to_be_bytes());
    }

    #[test]
    fn response_requires_exact_nonce_protocol_port_size_and_finite_lease() {
        let data = response([7; 12]);
        assert!(parse(&data, 7443, &[7; 12]).is_ok());
        assert!(parse(&data, 7443, &[8; 12]).is_err());
        assert!(parse(&data, 7444, &[7; 12]).is_err());
        for index in [0, 1, 2, 3, 12, 24, 36, 37, 40] {
            let mut changed = data;
            changed[index] ^= 1;
            assert!(parse(&changed, 7443, &[7; 12]).is_err());
        }
        let mut zero_lifetime = data;
        zero_lifetime[4..8].fill(0);
        assert!(parse(&zero_lifetime, 7443, &[7; 12]).is_err());
        for length in 0..60 {
            assert!(parse(&data[..length], 7443, &[7; 12]).is_err());
        }
        let mut changed = data.to_vec();
        changed.push(0);
        assert!(parse(&changed, 7443, &[7; 12]).is_err());
    }

    #[test]
    fn private_and_cgnat_gateway_addresses_are_not_external_candidates() {
        for ip in [
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(10, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
        ] {
            let mut data = response([7; 12]);
            data[44..60].copy_from_slice(&ip.to_ipv6_mapped().octets());
            assert!(
                !parse(&data, 7443, &[7; 12])
                    .unwrap()
                    .within_candidate_policy()
            );
        }
    }

    #[test]
    fn long_positive_grant_is_owned_but_outside_candidate_policy() {
        for lifetime in [601_u32, 7200, u32::MAX] {
            let mut data = response([7; 12]);
            data[4..8].copy_from_slice(&lifetime.to_be_bytes());
            let parsed = parse(&data, 7443, &[7; 12]).unwrap();
            assert_eq!(parsed.lifetime, lifetime);
            assert!(!parsed.within_candidate_policy());
        }
    }

    #[tokio::test]
    async fn fake_gateway_observes_zero_suggestions_for_exact_owned_deletion() {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = gateway.local_addr().unwrap().port();
        let server = async {
            let mut bytes = [0; 100];
            let (count, peer) = gateway.recv_from(&mut bytes).await.unwrap();
            assert_eq!(count, MAP_BYTES);
            let nonce: [u8; 12] = bytes[24..36].try_into().unwrap();
            gateway.send_to(&response(nonce), peer).await.unwrap();
            let (count, peer) = gateway.recv_from(&mut bytes).await.unwrap();
            assert_eq!(count, MAP_BYTES);
            assert_eq!(&bytes[4..8], &[0; 4]);
            assert_eq!(&bytes[24..36], &nonce);
            assert_eq!(bytes[36], 6);
            assert_eq!(&bytes[40..42], &7443_u16.to_be_bytes());
            assert_eq!(&bytes[42..60], &[0; 18]);
            let mut ack = response(nonce);
            ack[4..8].fill(0);
            gateway.send_to(&ack, peer).await.unwrap();
        };
        let client = async {
            let mut lease = map_at(&network(), &CancellationToken::new(), [7; 12], port)
                .await
                .unwrap();
            assert!(lease.is_candidate());
            assert!(lease.cleanup_at(&network(), port).await);
            assert!(!lease.is_candidate());
            assert_eq!(lease.remaining(), 0);
        };
        tokio::join!(server, client);
    }

    #[tokio::test]
    async fn fake_gateways_get_distinct_nonces_and_same_server_retries_retain_nonce() {
        let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let second_ip = Ipv4Addr::new(127, 0, 0, 2);
        let second = UdpSocket::bind((second_ip, 0)).await.unwrap();
        let mut second_network = network();
        second_network.gateway = second_ip;
        let first_server = async {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut bytes = [0; 100];
                let (count, peer) = first.recv_from(&mut bytes).await.unwrap();
                assert_eq!(count, MAP_BYTES);
                let nonce: [u8; 12] = bytes[24..36].try_into().unwrap();
                seen.push(nonce);
                first.send_to(&response(nonce), peer).await.unwrap();
            }
            seen
        };
        let second_server = async {
            let mut bytes = [0; 100];
            let (count, peer) = second.recv_from(&mut bytes).await.unwrap();
            assert_eq!(count, MAP_BYTES);
            let nonce: [u8; 12] = bytes[24..36].try_into().unwrap();
            second.send_to(&response(nonce), peer).await.unwrap();
            nonce
        };
        let client = async {
            let first_network = network();
            for (selected, port) in [
                (&first_network, first.local_addr().unwrap().port()),
                (&second_network, second.local_addr().unwrap().port()),
                (&first_network, first.local_addr().unwrap().port()),
            ] {
                let lease = map_at(
                    selected,
                    &CancellationToken::new(),
                    scoped_nonce(selected, [9; 12]),
                    port,
                )
                .await
                .unwrap();
                assert!(lease.is_candidate());
            }
        };
        let (first_nonces, second_nonce, ()) = tokio::join!(first_server, second_server, client);
        assert_eq!(first_nonces[0], first_nonces[1]);
        assert_ne!(first_nonces[0], second_nonce);
    }

    #[tokio::test]
    async fn fake_gateway_long_grant_keeps_cleanup_obligation_until_matching_ack() {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = gateway.local_addr().unwrap().port();
        let server = async {
            let mut bytes = [0; 100];
            let (_, peer) = gateway.recv_from(&mut bytes).await.unwrap();
            let nonce: [u8; 12] = bytes[24..36].try_into().unwrap();
            let mut granted = response(nonce);
            granted[4..8].copy_from_slice(&7200_u32.to_be_bytes());
            gateway.send_to(&granted, peer).await.unwrap();
            for valid_ack in [false, true] {
                let (_, peer) = gateway.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[4..8], &[0; 4]);
                assert_eq!(&bytes[24..36], &nonce);
                assert_eq!(&bytes[42..60], &[0; 18]);
                let mut ack = response(nonce);
                ack[4..8].fill(0);
                if !valid_ack {
                    ack[24] ^= 1;
                }
                gateway.send_to(&ack, peer).await.unwrap();
            }
        };
        let client = async {
            let mut lease = map_at(&network(), &CancellationToken::new(), [7; 12], port)
                .await
                .unwrap();
            assert!(!lease.is_candidate());
            assert!(lease.remaining() > 600);
            assert!(!lease.cleanup_at(&network(), port).await);
            assert!(lease.remaining() > 600);
            assert!(!lease.is_candidate());
            assert!(lease.cleanup_at(&network(), port).await);
            assert_eq!(lease.remaining(), 0);
        };
        tokio::join!(server, client);
    }

    #[tokio::test]
    async fn real_loopback_gateway_round_trip_and_source_filter() {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let wrong = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = gateway.local_addr().unwrap().port();
        let request = request(&network(), [7; 12], LEASE_SECONDS, None);
        let server = async {
            let mut bytes = [0; 100];
            let (count, peer) = gateway.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], &request);
            wrong.send_to(b"wrong source", peer).await.unwrap();
            gateway.send_to(&response([7; 12]), peer).await.unwrap();
        };
        let client = async {
            let reply = exchange(&network(), &request, &CancellationToken::new(), port)
                .await
                .unwrap();
            assert!(parse(&reply, 7443, &[7; 12]).is_ok());
        };
        tokio::join!(server, client);
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_silent_real_gateway() {
        let gateway = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let stop = CancellationToken::new();
        let server = async {
            let mut bytes = [0; 100];
            gateway.recv_from(&mut bytes).await.unwrap();
            stop.cancel();
        };
        let client = async {
            let error = exchange(
                &network(),
                &[0, 0],
                &stop,
                gateway.local_addr().unwrap().port(),
            )
            .await
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        };
        tokio::join!(server, client);
    }
}
