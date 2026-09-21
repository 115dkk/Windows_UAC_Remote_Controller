// SPDX-License-Identifier: GPL-2.0-or-later
//! Read-only IGD v2 probe. Discovery and control stay on the selected numeric
//! gateway origin. No production mapping mutation: IGD cannot atomically
//! exclude unknown same-host mappings, even with AddAnyPortMapping.
mod http;
mod xml;

use std::{io, net::IpAddr};
#[cfg(test)]
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::net::UdpSocket;

#[cfg(test)]
use super::LEASE_SECONDS;
use super::{CancellationToken, Network, bounded, global, invalid_response};
use http::Target;
use xml::Node;

const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

#[cfg(test)]
struct FixtureLease {
    external: SocketAddr,
    expires: Instant,
}

pub(super) async fn probe(network: &Network, stop: &CancellationToken) -> io::Result<()> {
    let target = discover(network, stop).await?;
    let reply = soap(&target, "GetExternalIPAddress", "", network, stop).await?;
    let ip: IpAddr = response(&reply, "GetExternalIPAddressResponse")?
        .value("NewExternalIPAddress")?
        .parse()
        .map_err(|_| invalid_response())?;
    if !global(ip) || !ip.is_ipv4() {
        return Err(invalid_response());
    }
    // A public router address without an owned mapping is not advertised.
    Ok(())
}

/// Test-only protocol fixture, deliberately excluded from product builds. The
/// round trip tests parsers/ownership checks, not safety of enabling mutation.
#[cfg(test)]
async fn map_target(
    network: &Network,
    stop: &CancellationToken,
    target: Target,
) -> io::Result<FixtureLease> {
    let external_reply = soap(&target, "GetExternalIPAddress", "", network, stop).await?;
    let external_ip: IpAddr = response(&external_reply, "GetExternalIPAddressResponse")?
        .value("NewExternalIPAddress")?
        .parse()
        .map_err(|_| invalid_response())?;
    if !global(external_ip) || !external_ip.is_ipv4() {
        return Err(invalid_response());
    }
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(|_| io::Error::other("mapping nonce unavailable"))?;
    let description = format!("RemoteUAC-{:032x}", u128::from_be_bytes(token));
    let arguments = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>0</NewExternalPort>\
         <NewProtocol>TCP</NewProtocol><NewInternalPort>{}</NewInternalPort>\
         <NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled>\
         <NewPortMappingDescription>{description}</NewPortMappingDescription>\
         <NewLeaseDuration>{LEASE_SECONDS}</NewLeaseDuration>",
        network.internal.port(),
        network.internal.ip(),
    );
    let begun = Instant::now();
    // Models the success reply only. The protocol's same-client overwrite
    // ambiguity is why this path is test-only and cannot be shipped safely.
    let reply = soap(&target, "AddAnyPortMapping", &arguments, network, stop).await?;
    let port: u16 = response(&reply, "AddAnyPortMappingResponse")?
        .value("NewReservedPort")?
        .parse()
        .map_err(|_| invalid_response())?;
    if port == 0 {
        return Err(invalid_response());
    }
    let entry = specific(&target, port, network, stop).await?;
    let lifetime = owned(&entry, network, &description)?;
    Ok(FixtureLease {
        external: SocketAddr::new(external_ip, port),
        expires: begun + Duration::from_secs(u64::from(lifetime)),
    })
    // No IGD DeletePortMapping or renewal: neither supports an atomic
    // description/tuple comparison. Cancellation, lost responses and shutdown
    // leave only the requested finite lease to expire (at most 600 seconds on
    // conforming gateways). Existing, unknown and permanent maps are untouched.
}

#[cfg(test)]
fn owned(reply: &Node, network: &Network, description: &str) -> io::Result<u32> {
    let entry = response(reply, "GetSpecificPortMappingEntryResponse")?;
    let client: IpAddr = entry
        .value("NewInternalClient")?
        .parse()
        .map_err(|_| invalid_response())?;
    let port: u16 = entry
        .value("NewInternalPort")?
        .parse()
        .map_err(|_| invalid_response())?;
    let lifetime: u32 = entry
        .value("NewLeaseDuration")?
        .parse()
        .map_err(|_| invalid_response())?;
    if client != IpAddr::V4(*network.internal.ip())
        || port != network.internal.port()
        || entry.value("NewPortMappingDescription")? != description
        || entry.value("NewEnabled")? != "1"
        || !(1..=LEASE_SECONDS).contains(&lifetime)
    {
        return Err(invalid_response());
    }
    Ok(lifetime)
}

#[cfg(test)]
async fn specific(
    target: &Target,
    port: u16,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Node> {
    let arguments = format!(
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>{port}</NewExternalPort><NewProtocol>TCP</NewProtocol>"
    );
    soap(
        target,
        "GetSpecificPortMappingEntry",
        &arguments,
        network,
        stop,
    )
    .await
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
    target: &Target,
    action: &str,
    arguments: &str,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<Node> {
    let body = format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{SERVICE}\">{arguments}</u:{action}></s:Body></s:Envelope>"
    );
    let result = http::request(target, Some((action, &body)), network, stop).await?;
    xml::parse(&result)
}

async fn discover(network: &Network, stop: &CancellationToken) -> io::Result<Target> {
    let location = bounded(stop, async {
        let socket = UdpSocket::bind((*network.internal.ip(), 0)).await?;
        socket.connect((network.gateway, 1900)).await?;
        // Directed discovery: no multicast interface selection or unrelated
        // LAN devices can supply URLs. A conforming unicast SSDP responder is
        // required; unsupported discovery leaves the LAN candidate available.
        socket.send(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n").await?;
        let mut bytes = [0; 4096];
        let count = socket.recv(&mut bytes).await?;
        if count == bytes.len() {
            return Err(invalid_response());
        }
        location(&bytes[..count])
    }).await?;
    let mut root = Target::absolute(&location, network.gateway)?;
    let body = http::request(&root, None, network, stop).await?;
    let document = xml::parse(&body)?;
    if document.name != "root" {
        return Err(invalid_response());
    }
    // URLBase can only equal the already vetted descriptor origin. Reject
    // alternate bases instead of fetching attacker-selected destinations.
    let base_count = document
        .children
        .iter()
        .filter(|node| node.name == "URLBase")
        .count();
    if base_count > 1 {
        return Err(invalid_response());
    }
    if base_count == 1 {
        let base = document.child("URLBase")?;
        let target = Target::absolute(base.text.trim(), network.gateway)?;
        if target.address != root.address || target.path != "/" {
            return Err(invalid_response());
        }
        root.path = target.path;
    }
    let mut services = Vec::new();
    find_services(&document, &mut services);
    if services.len() != 1 {
        return Err(invalid_response());
    }
    root.resolve(services[0].value("controlURL")?)
}

fn find_services<'a>(node: &'a Node, found: &mut Vec<&'a Node>) {
    if node.name == "service"
        && node
            .value("serviceType")
            .is_ok_and(|value| value == SERVICE)
    {
        found.push(node);
    }
    for child in &node.children {
        find_services(child, found);
    }
}

fn location(bytes: &[u8]) -> io::Result<String> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_response())?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn ambiguous_location_and_control_origins_fail_closed() {
        assert!(location(b"HTTP/1.1 200 OK\r\nLOCATION: a\r\nlocation: b\r\n\r\n").is_err());
        assert!(location(b"HTTP/1.1 302 Found\r\nLOCATION: a\r\n\r\n").is_err());
        assert_eq!(
            location(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/root.xml\r\n\r\n").unwrap(),
            "http://192.168.1.1/root.xml"
        );
    }

    #[test]
    fn exact_mapping_readback_rejects_permanent_unknown_and_different_owners() {
        let network = Network {
            internal: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 7443),
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            ipv6: vec![],
        };
        let make = |lease, description: &str| {
            xml::parse(&format!(
            "<Envelope><Body><GetSpecificPortMappingEntryResponse>\
             <NewInternalClient>192.168.1.2</NewInternalClient><NewInternalPort>7443</NewInternalPort>\
             <NewPortMappingDescription>{description}</NewPortMappingDescription><NewEnabled>1</NewEnabled>\
             <NewLeaseDuration>{lease}</NewLeaseDuration></GetSpecificPortMappingEntryResponse></Body></Envelope>"
        )).unwrap()
        };
        assert_eq!(
            owned(&make(599, "synthetic-owner"), &network, "synthetic-owner").unwrap(),
            599
        );
        assert!(owned(&make(0, "synthetic-owner"), &network, "synthetic-owner").is_err());
        assert!(owned(&make(601, "synthetic-owner"), &network, "synthetic-owner").is_err());
        assert!(owned(&make(600, "another-owner"), &network, "synthetic-owner").is_err());
    }

    #[tokio::test]
    async fn real_loopback_igd_allocates_finite_free_port_and_verifies_ownership() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = Target::absolute(
            &format!("http://{}/control", listener.local_addr().unwrap()),
            Ipv4Addr::LOCALHOST,
        )
        .unwrap();
        let network = Network {
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7443),
            gateway: Ipv4Addr::LOCALHOST,
            ipv6: vec![],
        };
        let server = async {
            let mut description = String::new();
            for action in [
                "GetExternalIPAddress",
                "AddAnyPortMapping",
                "GetSpecificPortMappingEntry",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut bytes = [0; 4096];
                loop {
                    let count = stream.read(&mut bytes).await.unwrap();
                    assert!(count > 0 && request.len() + count < 8192);
                    request.extend_from_slice(&bytes[..count]);
                    if let Some(split) = request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let header = std::str::from_utf8(&request[..split]).unwrap();
                        let length: usize = header
                            .lines()
                            .find_map(|line| line.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() >= split + 4 + length {
                            break;
                        }
                    }
                }
                let request = std::str::from_utf8(&request).unwrap();
                assert!(request.contains(&format!("#{action}\"")));
                let fields = match action {
                    "GetExternalIPAddress" => {
                        "<NewExternalIPAddress>8.8.8.8</NewExternalIPAddress>".to_owned()
                    }
                    "AddAnyPortMapping" => {
                        assert!(request.contains("<NewExternalPort>0</NewExternalPort>"));
                        assert!(request.contains("<NewLeaseDuration>600</NewLeaseDuration>"));
                        assert!(
                            request.contains("<NewInternalClient>127.0.0.1</NewInternalClient>")
                        );
                        description = request
                            .split_once("<NewPortMappingDescription>")
                            .unwrap()
                            .1
                            .split_once("</NewPortMappingDescription>")
                            .unwrap()
                            .0
                            .to_owned();
                        "<NewReservedPort>45000</NewReservedPort>".to_owned()
                    }
                    _ => {
                        assert!(request.contains("<NewExternalPort>45000</NewExternalPort>"));
                        format!(
                            "<NewInternalClient>127.0.0.1</NewInternalClient><NewInternalPort>7443</NewInternalPort><NewEnabled>1</NewEnabled><NewLeaseDuration>599</NewLeaseDuration><NewPortMappingDescription>{description}</NewPortMappingDescription>"
                        )
                    }
                };
                let body = format!(
                    "<Envelope><Body><{action}Response>{fields}</{action}Response></Body></Envelope>"
                );
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        };
        let client = async {
            let lease = map_target(&network, &CancellationToken::new(), target)
                .await
                .unwrap();
            assert_eq!(lease.external.port(), 45000);
            assert!(
                lease
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    <= 599
            );
        };
        tokio::join!(server, client);
    }
}
