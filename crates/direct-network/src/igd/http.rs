// SPDX-License-Identifier: GPL-2.0-or-later
//! Numeric same-origin HTTP only, one bounded socket, no redirects or DNS.
//! A 500 reply surfaces only as a typed UPnP error code, never as a body.
use std::{
    error, fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};

use super::{
    CancellationToken, Network, bounded, invalid_response,
    xml::{self, Node},
};

const MAX_RESPONSE: usize = 65536;
const MAX_HEADERS: usize = 8192;

pub(super) struct Target {
    pub(super) address: SocketAddrV4,
    pub(super) path: String,
}

/// One SOAP call. The matched service type names both header and namespace.
pub(super) struct Soap<'a> {
    pub(super) service: &'a str,
    pub(super) action: &'a str,
    pub(super) body: &'a str,
}

/// `detail/UPnPError/errorCode` of a SOAP fault the gateway answered with.
#[derive(Debug)]
struct Fault(u16);

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UPnP error {}", self.0)
    }
}

impl error::Error for Fault {}

pub(super) fn fault_code(error: &io::Error) -> Option<u16> {
    error
        .get_ref()?
        .downcast_ref::<Fault>()
        .map(|fault| fault.0)
}

/// `HTTP/1.0` or `HTTP/1.1`, a three-digit code, then nothing or any reason.
pub(super) fn status(line: &str) -> Option<u16> {
    let rest = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))?;
    let (code, reason) = rest.split_at_checked(3)?;
    if !code.bytes().all(|byte| byte.is_ascii_digit())
        || !(reason.is_empty() || reason.starts_with(' '))
    {
        return None;
    }
    code.parse().ok()
}

impl Target {
    pub(super) fn absolute(url: &str, gateway: Ipv4Addr) -> io::Result<Self> {
        if url.len() > 2048 || !url.is_ascii() {
            return Err(invalid_response());
        }
        let raw = url.strip_prefix("http://").ok_or_else(invalid_response)?;
        let (authority, path) = raw.split_once('/').ok_or_else(invalid_response)?;
        let address = if let Some((host, port)) = authority.split_once(':') {
            let ip: Ipv4Addr = host.parse().map_err(|_| invalid_response())?;
            let port: u16 = port.parse().map_err(|_| invalid_response())?;
            if host != ip.to_string() || port == 0 {
                return Err(invalid_response());
            }
            SocketAddrV4::new(ip, port)
        } else {
            let ip: Ipv4Addr = authority.parse().map_err(|_| invalid_response())?;
            if authority != ip.to_string() {
                return Err(invalid_response());
            }
            SocketAddrV4::new(ip, 80)
        };
        if *address.ip() != gateway {
            return Err(invalid_response());
        }
        let path = format!("/{path}");
        validate_path(&path)?;
        Ok(Self { address, path })
    }

    pub(super) fn resolve(&self, value: &str) -> io::Result<Self> {
        if value.is_empty() {
            return Err(invalid_response());
        }
        if value.starts_with("http://") {
            let target = Self::absolute(value, *self.address.ip())?;
            if target.address != self.address {
                return Err(invalid_response());
            }
            return Ok(target);
        }
        let path = if value.starts_with('/') {
            value.to_owned()
        } else {
            let (directory, _) = self.path.rsplit_once('/').ok_or_else(invalid_response)?;
            format!("{directory}/{value}")
        };
        validate_path(&path)?;
        Ok(Self {
            address: self.address,
            path,
        })
    }
}

fn validate_path(path: &str) -> io::Result<()> {
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || !path.is_ascii()
        || path
            .bytes()
            .any(|byte| byte <= 32 || byte >= 127 || b"\\%#?@:".contains(&byte))
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(invalid_response());
    }
    Ok(())
}

pub(super) async fn request(
    target: &Target,
    soap: Option<Soap<'_>>,
    network: &Network,
    stop: &CancellationToken,
) -> io::Result<String> {
    if *target.address.ip() != network.gateway {
        return Err(invalid_response());
    }
    bounded(stop, async {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new((*network.internal.ip()).into(), 0))?;
        let mut stream = socket.connect(SocketAddr::V4(target.address)).await?;
        let request = match soap {
            None => format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", target.path, target.address),
            Some(Soap { service, action, body }) => format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}#{action}\"\r\nContent-Length: {}\r\n\r\n{body}",
                target.path, target.address, body.len(),
            ),
        };
        stream.write_all(request.as_bytes()).await?;
        let mut received = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 { break; }
            if received.len() + count > MAX_RESPONSE { return Err(invalid_response()); }
            received.extend_from_slice(&buffer[..count]);
            if !received.windows(4).any(|bytes| bytes == b"\r\n\r\n") && received.len() > MAX_HEADERS {
                return Err(invalid_response());
            }
            // Some routers ignore `Connection: close`; a complete body ends the read.
            if framed_length(&received).is_some_and(|total| received.len() >= total) {
                break;
            }
        }
        decode(&received)
    }).await
}

fn framed_length(bytes: &[u8]) -> Option<usize> {
    let split = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&bytes[..split]).ok()?;
    let length = headers.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse::<usize>().ok()
    })?;
    split.checked_add(4)?.checked_add(length)
}

fn decode(bytes: &[u8]) -> io::Result<String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid_response)?;
    if split > MAX_HEADERS || bytes.len() > MAX_RESPONSE {
        return Err(invalid_response());
    }
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| invalid_response())?;
    let mut lines = headers.split("\r\n");
    let code = lines.next().and_then(status).ok_or_else(invalid_response)?;
    if code != 200 && code != 500 {
        return Err(invalid_response());
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid_response)?;
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
        {
            return Err(invalid_response());
        }
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(invalid_response());
            }
            length = Some(value.parse::<usize>().map_err(|_| invalid_response())?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(invalid_response());
            }
            chunked = true;
        }
    }
    let body = &bytes[split + 4..];
    let body = if chunked {
        if length.is_some() {
            return Err(invalid_response());
        }
        decode_chunks(body)?
    } else {
        if length.is_some_and(|length| length != body.len()) {
            return Err(invalid_response());
        }
        String::from_utf8(body.to_vec()).map_err(|_| invalid_response())?
    };
    if code == 500 {
        return Err(fault(&body));
    }
    Ok(body)
}

/// A 500 without a well-formed UPnP fault stays an ordinary rejection.
fn fault(body: &str) -> io::Error {
    xml::parse(body)
        .and_then(|document| upnp_error(&document))
        .map_or_else(|_| invalid_response(), |code| io::Error::other(Fault(code)))
}

fn upnp_error(document: &Node) -> io::Result<u16> {
    if document.name != "Envelope" {
        return Err(invalid_response());
    }
    document
        .child("Body")?
        .child("Fault")?
        .child("detail")?
        .child("UPnPError")?
        .value("errorCode")?
        .parse()
        .map_err(|_| invalid_response())
}

fn decode_chunks(mut bytes: &[u8]) -> io::Result<String> {
    let mut result = Vec::new();
    for _ in 0..512 {
        let split = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(invalid_response)?;
        if split == 0 || split > 8 {
            return Err(invalid_response());
        }
        let text = std::str::from_utf8(&bytes[..split]).map_err(|_| invalid_response())?;
        if !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_response());
        }
        let size = usize::from_str_radix(text, 16).map_err(|_| invalid_response())?;
        bytes = &bytes[split + 2..];
        if size == 0 {
            if bytes != b"\r\n" {
                return Err(invalid_response());
            }
            return String::from_utf8(result).map_err(|_| invalid_response());
        }
        if size > MAX_RESPONSE || size + 2 > bytes.len() || &bytes[size..size + 2] != b"\r\n" {
            return Err(invalid_response());
        }
        if result.len() + size > MAX_RESPONSE {
            return Err(invalid_response());
        }
        result.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
    Err(invalid_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn upnp_fault(code: u16) -> String {
        let body = format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
             <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
             <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
             <errorDescription>fixture</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
        );
        format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn url_constraints_block_ssrf_credentials_redirect_origins_and_injection() {
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let target = Target::absolute("http://192.168.1.1:5432/root.xml", gateway).unwrap();
        assert_eq!(target.resolve("/control").unwrap().path, "/control");
        for value in [
            "http://127.0.0.1/x",
            "http://example.test/x",
            "https://192.168.1.1/x",
            "http://user@192.168.1.1/x",
            "http://192.168.1.1:0/x",
            "http://192.168.1.1/%2e%2e/x",
        ] {
            assert!(Target::absolute(value, gateway).is_err());
        }
        for value in [
            "//evil/x",
            "../x",
            "/x\r\nInjected: yes",
            "http://192.168.1.1:5433/control",
            "/x#fragment",
            "\\evil",
        ] {
            assert!(target.resolve(value).is_err());
        }
    }

    #[test]
    fn bounded_http_rejects_redirects_framing_ambiguity_and_truncation() {
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap(),
            "ok"
        );
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
                .unwrap(),
            "ok"
        );
        for bytes in [
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\na\r\n",
        ] {
            assert!(decode(bytes).is_err());
        }
    }

    #[test]
    fn status_line_accepts_any_reason_and_only_200_or_500() {
        for (bytes, body) in [
            (
                b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok".as_slice(),
                "ok",
            ),
            (b"HTTP/1.1 200 ok\r\n\r\nok", "ok"),
            (b"HTTP/1.0 200 Everything Fine\r\n\r\nok", "ok"),
        ] {
            assert_eq!(decode(bytes).unwrap(), body);
        }
        for bytes in [
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno".as_slice(),
            b"HTTP/1.1 2000 OK\r\n\r\nok",
            b"HTTP/1.1 200OK\r\n\r\nok",
            b"HTTP/2 200\r\n\r\nok",
            b"http/1.1 200 OK\r\n\r\nok",
        ] {
            let error = decode(bytes).unwrap_err();
            assert_eq!(fault_code(&error), None);
        }
    }

    #[test]
    fn soap_fault_is_a_typed_upnp_error_and_other_500s_are_not() {
        let error = decode(upnp_fault(725).as_bytes()).unwrap_err();
        assert_eq!(fault_code(&error), Some(725));
        let error = decode(upnp_fault(714).as_bytes()).unwrap_err();
        assert_eq!(fault_code(&error), Some(714));
        for bytes in [
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\n\r\n<x/>".as_slice(),
            b"HTTP/1.1 500 Internal Server Error\r\n\r\n",
            b"HTTP/1.1 500 Internal Server Error\r\n\r\n<Envelope><Body><Fault><detail><UPnPError>\
              <errorCode>x</errorCode></UPnPError></detail></Fault></Body></Envelope>",
        ] {
            assert_eq!(fault_code(&decode(bytes).unwrap_err()), None);
        }
        assert_eq!(fault_code(&invalid_response()), None);
    }

    #[test]
    fn content_length_frames_a_reply_from_a_router_that_keeps_the_socket_open() {
        let reply = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
        assert_eq!(framed_length(&reply[..reply.len() - 1]), Some(reply.len()));
        assert_eq!(framed_length(reply), Some(reply.len()));
        assert_eq!(framed_length(b"HTTP/1.1 200 OK\r\n\r\nok"), None);
        assert_eq!(framed_length(b"HTTP/1.1 200 OK\r\nContent-Length: 2"), None);
    }

    #[tokio::test]
    async fn real_loopback_http_gateway_and_cancellable_silent_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let network = Network {
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7443),
            gateway: Ipv4Addr::LOCALHOST,
            ipv6: vec![],
        };
        let target =
            Target::absolute(&format!("http://{address}/root.xml"), Ipv4Addr::LOCALHOST).unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            // TCP may deliver the request in several reads.
            let mut received = Vec::new();
            while !received.ends_with(b"\r\n\r\n") {
                let mut bytes = [0; 4096];
                let count = stream.read(&mut bytes).await.unwrap();
                assert!(count > 0 && received.len() + count < 4096);
                received.extend_from_slice(&bytes[..count]);
            }
            assert!(received.starts_with(b"GET /root.xml HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n<x/>")
                .await
                .unwrap();
            // The framed reply lets the client close first.
            let _ = stream.read(&mut [0; 1]).await;
        };
        let client = async {
            assert_eq!(
                request(&target, None, &network, &CancellationToken::new())
                    .await
                    .unwrap(),
                "<x/>"
            );
        };
        tokio::join!(server, client);

        let stop = CancellationToken::new();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut first_byte = [0; 1];
            stream.read_exact(&mut first_byte).await.unwrap();
            stop.cancel();
            stop.cancelled().await;
        };
        let client = async {
            assert_eq!(
                request(&target, None, &network, &stop)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::Interrupted
            );
        };
        tokio::join!(server, client);
    }
}
