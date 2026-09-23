// SPDX-License-Identifier: GPL-2.0-or-later
//! The administrator's choice of how this PC learns an external relay address.
//! One fixed, versioned, canonical line on disk and one fixed CLI shape. It is
//! a routing preference, never authority, consent or proof of reachability.
#![forbid(unsafe_code)]
// The trust-store reader and the service session only exist on 64-bit
// Windows; other targets compile this module for its shared format and tests.
#![cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]

use std::net::SocketAddr;

use direct_network::ExternalAccess;

/// Bound for the stored line. The longest canonical value is
/// `v1 fixed [xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:65535\n` (57 bytes).
pub(crate) const MAX_STORED_BYTES: u64 = 64;
const VERSION: &str = "v1";

/// What the service found in its protected configuration at startup.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StoredExternalAccess {
    /// No file: the default, `Automatic`.
    Absent,
    Valid(ExternalAccess),
    /// Unknown, oversized, non-canonical or unusable content. The service
    /// falls back to `Automatic` and reports this, it does not stop.
    Invalid,
}

impl std::fmt::Debug for StoredExternalAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Absent => "StoredExternalAccess::Absent",
            Self::Valid(_) => "StoredExternalAccess::Valid(redacted)",
            Self::Invalid => "StoredExternalAccess::Invalid",
        })
    }
}

impl StoredExternalAccess {
    /// `None` means the file is absent. Any content is judged here, never by
    /// the storage adapter, so a bad value cannot poison the trust directory.
    pub(crate) fn from_stored(bytes: Option<&[u8]>) -> Self {
        match bytes {
            None => Self::Absent,
            Some(bytes) => decode(bytes).map_or(Self::Invalid, Self::Valid),
        }
    }

    /// The mode the service runs with. Invalid content means the default.
    pub(crate) fn effective(self) -> ExternalAccess {
        match self {
            Self::Valid(access) => access,
            Self::Absent | Self::Invalid => ExternalAccess::Automatic,
        }
    }
}

/// `auto`, `forward <port>` or `fixed <ip:port>`: the words shared by the CLI
/// and the stored line. `None` for a value `validated()` rejects.
fn words(access: ExternalAccess) -> Option<String> {
    Some(match access.validated().ok()? {
        ExternalAccess::Automatic => "auto".into(),
        ExternalAccess::RouterForward { external_port } => format!("forward {external_port}"),
        ExternalAccess::Fixed { address } => format!("fixed {address}"),
    })
}

/// The elevated CLI line after the verb, e.g. `external forward 7443`.
pub(crate) fn cli_argument(access: ExternalAccess) -> Option<String> {
    words(access).map(|words| format!("external {words}"))
}

/// Parses the two CLI tokens after `external`. The same rules as the service:
/// port 1..=65535, and for `fixed` a global unicast numeric address.
pub(crate) fn from_cli(mode: &str, value: Option<&str>) -> Option<ExternalAccess> {
    let access = match (mode, value) {
        ("auto", None) => ExternalAccess::Automatic,
        ("forward", Some(port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
            ExternalAccess::RouterForward {
                external_port: port.parse().ok()?,
            }
        }
        ("fixed", Some(address)) => ExternalAccess::Fixed {
            address: address.parse::<SocketAddr>().ok()?,
        },
        _ => return None,
    };
    access.validated().ok()
}

/// The exact bytes the writer stores. `None` for an invalid choice.
pub(crate) fn encode(access: ExternalAccess) -> Option<Vec<u8>> {
    let bytes = format!("{VERSION} {}\n", words(access)?).into_bytes();
    (bytes.len() as u64 <= MAX_STORED_BYTES).then_some(bytes)
}

/// Accepts exactly the canonical line `encode` produces and nothing else:
/// no other version, whitespace, second line, trailing byte or spelling.
pub(crate) fn decode(bytes: &[u8]) -> Option<ExternalAccess> {
    if bytes.len() as u64 > MAX_STORED_BYTES {
        return None;
    }
    let line = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    if !line.is_ascii() || line.contains(['\n', '\r', '\t']) {
        return None;
    }
    let mut tokens = line.split(' ');
    if tokens.next()? != VERSION {
        return None;
    }
    let mode = tokens.next()?;
    let value = tokens.next();
    if tokens.next().is_some() {
        return None;
    }
    let access = from_cli(mode, value)?;
    (encode(access)?.as_slice() == bytes).then_some(access)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(text: &str) -> ExternalAccess {
        ExternalAccess::Fixed {
            address: text.parse().unwrap(),
        }
    }

    #[test]
    fn every_mode_round_trips_through_one_canonical_line() {
        for (access, line) in [
            (ExternalAccess::Automatic, "v1 auto\n"),
            (
                ExternalAccess::RouterForward {
                    external_port: 7443,
                },
                "v1 forward 7443\n",
            ),
            (
                ExternalAccess::RouterForward {
                    external_port: 65535,
                },
                "v1 forward 65535\n",
            ),
            (fixed("93.184.216.34:7443"), "v1 fixed 93.184.216.34:7443\n"),
            (
                fixed("[2606:4700::1111]:443"),
                "v1 fixed [2606:4700::1111]:443\n",
            ),
        ] {
            assert_eq!(encode(access).unwrap(), line.as_bytes());
            assert_eq!(decode(line.as_bytes()), Some(access));
            assert_eq!(
                StoredExternalAccess::from_stored(Some(line.as_bytes())),
                StoredExternalAccess::Valid(access)
            );
        }
        let longest = fixed("[2606:4700:ffff:ffff:ffff:ffff:ffff:ffff]:65535");
        let bytes = encode(longest).unwrap();
        assert!(bytes.len() as u64 <= MAX_STORED_BYTES);
        assert_eq!(decode(&bytes), Some(longest));
    }

    #[test]
    fn unknown_noncanonical_trailing_and_unusable_content_is_invalid() {
        for bad in [
            &b""[..],
            b"\n",
            b"v1 auto",
            b"v1 auto\r\n",
            b"v1 auto\n\n",
            b"v1 auto\nx",
            b" v1 auto\n",
            b"v1  auto\n",
            b"v1 auto \n",
            b"v2 auto\n",
            b"V1 auto\n",
            b"v1 automatic\n",
            b"v1 auto 7443\n",
            b"v1 forward\n",
            b"v1 forward 0\n",
            b"v1 forward 07443\n",
            b"v1 forward +7443\n",
            b"v1 forward 65536\n",
            b"v1 forward 7443 7443\n",
            b"v1 fixed\n",
            b"v1 fixed 93.184.216.34\n",
            b"v1 fixed 93.184.216.34:0\n",
            b"v1 fixed 192.168.1.20:7443\n",
            b"v1 fixed 203.0.113.7:7443\n",
            b"v1 fixed 100.64.0.1:7443\n",
            b"v1 fixed [2001:db8::1]:7443\n",
            b"v1 fixed [fe80::1]:7443\n",
            b"v1 fixed [::ffff:93.184.216.34]:7443\n",
            b"v1 fixed [2606:4700:0::1111]:443\n",
            b"v1 fixed example.com:7443\n",
            b"v1 fixed\t93.184.216.34:7443\n",
            b"v1 fixed 93.184.216.34:7443\x00\n",
            b"\xff\xfe\n",
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
            assert_eq!(
                StoredExternalAccess::from_stored(Some(bad)),
                StoredExternalAccess::Invalid
            );
        }
        let oversized = format!("v1 auto\n{}", " ".repeat(MAX_STORED_BYTES as usize));
        assert_eq!(decode(oversized.as_bytes()), None);
    }

    #[test]
    fn absence_and_invalid_content_both_run_the_default_mode() {
        assert_eq!(
            StoredExternalAccess::from_stored(None),
            StoredExternalAccess::Absent
        );
        assert_eq!(
            StoredExternalAccess::Absent.effective(),
            ExternalAccess::Automatic
        );
        assert_eq!(
            StoredExternalAccess::Invalid.effective(),
            ExternalAccess::Automatic
        );
        let forward = ExternalAccess::RouterForward {
            external_port: 8443,
        };
        assert_eq!(StoredExternalAccess::Valid(forward).effective(), forward);
        assert!(
            !format!(
                "{:?}",
                StoredExternalAccess::Valid(fixed("93.184.216.34:7443"))
            )
            .contains("93.184")
        );
    }

    #[test]
    fn cli_words_accept_only_the_three_shapes_and_validate_like_the_service() {
        assert_eq!(from_cli("auto", None), Some(ExternalAccess::Automatic));
        assert_eq!(
            from_cli("forward", Some("7443")),
            Some(ExternalAccess::RouterForward {
                external_port: 7443
            })
        );
        assert_eq!(
            from_cli("fixed", Some("93.184.216.34:7443")),
            Some(fixed("93.184.216.34:7443"))
        );
        for (mode, value) in [
            ("auto", Some("7443")),
            ("automatic", None),
            ("forward", None),
            ("forward", Some("0")),
            ("forward", Some("-1")),
            ("forward", Some("+7443")),
            ("forward", Some("65536")),
            ("forward", Some("")),
            ("fixed", None),
            ("fixed", Some("10.0.0.2:7443")),
            ("fixed", Some("93.184.216.34:0")),
            ("fixed", Some("[2606:4700::1111%3]:443")),
            ("fixed", Some("host.example:443")),
            ("dmz", None),
        ] {
            assert_eq!(from_cli(mode, value), None, "{mode} {value:?}");
        }
        assert_eq!(
            cli_argument(ExternalAccess::RouterForward {
                external_port: 7443
            })
            .unwrap(),
            "external forward 7443"
        );
        assert_eq!(
            cli_argument(ExternalAccess::RouterForward { external_port: 0 }),
            None
        );
        assert_eq!(cli_argument(fixed("10.0.0.2:7443")), None);
    }
}
