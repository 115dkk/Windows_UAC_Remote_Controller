// SPDX-License-Identifier: GPL-2.0-or-later
//! The administrator's choice of how this PC learns an external relay address.
//! One fixed, versioned, canonical line on disk and one fixed CLI shape. It is
//! a routing preference, never authority, consent or proof of reachability.
#![forbid(unsafe_code)]
// The trust-store reader and the service session only exist on 64-bit
// Windows; other targets compile this module for its shared format and tests.
#![cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]

use std::net::{Ipv4Addr, SocketAddr};

use direct_network::ExternalAccess;

/// Bound for the stored line. The longest canonical value is
/// `v1 fixed [xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:65535\n` (57 bytes);
/// the longest forward-origin value is
/// `v1 forward 65535 255.255.255.254\n` (33 bytes).
pub(crate) const MAX_STORED_BYTES: u64 = 64;
const VERSION: &str = "v1";

/// The configured mode and the LAN address recorded when router forwarding was
/// saved. The address is diagnostic configuration, never a routing authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ExternalAccessSetting {
    pub(crate) access: ExternalAccess,
    pub(crate) forward_origin: Option<Ipv4Addr>,
}

impl std::fmt::Debug for ExternalAccessSetting {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExternalAccessSetting(redacted)")
    }
}

/// What the service found in its protected configuration at startup.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StoredExternalAccess {
    /// No file: the default, `Automatic`.
    Absent,
    Valid(ExternalAccessSetting),
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

    /// The complete setting the service runs with. Invalid content means the
    /// default mode and no remembered forward origin.
    pub(crate) fn effective_setting(self) -> ExternalAccessSetting {
        match self {
            Self::Valid(setting) => setting,
            Self::Absent | Self::Invalid => ExternalAccessSetting {
                access: ExternalAccess::Automatic,
                forward_origin: None,
            },
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

pub(crate) fn usable_forward_origin(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && !address.is_broadcast()
}

/// The exact bytes the writer stores. `None` for an invalid choice or for an
/// origin attached to anything except router-forward mode.
pub(crate) fn encode(setting: ExternalAccessSetting) -> Option<Vec<u8>> {
    let words = words(setting.access)?;
    let origin = match (setting.access, setting.forward_origin) {
        (ExternalAccess::RouterForward { .. }, Some(origin)) if usable_forward_origin(origin) => {
            format!(" {origin}")
        }
        (ExternalAccess::RouterForward { .. }, None)
        | (ExternalAccess::Automatic | ExternalAccess::Fixed { .. }, None) => String::new(),
        _ => return None,
    };
    let bytes = format!("{VERSION} {words}{origin}\n").into_bytes();
    (bytes.len() as u64 <= MAX_STORED_BYTES).then_some(bytes)
}

/// Accepts exactly the canonical line `encode` produces and nothing else:
/// no other version, whitespace, second line, trailing byte or spelling.
pub(crate) fn decode(bytes: &[u8]) -> Option<ExternalAccessSetting> {
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
    let origin = tokens.next();
    if tokens.next().is_some() {
        return None;
    }
    let access = from_cli(mode, value)?;
    let forward_origin = match (access, origin) {
        (ExternalAccess::RouterForward { .. }, Some(text)) => {
            let address = text.parse::<Ipv4Addr>().ok()?;
            if !usable_forward_origin(address) || address.to_string() != text {
                return None;
            }
            Some(address)
        }
        (ExternalAccess::RouterForward { .. }, None)
        | (ExternalAccess::Automatic | ExternalAccess::Fixed { .. }, None) => None,
        _ => return None,
    };
    let setting = ExternalAccessSetting {
        access,
        forward_origin,
    };
    (encode(setting)?.as_slice() == bytes).then_some(setting)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(text: &str) -> ExternalAccess {
        ExternalAccess::Fixed {
            address: text.parse().unwrap(),
        }
    }

    fn setting(access: ExternalAccess, forward_origin: Option<&str>) -> ExternalAccessSetting {
        ExternalAccessSetting {
            access,
            forward_origin: forward_origin.map(|text| text.parse().unwrap()),
        }
    }

    #[test]
    fn every_mode_and_optional_forward_origin_round_trip_canonically() {
        for (setting, line) in [
            (setting(ExternalAccess::Automatic, None), "v1 auto\n"),
            (
                setting(
                    ExternalAccess::RouterForward {
                        external_port: 7443,
                    },
                    None,
                ),
                "v1 forward 7443\n",
            ),
            (
                setting(
                    ExternalAccess::RouterForward {
                        external_port: 7443,
                    },
                    Some("192.168.219.102"),
                ),
                "v1 forward 7443 192.168.219.102\n",
            ),
            (
                setting(
                    ExternalAccess::RouterForward {
                        external_port: 65535,
                    },
                    Some("255.255.255.254"),
                ),
                "v1 forward 65535 255.255.255.254\n",
            ),
            (
                setting(fixed("93.184.216.34:7443"), None),
                "v1 fixed 93.184.216.34:7443\n",
            ),
            (
                setting(fixed("[2606:4700::1111]:443"), None),
                "v1 fixed [2606:4700::1111]:443\n",
            ),
        ] {
            assert_eq!(encode(setting).unwrap(), line.as_bytes());
            assert_eq!(decode(line.as_bytes()), Some(setting));
            assert_eq!(
                StoredExternalAccess::from_stored(Some(line.as_bytes())),
                StoredExternalAccess::Valid(setting)
            );
        }
        let longest = setting(
            fixed("[2606:4700:ffff:ffff:ffff:ffff:ffff:ffff]:65535"),
            None,
        );
        let bytes = encode(longest).unwrap();
        assert!(bytes.len() as u64 <= MAX_STORED_BYTES);
        assert_eq!(decode(&bytes), Some(longest));
        assert_eq!(
            encode(setting(
                ExternalAccess::RouterForward {
                    external_port: 65535
                },
                Some("255.255.255.254")
            ))
            .unwrap()
            .len(),
            33
        );
    }

    #[test]
    fn old_forward_line_still_decodes_without_an_origin() {
        assert_eq!(
            decode(b"v1 forward 7443\n"),
            Some(setting(
                ExternalAccess::RouterForward {
                    external_port: 7443
                },
                None
            ))
        );
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
            b"v1 auto 192.168.1.2\n",
            b"v1 forward\n",
            b"v1 forward 0\n",
            b"v1 forward 07443\n",
            b"v1 forward +7443\n",
            b"v1 forward 65536\n",
            b"v1 forward 7443 0.0.0.0\n",
            b"v1 forward 7443 127.0.0.1\n",
            b"v1 forward 7443 169.254.1.1\n",
            b"v1 forward 7443 224.0.0.1\n",
            b"v1 forward 7443 255.255.255.255\n",
            b"v1 forward 7443 192.168.001.2\n",
            b"v1 forward 7443 2001:db8::1\n",
            b"v1 forward 7443 192.168.1.2 extra\n",
            b"v1 forward  7443\n",
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
            b"v1 fixed 93.184.216.34:7443 192.168.1.2\n",
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
    fn encode_rejects_origins_outside_forward_mode_and_unusable_addresses() {
        assert!(encode(setting(ExternalAccess::Automatic, Some("192.168.1.2"))).is_none());
        assert!(encode(setting(fixed("93.184.216.34:7443"), Some("192.168.1.2"))).is_none());
        for origin in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                encode(setting(
                    ExternalAccess::RouterForward {
                        external_port: 7443
                    },
                    Some(origin)
                ))
                .is_none(),
                "{origin}"
            );
        }
    }

    #[test]
    fn absence_and_invalid_content_both_run_the_default_mode() {
        let automatic = setting(ExternalAccess::Automatic, None);
        assert_eq!(
            StoredExternalAccess::from_stored(None),
            StoredExternalAccess::Absent
        );
        assert_eq!(StoredExternalAccess::Absent.effective_setting(), automatic);
        assert_eq!(StoredExternalAccess::Invalid.effective_setting(), automatic);
        let forward = setting(
            ExternalAccess::RouterForward {
                external_port: 8443,
            },
            Some("192.168.1.50"),
        );
        assert_eq!(
            StoredExternalAccess::Valid(forward).effective_setting(),
            forward
        );
        assert!(
            !format!(
                "{:?}",
                StoredExternalAccess::Valid(setting(fixed("93.184.216.34:7443"), None))
            )
            .contains("93.184")
        );
        assert!(!format!("{forward:?}").contains("192.168"));
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
