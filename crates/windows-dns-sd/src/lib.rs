// SPDX-License-Identifier: GPL-2.0-or-later
//! Local routing hints only. DNS-SD never authenticates a PC or authorizes a peer.
#![deny(unsafe_code)]

use std::{fmt, net::Ipv4Addr};

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;

/// One registered DNS-SD service instance. Dropping it deregisters (best effort).
pub struct ServiceAnnouncement {
    #[cfg(windows)]
    inner: ffi::Announcement,
}

impl fmt::Debug for ServiceAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAnnouncement")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnouncementState {
    Pending,
    Registered,
    Failed(u32),
}

#[derive(Debug, thiserror::Error)]
pub enum AnnounceError {
    #[error("invalid DNS-SD name")]
    InvalidName,
    #[error("DNS-SD announcement is unavailable on this platform")]
    Unsupported,
    #[error("DNS-SD announcement failed ({0})")]
    Failed(u32),
}

impl ServiceAnnouncement {
    /// `instance` is a single ASCII DNS label; `service_type` is `_x._tcp`.
    /// The SRV target is the computer's DNS hostname plus `.local`, the name
    /// Windows already announces. Instance/service labels remain ASCII; the
    /// existing Windows hostname may contain non-ASCII characters.
    pub fn start(
        instance: &str,
        service_type: &str,
        ipv4: Ipv4Addr,
        port: u16,
        interface_index: u32,
    ) -> Result<Self, AnnounceError> {
        let names = Names::new(instance, service_type)?;
        #[cfg(windows)]
        {
            ffi::Announcement::start(&names, ipv4, port, interface_index)
                .map(|inner| Self { inner })
        }
        #[cfg(not(windows))]
        {
            let _ = (names, ipv4, port, interface_index);
            Err(AnnounceError::Unsupported)
        }
    }

    pub fn state(&self) -> AnnouncementState {
        #[cfg(windows)]
        {
            self.inner.state()
        }
        #[cfg(not(windows))]
        {
            // No non-Windows constructor can succeed.
            AnnouncementState::Failed(50)
        }
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
struct Names {
    instance: String,
}

impl Names {
    fn new(instance: &str, service_type: &str) -> Result<Self, AnnounceError> {
        let Some(service) = service_type.strip_suffix("._tcp") else {
            return Err(AnnounceError::InvalidName);
        };
        let Some(label) = service.strip_prefix('_') else {
            return Err(AnnounceError::InvalidName);
        };
        if !valid_label(instance) || service.len() > 63 || !valid_label(label) {
            return Err(AnnounceError::InvalidName);
        }
        Ok(Self {
            instance: format!("{instance}.{service_type}.local"),
        })
    }
}

fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label.as_bytes()[0].is_ascii_alphanumeric()
        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_use_only_the_supplied_label() {
        let names = Names::new("uacremote-0123456789abcdef0123", "_uacremote._tcp").unwrap();
        assert_eq!(
            names.instance,
            "uacremote-0123456789abcdef0123._uacremote._tcp.local"
        );
    }

    #[test]
    fn labels_are_ascii_bounded_and_cannot_inject_names() {
        for label in [
            "",
            "a.b",
            "한글",
            "a\0b",
            "a b",
            "-a",
            "a-",
            "a_b",
            &"a".repeat(64),
        ] {
            assert!(matches!(
                Names::new(label, "_uacremote._tcp"),
                Err(AnnounceError::InvalidName)
            ));
        }
        assert!(Names::new(&"a".repeat(63), "_uacremote._tcp").is_ok());
        assert!(Names::new("A-0", "_x._tcp").is_ok());
    }

    #[test]
    fn service_is_exactly_two_labels_with_tcp_transport() {
        for service in [
            "",
            "uacremote._tcp",
            "_._tcp",
            "_x._udp",
            "_x._tcp.local",
            "_x.y._tcp",
            "_한글._tcp",
            "_x\0._tcp",
            &format!("_{}._tcp", "a".repeat(63)),
        ] {
            assert!(matches!(
                Names::new("pc", service),
                Err(AnnounceError::InvalidName)
            ));
        }
        assert!(Names::new("pc", &format!("_{}._tcp", "a".repeat(62))).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn other_platforms_validate_then_report_unsupported() {
        assert!(matches!(
            ServiceAnnouncement::start("pc", "_x._tcp", Ipv4Addr::LOCALHOST, 7443, 0),
            Err(AnnounceError::Unsupported)
        ));
        assert!(matches!(
            ServiceAnnouncement::start("a.b", "_x._tcp", Ipv4Addr::LOCALHOST, 7443, 0),
            Err(AnnounceError::InvalidName)
        ));
    }
}
