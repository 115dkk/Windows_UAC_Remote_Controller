// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded DNS-SD routing hints for paired PCs. A hint grants no authority and
//! proves no reachability; all hints are memory-only and cleared on network change.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

/// Maximum number of DNS-SD instances retained for the current network.
pub(crate) const LAN_HINT_ENTRY_CAPACITY: usize = 8;
/// Maximum number of ordered addresses retained for one DNS-SD instance.
pub(crate) const LAN_HINT_ADDRESS_CAPACITY: usize = 2;
/// Maximum number of address strings accepted from one native observation.
pub(crate) const LAN_HINT_OBSERVATION_CAPACITY: usize = 8;
/// Maximum age of a DNS-SD observation before it is ignored and removed.
/// Android reports an instance again only when it changes, so a PC that keeps
/// its address is not re-reported; the network change that clears every hint
/// is what normally ends one.
pub(crate) const LAN_HINT_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Default)]
pub(crate) struct LanHints {
    entries: BTreeMap<String, LanHint>,
}

struct LanHint {
    addresses: Vec<SocketAddr>,
    seen_at: Instant,
}

impl LanHints {
    /// Records one shape-checked instance. The result says whether its retained
    /// ordered address list was added, changed or removed.
    pub(crate) fn record(
        &mut self,
        label: &str,
        addresses: impl IntoIterator<Item = SocketAddr>,
        now: Instant,
    ) -> bool {
        if !service_protocol::is_lan_instance_label(label) {
            return false;
        }
        self.prune(now);

        let mut accepted = Vec::with_capacity(LAN_HINT_ADDRESS_CAPACITY);
        for address in addresses {
            if lan_address(address) && !accepted.contains(&address) {
                accepted.push(address);
                if accepted.len() == LAN_HINT_ADDRESS_CAPACITY {
                    break;
                }
            }
        }
        if accepted.is_empty() {
            return self.entries.remove(label).is_some();
        }

        if let Some(existing) = self.entries.get_mut(label) {
            let changed = existing.addresses != accepted;
            existing.addresses = accepted;
            existing.seen_at = now;
            return changed;
        }
        if self.entries.len() == LAN_HINT_ENTRY_CAPACITY {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, hint)| hint.seen_at)
                .map(|(oldest, _)| oldest.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            label.to_owned(),
            LanHint {
                addresses: accepted,
                seen_at: now,
            },
        );
        true
    }

    pub(crate) fn forget(&mut self, label: &str) {
        self.entries.remove(label);
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(crate) fn addresses_for(&mut self, label: &str, now: Instant) -> Vec<SocketAddr> {
        self.prune(now);
        self.entries
            .get(label)
            .map(|hint| hint.addresses.clone())
            .unwrap_or_default()
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, hint| {
            !now.checked_duration_since(hint.seen_at)
                .is_some_and(|age| age >= LAN_HINT_TTL)
        });
    }
}

fn lan_address(address: SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(address) => private_v4(address),
            IpAddr::V6(address) => ula_v6(address),
        }
}

fn private_v4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    first == 10 || (first == 172 && (16..=31).contains(&second)) || (first == 192 && second == 168)
}

fn ula_v6(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;
    use approval_protocol::PcIdentity;

    fn label(seed: u8) -> String {
        service_protocol::lan_instance_label(&PcIdentity::from_bytes([seed; 32]).unwrap())
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn address_filter_accepts_only_rfc1918_and_ula_with_a_port() {
        let now = Instant::now();
        let mut hints = LanHints::default();
        let instance = label(1);
        for accepted in [
            "10.0.0.1:1",
            "172.16.0.1:7443",
            "172.31.255.254:65535",
            "192.168.1.2:7443",
            "[fc00::1]:7443",
            "[fdff:ffff::1]:7443",
        ] {
            assert!(
                hints.record(&instance, [address(accepted)], now),
                "{accepted}"
            );
            assert_eq!(hints.addresses_for(&instance, now), [address(accepted)]);
        }

        for rejected in [
            "8.8.8.8:7443",                // public IPv4
            "172.15.255.255:7443",         // outside RFC 1918
            "172.32.0.0:7443",             // outside RFC 1918
            "127.0.0.1:7443",              // loopback IPv4
            "169.254.1.1:7443",            // link-local IPv4
            "0.0.0.0:7443",                // unspecified IPv4
            "224.0.0.1:7443",              // multicast IPv4
            "100.64.0.1:7443",             // shared address space
            "192.0.2.1:7443",              // documentation IPv4
            "[2606:4700:4700::1111]:7443", // public IPv6
            "[::1]:7443",                  // loopback IPv6
            "[fe80::1]:7443",              // link-local IPv6
            "[::]:7443",                   // unspecified IPv6
            "[ff02::1]:7443",              // multicast IPv6
            "[2001:db8::1]:7443",          // documentation IPv6
            "[::ffff:192.168.1.2]:7443",   // IPv4-mapped IPv6
            "192.168.1.2:0",               // zero port
        ] {
            assert!(hints.record(&instance, [address("10.0.0.1:7443")], now));
            assert!(
                hints.record(&instance, [address(rejected)], now),
                "{rejected}"
            );
            assert!(hints.addresses_for(&instance, now).is_empty(), "{rejected}");
        }
    }

    #[test]
    fn each_entry_deduplicates_in_order_and_keeps_two_addresses() {
        let now = Instant::now();
        let mut hints = LanHints::default();
        let first = address("192.168.1.1:7443");
        let second = address("10.0.0.2:7443");
        let third = address("172.16.0.3:7443");
        let instance = label(2);
        assert!(hints.record(
            &instance,
            [address("8.8.8.8:7443"), first, first, second, third],
            now,
        ));
        assert_eq!(hints.addresses_for(&instance, now), [first, second]);
    }

    #[test]
    fn ninth_entry_evicts_the_oldest_observation() {
        let start = Instant::now();
        let mut hints = LanHints::default();
        let retained = address("192.168.1.1:7443");
        for seed in 1..=LAN_HINT_ENTRY_CAPACITY as u8 {
            assert!(hints.record(
                &label(seed),
                [retained],
                start + Duration::from_secs(u64::from(seed)),
            ));
        }
        assert!(hints.record(&label(9), [retained], start + Duration::from_secs(9),));
        assert!(hints.addresses_for(&label(1), start).is_empty());
        for seed in 2..=LAN_HINT_ENTRY_CAPACITY as u8 {
            assert_eq!(hints.addresses_for(&label(seed), start), [retained]);
        }
        assert_eq!(hints.addresses_for(&label(9), start), [retained]);
    }

    #[test]
    fn expired_entries_are_ignored_and_pruned() {
        let start = Instant::now();
        let mut hints = LanHints::default();
        let instance = label(3);
        let retained = address("192.168.1.3:7443");
        assert!(hints.record(&instance, [retained], start));
        assert_eq!(
            hints.addresses_for(&instance, start + LAN_HINT_TTL - Duration::from_nanos(1)),
            [retained]
        );
        assert!(
            hints
                .addresses_for(&instance, start + LAN_HINT_TTL)
                .is_empty()
        );
        assert!(hints.entries.is_empty());
    }

    #[test]
    fn empty_accepted_list_removes_an_existing_entry() {
        let now = Instant::now();
        let mut hints = LanHints::default();
        let instance = label(4);
        assert!(hints.record(&instance, [address("10.0.0.4:7443")], now));
        assert!(hints.record(&instance, std::iter::empty(), now));
        assert!(!hints.record(&instance, [address("8.8.8.8:7443")], now));
        assert!(hints.addresses_for(&instance, now).is_empty());
    }

    #[test]
    fn record_reports_new_changed_and_unchanged_lists() {
        let start = Instant::now();
        let mut hints = LanHints::default();
        let instance = label(5);
        let first = address("10.0.0.5:7443");
        let second = address("10.0.0.6:7443");
        assert!(hints.record(&instance, [first], start));
        assert!(!hints.record(&instance, [first], start + Duration::from_secs(1)));
        assert!(hints.record(&instance, [first, second], start + Duration::from_secs(2)));
        assert!(hints.record(&instance, [second, first], start + Duration::from_secs(3)));
    }

    #[test]
    fn clear_forgets_every_entry() {
        let now = Instant::now();
        let mut hints = LanHints::default();
        let retained = address("10.0.0.7:7443");
        for seed in [6, 7] {
            assert!(hints.record(&label(seed), [retained], now));
        }
        hints.clear();
        assert!(hints.entries.is_empty());
        assert!(hints.addresses_for(&label(6), now).is_empty());
    }

    #[test]
    fn malformed_instance_labels_are_never_stored() {
        let now = Instant::now();
        let mut hints = LanHints::default();
        let retained = address("10.0.0.8:7443");
        for malformed in [
            "",
            "uacremote-",
            "uacremote-0123456789abcdef012g",
            "UACREMOTE-0123456789abcdef0123",
        ] {
            assert!(!hints.record(malformed, [retained], now));
            assert!(hints.addresses_for(malformed, now).is_empty());
        }
        assert!(hints.entries.is_empty());
    }
}
