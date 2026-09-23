// SPDX-License-Identifier: GPL-2.0-or-later
//! One owner for exact-path mapping obligations, including shutdown selection.
//! A displaced grant retains its actual expiry and cannot become a candidate
//! again. Only a matching restored route may attempt its bounded router cleanup.
use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::{CancellationToken, LEASE_SECONDS, Network, igd, lease::Lease, pcp};

const MAX_OBLIGATIONS: usize = 4;

pub(super) struct MappingObligations {
    active: Option<(Network, Lease)>,
    displaced: Vec<(Network, Lease)>,
    failures: u32,
    next_probe: Instant,
}

impl MappingObligations {
    pub(super) fn new() -> Self {
        Self {
            active: None,
            displaced: Vec::new(),
            failures: 0,
            next_probe: Instant::now(),
        }
    }

    /// This same transition serves ordinary polling and final cleanup. No
    /// router I/O is possible until the exact current path selects an owner.
    fn select_path(&mut self, network: Option<&Network>, now: Instant) {
        self.displaced.retain(|(_, lease)| lease.expires() > now);
        if self
            .active
            .as_ref()
            .is_some_and(|(old, _)| !network.is_some_and(|current| old.same_mapping_path(current)))
        {
            if let Some((old, mut lease)) = self.active.take() {
                lease.require_cleanup();
                if lease.expires() > now {
                    self.displaced.push((old, lease));
                }
            }
            self.next_probe = now;
        }
        if self
            .active
            .as_ref()
            .is_some_and(|(_, lease)| lease.expires() <= now)
        {
            self.active = None;
        }
        if self.active.is_none()
            && let Some(index) = self
                .displaced
                .iter()
                .position(|(old, _)| network.is_some_and(|current| old.same_mapping_path(current)))
        {
            self.active = Some(self.displaced.swap_remove(index));
        }
    }

    fn can_map(&self, stop: &CancellationToken, now: Instant) -> bool {
        self.active.is_none()
            && self.displaced.len() < MAX_OBLIGATIONS
            && !stop.is_cancelled()
            && now >= self.next_probe
    }

    fn cleanup_finished(&mut self, confirmed: bool, now: Instant) {
        if confirmed {
            self.active = None;
            self.next_probe = now + Duration::from_secs(120);
        }
    }

    pub(super) async fn poll(
        &mut self,
        network: Option<&Network>,
        stop: &CancellationToken,
        nonce: [u8; 12],
    ) {
        self.select_path(network, Instant::now());
        let Some(network) = network else {
            return;
        };
        if let Some((_, mapping)) = self.active.as_mut()
            && mapping.is_candidate()
            && mapping.remaining() <= LEASE_SECONDS / 2
            && mapping.renew(network, stop).await.is_err()
        {
            // An uncertain renewal never erases the cleanup obligation.
            mapping.require_cleanup();
        }
        if self.can_map(stop, Instant::now()) {
            // PCP first; consumer routers that ignore it usually speak UPnP IGD.
            let mapped = match pcp::map(network, stop, nonce).await {
                Ok(lease) => Ok(Lease::Pcp(lease)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
                Err(_) => igd::map(network, stop).await.map(Lease::Igd),
            };
            if let Ok(mapping) = mapped {
                self.active = Some((network.clone(), mapping));
                self.failures = 0;
            } else {
                self.failures = self.failures.saturating_add(1);
                self.next_probe = Instant::now()
                    + Duration::from_secs(30_u64 << self.failures.saturating_sub(1).min(2));
            }
        }
        if let Some((_, mapping)) = self.active.as_mut()
            && !mapping.is_candidate()
        {
            let confirmed = mapping.cleanup(network).await;
            self.cleanup_finished(confirmed, Instant::now());
        }
    }

    pub(super) fn candidate(&self) -> Option<(SocketAddr, u32)> {
        self.active
            .as_ref()
            .filter(|(_, lease)| lease.is_candidate())
            .map(|(_, lease)| (lease.external(), lease.remaining()))
    }

    fn take_final(&mut self, network: Option<&Network>, now: Instant) -> Option<(Network, Lease)> {
        self.select_path(network, now);
        self.active.take()
    }

    pub(super) async fn shutdown(mut self, network: Option<&Network>) {
        if let Some((network, lease)) = self.take_final(network, Instant::now()) {
            // Exactly one bounded attempt, including a restored displaced
            // path. Silence does not establish that the router deleted it.
            lease.release(&network).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn network(gateway: u8) -> Network {
        Network {
            internal: "192.168.1.2:7443".parse().unwrap(),
            gateway: Ipv4Addr::new(192, 168, 1, gateway),
            ipv6: Vec::new(),
        }
    }

    fn lease(expires: Instant) -> Lease {
        Lease::Pcp(pcp::Lease::ownership_fixture(expires))
    }

    fn owner_on(network: &Network, expires: Instant) -> MappingObligations {
        let mut owner = MappingObligations::new();
        owner.active = Some((network.clone(), lease(expires)));
        owner
    }

    #[tokio::test]
    async fn poll_with_missing_or_cancelled_path_retains_only_existing_obligations() {
        let now = Instant::now();
        let original = network(1);
        let mut owner = owner_on(&original, now + Duration::from_secs(600));
        let stop = CancellationToken::new();
        owner.poll(None, &stop, [1; 12]).await;
        assert!(owner.candidate().is_none());
        assert_eq!(owner.displaced.len(), 1);
        stop.cancel();
        owner.poll(Some(&network(3)), &stop, [1; 12]).await;
        assert!(owner.active.is_none());
        assert_eq!(owner.displaced.len(), 1);
        assert!(owner.take_final(Some(&original), Instant::now()).is_some());
    }

    #[test]
    fn changed_path_withdraws_candidate_and_restoration_retains_cleanup_only() {
        let now = Instant::now();
        let original = network(1);
        let other = network(3);
        let mut owner = owner_on(&original, now + Duration::from_secs(7200));
        assert!(owner.candidate().is_some());
        owner.select_path(Some(&other), now);
        assert!(owner.candidate().is_none());
        assert_eq!(owner.displaced.len(), 1);
        owner.select_path(Some(&original), now);
        assert!(owner.active.is_some());
        assert!(owner.displaced.is_empty());
        assert!(owner.candidate().is_none());
        assert!(!owner.can_map(&CancellationToken::new(), now));
    }

    #[test]
    fn ipv6_rotation_preserves_mapping_but_local_tuple_change_displaces_it() {
        let now = Instant::now();
        let original = network(1);
        let mut owner = owner_on(&original, now + Duration::from_secs(600));
        let mut changed = original.clone();
        changed.ipv6.push("2606:4700:4700::1111".parse().unwrap());
        owner.select_path(Some(&changed), now);
        assert!(owner.candidate().is_some());
        changed.internal.set_port(7444);
        owner.select_path(Some(&changed), now);
        assert!(owner.candidate().is_none());
        assert_eq!(owner.displaced.len(), 1);
    }

    #[test]
    fn only_actual_granted_expiry_releases_displaced_capacity() {
        let now = Instant::now();
        let original = network(1);
        let mut owner = owner_on(&original, now + Duration::from_secs(7200));
        owner.select_path(None, now);
        owner.select_path(None, now + Duration::from_secs(601));
        assert_eq!(owner.displaced.len(), 1);
        owner.select_path(Some(&original), now + Duration::from_secs(7200));
        assert!(owner.active.is_none());
        assert!(owner.displaced.is_empty());
    }

    #[test]
    fn four_retained_obligations_stop_new_mapping_and_allow_exact_restoration() {
        let now = Instant::now();
        let stop = CancellationToken::new();
        let mut owner = MappingObligations::new();
        owner.next_probe = now;
        for gateway in 1..=4 {
            let path = network(gateway);
            owner.select_path(Some(&path), now);
            assert!(owner.can_map(&stop, now));
            owner.active = Some((path, lease(now + Duration::from_secs(600))));
        }
        owner.select_path(Some(&network(5)), now);
        assert_eq!(owner.displaced.len(), MAX_OBLIGATIONS);
        assert!(!owner.can_map(&stop, now));
        owner.select_path(Some(&network(1)), now);
        assert!(owner.active.is_some());
        assert_eq!(owner.displaced.len(), MAX_OBLIGATIONS - 1);
        assert!(!owner.can_map(&stop, now));
    }

    #[test]
    fn failed_cleanup_retains_obligation_and_confirmed_cleanup_delays_new_mapping() {
        let now = Instant::now();
        let path = network(1);
        let stop = CancellationToken::new();
        let mut owner = owner_on(&path, now + Duration::from_secs(600));
        owner.select_path(None, now);
        owner.select_path(Some(&path), now);
        owner.cleanup_finished(false, now);
        assert!(owner.active.is_some());
        assert!(owner.candidate().is_none());
        assert!(!owner.can_map(&stop, now));
        owner.cleanup_finished(true, now);
        assert!(owner.active.is_none());
        assert!(!owner.can_map(&stop, now + Duration::from_secs(119)));
        assert!(owner.can_map(&stop, now + Duration::from_secs(120)));
        stop.cancel();
        assert!(!owner.can_map(&stop, now + Duration::from_secs(121)));
    }

    #[test]
    fn shutdown_selects_only_one_owned_obligation_on_exact_restored_path() {
        let now = Instant::now();
        let original = network(1);
        let other = network(3);
        let mut owner = owner_on(&original, now + Duration::from_secs(600));
        owner.select_path(Some(&other), now);
        owner.active = Some((other.clone(), lease(now + Duration::from_secs(600))));
        let (selected, lease) = owner.take_final(Some(&original), now).unwrap();
        assert!(selected.same_mapping_path(&original));
        assert!(!lease.is_candidate());
        assert_eq!(owner.displaced.len(), 1);
        assert!(owner.displaced[0].0.same_mapping_path(&other));
        assert!(owner.take_final(Some(&original), now).is_none());
    }

    #[test]
    fn shutdown_without_exact_live_path_cannot_select_an_obligation() {
        let now = Instant::now();
        let path = network(1);
        for current in [None, Some(network(4))] {
            let mut owner = owner_on(&path, now + Duration::from_secs(600));
            assert!(owner.take_final(current.as_ref(), now).is_none());
        }
        let mut owner = owner_on(&path, now);
        assert!(owner.take_final(Some(&path), now).is_none());
    }
}
