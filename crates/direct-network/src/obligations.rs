// SPDX-License-Identifier: GPL-2.0-or-later
//! One owner for exact-path mapping obligations, including shutdown selection.
//! A displaced grant retains its actual expiry and cannot become a candidate
//! again. Only a matching restored route may attempt its bounded router cleanup.
use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::{
    CancellationToken, CandidateSource, DirectFailure, LEASE_SECONDS, Network, global, igd,
    lease::{Lease, ProductionRouter, RouterAdapter},
};

const MAX_OBLIGATIONS: usize = 4;

pub(super) struct MappingObligations {
    active: Option<(Network, Lease)>,
    displaced: Vec<(Network, Lease)>,
    failures: u32,
    next_probe: Instant,
    /// Why the latest mapping attempt produced no candidate; `None` after a
    /// usable grant or before any attempt.
    failure: Option<DirectFailure>,
}

impl MappingObligations {
    pub(super) fn new() -> Self {
        Self {
            active: None,
            displaced: Vec::new(),
            failures: 0,
            next_probe: Instant::now(),
            failure: None,
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
        let mut router = ProductionRouter;
        self.poll_with(network, stop, nonce, &mut router).await;
    }

    async fn poll_with<A: RouterAdapter>(
        &mut self,
        network: Option<&Network>,
        stop: &CancellationToken,
        nonce: [u8; 12],
        router: &mut A,
    ) {
        self.select_path(network, router.now());
        let Some(network) = network else {
            return;
        };
        if let Some((_, mapping)) = self.active.as_mut() {
            let now = router.now();
            if mapping.is_candidate_at(now)
                && mapping.remaining_at(now) <= LEASE_SECONDS / 2
                && router.renew(mapping, network, stop).await.is_err()
            {
                // An uncertain renewal never erases the cleanup obligation.
                mapping.require_cleanup();
            }
        }
        if self.can_map(stop, router.now()) {
            let mapped = router.map(network, stop, nonce).await;
            self.mapping_finished(network, mapped, router.now());
        }
        if let Some((_, mapping)) = self.active.as_mut()
            && !mapping.is_candidate_at(router.now())
        {
            let confirmed = router.cleanup(mapping, network).await;
            self.cleanup_finished(confirmed, router.now());
        }
    }

    pub(super) fn mapping_finished(
        &mut self,
        network: &Network,
        mapped: io::Result<Lease>,
        now: Instant,
    ) {
        match mapped {
            Ok(mapping) => {
                // A grant outside candidate policy is still owned for cleanup;
                // a non-global external address means another NAT sits above.
                self.failure = if mapping.is_candidate_at(now) {
                    None
                } else if global(mapping.external().ip()) {
                    Some(DirectFailure::NoMappingProtocol)
                } else {
                    Some(DirectFailure::PrivateExternalAddress)
                };
                self.active = Some((network.clone(), mapping));
                self.failures = 0;
            }
            Err(error) => {
                if error.kind() != io::ErrorKind::Interrupted {
                    self.failure = Some(if igd::private_external(&error) {
                        DirectFailure::PrivateExternalAddress
                    } else {
                        DirectFailure::NoMappingProtocol
                    });
                }
                self.failures = self.failures.saturating_add(1);
                self.next_probe =
                    now + Duration::from_secs(30_u64 << self.failures.saturating_sub(1).min(2));
            }
        }
    }

    pub(super) fn candidate(&self) -> Option<(SocketAddr, u32, CandidateSource)> {
        self.active
            .as_ref()
            .filter(|(_, lease)| lease.is_candidate())
            .map(|(_, lease)| (lease.external(), lease.remaining(), lease.source()))
    }

    /// Meaningful only while `candidate()` is `None`.
    pub(super) fn failure(&self) -> Option<DirectFailure> {
        self.failure
    }

    fn take_final(&mut self, network: Option<&Network>, now: Instant) -> Option<(Network, Lease)> {
        self.select_path(network, now);
        self.active.take()
    }

    pub(super) async fn shutdown(self, network: Option<&Network>) {
        let mut router = ProductionRouter;
        self.shutdown_with(network, &mut router).await;
    }

    async fn shutdown_with<A: RouterAdapter>(mut self, network: Option<&Network>, router: &mut A) {
        if let Some((network, lease)) = self.take_final(network, router.now()) {
            // Exactly one bounded attempt, including a restored displaced
            // path. Silence does not establish that the router deleted it.
            router.release(lease, &network).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::pcp;

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
    fn mapping_outcome_records_why_no_candidate_is_published() {
        let now = Instant::now();
        let path = network(1);
        let mut owner = MappingObligations::new();
        assert_eq!(owner.failure(), None);
        owner.mapping_finished(&path, Err(io::Error::from(io::ErrorKind::TimedOut)), now);
        assert_eq!(owner.failure(), Some(DirectFailure::NoMappingProtocol));
        assert!(!owner.can_map(&CancellationToken::new(), now + Duration::from_secs(29)));
        owner.mapping_finished(&path, Err(igd::private_external_error()), now);
        assert_eq!(owner.failure(), Some(DirectFailure::PrivateExternalAddress));
        // Cancellation says nothing about the router.
        owner.mapping_finished(&path, Err(io::Error::from(io::ErrorKind::Interrupted)), now);
        assert_eq!(owner.failure(), Some(DirectFailure::PrivateExternalAddress));

        let mut behind_nat = pcp::Lease::ownership_fixture(now + Duration::from_secs(600));
        behind_nat.external = "100.64.0.9:45000".parse().unwrap();
        behind_nat.require_cleanup();
        owner.mapping_finished(&path, Ok(Lease::Pcp(behind_nat)), now);
        assert!(owner.candidate().is_none());
        assert_eq!(owner.failure(), Some(DirectFailure::PrivateExternalAddress));

        let mut owner = MappingObligations::new();
        let mut long_grant = pcp::Lease::ownership_fixture(now + Duration::from_secs(7200));
        long_grant.require_cleanup();
        owner.mapping_finished(&path, Ok(Lease::Pcp(long_grant)), now);
        assert_eq!(owner.failure(), Some(DirectFailure::NoMappingProtocol));

        let mut owner = MappingObligations::new();
        owner.mapping_finished(&path, Err(io::Error::from(io::ErrorKind::TimedOut)), now);
        owner.mapping_finished(&path, Ok(lease(now + Duration::from_secs(600))), now);
        assert_eq!(owner.failure(), None);
        let (endpoint, _, source) = owner.candidate().unwrap();
        assert_eq!(endpoint, "8.8.8.8:45000".parse().unwrap());
        assert_eq!(source, CandidateSource::Pcp);
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

    #[derive(Debug, Eq, PartialEq)]
    enum RouterCall {
        Map(Instant),
        Renew(Instant),
        Cleanup(Instant),
        Release(Instant),
    }

    struct FakeRouter {
        now: Instant,
        grant: bool,
        calls: Vec<RouterCall>,
    }

    impl FakeRouter {
        fn new(now: Instant, grant: bool) -> Self {
            Self {
                now,
                grant,
                calls: Vec::new(),
            }
        }
    }

    impl crate::lease::RouterAdapter for FakeRouter {
        fn now(&self) -> Instant {
            self.now
        }

        async fn map(
            &mut self,
            _network: &Network,
            _stop: &CancellationToken,
            _nonce: [u8; 12],
        ) -> io::Result<Lease> {
            self.calls.push(RouterCall::Map(self.now));
            if self.grant {
                Ok(lease(self.now + Duration::from_secs(LEASE_SECONDS.into())))
            } else {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
        }

        async fn renew(
            &mut self,
            lease: &mut Lease,
            _network: &Network,
            _stop: &CancellationToken,
        ) -> io::Result<()> {
            self.calls.push(RouterCall::Renew(self.now));
            if let Lease::Pcp(lease) = lease {
                lease.expires = self.now + Duration::from_secs(LEASE_SECONDS.into());
            }
            Ok(())
        }

        async fn cleanup(&mut self, _lease: &mut Lease, _network: &Network) -> bool {
            self.calls.push(RouterCall::Cleanup(self.now));
            true
        }

        async fn release(&mut self, _lease: Lease, _network: &Network) {
            self.calls.push(RouterCall::Release(self.now));
        }
    }

    #[tokio::test]
    async fn poll_renews_an_obtained_mapping_before_expiry() {
        let mapped_at = Instant::now();
        let expires = mapped_at + Duration::from_secs(LEASE_SECONDS.into());
        let path = network(1);
        let stop = CancellationToken::new();
        let mut router = FakeRouter::new(mapped_at, true);
        let mut owner = MappingObligations::new();
        owner.next_probe = mapped_at;

        owner
            .poll_with(Some(&path), &stop, [1; 12], &mut router)
            .await;
        router.now = expires - Duration::from_secs(u64::from(LEASE_SECONDS / 2));
        owner
            .poll_with(Some(&path), &stop, [1; 12], &mut router)
            .await;

        assert_eq!(
            router.calls,
            [RouterCall::Map(mapped_at), RouterCall::Renew(router.now)]
        );
        assert!(router.now < expires);
    }

    #[tokio::test]
    async fn shutdown_releases_an_obtained_mapping() {
        let now = Instant::now();
        let path = network(1);
        let stop = CancellationToken::new();
        let mut router = FakeRouter::new(now, true);
        let mut owner = MappingObligations::new();
        owner.next_probe = now;

        owner
            .poll_with(Some(&path), &stop, [2; 12], &mut router)
            .await;
        owner.shutdown_with(Some(&path), &mut router).await;

        assert_eq!(
            router.calls,
            [RouterCall::Map(now), RouterCall::Release(now)]
        );
    }

    #[tokio::test]
    async fn shutdown_does_not_release_a_mapping_that_was_never_obtained() {
        let now = Instant::now();
        let path = network(1);
        let stop = CancellationToken::new();
        let mut router = FakeRouter::new(now, false);
        let mut owner = MappingObligations::new();
        owner.next_probe = now;

        owner
            .poll_with(Some(&path), &stop, [3; 12], &mut router)
            .await;
        owner.shutdown_with(Some(&path), &mut router).await;

        assert_eq!(router.calls, [RouterCall::Map(now)]);
    }
}
