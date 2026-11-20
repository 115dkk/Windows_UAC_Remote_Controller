// SPDX-License-Identifier: GPL-2.0-or-later
//! One owned router mapping as the obligation owner sees it. Each protocol
//! keeps its own ownership proof and cleanup rule behind this dispatch.
use std::{io, net::SocketAddr, time::Instant};

use super::{CancellationToken, CandidateSource, Network, igd, pcp};

pub(super) trait RouterAdapter {
    fn now(&self) -> Instant;

    async fn map(
        &mut self,
        network: &Network,
        stop: &CancellationToken,
        nonce: [u8; 12],
    ) -> io::Result<Lease>;

    async fn renew(
        &mut self,
        lease: &mut Lease,
        network: &Network,
        stop: &CancellationToken,
    ) -> io::Result<()>;

    async fn cleanup(&mut self, lease: &mut Lease, network: &Network) -> bool;

    async fn release(&mut self, lease: Lease, network: &Network);
}

pub(super) struct ProductionRouter;

impl RouterAdapter for ProductionRouter {
    fn now(&self) -> Instant {
        Instant::now()
    }

    async fn map(
        &mut self,
        network: &Network,
        stop: &CancellationToken,
        nonce: [u8; 12],
    ) -> io::Result<Lease> {
        // PCP first; consumer routers that ignore it usually speak UPnP IGD.
        match pcp::map(network, stop, nonce).await {
            Ok(lease) => Ok(Lease::Pcp(lease)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
            Err(_) => igd::map(network, stop).await.map(Lease::Igd),
        }
    }

    async fn renew(
        &mut self,
        lease: &mut Lease,
        network: &Network,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        lease.renew(network, stop).await
    }

    async fn cleanup(&mut self, lease: &mut Lease, network: &Network) -> bool {
        lease.cleanup(network).await
    }

    async fn release(&mut self, lease: Lease, network: &Network) {
        lease.release(network).await;
    }
}

pub(super) enum Lease {
    Pcp(pcp::Lease),
    Igd(igd::Lease),
}

impl Lease {
    pub(super) fn external(&self) -> SocketAddr {
        match self {
            Self::Pcp(lease) => lease.external,
            Self::Igd(lease) => lease.external,
        }
    }

    pub(super) fn source(&self) -> CandidateSource {
        match self {
            Self::Pcp(_) => CandidateSource::Pcp,
            Self::Igd(_) => CandidateSource::Upnp,
        }
    }

    pub(super) fn expires(&self) -> Instant {
        match self {
            Self::Pcp(lease) => lease.expires,
            Self::Igd(lease) => lease.expires,
        }
    }

    pub(super) fn is_candidate(&self) -> bool {
        self.is_candidate_at(Instant::now())
    }

    pub(super) fn is_candidate_at(&self, now: Instant) -> bool {
        match self {
            Self::Pcp(lease) => lease.is_candidate_at(now),
            Self::Igd(lease) => lease.is_candidate_at(now),
        }
    }

    pub(super) fn require_cleanup(&mut self) {
        match self {
            Self::Pcp(lease) => lease.require_cleanup(),
            Self::Igd(lease) => lease.require_cleanup(),
        }
    }

    pub(super) fn remaining(&self) -> u32 {
        self.remaining_at(Instant::now())
    }

    pub(super) fn remaining_at(&self, now: Instant) -> u32 {
        u32::try_from(self.expires().saturating_duration_since(now).as_secs()).unwrap_or(0)
    }

    pub(super) async fn renew(
        &mut self,
        network: &Network,
        stop: &CancellationToken,
    ) -> io::Result<()> {
        match self {
            Self::Pcp(lease) => lease.renew(network, stop).await,
            Self::Igd(lease) => lease.renew(network, stop).await,
        }
    }

    pub(super) async fn cleanup(&mut self, network: &Network) -> bool {
        match self {
            Self::Pcp(lease) => lease.cleanup(network).await,
            Self::Igd(lease) => lease.cleanup(network).await,
        }
    }

    pub(super) async fn release(self, network: &Network) {
        match self {
            Self::Pcp(lease) => lease.release(network).await,
            Self::Igd(lease) => lease.release(network).await,
        }
    }
}
