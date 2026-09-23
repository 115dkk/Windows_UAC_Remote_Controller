// SPDX-License-Identifier: GPL-2.0-or-later
//! One owned router mapping as the obligation owner sees it. Each protocol
//! keeps its own ownership proof and cleanup rule behind this dispatch.
use std::{io, net::SocketAddr, time::Instant};

use super::{CancellationToken, Network, igd, pcp};

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

    pub(super) fn expires(&self) -> Instant {
        match self {
            Self::Pcp(lease) => lease.expires,
            Self::Igd(lease) => lease.expires,
        }
    }

    pub(super) fn is_candidate(&self) -> bool {
        match self {
            Self::Pcp(lease) => lease.is_candidate(),
            Self::Igd(lease) => lease.is_candidate(),
        }
    }

    pub(super) fn require_cleanup(&mut self) {
        match self {
            Self::Pcp(lease) => lease.require_cleanup(),
            Self::Igd(lease) => lease.require_cleanup(),
        }
    }

    pub(super) fn remaining(&self) -> u32 {
        match self {
            Self::Pcp(lease) => lease.remaining(),
            Self::Igd(lease) => lease.remaining(),
        }
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
