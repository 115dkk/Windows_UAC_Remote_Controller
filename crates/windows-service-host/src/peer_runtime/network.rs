// SPDX-License-Identifier: GPL-2.0-or-later
//! Network configuration and worker ownership. Routing observations are not
//! authentication; peer guards and ceremony authority remain with ServiceSession.
use super::{PeerRuntimeError, ServicePeerCarrier, dialer, lan_announce, listener, pairing};
use crate::{
    external_access::ExternalAccessSetting,
    management_protocol::{ListenerFault, ManagementResponse},
};
use approval_protocol::DeviceId;
use direct_network::{CandidateSource, DirectFailure, DirectGatewayState, ExternalAccess};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

const FORWARD_ORIGIN_RETRY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExitReporting {
    Record,
    Discard,
}

pub(super) trait Worker {
    fn cancel(&mut self);
    fn drain(&mut self) -> bool;
    fn remaining_owners(&self) -> usize;
}
pub(super) trait Dialer: Worker {
    fn poll(
        &mut self,
        routes: &[(DeviceId, SocketAddr, relay_service::RouteId)],
        now: Instant,
    ) -> Vec<ServicePeerCarrier>;
    fn release(&mut self, device: DeviceId);
}
pub(super) trait Relay: Worker {
    fn is_running(&self) -> bool;
    fn supports_ipv6(&self) -> bool;
    fn abuse_counters(&self) -> relay_service::RelayAbuseCounters;
    fn take_exit(&mut self) -> Option<relay_service::HostedRelayExit>;
}
pub(super) trait Gateway: Worker {
    fn access(&self) -> ExternalAccess;
    fn snapshot(&self) -> GatewayReading;
}
/// Only local network/storage operations cross this seam. No key or registry
/// enters the adapter, including the controlled implementation used by tests.
pub(super) trait Platform {
    type Dialer: Dialer;
    type Relay: Relay;
    type Gateway: Gateway;
    fn start_dialer(&mut self, relay: Option<SocketAddr>)
    -> Result<Self::Dialer, PeerRuntimeError>;
    fn start_relay(&mut self) -> io::Result<Self::Relay>;
    fn start_gateway(
        &mut self,
        internal: SocketAddr,
        access: ExternalAccess,
    ) -> Option<Self::Gateway>;
    fn local_endpoint(&self) -> Option<SocketAddr>;
    fn store_relay(&mut self, relay: Option<SocketAddr>) -> Result<(), PeerRuntimeError>;
    fn store_external(&mut self, setting: ExternalAccessSetting) -> bool;
    fn poll_lan(&mut self, desired: Option<SocketAddrV4>, now: Instant);
    fn drop_lan(&mut self);
    fn listener_owner(&self) -> Option<windows_port_owner::ListenerOwner>;
    fn record(&mut self, event: crate::public_diagnostics::Event);
}

pub(super) struct Native {
    announcement: lan_announce::LanAnnouncement,
    label: String,
    #[cfg(test)]
    recorded: Option<std::rc::Rc<std::cell::RefCell<Vec<crate::public_diagnostics::Event>>>>,
}
impl Native {
    pub(super) fn new(pc: approval_protocol::PcIdentity) -> Self {
        Self {
            announcement: lan_announce::LanAnnouncement::default(),
            label: service_protocol::lan_instance_label(&pc),
            #[cfg(test)]
            recorded: None,
        }
    }
}
impl Platform for Native {
    type Dialer = dialer::DeviceDialer;
    type Relay = relay_service::HostedRelay;
    type Gateway = direct_network::DirectGatewayOwner;
    fn start_dialer(
        &mut self,
        relay: Option<SocketAddr>,
    ) -> Result<Self::Dialer, PeerRuntimeError> {
        match relay {
            Some(address) => dialer::DeviceDialer::new(address),
            None => dialer::DeviceDialer::new_embedded(),
        }
    }
    fn start_relay(&mut self) -> io::Result<Self::Relay> {
        // Retains the embedded PC-role loopback restriction and eviction policy.
        relay_service::HostedRelay::start_embedded(relay_service::EMBEDDED_RELAY_PORT)
    }
    fn start_gateway(
        &mut self,
        internal: SocketAddr,
        access: ExternalAccess,
    ) -> Option<Self::Gateway> {
        direct_network::DirectGatewayOwner::start(internal, access).ok()
    }
    fn local_endpoint(&self) -> Option<SocketAddr> {
        direct_network::local_endpoint(relay_service::EMBEDDED_RELAY_PORT).ok()
    }
    fn store_relay(&mut self, relay: Option<SocketAddr>) -> Result<(), PeerRuntimeError> {
        crate::native::configure_relay_for_running_service(relay)
            .map_err(|_| PeerRuntimeError::Registry)
    }
    fn store_external(&mut self, setting: ExternalAccessSetting) -> bool {
        crate::native::configure_external_access_for_running_service(setting).is_ok()
    }
    fn poll_lan(&mut self, desired: Option<SocketAddrV4>, now: Instant) {
        self.announcement.poll_endpoint(&self.label, desired, now);
    }
    fn drop_lan(&mut self) {
        self.announcement.withdraw();
    }
    fn listener_owner(&self) -> Option<windows_port_owner::ListenerOwner> {
        windows_port_owner::listener_owner(relay_service::EMBEDDED_RELAY_PORT)
            .ok()
            .flatten()
    }
    fn record(&mut self, event: crate::public_diagnostics::Event) {
        #[cfg(test)]
        if let Some(recorded) = &self.recorded {
            recorded.borrow_mut().push(event);
            return;
        }
        crate::public_diagnostics::record(event);
    }
}
impl Worker for dialer::DeviceDialer {
    fn cancel(&mut self) {
        self.cancel();
    }
    fn drain(&mut self) -> bool {
        self.drain()
    }
    fn remaining_owners(&self) -> usize {
        self.remaining_owners()
    }
}
impl Dialer for dialer::DeviceDialer {
    fn poll(
        &mut self,
        routes: &[(DeviceId, SocketAddr, relay_service::RouteId)],
        now: Instant,
    ) -> Vec<ServicePeerCarrier> {
        self.poll(routes, now)
    }
    fn release(&mut self, device: DeviceId) {
        self.release(device);
    }
}
impl Worker for relay_service::HostedRelay {
    fn cancel(&mut self) {
        relay_service::HostedRelay::cancel(self);
    }
    fn drain(&mut self) -> bool {
        self.drain()
    }
    fn remaining_owners(&self) -> usize {
        self.remaining_owners()
    }
}
impl Relay for relay_service::HostedRelay {
    fn is_running(&self) -> bool {
        self.is_running()
    }
    fn supports_ipv6(&self) -> bool {
        self.supports_ipv6()
    }
    fn abuse_counters(&self) -> relay_service::RelayAbuseCounters {
        self.abuse_counters()
    }
    fn take_exit(&mut self) -> Option<relay_service::HostedRelayExit> {
        self.take_exit()
    }
}
impl Worker for direct_network::DirectGatewayOwner {
    fn cancel(&mut self) {
        direct_network::DirectGatewayOwner::cancel(self);
    }
    fn drain(&mut self) -> bool {
        self.drain()
    }
    fn remaining_owners(&self) -> usize {
        self.remaining_owners()
    }
}
impl Gateway for direct_network::DirectGatewayOwner {
    fn access(&self) -> ExternalAccess {
        self.access()
    }
    fn snapshot(&self) -> GatewayReading {
        let snapshot = self.snapshot();
        GatewayReading {
            access: self.access(),
            state: snapshot.state,
            candidates: snapshot.candidates().to_vec(),
            validity_seconds: snapshot.remaining_validity_seconds(),
            external: snapshot.external(),
            source: snapshot.source(),
            failure: snapshot.failure(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct GatewayReading {
    pub(super) access: ExternalAccess,
    pub(super) state: DirectGatewayState,
    pub(super) candidates: Vec<SocketAddr>,
    pub(super) validity_seconds: u32,
    pub(super) external: Option<SocketAddr>,
    pub(super) source: Option<CandidateSource>,
    pub(super) failure: Option<DirectFailure>,
}
/// One immutable observation, shared by the named consumer projections. Their
/// deliberately different admission conditions are compatibility requirements.
#[derive(Clone, Debug)]
pub(super) struct Observation {
    pub(super) embedded: bool,
    pub(super) closing: bool,
    pub(super) pending: bool,
    pub(super) running: bool,
    pub(super) relay: Option<SocketAddr>,
    pub(super) ipv6: bool,
    pub(super) internal: Option<SocketAddr>,
    pub(super) gateway: Option<GatewayReading>,
    pub(super) access: ExternalAccess,
    pub(super) forward_origin: Option<Ipv4Addr>,
}
pub(super) struct InvitationAddresses {
    pub(super) relay: SocketAddr,
    pub(super) alternatives: Vec<SocketAddr>,
    pub(super) embedded: bool,
}
impl Observation {
    pub(super) fn management_snapshot(&self) -> (bool, bool, Option<SocketAddr>) {
        // Legacy Query deliberately does not test closing, pending or the gateway.
        (
            self.embedded,
            self.embedded && self.running,
            if self.embedded && !self.running {
                None
            } else {
                self.relay
            },
        )
    }
    pub(super) fn signed_candidates(&self) -> (Vec<SocketAddr>, u32) {
        // Signed hints deliberately do not test the gateway's access mode/state.
        let Some(reading) = &self.gateway else {
            return (Vec::new(), 0);
        };
        if !self.running
            || !self.embedded
            || self.closing
            || self.pending
            || self.internal.is_none()
            || self.internal != self.relay
        {
            return (Vec::new(), 0);
        }
        let seconds = reading
            .validity_seconds
            .min(service_protocol::MAX_ADDRESS_VALIDITY_SECONDS);
        if seconds == 0 {
            return (Vec::new(), 0);
        }
        let candidates: Vec<_> = reading
            .candidates
            .iter()
            .copied()
            .filter(|address| address.is_ipv4() || self.ipv6)
            .take(service_protocol::MAX_ADDRESS_CANDIDATES)
            .collect();
        if candidates.is_empty() {
            (Vec::new(), 0)
        } else {
            (candidates, seconds)
        }
    }
    pub(super) fn invitation_addresses(
        &self,
        configured: Option<SocketAddr>,
    ) -> Result<InvitationAddresses, pairing::Failure> {
        // Primary invitation admission deliberately does not test closing/pending.
        let relay = self.relay.ok_or(pairing::Failure::RelayUnconfigured)?;
        if configured.is_some_and(|configured| configured != relay)
            || (configured.is_none() && !self.running)
        {
            return Err(pairing::Failure::Protocol);
        }
        Ok(InvitationAddresses {
            relay,
            alternatives: self
                .signed_candidates()
                .0
                .into_iter()
                .filter(|candidate| *candidate != relay)
                .take(service_protocol::MAX_ADDRESS_CANDIDATES - 1)
                .collect(),
            embedded: self.embedded,
        })
    }
    pub(super) fn accepts_address_query(&self, recorded: SocketAddr) -> bool {
        // Route acceptance deliberately does not test closing or gateway validity.
        !self.pending
            && if self.embedded {
                self.relay.is_some() && self.running
            } else {
                self.relay == Some(recorded)
            }
    }
    pub(super) fn lan_announcement(&self) -> Option<SocketAddrV4> {
        // DNS-SD deliberately does not test pending, the gateway or hint validity.
        if !self.embedded || self.closing || !self.running {
            return None;
        }
        match self.relay? {
            SocketAddr::V4(address) if address.ip().is_private() => Some(address),
            _ => None,
        }
    }
    pub(super) fn external_status(&self) -> ManagementResponse {
        // External diagnostics deliberately do not test embedded/pending/listening.
        let usable =
            |address: &SocketAddr| crate::contract::validate_relay_endpoint(*address).is_ok();
        let reading = self.gateway.as_ref().filter(|gateway| {
            !self.closing && self.internal.is_some() && gateway.access == self.access
        });
        let (external, source) = match reading.map(|reading| (reading.external, reading.source)) {
            Some((Some(external), Some(source))) if usable(&external) => {
                (Some(external), Some(source))
            }
            _ => (None, None),
        };
        ManagementResponse::ExternalStatus {
            access: self.access,
            external,
            source,
            failure: reading
                .filter(|_| external.is_none())
                .and_then(|reading| reading.failure),
            lan: self
                .internal
                .filter(|_| !self.closing && self.gateway.is_some())
                .filter(usable),
            forward_origin: matches!(self.access, ExternalAccess::RouterForward { .. })
                .then_some(self.forward_origin)
                .flatten(),
        }
    }
    pub(super) fn direct_status(&self) -> ManagementResponse {
        use crate::management_protocol::DirectConnectionState as State;
        // Direct status deliberately does not require matching gateway access mode.
        let listening = self.embedded && !self.closing && !self.pending && self.running;
        let state = if self.closing || self.pending {
            State::Stopped
        } else if !self.embedded {
            State::Unknown
        } else if !listening {
            State::Unavailable
        } else {
            match self.gateway.as_ref().map(|reading| reading.state) {
                Some(DirectGatewayState::PublicIpv4Candidate) => {
                    if self.signed_candidates().0.is_empty() {
                        State::Discovering
                    } else {
                        State::Candidate
                    }
                }
                Some(DirectGatewayState::LanOnly) => State::LanOnly,
                Some(DirectGatewayState::MappedCandidate | DirectGatewayState::Ipv6Candidate) => {
                    let (candidates, _) = self.signed_candidates();
                    if candidates.is_empty() {
                        State::Discovering
                    } else if candidates
                        .iter()
                        .any(|address| Some(*address) != self.relay)
                        || self.relay.is_some_and(|address| address.is_ipv6())
                    {
                        State::Candidate
                    } else {
                        State::LanOnly
                    }
                }
                Some(DirectGatewayState::Unavailable | DirectGatewayState::Stopped) => {
                    State::Unavailable
                }
                Some(DirectGatewayState::Discovering) | None => State::Discovering,
            }
        };
        ManagementResponse::DirectStatus {
            embedded_relay: self.embedded,
            relay_listening: listening,
            state,
        }
    }
    pub(super) fn candidates_pending(&self) -> bool {
        self.embedded
            && !self.closing
            && !self.pending
            && self.running
            && self.gateway.as_ref().is_none_or(|reading| {
                reading.access != self.access
                    || matches!(
                        reading.state,
                        DirectGatewayState::Discovering | DirectGatewayState::Stopped
                    )
            })
    }
    pub(super) fn settled_external(&self) -> Option<SocketAddr> {
        let reading = self.gateway.as_ref()?;
        if reading.access != self.access
            || matches!(
                reading.state,
                DirectGatewayState::Discovering | DirectGatewayState::Stopped
            )
        {
            return None;
        }
        let external = reading.external?;
        self.signed_candidates()
            .0
            .contains(&external)
            .then_some(external)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Invalidation {
    Peers,
    Ceremony,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConfigurationResult {
    Ready,
    Unavailable,
}
struct Pending<D> {
    address: Option<SocketAddr>,
    old_dialer: Option<D>,
}
pub(super) struct Network<P: Platform = Native> {
    platform: P,
    dialer: Option<P::Dialer>,
    relay_host: Option<P::Relay>,
    gateway: Option<P::Gateway>,
    internal: Option<SocketAddr>,
    access: ExternalAccess,
    forward_origin: Option<Ipv4Addr>,
    forward_origin_retry_at: Option<Instant>,
    embedded: bool,
    retry_at: Instant,
    listener_fault: Option<ListenerFault>,
    owner_lookup: Option<(Instant, Option<windows_port_owner::ListenerOwner>)>,
    abuse_reported: Option<(Instant, relay_service::RelayAbuseCounters)>,
    relay: Option<SocketAddr>,
    pending: Option<Pending<P::Dialer>>,
    closing: bool,
    #[cfg(test)]
    gateway_fixture: Option<GatewayReading>,
}
impl<P: Platform> Network<P> {
    pub(super) fn new(platform: P, now: Instant) -> Self {
        Self {
            platform,
            dialer: None,
            relay_host: None,
            gateway: None,
            internal: None,
            access: ExternalAccess::Automatic,
            forward_origin: None,
            forward_origin_retry_at: None,
            embedded: false,
            retry_at: now,
            listener_fault: None,
            owner_lookup: None,
            abuse_reported: None,
            relay: None,
            pending: None,
            closing: false,
            #[cfg(test)]
            gateway_fixture: None,
        }
    }
    pub(super) fn observe(&self) -> Observation {
        let gateway = self.gateway.as_ref().map(Gateway::snapshot);
        #[cfg(test)]
        let gateway = self.gateway_fixture.clone().or(gateway);
        Observation {
            embedded: self.embedded,
            closing: self.closing,
            pending: self.pending.is_some(),
            running: self.relay_host.as_ref().is_some_and(Relay::is_running),
            relay: self.relay,
            ipv6: self.relay_host.as_ref().is_some_and(Relay::supports_ipv6),
            internal: self.internal,
            gateway,
            access: self.access,
            forward_origin: self.forward_origin,
        }
    }
    pub(super) fn use_external_access(&mut self, setting: ExternalAccessSetting) {
        self.access = setting.access;
        self.forward_origin = setting.forward_origin;
        self.forward_origin_retry_at = None;
    }
    pub(super) fn set_external(
        &mut self,
        access: ExternalAccess,
        now: Instant,
    ) -> ConfigurationResult {
        let forward_origin = match (access, self.internal) {
            (ExternalAccess::RouterForward { .. }, Some(SocketAddr::V4(internal)))
                if crate::external_access::usable_forward_origin(*internal.ip()) =>
            {
                Some(*internal.ip())
            }
            _ => None,
        };
        let setting = ExternalAccessSetting {
            access,
            forward_origin,
        };
        if !self.platform.store_external(setting) {
            return ConfigurationResult::Unavailable;
        }
        self.use_external_access(setting);
        self.retry_at = now;
        ConfigurationResult::Ready
    }
    pub(super) fn configure_after_ready(
        &mut self,
        relay: Option<SocketAddr>,
        now: Instant,
        invalidate: &mut impl FnMut(Invalidation),
    ) -> Result<(), PeerRuntimeError> {
        if self.closing {
            return Err(PeerRuntimeError::Closed);
        }
        self.embedded = relay.is_none();
        self.relay = relay;
        if self.embedded {
            self.poll_embedded(now, invalidate)?;
        } else {
            self.clear_listener_fault();
            self.dialer = relay
                .map(|address| self.platform.start_dialer(Some(address)))
                .transpose()?;
        }
        Ok(())
    }
    pub(super) fn withdraw(&mut self, invalidate: &mut impl FnMut(Invalidation)) {
        self.relay = None;
        self.cancel_gateway();
        self.platform.drop_lan();
        invalidate(Invalidation::Peers);
        if let Some(dialer) = self.dialer.as_mut() {
            dialer.cancel();
        }
        invalidate(Invalidation::Ceremony);
    }
    pub(super) fn request_relay(
        &mut self,
        address: Option<SocketAddr>,
        invalidate: &mut impl FnMut(Invalidation),
    ) -> Result<(), PeerRuntimeError> {
        if self.pending.is_some() {
            return Err(PeerRuntimeError::Protocol);
        }
        // Storage may have changed even when read-back fails. Never continue on
        // an unconfirmed setting; the session handles the fatal Registry error.
        self.platform.store_relay(address)?;
        self.withdraw(invalidate);
        let old_dialer = self.dialer.take();
        if let Some(host) = self.relay_host.as_mut() {
            host.cancel();
        }
        self.pending = Some(Pending {
            address,
            old_dialer,
        });
        Ok(())
    }
    pub(super) fn replacement_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub(super) fn poll_replacement(
        &mut self,
        now: Instant,
        invalidate: &mut impl FnMut(Invalidation),
    ) -> Result<Option<ConfigurationResult>, PeerRuntimeError> {
        let Some(mut pending) = self.pending.take() else {
            return Ok(None);
        };
        if pending
            .old_dialer
            .as_mut()
            .is_some_and(|dialer| !dialer.drain())
        {
            self.pending = Some(pending);
            return Ok(None);
        }
        pending.old_dialer = None;
        if !self.drain_gateway() {
            self.pending = Some(pending);
            return Ok(None);
        }
        if self.relay_host.is_some() && !self.drain_relay(ExitReporting::Record) {
            self.pending = Some(pending);
            return Ok(None);
        }
        self.relay_host = None;
        self.retry_at = now;
        self.configure_after_ready(pending.address, now, invalidate)?;
        Ok(Some(if self.relay.is_some() {
            ConfigurationResult::Ready
        } else {
            ConfigurationResult::Unavailable
        }))
    }
    /// Called at the original session poll point, before deferred queries/pairing.
    pub(super) fn poll(
        &mut self,
        now: Instant,
        invalidate: &mut impl FnMut(Invalidation),
    ) -> Result<(), PeerRuntimeError> {
        if !self.relay_host.as_ref().is_some_and(Relay::is_running) {
            self.poll_gateway(None);
            self.adopt_forward_origin(now);
        }
        self.poll_embedded(now, invalidate)
    }
    fn poll_embedded(
        &mut self,
        now: Instant,
        invalidate: &mut impl FnMut(Invalidation),
    ) -> Result<(), PeerRuntimeError> {
        if !self.embedded || self.pending.is_some() || self.closing || now < self.retry_at {
            return Ok(());
        }
        self.retry_at = now + Duration::from_secs(5);
        if self
            .relay_host
            .as_ref()
            .is_some_and(|host| !host.is_running())
        {
            self.withdraw(invalidate);
            if !self.drain_relay(ExitReporting::Record) {
                return Ok(());
            }
            self.relay_host = None;
            self.withdraw(invalidate);
        }
        if self.relay_host.is_none() {
            match self.platform.start_relay() {
                Ok(host) => {
                    self.relay_host = Some(host);
                    self.clear_listener_fault();
                }
                Err(error) => self.observe_listener_failure(&error, now),
            }
            if self.relay_host.is_none() {
                self.retry_at = now + Duration::from_secs(1);
            }
        }
        let endpoint = if self.relay_host.as_ref().is_some_and(Relay::is_running) {
            self.platform.local_endpoint().filter(|address| {
                address.is_ipv4() || self.relay_host.as_ref().is_some_and(Relay::supports_ipv6)
            })
        } else {
            None
        };
        if self.relay.is_some() && self.relay != endpoint {
            self.withdraw(invalidate);
        }
        if self.relay_host.as_ref().is_some_and(Relay::is_running) && self.relay.is_none() {
            if let Some(dialer) = self.dialer.as_mut() {
                if !dialer.drain() {
                    return Ok(());
                }
                self.dialer = None;
            }
            if let Some(endpoint) = endpoint {
                self.dialer = Some(self.platform.start_dialer(None)?);
                self.relay = Some(endpoint);
            }
        }
        self.poll_gateway(endpoint);
        self.adopt_forward_origin(now);
        self.platform
            .poll_lan(self.observe().lan_announcement(), now);
        self.observe_relay_abuse(now);
        Ok(())
    }
    fn cancel_gateway(&mut self) {
        self.internal = None;
        if let Some(gateway) = self.gateway.as_mut() {
            gateway.cancel();
        }
    }
    fn drain_gateway(&mut self) -> bool {
        self.cancel_gateway();
        if self
            .gateway
            .as_mut()
            .is_some_and(|gateway| !gateway.drain())
        {
            return false;
        }
        self.gateway = None;
        true
    }
    fn poll_gateway(&mut self, endpoint: Option<SocketAddr>) {
        let desired = endpoint.filter(|_| {
            self.embedded
                && !self.closing
                && self.pending.is_none()
                && self.relay_host.as_ref().is_some_and(Relay::is_running)
        });
        let other_mode = self
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.access() != self.access);
        if (self.internal != desired || (desired.is_none() && self.gateway.is_some()) || other_mode)
            && !self.drain_gateway()
        {
            return;
        }
        if self.gateway.is_none()
            && let Some(internal) = desired
            && let Some(gateway) = self.platform.start_gateway(internal, self.access)
        {
            self.gateway = Some(gateway);
            self.internal = Some(internal);
        }
    }
    fn adopt_forward_origin(&mut self, now: Instant) {
        if !matches!(self.access, ExternalAccess::RouterForward { .. })
            || self.forward_origin.is_some()
            || self.closing
            || self.pending.is_some()
            || self
                .forward_origin_retry_at
                .is_some_and(|retry| now < retry)
        {
            return;
        }
        if !self
            .gateway
            .as_ref()
            .is_some_and(|gateway| gateway.access() == self.access)
        {
            return;
        }
        let Some(origin) = self.internal.and_then(|internal| match internal {
            SocketAddr::V4(address)
                if crate::external_access::usable_forward_origin(*address.ip()) =>
            {
                Some(*address.ip())
            }
            _ => None,
        }) else {
            return;
        };
        if self.platform.store_external(ExternalAccessSetting {
            access: self.access,
            forward_origin: Some(origin),
        }) {
            self.forward_origin = Some(origin);
            self.forward_origin_retry_at = None;
        } else {
            self.forward_origin_retry_at = Some(now + FORWARD_ORIGIN_RETRY_INTERVAL);
        }
    }
    /// Consume each worker's exit after successful drain, before releasing it.
    fn drain_relay(&mut self, reporting: ExitReporting) -> bool {
        let Some(relay) = self.relay_host.as_mut() else {
            return false;
        };
        if !relay.drain() {
            return false;
        }
        if let Some(exit) = relay.take_exit()
            && reporting == ExitReporting::Record
        {
            self.platform
                .record(crate::public_diagnostics::Event::RelayWorkerStopped {
                    outcome: exit.into(),
                });
        }
        true
    }
    fn observe_relay_abuse(&mut self, now: Instant) {
        let Some(current) = self.relay_host.as_ref().map(Relay::abuse_counters) else {
            return;
        };
        if !listener::relay_abuse_due(current, self.abuse_reported, now) {
            return;
        }
        self.platform
            .record(crate::public_diagnostics::Event::RelayAbuse {
                evicted_pairs: current.evicted_pairs,
                rejected_duplicates: current.rejected_duplicates,
                rejected_pc_sources: current.rejected_pc_sources,
                rejected_evictions: current.rejected_evictions,
            });
        self.abuse_reported = Some((now, current));
    }
    fn observe_listener_failure(&mut self, error: &io::Error, now: Instant) {
        let platform = &self.platform;
        let fault = listener::fault_for_failure(error, now, &mut self.owner_lookup, || {
            platform.listener_owner()
        });
        self.set_listener_fault(fault);
    }
    fn set_listener_fault(&mut self, fault: Option<ListenerFault>) {
        if self.listener_fault != fault {
            self.platform
                .record(crate::public_diagnostics::Event::RelayListenerChanged {
                    fault: fault.clone(),
                });
            self.listener_fault = fault;
        }
    }
    fn clear_listener_fault(&mut self) {
        self.set_listener_fault(None);
        self.owner_lookup = None;
    }
    pub(super) fn listener_status(&self) -> ManagementResponse {
        ManagementResponse::ListenerStatus {
            port: relay_service::EMBEDDED_RELAY_PORT,
            fault: if self.embedded && !self.closing && self.pending.is_none() {
                self.listener_fault.clone()
            } else {
                None
            },
        }
    }
    pub(super) fn has_dialer(&self) -> bool {
        self.dialer.is_some()
    }
    pub(super) fn poll_dialer(
        &mut self,
        routes: &[(DeviceId, SocketAddr, relay_service::RouteId)],
        now: Instant,
    ) -> Vec<ServicePeerCarrier> {
        self.dialer
            .as_mut()
            .map_or_else(Vec::new, |dialer| dialer.poll(routes, now))
    }
    pub(super) fn release(&mut self, device: DeviceId) {
        if let Some(dialer) = self.dialer.as_mut() {
            dialer.release(device);
        }
    }
    /// Drop must reach the owner invariant even if the diagnostics volume is
    /// stalled. Clear the fault without its ordinary change row (audit #33 R-11).
    pub(super) fn prepare_drop(&mut self) {
        self.closing = true;
        self.listener_fault = None;
        self.owner_lookup = None;
    }

    /// The session shuts down ceremony/management between these two calls.
    pub(super) fn prepare_shutdown(&mut self) {
        self.closing = true;
        self.clear_listener_fault();
    }
    pub(super) fn begin_shutdown(&mut self) {
        self.cancel_gateway();
        self.platform.drop_lan();
        if let Some(host) = self.relay_host.as_mut() {
            host.cancel();
        }
        if let Some(dialer) = self.dialer.as_mut() {
            dialer.cancel();
        }
        if let Some(dialer) = self
            .pending
            .as_mut()
            .and_then(|pending| pending.old_dialer.as_mut())
        {
            dialer.cancel();
        }
    }
    /// Both explicit shutdown polls and the session Drop fallback retain and
    /// drain the same objects, with the original gateway/relay/dialer ordering.
    pub(super) fn drain_shutdown(&mut self) {
        self.drain_network(ExitReporting::Record);
    }

    pub(super) fn drain_for_drop(&mut self) {
        // Consume take_exit without a synchronous file write (audit #33 R-11).
        self.drain_network(ExitReporting::Discard);
    }

    fn drain_network(&mut self, reporting: ExitReporting) {
        self.drain_gateway();
        self.drain_relay(reporting);
        if let Some(dialer) = self.dialer.as_mut() {
            dialer.drain();
        }
        if let Some(dialer) = self
            .pending
            .as_mut()
            .and_then(|pending| pending.old_dialer.as_mut())
        {
            dialer.drain();
        }
        if self.pending.as_ref().is_some_and(|pending| {
            pending
                .old_dialer
                .as_ref()
                .is_none_or(|dialer| dialer.remaining_owners() == 0)
        }) {
            self.pending = None;
        }
    }
    pub(super) fn remaining_owners(&self) -> usize {
        self.relay_host.as_ref().map_or(0, Worker::remaining_owners)
            + self.gateway.as_ref().map_or(0, Worker::remaining_owners)
            + self.dialer.as_ref().map_or(0, Worker::remaining_owners)
            + self
                .pending
                .as_ref()
                .and_then(|pending| pending.old_dialer.as_ref())
                .map_or(0, Worker::remaining_owners)
    }
}

// Existing real TCP/signature tests need controlled gateway publications, not
// access to the production owner's mutable configuration or worker handles.
#[cfg(test)]
impl<P: Platform> Network<P> {
    pub(super) fn listener_owner_cached_fixture(&self) -> bool {
        self.owner_lookup.is_some()
    }
}

#[cfg(test)]
impl Network<Native> {
    pub(super) fn listener_failure_fixture(
        &mut self,
        owner: windows_port_owner::ListenerOwner,
        now: Instant,
    ) {
        self.embedded = true;
        self.owner_lookup = Some((now, Some(owner)));
        self.observe_listener_failure(&io::Error::from_raw_os_error(10048), now);
    }

    pub(super) fn start_real_gateway_fixture(&mut self, internal: SocketAddr) {
        self.embedded = true;
        self.relay_host =
            Some(relay_service::HostedRelay::start("127.0.0.1:0".parse().unwrap()).unwrap());
        self.relay = Some(internal);
        self.gateway_fixture = None;
        self.poll_gateway(Some(internal));
    }

    pub(super) fn poll_real_gateway_fixture(&mut self, internal: SocketAddr) {
        self.poll_gateway(Some(internal));
    }

    pub(super) fn real_gateway_snapshot_fixture(
        &self,
    ) -> Option<direct_network::DirectGatewaySnapshot> {
        self.gateway
            .as_ref()
            .map(direct_network::DirectGatewayOwner::snapshot)
    }

    pub(super) fn record_fixture(
        &mut self,
    ) -> std::rc::Rc<std::cell::RefCell<Vec<crate::public_diagnostics::Event>>> {
        let recorded = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        self.platform.recorded = Some(recorded.clone());
        recorded
    }

    // Leave the joined result for the actual session Drop to consume without
    // recording. Wait for completion before entering the fail-fast Drop.
    pub(super) fn finish_relay_fixture(&mut self) -> bool {
        self.relay_host
            .as_mut()
            .is_none_or(relay_service::HostedRelay::drain)
    }

    pub(super) fn install_route_fixture(&mut self, relay: SocketAddr) {
        self.relay = Some(relay);
    }
    pub(super) fn embed_fixture(&mut self, relay: SocketAddr, reading: GatewayReading) {
        self.embedded = true;
        self.relay_host =
            Some(relay_service::HostedRelay::start("127.0.0.1:0".parse().unwrap()).unwrap());
        self.retry_at = Instant::now() + Duration::from_secs(3_600);
        self.relay = Some(relay);
        self.internal = Some(relay);
        self.gateway_fixture = Some(reading);
    }
    pub(super) fn publish_fixture(&mut self, reading: GatewayReading) {
        self.gateway_fixture = Some(reading);
    }
    pub(super) fn embedded_fixture(&mut self, embedded: bool) {
        self.embedded = embedded;
    }
}
