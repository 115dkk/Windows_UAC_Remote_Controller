// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-owned routing publication. Fixed signed hints only, never approval,
//! generic signing, policy mutation, or changes to the enrollment key tuple.
use std::net::SocketAddr;

use service_protocol::{AddressAdvertisementFields, AddressQuery, UnsignedAddressAdvertisement};

use super::*;

const QUERY_INTERVAL: Duration =
    Duration::from_secs(service_protocol::ADDRESS_QUERY_MIN_INTERVAL_SECONDS);
/// A connection's own first query may still be in flight this long after its
/// first clock exchange.
#[cfg(all(windows, target_pointer_width = "64"))]
const HINT_REFRESH_GRACE: Duration = Duration::from_secs(10);
/// At most one hint refresh per device in this interval.
#[cfg(all(windows, target_pointer_width = "64"))]
const HINT_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
/// How long after its arrival a query that met a discovering owner may still be
/// answered. The phone drops its query ten seconds after sending it and ends a
/// connection that answers one it no longer holds, so this stays well inside.
const DEFERRED_ANSWER_WINDOW: Duration = Duration::from_secs(6);

/// A query that arrived while the gateway owner was still discovering, kept to
/// be answered once the owner settles. Without it a phone that reconnects right
/// after a service start is ended again once the external address appears.
pub(super) struct DeferredQuery {
    query: AddressQuery,
    state: Arc<PeerState>,
    /// The frame's own lifetime; the answer must drain before it.
    deadline: Instant,
    answer_by: Instant,
}

/// One read of what the gateway owner publishes. Only a test can supply one
/// in place of the owner.
#[cfg(all(windows, target_pointer_width = "64"))]
#[derive(Clone, Debug)]
pub(super) struct GatewayReading {
    pub(super) access: direct_network::ExternalAccess,
    pub(super) state: direct_network::DirectGatewayState,
    pub(super) candidates: Vec<SocketAddr>,
    pub(super) validity_seconds: u32,
    pub(super) external: Option<SocketAddr>,
}

impl ServiceSession<'_> {
    fn address_query_current(
        &mut self,
        state: &PeerState,
        query: &AddressQuery,
    ) -> Result<bool, PeerRuntimeError> {
        self.check_peer(state)?;
        if query.pc != self.engine.pc_identity() || query.device != state.binding.device {
            return Ok(false);
        }
        let routes = self
            .registry
            .as_mut()
            .ok_or(PeerRuntimeError::Closed)?
            .routes()?;
        let Some((_, recorded, _)) = routes
            .iter()
            .find(|(device, _, route)| *device == query.device && route.as_bytes() == &query.route)
        else {
            return Ok(false);
        };
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            if self.pending_relay.is_some() {
                return Ok(false);
            }
            if self.embedded_mode {
                return Ok(self.relay.is_some()
                    && self
                        .embedded_relay
                        .as_ref()
                        .is_some_and(relay_service::HostedRelay::is_running));
            }
            Ok(self.relay == Some(*recorded))
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            let _ = recorded;
            Ok(true)
        }
    }

    pub(super) fn respond_addresses(
        &mut self,
        index: usize,
        state: Arc<PeerState>,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        let now = self.now()?;
        let slot = &self.peers[index];
        if !slot.ready
            || !slot.clock_served
            || slot.protocol != Some(secure_channel::ControlProtocol::V2)
            || !Arc::ptr_eq(&slot.state, &state)
            || slot.responses_in_flight.len() >= RESPONSE_QUEUE_CAPACITY
            || slot.address_query_after.is_some_and(|after| now < after)
            || now >= deadline
        {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        let query = match AddressQuery::from_wire(bytes) {
            Ok(query) => query,
            Err(_) => {
                state.retire();
                return Ok(SessionProgress::PeerRejected);
            }
        };
        if !self.address_query_current(&state, &query)? {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        self.peers[index].address_query_after = Some(
            now.checked_add(QUERY_INTERVAL)
                .ok_or(PeerRuntimeError::Clock)?,
        );
        // A newer query replaces one still kept from before.
        self.peers[index].deferred_query = None;
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        if self.current_direct_candidates().0.is_empty() && self.direct_candidates_pending() {
            // An empty answer is a durable withdrawal on the phone. Keep this
            // query for a short while instead: `answer_deferred_queries`
            // answers it once the owner settles. Unanswered, it lapses; the
            // phone keeps its hints and asks again.
            let answer_by = now
                .checked_add(DEFERRED_ANSWER_WINDOW)
                .ok_or(PeerRuntimeError::Clock)?
                .min(deadline);
            let slot = &mut self.peers[index];
            slot.query_lapsed = true;
            slot.deferred_query = Some(DeferredQuery {
                query,
                state,
                deadline,
                answer_by,
            });
            return Ok(SessionProgress::Idle);
        }
        self.answer_query(index, state, &query, deadline)
    }

    /// Answers each kept query once the gateway owner has settled, while the
    /// phone still holds it. Nothing is ended here: a query that runs out of
    /// time stays lapsed and `refresh_stale_hints` decides as before.
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn answer_deferred_queries(&mut self, now: Instant) -> Result<(), PeerRuntimeError> {
        for index in 0..self.peers.len() {
            let Some(deferred) = self.peers[index].deferred_query.take() else {
                continue;
            };
            if now >= deferred.answer_by || !Arc::ptr_eq(&self.peers[index].state, &deferred.state)
            {
                continue;
            }
            if (self.current_direct_candidates().0.is_empty() && self.direct_candidates_pending())
                || self.peers[index].responses_in_flight.len() >= RESPONSE_QUEUE_CAPACITY
            {
                self.peers[index].deferred_query = Some(deferred);
                continue;
            }
            // The same checks the query passed on arrival, without ending a
            // connection that changed since: its own events decide that.
            if self.check_peer(&deferred.state).is_err()
                || !self.address_query_current(&deferred.state, &deferred.query)?
            {
                continue;
            }
            if self.key.public()? != self.pc_key {
                return Err(PeerRuntimeError::Identity);
            }
            self.answer_query(index, deferred.state, &deferred.query, deferred.deadline)?;
        }
        Ok(())
    }

    /// Signs the current candidates for `query` and queues them on this
    /// connection. The caller checked the query and the key.
    fn answer_query(
        &mut self,
        index: usize,
        state: Arc<PeerState>,
        query: &AddressQuery,
        deadline: Instant,
    ) -> Result<SessionProgress, PeerRuntimeError> {
        let (endpoints, valid_for_seconds) = self.current_direct_candidates();
        let message = UnsignedAddressAdvertisement::new(AddressAdvertisementFields {
            pc: self.engine.pc_identity(),
            epoch: self.engine.boot_epoch(),
            device: state.binding.device,
            route: query.route,
            nonce: query.nonce,
            valid_for_seconds,
            endpoints: endpoints.clone(),
        })
        .map_err(|_| PeerRuntimeError::Protocol)?;
        // Only the above closed, validated statement reaches this service-key
        // operation. The wire never supplies a digest or arbitrary signing input.
        let signature = self.key.sign_protocol(&message.signing_bytes())?;
        let signed = message
            .with_der_signature(&signature)
            .map_err(|_| PeerRuntimeError::Identity)?;
        if self.key.public()? != self.pc_key {
            return Err(PeerRuntimeError::Identity);
        }
        signed
            .verify(
                &PcPublicKey::from_spki_der(self.pc_key.as_spki_der())
                    .map_err(|_| PeerRuntimeError::Identity)?,
            )
            .map_err(|_| PeerRuntimeError::Identity)?;
        let (current, validity) = self.current_direct_candidates();
        if current != endpoints
            || (!current.is_empty() && validity == 0)
            || !self.address_query_current(&state, query)?
            || self.now()? >= deadline
        {
            state.retire();
            return Ok(SessionProgress::PeerRejected);
        }
        let bytes = encode_frame(&signed.to_wire()).map_err(|_| PeerRuntimeError::Protocol)?;
        let id = self.next_response;
        self.next_response = id.checked_add(1).ok_or(PeerRuntimeError::Capacity)?;
        self.peers[index]
            .responses
            .try_send(Response {
                source: state,
                id,
                bytes,
                deadline,
                kind: ResponseKind::Addresses,
            })
            .map_err(|_| PeerRuntimeError::Protocol)?;
        let slot = &mut self.peers[index];
        slot.responses_in_flight
            .push_back((id, deadline, ResponseKind::Addresses));
        slot.advertised = Some(endpoints);
        slot.query_lapsed = false;
        Ok(SessionProgress::Idle)
    }

    pub(super) fn current_direct_candidates(&self) -> (Vec<SocketAddr>, u32) {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.gateway_reading()
                .map_or((Vec::new(), 0), |reading| self.publishable(&reading))
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            (Vec::new(), 0)
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    fn gateway_reading(&self) -> Option<GatewayReading> {
        #[cfg(test)]
        {
            if let Some(reading) = self.gateway_fixture.as_ref() {
                return Some(reading.clone());
            }
        }
        self.direct_gateway.as_ref().map(|gateway| {
            let snapshot = gateway.snapshot();
            GatewayReading {
                access: gateway.access(),
                state: snapshot.state,
                candidates: snapshot.candidates().to_vec(),
                validity_seconds: snapshot.remaining_validity_seconds(),
                external: snapshot.external(),
            }
        })
    }

    /// The part of `reading` this listening relay may advertise, and for how long.
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn publishable(&self, reading: &GatewayReading) -> (Vec<SocketAddr>, u32) {
        let Some(host) = self
            .embedded_relay
            .as_ref()
            .filter(|host| host.is_running())
        else {
            return (Vec::new(), 0);
        };
        if !self.embedded_mode
            || self.closing
            || self.pending_relay.is_some()
            || self.direct_internal.is_none()
            || self.direct_internal != self.relay
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
            .filter(|address| address.is_ipv4() || host.supports_ipv6())
            .take(service_protocol::MAX_ADDRESS_CANDIDATES)
            .collect();
        if candidates.is_empty() {
            (Vec::new(), 0)
        } else {
            (candidates, seconds)
        }
    }

    /// The external address a new connection would be told now, once the
    /// owner of the configured mode has settled. `None` while there is none.
    #[cfg(all(windows, target_pointer_width = "64"))]
    fn settled_external(&self) -> Option<SocketAddr> {
        use direct_network::DirectGatewayState as State;
        let reading = self.gateway_reading()?;
        if reading.access != self.external_access
            || matches!(reading.state, State::Discovering | State::Stopped)
        {
            return None;
        }
        let external = reading.external?;
        self.publishable(&reading)
            .0
            .contains(&external)
            .then_some(external)
    }

    /// Ends, once per device and interval, the connection of a phone whose
    /// last hints lack the external address now published, so that it
    /// reconnects and asks. Returns what was recorded for each.
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn refresh_stale_hints(
        &mut self,
        now: Instant,
    ) -> Vec<crate::public_diagnostics::HintRefresh> {
        use crate::public_diagnostics::HintRefresh;
        self.hint_refreshes
            .retain(|_, at| now.saturating_duration_since(*at) < HINT_REFRESH_INTERVAL);
        // A phone deciding a live prompt keeps its connection; the refresh
        // waits for a later pass.
        if !self.embedded_mode || self.closing || self.prompt.is_live() {
            return Vec::new();
        }
        // Only a connection whose phone asked can be helped: one that never
        // asked would not ask on the next connection either.
        let due: Vec<usize> = (0..self.peers.len())
            .filter(|&index| {
                let peer = &self.peers[index];
                peer.ready
                    && peer.protocol == Some(secure_channel::ControlProtocol::V2)
                    && peer.state.live()
                    && peer.clock_since.is_some_and(|since| {
                        now.saturating_duration_since(since) >= HINT_REFRESH_GRACE
                    })
                    && (peer.advertised.is_some() || peer.query_lapsed)
                    && !self.hint_refreshes.contains_key(&peer.state.binding.device)
            })
            .collect();
        if due.is_empty() {
            return Vec::new();
        }
        // Without an external address there is nothing to learn: a
        // withdrawal is not worth a reconnect.
        let Some(external) = self.settled_external() else {
            return Vec::new();
        };
        let mut refreshed = Vec::new();
        for index in due {
            let peer = &self.peers[index];
            if peer
                .advertised
                .as_ref()
                .is_some_and(|told| told.contains(&external))
            {
                continue;
            }
            // The protocol lets only the phone ask for addresses, and a new
            // connection is the one moment it always asks: end this one.
            peer.state.retire();
            self.hint_refreshes.insert(peer.state.binding.device, now);
            let reason = if peer.query_lapsed {
                HintRefresh::QueryLapsed
            } else {
                HintRefresh::WithoutExternal
            };
            // Tests read the returned reasons instead of this PC's real file.
            #[cfg(not(test))]
            crate::public_diagnostics::record(crate::public_diagnostics::Event::HintsRefreshed {
                reason,
            });
            refreshed.push(reason);
        }
        refreshed
    }

    /// The embedded relay keeps listening while its gateway owner has not
    /// published yet, is momentarily unreadable, or is being replaced for a
    /// new mode or endpoint. None of these is a reason to withdraw hints.
    fn direct_candidates_pending(&self) -> bool {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            use direct_network::DirectGatewayState as State;
            let listening = self.embedded_mode
                && !self.closing
                && self.pending_relay.is_none()
                && self
                    .embedded_relay
                    .as_ref()
                    .is_some_and(relay_service::HostedRelay::is_running);
            listening
                && self.gateway_reading().is_none_or(|reading| {
                    reading.access != self.external_access
                        || matches!(reading.state, State::Discovering | State::Stopped)
                })
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            false
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn cancel_direct_gateway(&mut self) {
        self.direct_internal = None;
        if let Some(gateway) = self.direct_gateway.as_ref() {
            gateway.cancel();
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn drain_direct_gateway(&mut self) -> bool {
        self.cancel_direct_gateway();
        if self
            .direct_gateway
            .as_mut()
            .is_some_and(|gateway| !gateway.drain())
        {
            return false;
        }
        self.direct_gateway = None;
        true
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn poll_direct_gateway(&mut self, endpoint: Option<SocketAddr>) {
        let desired = endpoint.filter(|_| {
            self.embedded_mode
                && !self.closing
                && self.pending_relay.is_none()
                && self
                    .embedded_relay
                    .as_ref()
                    .is_some_and(relay_service::HostedRelay::is_running)
        });
        // A changed mode is handled exactly like a changed internal endpoint:
        // drain the owner, then start one for the configured mode.
        let other_mode = self
            .direct_gateway
            .as_ref()
            .is_some_and(|gateway| gateway.access() != self.external_access);
        if (self.direct_internal != desired
            || (desired.is_none() && self.direct_gateway.is_some())
            || other_mode)
            && !self.drain_direct_gateway()
        {
            return;
        }
        if self.direct_gateway.is_none()
            && let Some(internal) = desired
            && let Ok(gateway) =
                direct_network::DirectGatewayOwner::start(internal, self.external_access)
        {
            // Construction only starts a bounded background owner; no router
            // discovery or router I/O runs on this service worker.
            self.direct_gateway = Some(gateway);
            self.direct_internal = Some(internal);
        }
    }

    /// The configured mode and, when the current owner runs that mode, its
    /// observation. Addresses go to local management clients of this PC only.
    /// Every field is checked here so the reply always encodes.
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn external_status(&self) -> crate::management_protocol::ManagementResponse {
        let usable =
            |address: &SocketAddr| crate::contract::validate_relay_endpoint(*address).is_ok();
        let snapshot = self
            .direct_gateway
            .as_ref()
            .filter(|gateway| {
                !self.closing
                    && self.direct_internal.is_some()
                    && gateway.access() == self.external_access
            })
            .map(direct_network::DirectGatewayOwner::snapshot);
        let (external, source) = match snapshot
            .as_ref()
            .map(|snapshot| (snapshot.external(), snapshot.source()))
        {
            Some((Some(external), Some(source))) if usable(&external) => {
                (Some(external), Some(source))
            }
            _ => (None, None),
        };
        crate::management_protocol::ManagementResponse::ExternalStatus {
            access: self.external_access,
            external,
            source,
            failure: snapshot
                .as_ref()
                .filter(|_| external.is_none())
                .and_then(direct_network::DirectGatewaySnapshot::failure),
            lan: self
                .direct_internal
                .filter(|_| !self.closing && self.direct_gateway.is_some())
                .filter(usable),
        }
    }

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub(super) fn direct_status(&self) -> crate::management_protocol::ManagementResponse {
        use crate::management_protocol::{DirectConnectionState as State, ManagementResponse};
        let listening = self.embedded_mode
            && !self.closing
            && self.pending_relay.is_none()
            && self
                .embedded_relay
                .as_ref()
                .is_some_and(relay_service::HostedRelay::is_running);
        let state = if self.closing || self.pending_relay.is_some() {
            State::Stopped
        } else if !self.embedded_mode {
            State::Unknown
        } else if !listening {
            State::Unavailable
        } else {
            match self
                .direct_gateway
                .as_ref()
                .map(|gateway| gateway.snapshot().state)
            {
                Some(direct_network::DirectGatewayState::PublicIpv4Candidate) => {
                    if self.current_direct_candidates().0.is_empty() {
                        State::Discovering
                    } else {
                        State::Candidate
                    }
                }
                Some(direct_network::DirectGatewayState::LanOnly) => State::LanOnly,
                Some(
                    direct_network::DirectGatewayState::MappedCandidate
                    | direct_network::DirectGatewayState::Ipv6Candidate,
                ) => {
                    let (candidates, _) = self.current_direct_candidates();
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
                Some(
                    direct_network::DirectGatewayState::Unavailable
                    | direct_network::DirectGatewayState::Stopped,
                ) => State::Unavailable,
                Some(direct_network::DirectGatewayState::Discovering) | None => State::Discovering,
            }
        };
        ManagementResponse::DirectStatus {
            embedded_relay: self.embedded_mode,
            relay_listening: listening,
            state,
        }
    }
}
