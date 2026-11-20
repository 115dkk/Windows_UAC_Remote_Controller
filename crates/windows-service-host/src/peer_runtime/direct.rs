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

impl ServiceSession<'_> {
    fn address_query_current(
        &mut self,
        state: &PeerState,
        query: &AddressQuery,
    ) -> Result<bool, PeerRuntimeError> {
        if !self.peer_live(state) {
            return Ok(false);
        }
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
            Ok(self.network.observe().accepts_address_query(*recorded))
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
            || !matches!(
                slot.protocol,
                Some(secure_channel::ControlProtocol::V2 | secure_channel::ControlProtocol::V3)
            )
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
            // A connection that ended while this query waited has already
            // retired itself. Registry, key and epoch mismatches remain fatal.
            if !self.peer_live(&deferred.state) {
                deferred.state.retire();
                continue;
            }
            self.check_peer(&deferred.state)?;
            if !self.address_query_current(&deferred.state, &deferred.query)? {
                continue;
            }
            if self.key.public()? != self.pc_key {
                return Err(PeerRuntimeError::Identity);
            }
            if self.answer_query(index, deferred.state, &deferred.query, deferred.deadline)?
                == SessionProgress::PeerRejected
            {
                continue;
            }
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
        if !self.enqueue_peer_response(index, &state, bytes, deadline, ResponseKind::Addresses)? {
            return Ok(SessionProgress::PeerRejected);
        }
        let slot = &mut self.peers[index];
        slot.advertised = Some(endpoints);
        slot.query_lapsed = false;
        Ok(SessionProgress::Idle)
    }

    pub(super) fn current_direct_candidates(&self) -> (Vec<SocketAddr>, u32) {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.network.observe().signed_candidates()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            (Vec::new(), 0)
        }
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
        if !self.network.observe().embedded || self.closing || self.prompt.is_live() {
            return Vec::new();
        }
        // Only a connection whose phone asked can be helped: one that never
        // asked would not ask on the next connection either.
        let due: Vec<usize> = (0..self.peers.len())
            .filter(|&index| {
                let peer = &self.peers[index];
                peer.ready
                    && matches!(
                        peer.protocol,
                        Some(
                            secure_channel::ControlProtocol::V2
                                | secure_channel::ControlProtocol::V3
                        )
                    )
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
        let Some(external) = self.network.observe().settled_external() else {
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

    fn direct_candidates_pending(&self) -> bool {
        #[cfg(all(windows, target_pointer_width = "64"))]
        {
            self.network.observe().candidates_pending()
        }
        #[cfg(not(all(windows, target_pointer_width = "64")))]
        {
            false
        }
    }
}
