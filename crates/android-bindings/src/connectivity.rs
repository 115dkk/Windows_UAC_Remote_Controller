// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded relay dialing for current durable associations.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use android_controller::{MAX_PEER_ASSOCIATIONS, PeerAssociationRef};
use relay_service::{Registration, RendezvousCarrier, RendezvousError, Role, RouteId};
use tokio_util::sync::CancellationToken;

use crate::{BridgeError, MobileController};

const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A dial that follows a lost carrier keeps trying this long before it reports
/// a failure and hands over to the backoff. Nothing wakes maintenance when a
/// backoff ends, so a PC service restart would otherwise wait for the next
/// maintenance tick. The presentation waits as long while a dial is in flight.
const RECOVERY_WINDOW: Duration = Duration::from_secs(120);
/// Attempts of one recovery dial start at least this far apart.
const RECOVERY_SPACING: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct NativeConnectivityStatus {
    pub associations: u32,
    pub connected: u32,
    pub dialing: u32,
    pub without_endpoint: u32,
}

/// How far a failed dial got, least informative first. Display only: it never
/// changes what is dialled, when, or what a later peer is trusted with.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, uniffi::Enum)]
pub enum NativeDialFailure {
    /// Every address timed out or was unreachable.
    Unreachable,
    /// Some address refused or reset the TCP connect.
    Refused,
    /// A relay accepted the TCP connect but sent no READY.
    NoAnswer,
}

impl NativeDialFailure {
    /// Cancellation is not an observation of the PC or its network.
    pub(crate) const fn classify(error: RendezvousError) -> Option<Self> {
        match error {
            RendezvousError::Cancelled => None,
            RendezvousError::ConnectTimeout | RendezvousError::Connection => {
                Some(Self::Unreachable)
            }
            RendezvousError::Refused => Some(Self::Refused),
            RendezvousError::Closed
            | RendezvousError::RendezvousTimeout
            | RendezvousError::InvalidMarker => Some(Self::NoAnswer),
        }
    }
}

/// This phone's dialing toward its paired, unconnected PCs. An observation for
/// the presentation, not reachability, authentication or an action input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct NativePcConnection {
    /// A dial to some paired, unconnected PC is in flight.
    pub dialing: bool,
    /// The furthest failure among unconnected PCs since their last carrier.
    pub last_failure: Option<NativeDialFailure>,
    /// Every paired PC has a stored global address besides its relay address.
    pub external_route: bool,
}

#[derive(Clone, Copy)]
pub(super) struct DialState {
    pub(super) generation: u64,
    pub(super) in_flight: bool,
    pub(super) failures: u8,
    pub(super) candidate_cursor: usize,
    pub(super) retry_at: Option<Instant>,
    /// The furthest failure since this association last held a carrier.
    pub(super) failure: Option<NativeDialFailure>,
}

pub(crate) struct ConnectivityOwner {
    pub(super) states: Mutex<BTreeMap<(approval_protocol::PcIdentity, u64), DialState>>,
    network: Mutex<NetworkGeneration>,
    stop: CancellationToken,
}

struct NetworkGeneration {
    number: u64,
    available: bool,
    stop: CancellationToken,
}

impl Default for ConnectivityOwner {
    fn default() -> Self {
        Self {
            states: Mutex::new(BTreeMap::new()),
            network: Mutex::new(NetworkGeneration {
                number: 0,
                available: true,
                stop: CancellationToken::new(),
            }),
            stop: CancellationToken::new(),
        }
    }
}

impl ConnectivityOwner {
    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }

    pub(super) fn key(reference: PeerAssociationRef) -> (approval_protocol::PcIdentity, u64) {
        (reference.pc(), reference.generation())
    }

    fn complete(
        &self,
        reference: PeerAssociationRef,
        generation: u64,
        outcome: Result<(), Option<NativeDialFailure>>,
        now: Instant,
    ) {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(state) = states.get_mut(&Self::key(reference)) else {
            return;
        };
        if state.generation != generation {
            return;
        }
        state.in_flight = false;
        match outcome {
            Ok(()) => {
                state.failures = 0;
                state.retry_at = None;
                state.failure = None;
            }
            Err(failure) => {
                // A local refusal (None) keeps what the network last showed.
                state.failure = state.failure.max(failure);
                state.failures = state.failures.saturating_add(1);
                let shift = u32::from(state.failures.saturating_sub(1)).min(4);
                let delay = FIRST_BACKOFF
                    .checked_mul(1_u32 << shift)
                    .unwrap_or(MAX_BACKOFF)
                    .min(MAX_BACKOFF);
                state.retry_at = now.checked_add(delay);
            }
        }
    }

    /// Whether a dial is in flight and the furthest failure, over the given
    /// `(association, connected)` pairs. A connected PC contributes nothing.
    fn observe(&self, peers: &[(PeerAssociationRef, bool)]) -> (bool, Option<NativeDialFailure>) {
        let states = self
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        peers
            .iter()
            .filter(|(_, connected)| !connected)
            .filter_map(|(reference, _)| states.get(&Self::key(*reference)))
            .fold((false, None), |(dialing, failure), state| {
                (dialing || state.in_flight, failure.max(state.failure))
            })
    }
}

/// Whether the stored candidates hold a global address other than the relay
/// address the PC was paired on. Stored coordinates only, not reachability.
/// Without a relay address nothing is dialled at all, so there is no route.
pub(crate) fn external_route(
    relay: Option<std::net::SocketAddr>,
    candidates: &[std::net::SocketAddr],
) -> bool {
    relay.is_some_and(|relay| {
        candidates
            .iter()
            .any(|candidate| *candidate != relay && global(candidate.ip()))
    })
}

/// The same conservative allow-list as `direct_network::global`, which the
/// phone crates do not depend on: private, shared, link-local, loopback,
/// documentation, benchmarking, 6to4 and reserved ranges are not global.
fn global(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_link_local()
                && a != 0
                && a < 224
                && !ip.is_private()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && (b == 0 || (b == 88 && c == 99)))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        std::net::IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub(crate) struct DialRequest {
    pub(crate) reference: PeerAssociationRef,
    pub(crate) address: std::net::SocketAddr,
    pub(crate) alternatives: Vec<std::net::SocketAddr>,
    pub(crate) route: [u8; 32],
    generation: u64,
    network_stop: CancellationToken,
    /// Until when this dial retries failed attempts; None for one attempt.
    recover_until: Option<Instant>,
}

/// A dial is a recovery dial when nothing failed since this association last
/// held a carrier, since the network changed or since start.
fn recovery_deadline(state: &DialState, now: Instant) -> Option<Instant> {
    if state.failures == 0 {
        now.checked_add(RECOVERY_WINDOW)
    } else {
        None
    }
}

pub(crate) struct DialCompletion {
    pub(crate) reference: PeerAssociationRef,
    /// Ok once a carrier was attached; otherwise what the network showed, if
    /// anything (a replaced network or a local refusal shows nothing).
    pub(crate) outcome: Result<(), Option<NativeDialFailure>>,
    generation: u64,
    completed_at: Instant,
}

/// One durable association with its optional relay address and route.
type AssociationRelay = (
    PeerAssociationRef,
    Option<(std::net::SocketAddr, [u8; 32])>,
    Vec<std::net::SocketAddr>,
);

impl MobileController {
    fn connectivity_snapshot(&self) -> Result<Vec<AssociationRelay>, BridgeError> {
        self.with_inbox(|owner| {
            let ledger = owner
                .peer_associations()
                .map_err(|_| BridgeError::StorageUnavailable)?;
            if ledger.len() > MAX_PEER_ASSOCIATIONS {
                return Err(BridgeError::InvalidObservation);
            }
            Ok(ledger
                .entries()
                .map(|association| {
                    (
                        association.reference(),
                        association.descriptor().relay(),
                        ledger.routing_candidates(association.reference()).to_vec(),
                    )
                })
                .collect())
        })
    }

    fn receive_dial_completions(&self) {
        for completion in self.intake.take_dial_completions() {
            self.connectivity.complete(
                completion.reference,
                completion.generation,
                completion.outcome,
                completion.completed_at,
            );
        }
    }

    /// The request catalogue's connection summary over `(association,
    /// connected, external_route)`; None when no PC is paired. Finished dials
    /// are taken in first, so an ended one never reads as still in flight.
    pub(crate) fn pc_connection(
        &self,
        peers: &[(PeerAssociationRef, bool, bool)],
    ) -> Option<NativePcConnection> {
        if peers.is_empty() {
            return None;
        }
        self.receive_dial_completions();
        let connections: Vec<_> = peers
            .iter()
            .map(|(reference, connected, _)| (*reference, *connected))
            .collect();
        let (dialing, last_failure) = self.connectivity.observe(&connections);
        Some(NativePcConnection {
            dialing,
            last_failure,
            external_route: peers.iter().all(|(_, _, external)| *external),
        })
    }
}

#[uniffi::export]
impl MobileController {
    /// Fixed native lifecycle signal only: retire old carriers, never approve,
    /// re-pair, extend a request deadline, or substitute network reachability
    /// for authenticated peer readiness. Serialized with stream admission.
    pub fn network_changed(&self, available: bool) -> Result<(), BridgeError> {
        let _admission = self.enter()?;
        if !self
            .approval_alive
            .load(std::sync::atomic::Ordering::Acquire)
            || self.connectivity.stop.is_cancelled()
        {
            return Err(BridgeError::Closed);
        }
        let associations = self.connectivity_snapshot()?;
        let mut network = self
            .connectivity
            .network
            .lock()
            .map_err(|_| BridgeError::Closed)?;
        let number = network.number.checked_add(1).ok_or(BridgeError::Closed)?;
        network.stop.cancel();
        *network = NetworkGeneration {
            number,
            available,
            stop: CancellationToken::new(),
        };
        self.connectivity
            .states
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .clear();
        for (reference, _, _) in associations {
            self.intake.retire_association(reference);
        }
        Ok(())
    }

    pub fn maintain_connections(self: &Arc<Self>) -> Result<NativeConnectivityStatus, BridgeError> {
        let _admission = self.enter()?;
        if !self
            .approval_alive
            .load(std::sync::atomic::Ordering::Acquire)
            || self.connectivity.stop.is_cancelled()
        {
            return Err(BridgeError::Closed);
        }
        self.start_intake_reactor()?;
        self.receive_dial_completions();
        let associations = self.connectivity_snapshot()?;
        let network = self
            .connectivity
            .network
            .lock()
            .map_err(|_| BridgeError::Closed)?;
        let now = Instant::now();
        let mut requests = Vec::new();
        let mut connected = 0_u32;
        let mut without_endpoint = 0_u32;
        {
            let mut states = self
                .connectivity
                .states
                .lock()
                .map_err(|_| BridgeError::Closed)?;
            states.retain(|key, _| {
                associations
                    .iter()
                    .any(|(reference, _, _)| *key == ConnectivityOwner::key(*reference))
            });
            for (reference, endpoint, alternatives) in &associations {
                let Some((address, route)) = endpoint else {
                    without_endpoint += 1;
                    continue;
                };
                if !network.available {
                    continue;
                }
                let state = states
                    .entry(ConnectivityOwner::key(*reference))
                    .or_insert(DialState {
                        generation: network.number,
                        in_flight: false,
                        failures: 0,
                        candidate_cursor: 0,
                        retry_at: None,
                        failure: None,
                    });
                if self.intake.has_live_peer(*reference) {
                    if self.intake.has_connected_peer(*reference) {
                        connected += 1;
                    }
                    state.failures = 0;
                    state.retry_at = None;
                    state.failure = None;
                    continue;
                }
                if state.in_flight || state.retry_at.is_some_and(|retry| now < retry) {
                    continue;
                }
                state.in_flight = true;
                // Rotate after every carrier attempt, including a failed TLS
                // handshake, so a stale/hostile READY endpoint cannot starve
                // another pinned candidate on all subsequent reconnects.
                let mut candidates = vec![*address];
                for alternative in alternatives {
                    if !candidates.contains(alternative) {
                        candidates.push(*alternative);
                    }
                }
                let cursor = state.candidate_cursor % candidates.len();
                candidates.rotate_left(cursor);
                state.candidate_cursor = (cursor + 1) % candidates.len();
                requests.push(DialRequest {
                    reference: *reference,
                    address: candidates[0],
                    alternatives: candidates[1..].to_vec(),
                    route: *route,
                    generation: network.number,
                    network_stop: network.stop.clone(),
                    recover_until: recovery_deadline(state, now),
                });
            }
        }
        for request in requests {
            if let Err(request) = self.intake.spawn_dial(request) {
                self.connectivity
                    .complete(request.reference, request.generation, Err(None), now);
            }
        }
        if self.connectivity.stop.is_cancelled() {
            return Err(BridgeError::Closed);
        }
        let dialing = self
            .connectivity
            .states
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .values()
            .filter(|state| state.in_flight)
            .count() as u32;
        Ok(NativeConnectivityStatus {
            associations: associations.len() as u32,
            connected,
            dialing,
            without_endpoint,
        })
    }
}

pub(crate) async fn run_dial(
    controller: Weak<MobileController>,
    intake_stop: CancellationToken,
    request: DialRequest,
) -> DialCompletion {
    let outcome = dial(&controller, &intake_stop, &request).await;
    DialCompletion {
        reference: request.reference,
        outcome,
        generation: request.generation,
        completed_at: Instant::now(),
    }
}

/// Every attempt of one dial. They keep the candidate order the dial was
/// created with: the cursor rotated once for the whole dial.
async fn dial(
    controller: &Weak<MobileController>,
    intake_stop: &CancellationToken,
    request: &DialRequest,
) -> Result<(), Option<NativeDialFailure>> {
    // A replaced network, a stopping owner or an unusable route says nothing
    // about the PC.
    let Ok(route) = RouteId::new(request.route) else {
        return Err(None);
    };
    let mut failure = None;
    loop {
        let began = Instant::now();
        // Only the rendezvous wait is asynchronous; stream admission below is a
        // separate synchronous phase, not a closure inside a select! expansion.
        // The production JoinSet::spawn call checks the future's Send bound.
        let attempt = request
            .network_stop
            .clone()
            .run_until_cancelled_owned(connect_candidates(
                request.address,
                &request.alternatives,
                route,
                intake_stop.clone(),
            ))
            .await;
        match attempt {
            None | Some(Err(RendezvousError::Cancelled)) => return Err(None),
            Some(Err(error)) => failure = failure.max(NativeDialFailure::classify(error)),
            Some(Ok(carrier)) => match attach(controller, request, carrier) {
                Ok(()) => return Ok(()),
                // Admission held by another native call for a moment: the
                // PC side re-registers at once, so another attempt can work.
                Err(BridgeError::Busy) => {}
                // Any other local refusal shows nothing about the network.
                Err(_) => return Err(None),
            },
        }
        let next = (began + RECOVERY_SPACING).max(Instant::now());
        if !request.recover_until.is_some_and(|until| next < until) {
            return Err(failure);
        }
        tokio::select! {
            biased;
            () = request.network_stop.cancelled() => return Err(None),
            () = intake_stop.cancelled() => return Err(None),
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(next)) => {}
        }
    }
}

/// The combinator drops the old network's pending socket on cancellation.
/// Simultaneous completion/cancellation may return a carrier; attachment still
/// checks this exact token AFTER acquiring owner admission, so it cannot revive
/// the old transport generation.
fn attach(
    controller: &Weak<MobileController>,
    request: &DialRequest,
    carrier: RendezvousCarrier,
) -> Result<(), BridgeError> {
    let stream = carrier
        .into_stream()
        .into_std()
        .map_err(|_| BridgeError::Closed)?;
    stream
        .set_nonblocking(false)
        .map_err(|_| BridgeError::Closed)?;
    Weak::<MobileController>::upgrade(controller)
        .ok_or(BridgeError::Closed)?
        .attach_network_stream(request.reference, stream, &request.network_stop)
        .map(|_| ())
}

/// Only carrier discovery is retried. TLS signing, requests and decisions are
/// never replayed across candidates. Several candidates race their TCP connects
/// and register on the first handshake alone; every other socket is dropped.
pub(crate) async fn connect_candidates(
    primary: std::net::SocketAddr,
    alternatives: &[std::net::SocketAddr],
    route: RouteId,
    stop: CancellationToken,
) -> Result<relay_service::RendezvousCarrier, RendezvousError> {
    let mut addresses = vec![primary];
    for address in alternatives.iter().take(4) {
        if !addresses.contains(address) {
            addresses.push(*address);
        }
    }
    if addresses.len() == 1 {
        // Preserve the shipped single-endpoint LAN/rendezvous timeout profile.
        return relay_service::connect_rendezvous(
            primary,
            Registration::new(Role::Phone, route),
            stop,
        )
        .await;
    }
    // A black-holed LAN address no longer holds the external one back: the
    // next candidate is dialled 250 ms later instead of after a 5 s timeout.
    // The race reports the furthest failure across its attempts.
    relay_service::connect_rendezvous_any(&addresses, Registration::new(Role::Phone, route), stop)
        .await
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    fn reference() -> PeerAssociationRef {
        reference_for(7)
    }

    fn reference_for(pc: u8) -> PeerAssociationRef {
        use android_controller::{
            LocalAttestationChallenge, LocalKeyHandle, LocalKeyLedger, LocalKeySetDescriptor,
            PeerAssociationDescriptor, PeerAssociationLedger, PeerAssociationMutation,
        };
        use approval_protocol::DeviceId;
        use p256::{PublicKey, ecdsa::SigningKey, pkcs8::EncodePublicKey};
        use secure_channel::TlsPublicKey;

        fn public(seed: u8) -> TlsPublicKey {
            let signing = SigningKey::from_slice(&[seed; 32]).unwrap();
            let point = PublicKey::from_sec1_bytes(
                signing.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap();
            TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
        }

        let handle = LocalKeyHandle::from_bytes([1; 32]).unwrap();
        let challenge = LocalAttestationChallenge::from_bytes([2; 32]).unwrap();
        let mut keys = LocalKeyLedger::new();
        keys.begin_creation(handle, challenge).unwrap();
        keys.record_created(
            LocalKeySetDescriptor::new(handle, challenge, public(3), public(4), public(5)).unwrap(),
        )
        .unwrap();
        let mut associations = PeerAssociationLedger::new();
        match associations
            .record_from_trusted_host(
                PeerAssociationDescriptor::new(
                    approval_protocol::PcIdentity::from_bytes([pc; 32]).unwrap(),
                    DeviceId::from_bytes([8; 16]).unwrap(),
                    1,
                    handle,
                    public(9),
                    public(10),
                )
                .unwrap(),
                &keys,
            )
            .unwrap()
        {
            PeerAssociationMutation::Recorded(reference) => reference,
            _ => panic!("new synthetic association"),
        }
    }

    #[test]
    fn failed_dials_back_off_per_association_and_cap_at_sixty_seconds() {
        let owner = ConnectivityOwner::default();
        let reference = reference();
        let start = Instant::now();
        owner.states.lock().unwrap().insert(
            ConnectivityOwner::key(reference),
            DialState {
                generation: 0,
                in_flight: true,
                failures: 0,
                candidate_cursor: 0,
                retry_at: None,
                failure: None,
            },
        );
        for (failure, seconds) in [(1_u8, 5_u64), (2, 10), (3, 20), (4, 40), (5, 60), (6, 60)] {
            owner.complete(reference, 0, Err(None), start);
            let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
            assert_eq!(state.failures, failure);
            assert_eq!(
                state.retry_at,
                start.checked_add(Duration::from_secs(seconds))
            );
            owner
                .states
                .lock()
                .unwrap()
                .get_mut(&ConnectivityOwner::key(reference))
                .unwrap()
                .in_flight = true;
        }
    }

    #[test]
    fn successful_dial_resets_backoff() {
        let owner = ConnectivityOwner::default();
        let reference = reference();
        owner.states.lock().unwrap().insert(
            ConnectivityOwner::key(reference),
            DialState {
                generation: 0,
                in_flight: true,
                failures: 4,
                candidate_cursor: 0,
                retry_at: Some(Instant::now()),
                failure: Some(NativeDialFailure::NoAnswer),
            },
        );
        owner.complete(reference, 0, Ok(()), Instant::now());
        let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
        assert!(!state.in_flight);
        assert_eq!(state.failures, 0);
        assert_eq!(state.retry_at, None);
        assert_eq!(state.failure, None);
    }

    #[test]
    fn stale_network_completion_cannot_finish_or_penalize_new_dial() {
        let owner = ConnectivityOwner::default();
        let reference = reference();
        owner.states.lock().unwrap().insert(
            ConnectivityOwner::key(reference),
            DialState {
                generation: 2,
                in_flight: true,
                failures: 0,
                candidate_cursor: 0,
                retry_at: None,
                failure: None,
            },
        );
        for outcome in [Err(Some(NativeDialFailure::NoAnswer)), Ok(())] {
            owner.complete(reference, 1, outcome, Instant::now());
            let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
            assert!(state.in_flight);
            assert_eq!(state.failures, 0);
            assert_eq!(state.retry_at, None);
            assert_eq!(state.failure, None);
        }
    }

    #[tokio::test]
    async fn network_replacement_cancels_rendezvous_wait_without_ready_marker() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let network_stop = CancellationToken::new();
        let request = DialRequest {
            reference: reference(),
            address,
            alternatives: Vec::new(),
            route: [9; 32],
            generation: 4,
            network_stop: network_stop.clone(),
            recover_until: None,
        };
        let job = tokio::spawn(run_dial(Weak::new(), CancellationToken::new(), request));
        // Real rendezvous connection, deliberately no READY. Cancellation is
        // independent of a response or timeout from the old remote endpoint.
        let (_stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        network_stop.cancel();
        let completion = tokio::time::timeout(Duration::from_secs(1), job)
            .await
            .unwrap()
            .unwrap();
        // The replaced network says nothing about the PC.
        assert_eq!(completion.outcome, Err(None));
        assert_eq!(completion.generation, 4);
    }

    #[tokio::test]
    async fn already_cancelled_network_dial_never_opens_a_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let network_stop = CancellationToken::new();
        network_stop.cancel();
        let completion = run_dial(
            Weak::new(),
            CancellationToken::new(),
            DialRequest {
                reference: reference(),
                address: listener.local_addr().unwrap(),
                alternatives: Vec::new(),
                route: [9; 32],
                generation: 1,
                network_stop,
                recover_until: None,
            },
        )
        .await;
        assert_eq!(completion.outcome, Err(None));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stalled_primary_falls_back_to_one_alternative_carrier() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary = unavailable.local_addr().unwrap();
        // Keep this port owned and deliberately withhold READY. A closed port
        // may be reused by the alternate listener, and Windows connection-refusal
        // retries need not finish within the old two-second fixture deadline.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alternate = listener.local_addr().unwrap();
        assert_ne!(primary, alternate);
        let route = RouteId::new([11; 32]).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let expected = Registration::new(Role::Phone, route).to_wire();
            let mut bytes = vec![0; expected.len()];
            let mut read = 0;
            while read < bytes.len() {
                stream.readable().await.unwrap();
                match stream.try_read(&mut bytes[read..]) {
                    Ok(0) => panic!("closed before registration"),
                    Ok(count) => read += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => panic!("read: {error}"),
                }
            }
            assert_eq!(bytes, expected);
            let mut written = 0;
            while written < relay_service::READY_MARKER.len() {
                stream.writable().await.unwrap();
                match stream.try_write(&relay_service::READY_MARKER[written..]) {
                    Ok(0) => panic!("closed before ready"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(error) => panic!("write: {error}"),
                }
            }
            stream
        });
        let carrier = tokio::time::timeout(
            // The production per-candidate timeout is five seconds. Allow that
            // timeout plus the bounded alternate exchange; do not change it.
            Duration::from_secs(10),
            connect_candidates(primary, &[alternate], route, CancellationToken::new()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(carrier.into_stream().peer_addr().unwrap(), alternate);
        let _primary_connection =
            tokio::time::timeout(Duration::from_secs(1), unavailable.accept())
                .await
                .unwrap()
                .unwrap();
        drop(server.await.unwrap());
    }

    #[tokio::test]
    async fn loopback_dial_waits_for_ready_marker() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let route = [9; 32];
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let expected = Registration::new(Role::Phone, RouteId::new(route).unwrap()).to_wire();
            let mut registration = vec![0; expected.len()];
            let mut read = 0;
            while read < registration.len() {
                stream.readable().await.unwrap();
                match stream.try_read(&mut registration[read..]) {
                    Ok(0) => panic!("registration closed early"),
                    Ok(count) => read += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => panic!("registration read failed: {error}"),
                }
            }
            assert_eq!(registration, expected);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut written = 0;
            while written < relay_service::READY_MARKER.len() {
                stream.writable().await.unwrap();
                match stream.try_write(&relay_service::READY_MARKER[written..]) {
                    Ok(0) => panic!("ready marker closed early"),
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => panic!("ready marker write failed: {error}"),
                }
            }
        });
        let carrier = relay_service::connect_rendezvous(
            address,
            Registration::new(Role::Phone, RouteId::new(route).unwrap()),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        drop(carrier);
        server.await.unwrap();
    }

    #[test]
    fn rendezvous_errors_classify_by_how_far_the_dial_got() {
        for (error, expected) in [
            (RendezvousError::Cancelled, None),
            (
                RendezvousError::ConnectTimeout,
                Some(NativeDialFailure::Unreachable),
            ),
            (
                RendezvousError::Connection,
                Some(NativeDialFailure::Unreachable),
            ),
            (RendezvousError::Refused, Some(NativeDialFailure::Refused)),
            (RendezvousError::Closed, Some(NativeDialFailure::NoAnswer)),
            (
                RendezvousError::RendezvousTimeout,
                Some(NativeDialFailure::NoAnswer),
            ),
            (
                RendezvousError::InvalidMarker,
                Some(NativeDialFailure::NoAnswer),
            ),
        ] {
            assert_eq!(NativeDialFailure::classify(error), expected, "{error:?}");
        }
        assert!(NativeDialFailure::Unreachable < NativeDialFailure::Refused);
        assert!(NativeDialFailure::Refused < NativeDialFailure::NoAnswer);
    }

    #[test]
    fn failures_keep_the_furthest_until_a_carrier_attaches() {
        let owner = ConnectivityOwner::default();
        let reference = reference();
        owner.states.lock().unwrap().insert(
            ConnectivityOwner::key(reference),
            DialState {
                generation: 0,
                in_flight: true,
                failures: 0,
                candidate_cursor: 0,
                retry_at: None,
                failure: None,
            },
        );
        let failure = || owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)].failure;
        for (outcome, expected) in [
            (
                Err(Some(NativeDialFailure::Refused)),
                Some(NativeDialFailure::Refused),
            ),
            (
                Err(Some(NativeDialFailure::Unreachable)),
                Some(NativeDialFailure::Refused),
            ),
            // A local refusal or a replaced network shows nothing new.
            (Err(None), Some(NativeDialFailure::Refused)),
            (
                Err(Some(NativeDialFailure::NoAnswer)),
                Some(NativeDialFailure::NoAnswer),
            ),
            (Ok(()), None),
            (
                Err(Some(NativeDialFailure::Unreachable)),
                Some(NativeDialFailure::Unreachable),
            ),
        ] {
            owner.complete(reference, 0, outcome, Instant::now());
            assert_eq!(failure(), expected);
        }
    }

    #[test]
    fn only_unconnected_pcs_contribute_dialing_and_failure() {
        let owner = ConnectivityOwner::default();
        let (first, second, unknown) = (reference_for(7), reference_for(17), reference_for(27));
        for (reference, in_flight, failure) in [
            (first, true, Some(NativeDialFailure::Refused)),
            (second, false, Some(NativeDialFailure::NoAnswer)),
        ] {
            owner.states.lock().unwrap().insert(
                ConnectivityOwner::key(reference),
                DialState {
                    generation: 0,
                    in_flight,
                    failures: 1,
                    candidate_cursor: 0,
                    retry_at: None,
                    failure,
                },
            );
        }
        assert_eq!(
            owner.observe(&[(first, false), (second, false)]),
            (true, Some(NativeDialFailure::NoAnswer))
        );
        assert_eq!(
            owner.observe(&[(first, false), (second, true)]),
            (true, Some(NativeDialFailure::Refused))
        );
        assert_eq!(
            owner.observe(&[(first, true), (second, false)]),
            (false, Some(NativeDialFailure::NoAnswer))
        );
        assert_eq!(
            owner.observe(&[(first, true), (second, true)]),
            (false, None)
        );
        assert_eq!(owner.observe(&[(unknown, false)]), (false, None));
        assert_eq!(owner.observe(&[]), (false, None));
    }

    #[test]
    fn an_external_route_is_a_stored_global_address_other_than_the_relay() {
        let address = |text: &str| text.parse::<std::net::SocketAddr>().unwrap();
        let relay = Some(address("192.168.0.10:7443"));
        assert!(external_route(relay, &[address("8.8.8.8:7443")]));
        assert!(external_route(
            relay,
            &[address("192.168.0.10:7443"), address("[2400:cb00::1]:7443")]
        ));
        for local in [
            "192.168.0.10:7443",
            "10.0.0.2:7443",
            "172.16.4.1:7443",
            "169.254.1.1:7443",
            "100.64.0.1:7443",
            "192.0.2.1:7443",
            "198.18.0.1:7443",
            "198.51.100.1:7443",
            "203.0.113.7:7443",
            "240.0.0.1:7443",
            "[fd00::1]:7443",
            "[2001:db8::1]:7443",
            "[2002:c000:201::1]:7443",
            "[3fff::1]:7443",
        ] {
            assert!(!external_route(relay, &[address(local)]), "{local}");
        }
        assert!(!external_route(relay, &[]));
        // The relay itself is not a second route, and without one nothing is dialled.
        let public = address("8.8.8.8:7443");
        assert!(!external_route(Some(public), &[public]));
        assert!(!external_route(None, &[public]));
    }

    #[tokio::test]
    async fn a_relay_that_closes_before_ready_completes_as_no_answer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let expected = Registration::new(Role::Phone, RouteId::new([9; 32]).unwrap()).to_wire();
            let mut registration = vec![0; expected.len()];
            let mut read = 0;
            while read < registration.len() {
                stream.readable().await.unwrap();
                match stream.try_read(&mut registration[read..]) {
                    Ok(0) => panic!("registration closed early"),
                    Ok(count) => read += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => panic!("registration read failed: {error}"),
                }
            }
            assert_eq!(registration, expected);
            // Dropped here without READY.
        });
        let completion = tokio::time::timeout(
            Duration::from_secs(5),
            run_dial(
                Weak::new(),
                CancellationToken::new(),
                DialRequest {
                    reference: reference(),
                    address,
                    alternatives: Vec::new(),
                    route: [9; 32],
                    generation: 3,
                    network_stop: CancellationToken::new(),
                    recover_until: None,
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(completion.outcome, Err(Some(NativeDialFailure::NoAnswer)));
        server.await.unwrap();
    }

    fn dial_to(
        address: std::net::SocketAddr,
        recover_until: Option<Instant>,
        network_stop: CancellationToken,
    ) -> DialRequest {
        DialRequest {
            reference: reference(),
            address,
            alternatives: Vec::new(),
            route: [9; 32],
            generation: 5,
            network_stop,
            recover_until,
        }
    }

    /// One whole phone registration, read the way the relay reads it; None
    /// when the phone closed first.
    async fn registration(stream: &tokio::net::TcpStream) -> Option<Vec<u8>> {
        let expected = Registration::new(Role::Phone, RouteId::new([9; 32]).unwrap()).to_wire();
        let mut bytes = vec![0; expected.len()];
        let mut read = 0;
        while read < bytes.len() {
            stream.readable().await.ok()?;
            match stream.try_read(&mut bytes[read..]) {
                Ok(0) => return None,
                Ok(count) => read += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => return None,
            }
        }
        Some(bytes)
    }

    /// A relay that takes each registration and closes without READY. Returns
    /// how many connections it has accepted.
    fn relay_without_ready(
        listener: tokio::net::TcpListener,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = registration(&stream).await;
            }
        });
        accepted
    }

    #[test]
    fn a_dial_is_a_recovery_dial_only_before_its_first_failure() {
        let now = Instant::now();
        let state = |failures| DialState {
            generation: 0,
            in_flight: false,
            failures,
            candidate_cursor: 0,
            retry_at: None,
            failure: None,
        };
        assert_eq!(
            recovery_deadline(&state(0), now),
            now.checked_add(RECOVERY_WINDOW)
        );
        for failures in [1, 2, u8::MAX] {
            assert_eq!(recovery_deadline(&state(failures), now), None);
        }
    }

    #[tokio::test]
    async fn a_single_dial_makes_one_attempt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = relay_without_ready(listener);
        let completion = tokio::time::timeout(
            Duration::from_secs(5),
            run_dial(
                Weak::new(),
                CancellationToken::new(),
                dial_to(address, None, CancellationToken::new()),
            ),
        )
        .await
        .unwrap();
        assert_eq!(completion.outcome, Err(Some(NativeDialFailure::NoAnswer)));
        tokio::time::sleep(RECOVERY_SPACING + Duration::from_millis(500)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_recovery_dial_retries_until_its_window_ends() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = relay_without_ready(listener);
        let began = Instant::now();
        let completion = tokio::time::timeout(
            Duration::from_secs(10),
            run_dial(
                Weak::new(),
                CancellationToken::new(),
                dial_to(
                    address,
                    Some(began + Duration::from_millis(2_500)),
                    CancellationToken::new(),
                ),
            ),
        )
        .await
        .unwrap();
        let elapsed = began.elapsed();
        assert_eq!(completion.outcome, Err(Some(NativeDialFailure::NoAnswer)));
        // Attempts start at about 0, 1 and 2 s; a fourth would start after the window.
        assert!(
            elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(6),
            "took {elapsed:?}"
        );
        let attempts = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert!(attempts >= 3, "{attempts} attempts");
    }

    #[tokio::test]
    async fn a_recovery_dial_reaches_a_relay_that_starts_listening_later() {
        // Nothing listens here until the relay "restarts" below.
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        drop(reserved);
        let began = Instant::now();
        let dial = tokio::spawn(run_dial(
            Weak::new(),
            CancellationToken::new(),
            dial_to(
                address,
                Some(began + Duration::from_secs(20)),
                CancellationToken::new(),
            ),
        ));
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let rebind_limit = Instant::now() + Duration::from_secs(1);
        let listener = loop {
            match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => break listener,
                Err(error) => {
                    assert!(Instant::now() < rebind_limit, "rebind {address}: {error}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            registration(&stream).await.unwrap(),
            Registration::new(Role::Phone, RouteId::new([9; 32]).unwrap()).to_wire()
        );
        let mut written = 0;
        while written < relay_service::READY_MARKER.len() {
            stream.writable().await.unwrap();
            match stream.try_write(&relay_service::READY_MARKER[written..]) {
                Ok(0) => panic!("ready marker closed early"),
                Ok(count) => written += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("ready marker write failed: {error}"),
            }
        }
        let completion = tokio::time::timeout(Duration::from_secs(10), dial)
            .await
            .unwrap()
            .unwrap();
        // There is no controller to attach to: a local refusal shows nothing.
        assert_eq!(completion.outcome, Err(None));
        assert!(
            began.elapsed() < Duration::from_secs(12),
            "took {:?}",
            began.elapsed()
        );
        drop(stream);
    }

    #[tokio::test]
    async fn a_network_change_ends_a_recovery_dial_between_attempts() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = relay_without_ready(listener);
        let network_stop = CancellationToken::new();
        let dial = tokio::spawn(run_dial(
            Weak::new(),
            CancellationToken::new(),
            dial_to(
                address,
                Some(Instant::now() + Duration::from_secs(60)),
                network_stop.clone(),
            ),
        ));
        let limit = Instant::now() + Duration::from_secs(5);
        while accepted.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(Instant::now() < limit, "the first attempt never arrived");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The relay closes at once, so the dial is now waiting for its next attempt.
        tokio::time::sleep(Duration::from_millis(200)).await;
        network_stop.cancel();
        let cancelled = Instant::now();
        let completion = tokio::time::timeout(Duration::from_secs(2), dial)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(completion.outcome, Err(None));
        assert!(cancelled.elapsed() < Duration::from_secs(2));
    }
}
