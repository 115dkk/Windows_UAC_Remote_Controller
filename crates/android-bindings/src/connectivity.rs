// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded relay dialing for current durable associations.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

use android_controller::{MAX_PEER_ASSOCIATIONS, PeerAssociationRef};
use relay_service::{Registration, Role, RouteId};
use tokio_util::sync::CancellationToken;

use crate::{BridgeError, MobileController};

const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct NativeConnectivityStatus {
    pub associations: u32,
    pub connected: u32,
    pub dialing: u32,
    pub without_endpoint: u32,
}

#[derive(Clone, Copy)]
pub(super) struct DialState {
    pub(super) generation: u64,
    pub(super) in_flight: bool,
    pub(super) failures: u8,
    pub(super) candidate_cursor: usize,
    pub(super) retry_at: Option<Instant>,
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
        succeeded: bool,
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
        if succeeded {
            state.failures = 0;
            state.retry_at = None;
        } else {
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

pub(crate) struct DialRequest {
    pub(crate) reference: PeerAssociationRef,
    pub(crate) address: std::net::SocketAddr,
    pub(crate) alternatives: Vec<std::net::SocketAddr>,
    pub(crate) route: [u8; 32],
    generation: u64,
    network_stop: CancellationToken,
}

pub(crate) struct DialCompletion {
    pub(crate) reference: PeerAssociationRef,
    pub(crate) succeeded: bool,
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
                completion.succeeded,
                completion.completed_at,
            );
        }
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
                    });
                if self.intake.has_live_peer(*reference) {
                    if self.intake.has_connected_peer(*reference) {
                        connected += 1;
                    }
                    state.failures = 0;
                    state.retry_at = None;
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
                });
            }
        }
        for request in requests {
            if let Err(request) = self.intake.spawn_dial(request) {
                self.connectivity
                    .complete(request.reference, request.generation, false, now);
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
    // Only the rendezvous wait is asynchronous; stream admission below is a
    // separate synchronous phase, not a closure inside a select! expansion.
    // The production JoinSet::spawn call checks the future's Send bound.
    let carrier = match RouteId::new(request.route) {
        Ok(route) => request
            .network_stop
            .clone()
            .run_until_cancelled_owned(connect_candidates(
                request.address,
                &request.alternatives,
                route,
                intake_stop,
            ))
            .await
            .flatten(),
        Err(_) => None,
    };
    // The combinator drops the old network's pending socket on cancellation.
    // Simultaneous completion/cancellation may return a carrier; attachment
    // still checks this exact token AFTER acquiring owner admission, so it
    // cannot revive the old transport generation.
    let succeeded = carrier
        .and_then(|carrier| carrier.into_stream().into_std().ok())
        .and_then(|stream| {
            stream.set_nonblocking(false).ok()?;
            Weak::<MobileController>::upgrade(&controller)?
                .attach_network_stream(request.reference, stream, &request.network_stop)
                .ok()
        })
        .is_some();
    DialCompletion {
        reference: request.reference,
        succeeded,
        generation: request.generation,
        completed_at: Instant::now(),
    }
}

/// Only carrier discovery is retried. TLS signing, requests and decisions are
/// never replayed across candidates. Each failed/timed-out future drops its socket.
pub(crate) async fn connect_candidates(
    primary: std::net::SocketAddr,
    alternatives: &[std::net::SocketAddr],
    route: RouteId,
    stop: CancellationToken,
) -> Option<relay_service::RendezvousCarrier> {
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
        .await
        .ok();
    }
    for address in addresses {
        if stop.is_cancelled() {
            return None;
        }
        if let Ok(Ok(carrier)) = tokio::time::timeout(
            Duration::from_secs(5),
            relay_service::connect_rendezvous(
                address,
                Registration::new(Role::Phone, route),
                stop.clone(),
            ),
        )
        .await
        {
            return Some(carrier);
        }
    }
    None
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    fn reference() -> PeerAssociationRef {
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
                    approval_protocol::PcIdentity::from_bytes([7; 32]).unwrap(),
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
            },
        );
        for (failure, seconds) in [(1_u8, 5_u64), (2, 10), (3, 20), (4, 40), (5, 60), (6, 60)] {
            owner.complete(reference, 0, false, start);
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
            },
        );
        owner.complete(reference, 0, true, Instant::now());
        let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
        assert!(!state.in_flight);
        assert_eq!(state.failures, 0);
        assert_eq!(state.retry_at, None);
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
            },
        );
        for succeeded in [false, true] {
            owner.complete(reference, 1, succeeded, Instant::now());
            let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
            assert!(state.in_flight);
            assert_eq!(state.failures, 0);
            assert_eq!(state.retry_at, None);
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
        assert!(!completion.succeeded);
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
            },
        )
        .await;
        assert!(!completion.succeeded);
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
}
