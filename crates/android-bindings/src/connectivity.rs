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
    pub(super) in_flight: bool,
    pub(super) failures: u8,
    pub(super) retry_at: Option<Instant>,
}

pub(crate) struct ConnectivityOwner {
    pub(super) states: Mutex<BTreeMap<(approval_protocol::PcIdentity, u64), DialState>>,
    stop: CancellationToken,
}

impl Default for ConnectivityOwner {
    fn default() -> Self {
        Self {
            states: Mutex::new(BTreeMap::new()),
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

    fn complete(&self, reference: PeerAssociationRef, succeeded: bool, now: Instant) {
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(state) = states.get_mut(&Self::key(reference)) else {
            return;
        };
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
    pub(crate) route: [u8; 32],
}

pub(crate) struct DialCompletion {
    pub(crate) reference: PeerAssociationRef,
    pub(crate) succeeded: bool,
}

/// One durable association with its optional relay address and route.
type AssociationRelay = (PeerAssociationRef, Option<(std::net::SocketAddr, [u8; 32])>);

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
                .map(|association| (association.reference(), association.descriptor().relay()))
                .collect())
        })
    }

    fn receive_dial_completions(&self) {
        for completion in self.intake.take_dial_completions() {
            self.connectivity
                .complete(completion.reference, completion.succeeded, Instant::now());
        }
    }
}

#[uniffi::export]
impl MobileController {
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
                    .any(|(reference, _)| *key == ConnectivityOwner::key(*reference))
            });
            for (reference, endpoint) in &associations {
                let Some((address, route)) = endpoint else {
                    without_endpoint += 1;
                    continue;
                };
                let state = states
                    .entry(ConnectivityOwner::key(*reference))
                    .or_insert(DialState {
                        in_flight: false,
                        failures: 0,
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
                requests.push(DialRequest {
                    reference: *reference,
                    address: *address,
                    route: *route,
                });
            }
        }
        for request in requests {
            if let Err(request) = self.intake.spawn_dial(request) {
                self.connectivity.complete(request.reference, false, now);
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
    let succeeded = match RouteId::new(request.route) {
        Ok(route) => relay_service::connect_rendezvous(
            request.address,
            Registration::new(Role::Phone, route),
            intake_stop,
        )
        .await
        .ok()
        .and_then(|carrier| carrier.into_stream().into_std().ok())
        .and_then(|stream| {
            stream.set_nonblocking(false).ok()?;
            Weak::<MobileController>::upgrade(&controller)?
                .attach_provisioned_stream(request.reference, stream)
                .ok()
        })
        .is_some(),
        Err(_) => false,
    };
    DialCompletion {
        reference: request.reference,
        succeeded,
    }
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
                in_flight: true,
                failures: 0,
                retry_at: None,
            },
        );
        for (failure, seconds) in [(1_u8, 5_u64), (2, 10), (3, 20), (4, 40), (5, 60), (6, 60)] {
            owner.complete(reference, false, start);
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
                in_flight: true,
                failures: 4,
                retry_at: Some(Instant::now()),
            },
        );
        owner.complete(reference, true, Instant::now());
        let state = owner.states.lock().unwrap()[&ConnectivityOwner::key(reference)];
        assert!(!state.in_flight);
        assert_eq!(state.failures, 0);
        assert_eq!(state.retry_at, None);
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
