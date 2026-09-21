// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host TLS/socket and durable-state tests with synthetic keys/identities.
//! These are not Android Keystore, device networking or UAC acceptance evidence.
use super::*;
use service_protocol::{
    AddressAdvertisementFields, AddressQuery, ClockProbeNonce, UnsignedAddressAdvertisement,
};

async fn routed_pair(
    temp: &tempfile::TempDir,
    clock: &Arc<HostClock>,
) -> (DurableInbox, PeerAssociationRef, Pair) {
    let (mut owner, old) = owner(temp, clock);
    owner
        .revoke_peer_association_from_trusted_host(old)
        .unwrap();
    let reference = reference(
        owner
            .record_peer_association_from_trusted_host(
                association()
                    .with_relay("192.0.2.1:443".parse().unwrap(), [40; 32])
                    .unwrap(),
            )
            .unwrap()
            .1,
    );
    let mut pair = pair(
        &owner,
        reference,
        Arc::clone(clock),
        CancellationToken::new(),
        Arc::new(ConnectionBudget::new(2).unwrap()),
    )
    .await;
    let clock_event = initial_clock(&mut pair, &owner, clock, PC_SIGNING_KEY)
        .await
        .unwrap();
    pair.phone
        .apply_event(&mut owner, clock_event, clock.inbox())
        .unwrap();
    (owner, reference, pair)
}

async fn exchange(
    pair: &mut Pair,
    mutation: u8,
) -> Result<android_controller::ReceivedAddressAdvertisement, PeerSocketError> {
    exchange_wire(pair, mutation)
        .await
        .map(|(message, _)| message)
}

async fn exchange_wire(
    pair: &mut Pair,
    mutation: u8,
) -> Result<(android_controller::ReceivedAddressAdvertisement, Vec<u8>), PeerSocketError> {
    let pc = async {
        let query = loop {
            if let SocketEvent::Frame(frame) = pair.pc.next_event().await.unwrap() {
                break AddressQuery::from_wire(&frame.into_bytes()).unwrap();
            }
        };
        let mut fields = AddressAdvertisementFields {
            pc: query.pc,
            epoch: epoch(),
            device: query.device,
            route: query.route,
            nonce: query.nonce,
            valid_for_seconds: 1,
            endpoints: vec!["198.51.100.4:443".parse().unwrap()],
        };
        match mutation {
            1 => fields.nonce = ClockProbeNonce::from_bytes([66; 32]).unwrap(),
            2 => fields.pc = PcIdentity::from_bytes([66; 32]).unwrap(),
            3 => fields.device = DeviceId::from_bytes([66; 16]).unwrap(),
            4 => fields.route = [66; 32],
            5 => fields.epoch = BootEpoch::from_bytes([66; 32]).unwrap(),
            7 => {
                fields.valid_for_seconds = 0;
                fields.endpoints.clear();
            }
            10..=14 => {
                fields.valid_for_seconds = u32::from(mutation - 10);
                if mutation == 10 {
                    fields.endpoints.clear();
                }
            }
            _ => (),
        }
        let unsigned = UnsignedAddressAdvertisement::new(fields).unwrap();
        let key =
            SigningKey::from_slice(&[if mutation == 6 { 99 } else { PC_SIGNING_KEY }; 32]).unwrap();
        let signature: Signature = key.sign(&unsigned.signing_bytes());
        let signed = unsigned
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap();
        pair.pc
            .queue_frame(encode_frame(&signed.to_wire()).unwrap())
            .unwrap();
        loop {
            if matches!(
                pair.pc.next_event().await.unwrap(),
                SocketEvent::OutboundDrained
            ) {
                break;
            }
        }
        signed.to_wire()
    };
    let phone = async {
        loop {
            match pair.phone.next_event().await? {
                PcSocketEvent::Addresses(message) => return Ok(*message),
                PcSocketEvent::OutboundDrained => (),
                other => panic!("unexpected address exchange: {other:?}"),
            }
        }
    };
    let (wire, message) = tokio::join!(pc, phone);
    message.map(|message| (message, wire))
}

fn at_nanos(nanos: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(nanos / MILLI),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        nanos,
    )
    .unwrap()
}

#[tokio::test]
async fn withdrawal_and_short_ttls_do_not_query_inside_server_rate_limit() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for ttl in 0..=4 {
            let temp = tempfile::tempdir().unwrap();
            let clock = HostClock::new();
            let (mut owner, _, mut pair) = routed_pair(&temp, &clock).await;
            pair.phone
                .refresh_routing_candidates(&owner, clock.inbox())
                .unwrap();
            let message = exchange(&mut pair, 10 + ttl).await.unwrap();
            let received = clock.inbox();
            pair.phone
                .apply_routing_candidates(&mut owner, message, received)
                .unwrap();
            let before = pair.phone.pending_counts();
            for seconds in 0..=5 {
                pair.phone
                    .refresh_routing_candidates(
                        &owner,
                        at_nanos(received.phone_monotonic_nanos() + seconds * 1_000_000_000),
                    )
                    .unwrap();
                assert_eq!(
                    pair.phone.pending_counts(),
                    before,
                    "TTL {ttl}, elapsed {seconds}"
                );
            }
            pair.phone
                .refresh_routing_candidates(
                    &owner,
                    at_nanos(received.phone_monotonic_nanos() + 6_000_000_000),
                )
                .unwrap();
            assert_ne!(pair.phone.pending_counts(), before);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unanswered_query_expires_and_late_response_cannot_answer_fresh_nonce() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
        let sent = clock.inbox();
        pair.phone.refresh_routing_candidates(&owner, sent).unwrap();
        // Queued receipt has not been applied: the old exchange is still pending.
        let delayed = exchange(&mut pair, 0).await.unwrap();
        let before = pair.phone.pending_counts();
        let later = at_nanos(sent.phone_monotonic_nanos() + 11_000_000_000);
        pair.phone
            .refresh_routing_candidates(&owner, later)
            .unwrap();
        assert_ne!(pair.phone.pending_counts(), before);
        assert_eq!(
            pair.phone
                .apply_routing_candidates(&mut owner, delayed, later),
            Err(PeerSocketError::AddressContext)
        );
        assert!(
            owner
                .peer_associations()
                .unwrap()
                .routing_candidates(reference)
                .is_empty()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn signed_hints_are_routing_only_and_survive_reboot_without_reviving_request_authority() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
        let association = owner
            .peer_associations()
            .unwrap()
            .resolve(reference)
            .unwrap()
            .clone();
        let counts = owner.counts().unwrap();
        pair.phone
            .refresh_routing_candidates(&owner, clock.inbox())
            .unwrap();
        let message = exchange(&mut pair, 0).await.unwrap();
        pair.phone
            .apply_routing_candidates(&mut owner, message, clock.inbox())
            .unwrap();
        pair.phone.check_current(&owner).unwrap();
        assert_eq!(
            owner.peer_associations().unwrap().resolve(reference),
            Some(&association)
        );
        assert_eq!(owner.counts().unwrap(), counts);
        drop(pair);
        drop(owner);
        let (owner, update) = DurableInbox::open_existing_host_model(
            directory(&temp),
            PhoneBootId::from_native_boot_count(6).unwrap(),
            clock.inbox(),
        )
        .unwrap();
        assert_eq!(
            owner
                .peer_associations()
                .unwrap()
                .routing_candidates(reference),
            ["198.51.100.4:443".parse::<std::net::SocketAddr>().unwrap()]
        );
        assert!(
            update
                .update()
                .effects()
                .iter()
                .all(|effect| !matches!(effect, Effect::Show(_)))
        );
        assert_eq!(
            owner.peer_associations().unwrap().resolve(reference),
            Some(&association)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_signature_or_any_query_context_cannot_replace_coordinates() {
    tokio::time::timeout(TEST_DEADLINE, async {
        for mutation in 1..=6 {
            let temp = tempfile::tempdir().unwrap();
            let clock = HostClock::new();
            let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
            pair.phone
                .refresh_routing_candidates(&owner, clock.inbox())
                .unwrap();
            let result = exchange(&mut pair, mutation).await;
            if mutation == 6 {
                assert!(result.is_err());
            } else {
                assert!(
                    pair.phone
                        .apply_routing_candidates(&mut owner, result.unwrap(), clock.inbox())
                        .is_err()
                );
            }
            assert!(
                owner
                    .peer_associations()
                    .unwrap()
                    .routing_candidates(reference)
                    .is_empty()
            );
            assert!(owner.fault().is_none());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_hint_cannot_mutate_reenrollment_and_expired_query_cannot_refresh_cache() {
    tokio::time::timeout(TEST_DEADLINE, async {
        for replace in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let clock = HostClock::new();
            let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
            pair.phone
                .refresh_routing_candidates(&owner, clock.inbox())
                .unwrap();
            let message = exchange(&mut pair, 0).await.unwrap();
            let now = if replace {
                let descriptor = owner
                    .peer_associations()
                    .unwrap()
                    .resolve(reference)
                    .unwrap()
                    .descriptor()
                    .clone();
                owner
                    .revoke_peer_association_from_trusted_host(reference)
                    .unwrap();
                owner
                    .record_peer_association_from_trusted_host(descriptor)
                    .unwrap();
                clock.inbox()
            } else {
                InboxClock::new(
                    ClockReading::new(
                        MonotonicTime::from_millis(20_000),
                        LocalTime::new(Weekday::Monday, 600).unwrap(),
                    ),
                    20_000_000_000,
                )
                .unwrap()
            };
            assert!(
                pair.phone
                    .apply_routing_candidates(&mut owner, message, now)
                    .is_err()
            );
            let current = owner
                .peer_associations()
                .unwrap()
                .lookup_current(pc())
                .unwrap()
                .reference();
            assert!(
                owner
                    .peer_associations()
                    .unwrap()
                    .routing_candidates(current)
                    .is_empty()
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_withdrawal_removes_last_known_coordinates() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
        owner
            .record_routing_candidates(reference, vec!["198.51.100.9:443".parse().unwrap()])
            .unwrap();
        pair.phone
            .refresh_routing_candidates(&owner, clock.inbox())
            .unwrap();
        let message = exchange(&mut pair, 7).await.unwrap();
        pair.phone
            .apply_routing_candidates(&mut owner, message, clock.inbox())
            .unwrap();
        assert!(
            owner
                .peer_associations()
                .unwrap()
                .routing_candidates(reference)
                .is_empty()
        );
        pair.phone.check_current(&owner).unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn replayed_signed_hint_cannot_rearm_consumed_exchange() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference, mut pair) = routed_pair(&temp, &clock).await;
        pair.phone
            .refresh_routing_candidates(&owner, clock.inbox())
            .unwrap();
        let (message, wire) = exchange_wire(&mut pair, 0).await.unwrap();
        pair.phone
            .apply_routing_candidates(&mut owner, message, clock.inbox())
            .unwrap();
        let before = owner
            .peer_associations()
            .unwrap()
            .routing_candidates(reference)
            .to_vec();
        pair.pc.queue_frame(encode_frame(&wire).unwrap()).unwrap();
        let send = async {
            loop {
                if matches!(
                    pair.pc.next_event().await.unwrap(),
                    SocketEvent::OutboundDrained
                ) {
                    break;
                }
            }
        };
        let receive = async {
            loop {
                match pair.phone.next_event().await {
                    Ok(PcSocketEvent::OutboundDrained) => (),
                    Err(error) => return error,
                    other => panic!("replay escaped consumption: {other:?}"),
                }
            }
        };
        let (_, error) = tokio::join!(send, receive);
        assert_eq!(error, PeerSocketError::AddressContext);
        assert_eq!(
            owner
                .peer_associations()
                .unwrap()
                .routing_candidates(reference),
            before
        );
    })
    .await
    .unwrap();
}
