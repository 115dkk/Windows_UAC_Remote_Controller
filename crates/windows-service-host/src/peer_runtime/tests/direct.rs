// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TCP/pinned TLS/framing with synthetic keys and registry. These tests
//! exercise routing dispatch only, not router mapping, hardware or UAC consent.
use super::*;
use service_protocol::{AddressQuery, ClockProbeNonce, SignedAddressAdvertisement};

fn route() -> relay_service::RouteId {
    relay_service::RouteId::new([41; 32]).unwrap()
}

fn install_route(session: &mut ServiceSession<'_>, registry: &Rc<RefCell<RegistryFixture>>) {
    let relay = "192.168.1.50:7443".parse().unwrap();
    registry
        .borrow_mut()
        .routes
        .insert(device(1), (relay, route()));
    #[cfg(all(windows, target_pointer_width = "64"))]
    {
        session.network.install_route_fixture(relay);
    }
    let _ = session;
}

fn query(session: &ServiceSession<'_>) -> AddressQuery {
    AddressQuery::new(
        session.engine.pc_identity(),
        device(1),
        *route().as_bytes(),
        ClockProbeNonce::from_bytes([42; 32]).unwrap(),
    )
    .unwrap()
}

fn interactive_client(
    client: TcpStream,
    server_key: TlsPublicKey,
    first: Vec<u8>,
) -> (Client, async_mpsc::Sender<Vec<u8>>) {
    let (send, notices) = mpsc::sync_channel(16);
    let (commands, mut receive) = async_mpsc::channel::<Vec<u8>>(4);
    let thread = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = runtime.block_on(async {
            tokio::time::timeout(TEST_LIMIT, async {
                client.set_nonblocking(true).unwrap();
                let identity = TlsIdentity::from_trusted_host(EndpointRole::Client, Arc::new(PhoneSigner::new(5))).unwrap();
                let transport = PeerTransport::client(Arc::new(ConnectionBudget::new(1).unwrap()), identity, server_key, Instant::now()).unwrap();
                let mut driver = SocketDriver::new(tokio::net::TcpStream::from_std(client).unwrap(), transport, Arc::new(ServiceClock), SocketLimits::default(), CancellationToken::new()).unwrap();
                loop {
                    tokio::select! {
                        event = driver.next_event() => match event {
                            Ok(SocketEvent::Ready) => {
                                send.send(Notice::Ready).unwrap();
                                driver.queue_frame(encode_frame(&first).unwrap()).unwrap();
                            }
                            Ok(SocketEvent::Frame(frame)) => { send.send(Notice::Frame(frame.into_bytes())).unwrap(); }
                            Ok(SocketEvent::OutboundDrained) => (),
                            _ => break,
                        },
                        Some(bytes) = receive.recv() => { driver.queue_frame(encode_frame(&bytes).unwrap()).unwrap(); }
                    }
                }
            }).await
        });
        let _ = send.send(Notice::Closed);
    });
    (
        Client {
            notices,
            thread: Some(thread),
        },
        commands,
    )
}

fn ready(
    session: &mut ServiceSession<'_>,
    key: &Identity,
    clients: &mut Vec<Client>,
) -> async_mpsc::Sender<Vec<u8>> {
    let (server, client) = streams();
    session
        .attach_carrier(ServicePeerCarrier {
            stream: server,
            device: device(1),
        })
        .unwrap();
    let probe = ClockProbe::start(session.engine.pc_identity(), 0).unwrap();
    let (client, commands) = interactive_client(
        client,
        key.public.clone(),
        probe.request().to_wire().to_vec(),
    );
    clients.push(client);
    drive_until(session, |progress| {
        progress == SessionProgress::ClockDrained
    });
    assert_eq!(
        session.peers[0].protocol,
        Some(secure_channel::ControlProtocol::V3)
    );
    commands
}

fn advertisement(session: &mut ServiceSession<'_>, client: &Client) -> SignedAddressAdvertisement {
    let limit = Instant::now() + TEST_LIMIT;
    loop {
        assert!(
            Instant::now() < limit,
            "signed routing response not delivered"
        );
        session.process_one().unwrap();
        while let Ok(notice) = client.notices.try_recv() {
            if let Notice::Frame(bytes) = notice
                && let Ok(value) = SignedAddressAdvertisement::from_wire(&bytes)
            {
                return value;
            }
        }
        thread::yield_now();
    }
}

#[test]
fn routing_query_returns_context_bound_signed_withdrawal_without_authorizing_requests() {
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let commands = ready(session, key, clients);
        let query = query(session);
        commands.try_send(query.to_wire()).unwrap();
        let signed = advertisement(session, &clients[0]);
        let verified = signed
            .verify(&PcPublicKey::from_spki_der(key.public.as_spki_der()).unwrap())
            .unwrap();
        let fields = verified.fields();
        assert_eq!(fields.pc, query.pc);
        assert_eq!(fields.device, query.device);
        assert_eq!(fields.route, query.route);
        assert_eq!(fields.nonce, query.nonce);
        assert_eq!(fields.epoch, session.engine.boot_epoch());
        assert_eq!(fields.valid_for_seconds, 0);
        assert!(fields.endpoints.is_empty());
        assert!(session.prompt.live().is_none());
        assert!(session.peers[0].state.live());
        commands.try_send(query.to_wire()).unwrap();
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
    });
}

#[test]
fn routing_query_rejects_wrong_pc_device_route_and_stale_registered_route() {
    for mutation in 0..4 {
        exercise(|session, key, registry, clients| {
            install_route(session, &registry);
            let commands = ready(session, key, clients);
            let mut query = query(session);
            match mutation {
                0 => query.pc = PcIdentity::from_bytes([99; 32]).unwrap(),
                1 => query.device = device(2),
                2 => query.route = [99; 32],
                3 => {
                    registry.borrow_mut().routes.get_mut(&device(1)).unwrap().1 =
                        relay_service::RouteId::new([99; 32]).unwrap()
                }
                _ => unreachable!(),
            }
            commands.try_send(query.to_wire()).unwrap();
            drive_until(session, |progress| {
                progress == SessionProgress::PeerRejected
            });
            assert!(session.peers.iter().all(|peer| {
                peer.responses_in_flight
                    .iter()
                    .all(|(_, _, kind)| *kind != ResponseKind::Addresses)
            }));
        });
    }
}

#[test]
fn routing_query_requires_clock_and_v2_capability() {
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let (server, client) = streams();
        let query = query(session);
        session
            .attach_carrier(ServicePeerCarrier {
                stream: server,
                device: device(1),
            })
            .unwrap();
        clients.push(raw_client(
            client,
            key.public.clone(),
            5,
            vec![query.to_wire()],
        ));
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
    });
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let commands = ready(session, key, clients);
        // Dispatch-gate fixture only. Actual legacy TLS negotiation is exercised
        // by secure-channel's real V1 client/server compatibility byte pumps.
        session.peers[0].protocol = Some(secure_channel::ControlProtocol::V1);
        commands.try_send(query(session).to_wire()).unwrap();
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
    });
}

#[test]
fn registry_route_change_after_signing_retires_before_address_queue() {
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let commands = ready(session, key, clients);
        *key.after_protocol.borrow_mut() = Some(Box::new(move || {
            registry.borrow_mut().routes.get_mut(&device(1)).unwrap().1 =
                relay_service::RouteId::new([99; 32]).unwrap();
        }));
        commands.try_send(query(session).to_wire()).unwrap();
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
        assert!(session.peers.iter().all(|peer| {
            peer.responses_in_flight
                .iter()
                .all(|(_, _, kind)| *kind != ResponseKind::Addresses)
        }));
    });
}

#[test]
fn peer_retired_during_address_signature_is_rejected_without_closing_session() {
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let commands = ready(session, key, clients);
        let state = Arc::clone(&session.peers[0].state);
        let retire_during_signature = Arc::clone(&state);
        *key.after_protocol.borrow_mut() = Some(Box::new(move || {
            retire_during_signature.retire();
        }));

        commands.try_send(query(session).to_wire()).unwrap();
        drive_until(session, |progress| {
            progress == SessionProgress::PeerRejected
        });
        assert!(!state.live());
        assert!(!session.closing);
        assert!(session.peers[0].responses_in_flight.is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn routing_mode_withdrawal_retires_output_guards_and_status_contains_no_coordinates() {
    exercise(|session, key, registry, clients| {
        install_route(session, &registry);
        let _commands = ready(session, key, clients);
        let state = Arc::clone(&session.peers[0].state);
        assert!(!state.is_revoked());
        session.withdraw_relay();
        assert!(state.is_revoked());
        assert_eq!(session.current_direct_candidates(), (Vec::new(), 0));
        let response = session
            .handle_management(
                crate::ffi::ManagementClientClass::GuiMedium,
                crate::management_protocol::ManagementRequest::QueryDirect,
            )
            .unwrap();
        assert!(matches!(
            response,
            Some(crate::management_protocol::ManagementResponse::DirectStatus { .. })
        ));
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn watcher_read_is_a_medium_client_query_of_current_health() {
    use crate::{
        ffi::ManagementClientClass,
        management_protocol::{
            ManagementRequest, ManagementResponse, WatcherHealth, WatcherRefusal,
        },
    };
    exercise(|session, _, _, _| {
        assert_eq!(
            session
                .handle_management(
                    ManagementClientClass::GuiMedium,
                    ManagementRequest::QueryWatcher,
                )
                .unwrap(),
            Some(ManagementResponse::WatcherStatus {
                health: WatcherHealth::Starting,
            })
        );
        session.set_watcher_health(WatcherHealth::Unavailable(WatcherRefusal::HelperDamaged));
        assert_eq!(
            session
                .handle_management(
                    ManagementClientClass::GuiMedium,
                    ManagementRequest::QueryWatcher,
                )
                .unwrap(),
            Some(ManagementResponse::WatcherStatus {
                health: WatcherHealth::Unavailable(WatcherRefusal::HelperDamaged),
            })
        );
        session.set_watcher_health(WatcherHealth::Running);
        assert_eq!(
            session
                .handle_management(
                    ManagementClientClass::GuiMedium,
                    ManagementRequest::QueryWatcher,
                )
                .unwrap(),
            Some(ManagementResponse::WatcherStatus {
                health: WatcherHealth::Running,
            })
        );
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn external_status(
    session: &mut ServiceSession<'_>,
    class: crate::ffi::ManagementClientClass,
) -> crate::management_protocol::ManagementResponse {
    session
        .handle_management(
            class,
            crate::management_protocol::ManagementRequest::QueryExternal,
        )
        .unwrap()
        .expect("the external read replies synchronously")
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn external_read_is_a_gui_query_and_its_mutation_is_elevated_cli_only() {
    use crate::{
        ffi::ManagementClientClass,
        management_protocol::{ManagementRequest, ManagementResponse},
    };
    use direct_network::ExternalAccess;
    exercise(|session, _, _, _| {
        // No gateway owner: the configured mode only, no observation.
        let status = external_status(session, ManagementClientClass::GuiMedium);
        assert_eq!(
            status,
            ManagementResponse::ExternalStatus {
                access: ExternalAccess::Automatic,
                external: None,
                source: None,
                failure: None,
                lan: None,
                forward_origin: None,
            }
        );
        crate::management_protocol::encode_response(&status).unwrap();
        let forward = ExternalAccess::RouterForward {
            external_port: 8443,
        };
        session.use_external_access(crate::external_access::ExternalAccessSetting {
            access: forward,
            forward_origin: None,
        });
        assert!(matches!(
            external_status(session, ManagementClientClass::GuiMedium),
            ManagementResponse::ExternalStatus { access, .. } if access == forward
        ));
        let fixed = ExternalAccess::Fixed {
            address: "93.184.216.34:7443".parse().unwrap(),
        };
        // A medium GUI client cannot change it.
        assert!(matches!(
            session
                .handle_management(
                    ManagementClientClass::GuiMedium,
                    ManagementRequest::SetExternalAccess { access: fixed },
                )
                .unwrap(),
            Some(ManagementResponse::Refused(_))
        ));
        // Outside the real service the protected write is refused, and a
        // choice that was not persisted is not applied either.
        assert!(matches!(
            session
                .handle_management(
                    ManagementClientClass::CliElevated,
                    ManagementRequest::SetExternalAccess { access: fixed },
                )
                .unwrap(),
            Some(ManagementResponse::Refused(_))
        ));
        assert_eq!(session.network.observe().access, forward);
        assert_eq!(session.network.observe().forward_origin, None);
    });
}

// Hint refresh: a connected phone learns addresses only by asking, so the PC
// ends the connection of one holding stale hints. A fixed reading replaces the
// gateway owner, and time moves only when the test moves it.

#[cfg(all(windows, target_pointer_width = "64"))]
const LAN: &str = "192.168.219.103:7443";
#[cfg(all(windows, target_pointer_width = "64"))]
const EXTERNAL: &str = "203.0.113.9:7443";

#[cfg(all(windows, target_pointer_width = "64"))]
fn reading(
    state: direct_network::DirectGatewayState,
    candidates: &[&str],
    external: Option<&str>,
) -> crate::peer_runtime::network::GatewayReading {
    crate::peer_runtime::network::GatewayReading {
        access: direct_network::ExternalAccess::Automatic,
        state,
        candidates: candidates
            .iter()
            .map(|value| value.parse().unwrap())
            .collect(),
        validity_seconds: if candidates.is_empty() { 0 } else { 60 },
        external: external.map(|value| value.parse().unwrap()),
        source: None,
        failure: None,
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn lan_only() -> crate::peer_runtime::network::GatewayReading {
    reading(direct_network::DirectGatewayState::LanOnly, &[LAN], None)
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn mapped() -> crate::peer_runtime::network::GatewayReading {
    reading(
        direct_network::DirectGatewayState::MappedCandidate,
        &[LAN, EXTERNAL],
        Some(EXTERNAL),
    )
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn discovering() -> crate::peer_runtime::network::GatewayReading {
    reading(direct_network::DirectGatewayState::Discovering, &[], None)
}

/// A listening embedded relay publishing `reading`. The relay retry never comes
/// due, so no real gateway owner starts and no router traffic happens.
#[cfg(all(windows, target_pointer_width = "64"))]
fn embed(
    session: &mut ServiceSession<'_>,
    registry: &Rc<RefCell<RegistryFixture>>,
    reading: crate::peer_runtime::network::GatewayReading,
) {
    let lan: std::net::SocketAddr = LAN.parse().unwrap();
    registry
        .borrow_mut()
        .routes
        .insert(device(1), (lan, route()));
    session.network.embed_fixture(lan, reading);
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn exercise_timed(
    test: impl FnOnce(
        &mut ServiceSession<'_>,
        &Identity,
        Rc<RefCell<RegistryFixture>>,
        &mut Vec<Client>,
        &ControlledClock,
    ),
) {
    let key = Identity::new();
    let registry = registry();
    let origin = Instant::now();
    let clock = Arc::new(ControlledClock {
        origin,
        offset: Mutex::new(Duration::ZERO),
        calls: AtomicU64::new(0),
    });
    let mut session = ServiceSession::new(
        RegistryOwner::Fixture(Rc::clone(&registry), PhantomData),
        SessionKey::Fixture(&key),
        origin,
        clock.clone(),
    )
    .unwrap();
    let mut clients = Vec::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        test(&mut session, &key, registry, &mut clients, &clock)
    }));
    drain(&mut session);
    drop(session);
    for mut client in clients {
        let thread = client.thread.take().unwrap();
        let end = Instant::now() + TEST_LIMIT;
        while !thread.is_finished() {
            assert!(Instant::now() < end, "actual client owner did not finish");
            thread::yield_now();
        }
        thread.join().unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn at(clock: &ControlledClock, seconds: u64) {
    *clock.offset.lock().unwrap() = Duration::from_secs(seconds);
}

/// Every queued response drained, so a later clock step expires no frame.
#[cfg(all(windows, target_pointer_width = "64"))]
fn settle(session: &mut ServiceSession<'_>) {
    let limit = Instant::now() + TEST_LIMIT;
    while session
        .peers
        .iter()
        .any(|peer| !peer.responses_in_flight.is_empty())
    {
        assert!(Instant::now() < limit, "queued responses did not drain");
        session.process_one().unwrap();
        thread::yield_now();
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn told(
    session: &mut ServiceSession<'_>,
    key: &Identity,
    client: &Client,
) -> Vec<std::net::SocketAddr> {
    let signed = advertisement(session, client);
    settle(session);
    signed
        .verify(&PcPublicKey::from_spki_der(key.public.as_spki_der()).unwrap())
        .unwrap()
        .fields()
        .endpoints
        .clone()
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn lapse(session: &mut ServiceSession<'_>, commands: &async_mpsc::Sender<Vec<u8>>) {
    commands.try_send(query(session).to_wire()).unwrap();
    let limit = Instant::now() + TEST_LIMIT;
    while !session.peers[0].query_lapsed {
        assert!(Instant::now() < limit, "the query did not lapse");
        session.process_one().unwrap();
        thread::yield_now();
    }
    assert!(session.peers[0].advertised.is_none());
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn reaped(session: &mut ServiceSession<'_>) {
    let limit = Instant::now() + TEST_LIMIT;
    while !session.peers.is_empty() {
        assert!(
            Instant::now() < limit,
            "the ended connection was not reaped"
        );
        session.process_one().unwrap();
        thread::yield_now();
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn spin(session: &mut ServiceSession<'_>) {
    for _ in 0..16 {
        session.process_one().unwrap();
        thread::yield_now();
    }
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_phone_told_only_the_lan_address_is_ended_once_an_external_address_appears() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, lan_only());
        let commands = ready(session, key, clients);
        commands.try_send(query(session).to_wire()).unwrap();
        let lan: std::net::SocketAddr = LAN.parse().unwrap();
        assert_eq!(told(session, key, &clients[0]), vec![lan]);
        assert_eq!(session.peers[0].advertised, Some(vec![lan]));
        let state = Arc::clone(&session.peers[0].state);

        session.network.publish_fixture(mapped());
        // The first ten seconds after the clock exchange belong to the
        // connection's own query.
        at(clock, 9);
        spin(session);
        assert!(state.live());
        // The normal poll path ends it.
        at(clock, 10);
        session.process_one().unwrap();
        assert!(!state.live());
        assert!(session.hint_refreshes.contains_key(&device(1)));
        reaped(session);

        // The redialled connection asks at once and is told the external
        // address, so it is left alone.
        let commands = ready(session, key, clients);
        commands.try_send(query(session).to_wire()).unwrap();
        let external: std::net::SocketAddr = EXTERNAL.parse().unwrap();
        assert_eq!(told(session, key, &clients[1]), vec![lan, external]);
        let state = Arc::clone(&session.peers[0].state);
        at(clock, 200);
        spin(session);
        assert!(state.live());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_phone_already_told_the_external_address_keeps_its_connection() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, mapped());
        let commands = ready(session, key, clients);
        commands.try_send(query(session).to_wire()).unwrap();
        let endpoints = told(session, key, &clients[0]);
        assert!(endpoints.contains(&EXTERNAL.parse().unwrap()));
        let state = Arc::clone(&session.peers[0].state);
        at(clock, 11);
        let now = session.now().unwrap();
        assert!(session.refresh_stale_hints(now).is_empty());
        at(clock, 150);
        spin(session);
        assert!(state.live());
        assert!(session.hint_refreshes.is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_lapsed_query_is_refreshed_after_the_grace_and_at_most_once_per_interval() {
    use crate::public_diagnostics::HintRefresh;
    exercise_timed(|session, key, registry, clients, clock| {
        // Service start: the phone asks while the owner is still discovering.
        embed(session, &registry, discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        let state = Arc::clone(&session.peers[0].state);
        session.network.publish_fixture(mapped());
        at(clock, 9);
        let now = session.now().unwrap();
        assert!(session.refresh_stale_hints(now).is_empty());
        assert!(state.live());
        at(clock, 10);
        let now = session.now().unwrap();
        assert_eq!(
            session.refresh_stale_hints(now),
            vec![HintRefresh::QueryLapsed]
        );
        assert!(!state.live());
        reaped(session);

        // The redialled connection lapses too (the owner went back to
        // discovering), then the owner settles again. Its device was
        // refreshed at 10 s: nothing until 130 s, then once.
        session.network.publish_fixture(discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        let state = Arc::clone(&session.peers[0].state);
        session.network.publish_fixture(mapped());
        for seconds in [25, 60, 129] {
            at(clock, seconds);
            let now = session.now().unwrap();
            assert!(session.refresh_stale_hints(now).is_empty());
            spin(session);
            assert!(state.live(), "refreshed again at {seconds} s");
        }
        at(clock, 130);
        let now = session.now().unwrap();
        assert_eq!(
            session.refresh_stale_hints(now),
            vec![HintRefresh::QueryLapsed]
        );
        assert!(!state.live());
        assert!(session.refresh_stale_hints(now).is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_query_met_while_discovering_is_answered_once_the_owner_settles() {
    exercise_timed(|session, key, registry, clients, clock| {
        // A phone that redials right after a service start asks before the
        // owner has settled.
        embed(session, &registry, discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        let state = Arc::clone(&session.peers[0].state);
        at(clock, 2);
        spin(session);
        assert!(session.peers[0].deferred_query.is_some());
        assert!(session.peers[0].advertised.is_none());

        session.network.publish_fixture(mapped());
        at(clock, 4);
        let lan: std::net::SocketAddr = LAN.parse().unwrap();
        let external: std::net::SocketAddr = EXTERNAL.parse().unwrap();
        assert_eq!(told(session, key, &clients[0]), vec![lan, external]);
        assert!(!session.peers[0].query_lapsed);
        assert!(session.peers[0].deferred_query.is_none());
        // Told the external address, the connection is not ended for hints.
        at(clock, 200);
        spin(session);
        assert!(state.live());
        assert!(session.hint_refreshes.is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn peer_retired_during_deferred_address_signature_is_skipped_without_closing_session() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        let state = Arc::clone(&session.peers[0].state);
        let retire_during_signature = Arc::clone(&state);
        *key.after_protocol.borrow_mut() = Some(Box::new(move || {
            retire_during_signature.retire();
        }));

        session.network.publish_fixture(mapped());
        at(clock, 4);
        let now = session.now().unwrap();
        assert_eq!(session.answer_deferred_queries(now), Ok(()));
        assert!(session.peers[0].deferred_query.is_none());
        assert!(!state.live());
        assert!(!session.closing);
        assert!(session.peers[0].responses_in_flight.is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_kept_query_gets_whatever_the_owner_settles_on() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        session.network.publish_fixture(lan_only());
        at(clock, 1);
        let lan: std::net::SocketAddr = LAN.parse().unwrap();
        assert_eq!(told(session, key, &clients[0]), vec![lan]);
        assert!(!session.peers[0].query_lapsed);
        assert!(session.peers[0].deferred_query.is_none());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_query_kept_past_its_window_is_left_to_the_hint_refresh() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, discovering());
        let commands = ready(session, key, clients);
        lapse(session, &commands);
        let state = Arc::clone(&session.peers[0].state);
        // The owner settles only once the phone no longer holds its query:
        // an answer now would end the connection on the phone.
        at(clock, 6);
        session.network.publish_fixture(mapped());
        spin(session);
        assert!(session.peers[0].deferred_query.is_none());
        assert!(session.peers[0].advertised.is_none());
        assert!(session.peers[0].responses_in_flight.is_empty());
        assert!(clients[0].notices.try_iter().all(|notice| !matches!(
            notice,
            Notice::Frame(ref bytes) if SignedAddressAdvertisement::from_wire(bytes).is_ok()
        )));
        assert!(state.live());
        // The lapsed query is then refreshed exactly as before.
        at(clock, 10);
        session.process_one().unwrap();
        assert!(!state.live());
        assert!(session.hint_refreshes.contains_key(&device(1)));
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn without_a_settled_external_address_no_connection_is_ended() {
    use direct_network::{DirectGatewayState, ExternalAccess};
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, lan_only());
        let commands = ready(session, key, clients);
        commands.try_send(query(session).to_wire()).unwrap();
        told(session, key, &clients[0]);
        let state = Arc::clone(&session.peers[0].state);
        at(clock, 11);
        // Only the LAN address: withdrawing an external one is not worth a
        // reconnect either.
        kept(session, &state);
        // An owner that has not settled, or that runs another mode.
        let mut unsettled = mapped();
        unsettled.state = DirectGatewayState::Discovering;
        session.network.publish_fixture(unsettled);
        kept(session, &state);
        let mut other_mode = mapped();
        other_mode.access = ExternalAccess::RouterForward {
            external_port: 7443,
        };
        session.network.publish_fixture(other_mode);
        kept(session, &state);
        // An external address this relay would not publish.
        let mut expired = mapped();
        expired.validity_seconds = 0;
        session.network.publish_fixture(expired);
        kept(session, &state);
        // Not the embedded relay.
        session.network.publish_fixture(mapped());
        session.network.embedded_fixture(false);
        kept(session, &state);
        session.network.embedded_fixture(true);
        assert!(session.hint_refreshes.is_empty());
    });
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn kept(session: &mut ServiceSession<'_>, state: &PeerState) {
    let now = session.now().unwrap();
    assert!(session.refresh_stale_hints(now).is_empty());
    spin(session);
    assert!(state.live());
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
fn a_connection_that_never_asked_is_not_ended() {
    exercise_timed(|session, key, registry, clients, clock| {
        embed(session, &registry, mapped());
        let _commands = ready(session, key, clients);
        let state = Arc::clone(&session.peers[0].state);
        at(clock, 30);
        let now = session.now().unwrap();
        assert!(session.refresh_stale_hints(now).is_empty());
        spin(session);
        assert!(state.live());
    });
}
