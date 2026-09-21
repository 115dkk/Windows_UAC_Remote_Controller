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
        session.relay = Some(relay);
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
        Some(secure_channel::ControlProtocol::V2)
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
