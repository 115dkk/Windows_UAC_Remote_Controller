// SPDX-License-Identifier: GPL-2.0-or-later
use super::*;

#[test]
fn public_local_ipv4_is_a_candidate_without_a_gateway_mapping() {
    assert_eq!(
        local_ipv4_state(Ipv4Addr::new(8, 8, 8, 8)),
        DirectGatewayState::PublicIpv4Candidate
    );
    assert_eq!(
        local_ipv4_state(Ipv4Addr::new(192, 168, 1, 2)),
        DirectGatewayState::LanOnly
    );
}

#[test]
fn mapping_path_identity_ignores_ipv6_candidate_rotation_but_not_gateway_change() {
    let original = Network {
        internal: "192.168.1.2:7443".parse().unwrap(),
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        ipv6: vec![],
    };
    let mut changed = original.clone();
    changed.ipv6.push("2606:4700:4700::1111".parse().unwrap());
    assert!(original.same_mapping_path(&changed));
    changed.gateway = Ipv4Addr::new(192, 168, 1, 254);
    assert!(!original.same_mapping_path(&changed));
}

#[test]
fn public_classification_excludes_local_cgnat_documentation_and_transition_ranges() {
    for address in [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.168.0.1",
        "100.64.0.1",
        "100.127.255.254",
        "192.0.2.1",
        "192.88.99.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2001:db8::1",
        "2001::1",
        "2002:0808:0808::1",
        "3fff::1",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
    ] {
        assert!(
            !global(address.parse().unwrap()),
            "special-purpose address classified as public"
        );
    }
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(global(address.parse().unwrap()));
    }
}

#[test]
fn owner_rejects_invalid_or_scoped_local_endpoints_before_spawning() {
    assert!(
        DirectGatewayOwner::start_with_mapping_nonce(
            "192.168.1.2:7443".parse().unwrap(),
            ExternalAccess::Automatic,
            [0; 12]
        )
        .is_err()
    );
    for address in [
        "0.0.0.0:7443",
        "127.0.0.1:7443",
        "192.168.1.2:0",
        "224.0.0.1:7443",
        "[::]:7443",
        "[fe80::1%3]:7443",
        "[2001:db8::1]:7443",
    ] {
        assert!(
            DirectGatewayOwner::start(address.parse().unwrap(), ExternalAccess::Automatic).is_err()
        );
    }
    for access in [
        ExternalAccess::RouterForward { external_port: 0 },
        ExternalAccess::Fixed {
            address: "192.168.1.9:7443".parse().unwrap(),
        },
    ] {
        assert!(DirectGatewayOwner::start("192.168.1.2:7443".parse().unwrap(), access).is_err());
    }
}

#[test]
fn external_access_accepts_only_a_port_and_a_public_unscoped_address() {
    for access in [
        ExternalAccess::Automatic,
        ExternalAccess::RouterForward { external_port: 1 },
        ExternalAccess::RouterForward {
            external_port: 65535,
        },
        ExternalAccess::Fixed {
            address: "8.8.8.8:7443".parse().unwrap(),
        },
        ExternalAccess::Fixed {
            address: "[2606:4700:4700::1111]:7443".parse().unwrap(),
        },
    ] {
        assert_eq!(access.validated(), Ok(access));
    }
    assert_eq!(
        ExternalAccess::RouterForward { external_port: 0 }.validated(),
        Err(InvalidExternalAccess::ZeroPort)
    );
    assert_eq!(
        ExternalAccess::Fixed {
            address: "8.8.8.8:0".parse().unwrap()
        }
        .validated(),
        Err(InvalidExternalAccess::ZeroPort)
    );
    let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2606:4700:4700::1111".parse().unwrap(),
        7443,
        0,
        3,
    ));
    let labelled = SocketAddr::V6(std::net::SocketAddrV6::new(
        "2606:4700:4700::1111".parse().unwrap(),
        7443,
        5,
        0,
    ));
    for address in [
        "192.168.1.9:7443".parse().unwrap(),
        "100.64.0.1:7443".parse().unwrap(),
        "203.0.113.7:7443".parse().unwrap(),
        "127.0.0.1:7443".parse().unwrap(),
        "[fe80::1]:7443".parse().unwrap(),
        "[::ffff:8.8.8.8]:7443".parse().unwrap(),
        scoped,
        labelled,
    ] {
        assert_eq!(
            ExternalAccess::Fixed { address }.validated(),
            Err(InvalidExternalAccess::NotPublic)
        );
    }
}

fn lan() -> SocketAddrV4 {
    "192.168.1.2:7443".parse().unwrap()
}

fn external(endpoint: &str, source: CandidateSource) -> Result<External, Option<DirectFailure>> {
    Ok(External::new(endpoint.parse().unwrap(), source))
}

#[test]
fn automatic_mapping_is_a_mapped_candidate_after_lan_and_ipv6() {
    let ipv6: Vec<IpAddr> = vec!["2606:4700:4700::1111".parse().unwrap()];
    for source in [CandidateSource::Pcp, CandidateSource::Upnp] {
        let mapped = External {
            endpoint: "8.8.8.8:45000".parse().unwrap(),
            seconds: 20,
            source,
        };
        let snapshot = compose(lan(), &ipv6, Ok(mapped));
        assert_eq!(snapshot.state, DirectGatewayState::MappedCandidate);
        assert_eq!(
            snapshot.candidates(),
            [
                "192.168.1.2:7443".parse().unwrap(),
                "[2606:4700:4700::1111]:7443".parse().unwrap(),
                "8.8.8.8:45000".parse().unwrap(),
            ]
        );
        assert_eq!(snapshot.external(), Some("8.8.8.8:45000".parse().unwrap()));
        assert_eq!(snapshot.source(), Some(source));
        assert_eq!(snapshot.failure(), None);
        assert_eq!(snapshot.validity_seconds, 20);
    }
}

#[test]
fn automatic_without_mapping_reports_why_only_after_asking_a_gateway() {
    let mut mappings = obligations::MappingObligations::new();
    assert_eq!(automatic(lan(), &mappings, true), Err(None));
    let path = Network {
        internal: lan(),
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        ipv6: vec![],
    };
    let refused = io::Error::from(io::ErrorKind::TimedOut);
    mappings.mapping_finished(&path, Err(refused), Instant::now());
    assert_eq!(
        automatic(lan(), &mappings, true),
        Err(Some(DirectFailure::NoMappingProtocol))
    );
    // No selected gateway this round: nothing was asked, nothing is claimed.
    assert_eq!(automatic(lan(), &mappings, false), Err(None));
    let public: SocketAddrV4 = "8.8.8.8:7443".parse().unwrap();
    assert_eq!(
        automatic(public, &mappings, true),
        external("8.8.8.8:7443", CandidateSource::PublicInterface)
    );
    for failure in [
        DirectFailure::NoMappingProtocol,
        DirectFailure::PrivateExternalAddress,
    ] {
        let snapshot = compose(lan(), &[], Err(Some(failure)));
        assert_eq!(snapshot.state, DirectGatewayState::LanOnly);
        assert_eq!(snapshot.candidates(), [SocketAddr::V4(lan())]);
        assert_eq!(snapshot.external(), None);
        assert_eq!(snapshot.source(), None);
        assert_eq!(snapshot.failure(), Some(failure));
    }
    let snapshot = compose(
        public,
        &[],
        external("8.8.8.8:7443", CandidateSource::PublicInterface),
    );
    assert_eq!(snapshot.state, DirectGatewayState::PublicIpv4Candidate);
    assert_eq!(snapshot.candidates(), [SocketAddr::V4(public)]);
    assert_eq!(snapshot.external(), Some(SocketAddr::V4(public)));
    assert_eq!(snapshot.source(), Some(CandidateSource::PublicInterface));
}

#[tokio::test]
async fn router_forward_on_a_public_interface_publishes_the_forwarded_port_without_stun() {
    let public: SocketAddrV4 = "8.8.8.8:7443".parse().unwrap();
    let mut stun = stun::PublicAddress::new();
    // A cancelled token would fail any query; none may be attempted here.
    let stop = CancellationToken::new();
    stop.cancel();
    let result = forwarded(public, 8443, None, &mut stun, &stop).await;
    assert_eq!(
        result,
        external("8.8.8.8:8443", CandidateSource::PublicInterface)
    );
    let snapshot = compose(public, &[], result);
    assert_eq!(snapshot.state, DirectGatewayState::MappedCandidate);
    assert_eq!(
        snapshot.candidates(),
        [SocketAddr::V4(public), "8.8.8.8:8443".parse().unwrap()]
    );
    let result = forwarded(public, 7443, None, &mut stun, &stop).await;
    let snapshot = compose(public, &[], result);
    assert_eq!(snapshot.state, DirectGatewayState::PublicIpv4Candidate);
    assert_eq!(snapshot.candidates(), [SocketAddr::V4(public)]);
    assert_eq!(snapshot.source(), Some(CandidateSource::PublicInterface));
}

#[tokio::test]
async fn router_forward_without_a_public_answer_reports_it_unavailable() {
    let mut stun = stun::PublicAddress::new();
    let stop = CancellationToken::new();
    stop.cancel();
    let result = forwarded(lan(), 8443, None, &mut stun, &stop).await;
    assert_eq!(result, Err(Some(DirectFailure::PublicAddressUnavailable)));
    let snapshot = compose(lan(), &[], result);
    assert_eq!(snapshot.state, DirectGatewayState::LanOnly);
    assert_eq!(snapshot.external(), None);
    assert_eq!(
        snapshot.failure(),
        Some(DirectFailure::PublicAddressUnavailable)
    );
    let snapshot = compose(lan(), &[], external("8.8.8.8:8443", CandidateSource::Stun));
    assert_eq!(snapshot.state, DirectGatewayState::MappedCandidate);
    assert_eq!(snapshot.external(), Some("8.8.8.8:8443".parse().unwrap()));
    assert_eq!(snapshot.source(), Some(CandidateSource::Stun));
    assert_eq!(snapshot.validity_seconds, CANDIDATE_SECONDS);
}

#[test]
fn fixed_address_is_published_as_given_in_either_family() {
    let snapshot = compose(lan(), &[], external("1.1.1.1:7443", CandidateSource::Fixed));
    assert_eq!(snapshot.state, DirectGatewayState::MappedCandidate);
    assert_eq!(snapshot.source(), Some(CandidateSource::Fixed));
    assert_eq!(snapshot.candidates().len(), 2);
    let ipv6 = compose(
        lan(),
        &[],
        external("[2606:4700:4700::1111]:9443", CandidateSource::Fixed),
    );
    assert_eq!(ipv6.state, DirectGatewayState::Ipv6Candidate);
    assert_eq!(
        ipv6.external(),
        Some("[2606:4700:4700::1111]:9443".parse().unwrap())
    );
    let two: Vec<IpAddr> = vec![
        "2606:4700:4700::1111".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ];
    let full = compose(
        lan(),
        &two,
        external("[2606:4700:4700::1001]:9443", CandidateSource::Fixed),
    );
    assert_eq!(full.candidates().len(), 4);
    assert_eq!(full.candidates()[3], full.external().unwrap());
}

#[test]
fn ipv6_only_host_publishes_its_own_address_or_the_fixed_one() {
    let internal: SocketAddr = "[2606:4700:4700::1111]:7443".parse().unwrap();
    let automatic = compose_ipv6(internal, ExternalAccess::Automatic);
    assert_eq!(automatic.state, DirectGatewayState::Ipv6Candidate);
    assert_eq!(automatic.candidates(), [internal]);
    assert_eq!(automatic.external(), Some(internal));
    assert_eq!(automatic.source(), Some(CandidateSource::PublicInterface));
    let forwarded = compose_ipv6(internal, ExternalAccess::RouterForward { external_port: 1 });
    assert_eq!(forwarded.state, DirectGatewayState::Ipv6Candidate);
    assert_eq!(forwarded.candidates(), [internal]);
    assert_eq!(forwarded.external(), None);
    assert_eq!(
        forwarded.failure(),
        Some(DirectFailure::PublicAddressUnavailable)
    );
    let address: SocketAddr = "8.8.8.8:7443".parse().unwrap();
    let fixed = compose_ipv6(internal, ExternalAccess::Fixed { address });
    assert_eq!(fixed.state, DirectGatewayState::MappedCandidate);
    assert_eq!(fixed.candidates(), [internal, address]);
    assert_eq!(fixed.source(), Some(CandidateSource::Fixed));
}

#[test]
fn candidate_debug_is_redacted_and_validity_expires() {
    let mut snapshot = DirectGatewaySnapshot::new(
        DirectGatewayState::MappedCandidate,
        vec!["8.8.8.8:45000".parse().unwrap()],
        60,
    );
    snapshot = snapshot.with_external(Ok(External::new(
        "8.8.8.8:45000".parse().unwrap(),
        CandidateSource::Stun,
    )));
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("8.8.8.8"));
    assert!(!debug.contains("45000"));
    assert!(debug.contains("Stun"));
    assert_eq!(snapshot.candidates().len(), 1);
    assert!(snapshot.remaining_validity_seconds() <= 60);
    snapshot.expires = Instant::now();
    assert_eq!(snapshot.remaining_validity_seconds(), 0);
}

#[test]
fn snapshot_is_nonblocking_and_drain_retains_owner_until_thread_finished() {
    let stop = CancellationToken::new();
    let shared = Arc::new(Mutex::new(DirectGatewaySnapshot::new(
        DirectGatewayState::LanOnly,
        vec!["192.168.1.2:7443".parse().unwrap()],
        60,
    )));
    let (send, receive) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        receive.recv_timeout(Duration::from_secs(3)).unwrap();
    });
    let mut owner = DirectGatewayOwner {
        stop,
        shared: shared.clone(),
        worker: Some(worker),
        access: ExternalAccess::Automatic,
    };
    assert_eq!(owner.access(), ExternalAccess::Automatic);
    assert_eq!(owner.snapshot().candidates().len(), 1);
    {
        let _locked = shared.lock().unwrap();
        assert_eq!(owner.snapshot().state, DirectGatewayState::Discovering);
    }
    assert!(!owner.drain());
    assert_eq!(owner.remaining_owners(), 1);
    assert_eq!(owner.snapshot().state, DirectGatewayState::Stopped);
    send.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !owner.drain() {
        assert!(Instant::now() < deadline);
        thread::yield_now();
    }
    assert_eq!(owner.remaining_owners(), 0);
}

#[tokio::test]
async fn cancellation_stops_long_backoff_without_waiting_for_its_deadline() {
    let stop = CancellationToken::new();
    stop.cancel();
    assert!(pause(&stop, Duration::from_secs(120)).await);
    let error = bounded(&stop, async { Ok::<_, io::Error>(()) })
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
}
