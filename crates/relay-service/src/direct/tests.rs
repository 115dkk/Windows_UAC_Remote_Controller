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
        DirectGatewayOwner::start_with_mapping_nonce("192.168.1.2:7443".parse().unwrap(), [0; 12])
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
        assert!(DirectGatewayOwner::start(address.parse().unwrap()).is_err());
    }
}

#[test]
fn candidate_debug_is_redacted_and_validity_expires() {
    let mut snapshot = DirectGatewaySnapshot::new(
        DirectGatewayState::MappedCandidate,
        vec!["8.8.8.8:45000".parse().unwrap()],
        60,
    );
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("8.8.8.8"));
    assert!(!debug.contains("45000"));
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
    };
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
