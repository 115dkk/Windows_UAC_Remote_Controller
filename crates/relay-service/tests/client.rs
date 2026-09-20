// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual loopback carrier setup, never a claim of peer authentication.

use std::{io::ErrorKind, time::Duration};

use relay_service::{
    CLIENT_RENDEZVOUS_TIMEOUT, CancellationToken, HEADER_BYTES, READY_MARKER, Registration,
    RendezvousError, Role, RouteId, connect_rendezvous,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{advance, pause, timeout},
};

fn registration() -> Registration {
    Registration::new(
        Role::Phone,
        RouteId::new([31; 32]).expect("synthetic route"),
    )
}

#[tokio::test]
async fn already_cancelled_setup_never_opens_a_socket() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("nonblocking probe");
    let stop = CancellationToken::new();
    stop.cancel();
    let result = connect_rendezvous(listener.local_addr().unwrap(), registration(), stop).await;
    assert_eq!(result.unwrap_err(), RendezvousError::Cancelled);
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[tokio::test]
async fn fixed_header_and_marker_preserve_coalesced_carrier_bytes_without_claiming_trust() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let release = CancellationToken::new();
    let server_release = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = [0; HEADER_BYTES];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(header, registration().to_wire());
        let mut coalesced = READY_MARKER.to_vec();
        coalesced.extend_from_slice(b"untrusted carrier bytes");
        socket.write_all(&coalesced).await.unwrap();
        server_release.cancelled().await;
    });
    let carrier = timeout(
        Duration::from_secs(2),
        connect_rendezvous(address, registration(), CancellationToken::new()),
    )
    .await
    .expect("bounded loopback health")
    .unwrap();
    assert_eq!(
        format!("{carrier:?}"),
        "RendezvousCarrier([unauthenticated])"
    );
    let mut socket = carrier.into_stream();
    assert!(socket.nodelay().unwrap());
    let mut bytes = [0; 23];
    timeout(Duration::from_secs(2), socket.read_exact(&mut bytes))
        .await
        .expect("bounded loopback health")
        .unwrap();
    assert_eq!(&bytes, b"untrusted carrier bytes");
    release.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn a_same_length_wrong_marker_is_rejected_without_exposing_server_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let release = CancellationToken::new();
    let server_release = release.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.read_exact(&mut [0; HEADER_BYTES]).await.unwrap();
        socket.write_all(b"BADMARKER").await.unwrap();
        server_release.cancelled().await;
    });
    let result = timeout(
        Duration::from_secs(2),
        connect_rendezvous(address, registration(), CancellationToken::new()),
    )
    .await
    .expect("bounded loopback health");
    assert_eq!(result.unwrap_err(), RendezvousError::InvalidMarker);
    release.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn cancelling_a_waiting_marker_completes_without_waiting_for_the_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let release = CancellationToken::new();
    let server_release = release.clone();
    let (registered, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.read_exact(&mut [0; HEADER_BYTES]).await.unwrap();
        registered.send(()).unwrap();
        server_release.cancelled().await;
    });
    let client = tokio::spawn(connect_rendezvous(address, registration(), stop.clone()));
    timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    stop.cancel();
    let result = timeout(Duration::from_secs(2), client)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err(), RendezvousError::Cancelled);
    release.cancel();
    server.await.unwrap();
}

#[tokio::test]
async fn waiting_marker_has_an_absolute_deadline_without_real_thirty_second_sleep() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let release = CancellationToken::new();
    let server_release = release.clone();
    let (registered, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.read_exact(&mut [0; HEADER_BYTES]).await.unwrap();
        registered.send(()).unwrap();
        server_release.cancelled().await;
    });
    let client = tokio::spawn(connect_rendezvous(
        address,
        registration(),
        CancellationToken::new(),
    ));
    // Real TCP registration completes first; only the deadline clock is paused.
    timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    pause();
    advance(CLIENT_RENDEZVOUS_TIMEOUT + Duration::from_nanos(1)).await;
    let result = client.await.unwrap();
    assert_eq!(result.unwrap_err(), RendezvousError::RendezvousTimeout);
    release.cancel();
    server.await.unwrap();
}
