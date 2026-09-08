// SPDX-License-Identifier: GPL-2.0-or-later
//! Public API + real ephemeral LOCALHOST sockets; no TLS or device proof.

use relay_service::{
    CancellationToken, READY_MARKER, Registration, RelayError, RelayLimits, RelayReport, Role,
    RouteId, run,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

struct LocalRelay {
    address: SocketAddr,
    stop: CancellationToken,
    task: Option<JoinHandle<Result<RelayReport, RelayError>>>,
}

impl LocalRelay {
    async fn start(limits: RelayLimits) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback fixture");
        let address = listener.local_addr().expect("ephemeral fixture address");
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(listener, limits, stop.clone()));
        Self {
            address,
            stop,
            task: Some(task),
        }
    }

    async fn connect(&self) -> TcpStream {
        let socket = TcpStream::connect(self.address)
            .await
            .expect("loopback fixture connection");
        // Match the product rendezvous connector's small-record socket policy.
        socket
            .set_nodelay(true)
            .expect("product endpoint socket policy");
        socket
    }

    async fn register(&self, role: Role, route: u8) -> TcpStream {
        let mut socket = self.connect().await;
        socket
            .write_all(
                &Registration::new(role, RouteId::new([route; 32]).expect("synthetic route"))
                    .to_wire(),
            )
            .await
            .expect("synthetic fixed registration");
        socket
    }

    async fn pair(&self, route: u8) -> (TcpStream, TcpStream) {
        let mut pc = self.register(Role::Pc, route).await;
        let mut phone = self.register(Role::Phone, route).await;
        read_ready(&mut pc).await;
        read_ready(&mut phone).await;
        (pc, phone)
    }

    async fn finish(mut self) -> RelayReport {
        self.stop.cancel();
        timeout(
            Duration::from_secs(6),
            self.task.take().expect("running fixture"),
        )
        .await
        .expect("bounded shutdown")
        .expect("relay task")
        .expect("clean relay shutdown")
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn read_ready(socket: &mut TcpStream) {
    let mut marker = [0; 9];
    timeout(Duration::from_secs(2), socket.read_exact(&mut marker))
        .await
        .expect("routing deadline")
        .expect("untrusted marker");
    assert_eq!(&marker, READY_MARKER);
}

async fn expect_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), socket.read(&mut byte))
        .await
        .expect("close deadline");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected forwarded data"
    );
}

async fn settle_waiting(socket: &mut TcpStream) {
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(40), socket.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn full_connection_budget_rejects_a_new_socket_before_spawning_its_protocol_work() {
    let relay = LocalRelay::start(RelayLimits::new(2, 1).expect("two socket slots")).await;
    let (_pc, _phone) = relay.pair(1).await;
    let mut excess = relay.connect().await;
    // No header is required to consume/reject this socket: admission comes first.
    expect_closed(&mut excess).await;
    let report = relay.finish().await;
    assert_eq!(report.accepted, 2);
    assert_eq!(report.rejected_capacity, 1);
    assert_eq!(report.peak_connections, 2);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn full_waiting_room_budget_still_allows_an_existing_rooms_counterpart() {
    let relay = LocalRelay::start(RelayLimits::new(4, 1).expect("one waiting room")).await;
    let mut pc = relay.register(Role::Pc, 1).await;
    settle_waiting(&mut pc).await;
    let mut excess_room = relay.register(Role::Pc, 2).await;
    expect_closed(&mut excess_room).await;
    let mut phone = relay.register(Role::Phone, 1).await;
    read_ready(&mut pc).await;
    read_ready(&mut phone).await;
    let report = relay.finish().await;
    assert_eq!(report.rejected_waiting_rooms, 1);
    assert_eq!(report.peak_waiting_rooms, 1);
    assert_eq!(report.paired, 1);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn waiting_eof_releases_the_route_and_socket_slot_for_a_new_pair() {
    let relay = LocalRelay::start(RelayLimits::new(2, 1).expect("bounded relay")).await;
    let mut departed = relay.register(Role::Pc, 1).await;
    settle_waiting(&mut departed).await;
    departed.shutdown().await.expect("synthetic peer EOF");
    // Observe the relay's closure rather than assuming a sleep cleaned its room.
    expect_closed(&mut departed).await;
    let (_pc, _phone) = relay.pair(1).await;
    let report = relay.finish().await;
    assert_eq!(report.paired, 1);
    assert_eq!(report.remaining_connections, 0);
    assert!(report.disconnected >= 1);
}

#[tokio::test]
async fn eof_in_one_active_direction_closes_both_and_does_not_orphan_the_route() {
    let relay = LocalRelay::start(RelayLimits::new(2, 1).expect("bounded relay")).await;
    let (mut pc, mut phone) = relay.pair(1).await;
    pc.shutdown().await.expect("active peer EOF");
    for (direction, socket) in [("counterpart", &mut phone), ("origin", &mut pc)] {
        let mut byte = [0];
        let result = timeout(Duration::from_secs(2), socket.read(&mut byte)).await;
        if !matches!(result, Ok(Ok(0)) | Ok(Err(_))) {
            // Preserve the original 2-second bound and collect only safe counts
            // after cleanup. This diagnoses which lifecycle actually ended; it
            // does not retry the connection or hide an intermittent failure.
            let report = relay.finish().await;
            panic!("active EOF did not close {direction}; aggregate cleanup report: {report:?}");
        }
    }
    assert!(
        !relay.stop.is_cancelled(),
        "one route closure is not server shutdown"
    );
    let (_new_pc, _new_phone) = relay.pair(1).await;
    let report = relay.finish().await;
    assert_eq!(report.paired, 2);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn repeated_route_generations_each_close_on_the_first_eof_attempt() {
    let relay = LocalRelay::start(RelayLimits::new(2, 1).expect("bounded relay")).await;
    for generation in 0..16 {
        let (mut pc, mut phone) = relay.pair(1).await;
        pc.shutdown().await.expect("one EOF per generation");
        let mut byte = [0];
        let result = timeout(Duration::from_secs(2), phone.read(&mut byte)).await;
        if !matches!(result, Ok(Ok(0)) | Ok(Err(_))) {
            let report = relay.finish().await;
            panic!(
                "route generation {generation} failed its first EOF; aggregate cleanup report: {report:?}"
            );
        }
        expect_closed(&mut pc).await;
    }
    let report = relay.finish().await;
    assert_eq!(report.paired, 16);
    assert_eq!(report.remaining_connections, 0);
}
