// SPDX-License-Identifier: GPL-2.0-or-later
//! Real ephemeral loopback TCP with synthetic bytes. No TLS/native UAC proof.

use std::{net::SocketAddr, time::Duration};

use relay_service::{
    CancellationToken, READY_MARKER, Registration, RelayError, RelayLimits, RelayReport, Role,
    RouteId, run,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

struct Server {
    address: SocketAddr,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<RelayReport, RelayError>>>,
}

impl Server {
    async fn start(limits: RelayLimits) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral loopback listener");
        let address = listener.local_addr().expect("local test address");
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(run(listener, limits, cancellation.clone()));
        Self {
            address,
            cancellation,
            task: Some(task),
        }
    }

    async fn register(&self, role: Role, route: u8) -> TcpStream {
        let mut socket = TcpStream::connect(self.address)
            .await
            .expect("local synthetic peer");
        socket
            .set_nodelay(true)
            .expect("product endpoint socket policy");
        let registration =
            Registration::new(role, RouteId::new([route; 32]).expect("synthetic route"));
        socket
            .write_all(&registration.to_wire())
            .await
            .expect("fixed registration header");
        socket
    }

    async fn shutdown(mut self) -> RelayReport {
        self.cancellation.cancel();
        timeout(
            Duration::from_secs(6),
            self.task.take().expect("running relay"),
        )
        .await
        .expect("bounded relay shutdown")
        .expect("relay task did not panic")
        .expect("relay ended without infrastructure failure")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn ready(socket: &mut TcpStream) {
    let mut marker = [0; 9];
    timeout(Duration::from_secs(2), socket.read_exact(&mut marker))
        .await
        .expect("local rendezvous marker deadline")
        .expect("rendezvous marker read");
    assert_eq!(&marker, READY_MARKER);
}

async fn closed(socket: &mut TcpStream) {
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), socket.read(&mut byte))
        .await
        .expect("bounded socket closure");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected data instead of closure"
    );
}

async fn remains_waiting(socket: &mut TcpStream) {
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(40), socket.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn complementary_peers_receive_untrusted_marker_then_opaque_bytes_in_both_directions() {
    let server = Server::start(RelayLimits::default()).await;
    let mut pc = server.register(Role::Pc, 1).await;
    let mut phone = server.register(Role::Phone, 1).await;
    ready(&mut pc).await;
    ready(&mut phone).await;
    // Deliberately synthetic plaintext only to exercise byte transport; real
    // endpoints must start their mutually pinned inner TLS handshake here.
    pc.write_all(b"synthetic PC bytes")
        .await
        .expect("PC fixture send");
    let mut pc_bytes = [0; 18];
    timeout(Duration::from_secs(2), phone.read_exact(&mut pc_bytes))
        .await
        .expect("local forward deadline")
        .expect("PC bytes forwarded");
    assert_eq!(&pc_bytes, b"synthetic PC bytes");
    phone
        .write_all(b"synthetic phone bytes")
        .await
        .expect("phone fixture send");
    let mut phone_bytes = [0; 21];
    timeout(Duration::from_secs(2), pc.read_exact(&mut phone_bytes))
        .await
        .expect("local reverse deadline")
        .expect("phone bytes forwarded");
    assert_eq!(&phone_bytes, b"synthetic phone bytes");
    let report = server.shutdown().await;
    assert_eq!(report.paired, 1);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn different_rooms_do_not_pair_or_cross_forward() {
    let server = Server::start(RelayLimits::default()).await;
    let mut pc_a = server.register(Role::Pc, 1).await;
    let mut phone_b = server.register(Role::Phone, 2).await;
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(40), pc_a.read(&mut byte))
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(40), phone_b.read(&mut byte))
            .await
            .is_err()
    );
    let mut phone_a = server.register(Role::Phone, 1).await;
    let mut pc_b = server.register(Role::Pc, 2).await;
    ready(&mut pc_a).await;
    ready(&mut phone_a).await;
    ready(&mut pc_b).await;
    ready(&mut phone_b).await;
    pc_a.write_all(b"A").await.expect("room A fixture");
    phone_b.write_all(b"B").await.expect("room B fixture");
    phone_a
        .read_exact(&mut byte)
        .await
        .expect("only A counterpart");
    assert_eq!(&byte, b"A");
    pc_b.read_exact(&mut byte)
        .await
        .expect("only B counterpart");
    assert_eq!(&byte, b"B");
    assert!(
        timeout(Duration::from_millis(40), pc_a.read(&mut byte))
            .await
            .is_err()
    );
    let report = server.shutdown().await;
    assert_eq!(report.paired, 2);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn duplicate_waiting_role_cannot_replace_or_disconnect_the_first_participant() {
    let server = Server::start(RelayLimits::default()).await;
    let mut original = server.register(Role::Pc, 1).await;
    remains_waiting(&mut original).await;
    let mut duplicate = server.register(Role::Pc, 1).await;
    closed(&mut duplicate).await;
    let mut phone = server.register(Role::Phone, 1).await;
    ready(&mut original).await;
    ready(&mut phone).await;
    original
        .write_all(b"O")
        .await
        .expect("original participant still owns the route");
    let mut byte = [0];
    phone
        .read_exact(&mut byte)
        .await
        .expect("original is connected");
    assert_eq!(&byte, b"O");
    let report = server.shutdown().await;
    assert_eq!(report.rejected_duplicates, 1);
    assert_eq!(report.paired, 1);
}

#[tokio::test]
async fn active_route_rejects_new_roles_without_kicking_the_connected_pair() {
    let server = Server::start(RelayLimits::default()).await;
    let mut pc = server.register(Role::Pc, 1).await;
    let mut phone = server.register(Role::Phone, 1).await;
    ready(&mut pc).await;
    ready(&mut phone).await;
    for role in [Role::Pc, Role::Phone] {
        let mut duplicate = server.register(role, 1).await;
        closed(&mut duplicate).await;
    }
    phone
        .write_all(b"S")
        .await
        .expect("original pair still sends");
    let mut byte = [0];
    timeout(Duration::from_secs(2), pc.read_exact(&mut byte))
        .await
        .expect("original pair still receives")
        .expect("original pair byte");
    assert_eq!(&byte, b"S");
    let report = server.shutdown().await;
    assert_eq!(report.rejected_duplicates, 2);
    assert_eq!(report.paired, 1);
}

#[tokio::test]
async fn invalid_magic_version_role_and_zero_route_are_closed_without_reflection() {
    let server = Server::start(RelayLimits::default()).await;
    let valid =
        Registration::new(Role::Pc, RouteId::new([1; 32]).expect("synthetic route")).to_wire();
    let mut wrong_magic = valid;
    wrong_magic[0] ^= 1;
    let mut wrong_version = valid;
    wrong_version[9] = 2;
    let mut wrong_role = valid;
    wrong_role[10] = 3;
    let mut zero_route = valid;
    zero_route[11..].fill(0);
    for invalid in [wrong_magic, wrong_version, wrong_role, zero_route] {
        let mut socket = TcpStream::connect(server.address)
            .await
            .expect("invalid synthetic peer");
        socket
            .write_all(&invalid)
            .await
            .expect("invalid fixed fixture");
        closed(&mut socket).await;
    }
    let report = server.shutdown().await;
    assert_eq!(report.invalid_registrations, 4);
    assert_eq!(report.paired, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn partial_header_expires_without_reserving_a_room_or_leaking_a_connection() {
    let limits = RelayLimits::default()
        .with_timeouts(
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
        )
        .expect("tight test deadlines");
    let server = Server::start(limits).await;
    let mut partial = TcpStream::connect(server.address)
        .await
        .expect("partial synthetic peer");
    partial
        .write_all(b"WUAC")
        .await
        .expect("partial fixed header");
    closed(&mut partial).await;
    let report = server.shutdown().await;
    assert_eq!(report.header_timeouts, 1);
    assert_eq!(report.peak_waiting_rooms, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn pipelined_opaque_bytes_are_preserved_once_after_both_ready_markers() {
    let server = Server::start(RelayLimits::default()).await;
    let mut pc = server.register(Role::Pc, 1).await;
    let pc_fixture = b"synthetic pre-pair PC bytes";
    pc.write_all(pc_fixture)
        .await
        .expect("pipelined synthetic PC fixture");
    // Functional assertion: no reflection/ready bytes exist without a counterpart.
    remains_waiting(&mut pc).await;
    let mut phone = server.register(Role::Phone, 1).await;
    let phone_fixture = b"synthetic pre-marker phone bytes";
    phone
        .write_all(phone_fixture)
        .await
        .expect("pipelined synthetic phone fixture");
    ready(&mut pc).await;
    ready(&mut phone).await;
    let mut at_phone = vec![0; pc_fixture.len()];
    let mut at_pc = vec![0; phone_fixture.len()];
    timeout(Duration::from_secs(2), phone.read_exact(&mut at_phone))
        .await
        .expect("forwarded prefix deadline")
        .expect("complete PC fixture");
    timeout(Duration::from_secs(2), pc.read_exact(&mut at_pc))
        .await
        .expect("reverse prefix deadline")
        .expect("complete phone fixture");
    assert_eq!(at_phone.as_slice(), pc_fixture.as_slice());
    assert_eq!(at_pc.as_slice(), phone_fixture.as_slice());
    pc.write_all(b"!")
        .await
        .expect("next byte after preserved prefix");
    let mut next = [0];
    timeout(Duration::from_secs(2), phone.read_exact(&mut next))
        .await
        .expect("following byte deadline")
        .expect("no replayed prefix byte");
    assert_eq!(&next, b"!");
    let report = server.shutdown().await;
    assert_eq!(report.paired, 1);
    assert_eq!(report.remaining_connections, 0);
}
