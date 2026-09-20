// SPDX-License-Identifier: GPL-2.0-or-later
//! Real loopback sockets and short actual Tokio deadlines. No paused-time I/O claims.

use relay_service::{
    CancellationToken, READY_MARKER, Registration, RelayError, RelayLimits, RelayReport, Role,
    RouteId, run,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};

struct TimedRelay {
    address: SocketAddr,
    stop: CancellationToken,
    task: Option<JoinHandle<Result<RelayReport, RelayError>>>,
}

impl TimedRelay {
    async fn start(waiting: Duration, idle: Duration, absolute: Duration) -> Self {
        let limits = RelayLimits::default()
            .with_timeouts(
                Duration::from_secs(1),
                waiting,
                idle,
                absolute,
                Duration::from_secs(1),
            )
            .expect("bounded test deadlines");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral loopback listener");
        let address = listener.local_addr().expect("loopback address");
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(listener, limits, stop.clone()));
        Self {
            address,
            stop,
            task: Some(task),
        }
    }

    async fn register(&self, role: Role, route: u8) -> TcpStream {
        let mut socket = TcpStream::connect(self.address)
            .await
            .expect("local fixture peer");
        socket
            .set_nodelay(true)
            .expect("product endpoint socket policy");
        socket
            .write_all(
                &Registration::new(role, RouteId::new([route; 32]).expect("synthetic route"))
                    .to_wire(),
            )
            .await
            .expect("fixed registration");
        socket
    }

    async fn pair(&self) -> (TcpStream, TcpStream) {
        let mut pc = self.register(Role::Pc, 1).await;
        let mut phone = self.register(Role::Phone, 1).await;
        for socket in [&mut pc, &mut phone] {
            let mut marker = [0; 9];
            timeout(Duration::from_secs(2), socket.read_exact(&mut marker))
                .await
                .expect("marker deadline")
                .expect("marker read");
            assert_eq!(&marker, READY_MARKER);
        }
        (pc, phone)
    }

    async fn finish(mut self) -> RelayReport {
        self.stop.cancel();
        timeout(
            Duration::from_secs(2),
            self.task.take().expect("running relay"),
        )
        .await
        .expect("shutdown deadline")
        .expect("task did not panic")
        .expect("clean shutdown")
    }
}

impl Drop for TimedRelay {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn expect_closed(socket: &mut TcpStream) {
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), socket.read(&mut byte))
        .await
        .expect("bounded close");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected payload instead of close"
    );
}

#[tokio::test]
async fn unmatched_participant_is_closed_at_the_waiting_deadline() {
    let relay = TimedRelay::start(
        Duration::from_millis(150),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .await;
    let mut waiter = relay.register(Role::Pc, 1).await;
    expect_closed(&mut waiter).await;
    let report = relay.finish().await;
    assert_eq!(report.waiting_timeouts, 1);
    assert_eq!(report.paired, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn early_buffered_data_and_eof_never_escape_the_absolute_waiting_deadline() {
    let relay = TimedRelay::start(
        Duration::from_millis(150),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .await;
    let mut waiter = relay.register(Role::Pc, 1).await;
    waiter
        .write_all(b"synthetic early bytes")
        .await
        .expect("early synthetic fixture");
    waiter.shutdown().await.expect("EOF behind early bytes");
    expect_closed(&mut waiter).await;
    let report = relay.finish().await;
    assert_eq!(report.waiting_timeouts, 1);
    assert_eq!(report.paired, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn inactivity_closes_both_active_peers_without_waiting_for_absolute_lifetime() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_millis(100),
        Duration::from_secs(2),
    )
    .await;
    let (mut pc, mut phone) = relay.pair().await;
    expect_closed(&mut pc).await;
    expect_closed(&mut phone).await;
    let report = relay.finish().await;
    assert_eq!(report.idle_timeouts, 1);
    assert_eq!(report.absolute_timeouts, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn actual_forward_progress_in_either_direction_refreshes_inactivity() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_millis(300),
        Duration::from_secs(2),
    )
    .await;
    let (mut pc, mut phone) = relay.pair().await;
    for direction in 0..4 {
        let (sender, receiver) = if direction % 2 == 0 {
            (&mut pc, &mut phone)
        } else {
            (&mut phone, &mut pc)
        };
        sender.write_all(b"S").await.expect("synthetic progress");
        let mut byte = [0];
        timeout(Duration::from_secs(1), receiver.read_exact(&mut byte))
            .await
            .expect("progress deadline")
            .expect("opaque byte forwarded");
        assert_eq!(&byte, b"S");
        sleep(Duration::from_millis(100)).await;
    }
    // More than the initial idle duration has elapsed, with continued progress.
    pc.write_all(b"F")
        .await
        .expect("still live after original idle deadline");
    let mut byte = [0];
    timeout(Duration::from_secs(1), phone.read_exact(&mut byte))
        .await
        .expect("final progress deadline")
        .expect("still paired");
    assert_eq!(&byte, b"F");
    let report = relay.finish().await;
    assert_eq!(report.idle_timeouts, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn absolute_pair_lifetime_is_not_extended_by_ongoing_traffic() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_millis(500),
    )
    .await;
    let (mut pc, mut phone) = relay.pair().await;
    let terminated = timeout(Duration::from_secs(2), async {
        for _ in 0..20 {
            if pc.write_all(b"T").await.is_err() {
                return true;
            }
            let mut byte = [0];
            if phone.read_exact(&mut byte).await.is_err() {
                return true;
            }
            assert_eq!(&byte, b"T");
            sleep(Duration::from_millis(40)).await;
        }
        false
    })
    .await
    .expect("bounded absolute-lifetime observation");
    assert!(
        terminated,
        "traffic must not keep a route beyond its absolute lifetime"
    );
    let report = relay.finish().await;
    assert_eq!(report.absolute_timeouts, 1);
    assert_eq!(report.idle_timeouts, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn shutdown_closes_active_waiting_and_partial_header_connections_together() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .await;
    let (mut pc, mut phone) = relay.pair().await;
    let mut waiter = relay.register(Role::Pc, 2).await;
    let mut byte = [0];
    assert!(
        timeout(Duration::from_millis(40), waiter.read(&mut byte))
            .await
            .is_err()
    );
    let mut partial = TcpStream::connect(relay.address)
        .await
        .expect("partial loopback peer");
    partial
        .write_all(b"W")
        .await
        .expect("partial fixture header");
    assert!(
        timeout(Duration::from_millis(40), partial.read(&mut byte))
            .await
            .is_err()
    );
    let report = relay.finish().await;
    expect_closed(&mut pc).await;
    expect_closed(&mut phone).await;
    expect_closed(&mut waiter).await;
    expect_closed(&mut partial).await;
    assert_eq!(report.accepted, 4);
    assert_eq!(report.remaining_connections, 0);
}

fn synthetic_backpressure(mut sender: TcpStream) -> JoinHandle<()> {
    tokio::spawn(async move {
        // One fixed synthetic buffer, no payload queue. The peer deliberately
        // stops reading so production relay writes encounter TCP backpressure.
        let bytes = [b'S'; 16 * 1024];
        loop {
            if sender.write_all(&bytes).await.is_err() {
                return;
            }
        }
    })
}

async fn bounded_producer_end(mut producer: JoinHandle<()>) {
    let result = timeout(Duration::from_secs(3), &mut producer).await;
    if result.is_err() {
        producer.abort();
        let _ = producer.await;
    }
    assert!(
        matches!(result, Ok(Ok(()))),
        "synthetic producer did not stop after relay closure"
    );
}

#[tokio::test]
async fn cancellation_remains_effective_while_a_peer_does_not_read_forwarded_bytes() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .await;
    let (pc, _not_reading_phone) = relay.pair().await;
    let producer = synthetic_backpressure(pc);
    sleep(Duration::from_millis(100)).await;
    let report = relay.finish().await;
    bounded_producer_end(producer).await;
    assert_eq!(report.remaining_connections, 0);
    assert!(report.cancelled >= 1);
}

#[tokio::test]
async fn inactivity_remains_effective_inside_a_backpressured_write_loop() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_millis(150),
        Duration::from_secs(2),
    )
    .await;
    let (pc, _not_reading_phone) = relay.pair().await;
    bounded_producer_end(synthetic_backpressure(pc)).await;
    let report = relay.finish().await;
    assert_eq!(report.idle_timeouts, 1);
    assert_eq!(report.absolute_timeouts, 0);
    assert_eq!(report.remaining_connections, 0);
}

#[tokio::test]
async fn absolute_lifetime_also_cancels_a_backpressured_write_loop() {
    let relay = TimedRelay::start(
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_millis(300),
    )
    .await;
    let (pc, _not_reading_phone) = relay.pair().await;
    bounded_producer_end(synthetic_backpressure(pc)).await;
    let report = relay.finish().await;
    assert_eq!(report.absolute_timeouts, 1);
    assert_eq!(report.idle_timeouts, 0);
    assert_eq!(report.remaining_connections, 0);
}
