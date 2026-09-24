// SPDX-License-Identifier: GPL-2.0-or-later
//! Untrusted rendezvous carrier setup. The result MUST be wrapped in peer-pinned
//! TLS; neither the public marker nor this successful function authenticates a PC.
use crate::{CancellationToken, READY_MARKER, Registration};
use std::{fmt, future::Future, io, net::SocketAddr, pin::pin, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const CLIENT_RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
/// RFC 8305 connection attempt delay: the next address is dialled this long
/// after the previous one, or at once when an attempt in flight fails.
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// READY bound on the one registered socket of a multi-address race.
const RACE_RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(5);
/// Distinct addresses one race dials at most.
const MAX_RACE_ADDRESSES: usize = 5;

/// Opaque byte carrier only, deliberately not named authenticated/ready/paired.
pub struct RendezvousCarrier(TcpStream);
impl RendezvousCarrier {
    /// Move directly into the endpoint's bounded, authenticated TLS actor.
    /// Do not send plaintext application requests or credentials on this stream.
    pub fn into_stream(self) -> TcpStream {
        self.0
    }
}
impl fmt::Debug for RendezvousCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendezvousCarrier([unauthenticated])")
    }
}

pub async fn connect_rendezvous(
    address: SocketAddr,
    registration: Registration,
    stop: CancellationToken,
) -> Result<RendezvousCarrier, RendezvousError> {
    let mut stream = tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(RendezvousError::Cancelled),
        result = timeout(CONNECT_TIMEOUT, TcpStream::connect(address)) => {
            result.map_err(|_| RendezvousError::ConnectTimeout)?.map_err(connect_failure)?
        }
    };
    register(&mut stream, registration, CLIENT_RENDEZVOUS_TIMEOUT, &stop).await?;
    Ok(RendezvousCarrier(stream))
}

/// A refused or reset connect proves that a host answered at this address;
/// any other connect error never reached one.
fn connect_failure(error: io::Error) -> RendezvousError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            RendezvousError::Refused
        }
        _ => RendezvousError::Connection,
    }
}

/// Dial several addresses of one relay and register on exactly one socket.
///
/// The TCP connects race in the RFC 8305 manner: the addresses are deduplicated
/// in order (at most five are used), the first is dialled at once and each
/// further one 250 ms after the previous, or at once when an attempt in flight
/// fails. Every connect is bounded by [`CONNECT_TIMEOUT`].
///
/// The first completed handshake wins. Every other attempt is cancelled and its
/// socket closed before the registration is written on the winner, because a
/// relay evicts an active pair when a second registration arrives on the same
/// route. The winner must deliver READY within five seconds; when it times out,
/// closes or sends a wrong marker, its socket is closed and the race resumes
/// over the addresses whose connect has not failed yet.
///
/// When every address fails, the error is the one that got furthest: a relay
/// that accepted the connect but sent no READY, then a refused connect, then an
/// address that never answered. Equal ones report the latest.
///
/// `stop` ends the call promptly and no attempt outlives it. Single-address
/// callers keep [`connect_rendezvous`] and its longer READY wait.
pub async fn connect_rendezvous_any(
    addresses: &[SocketAddr],
    registration: Registration,
    stop: CancellationToken,
) -> Result<RendezvousCarrier, RendezvousError> {
    race_rendezvous(addresses, registration, stop, TcpStream::connect).await
}

/// [`connect_rendezvous_any`] with the TCP connect injected, so tests can model
/// a SYN that is never answered.
async fn race_rendezvous<C, F>(
    addresses: &[SocketAddr],
    registration: Registration,
    stop: CancellationToken,
    connect: C,
) -> Result<RendezvousCarrier, RendezvousError>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<TcpStream>> + Send + 'static,
{
    if stop.is_cancelled() {
        return Err(RendezvousError::Cancelled);
    }
    let mut candidates = Vec::with_capacity(MAX_RACE_ADDRESSES);
    for address in addresses {
        if candidates.len() == MAX_RACE_ADDRESSES {
            break;
        }
        if !candidates.contains(address) {
            candidates.push(*address);
        }
    }
    // The furthest registration failure so far; a later connect failure that
    // never reached a relay does not replace it.
    let mut kept: Option<RendezvousError> = None;
    loop {
        let (mut stream, winner) = match race_connect(&mut candidates, &stop, &connect).await {
            Ok(value) => value,
            Err(RendezvousError::Cancelled) => return Err(RendezvousError::Cancelled),
            Err(failure) => return Err(kept.map_or(failure, |kept| kept.furthest(failure))),
        };
        candidates.retain(|address| *address != winner);
        let registered = register(&mut stream, registration, RACE_RENDEZVOUS_TIMEOUT, &stop).await;
        match registered {
            Ok(()) => return Ok(RendezvousCarrier(stream)),
            Err(RendezvousError::Cancelled) => return Err(RendezvousError::Cancelled),
            Err(failure) => {
                let failure = kept.map_or(failure, |kept| kept.furthest(failure));
                if candidates.is_empty() {
                    return Err(failure);
                }
                kept = Some(failure);
                // The failed registration's socket closes here, before the
                // race resumes, so at most one registered socket exists.
                drop(stream);
            }
        }
    }
}

/// One race over `candidates`. Every address whose connect failed or timed out
/// is removed; the winner stays for the caller to judge. All attempts are
/// finished and their sockets closed when this returns.
async fn race_connect<C, F>(
    candidates: &mut Vec<SocketAddr>,
    stop: &CancellationToken,
    connect: &C,
) -> Result<(TcpStream, SocketAddr), RendezvousError>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<TcpStream>> + Send + 'static,
{
    let mut attempts = JoinSet::new();
    let mut started = 0;
    let mut failed = Vec::new();
    let mut error = RendezvousError::Connection;
    let mut next_start = pin!(sleep_until(Instant::now()));
    let outcome = loop {
        if attempts.is_empty() && started == candidates.len() {
            break Err(error);
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => break Err(RendezvousError::Cancelled),
            joined = attempts.join_next(), if !attempts.is_empty() => match joined {
                Some(Ok((address, Ok(stream)))) => break Ok((stream, address)),
                Some(Ok((address, Err(failure)))) => {
                    failed.push(address);
                    error = error.furthest(failure);
                    next_start.as_mut().reset(Instant::now());
                }
                Some(Err(join_error)) if join_error.is_panic() => {
                    std::panic::resume_unwind(join_error.into_panic())
                }
                // Attempts are aborted only by the shutdown below.
                Some(Err(_)) | None => {}
            },
            () = &mut next_start, if started < candidates.len() => {
                let address = candidates[started];
                started += 1;
                let attempt = connect(address);
                // The task only connects. Registration bytes are written by
                // the caller, on the winner alone, after the shutdown below.
                attempts.spawn(async move {
                    let result = match timeout(CONNECT_TIMEOUT, attempt).await {
                        Ok(Ok(stream)) => Ok(stream),
                        Ok(Err(failure)) => Err(connect_failure(failure)),
                        Err(_) => Err(RendezvousError::ConnectTimeout),
                    };
                    (address, result)
                });
                next_start
                    .as_mut()
                    .reset(Instant::now() + CONNECTION_ATTEMPT_DELAY);
            }
        }
    };
    // Abort and await every other attempt. Late handshakes that already
    // finished are dropped here too, so no losing socket stays open.
    attempts.shutdown().await;
    candidates.retain(|address| !failed.contains(address));
    outcome
}

/// Write the registration on this one socket and wait for READY within `bound`.
async fn register(
    stream: &mut TcpStream,
    registration: Registration,
    bound: Duration,
    stop: &CancellationToken,
) -> Result<(), RendezvousError> {
    // The application uses small control/TLS records. Set the actual socket
    // policy in product code, not only in a benchmark or test fixture.
    stream
        .set_nodelay(true)
        .map_err(|_| RendezvousError::Connection)?;
    let exchange = async {
        stream
            .write_all(&registration.to_wire())
            .await
            .map_err(|_| RendezvousError::Closed)?;
        let mut marker = [0; READY_MARKER.len()];
        stream
            .read_exact(&mut marker)
            .await
            .map_err(|_| RendezvousError::Closed)?;
        if &marker != READY_MARKER {
            return Err(RendezvousError::InvalidMarker);
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(RendezvousError::Cancelled),
        result = timeout(bound, exchange) => {
            result.map_err(|_| RendezvousError::RendezvousTimeout)?
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RendezvousError {
    #[error("rendezvous setup was cancelled")]
    Cancelled,
    #[error("rendezvous connection deadline expired")]
    ConnectTimeout,
    #[error("rendezvous waiting deadline expired")]
    RendezvousTimeout,
    #[error("rendezvous connection could not complete")]
    Connection,
    /// The host at the address refused or reset the TCP connect.
    #[error("rendezvous connection was refused")]
    Refused,
    /// The relay accepted the connect, then closed or reset it before READY.
    #[error("rendezvous connection closed before its marker")]
    Closed,
    #[error("rendezvous marker was invalid")]
    InvalidMarker,
}

impl RendezvousError {
    /// How far a failed setup got: no host answered, a host refused the
    /// connect, or a relay accepted it and sent no READY.
    const fn progress(self) -> u8 {
        match self {
            Self::Cancelled | Self::ConnectTimeout | Self::Connection => 0,
            Self::Refused => 1,
            Self::Closed | Self::RendezvousTimeout | Self::InvalidMarker => 2,
        }
    }

    /// The failure that got further; on a tie, the later one.
    const fn furthest(self, later: Self) -> Self {
        if later.progress() >= self.progress() {
            later
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    //! Races driven through the injectable connector. Relay stand-ins tolerate
    //! split reads and treat a reset exactly like EOF.
    use super::*;
    use crate::{HEADER_BYTES, Role, RouteId};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{net::TcpListener, sync::Barrier, time::sleep};

    fn registration() -> Registration {
        Registration::new(
            Role::Phone,
            RouteId::new([41; 32]).expect("synthetic route"),
        )
    }

    /// TEST-NET-1 addresses; the injected connectors never dial them.
    fn unroutable(host: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, host], 7443))
    }

    /// Accept once and collect what arrives until a full header, EOF, reset or
    /// silence. After a full header answer `reply` and hold the socket until
    /// `release`. Returns every byte received.
    async fn relay_stub(
        listener: TcpListener,
        reply: &'static [u8],
        release: CancellationToken,
    ) -> Vec<u8> {
        let Ok(Ok((mut socket, _))) = timeout(Duration::from_secs(3), listener.accept()).await
        else {
            return Vec::new();
        };
        let mut received = Vec::new();
        let mut buffer = [0; HEADER_BYTES];
        while received.len() < HEADER_BYTES {
            let wanted = HEADER_BYTES - received.len();
            match timeout(Duration::from_secs(3), socket.read(&mut buffer[..wanted])).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return received,
                Ok(Ok(count)) => received.extend_from_slice(&buffer[..count]),
            }
        }
        let _ = socket.write_all(reply).await;
        release.cancelled().await;
        received
    }

    /// Counts connect futures still alive; dropping an attempt leaves the count.
    struct Live(Arc<AtomicUsize>);
    impl Live {
        fn enter(count: &Arc<AtomicUsize>) -> Self {
            count.fetch_add(1, Ordering::SeqCst);
            Self(Arc::clone(count))
        }
    }
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_hanging_first_connect_does_not_delay_the_second_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();
        let black_hole = unroutable(1);
        let release = CancellationToken::new();
        let server = tokio::spawn(relay_stub(listener, READY_MARKER, release.clone()));
        let began = Instant::now();
        let carrier = timeout(
            Duration::from_secs(3),
            race_rendezvous(
                &[black_hole, reachable],
                registration(),
                CancellationToken::new(),
                move |address| async move {
                    if address == black_hole {
                        // A SYN that is never answered.
                        std::future::pending::<()>().await;
                    }
                    TcpStream::connect(address).await
                },
            ),
        )
        .await
        .expect("bounded race")
        .expect("carrier from the second address");
        let elapsed = began.elapsed();
        assert!(elapsed < Duration::from_millis(1500), "took {elapsed:?}");
        let stream = carrier.into_stream();
        assert_eq!(stream.peer_addr().unwrap(), reachable);
        assert!(stream.nodelay().unwrap());
        release.cancel();
        assert_eq!(server.await.unwrap(), registration().to_wire());
    }

    #[tokio::test]
    async fn the_losing_handshake_never_receives_a_registration_byte() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let second_address = second.local_addr().unwrap();
        let release = CancellationToken::new();
        let first_server = tokio::spawn(relay_stub(first, READY_MARKER, release.clone()));
        let second_server = tokio::spawn(relay_stub(second, READY_MARKER, release.clone()));
        // Neither attempt reports before both handshakes are complete, so the
        // race really has a connected loser the relay can accept.
        let both_connected = Arc::new(Barrier::new(2));
        let carrier = timeout(
            Duration::from_secs(3),
            race_rendezvous(
                &[first_address, second_address],
                registration(),
                CancellationToken::new(),
                move |address| {
                    let both_connected = Arc::clone(&both_connected);
                    async move {
                        let stream = TcpStream::connect(address).await?;
                        both_connected.wait().await;
                        Ok::<_, io::Error>(stream)
                    }
                },
            ),
        )
        .await
        .expect("bounded race")
        .expect("carrier");
        let stream = carrier.into_stream();
        let winner = stream.peer_addr().unwrap();
        release.cancel();
        let first_bytes = timeout(Duration::from_secs(10), first_server)
            .await
            .unwrap()
            .unwrap();
        let second_bytes = timeout(Duration::from_secs(10), second_server)
            .await
            .unwrap()
            .unwrap();
        let (winner_bytes, loser_bytes) = if winner == first_address {
            (first_bytes, second_bytes)
        } else {
            assert_eq!(winner, second_address);
            (second_bytes, first_bytes)
        };
        assert_eq!(winner_bytes, registration().to_wire());
        assert!(loser_bytes.is_empty(), "the loser received {loser_bytes:?}");
        drop(stream);
    }

    #[tokio::test]
    async fn cancelling_the_race_returns_promptly_and_leaves_no_attempt_running() {
        let started = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let addresses = [unroutable(1), unroutable(2), unroutable(3)];
        let connector = {
            let started = Arc::clone(&started);
            let live = Arc::clone(&live);
            move |_address: SocketAddr| {
                started.fetch_add(1, Ordering::SeqCst);
                let live = Arc::clone(&live);
                async move {
                    let _live = Live::enter(&live);
                    std::future::pending::<io::Result<TcpStream>>().await
                }
            }
        };
        let canceller = async {
            timeout(Duration::from_secs(2), async {
                while live.load(Ordering::SeqCst) < 2 {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("two attempts in flight");
            stop.cancel();
            Instant::now()
        };
        let (result, cancelled_at) = tokio::join!(
            race_rendezvous(&addresses, registration(), stop.clone(), connector),
            canceller
        );
        let returned_after = cancelled_at.elapsed();
        assert_eq!(result.unwrap_err(), RendezvousError::Cancelled);
        assert!(
            returned_after < Duration::from_millis(500),
            "took {returned_after:?}"
        );
        assert_eq!(
            live.load(Ordering::SeqCst),
            0,
            "an attempt outlived the race"
        );
        let attempts = started.load(Ordering::SeqCst);
        sleep(2 * CONNECTION_ATTEMPT_DELAY).await;
        assert_eq!(
            started.load(Ordering::SeqCst),
            attempts,
            "an attempt started after the race ended"
        );
    }

    #[tokio::test]
    async fn an_already_cancelled_race_never_dials() {
        let stop = CancellationToken::new();
        stop.cancel();
        let dialled = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dialled);
        let result = race_rendezvous(
            &[unroutable(1), unroutable(2)],
            registration(),
            stop,
            move |address| {
                counter.fetch_add(1, Ordering::SeqCst);
                TcpStream::connect(address)
            },
        )
        .await;
        assert_eq!(result.unwrap_err(), RendezvousError::Cancelled);
        assert_eq!(dialled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_connects_start_the_next_address_at_once_and_each_is_dialled_once() {
        let dialled = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&dialled);
        let began = Instant::now();
        let result = race_rendezvous(
            &[unroutable(1), unroutable(2), unroutable(1), unroutable(3)],
            registration(),
            CancellationToken::new(),
            move |address| {
                record.lock().unwrap().push(address);
                async { Err::<TcpStream, _>(io::Error::from(io::ErrorKind::ConnectionRefused)) }
            },
        )
        .await;
        let elapsed = began.elapsed();
        assert_eq!(result.unwrap_err(), RendezvousError::Refused);
        assert!(elapsed < CONNECTION_ATTEMPT_DELAY, "took {elapsed:?}");
        assert_eq!(
            *dialled.lock().unwrap(),
            [unroutable(1), unroutable(2), unroutable(3)]
        );
    }

    #[tokio::test]
    async fn a_winner_with_a_wrong_marker_is_closed_and_the_race_resumes_without_it() {
        let wrong = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let right = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let wrong_address = wrong.local_addr().unwrap();
        let right_address = right.local_addr().unwrap();
        let release = CancellationToken::new();
        let wrong_server = tokio::spawn(relay_stub(wrong, b"BADMARKER", release.clone()));
        let right_server = tokio::spawn(relay_stub(right, READY_MARKER, release.clone()));
        let dialled = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&dialled);
        let carrier = timeout(
            Duration::from_secs(3),
            race_rendezvous(
                &[wrong_address, right_address],
                registration(),
                CancellationToken::new(),
                move |address| {
                    record.lock().unwrap().push(address);
                    TcpStream::connect(address)
                },
            ),
        )
        .await
        .expect("bounded race")
        .expect("carrier from the second address");
        assert_eq!(carrier.into_stream().peer_addr().unwrap(), right_address);
        assert_eq!(*dialled.lock().unwrap(), [wrong_address, right_address]);
        release.cancel();
        assert_eq!(wrong_server.await.unwrap(), registration().to_wire());
        assert_eq!(right_server.await.unwrap(), registration().to_wire());
    }

    #[test]
    fn only_a_refused_or_reset_connect_counts_as_an_answering_host() {
        for (kind, expected) in [
            (io::ErrorKind::ConnectionRefused, RendezvousError::Refused),
            (io::ErrorKind::ConnectionReset, RendezvousError::Refused),
            (
                io::ErrorKind::NetworkUnreachable,
                RendezvousError::Connection,
            ),
            (io::ErrorKind::HostUnreachable, RendezvousError::Connection),
            (
                io::ErrorKind::ConnectionAborted,
                RendezvousError::Connection,
            ),
            (io::ErrorKind::AddrNotAvailable, RendezvousError::Connection),
        ] {
            assert_eq!(connect_failure(io::Error::from(kind)), expected, "{kind:?}");
        }
    }

    #[tokio::test]
    async fn a_refusal_outranks_an_address_that_never_answered_in_either_order() {
        for (refused, unreachable) in [
            (unroutable(1), unroutable(2)),
            (unroutable(2), unroutable(1)),
        ] {
            let result = race_rendezvous(
                &[unroutable(1), unroutable(2)],
                registration(),
                CancellationToken::new(),
                move |address| async move {
                    let kind = if address == refused {
                        io::ErrorKind::ConnectionRefused
                    } else {
                        assert_eq!(address, unreachable);
                        io::ErrorKind::NetworkUnreachable
                    };
                    Err::<TcpStream, _>(io::Error::from(kind))
                },
            )
            .await;
            assert_eq!(result.unwrap_err(), RendezvousError::Refused);
        }
    }

    #[tokio::test]
    async fn a_relay_that_closes_before_ready_outranks_a_later_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closing = listener.local_addr().unwrap();
        let refused = unroutable(1);
        // Read the whole registration, then close without READY.
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = [0; HEADER_BYTES];
            socket.read_exact(&mut header).await.unwrap();
            header
        });
        let result = timeout(
            Duration::from_secs(3),
            race_rendezvous(
                &[closing, refused],
                registration(),
                CancellationToken::new(),
                move |address| async move {
                    if address == refused {
                        return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
                    }
                    TcpStream::connect(address).await
                },
            ),
        )
        .await
        .expect("bounded race");
        assert_eq!(result.unwrap_err(), RendezvousError::Closed);
        assert_eq!(server.await.unwrap(), registration().to_wire());
    }

    #[tokio::test]
    async fn a_single_relay_that_closes_before_ready_is_not_a_connect_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut header = [0; HEADER_BYTES];
            socket.read_exact(&mut header).await.unwrap();
        });
        let result = timeout(
            Duration::from_secs(3),
            connect_rendezvous(address, registration(), CancellationToken::new()),
        )
        .await
        .expect("bounded setup");
        assert_eq!(result.unwrap_err(), RendezvousError::Closed);
        server.await.unwrap();
    }
}
