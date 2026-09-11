// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-owned outbound rendezvous dialer. A relay-ready byte stream is still
//! unauthenticated and enters the existing peer-pinned TLS carrier path.
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use approval_protocol::DeviceId;
use framed_transport::CancellationToken;
use relay_service::{Registration, Role, RouteId, connect_rendezvous};
use tokio::{sync::mpsc, task::JoinSet};

use super::ServicePeerCarrier;

const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const TICK: Duration = Duration::from_millis(100);
const MAX_DEVICES: usize = 32;

enum Command {
    Poll {
        routes: Vec<(DeviceId, SocketAddr, RouteId)>,
        now: Instant,
    },
    Released(DeviceId),
    Cancel,
}
struct ResultMessage {
    device: DeviceId,
    relay: SocketAddr,
    route: RouteId,
    generation: u64,
    stream: Option<std::net::TcpStream>,
}
struct Entry {
    relay: SocketAddr,
    route: RouteId,
    generation: u64,
    next_attempt: Instant,
    backoff: Duration,
    dialing: bool,
    delivered: bool,
}

pub(super) struct DeviceDialer {
    relay: SocketAddr,
    commands: mpsc::Sender<Command>,
    results: std::sync::mpsc::Receiver<ResultMessage>,
    stop: CancellationToken,
    thread: Option<JoinHandle<()>>,
    pending_releases: BTreeSet<DeviceId>,
}
impl fmt::Debug for DeviceDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceDialer")
            .field(
                "thread_finished",
                &self.thread.as_ref().is_none_or(JoinHandle::is_finished),
            )
            .finish_non_exhaustive()
    }
}

impl DeviceDialer {
    pub(super) fn new(relay: SocketAddr) -> Result<Self, super::PeerRuntimeError> {
        let stop = CancellationToken::new();
        let thread_stop = stop.clone();
        let (command_sender, commands) = mpsc::channel(MAX_DEVICES + 2);
        let (result_sender, results) = std::sync::mpsc::sync_channel(MAX_DEVICES);
        let (startup_sender, startup) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("service-dialer".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = startup_sender.send(false);
                    return;
                };
                if startup_sender.send(true).is_err() {
                    return;
                }
                runtime.block_on(run(commands, result_sender, thread_stop));
            })
            .map_err(|_| super::PeerRuntimeError::Io)?;
        if startup.recv() != Ok(true) {
            stop.cancel();
            let _ = thread.join();
            return Err(super::PeerRuntimeError::Io);
        }
        Ok(Self {
            relay,
            commands: command_sender,
            results,
            stop,
            thread: Some(thread),
            pending_releases: BTreeSet::new(),
        })
    }

    pub(super) fn poll(
        &mut self,
        routes: &[(DeviceId, SocketAddr, RouteId)],
        now: Instant,
    ) -> Vec<ServicePeerCarrier> {
        self.flush_releases();
        let mut bounded: Vec<_> = routes
            .iter()
            .filter(|(_, relay, _)| *relay == self.relay)
            .take(MAX_DEVICES)
            .cloned()
            .collect();
        bounded.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        let _ = self.commands.try_send(Command::Poll {
            routes: bounded,
            now,
        });
        let mut carriers = Vec::new();
        while carriers.len() < MAX_DEVICES {
            match self.results.try_recv() {
                Ok(ResultMessage {
                    device,
                    stream: Some(stream),
                    ..
                }) => carriers.push(ServicePeerCarrier { stream, device }),
                Ok(ResultMessage { stream: None, .. }) => (),
                Err(_) => break,
            }
        }
        carriers
    }

    pub(super) fn release(&mut self, device: DeviceId) {
        self.pending_releases.insert(device);
        self.flush_releases();
    }

    fn flush_releases(&mut self) {
        let pending: Vec<_> = self.pending_releases.iter().copied().collect();
        for device in pending {
            match self.commands.try_send(Command::Released(device)) {
                Ok(()) => {
                    self.pending_releases.remove(&device);
                }
                Err(mpsc::error::TrySendError::Full(_)) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending_releases.clear();
                    break;
                }
            }
        }
    }

    pub(super) fn cancel(&mut self) {
        self.stop.cancel();
        let _ = self.commands.try_send(Command::Cancel);
    }

    pub(super) fn drain(&mut self) -> bool {
        self.cancel();
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.thread.take().map(JoinHandle::join);
        }
        self.thread.is_none()
    }

    pub(super) fn remaining_owners(&self) -> usize {
        usize::from(self.thread.is_some())
    }
}
impl Drop for DeviceDialer {
    fn drop(&mut self) {
        self.cancel();
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.thread.take().map(JoinHandle::join);
        }
    }
}

async fn run(
    mut commands: mpsc::Receiver<Command>,
    results: std::sync::mpsc::SyncSender<ResultMessage>,
    stop: CancellationToken,
) {
    let mut entries = BTreeMap::<DeviceId, Entry>::new();
    let mut tasks = JoinSet::new();
    let mut ticker = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => break,
            command = commands.recv() => match command {
                Some(Command::Poll { routes, now }) => {
                    synchronize(&mut entries, routes, now);
                    start_due_dials(&mut entries, &mut tasks, now, &stop);
                }
                Some(Command::Released(device)) => {
                    if let Some(entry) = entries.get_mut(&device) {
                        entry.delivered = false;
                        entry.next_attempt = Instant::now();
                        entry.backoff = FIRST_BACKOFF;
                    }
                }
                Some(Command::Cancel) | None => break,
            },
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok(message)) = joined {
                    let current = entries.get_mut(&message.device).filter(|entry| {
                        entry.relay == message.relay
                            && entry.route == message.route
                            && entry.generation == message.generation
                    });
                    if let Some(entry) = current {
                        entry.dialing = false;
                        if message.stream.is_some() {
                            entry.delivered = true;
                            entry.backoff = FIRST_BACKOFF;
                        } else if let Ok((next_attempt, next_backoff)) =
                            retry_after(Instant::now(), entry.backoff)
                        {
                            entry.next_attempt = next_attempt;
                            entry.backoff = next_backoff;
                        } else {
                            entry.delivered = true;
                        }
                        let _ = results.try_send(message);
                    }
                }
            }
            _ = ticker.tick() => {
                start_due_dials(&mut entries, &mut tasks, Instant::now(), &stop);
            }
        }
    }
    stop.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

fn start_due_dials(
    entries: &mut BTreeMap<DeviceId, Entry>,
    tasks: &mut JoinSet<ResultMessage>,
    now: Instant,
    stop: &CancellationToken,
) {
    for (device, entry) in entries {
        if entry.dialing || entry.delivered || now < entry.next_attempt {
            continue;
        }
        entry.dialing = true;
        let device = *device;
        let relay = entry.relay;
        let route = entry.route;
        let generation = entry.generation;
        let task_stop = stop.child_token();
        tasks.spawn(async move {
            let stream = match connect_rendezvous(
                relay,
                Registration::new(Role::Pc, route),
                task_stop,
            )
            .await
            {
                Ok(carrier) => carrier
                    .into_stream()
                    .into_std()
                    .ok()
                    .and_then(|stream| stream.set_nonblocking(false).ok().map(|()| stream)),
                Err(_) => None,
            };
            ResultMessage {
                device,
                relay,
                route,
                generation,
                stream,
            }
        });
    }
}

fn retry_after(now: Instant, backoff: Duration) -> Result<(Instant, Duration), ()> {
    Ok((
        now.checked_add(backoff).ok_or(())?,
        backoff.saturating_mul(2).min(MAX_BACKOFF),
    ))
}

fn synchronize(
    entries: &mut BTreeMap<DeviceId, Entry>,
    routes: Vec<(DeviceId, SocketAddr, RouteId)>,
    now: Instant,
) {
    let retained: BTreeSet<_> = routes.iter().map(|(device, _, _)| *device).collect();
    entries.retain(|device, _| retained.contains(device));
    for (device, relay, route) in routes {
        match entries.get_mut(&device) {
            Some(entry) if entry.relay != relay || entry.route != route => {
                entry.relay = relay;
                entry.route = route;
                entry.generation = entry.generation.wrapping_add(1).max(1);
                entry.next_attempt = now;
                entry.backoff = FIRST_BACKOFF;
                entry.dialing = false;
                entry.delivered = false;
            }
            Some(_) => {}
            None => {
                entries.insert(
                    device,
                    Entry {
                        relay,
                        route,
                        generation: 1_u64,
                        next_attempt: now,
                        backoff: FIRST_BACKOFF,
                        dialing: false,
                        delivered: false,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc as sync_mpsc,
        thread,
    };

    fn device(value: u8) -> DeviceId {
        DeviceId::from_bytes([value; 16]).unwrap()
    }

    #[test]
    fn retry_backoff_starts_at_five_seconds_and_caps_at_sixty() {
        let now = Instant::now();
        let mut backoff = FIRST_BACKOFF;
        for expected in [5, 10, 20, 40, 60, 60] {
            assert_eq!(backoff, Duration::from_secs(expected));
            let (next, doubled) = retry_after(now, backoff).unwrap();
            assert_eq!(next.duration_since(now), backoff);
            backoff = doubled;
        }
        assert_eq!(backoff, MAX_BACKOFF);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn loopback_dial_succeeds_once_and_waits_for_release() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let relay = listener.local_addr().unwrap();
        let route = RouteId::new([7; 32]).unwrap();
        let expected = Registration::new(Role::Pc, route).to_wire();
        let (accepted_sender, accepted) = sync_mpsc::channel();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut connections = 0;
            // Accepted sockets stay open until the test joins this thread: a
            // Windows socket dropped right after its write can reset the peer
            // before the READY marker was read.
            let mut kept = Vec::new();
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Windows hands out nonblocking accepted sockets from a
                        // nonblocking listener; the fake relay reads synchronously.
                        stream.set_nonblocking(false).unwrap();
                        let mut registration = vec![0; expected.len()];
                        stream.read_exact(&mut registration).unwrap();
                        assert_eq!(registration, expected);
                        stream.write_all(relay_service::READY_MARKER).unwrap();
                        kept.push(stream);
                        connections += 1;
                        accepted_sender.send(connections).unwrap();
                        if connections == 2 {
                            return kept;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::yield_now();
                    }
                    Err(error) => panic!("loopback relay failed: {error}"),
                }
            }
            kept
        });
        let mut dialer = DeviceDialer::new(relay).unwrap();
        let routes = [(device(1), relay, route)];
        let deadline = Instant::now() + Duration::from_secs(5);
        let carrier = loop {
            let mut carriers = dialer.poll(&routes, Instant::now());
            if let Some(carrier) = carriers.pop() {
                break carrier;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(carrier.device, device(1));
        assert_eq!(accepted.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        drop(carrier);
        let quiet_until = Instant::now() + Duration::from_millis(250);
        while Instant::now() < quiet_until {
            assert!(dialer.poll(&routes, Instant::now()).is_empty());
            thread::yield_now();
        }
        assert!(accepted.try_recv().is_err());
        dialer.release(device(1));
        assert_eq!(accepted.recv_timeout(Duration::from_secs(5)).unwrap(), 2);
        let deadline = Instant::now() + Duration::from_secs(5);
        while dialer.poll(&routes, Instant::now()).is_empty() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        dialer.cancel();
        while !dialer.drain() {
            thread::yield_now();
        }
        let _kept_open_until_now = server.join().unwrap();
    }

    #[test]
    fn unchanged_route_keeps_delivery_and_changed_route_invalidates_generation() {
        let relay: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let first = RouteId::new([3; 32]).unwrap();
        let second = RouteId::new([4; 32]).unwrap();
        let mut entries = BTreeMap::new();
        let now = Instant::now();
        synchronize(&mut entries, vec![(device(1), relay, first)], now);
        let entry = entries.get_mut(&device(1)).unwrap();
        entry.delivered = true;
        let generation = entry.generation;

        synchronize(&mut entries, vec![(device(1), relay, first)], now);
        let entry = entries.get(&device(1)).unwrap();
        assert!(entry.delivered);
        assert_eq!(entry.generation, generation);

        let changed_at = now + Duration::from_secs(1);
        synchronize(&mut entries, vec![(device(1), relay, second)], changed_at);
        let entry = entries.get(&device(1)).unwrap();
        assert!(!entry.delivered);
        assert_eq!(entry.generation, generation + 1);
        assert_eq!(entry.next_attempt, changed_at);
    }
}
