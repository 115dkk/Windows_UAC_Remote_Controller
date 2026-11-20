// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::{Instant, sleep_until, timeout_at},
};

use crate::{
    ACCEPT_BACKOFF, COPY_BUFFER_BYTES, CancellationToken, EVICTION_COOLDOWN_INITIAL,
    EVICTION_COOLDOWN_MAX, EVICTION_RECORDS_PER_WAITING_ROOM, HEADER_BYTES,
    MAX_CONSECUTIVE_ACCEPT_FAILURES, MAX_TASK_FAILURES, PcRoleSource, READY_MARKER, Registration,
    RelayAbuseCounters, RelayError, RelayLimits, RelayPolicy, RelayReport, Role, RouteId,
    SHORT_LIVED,
};

struct Peer {
    socket: TcpStream,
    // At most one opaque byte may arrive before pairing. It stays with this
    // socket and is forwarded once, after both markers, never to another room.
    early_byte: Option<u8>,
    // Moved with the socket, including through the one-shot handoff. Closing a
    // task must not release a slot while another task still owns its socket.
    _permit: OwnedSemaphorePermit,
}

struct Register {
    id: u64,
    registration: Registration,
    source: SocketAddr,
    deadline: Instant,
    assignment: oneshot::Sender<Assignment>,
}

enum Assignment {
    Lead {
        counterpart: oneshot::Receiver<Peer>,
        paired_at: Instant,
        eviction: CancellationToken,
    },
    Follow {
        handoff: oneshot::Sender<Peer>,
        paired_at: Instant,
        eviction: CancellationToken,
    },
    Reject,
}

enum RouteState {
    Waiting(Register),
    Active {
        leader: u64,
        follower: u64,
        // A follower may finish before handing its socket to the leader. Keep
        // that one returned socket here until this exact leader generation ends.
        retired_follower: Option<Peer>,
        // Belongs to this generation only. `register` removes the generation
        // from the map and then cancels this, so a task that observes it can
        // never match, retire or refill the entry that replaced it.
        eviction: CancellationToken,
    },
}

#[derive(Clone, Copy)]
enum EndReason {
    InvalidHeader,
    HeaderTimeout,
    WaitingTimeout,
    RendezvousTimeout,
    IdleTimeout,
    AbsoluteTimeout,
    Disconnected,
    IoFailure,
    Cancelled,
    // A fresh registration replaced this task's pair; `register` counted it.
    Evicted,
    Rejected,
    Transferred,
}

struct TaskExit {
    id: u64,
    route: Option<RouteId>,
    reason: EndReason,
    // Keep sockets/permits alive until the coordinator has retired the exact
    // route generation. Remote-observed EOF must not precede that retirement.
    retired: HeldPeers,
}

struct HeldPeers {
    first: Option<Peer>,
    second: Option<Peer>,
}

#[derive(Debug, Default)]
pub(crate) struct RelayAbuseCounterStore {
    evicted_pairs: AtomicU64,
    rejected_duplicates: AtomicU64,
    rejected_pc_sources: AtomicU64,
    rejected_evictions: AtomicU64,
}

impl RelayAbuseCounterStore {
    pub(crate) fn snapshot(&self) -> RelayAbuseCounters {
        RelayAbuseCounters {
            evicted_pairs: self.evicted_pairs.load(Ordering::Relaxed),
            rejected_duplicates: self.rejected_duplicates.load(Ordering::Relaxed),
            rejected_pc_sources: self.rejected_pc_sources.load(Ordering::Relaxed),
            rejected_evictions: self.rejected_evictions.load(Ordering::Relaxed),
        }
    }

    fn increment(counter: &AtomicU64) {
        let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }

    pub(crate) fn count_evicted_pair(&self) {
        Self::increment(&self.evicted_pairs);
    }

    pub(crate) fn count_rejected_duplicate(&self) {
        Self::increment(&self.rejected_duplicates);
    }

    pub(crate) fn count_rejected_pc_source(&self) {
        Self::increment(&self.rejected_pc_sources);
    }

    pub(crate) fn count_rejected_eviction(&self) {
        Self::increment(&self.rejected_evictions);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvictionStage {
    Idle,
    WaitingEvictor {
        id: u64,
    },
    ActivePair {
        leader: u64,
        paired_at: Instant,
        strike_if_short: bool,
    },
}

#[derive(Clone, Copy, Debug)]
struct EvictionRecord {
    strikes: u8,
    cooldown_until: Option<Instant>,
    stage: EvictionStage,
    touched_at: Instant,
}

struct EvictionTracker {
    records: BTreeMap<RouteId, EvictionRecord>,
    capacity: usize,
}

impl EvictionTracker {
    fn new(limits: RelayLimits) -> Self {
        Self {
            records: BTreeMap::new(),
            capacity: limits
                .waiting_rooms
                .saturating_mul(EVICTION_RECORDS_PER_WAITING_ROOM)
                .max(1),
        }
    }

    fn purge_untracked_idle_records(&mut self) {
        self.records
            .retain(|_, record| record.stage != EvictionStage::Idle || record.strikes > 0);
    }

    fn ensure_room(&mut self, route: RouteId) {
        if self.records.contains_key(&route) {
            return;
        }
        self.purge_untracked_idle_records();
        if self.records.len() < self.capacity {
            return;
        }
        let oldest_idle = self
            .records
            .iter()
            .filter(|(_, record)| record.stage == EvictionStage::Idle)
            .min_by_key(|(_, record)| record.touched_at)
            .map(|(route, _)| *route);
        let oldest = oldest_idle.or_else(|| {
            self.records
                .iter()
                .min_by_key(|(_, record)| record.touched_at)
                .map(|(route, _)| *route)
        });
        if let Some(oldest) = oldest {
            self.records.remove(&oldest);
        }
    }

    fn start_evictor(&mut self, route: RouteId, id: u64, now: Instant) {
        self.ensure_room(route);
        let record = self.records.entry(route).or_insert(EvictionRecord {
            strikes: 0,
            cooldown_until: None,
            stage: EvictionStage::Idle,
            touched_at: now,
        });
        record.stage = EvictionStage::WaitingEvictor { id };
        record.touched_at = now;
    }

    fn pair_formed(&mut self, route: RouteId, leader: u64, follower: u64, paired_at: Instant) {
        let Some(record) = self.records.get_mut(&route) else {
            return;
        };
        let strike_if_short = matches!(
            record.stage,
            EvictionStage::WaitingEvictor { id } if id == leader || id == follower
        );
        record.stage = EvictionStage::ActivePair {
            leader,
            paired_at,
            strike_if_short,
        };
        record.touched_at = paired_at;
    }

    fn waiting_evictor_ended(&mut self, route: RouteId, id: u64, now: Instant) {
        let matches = matches!(
            self.records.get(&route).map(|record| record.stage),
            Some(EvictionStage::WaitingEvictor { id: pending }) if pending == id
        );
        if matches {
            self.strike(route, now);
        }
    }

    fn account_pair_before_eviction(&mut self, route: RouteId, leader: u64, now: Instant) {
        let survived = matches!(
            self.records.get(&route).map(|record| record.stage),
            Some(EvictionStage::ActivePair {
                leader: recorded,
                paired_at,
                ..
            }) if recorded == leader && now > paired_at + SHORT_LIVED
        );
        if survived {
            self.records.remove(&route);
            return;
        }

        let Some(record) = self.records.get_mut(&route) else {
            return;
        };
        let EvictionStage::ActivePair {
            leader: recorded,
            strike_if_short,
            ..
        } = &mut record.stage
        else {
            return;
        };
        if *recorded != leader || !*strike_if_short {
            return;
        }

        // The attempted replacement is charged against this still-live pair.
        // Clear the marker before applying the strike so this generation's
        // eventual completion cannot charge the same short lifetime twice.
        *strike_if_short = false;
        record.touched_at = now;
        Self::apply_strike(record, now);
    }

    fn pair_ended(&mut self, route: RouteId, leader: u64, now: Instant) {
        let Some(mut record) = self.records.remove(&route) else {
            return;
        };
        let EvictionStage::ActivePair {
            leader: recorded,
            paired_at,
            strike_if_short,
        } = record.stage
        else {
            self.records.insert(route, record);
            return;
        };
        if recorded != leader {
            self.records.insert(route, record);
            return;
        }
        if now > paired_at + SHORT_LIVED {
            return;
        }
        record.stage = EvictionStage::Idle;
        record.touched_at = now;
        if strike_if_short {
            Self::apply_strike(&mut record, now);
        }
        if record.strikes > 0 {
            self.records.insert(route, record);
        }
    }

    fn strike(&mut self, route: RouteId, now: Instant) {
        let Some(record) = self.records.get_mut(&route) else {
            return;
        };
        record.stage = EvictionStage::Idle;
        record.touched_at = now;
        Self::apply_strike(record, now);
    }

    fn apply_strike(record: &mut EvictionRecord, now: Instant) {
        record.strikes = record.strikes.saturating_add(1).min(6);
        let cooldown = cooldown_for_strikes(record.strikes);
        record.cooldown_until = (!cooldown.is_zero()).then(|| now + cooldown);
    }

    fn is_cooling_down(&mut self, route: RouteId, now: Instant) -> bool {
        let cooling = self
            .records
            .get(&route)
            .and_then(|record| record.cooldown_until)
            .is_some_and(|until| now < until);
        if !cooling
            && matches!(
                self.records.get(&route),
                Some(record) if record.stage == EvictionStage::Idle && record.strikes == 0
            )
        {
            self.records.remove(&route);
        }
        cooling
    }
}

fn cooldown_for_strikes(strikes: u8) -> Duration {
    if strikes < 2 {
        return Duration::ZERO;
    }
    let multiplier = 1_u32 << u32::from(strikes.saturating_sub(2).min(4));
    EVICTION_COOLDOWN_INITIAL
        .saturating_mul(multiplier)
        .min(EVICTION_COOLDOWN_MAX)
}

struct RouteRegistry {
    routes: BTreeMap<RouteId, RouteState>,
    limits: RelayLimits,
    policy: RelayPolicy,
    evictions: EvictionTracker,
    abuse: Arc<RelayAbuseCounterStore>,
}

impl RouteRegistry {
    fn new(limits: RelayLimits, policy: RelayPolicy, abuse: Arc<RelayAbuseCounterStore>) -> Self {
        Self {
            routes: BTreeMap::new(),
            limits,
            policy,
            evictions: EvictionTracker::new(limits),
            abuse,
        }
    }

    fn count_eviction(&self, report: &mut RelayReport) {
        report.evicted_pairs = report.evicted_pairs.saturating_add(1);
        self.abuse.count_evicted_pair();
    }

    fn count_duplicate(&self, report: &mut RelayReport) {
        report.rejected_duplicates = report.rejected_duplicates.saturating_add(1);
        self.abuse.count_rejected_duplicate();
    }

    fn count_pc_source_rejection(&self, report: &mut RelayReport) {
        report.rejected_pc_sources = report.rejected_pc_sources.saturating_add(1);
        self.abuse.count_rejected_pc_source();
    }

    fn count_eviction_rejection(&self, report: &mut RelayReport) {
        report.rejected_evictions = report.rejected_evictions.saturating_add(1);
        self.abuse.count_rejected_eviction();
    }

    fn clear(&mut self) {
        self.routes.clear();
    }
}

/// Run the byte rendezvous service on an already-bound caller-owned listener.
///
/// No authentication or application decryption occurs. The caller chooses the
/// listen interface; the bundled CLI defaults to loopback. Cancel and await this
/// future to obtain bounded cleanup evidence. Dropping the future cancels its
/// child token and aborts its JoinSet; it never deliberately detaches workers.
/// The returned future is explicitly spawnable. Rust checks this guarantee at
/// the library boundary; callers need not infer auto-traits through the private
/// coordinator's nested select/copy futures. This is not an unsafe assertion.
pub fn run(
    listener: TcpListener,
    limits: RelayLimits,
    cancellation: CancellationToken,
) -> impl Future<Output = Result<RelayReport, RelayError>> + Send {
    run_with_policy(listener, limits, RelayPolicy::default(), cancellation)
}

/// Run with an explicit source-admission policy; the wire contract is unchanged.
pub fn run_with_policy(
    listener: TcpListener,
    limits: RelayLimits,
    policy: RelayPolicy,
    cancellation: CancellationToken,
) -> impl Future<Output = Result<RelayReport, RelayError>> + Send {
    run_with_policy_and_counters(
        listener,
        limits,
        policy,
        cancellation,
        Arc::new(RelayAbuseCounterStore::default()),
    )
}

pub(crate) fn run_with_policy_and_counters(
    listener: TcpListener,
    limits: RelayLimits,
    policy: RelayPolicy,
    cancellation: CancellationToken,
    abuse: Arc<RelayAbuseCounterStore>,
) -> impl Future<Output = Result<RelayReport, RelayError>> + Send {
    run_loop(listener, limits, policy, cancellation, abuse)
}

async fn run_loop(
    listener: TcpListener,
    limits: RelayLimits,
    policy: RelayPolicy,
    cancellation: CancellationToken,
    abuse: Arc<RelayAbuseCounterStore>,
) -> Result<RelayReport, RelayError> {
    let cancellation = cancellation.child_token();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let permits = Arc::new(Semaphore::new(limits.connections));
    let (mailbox, mut receiver) = mpsc::channel::<Register>(limits.connections);
    let mut tasks = JoinSet::new();
    let mut routes = RouteRegistry::new(limits, policy, abuse);
    let mut report = RelayReport::default();
    let mut next_id = 0_u64;
    // Cleared by one accepted connection, so only an unbroken run of refusals
    // counts. `accept_backoff` disables the accept branch instead of awaiting
    // inside it, so a refusing listener never stalls cancellation, registration
    // or task retirement.
    let mut accept_faults = 0_u32;
    let mut accept_backoff: Option<Instant> = None;
    let mut failure = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break None,
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(exit)) => {
                        if let Err(error) =
                            routes.finish_task(exit, &mut report)
                        {
                            break Some(error);
                        }
                    }
                    Some(Err(_)) => {
                        // Nothing is aborted while this loop runs, so this is a
                        // panic. The task unwound its own sockets and slots, so
                        // that connection is already gone and the rest of the
                        // service is untouched. Its route entry is not: tokio
                        // names the task with an identifier this crate cannot
                        // read on stable, so `finish_task` never runs for it and
                        // the entry holds any retained follower socket until
                        // shutdown or until a fresh registration evicts it.
                        // Serve on, and stop once that leak adds up.
                        report.task_failures = report.task_failures.saturating_add(1);
                        if report.task_failures > MAX_TASK_FAILURES {
                            break Some(RelayError::TaskFailed);
                        }
                    }
                    None => (),
                }
            }
            registration = receiver.recv() => {
                if let Some(registration) = registration {
                    routes.register(registration, &mut report);
                }
            }
            accepted = listener.accept(), if accept_backoff.is_none() => {
                let (socket, source) = match accepted {
                    Ok(accepted) => {
                        accept_faults = 0;
                        accepted
                    }
                    // A descriptor shortage, or a client that resets while the
                    // kernel is still completing its handshake, costs the one
                    // connection it refused. Retiring the listener for it would
                    // let any client end the service for everyone.
                    Err(_) => {
                        report.accept_failures = report.accept_failures.saturating_add(1);
                        accept_faults = accept_faults.saturating_add(1);
                        match accept_setback(accept_faults, Instant::now()) {
                            Ok(until) => {
                                accept_backoff = Some(until);
                                continue;
                            }
                            Err(error) => break Some(error),
                        }
                    }
                };
                // No connection task/queue is created until its owned socket
                // slot is reserved. A full service explicitly closes new sockets.
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        report.rejected_capacity = report.rejected_capacity.saturating_add(1);
                        drop(socket);
                        continue;
                    }
                };
                let Some(id) = next_id.checked_add(1) else {
                    break Some(RelayError::IdentifierExhausted);
                };
                next_id = id;
                report.accepted = report.accepted.saturating_add(1);
                report.peak_connections = report.peak_connections.max(limits.connections - permits.available_permits());
                // Small readiness/request records must not wait for coalescing.
                // This option is socket-local, not a machine TCP policy change.
                if socket.set_nodelay(true).is_err() {
                    report.io_failures = report.io_failures.saturating_add(1);
                    drop(socket);
                    drop(permit);
                    continue;
                }
                tasks.spawn(connection(
                    id,
                    Peer {
                        socket,
                        early_byte: None,
                        _permit: permit,
                    },
                    source,
                    Instant::now(),
                    mailbox.clone(),
                    limits,
                    cancellation.clone(),
                ));
            }
            // Last, so a backoff that is already due still yields to
            // cancellation, retirement and registration first.
            _ = sleep_until(accept_backoff.unwrap_or_else(Instant::now)), if accept_backoff.is_some() => {
                accept_backoff = None;
            }
        }
    };

    drop(listener);
    cancellation.cancel();
    routes.clear(); // closes all outstanding waiting assignments
    receiver.close();
    drop(mailbox);
    while receiver.try_recv().is_ok() {} // bounded metadata-only control mailbox

    let final_deadline = Instant::now() + limits.shutdown_timeout;
    let graceful_deadline = Instant::now() + limits.shutdown_timeout / 2;
    while !tasks.is_empty() {
        match timeout_at(graceful_deadline, tasks.join_next()).await {
            Ok(Some(Ok(exit))) => {
                if let Err(error) = routes.finish_task(exit, &mut report) {
                    failure = Some(error);
                }
            }
            Ok(Some(Err(_))) => report.task_failures = report.task_failures.saturating_add(1),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if !tasks.is_empty() {
        tasks.abort_all();
    }
    while !tasks.is_empty() {
        match timeout_at(final_deadline, tasks.join_next()).await {
            Ok(Some(Ok(exit))) => {
                if let Err(error) = routes.finish_task(exit, &mut report) {
                    failure = Some(error);
                }
            }
            Ok(Some(Err(error))) if error.is_cancelled() => (),
            Ok(Some(Err(_))) => report.task_failures = report.task_failures.saturating_add(1),
            Ok(None) => break,
            Err(_) => return Err(RelayError::ShutdownIncomplete),
        }
    }
    report.remaining_connections = limits.connections - permits.available_permits();
    if report.remaining_connections != 0 {
        return Err(RelayError::ShutdownIncomplete);
    }
    if let Some(error) = failure {
        return Err(error);
    }
    if report.task_failures != 0 {
        return Err(RelayError::TaskFailed);
    }
    Ok(report)
}

/// What one refused `accept` costs. `Ok` carries the instant the listener may
/// be polled again; `Err` means it has refused for long enough to be broken
/// rather than busy, and the run stops.
fn accept_setback(consecutive: u32, now: Instant) -> Result<Instant, RelayError> {
    if consecutive > MAX_CONSECUTIVE_ACCEPT_FAILURES {
        return Err(RelayError::AcceptFailed);
    }
    Ok(now + ACCEPT_BACKOFF)
}

fn pc_source_is_allowed(
    policy: PcRoleSource,
    registration: Registration,
    source: SocketAddr,
) -> bool {
    registration.role() != Role::Pc || policy == PcRoleSource::Any || is_loopback_source(source)
}

fn is_loopback_source(source: SocketAddr) -> bool {
    match source.ip() {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

impl RouteRegistry {
    fn register(&mut self, incoming: Register, report: &mut RelayReport) {
        let now = Instant::now();
        if !pc_source_is_allowed(
            self.policy.pc_role_source(),
            incoming.registration,
            incoming.source,
        ) {
            self.count_pc_source_rejection(report);
            let _ = incoming.assignment.send(Assignment::Reject);
            return;
        }

        // Only stale waiting assignments are removed here. A live duplicate never
        // overwrites or kicks a participant that is still waiting in its role.
        let stale_waiters: Vec<_> = self
            .routes
            .iter()
            .filter_map(|(route, state)| match state {
                RouteState::Waiting(waiter)
                    if waiter.deadline <= now || waiter.assignment.is_closed() =>
                {
                    Some((*route, waiter.id))
                }
                _ => None,
            })
            .collect();
        for (route, id) in stale_waiters {
            self.routes.remove(&route);
            self.evictions.waiting_evictor_ended(route, id, now);
        }
        if incoming.deadline <= now || incoming.assignment.is_closed() {
            return;
        }
        let route = incoming.registration.route();
        match self.routes.get(&route) {
            Some(RouteState::Active { leader, .. }) => {
                let leader = *leader;
                // A fresh registration still replaces a silent pair immediately so
                // an endpoint that changed networks is not held until inactivity.
                // Source and room admission happen first. Before eviction, charge a
                // still-short-lived pair formed by the previous evictor. The first
                // consecutive strike has no cooldown; the second starts at thirty
                // seconds, then doubles to five minutes. A cooldown rejection leaves
                // the active pair alone, and its later completion cannot charge it
                // twice. A pair that survives ten seconds clears the history.
                // Endpoint identity remains the pinned inner TLS peer.
                if self.waiting_rooms() >= self.limits.waiting_rooms {
                    report.rejected_waiting_rooms = report.rejected_waiting_rooms.saturating_add(1);
                    let _ = incoming.assignment.send(Assignment::Reject);
                    return;
                }
                self.evictions
                    .account_pair_before_eviction(route, leader, now);
                if self.evictions.is_cooling_down(route, now) {
                    self.count_eviction_rejection(report);
                    let _ = incoming.assignment.send(Assignment::Reject);
                    return;
                }
                self.evict(route);
                self.count_eviction(report);
                self.evictions.start_evictor(route, incoming.id, now);
            }
            Some(RouteState::Waiting(waiter))
                if waiter.registration.role() == incoming.registration.role() =>
            {
                self.count_duplicate(report);
                let _ = incoming.assignment.send(Assignment::Reject);
                return;
            }
            _ => (),
        }
        if let Some(RouteState::Waiting(waiter)) = self.routes.remove(&route) {
            let (handoff, counterpart) = oneshot::channel();
            let leader = waiter.id;
            let follower = incoming.id;
            let eviction = CancellationToken::new();
            if waiter
                .assignment
                .send(Assignment::Lead {
                    counterpart,
                    paired_at: now,
                    eviction: eviction.clone(),
                })
                .is_ok()
            {
                self.routes.insert(
                    route,
                    RouteState::Active {
                        leader,
                        follower,
                        retired_follower: None,
                        eviction: eviction.clone(),
                    },
                );
                if incoming
                    .assignment
                    .send(Assignment::Follow {
                        handoff,
                        paired_at: now,
                        eviction,
                    })
                    .is_ok()
                {
                    self.evictions.pair_formed(route, leader, follower, now);
                    report.paired = report.paired.saturating_add(1);
                } else {
                    self.evictions.waiting_evictor_ended(route, follower, now);
                }
                // A failed follower assignment drops the one-shot sender. The
                // leader then closes under its bounded rendezvous deadline.
                return;
            }
            self.evictions.waiting_evictor_ended(route, leader, now);
            // The previous waiter has actually gone away; retain the new arrival as
            // an ordinary waiter instead of pairing it with an abandoned socket.
        }
        let waiting = self.waiting_rooms();
        if waiting >= self.limits.waiting_rooms {
            report.rejected_waiting_rooms = report.rejected_waiting_rooms.saturating_add(1);
            let _ = incoming.assignment.send(Assignment::Reject);
        } else {
            self.routes.insert(route, RouteState::Waiting(incoming));
            report.peak_waiting_rooms = report.peak_waiting_rooms.max(waiting + 1);
        }
    }

    fn waiting_rooms(&self) -> usize {
        self.routes
            .values()
            .filter(|state| matches!(state, RouteState::Waiting(_)))
            .count()
    }

    /// Retire one active generation for a fresh registration on its route.
    ///
    /// The entry leaves the map before anything closes, so the same ordering holds
    /// as for an ordinary retirement: no remote EOF precedes it, and a party that
    /// reconnects on that EOF meets the replacement, never the dead pair. The
    /// retained follower, if any, is owned by this entry alone and closes here. The
    /// leader, and a follower that has not yet claimed its assignment, observe the
    /// cancelled token and return their sockets; `finish_task` then drops them,
    /// because their identifiers no longer match anything on the route.
    fn evict(&mut self, route: RouteId) {
        if let Some(RouteState::Active {
            retired_follower,
            eviction,
            ..
        }) = self.routes.remove(&route)
        {
            eviction.cancel();
            drop(retired_follower);
        }
    }
}

async fn connection(
    id: u64,
    peer: Peer,
    source: SocketAddr,
    accepted_at: Instant,
    mailbox: mpsc::Sender<Register>,
    limits: RelayLimits,
    cancellation: CancellationToken,
) -> TaskExit {
    let mut retired = HeldPeers {
        first: Some(peer),
        second: None,
    };
    let (route, reason) = connection_work(
        id,
        &mut retired,
        source,
        accepted_at,
        mailbox,
        limits,
        cancellation,
    )
    .await;
    TaskExit {
        id,
        route,
        reason,
        retired,
    }
}

async fn connection_work(
    id: u64,
    held: &mut HeldPeers,
    source: SocketAddr,
    accepted_at: Instant,
    mailbox: mpsc::Sender<Register>,
    limits: RelayLimits,
    cancellation: CancellationToken,
) -> (Option<RouteId>, EndReason) {
    let Some(peer) = held.first.as_mut() else {
        return ended(None, EndReason::IoFailure);
    };
    let mut header = [0; HEADER_BYTES];
    let read = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return ended(None, EndReason::Cancelled),
        result = timeout_at(accepted_at + limits.header_timeout, peer.socket.read_exact(&mut header)) => result,
    };
    match read {
        Err(_) => return ended(None, EndReason::HeaderTimeout),
        Ok(Err(_)) => return ended(None, EndReason::InvalidHeader),
        Ok(Ok(_)) => (),
    }
    let registration = match Registration::from_wire(&header) {
        Ok(registration) => registration,
        Err(_) => return ended(None, EndReason::InvalidHeader),
    };
    let route = Some(registration.route());
    let deadline = Instant::now() + limits.waiting_timeout;
    let (assignment, mut assigned) = oneshot::channel();
    let registration = Register {
        id,
        registration,
        source,
        deadline,
        assignment,
    };
    let sent = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            held.second = close_assignment(&mut assigned);
            return ended(route, EndReason::Cancelled);
        },
        result = timeout_at(deadline, mailbox.send(registration)) => result,
    };
    match sent {
        Err(_) => {
            held.second = close_assignment(&mut assigned);
            return ended(route, EndReason::WaitingTimeout);
        }
        Ok(Err(_)) => {
            held.second = close_assignment(&mut assigned);
            return ended(route, EndReason::Cancelled);
        }
        Ok(Ok(())) => (),
    }

    let mut early_byte = [0; 1];
    let mut observe_eof = true;
    let assignment = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                held.second = close_assignment(&mut assigned);
                return ended(route, EndReason::Cancelled);
            },
            _ = sleep_until(deadline) => {
                held.second = close_assignment(&mut assigned);
                return ended(route, EndReason::WaitingTimeout);
            },
            result = &mut assigned => match result {
                Ok(assignment) => break assignment,
                Err(_) => {
                    held.second = close_assignment(&mut assigned);
                    return ended(route, EndReason::Rejected);
                },
            },
            result = peer.socket.read(&mut early_byte), if observe_eof => match result {
                Ok(0) => {
                    held.second = close_assignment(&mut assigned);
                    return ended(route, EndReason::Disconnected);
                },
                // Use the same cancel-safe AsyncRead path as active copying,
                // instead of switching a pending MSG_PEEK readiness waiter to
                // another task during handoff. Preserve the sole consumed byte
                // without interpretation; no repeated readable-data spin.
                Ok(_) => {
                    peer.early_byte = Some(early_byte[0]);
                    observe_eof = false;
                }
                Err(_) => {
                    held.second = close_assignment(&mut assigned);
                    return ended(route, EndReason::IoFailure);
                },
            },
        }
    };
    match assignment {
        Assignment::Reject => ended(route, EndReason::Rejected),
        Assignment::Follow {
            handoff,
            paired_at,
            eviction,
        } => {
            if cancellation.is_cancelled() {
                return ended(route, EndReason::Cancelled);
            }
            // The generation was replaced before this task claimed its place.
            // Keep the socket rather than hand it to a leader that is leaving;
            // `finish_task` closes it because the route now belongs to others.
            if eviction.is_cancelled() {
                return ended(route, EndReason::Evicted);
            }
            if Instant::now() >= paired_at + limits.header_timeout.min(limits.absolute_timeout) {
                return ended(route, EndReason::RendezvousTimeout);
            }
            let Some(peer) = held.first.take() else {
                return ended(route, EndReason::IoFailure);
            };
            match handoff.send(peer) {
                Ok(()) => ended(None, EndReason::Transferred),
                Err(peer) => {
                    held.first = Some(peer);
                    ended(route, EndReason::Disconnected)
                }
            }
        }
        Assignment::Lead {
            mut counterpart,
            paired_at,
            eviction,
        } => {
            let other = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    held.second = close_handoff(&mut counterpart);
                    return ended(route, EndReason::Cancelled);
                },
                // Adopt a follower that already handed over, exactly as on
                // cancellation, so its socket closes with this task's exit.
                _ = eviction.cancelled() => {
                    held.second = close_handoff(&mut counterpart);
                    return ended(route, EndReason::Evicted);
                },
                result = timeout_at(paired_at + limits.header_timeout.min(limits.absolute_timeout), &mut counterpart) => result,
            };
            let other = match other {
                Ok(Ok(other)) => other,
                Ok(Err(_)) => return ended(route, EndReason::Disconnected),
                Err(_) => {
                    held.second = close_handoff(&mut counterpart);
                    return ended(route, EndReason::RendezvousTimeout);
                }
            };
            held.second = Some(other);
            let (Some(first), Some(second)) = (&mut held.first, &mut held.second) else {
                return ended(route, EndReason::IoFailure);
            };
            let reason = relay_pair(first, second, paired_at, limits, cancellation, eviction).await;
            ended(route, reason)
        }
    }
}

fn close_assignment(assigned: &mut oneshot::Receiver<Assignment>) -> Option<Peer> {
    // Cancellation/deadline can win while a Lead is queued but unclaimed and
    // its counterpart channel already owns the follower. Close admission first,
    // then adopt that Peer instead of dropping it with the unread assignment.
    assigned.close();
    match assigned.try_recv() {
        Ok(Assignment::Lead {
            mut counterpart, ..
        }) => close_handoff(&mut counterpart),
        // A Follow owns only its handoff sender, not a counterpart socket.
        // Closing it wakes the leader; this task still owns its original Peer.
        Ok(Assignment::Follow { .. } | Assignment::Reject) | Err(_) => None,
    }
}

fn close_handoff(counterpart: &mut oneshot::Receiver<Peer>) -> Option<Peer> {
    counterpart.close();
    counterpart.try_recv().ok()
}

async fn relay_pair(
    first: &mut Peer,
    second: &mut Peer,
    paired_at: Instant,
    limits: RelayLimits,
    cancellation: CancellationToken,
    eviction: CancellationToken,
) -> EndReason {
    let absolute_deadline = paired_at + limits.absolute_timeout;
    let marker_deadline = (paired_at + limits.header_timeout).min(absolute_deadline);
    let markers = async {
        tokio::try_join!(
            first.socket.write_all(READY_MARKER),
            second.socket.write_all(READY_MARKER)
        )
    };
    let ready = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return EndReason::Cancelled,
        _ = eviction.cancelled() => return EndReason::Evicted,
        result = timeout_at(marker_deadline, markers) => result,
    };
    match ready {
        Ok(Ok(_)) => (),
        Ok(Err(_)) => return EndReason::IoFailure,
        Err(_) if Instant::now() >= absolute_deadline => return EndReason::AbsoluteTimeout,
        Err(_) => return EndReason::RendezvousTimeout,
    }
    // Only after BOTH untrusted markers were written do opaque bytes flow.
    let (progress, observed) = watch::channel(Instant::now());
    let first_byte = first.early_byte.take();
    let second_byte = second.early_byte.take();
    let (mut first_read, mut first_write) = first.socket.split();
    let (mut second_read, mut second_write) = second.socket.split();
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => EndReason::Cancelled,
        // A silent pair whose far side died without a FIN ends here as soon
        // as a fresh registration replaces it, not at the inactivity deadline.
        _ = eviction.cancelled() => EndReason::Evicted,
        _ = sleep_until(absolute_deadline) => EndReason::AbsoluteTimeout,
        _ = inactivity(observed, limits.inactivity_timeout) => EndReason::IdleTimeout,
        reason = copy_direction(first_byte, &mut first_read, &mut second_write, &progress) => reason,
        reason = copy_direction(second_byte, &mut second_read, &mut first_write, &progress) => reason,
    }
    // Selecting EOF/error in either direction drops both copy futures. Sockets
    // stay in TaskExit until the coordinator retires their exact route, then
    // closes both and releases both permits before accepting another socket.
}

async fn copy_direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    initial_byte: Option<u8>,
    reader: &mut R,
    writer: &mut W,
    progress: &watch::Sender<Instant>,
) -> EndReason {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut count = if let Some(byte) = initial_byte {
        buffer[0] = byte;
        1
    } else {
        0
    };
    loop {
        if count == 0 {
            count = match reader.read(&mut buffer).await {
                Ok(0) => return EndReason::Disconnected,
                Ok(count) => count,
                Err(_) => return EndReason::IoFailure,
            };
        }
        let mut written = 0;
        while written < count {
            match writer.write(&buffer[written..count]).await {
                Ok(0) | Err(_) => return EndReason::IoFailure,
                Ok(count) => {
                    written += count;
                    // Actual forwarding progress in EITHER direction resets
                    // inactivity. This single-slot watch carries no payload.
                    progress.send_replace(Instant::now());
                }
            }
        }
        count = 0;
    }
}

async fn inactivity(mut progress: watch::Receiver<Instant>, duration: Duration) {
    loop {
        let last = *progress.borrow_and_update();
        tokio::select! {
            biased;
            changed = progress.changed() => if changed.is_err() { return; },
            _ = sleep_until(last + duration) => {
                if Instant::now().duration_since(*progress.borrow()) >= duration { return; }
            }
        }
    }
}

fn ended(route: Option<RouteId>, reason: EndReason) -> (Option<RouteId>, EndReason) {
    (route, reason)
}

impl RouteRegistry {
    fn finish_task(
        &mut self,
        mut exit: TaskExit,
        report: &mut RelayReport,
    ) -> Result<(), RelayError> {
        if let Some(route) = exit.route {
            let now = Instant::now();
            self.evictions.waiting_evictor_ended(route, exit.id, now);
            // Every task of an evicted generation lands in the last arm: the route
            // now holds nothing, or a replacement whose connection identifiers are
            // all different from its own, because identifiers are never reused.
            let malformed = match self.routes.get_mut(&route) {
                Some(RouteState::Active {
                    leader,
                    follower,
                    retired_follower,
                    ..
                }) if *follower == exit.id => {
                    if *leader == *follower
                        || retired_follower.is_some()
                        || exit.retired.first.is_none()
                        || exit.retired.second.is_some()
                    {
                        true
                    } else {
                        // Only the registered follower for this exact active
                        // generation may fill its single retained-socket slot.
                        *retired_follower = exit.retired.first.take();
                        false
                    }
                }
                Some(RouteState::Active {
                    leader,
                    follower,
                    retired_follower,
                    ..
                }) if *leader == exit.id => {
                    *leader == *follower
                        || exit.retired.first.is_none()
                        || (retired_follower.is_some() && exit.retired.second.is_some())
                }
                Some(RouteState::Waiting(waiter)) if waiter.id == exit.id => {
                    exit.retired.first.is_none() || exit.retired.second.is_some()
                }
                _ => false,
            };
            if malformed {
                // Never overwrite a retained Peer or silently release conflicting
                // ownership. Retire the matching generation before drops and make
                // the coordinator stop accepting new sockets and shut down.
                self.routes.remove(&route);
                report.task_failures = report.task_failures.saturating_add(1);
                return Err(RelayError::TaskFailed);
            }
            let owns_waiting = matches!(
                self.routes.get(&route),
                Some(RouteState::Waiting(waiter)) if waiter.id == exit.id
            );
            if owns_waiting {
                self.routes.remove(&route);
            } else {
                self.finish_active_generation(route, exit.id, now);
            }
        }
        let counter = match exit.reason {
            EndReason::InvalidHeader => Some(&mut report.invalid_registrations),
            EndReason::HeaderTimeout => Some(&mut report.header_timeouts),
            EndReason::WaitingTimeout => Some(&mut report.waiting_timeouts),
            EndReason::RendezvousTimeout => Some(&mut report.rendezvous_timeouts),
            EndReason::IdleTimeout => Some(&mut report.idle_timeouts),
            EndReason::AbsoluteTimeout => Some(&mut report.absolute_timeouts),
            EndReason::Disconnected => Some(&mut report.disconnected),
            EndReason::IoFailure => Some(&mut report.io_failures),
            EndReason::Cancelled => Some(&mut report.cancelled),
            // `register` counts one eviction per pair, not one per task.
            EndReason::Evicted | EndReason::Rejected | EndReason::Transferred => None,
        };
        if let Some(counter) = counter {
            *counter = counter.saturating_add(1);
        }
        // This is intentionally after generation-safe route retirement. Clients
        // observing our EOF can reconnect without racing a stale route/socket slot.
        drop(exit.retired);
        Ok(())
    }

    fn finish_active_generation(&mut self, route: RouteId, leader: u64, now: Instant) -> bool {
        let owns_active = matches!(
            self.routes.get(&route),
            Some(RouteState::Active { leader: current, .. }) if *current == leader
        );
        if owns_active {
            self.routes.remove(&route);
            self.evictions.pair_ended(route, leader, now);
        }
        owns_active
    }
}

#[cfg(test)]
fn route_registry(limits: RelayLimits) -> RouteRegistry {
    RouteRegistry::new(
        limits,
        RelayPolicy::default(),
        Arc::new(RelayAbuseCounterStore::default()),
    )
}

#[cfg(test)]
fn synthetic_source() -> SocketAddr {
    "127.0.0.1:7443".parse().expect("fixed loopback source")
}

#[cfg(test)]
mod assignment_ownership_tests {
    use super::*;

    async fn socket_owner(permits: &Arc<Semaphore>, early_byte: Option<u8>) -> (Peer, TcpStream) {
        // Socket ownership only: the regression never waits for or interprets
        // TCP EOF. Both connections are fully established before virtual time.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("synthetic listener");
        let address = listener.local_addr().expect("synthetic local address");
        let (remote, accepted) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(TcpStream::connect(address), listener.accept())
        })
        .await
        .expect("bounded socket-owner setup");
        let remote = remote.expect("synthetic client socket");
        let (socket, _) = accepted.expect("synthetic accepted socket");
        let permit = Arc::clone(permits)
            .try_acquire_owned()
            .expect("reserved fixture slot");
        (
            Peer {
                socket,
                early_byte,
                _permit: permit,
            },
            remote,
        )
    }

    #[derive(Clone, Copy, PartialEq)]
    enum StagedAbort {
        Cancellation,
        Deadline,
        Eviction,
    }

    async fn staged_lead_abort_keeps_both_peers(abort: StagedAbort) {
        let permits = Arc::new(Semaphore::new(2));
        let (leader, mut leader_remote) = socket_owner(&permits, None).await;
        let (follower, _follower_remote) = socket_owner(&permits, Some(b'S')).await;
        let route = RouteId::new([0x35; 32]).expect("synthetic route");
        leader_remote
            .write_all(&Registration::new(Role::Pc, route).to_wire())
            .await
            .expect("complete synthetic registration");
        let limits = RelayLimits::new(2, 1).expect("two fixture socket slots");
        let cancellation = CancellationToken::new();
        let (mailbox, mut registrations) = mpsc::channel(2);
        let work = connection(
            1,
            leader,
            synthetic_source(),
            Instant::now(),
            mailbox,
            limits,
            cancellation.clone(),
        );
        tokio::pin!(work);

        // Poll the actual connection future only far enough to publish its
        // registration. It is not spawned and cannot consume Lead while this
        // test stages the two one-shot messages below.
        let waiting = tokio::select! {
            registration = registrations.recv() => registration.expect("published registration"),
            _ = &mut work => panic!("connection ended before assignment staging"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("registration setup did not finish"),
        };
        let deadline = waiting.deadline;
        let (handoff, counterpart) = oneshot::channel();
        let eviction = CancellationToken::new();
        assert!(
            waiting
                .assignment
                .send(Assignment::Lead {
                    counterpart,
                    paired_at: Instant::now(),
                    eviction: eviction.clone(),
                })
                .is_ok()
        );
        assert!(
            handoff.send(follower).is_ok(),
            "follower must be queued in the unclaimed Lead"
        );
        let mut routes = route_registry(limits);
        routes.routes.insert(
            route,
            RouteState::Active {
                leader: 1,
                follower: 2,
                retired_follower: None,
                eviction,
            },
        );
        let mut report = RelayReport::default();
        assert_eq!(permits.available_permits(), 0);

        // Held to the end so an evicting replacement stays a live waiter.
        let (replacement, _replacement_assigned) = oneshot::channel();
        match abort {
            StagedAbort::Deadline => {
                // Pause only after all socket I/O and staging. The following
                // poll selects an already-expired timer, not a virtual-time
                // TCP result.
                tokio::time::pause();
                // Tokio timers have millisecond granularity. Await the paused
                // deadline plus one whole millisecond, not a one-nanosecond nudge.
                tokio::time::sleep_until(deadline + Duration::from_millis(1)).await;
            }
            StagedAbort::Cancellation => cancellation.cancel(),
            // The real coordinator path: a fresh phone registration arrives
            // while the Lead, and the follower inside it, are still unclaimed.
            StagedAbort::Eviction => routes.register(
                Register {
                    id: 3,
                    registration: Registration::new(Role::Phone, route),
                    source: synthetic_source(),
                    deadline: Instant::now() + limits.waiting_timeout,
                    assignment: replacement,
                },
                &mut report,
            ),
        }
        let exit = work.await;
        if abort == StagedAbort::Deadline {
            tokio::time::resume();
        }
        assert!(matches!(
            (abort, exit.reason),
            (StagedAbort::Deadline, EndReason::WaitingTimeout)
                | (StagedAbort::Cancellation, EndReason::Cancelled)
                | (StagedAbort::Eviction, EndReason::Evicted)
        ));
        if abort == StagedAbort::Eviction {
            assert!(matches!(
                routes.routes.get(&route),
                Some(RouteState::Waiting(waiter)) if waiter.id == 3
            ));
        } else {
            assert!(matches!(
                routes.routes.get(&route),
                Some(RouteState::Active { leader: 1, .. })
            ));
        }
        // The current bug drops the Peer inside the unread Assignment::Lead
        // when the selected cancellation/deadline/eviction branch drops
        // `assigned`.
        assert_eq!(
            permits.available_permits(),
            0,
            "both socket permits must remain held before exact-generation retirement"
        );
        assert!(exit.retired.first.is_some());
        assert_eq!(
            exit.retired
                .second
                .as_ref()
                .and_then(|peer| peer.early_byte),
            Some(b'S')
        );

        routes
            .finish_task(exit, &mut report)
            .expect("valid exact-generation retirement");
        if abort == StagedAbort::Eviction {
            // The evicted leader's exit leaves its replacement waiting.
            assert!(matches!(
                routes.routes.get(&route),
                Some(RouteState::Waiting(waiter)) if waiter.id == 3
            ));
            assert_eq!(report.evicted_pairs, 1);
        } else {
            assert!(!routes.routes.contains_key(&route));
        }
        assert_eq!(report.task_failures, 0);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn cancellation_before_claiming_lead_retains_already_handed_peer_until_retirement() {
        staged_lead_abort_keeps_both_peers(StagedAbort::Cancellation).await;
    }

    #[tokio::test]
    async fn deadline_before_claiming_lead_retains_already_handed_peer_until_retirement() {
        staged_lead_abort_keeps_both_peers(StagedAbort::Deadline).await;
    }

    #[tokio::test]
    async fn eviction_before_claiming_lead_retains_already_handed_peer_until_its_exit() {
        staged_lead_abort_keeps_both_peers(StagedAbort::Eviction).await;
    }

    #[tokio::test]
    async fn expired_follower_handoff_keeps_socket_until_leader_generation_retirement() {
        let permits = Arc::new(Semaphore::new(2));
        // The test parent retains the leader so its generation cannot retire
        // before the explicitly chosen finish_task call below.
        let (leader, _leader_remote) = socket_owner(&permits, None).await;
        let (follower, mut follower_remote) = socket_owner(&permits, Some(b'F')).await;
        let route = RouteId::new([0x36; 32]).expect("synthetic route");
        let limits = RelayLimits::new(2, 1).expect("two fixture slots");
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let (leader_assignment, mut leader_assigned) = oneshot::channel();
        routes.register(
            Register {
                id: 1,
                registration: Registration::new(Role::Pc, route),
                source: synthetic_source(),
                deadline: Instant::now() + limits.waiting_timeout,
                assignment: leader_assignment,
            },
            &mut report,
        );

        follower_remote
            .write_all(&Registration::new(Role::Phone, route).to_wire())
            .await
            .expect("complete follower registration");
        let (mailbox, mut registrations) = mpsc::channel(2);
        let work = connection(
            2,
            follower,
            synthetic_source(),
            Instant::now(),
            mailbox,
            limits,
            CancellationToken::new(),
        );
        tokio::pin!(work);
        let incoming = tokio::select! {
            registration = registrations.recv() => registration.expect("published follower registration"),
            _ = &mut work => panic!("follower ended before assignment staging"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("follower setup did not finish"),
        };
        // Use the actual coordinator registration path to establish ownership;
        // do not hand-construct the Active variant or guess a follower identity.
        routes.register(incoming, &mut report);
        let (mut counterpart, paired_at) = match leader_assigned.try_recv() {
            Ok(Assignment::Lead {
                counterpart,
                paired_at,
                ..
            }) => (counterpart, paired_at),
            _ => panic!("coordinator did not assign the staged leader"),
        };
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active { leader: 1, .. })
        ));
        assert_eq!(permits.available_permits(), 0);

        // All TCP setup is done. Expire only the shorter paired handoff timer,
        // not the follower's waiting timer, before polling its queued Follow.
        // No server-wide cancellation or remote EOF timing is involved.
        tokio::time::pause();
        tokio::time::sleep_until(
            paired_at
                + limits.header_timeout.min(limits.absolute_timeout)
                + Duration::from_millis(1),
        )
        .await;
        let follower_exit = work.await;
        tokio::time::resume();
        assert!(matches!(follower_exit.reason, EndReason::RendezvousTimeout));
        assert!(follower_exit.retired.first.is_some());
        assert!(matches!(
            counterpart.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert_eq!(permits.available_permits(), 0);

        routes
            .finish_task(follower_exit, &mut report)
            .expect("retained follower exit");
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active { leader: 1, .. })
        ));
        assert_eq!(
            permits.available_permits(),
            0,
            "nonleader exit must not drop its socket before the active leader generation retires"
        );

        let leader_exit = TaskExit {
            id: 1,
            route: Some(route),
            reason: EndReason::Disconnected,
            retired: HeldPeers {
                first: Some(leader),
                second: None,
            },
        };
        routes
            .finish_task(leader_exit, &mut report)
            .expect("leader retirement");
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(permits.available_permits(), 2);
    }

    fn active_generation(
        route: RouteId,
        leader: u64,
        follower: u64,
        limits: RelayLimits,
        routes: &mut RouteRegistry,
        report: &mut RelayReport,
    ) -> (oneshot::Receiver<Assignment>, oneshot::Receiver<Assignment>) {
        let (first, first_receiver) = oneshot::channel();
        let (second, second_receiver) = oneshot::channel();
        for (id, role, assignment) in [(leader, Role::Pc, first), (follower, Role::Phone, second)] {
            routes.register(
                Register {
                    id,
                    registration: Registration::new(role, route),
                    source: synthetic_source(),
                    deadline: Instant::now() + limits.waiting_timeout,
                    assignment,
                },
                report,
            );
        }
        (first_receiver, second_receiver)
    }

    fn exited_peer(id: u64, route: RouteId, peer: Peer, reason: EndReason) -> TaskExit {
        TaskExit {
            id,
            route: Some(route),
            reason,
            retired: HeldPeers {
                first: Some(peer),
                second: None,
            },
        }
    }

    #[tokio::test]
    async fn leader_first_retirement_does_not_wait_for_or_misattach_late_follower() {
        let permits = Arc::new(Semaphore::new(2));
        let (leader, _leader_remote) = socket_owner(&permits, None).await;
        let (follower, _follower_remote) = socket_owner(&permits, Some(b'F')).await;
        let route = RouteId::new([0x37; 32]).expect("synthetic route");
        let limits = RelayLimits::new(2, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let _assignments = active_generation(route, 1, 2, limits, &mut routes, &mut report);
        routes
            .finish_task(
                exited_peer(1, route, leader, EndReason::Disconnected),
                &mut report,
            )
            .expect("leader retires its generation first");
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(
            permits.available_permits(),
            1,
            "parent still owns the late follower"
        );
        routes
            .finish_task(
                exited_peer(2, route, follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("late follower belongs to the already-retired generation");
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test]
    async fn stale_follower_cannot_attach_to_or_retire_a_new_active_generation() {
        let permits = Arc::new(Semaphore::new(4));
        let (old_leader, _old_leader_remote) = socket_owner(&permits, None).await;
        let (old_follower, _old_follower_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x38; 32]).expect("synthetic reused route");
        let limits = RelayLimits::new(4, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let old_assignments = active_generation(route, 1, 2, limits, &mut routes, &mut report);
        routes
            .finish_task(
                exited_peer(1, route, old_leader, EndReason::Disconnected),
                &mut report,
            )
            .expect("old leader retirement");
        drop(old_assignments);
        let (new_leader, _new_leader_remote) = socket_owner(&permits, None).await;
        let (new_follower, _new_follower_remote) = socket_owner(&permits, None).await;
        let _new_assignments = active_generation(route, 3, 4, limits, &mut routes, &mut report);
        routes
            .finish_task(
                exited_peer(2, route, old_follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("stale follower cleanup");
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active {
                leader: 3,
                follower: 4,
                retired_follower: None,
                ..
            })
        ));
        assert_eq!(
            permits.available_permits(),
            2,
            "only the new generation's two sockets remain"
        );
        routes
            .finish_task(
                exited_peer(4, route, new_follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("new matching follower is retained");
        assert_eq!(permits.available_permits(), 2);
        routes
            .finish_task(
                exited_peer(3, route, new_leader, EndReason::Disconnected),
                &mut report,
            )
            .expect("new leader retirement");
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(permits.available_permits(), 4);
    }

    #[tokio::test]
    async fn shutdown_route_clear_releases_the_retained_follower_without_detaching_a_socket() {
        let permits = Arc::new(Semaphore::new(2));
        let (leader, _leader_remote) = socket_owner(&permits, None).await;
        let (follower, _follower_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x39; 32]).expect("synthetic route");
        let limits = RelayLimits::new(2, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let _assignments = active_generation(route, 1, 2, limits, &mut routes, &mut report);
        routes
            .finish_task(
                exited_peer(2, route, follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("follower retained before shutdown");
        assert_eq!(permits.available_permits(), 0);
        // This is the coordinator's ownership cleanup step, not an assertion
        // that an unawaited run future or a TCP peer has already terminated.
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        routes.clear();
        assert_eq!(permits.available_permits(), 1);
        routes
            .finish_task(
                exited_peer(1, route, leader, EndReason::Cancelled),
                &mut report,
            )
            .expect("leader cleanup after route clear");
        assert_eq!(permits.available_permits(), 2);
        assert_eq!(report.task_failures, 0);
    }

    #[tokio::test]
    async fn duplicate_matching_follower_ownership_fails_closed_without_overwriting_the_slot() {
        let permits = Arc::new(Semaphore::new(3));
        let (leader, _leader_remote) = socket_owner(&permits, None).await;
        let (follower, _follower_remote) = socket_owner(&permits, None).await;
        let (conflicting_peer, _conflicting_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x3a; 32]).expect("synthetic route");
        let limits = RelayLimits::new(3, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let _assignments = active_generation(route, 1, 2, limits, &mut routes, &mut report);
        routes
            .finish_task(
                exited_peer(2, route, follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("first follower ownership");
        assert_eq!(permits.available_permits(), 0);
        // Impossible with the normal unique task IDs/owned Peer handoff: inject
        // it only into the private seam to require explicit failure, not replacement.
        assert_eq!(
            routes.finish_task(
                exited_peer(2, route, conflicting_peer, EndReason::RendezvousTimeout),
                &mut report
            ),
            Err(RelayError::TaskFailed),
        );
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(report.task_failures, 1);
        assert_eq!(
            permits.available_permits(),
            2,
            "conflicting peers drop only after route retirement"
        );
        routes
            .finish_task(
                exited_peer(1, route, leader, EndReason::Cancelled),
                &mut report,
            )
            .expect("remaining leader cleanup");
        assert_eq!(permits.available_permits(), 3);
    }

    fn fresh_registration(
        id: u64,
        role: Role,
        route: RouteId,
        limits: RelayLimits,
    ) -> (Register, oneshot::Receiver<Assignment>) {
        let (assignment, assigned) = oneshot::channel();
        (
            Register {
                id,
                registration: Registration::new(role, route),
                source: synthetic_source(),
                deadline: Instant::now() + limits.waiting_timeout,
                assignment,
            },
            assigned,
        )
    }

    fn lead_eviction(assigned: &mut oneshot::Receiver<Assignment>) -> CancellationToken {
        match assigned.try_recv() {
            Ok(Assignment::Lead { eviction, .. }) => eviction,
            _ => panic!("coordinator did not assign a leader"),
        }
    }

    #[tokio::test]
    async fn eviction_closes_the_retained_follower_and_leaves_the_replacement_waiting() {
        let permits = Arc::new(Semaphore::new(2));
        let (leader, _leader_remote) = socket_owner(&permits, None).await;
        let (follower, _follower_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x3b; 32]).expect("synthetic route");
        let limits = RelayLimits::new(2, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let (mut leader_assigned, _follower_assigned) =
            active_generation(route, 1, 2, limits, &mut routes, &mut report);
        let eviction = lead_eviction(&mut leader_assigned);
        routes
            .finish_task(
                exited_peer(2, route, follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("follower retained by its generation");
        assert_eq!(permits.available_permits(), 0);

        let (fresh, mut fresh_assigned) = fresh_registration(3, Role::Phone, route, limits);
        routes.register(fresh, &mut report);
        assert!(eviction.is_cancelled());
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 3
        ));
        assert!(
            matches!(
                fresh_assigned.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "the replacement waits; it is not rejected"
        );
        assert_eq!(
            permits.available_permits(),
            1,
            "the retained follower closes with its generation"
        );
        assert_eq!(report.evicted_pairs, 1);
        assert_eq!(report.rejected_duplicates, 0);

        routes
            .finish_task(
                exited_peer(1, route, leader, EndReason::Evicted),
                &mut report,
            )
            .expect("an evicted leader's exit is not malformed");
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 3
        ));
        assert_eq!(permits.available_permits(), 2);
        assert_eq!(report.task_failures, 0);
    }

    #[tokio::test]
    async fn late_exits_of_an_evicted_generation_leave_the_next_generation_intact() {
        let permits = Arc::new(Semaphore::new(4));
        let (old_leader, _old_leader_remote) = socket_owner(&permits, None).await;
        let (old_follower, _old_follower_remote) = socket_owner(&permits, None).await;
        let (new_leader, _new_leader_remote) = socket_owner(&permits, None).await;
        let (new_follower, _new_follower_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x3c; 32]).expect("synthetic route");
        let limits = RelayLimits::new(4, 1).unwrap();
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let (mut old_assigned, _old_follower_assigned) =
            active_generation(route, 1, 2, limits, &mut routes, &mut report);
        let old_eviction = lead_eviction(&mut old_assigned);
        // A fresh PC evicts and waits, and the next phone pairs with it, while
        // both tasks of the old generation are still running.
        let _new_assignments = active_generation(route, 3, 4, limits, &mut routes, &mut report);
        assert!(old_eviction.is_cancelled());
        let next_generation_untouched = |routes: &RouteRegistry| {
            matches!(
                routes.routes.get(&route),
                Some(RouteState::Active {
                    leader: 3,
                    follower: 4,
                    retired_follower: None,
                    ..
                })
            )
        };
        assert!(next_generation_untouched(&routes));
        assert_eq!(report.evicted_pairs, 1);
        assert_eq!(report.paired, 2);
        assert_eq!(report.rejected_duplicates, 0);

        // The old follower never handed over, so each old task returns its
        // own socket, and each arrives after the next generation is active.
        routes
            .finish_task(
                exited_peer(2, route, old_follower, EndReason::Evicted),
                &mut report,
            )
            .expect("late evicted follower");
        assert!(
            next_generation_untouched(&routes),
            "an old follower never fills the next generation's slot"
        );
        routes
            .finish_task(
                exited_peer(1, route, old_leader, EndReason::Evicted),
                &mut report,
            )
            .expect("late evicted leader");
        assert!(
            next_generation_untouched(&routes),
            "an old leader never retires the next generation"
        );
        assert_eq!(
            permits.available_permits(),
            2,
            "only the next generation's sockets remain"
        );
        assert_eq!(report.task_failures, 0);

        // The next generation still retires by its own rules.
        routes
            .finish_task(
                exited_peer(4, route, new_follower, EndReason::RendezvousTimeout),
                &mut report,
            )
            .expect("new follower retained");
        assert_eq!(permits.available_permits(), 2);
        routes
            .finish_task(
                exited_peer(3, route, new_leader, EndReason::Disconnected),
                &mut report,
            )
            .expect("new leader retirement");
        assert!(!routes.routes.contains_key(&route));
        assert_eq!(permits.available_permits(), 4);
        assert_eq!(report.task_failures, 0);
    }

    #[tokio::test]
    async fn follower_of_an_evicted_generation_keeps_its_socket_instead_of_handing_it_over() {
        let permits = Arc::new(Semaphore::new(1));
        let (follower, mut follower_remote) = socket_owner(&permits, None).await;
        let route = RouteId::new([0x3d; 32]).expect("synthetic route");
        let limits = RelayLimits::new(2, 1).expect("two fixture slots");
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let (leader, mut leader_assigned) = fresh_registration(1, Role::Pc, route, limits);
        routes.register(leader, &mut report);
        follower_remote
            .write_all(&Registration::new(Role::Phone, route).to_wire())
            .await
            .expect("complete follower registration");
        let (mailbox, mut registrations) = mpsc::channel(2);
        let work = connection(
            2,
            follower,
            synthetic_source(),
            Instant::now(),
            mailbox,
            limits,
            CancellationToken::new(),
        );
        tokio::pin!(work);
        let incoming = tokio::select! {
            registration = registrations.recv() => registration.expect("published follower registration"),
            _ = &mut work => panic!("follower ended before assignment staging"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("follower setup did not finish"),
        };
        routes.register(incoming, &mut report);
        let mut counterpart = match leader_assigned.try_recv() {
            Ok(Assignment::Lead { counterpart, .. }) => counterpart,
            _ => panic!("coordinator did not assign the staged leader"),
        };

        // Evict while the follower's Follow is queued but unclaimed.
        let (fresh, _fresh_assigned) = fresh_registration(3, Role::Phone, route, limits);
        routes.register(fresh, &mut report);
        let exit = work.await;
        assert!(matches!(exit.reason, EndReason::Evicted));
        assert!(
            exit.retired.first.is_some(),
            "the follower keeps its own socket"
        );
        assert!(
            matches!(
                counterpart.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            ),
            "nothing is handed to a leader that is leaving"
        );
        assert_eq!(permits.available_permits(), 0);

        routes
            .finish_task(exit, &mut report)
            .expect("an evicted follower's exit is not malformed");
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 3
        ));
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(report.task_failures, 0);
    }

    #[tokio::test]
    async fn a_registration_that_cannot_wait_leaves_the_active_pair_alone() {
        let route = RouteId::new([0x3e; 32]).expect("synthetic route");
        let other = RouteId::new([0x3f; 32]).expect("synthetic route");
        let limits = RelayLimits::new(4, 1).expect("one waiting room");
        let mut routes = route_registry(limits);
        let mut report = RelayReport::default();
        let (mut leader_assigned, _follower_assigned) =
            active_generation(route, 1, 2, limits, &mut routes, &mut report);
        let eviction = lead_eviction(&mut leader_assigned);
        let (occupant, _occupant_assigned) = fresh_registration(3, Role::Pc, other, limits);
        routes.register(occupant, &mut report);

        let (fresh, mut fresh_assigned) = fresh_registration(4, Role::Phone, route, limits);
        routes.register(fresh, &mut report);
        assert!(matches!(fresh_assigned.try_recv(), Ok(Assignment::Reject)));
        assert!(!eviction.is_cancelled());
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active {
                leader: 1,
                follower: 2,
                ..
            })
        ));
        assert_eq!(report.rejected_waiting_rooms, 1);
        assert_eq!(report.evicted_pairs, 0);
    }
}

#[cfg(test)]
mod mitigation_tests {
    use super::*;
    use tokio::sync::oneshot;

    fn state(
        limits: RelayLimits,
        policy: RelayPolicy,
    ) -> (RouteRegistry, Arc<RelayAbuseCounterStore>) {
        let abuse = Arc::new(RelayAbuseCounterStore::default());
        (
            RouteRegistry::new(limits, policy, Arc::clone(&abuse)),
            abuse,
        )
    }

    fn admit(
        id: u64,
        role: Role,
        route: RouteId,
        source: SocketAddr,
        routes: &mut RouteRegistry,
        report: &mut RelayReport,
    ) -> oneshot::Receiver<Assignment> {
        let (assignment, assigned) = oneshot::channel();
        let deadline = Instant::now() + routes.limits.waiting_timeout;
        routes.register(
            Register {
                id,
                registration: Registration::new(role, route),
                source,
                deadline,
                assignment,
            },
            report,
        );
        assigned
    }

    fn form_pair(
        route: RouteId,
        leader: u64,
        follower: u64,
        routes: &mut RouteRegistry,
        report: &mut RelayReport,
    ) {
        let first = admit(leader, Role::Pc, route, synthetic_source(), routes, report);
        let second = admit(
            follower,
            Role::Phone,
            route,
            synthetic_source(),
            routes,
            report,
        );
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active { .. })
        ));
        drop((first, second));
    }

    fn close_active(route: RouteId, routes: &mut RouteRegistry) {
        let Some(RouteState::Active { leader, .. }) = routes.routes.get(&route) else {
            panic!("synthetic route was not active");
        };
        let leader = *leader;
        assert!(routes.finish_active_generation(route, leader, Instant::now()));
    }

    #[test]
    fn loopback_source_predicate_handles_native_and_mapped_addresses() {
        for source in [
            "127.0.0.1:1",
            "127.255.255.254:1",
            "[::1]:1",
            "[::ffff:127.0.0.1]:1",
        ] {
            assert!(is_loopback_source(source.parse().unwrap()), "{source}");
        }
        for source in ["192.0.2.1:1", "[::ffff:192.0.2.1]:1", "[2001:db8::1]:1"] {
            assert!(!is_loopback_source(source.parse().unwrap()), "{source}");
        }
        let route = RouteId::new([0x70; 32]).unwrap();
        assert!(pc_source_is_allowed(
            PcRoleSource::LoopbackOnly,
            Registration::new(Role::Phone, route),
            "192.0.2.1:1".parse().unwrap()
        ));
    }

    #[test]
    fn refused_remote_pc_neither_evicts_nor_waits() {
        let limits = RelayLimits::new(8, 4).unwrap();
        let policy = RelayPolicy::new(PcRoleSource::LoopbackOnly);
        let (mut routes, abuse) = state(limits, policy);
        let mut report = RelayReport::default();
        let route = RouteId::new([0x71; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);
        let eviction = match routes.routes.get(&route) {
            Some(RouteState::Active { eviction, .. }) => eviction.clone(),
            _ => panic!("synthetic pair missing"),
        };
        let mut rejected = admit(
            3,
            Role::Pc,
            route,
            "192.0.2.1:4000".parse().unwrap(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        assert!(!eviction.is_cancelled());
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active { .. })
        ));

        let other = RouteId::new([0x72; 32]).unwrap();
        let mut rejected = admit(
            4,
            Role::Pc,
            other,
            "[2001:db8::1]:4000".parse().unwrap(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        assert!(!routes.routes.contains_key(&other));
        assert_eq!(report.rejected_pc_sources, 2);
        assert_eq!(report.evicted_pairs, 0);
        assert_eq!(report.peak_waiting_rooms, 1);
        assert_eq!(abuse.snapshot().rejected_pc_sources, 2);
    }

    #[test]
    fn duplicate_rejection_updates_the_shared_abuse_counter() {
        let limits = RelayLimits::new(4, 2).unwrap();
        let (mut routes, abuse) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x73; 32]).unwrap();
        let _waiting = admit(
            1,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let mut rejected = admit(
            2,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        assert_eq!(report.rejected_duplicates, 1);
        assert_eq!(abuse.snapshot().rejected_duplicates, 1);
    }

    #[test]
    fn any_policy_still_admits_a_remote_pc_source() {
        let limits = RelayLimits::new(2, 1).unwrap();
        let (mut routes, _) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x73; 32]).unwrap();
        let _waiting = admit(
            1,
            Role::Pc,
            route,
            "192.0.2.1:4000".parse().unwrap(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(_))
        ));
        assert_eq!(report.rejected_pc_sources, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_evictions_of_open_short_lived_pairs_double_cooldown_to_the_cap() {
        let limits = RelayLimits::new(16, 4).unwrap();
        let (mut routes, abuse) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x74; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);

        let first_evictor = admit(
            3,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let first_counterpart = admit(
            4,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );

        // Registration #2 charges strike one before admission, but that first
        // strike is free and therefore replaces the still-short-lived pair.
        let second_evictor = admit(
            5,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 5
        ));
        let first_strike = routes.evictions.records.get(&route).unwrap();
        assert_eq!(first_strike.strikes, 1);
        assert_eq!(first_strike.cooldown_until, None);
        let second_counterpart = admit(
            6,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        drop((first_evictor, first_counterpart));

        let cooldowns = [30, 60, 120, 240, 300, 300];
        let mut active_leader = 5_u64;
        let mut active_follower = 6_u64;
        let mut active_assignments = Some((second_evictor, second_counterpart));
        let mut attack_id = 7_u64;
        for (index, seconds) in cooldowns.into_iter().enumerate() {
            // Registration #3 and its later equivalents charge the active pair
            // before admission. Strike two starts at thirty seconds; subsequent
            // consecutive strikes double until the five-minute plateau.
            let mut rejected = admit(
                attack_id,
                Role::Phone,
                route,
                synthetic_source(),
                &mut routes,
                &mut report,
            );
            assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
            assert!(matches!(
                routes.routes.get(&route),
                Some(RouteState::Active {
                    leader,
                    follower,
                    ..
                }) if *leader == active_leader && *follower == active_follower
            ));
            let record = routes.evictions.records.get(&route).unwrap();
            assert_eq!(record.strikes, (index as u8 + 2).min(6));
            assert_eq!(
                record.cooldown_until.unwrap() - Instant::now(),
                Duration::from_secs(seconds)
            );
            assert!(matches!(
                record.stage,
                EvictionStage::ActivePair {
                    leader,
                    strike_if_short: false,
                    ..
                } if leader == active_leader
            ));

            drop(active_assignments.take());
            close_active(route, &mut routes);
            let record = routes.evictions.records.get(&route).unwrap();
            assert_eq!(
                record.strikes,
                (index as u8 + 2).min(6),
                "closing the accounted pair must not add a second strike"
            );

            if index + 1 < cooldowns.len() {
                tokio::time::advance(Duration::from_secs(seconds) + Duration::from_millis(1)).await;
                form_pair(
                    route,
                    attack_id + 1,
                    attack_id + 2,
                    &mut routes,
                    &mut report,
                );
                let evictor = admit(
                    attack_id + 3,
                    Role::Pc,
                    route,
                    synthetic_source(),
                    &mut routes,
                    &mut report,
                );
                let counterpart = admit(
                    attack_id + 4,
                    Role::Phone,
                    route,
                    synthetic_source(),
                    &mut routes,
                    &mut report,
                );
                active_leader = attack_id + 3;
                active_follower = attack_id + 4;
                active_assignments = Some((evictor, counterpart));
                attack_id += 5;
            }
        }

        assert_eq!(report.evicted_pairs, 7);
        assert_eq!(report.rejected_evictions, cooldowns.len() as u64);
        assert_eq!(abuse.snapshot().evicted_pairs, 7);
        assert_eq!(abuse.snapshot().rejected_evictions, cooldowns.len() as u64);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_and_late_pair_completions_cannot_change_or_double_the_strike() {
        let limits = RelayLimits::new(8, 2).unwrap();
        let (mut routes, _) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x75; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);
        let first_evictor = admit(
            3,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let first_counterpart = admit(
            4,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );

        let current = *routes.evictions.records.get(&route).unwrap();
        assert!(!routes.finish_active_generation(route, 1, Instant::now()));
        let after_stale = *routes.evictions.records.get(&route).unwrap();
        assert_eq!(after_stale.stage, current.stage);
        assert_eq!(after_stale.strikes, current.strikes);

        let second_evictor = admit(
            5,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let free_strike = *routes.evictions.records.get(&route).unwrap();
        assert_eq!(free_strike.strikes, 1);
        assert_eq!(free_strike.cooldown_until, None);
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 5
        ));
        let second_counterpart = admit(
            6,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );

        let mut rejected = admit(
            7,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        let charged = *routes.evictions.records.get(&route).unwrap();
        assert_eq!(charged.strikes, 2);
        assert!(matches!(
            charged.stage,
            EvictionStage::ActivePair {
                leader: 5,
                strike_if_short: false,
                ..
            }
        ));

        assert!(!routes.finish_active_generation(route, 3, Instant::now()));
        let after_stale = *routes.evictions.records.get(&route).unwrap();
        assert_eq!(after_stale.stage, charged.stage);
        assert_eq!(after_stale.strikes, charged.strikes);
        drop((
            first_evictor,
            first_counterpart,
            second_evictor,
            second_counterpart,
        ));
        close_active(route, &mut routes);
        assert!(!routes.finish_active_generation(route, 5, Instant::now()));
        let after_late = routes.evictions.records.get(&route).unwrap();
        assert_eq!(after_late.strikes, 2);
        assert_eq!(after_late.cooldown_until, charged.cooldown_until);
        assert_eq!(report.evicted_pairs, 2);
        assert_eq!(report.rejected_evictions, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_lived_genuine_handover_never_strikes_or_rejects() {
        let limits = RelayLimits::new(8, 2).unwrap();
        let (mut routes, _) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x76; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);
        tokio::time::advance(SHORT_LIVED + Duration::from_millis(1)).await;

        let handover = admit(
            3,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let counterpart = admit(
            4,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active {
                leader: 3,
                follower: 4,
                ..
            })
        ));

        tokio::time::advance(SHORT_LIVED + Duration::from_millis(1)).await;
        drop((handover, counterpart));
        close_active(route, &mut routes);
        assert!(!routes.evictions.records.contains_key(&route));
        assert_eq!(report.evicted_pairs, 1);
        assert_eq!(report.rejected_evictions, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_short_lived_evictor_pair_starts_cooldown_then_expiry_allows_eviction() {
        let limits = RelayLimits::new(16, 4).unwrap();
        let (mut routes, abuse) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x74; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);

        let first_evictor = admit(
            3,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let first_counterpart = admit(
            4,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let second_evictor = admit(
            5,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let first_strike = routes.evictions.records.get(&route).unwrap();
        assert_eq!(first_strike.strikes, 1);
        assert_eq!(first_strike.cooldown_until, None);
        let second_counterpart = admit(
            6,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );

        let mut rejected = admit(
            7,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Active {
                leader: 5,
                follower: 6,
                ..
            })
        ));
        let second_strike = routes.evictions.records.get(&route).unwrap();
        assert_eq!(second_strike.strikes, 2);
        assert_eq!(
            second_strike.cooldown_until.unwrap() - Instant::now(),
            EVICTION_COOLDOWN_INITIAL
        );
        assert_eq!(report.rejected_evictions, 1);
        assert_eq!(report.evicted_pairs, 2);

        tokio::time::advance(EVICTION_COOLDOWN_INITIAL + Duration::from_millis(1)).await;
        let _accepted = admit(
            8,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(
            matches!(routes.routes.get(&route), Some(RouteState::Waiting(waiter)) if waiter.id == 8)
        );
        drop((
            first_evictor,
            first_counterpart,
            second_evictor,
            second_counterpart,
        ));
        assert_eq!(report.evicted_pairs, 3);
        assert_eq!(abuse.snapshot().rejected_evictions, 1);
        assert_eq!(abuse.snapshot().evicted_pairs, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_pair_surviving_short_lived_clears_prior_strikes() {
        let limits = RelayLimits::new(16, 4).unwrap();
        let (mut routes, _) = state(limits, RelayPolicy::default());
        let mut report = RelayReport::default();
        let route = RouteId::new([0x75; 32]).unwrap();
        form_pair(route, 1, 2, &mut routes, &mut report);
        let first_evictor = admit(
            3,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let first_counterpart = admit(
            4,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let second_evictor = admit(
            5,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let second_counterpart = admit(
            6,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let mut rejected = admit(
            7,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(rejected.try_recv(), Ok(Assignment::Reject)));
        assert_eq!(routes.evictions.records.get(&route).unwrap().strikes, 2);

        tokio::time::advance(EVICTION_COOLDOWN_INITIAL + Duration::from_millis(1)).await;
        let third_evictor = admit(
            8,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        let cleared = routes.evictions.records.get(&route).unwrap();
        assert_eq!(cleared.strikes, 0);
        assert_eq!(cleared.cooldown_until, None);
        let third_counterpart = admit(
            9,
            Role::Pc,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );

        let _free_again = admit(
            10,
            Role::Phone,
            route,
            synthetic_source(),
            &mut routes,
            &mut report,
        );
        assert!(matches!(
            routes.routes.get(&route),
            Some(RouteState::Waiting(waiter)) if waiter.id == 10
        ));
        let restarted = routes.evictions.records.get(&route).unwrap();
        assert_eq!(restarted.strikes, 1);
        assert_eq!(restarted.cooldown_until, None);
        drop((
            first_evictor,
            first_counterpart,
            second_evictor,
            second_counterpart,
            third_evictor,
            third_counterpart,
        ));
        assert_eq!(report.rejected_evictions, 1);
        assert_eq!(report.evicted_pairs, 4);
    }

    #[test]
    fn first_strike_is_free_then_consecutive_strikes_double_to_the_fixed_cap() {
        let limits = RelayLimits::new(2, 1).unwrap();
        let mut tracker = EvictionTracker::new(limits);
        let route = RouteId::new([0x76; 32]).unwrap();
        let now = Instant::now();
        let cooldowns = [
            None,
            Some(30),
            Some(60),
            Some(120),
            Some(240),
            Some(300),
            Some(300),
        ];
        for (index, expected) in cooldowns.into_iter().enumerate() {
            let id = index as u64 + 1;
            tracker.start_evictor(route, id, now);
            tracker.waiting_evictor_ended(route, id, now);
            let record = tracker.records.get(&route).unwrap();
            assert_eq!(record.strikes, (index as u8 + 1).min(6));
            assert_eq!(
                record.cooldown_until.map(|until| until - now),
                expected.map(Duration::from_secs)
            );
        }
    }

    #[test]
    fn eviction_bookkeeping_drops_oldest_entries_at_its_limit() {
        let limits = RelayLimits::new(64, 1).unwrap();
        let mut tracker = EvictionTracker::new(limits);
        let now = Instant::now();
        for value in 1_u8..=100 {
            tracker.start_evictor(RouteId::new([value; 32]).unwrap(), u64::from(value), now);
        }
        assert_eq!(tracker.records.len(), EVICTION_RECORDS_PER_WAITING_ROOM);
        assert!(
            tracker
                .records
                .contains_key(&RouteId::new([100; 32]).unwrap())
        );
    }
}

#[cfg(test)]
mod resilience_tests {
    use super::*;
    use crate::MAX_ACCEPTED_CONNECTIONS;

    #[test]
    fn a_refused_accept_costs_a_wait_and_not_the_listener() {
        let now = Instant::now();
        assert_eq!(accept_setback(1, now), Ok(now + ACCEPT_BACKOFF));
        assert_eq!(
            accept_setback(MAX_CONSECUTIVE_ACCEPT_FAILURES, now),
            Ok(now + ACCEPT_BACKOFF),
            "the last tolerated refusal still only costs a wait"
        );
    }

    #[test]
    fn a_listener_that_refuses_everything_ends_the_run_within_a_bound() {
        let now = Instant::now();
        assert_eq!(
            accept_setback(MAX_CONSECUTIVE_ACCEPT_FAILURES + 1, now),
            Err(RelayError::AcceptFailed),
        );
        // Refusing every poll costs this much wall clock before the run gives
        // up. Neither an unbounded spin nor an unbounded wait.
        let patience = ACCEPT_BACKOFF * MAX_CONSECUTIVE_ACCEPT_FAILURES;
        assert!(patience >= Duration::from_secs(1), "{patience:?} spins");
        assert!(patience <= Duration::from_secs(10), "{patience:?} hangs");
    }

    #[test]
    fn tolerated_task_panics_cannot_strand_the_whole_socket_pool() {
        // Each tolerated panic strands one route entry, and that entry holds at
        // most one retained follower socket and its slot until shutdown.
        assert!(
            MAX_TASK_FAILURES < MAX_ACCEPTED_CONNECTIONS as u64,
            "a run must give up before the strand exhausts its own capacity"
        );
    }
}
