// SPDX-License-Identifier: GPL-2.0-or-later
//! One Application-lifetime I/O scheduler. Parked records own their actual
//! sockets; only the existing MobileController business owner can apply them.
use crate::{
    BridgeError, MobileController, NativePlatform,
    intake_delivery::{
        DeliveryCommand, DeliveryControl, DeliveryResult, NativeDecisionProgress, QueuedWrite,
    },
    native_clock::{ProjectionAnchor, native_callback},
};
use android_controller::{
    AssociatedPcSocket, NativePeerLease, PcSocketEvent, PcSocketInputs, PeerAssociationRef,
};
use framed_transport::{ConnectionBudget, SocketLimits};
use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

const MAX_PEERS: usize = 32;
const OBSERVE_INTERVAL: Duration = Duration::from_millis(25);

/// Rust composition bookkeeping only, never exported through UniFFI/Tauri.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IntakePeerId(u64);
impl fmt::Debug for IntakePeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IntakePeerId([redacted])")
    }
}
struct PeerControl {
    reference: PeerAssociationRef,
    active: AtomicBool,
    connected: AtomicBool,
    correlated: AtomicBool,
    stop: CancellationToken,
    sender: mpsc::Sender<PeerCommand>,
    last_correlation: AtomicU64,
    next_probe: AtomicU64,
    probe_deadline: AtomicU64,
    probe_enqueued: AtomicBool,
    probe_pending: AtomicBool,
    probe_retry_blocked: AtomicBool,
}
enum PeerCommand {
    Decision(DeliveryCommand),
    Probe,
}
struct RuntimeState {
    sender: mpsc::Sender<AttachInput>,
    thread: JoinHandle<()>,
    finished: Arc<AtomicBool>,
}
#[derive(Default)]
struct Inner {
    runtime: Option<RuntimeState>,
    peers: Vec<Arc<PeerControl>>,
    pending: Vec<DeliveryCommand>,
    next_id: u64,
}
pub(crate) struct IntakeOwner {
    inner: Mutex<Inner>,
    notify: Arc<Notify>,
    stop: CancellationToken,
    deadline: AtomicU64,
    maintenance: AtomicBool,
    failed: AtomicBool,
    waiting_admission: AtomicBool,
    native_progress_pending: AtomicBool,
    temporal_refresh: AtomicBool,
}
impl Default for IntakeOwner {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            notify: Arc::new(Notify::new()),
            stop: CancellationToken::new(),
            deadline: AtomicU64::new(0),
            maintenance: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            waiting_admission: AtomicBool::new(false),
            native_progress_pending: AtomicBool::new(false),
            temporal_refresh: AtomicBool::new(false),
        }
    }
}
impl IntakeOwner {
    #[cfg(test)]
    pub(crate) fn accepted_correlation_for_tests(
        &self,
        reference: PeerAssociationRef,
    ) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        inner.peers.iter().find_map(|peer| {
            (peer.reference == reference
                && peer.active.load(Ordering::Acquire)
                && !peer.stop.is_cancelled()
                && peer.correlated.load(Ordering::Acquire)
                && !peer.probe_pending.load(Ordering::Acquire))
            .then(|| peer.last_correlation.load(Ordering::Acquire))
        })
    }
    #[cfg(test)]
    pub(crate) fn join_completed_for_tests(&self) {
        let runtime = self.inner.lock().unwrap().runtime.take();
        if let Some(runtime) = runtime {
            assert!(
                runtime.finished.load(Ordering::Acquire),
                "public cleanup must drain actual I/O first"
            );
            // Synthetic test callbacks are nonblocking. This is fixture teardown,
            // not the native command worker's production nonblocking join path.
            runtime.thread.join().unwrap();
        }
    }
    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }
    pub(crate) fn admission_released(&self) {
        if self.waiting_admission.swap(false, Ordering::AcqRel) {
            self.wake();
        }
    }
    pub(crate) fn request_maintenance(&self) {
        self.maintenance.store(true, Ordering::Release);
        self.wake();
    }
    pub(crate) fn set_deadline(&self, value: Option<u64>) {
        self.deadline.store(value.unwrap_or(0), Ordering::Release);
    }
    pub(crate) fn counts(&self) -> (u8, u8) {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        (
            inner
                .peers
                .iter()
                .filter(|peer| peer.active.load(Ordering::Acquire))
                .count() as u8,
            inner
                .peers
                .iter()
                .filter(|peer| {
                    peer.active.load(Ordering::Acquire) && peer.connected.load(Ordering::Acquire)
                })
                .count() as u8,
        )
    }
    pub(crate) fn awaiting_temporal_refresh(&self) -> bool {
        self.temporal_refresh.load(Ordering::Acquire)
    }
    pub(crate) fn await_temporal_refresh(&self) {
        self.temporal_refresh.store(true, Ordering::Release);
        self.maintenance.store(true, Ordering::Release);
        self.native_progress_pending.store(true, Ordering::Release);
        self.wake();
    }
    pub(crate) fn stop(&self) {
        self.stop.cancel();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        for peer in &inner.peers {
            peer.stop.cancel();
        }
        for pending in inner.pending.drain(..) {
            pending.control().stop();
        }
        self.wake();
    }
    pub(crate) fn cleanup_complete(&self) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let done = inner
            .runtime
            .as_ref()
            .is_none_or(|runtime| runtime.finished.load(Ordering::Acquire));
        if done {
            // The flag means all I/O/provider resources are already drained.
            // Join only after actual thread completion: never wait on its final
            // nonblocking native progress notification from the command worker.
            if inner
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.thread.is_finished())
                && let Some(runtime) = inner.runtime.take()
                && runtime.thread.join().is_err()
            {
                self.failed.store(true, Ordering::Release);
            }
            inner
                .peers
                .retain(|peer| peer.active.load(Ordering::Acquire));
        }
        done && inner.peers.is_empty()
    }
    pub(crate) fn enqueue_delivery(&self, command: DeliveryCommand) -> Result<(), BridgeError> {
        if self.stop.is_cancelled() {
            command.control().stop();
            return Err(BridgeError::Closed);
        }
        let mut inner = self.inner.lock().map_err(|_| BridgeError::Closed)?;
        inner.pending.retain(|pending| {
            if pending.is_cancelled() {
                pending.control().stop();
                false
            } else {
                true
            }
        });
        if let Some(existing) = inner
            .pending
            .iter()
            .find(|pending| pending.key() == command.key())
        {
            return if existing.same_identity(&command) {
                Ok(())
            } else {
                Err(BridgeError::Busy)
            };
        }
        if inner.pending.len() >= 32 {
            return Err(BridgeError::Busy);
        }
        inner
            .pending
            .try_reserve(1)
            .map_err(|_| BridgeError::NativeUnavailable)?;
        command
            .control()
            .set(NativeDecisionProgress::WaitingForPeer);
        inner.pending.push(command);
        drop(inner);
        self.flush_waiting();
        self.wake();
        Ok(())
    }
    fn flush_waiting(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        inner.pending.retain(|pending| {
            if pending.is_cancelled() {
                pending.control().stop();
                false
            } else {
                true
            }
        });
        for command in &inner.pending {
            let control = command.control();
            if control.retry_blocked.load(Ordering::Acquire) {
                continue;
            }
            let Some(peer) = inner.peers.iter().find(|peer| {
                peer.reference == command.reference()
                    && peer.active.load(Ordering::Acquire)
                    && peer.correlated.load(Ordering::Acquire)
            }) else {
                continue;
            };
            if control
                .queued_command
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if peer
                .sender
                .try_send(PeerCommand::Decision(command.clone_handle()))
                .is_err()
            {
                control.queued_command.store(false, Ordering::Release);
            }
        }
    }
    fn remove_delivery(&self, control: &Arc<DeliveryControl>) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pending
            .retain(|pending| !Arc::ptr_eq(&pending.control(), control));
    }
    fn unblock_peer(&self, reference: PeerAssociationRef) {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        for peer in &inner.peers {
            if peer.reference == reference {
                peer.probe_retry_blocked.store(false, Ordering::Release);
            }
        }
        for command in &inner.pending {
            if command.reference() == reference {
                command
                    .control()
                    .retry_blocked
                    .store(false, Ordering::Release);
            }
        }
    }
    fn schedule_probes(&self, now: u64) {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        for peer in &inner.peers {
            if !peer.active.load(Ordering::Acquire) {
                continue;
            }
            if peer.probe_pending.load(Ordering::Acquire) {
                if now >= peer.probe_deadline.load(Ordering::Acquire) {
                    peer.stop.cancel();
                }
                continue;
            }
            let due = peer.next_probe.load(Ordering::Acquire);
            if due == 0 || now < due || peer.probe_retry_blocked.load(Ordering::Acquire) {
                continue;
            }
            if peer
                .probe_enqueued
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if peer.sender.try_send(PeerCommand::Probe).is_err() {
                peer.probe_enqueued.store(false, Ordering::Release);
            }
        }
    }
    fn peer_closed(&self, peer: &PeerControl) {
        peer.active.store(false, Ordering::Release);
        peer.connected.store(false, Ordering::Release);
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        for pending in &inner.pending {
            if pending.reference() == peer.reference {
                pending
                    .control()
                    .queued_command
                    .store(false, Ordering::Release);
                pending
                    .control()
                    .retry_blocked
                    .store(false, Ordering::Release);
            }
        }
        drop(inner);
        self.native_progress_pending.store(true, Ordering::Release);
        self.wake();
    }
}

struct PeerCompletion {
    control: Arc<PeerControl>,
    intake: Arc<IntakeOwner>,
}
impl Drop for PeerCompletion {
    fn drop(&mut self) {
        self.intake.peer_closed(&self.control);
    }
}
// Field order closes the actual socket before native leases/transport identity
// and finally the accepted-peer bookkeeping reservation.
struct AttachInput {
    socket: std::net::TcpStream,
    lease: NativePeerLease,
    commands: mpsc::Receiver<PeerCommand>,
    completion: PeerCompletion,
}
struct PreparedAttach {
    socket: tokio::net::TcpStream,
    identity: secure_channel::TlsIdentity,
    commands: mpsc::Receiver<PeerCommand>,
    completion: PeerCompletion,
    clock: Arc<crate::native_clock::NativeSocketClock>,
}
struct PeerOwned {
    socket: AssociatedPcSocket,
    commands: mpsc::Receiver<PeerCommand>,
    write: Option<QueuedWrite>,
    completion: PeerCompletion,
}
enum PeerWork {
    Event(Result<PcSocketEvent, android_controller::PeerSocketError>),
    Decision(DeliveryCommand),
    Probe,
    Stop,
}
struct ParkedPeer {
    owned: PeerOwned,
    work: PeerWork,
}
enum Parked {
    Attach(Box<PreparedAttach>),
    Peer(Box<ParkedPeer>),
}

impl MobileController {
    /// Actual trusted native Rust composition ONLY. Does not dial, enroll or
    /// expose a fd/address/pin. Accepted scheduling is not an authenticated peer.
    pub fn attach_provisioned_stream(
        self: &Arc<Self>,
        association: PeerAssociationRef,
        stream: std::net::TcpStream,
    ) -> Result<IntakePeerId, BridgeError> {
        struct Carrier {
            socket: Option<std::net::TcpStream>,
            lease: Option<NativePeerLease>,
        }
        let mut carrier = Carrier {
            socket: Some(stream),
            lease: None,
        };
        let _admission = self.enter()?;
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        if self.intake.awaiting_temporal_refresh() {
            return Err(BridgeError::PresentationRefreshRequired);
        }
        self.start_intake_reactor()?;
        carrier.lease = Some(self.with_inbox(|owner| {
            owner
                .lease_peer_association(association)
                .map_err(|_| BridgeError::LocalKeysUnavailable)
        })?);
        let (tx, rx) = mpsc::channel(1);
        let mut inner = self.intake.inner.lock().map_err(|_| BridgeError::Closed)?;
        inner
            .peers
            .retain(|peer| peer.active.load(Ordering::Acquire));
        if inner.peers.len() >= MAX_PEERS
            || inner.peers.iter().any(|peer| peer.reference == association)
        {
            return Err(BridgeError::Busy);
        }
        let sender = inner
            .runtime
            .as_ref()
            .ok_or(BridgeError::Closed)?
            .sender
            .clone();
        inner.next_id = inner
            .next_id
            .checked_add(1)
            .ok_or(BridgeError::NativeUnavailable)?;
        let id = IntakePeerId(inner.next_id);
        let control = Arc::new(PeerControl {
            reference: association,
            active: AtomicBool::new(true),
            connected: AtomicBool::new(false),
            correlated: AtomicBool::new(false),
            stop: self.intake.stop.child_token(),
            sender: tx,
            last_correlation: AtomicU64::new(0),
            next_probe: AtomicU64::new(0),
            probe_deadline: AtomicU64::new(0),
            probe_enqueued: AtomicBool::new(false),
            probe_pending: AtomicBool::new(false),
            probe_retry_blocked: AtomicBool::new(false),
        });
        inner.peers.push(Arc::clone(&control));
        drop(inner);
        let input = AttachInput {
            socket: carrier.socket.take().ok_or(BridgeError::Closed)?,
            lease: carrier.lease.take().ok_or(BridgeError::Closed)?,
            commands: rx,
            completion: PeerCompletion {
                control,
                intake: Arc::clone(&self.intake),
            },
        };
        let result = sender.try_send(input);
        result.map_err(|_| BridgeError::Busy)?;
        Ok(id)
    }
    pub(crate) fn start_intake_reactor(self: &Arc<Self>) -> Result<(), BridgeError> {
        if self.intake.stop.is_cancelled() {
            return Err(BridgeError::Closed);
        }
        if self
            .intake
            .inner
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .runtime
            .is_some()
        {
            return Ok(());
        }
        let anchor = ProjectionAnchor::capture(&*self.platform, self.boot)?;
        let (sender, receiver) = mpsc::channel(MAX_PEERS);
        let weak = Arc::downgrade(self);
        let intake = Arc::clone(&self.intake);
        let platform = Arc::clone(&self.platform);
        let finished = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&finished);
        let owner_lease = Arc::clone(&self._owner_lease);
        let thread = std::thread::Builder::new()
            .name("uac-native-io".into())
            .spawn(move || {
                struct Finish(Arc<AtomicBool>);
                impl Drop for Finish {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                let _finished = Finish(done);
                let _owner_lease = owner_lease;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ())?;
                    runtime.block_on(reactor(
                        weak.clone(),
                        Arc::clone(&intake),
                        Arc::clone(&platform),
                        anchor,
                        receiver,
                    ));
                    drop(runtime);
                    Ok::<(), ()>(())
                }));
                if !matches!(result, Ok(Ok(()))) || intake.failed.load(Ordering::Acquire) {
                    fail_reactor(&weak, &intake);
                }
                _finished.0.store(true, Ordering::Release);
                // All owned I/O resources dropped before the completion wake. A
                // failing native notification cannot unwind this outer guard or
                // leave the remaining controller logically live.
                if !matches!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| native_callback(
                        || platform.intake_progress()
                    ))),
                    Ok(Ok(()))
                ) {
                    fail_reactor(&weak, &intake);
                }
            })
            .map_err(|_| BridgeError::NativeUnavailable)?;
        self.intake
            .inner
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .runtime = Some(RuntimeState {
            sender,
            thread,
            finished,
        });
        Ok(())
    }
    pub(crate) fn signal_intake_maintenance(&self) {
        self.intake.request_maintenance();
    }
}
fn fail_reactor(controller: &Weak<MobileController>, intake: &IntakeOwner) {
    intake.failed.store(true, Ordering::Release);
    intake.stop();
    if let Some(owner) = controller.upgrade() {
        owner.stop_intake();
        owner.cleanup_pending.store(true, Ordering::Release);
    }
}

async fn wait_peer(mut owned: PeerOwned) -> ParkedPeer {
    let stop = owned.completion.control.stop.clone();
    let work = tokio::select! {
        biased;
        _ = stop.cancelled() => PeerWork::Stop,
        command = owned.commands.recv() => match command { Some(PeerCommand::Decision(value)) => PeerWork::Decision(value), Some(PeerCommand::Probe) => PeerWork::Probe, None => PeerWork::Stop },
        event = owned.socket.next_event() => PeerWork::Event(event),
    };
    ParkedPeer { owned, work }
}
fn prepare_attach(
    input: AttachInput,
    anchor: ProjectionAnchor,
    platform: Arc<dyn NativePlatform>,
) -> Result<PreparedAttach, BridgeError> {
    input
        .socket
        .set_nonblocking(true)
        .map_err(|_| BridgeError::NativeUnavailable)?;
    let socket = tokio::net::TcpStream::from_std(input.socket)
        .map_err(|_| BridgeError::NativeUnavailable)?;
    let clock = anchor.clock(Arc::clone(&platform));
    let (socket, identity) =
        crate::transport::native_identity_with_socket(socket, input.lease, platform)?;
    Ok(PreparedAttach {
        socket,
        identity,
        commands: input.commands,
        completion: input.completion,
        clock,
    })
}
async fn reactor(
    controller: Weak<MobileController>,
    intake: Arc<IntakeOwner>,
    platform: Arc<dyn NativePlatform>,
    anchor: ProjectionAnchor,
    mut attach: mpsc::Receiver<AttachInput>,
) {
    let budget = Arc::new(ConnectionBudget::new(MAX_PEERS).expect("fixed nonzero peer capacity"));
    let mut jobs = JoinSet::new();
    let mut parked = VecDeque::new();
    let mut blocked = false;
    let mut last_local = None;
    let mut observation = tokio::time::interval(OBSERVE_INTERVAL);
    observation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if intake.stop.is_cancelled() {
            break;
        }
        if intake.native_progress_pending.swap(false, Ordering::AcqRel) {
            let _ = native_callback(|| platform.intake_progress());
        }
        if !blocked
            && (!parked.is_empty()
                || (intake.maintenance.load(Ordering::Acquire)
                    && !intake.awaiting_temporal_refresh()))
            && let Some(owner) = controller.upgrade()
        {
            match owner.enter() {
                Ok(admission) => {
                    if intake.failed.load(Ordering::Acquire)
                        || !owner.approval_alive.load(Ordering::Acquire)
                    {
                        owner.drop_owner();
                        drop(admission);
                        break;
                    }
                    if !intake.awaiting_temporal_refresh()
                        && intake.maintenance.swap(false, Ordering::AcqRel)
                    {
                        match owner.maintain_requests_admitted() {
                            Ok(()) => (),
                            Err(BridgeError::PresentationRefreshRequired) => {
                                intake.temporal_refresh.store(true, Ordering::Release);
                                intake.maintenance.store(true, Ordering::Release);
                            }
                            Err(_) => {
                                intake.failed.store(true, Ordering::Release);
                                owner.drop_owner();
                            }
                        }
                        intake
                            .native_progress_pending
                            .store(true, Ordering::Release);
                    } else if let Some(work) = parked.pop_front() {
                        match process_parked(&owner, work, Arc::clone(&budget)) {
                            Ok(Some(peer)) => {
                                jobs.spawn(wait_peer(peer));
                            }
                            Ok(None) => (),
                            Err(BridgeError::PresentationRefreshRequired) => {
                                intake.await_temporal_refresh();
                                if owner.pause_native_presentations().is_err() {
                                    intake.failed.store(true, Ordering::Release);
                                    owner.drop_owner();
                                }
                            }
                            Err(_) => {
                                intake.failed.store(true, Ordering::Release);
                                owner.drop_owner();
                            }
                        }
                    }
                    drop(admission);
                    intake.flush_waiting();
                    // Native worker wake follows actual admission release;
                    // otherwise a fast worker can see Busy and lose this wake.
                    if intake.native_progress_pending.swap(false, Ordering::AcqRel)
                        && native_callback(|| platform.intake_progress()).is_err()
                    {
                        intake.failed.store(true, Ordering::Release);
                        intake.stop.cancel();
                    }
                }
                Err(BridgeError::Busy) => {
                    blocked = true;
                    intake.waiting_admission.store(true, Ordering::Release);
                    // Close the lost-wakeup window when the previous owner
                    // released immediately before the waiter flag was recorded.
                    if !owner.active.load(Ordering::Acquire) {
                        intake.admission_released();
                    }
                }
                Err(_) => break,
            }
        }
        tokio::select! {
            biased;
            _ = intake.stop.cancelled() => break,
            _ = observation.tick() => {
                observe_parked(&mut parked, &intake, &*platform, &mut last_local);
            }
            _ = intake.notify.notified() => { blocked = false; }
            input = attach.recv() => {
                if let Some(input) = input {
                    match prepare_attach(input, anchor, Arc::clone(&platform)) {
                        Ok(value) => parked.push_back(Parked::Attach(Box::new(value))),
                        Err(_) => { let _ = native_callback(|| platform.intake_progress()); }
                    }
                } else { break; }
            }
            completed = jobs.join_next(), if !jobs.is_empty() => {
                match completed {
                    Some(Ok(peer)) => parked.push_back(Parked::Peer(Box::new(peer))),
                    Some(Err(_)) => { intake.failed.store(true, Ordering::Release); intake.stop.cancel(); }
                    None => (),
                }
            }
        }
        if parked.len() > MAX_PEERS {
            intake.failed.store(true, Ordering::Release);
            break;
        }
    }
    intake.stop.cancel();
    attach.close();
    while attach.try_recv().is_ok() {}
    parked.clear();
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    if intake.failed.load(Ordering::Acquire)
        && let Some(owner) = controller.upgrade()
    {
        owner.approval_alive.store(false, Ordering::Release);
        owner.cleanup_pending.store(true, Ordering::Release);
    }
}
fn preserve_drained(peer: &mut ParkedPeer) {
    if matches!(
        &peer.work,
        PeerWork::Event(Ok(PcSocketEvent::OutboundDrained))
    ) && let Some(write) = peer.owned.write.take()
    {
        write.complete();
    }
}
fn observe_parked(
    parked: &mut VecDeque<Parked>,
    intake: &IntakeOwner,
    platform: &dyn NativePlatform,
    last_local: &mut Option<(notification_policy::LocalTime, u64)>,
) {
    let mut index = 0;
    while index < parked.len() {
        let alive = match &mut parked[index] {
            Parked::Peer(peer) => {
                preserve_drained(peer);
                peer.owned.socket.observe_liveness().is_ok()
            }
            Parked::Attach(peer) => !peer.completion.control.stop.is_cancelled(),
        };
        if alive {
            index += 1;
        } else {
            parked.remove(index);
        }
    }
    match native_callback(|| platform.presentation_clock()).and_then(crate::native_clock::validate)
    {
        Ok(now) => {
            if intake.temporal_refresh.swap(false, Ordering::AcqRel) {
                intake.maintenance.store(true, Ordering::Release);
            }
            intake.schedule_probes(now.clock.phone_monotonic_nanos());
            let local = (now.clock.reading().local, now.time_epoch);
            let deadline = intake.deadline.load(Ordering::Acquire);
            if (deadline != 0 && now.clock.phone_monotonic_nanos() >= deadline)
                || last_local.is_some_and(|old| old != local)
            {
                intake.maintenance.store(true, Ordering::Release);
            }
            *last_local = Some(local);
        }
        Err(BridgeError::PresentationRefreshRequired) => {
            if !intake.temporal_refresh.swap(true, Ordering::AcqRel) {
                intake
                    .native_progress_pending
                    .store(true, Ordering::Release);
            }
            intake.maintenance.store(true, Ordering::Release);
        }
        Err(_) => {
            intake.failed.store(true, Ordering::Release);
            intake.stop.cancel();
        }
    }
}

fn process_parked(
    owner: &MobileController,
    work: Parked,
    budget: Arc<ConnectionBudget>,
) -> Result<Option<PeerOwned>, BridgeError> {
    match work {
        Parked::Attach(value) => {
            let PreparedAttach {
                socket,
                identity,
                commands,
                completion,
                clock,
            } = *value;
            let reference = completion.control.reference;
            let stop = completion.control.stop.clone();
            let socket = owner.with_inbox(|inbox| {
                AssociatedPcSocket::new(
                    inbox,
                    reference,
                    PcSocketInputs {
                        socket,
                        identity,
                        budget,
                        clock,
                        limits: SocketLimits::default(),
                        stop,
                    },
                )
                .map_err(|_| BridgeError::NativeUnavailable)
            })?;
            Ok(Some(PeerOwned {
                socket,
                commands,
                write: None,
                completion,
            }))
        }
        Parked::Peer(value) => {
            let mut value = *value;
            preserve_drained(&mut value);
            let ParkedPeer { mut owned, work } = value;
            if owned.completion.control.stop.is_cancelled() {
                return Ok(None);
            }
            // A queued verified event is not permission to apply after the
            // original socket deadline. Observe BEFORE any intent/positive work.
            if owned.socket.observe_liveness().is_err() {
                return Ok(None);
            }
            match work {
                PeerWork::Stop
                | PeerWork::Event(Err(_))
                | PeerWork::Event(Ok(PcSocketEvent::PeerClosed | PcSocketEvent::LocallyClosed)) => {
                    return Ok(None);
                }
                PeerWork::Event(Ok(PcSocketEvent::Ready)) => {
                    owner
                        .intake
                        .unblock_peer(owned.completion.control.reference);
                    owned
                        .completion
                        .control
                        .connected
                        .store(true, Ordering::Release);
                    queue_probe(owner, &mut owned)?;
                    owner
                        .intake
                        .native_progress_pending
                        .store(true, Ordering::Release);
                }
                PeerWork::Event(Ok(PcSocketEvent::Message(message))) => {
                    owner
                        .intake
                        .unblock_peer(owned.completion.control.reference);
                    let now = owner.read_clock()?;
                    let update = owner
                        .with_inbox(|inbox| Ok(owned.socket.apply_event(inbox, *message, now)))?;
                    let update = match update {
                        Ok(update) => update,
                        Err(android_controller::PeerSocketError::ReceivingSource(_)) => {
                            return Ok(Some(owned));
                        }
                        Err(android_controller::PeerSocketError::Persistence(_)) => {
                            return Err(BridgeError::StorageUnavailable);
                        }
                        Err(_) => return Ok(None),
                    };
                    if let Some(received) = owned.socket.correlation_received_nanos() {
                        let control = &owned.completion.control;
                        if !control.correlated.load(Ordering::Acquire)
                            || control.last_correlation.load(Ordering::Acquire) != received
                        {
                            control.last_correlation.store(received, Ordering::Release);
                            control.next_probe.store(
                                received
                                    .checked_add(240_000_000_000)
                                    .ok_or(BridgeError::InvalidObservation)?,
                                Ordering::Release,
                            );
                            control.probe_pending.store(false, Ordering::Release);
                            control.probe_enqueued.store(false, Ordering::Release);
                            control.correlated.store(true, Ordering::Release);
                        }
                    }
                    owner.dispatch_effects(
                        update.committed().update().effects().to_vec(),
                        update.committed().update().fault().is_some(),
                    )?;
                    if owner
                        .with_inbox(|inbox| {
                            update
                                .check_current(inbox)
                                .map_err(|_| BridgeError::NativeUnavailable)
                        })
                        .is_err()
                    {
                        return Ok(None);
                    }
                    owner
                        .intake
                        .native_progress_pending
                        .store(true, Ordering::Release);
                }
                PeerWork::Event(Ok(PcSocketEvent::OutboundDrained)) => {
                    owner
                        .intake
                        .unblock_peer(owned.completion.control.reference);
                    if let Some(write) = owned.write.take() {
                        write.complete();
                    }
                    owner
                        .intake
                        .native_progress_pending
                        .store(true, Ordering::Release);
                }
                PeerWork::Decision(command) => {
                    let control = command.control();
                    match owner.process_delivery(&mut owned.socket, command)? {
                        DeliveryResult::Queued(write) => {
                            if owned.write.is_some() {
                                owned.socket.abort();
                                return Err(BridgeError::OwnerFaulted);
                            }
                            owned.write = Some(write);
                            owner.intake.remove_delivery(&control);
                        }
                        DeliveryResult::Rejected => owner.intake.remove_delivery(&control),
                        DeliveryResult::Retry(_command, reason) => {
                            if reason == android_controller::SendRetry::ClockRequired {
                                queue_probe(owner, &mut owned)?;
                            }
                        }
                    }
                }
                PeerWork::Probe => {
                    queue_probe(owner, &mut owned)?;
                }
            }
            if owned.socket.observe_liveness().is_err() {
                return Ok(None);
            }
            Ok(Some(owned))
        }
    }
}
fn queue_probe(owner: &MobileController, peer: &mut PeerOwned) -> Result<(), BridgeError> {
    let now = owner.read_clock()?;
    let result = owner.with_inbox(|inbox| Ok(peer.socket.queue_clock_probe(inbox, now)))?;
    let control = &peer.completion.control;
    control.probe_enqueued.store(false, Ordering::Release);
    match result {
        Ok(()) => {
            control.probe_deadline.store(
                now.phone_monotonic_nanos()
                    .checked_add(service_protocol::MAX_CLOCK_PROBE_RTT_NANOS)
                    .ok_or(BridgeError::InvalidObservation)?,
                Ordering::Release,
            );
            control.probe_pending.store(true, Ordering::Release);
        }
        Err(android_controller::PeerSocketError::ProbePending) => (),
        Err(android_controller::PeerSocketError::Socket(
            framed_transport::SocketError::Transport(framed_transport::TransportError::Busy),
        )) => {
            control.probe_retry_blocked.store(true, Ordering::Release);
        }
        Err(_) => return Err(BridgeError::NativeUnavailable),
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn process_parked_message_for_test(
    owner: &MobileController,
    socket: AssociatedPcSocket,
    message: android_controller::ReceivedPcEvent,
    reference: PeerAssociationRef,
) -> Result<(), BridgeError> {
    // Test scheduling wrapper only: socket/message are produced by the real
    // public TLS/verification path, not fabricated provenance or a new ingress API.
    let (sender, commands) = mpsc::channel(1);
    let control = Arc::new(PeerControl {
        reference,
        active: AtomicBool::new(true),
        connected: AtomicBool::new(true),
        correlated: AtomicBool::new(true),
        stop: owner.intake.stop.child_token(),
        sender,
        last_correlation: AtomicU64::new(0),
        next_probe: AtomicU64::new(0),
        probe_deadline: AtomicU64::new(0),
        probe_enqueued: AtomicBool::new(false),
        probe_pending: AtomicBool::new(false),
        probe_retry_blocked: AtomicBool::new(false),
    });
    let owned = PeerOwned {
        socket,
        commands,
        write: None,
        completion: PeerCompletion {
            control,
            intake: Arc::clone(&owner.intake),
        },
    };
    let _ = process_parked(
        owner,
        Parked::Peer(Box::new(ParkedPeer {
            owned,
            work: PeerWork::Event(Ok(PcSocketEvent::Message(Box::new(message)))),
        })),
        Arc::new(ConnectionBudget::new(1).unwrap()),
    )?;
    Ok(())
}
