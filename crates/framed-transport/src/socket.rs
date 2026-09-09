// SPDX-License-Identifier: GPL-2.0-or-later
//! Concrete Tokio TCP composition. No detached task, application queue, key
//! creation, peer enrollment, protocol decision or native action lives here.

use std::{
    fmt,
    future::Future,
    io::ErrorKind,
    sync::Arc,
    time::{Duration, Instant},
};

use secure_channel::{MAX_DRAIN_BYTES, MAX_INGRESS_BYTES};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::{
    FRAME_TIMEOUT, PeerTransport, PendingCounts, ReceivedFrame, TransportError, TransportStatus,
};

pub const MAX_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_SOCKET_LIFETIME: Duration = Duration::from_secs(3_600);
const CLOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Trusted native suspend-inclusive monotonic projection, shared with the
/// supplied PeerTransport. Never use renderer/relay timestamps or silently fall
/// back to std::Instant on Android. Read failure/regression is terminal.
pub trait SocketClock: Send + Sync {
    fn now(&self) -> Result<Instant, SocketClockUnavailable>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("trusted native socket clock is unavailable")]
pub struct SocketClockUnavailable;

/// Downward-only restriction on an already-authorized outbound frame. This is
/// not peer enrollment, approval authority, or evidence of remote acceptance.
/// Implementations must use bounded, nonblocking state observations (normally
/// atomics): no IO, driver mutation, reentry, signing or application/store locks.
/// Once revoked, an implementation must never become unrevoked.
pub trait OutboundFrameGuard: Send + Sync {
    fn is_revoked(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketLimits {
    idle_timeout: Duration,
    lifetime: Duration,
    io_chunk_bytes: usize,
}

impl Default for SocketLimits {
    fn default() -> Self {
        Self {
            idle_timeout: MAX_SOCKET_IDLE_TIMEOUT,
            lifetime: MAX_SOCKET_LIFETIME,
            io_chunk_bytes: MAX_INGRESS_BYTES.min(MAX_DRAIN_BYTES),
        }
    }
}

impl SocketLimits {
    pub fn new(idle_timeout: Duration, lifetime: Duration) -> Result<Self, SocketLimitsError> {
        if idle_timeout.is_zero()
            || idle_timeout > MAX_SOCKET_IDLE_TIMEOUT
            || lifetime.is_zero()
            || lifetime > MAX_SOCKET_LIFETIME
        {
            return Err(SocketLimitsError);
        }
        Ok(Self {
            idle_timeout,
            lifetime,
            ..Self::default()
        })
    }

    /// Bound work per actual socket operation, without changing buffer/deadline
    /// limits. A smaller quantum is useful on constrained native consumers.
    pub fn with_io_chunk_bytes(mut self, bytes: usize) -> Result<Self, SocketLimitsError> {
        if bytes == 0 || bytes > MAX_INGRESS_BYTES.min(MAX_DRAIN_BYTES) {
            return Err(SocketLimitsError);
        }
        self.io_chunk_bytes = bytes;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("socket limits must be positive and within the fixed maximum bounds")]
pub struct SocketLimitsError;

/// Transport events only. No variant means enrollment, remote receipt,
/// per-use phone authentication, successful approval or a Windows result.
#[derive(Debug)]
pub enum SocketEvent {
    /// Local peer-pinned TLS/readiness state, reported once.
    Ready,
    Frame(ReceivedFrame),
    /// One queued frame's ciphertext was handed to the local TCP socket.
    /// This is not remote receipt or acceptance.
    OutboundDrained,
    /// Authenticated TLS close_notify and a complete framing boundary.
    PeerClosed,
    /// Our close_notify was handed to TCP; no peer acknowledgment is asserted.
    LocallyClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketPending {
    pub transport: PendingCounts,
    pub socket_read_bytes: usize,
    pub socket_write_bytes: usize,
    pub outbound_frame: bool,
}

/// Own one already connected socket and its fresh, budget-reserved transport.
///
/// A rendezvous caller passes `RendezvousCarrier::into_stream()` here, then keeps
/// polling `next_event`. There is no connecting, listener, TOFU or private key
/// constructor. No mutating PeerTransport method may run before adoption; its
/// original handshake deadline is retained, not restarted here. Read-only status
/// inspection is allowed. The transport and clock must use the same native time domain.
/// Accepted sockets outside this object still need a host admission bound.
///
/// No background timer/task is spawned: deadlines/cancellation are enforced
/// while driven and before each later operation/event. Dropping a pending
/// next_event future retains partial I/O in this owner; dropping this owner
/// closes the socket and releases the existing ConnectionBudget reservation.
pub struct SocketDriver {
    socket: Option<TcpStream>,
    transport: Box<PeerTransport>,
    clock: Arc<dyn SocketClock>,
    stop: CancellationToken,
    limits: SocketLimits,
    last_clock: Instant,
    last_activity: Instant,
    absolute_deadline: Instant,
    input: Box<[u8]>,
    input_start: usize,
    input_end: usize,
    input_deadline: Option<Instant>,
    output: Box<[u8]>,
    output_start: usize,
    output_end: usize,
    output_deadline: Option<Instant>,
    frame_deadline: Option<Instant>,
    frame_guard: Option<Arc<dyn OutboundFrameGuard>>,
    close_deadline: Option<Instant>,
    ready_reported: bool,
    eof: bool,
    closing: bool,
    terminal: bool,
    failure: Option<SocketError>,
}

impl fmt::Debug for SocketDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocketDriver")
            .field("pending", &self.pending_counts())
            .field("closing", &self.closing)
            .field("terminal", &self.terminal)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

enum Step {
    Event(SocketEvent),
    Progress,
    Pending,
}

// Fields drop in declaration order, including any constructor early-return.
// Do not leave these as independent function parameters whose drop order could
// release the transport reservation before closing its actual socket.
struct SocketParts {
    socket: TcpStream,
    transport: Box<PeerTransport>,
}

impl SocketDriver {
    pub fn new(
        socket: TcpStream,
        transport: PeerTransport,
        clock: Arc<dyn SocketClock>,
        limits: SocketLimits,
        stop: CancellationToken,
    ) -> Result<Self, SocketError> {
        let mut owned = SocketParts {
            socket,
            transport: Box::new(transport),
        };
        if stop.is_cancelled() {
            return Err(SocketError::Cancelled);
        }
        let now = clock.now().map_err(|_| SocketError::ClockUnavailable)?;
        let absolute_deadline = now
            .checked_add(limits.lifetime)
            .ok_or(SocketError::ClockRange)?;
        now.checked_add(limits.idle_timeout)
            .ok_or(SocketError::ClockRange)?;
        if !owned.transport.can_adopt_socket() {
            return Err(SocketError::InvalidTransportState);
        }
        owned.transport.tick(now).map_err(SocketError::Transport)?;
        if !matches!(
            owned.transport.status(),
            TransportStatus::Handshaking
                | TransportStatus::AwaitingReadiness
                | TransportStatus::Ready
        ) {
            return Err(SocketError::Closed);
        }
        owned
            .socket
            .set_nodelay(true)
            .map_err(|_| SocketError::Io)?;
        let mut driver = Self {
            socket: Some(owned.socket),
            transport: owned.transport,
            clock,
            stop,
            limits,
            last_clock: now,
            last_activity: now,
            absolute_deadline,
            // vec! allocates directly on the heap, unlike Box::new([0; N])
            // which may first construct large arrays on a debug-build stack.
            input: vec![0; MAX_INGRESS_BYTES].into_boxed_slice(),
            input_start: 0,
            input_end: 0,
            input_deadline: None,
            output: vec![0; MAX_DRAIN_BYTES].into_boxed_slice(),
            output_start: 0,
            output_end: 0,
            output_deadline: None,
            frame_deadline: None,
            frame_guard: None,
            close_deadline: None,
            ready_reported: false,
            eof: false,
            closing: false,
            terminal: false,
            failure: None,
        };
        // A synchronous platform signer may have run inside the preceding tick.
        // Fresh time/cancellation is required before exposing the constructed owner.
        driver.observe()?;
        Ok(driver)
    }

    pub fn pending_counts(&self) -> SocketPending {
        SocketPending {
            transport: self.transport.pending_counts(),
            socket_read_bytes: self.input_end - self.input_start,
            socket_write_bytes: self.output_end - self.output_start,
            outbound_frame: self.frame_deadline.is_some(),
        }
    }

    pub fn failure_reason(&self) -> Option<SocketError> {
        self.failure
    }

    /// Queue one already-framed message only after Ready. Busy/NotReady drop the
    /// supplied Vec without replacing the pending frame. The original ten-second
    /// deadline extends through actual partial socket writes, never restarts.
    pub fn queue_frame(&mut self, frame: Vec<u8>) -> Result<(), SocketError> {
        self.queue_frame_with_guard(frame, None)
    }

    /// Restrict one already-authorized, already-framed message until its actual
    /// OutboundDrained event. The supplied deadline uses the SAME trusted native
    /// Instant domain as this driver and can only shorten the usual ten seconds.
    /// A rejected new restriction is not admitted; Busy/NotReady never replace
    /// the existing frame or its guard. Revocation/expiry AFTER admission closes
    /// the connection and discards retained output, including encrypted bytes.
    ///
    /// The owner must continuously drive next_event; the existing at-most-25-ms
    /// idle polling observes revocation without a task or an application lock.
    /// Checks surround TLS work and each partial write, but cannot recall bytes
    /// already handed to TCP or interrupt synchronous native signing. Neither
    /// this guard nor OutboundDrained proves remote receipt or acceptance.
    pub fn queue_guarded_frame(
        &mut self,
        frame: Vec<u8>,
        absolute_deadline: Instant,
        guard: Arc<dyn OutboundFrameGuard>,
    ) -> Result<(), SocketError> {
        self.queue_frame_with_guard(frame, Some((absolute_deadline, guard)))
    }

    fn queue_frame_with_guard(
        &mut self,
        frame: Vec<u8>,
        restriction: Option<(Instant, Arc<dyn OutboundFrameGuard>)>,
    ) -> Result<(), SocketError> {
        let now = self.observe()?;
        if self.closing {
            return Err(SocketError::Closing);
        }
        if self.frame_deadline.is_some() {
            return Err(SocketError::Transport(TransportError::Busy));
        }
        let mut deadline = now
            .checked_add(FRAME_TIMEOUT)
            .ok_or_else(|| self.fail(SocketError::ClockRange))?;
        let guard = if let Some((restricted_deadline, guard)) = restriction {
            if guard.is_revoked() {
                return Err(SocketError::OutboundRevoked);
            }
            if now >= restricted_deadline {
                return Err(SocketError::SendDeadline);
            }
            deadline = deadline.min(restricted_deadline);
            Some(guard)
        } else {
            None
        };
        match self.transport.queue_frame(frame, now) {
            Ok(()) => {
                self.frame_deadline = Some(deadline);
                self.frame_guard = guard;
            }
            Err(error @ (TransportError::Busy | TransportError::NotReady)) => {
                return Err(SocketError::Transport(error));
            }
            Err(error) => return Err(self.fail(SocketError::Transport(error))),
        }
        self.observe()?;
        Ok(())
    }

    /// Start local graceful termination only after application output/unread
    /// framing has drained. Continue next_event until LocallyClosed or error.
    /// Revocation/protocol failure must use immediate abort instead.
    pub fn begin_close(&mut self) -> Result<(), SocketError> {
        let now = self.observe()?;
        if self.closing {
            return Err(SocketError::Closing);
        }
        if self.frame_deadline.is_some()
            || self.input_start != self.input_end
            || self.output_start != self.output_end
        {
            return Err(SocketError::Transport(TransportError::Busy));
        }
        match self.transport.start_socket_close(now) {
            Ok(()) => (),
            Err(error @ (TransportError::Busy | TransportError::NotReady)) => {
                return Err(SocketError::Transport(error));
            }
            Err(error) => return Err(self.fail(SocketError::Transport(error))),
        }
        self.closing = true;
        self.close_deadline = Some(
            now.checked_add(FRAME_TIMEOUT)
                .ok_or_else(|| self.fail(SocketError::ClockRange))?,
        );
        self.observe()?;
        Ok(())
    }

    /// Irreversible resource withdrawal, not a graceful peer-close claim.
    pub fn abort(&mut self) {
        self.fail(SocketError::Aborted);
    }

    /// The native owner calls this after a received protocol/signature rejection.
    /// It always closes the actual socket and never returns a success outcome.
    pub fn reject_protocol_message(&mut self) -> Result<(), SocketError> {
        let now = self.observe()?;
        let _ = self.transport.reject_protocol_message(now);
        Err(self.fail(SocketError::Transport(TransportError::ProtocolRejected)))
    }

    /// Cancellation-safe partial-I/O ownership; the future spawns no work.
    /// The containing native actor must continuously drive it while connected.
    pub fn next_event(
        &mut self,
    ) -> impl Future<Output = Result<SocketEvent, SocketError>> + Send + '_ {
        self.drive()
    }

    async fn drive(&mut self) -> Result<SocketEvent, SocketError> {
        loop {
            match self.step()? {
                Step::Event(event) => return Ok(event),
                Step::Progress => tokio::task::yield_now().await,
                Step::Pending => self.wait_for_io().await?,
            }
        }
    }

    fn step(&mut self) -> Result<Step, SocketError> {
        let now = self.observe()?;
        let mut progress = false;
        if !self.closing {
            let result = self.transport.tick(now);
            self.transport_result(result)?;
            self.observe()?;
            if !self.ready_reported && self.transport.status() == TransportStatus::Ready {
                self.ready_reported = true;
                return Ok(Step::Event(SocketEvent::Ready));
            }
        }

        // Exactly one bounded nonblocking write per turn. No write_all future
        // can hide cancellation, partial progress or the original send deadline.
        if self.output_start < self.output_end {
            self.observe()?;
            let end = (self.output_start + self.limits.io_chunk_bytes).min(self.output_end);
            let result = self
                .socket
                .as_ref()
                .ok_or(SocketError::Closed)?
                .try_write(&self.output[self.output_start..end]);
            let after_write = self.observe()?;
            match result {
                Ok(0) => return Err(self.fail(SocketError::WriteZero)),
                Ok(count) => {
                    self.output_start += count;
                    self.last_activity = after_write;
                    progress = true;
                    if self.output_start == self.output_end {
                        self.output_start = 0;
                        self.output_end = 0;
                        self.output_deadline = None;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => (),
                Err(_) => return Err(self.fail(SocketError::Io)),
            }
        }

        let pending = self.transport.pending_counts();
        if self.output_start == self.output_end && pending.outbound_tls_bytes == 0 {
            if self.closing {
                self.observe()?;
                self.finish_socket();
                return Ok(Step::Event(SocketEvent::LocallyClosed));
            }
            if self.frame_deadline.is_some() && !pending.outbound_frame {
                self.observe()?;
                self.frame_deadline = None;
                self.frame_guard = None;
                return Ok(Step::Event(SocketEvent::OutboundDrained));
            }
        }

        if !self.closing {
            let before = self.transport.pending_counts();
            let now = self.observe()?;
            let result = self.transport.poll_frame(now);
            let frame = self.transport_result(result)?;
            self.observe()?;
            if let Some(frame) = frame {
                return Ok(Step::Event(SocketEvent::Frame(frame)));
            }
            progress |= before != self.transport.pending_counts();
            if self.transport.status() == TransportStatus::PeerClosed {
                self.finish_socket();
                return Ok(Step::Event(SocketEvent::PeerClosed));
            }

            if self.input_start < self.input_end {
                let now = self.observe()?;
                let result = self
                    .transport
                    .feed_tls(&self.input[self.input_start..self.input_end], now);
                let consumed = self.transport_result(result)?;
                self.input_start += consumed;
                // Required after synchronous TLS/native signing. This does not
                // claim to interrupt the signer while it is executing.
                self.observe()?;
                progress |= consumed > 0;
                if self.input_start == self.input_end {
                    self.input_start = 0;
                    self.input_end = 0;
                    self.input_deadline = None;
                }
            }
        }

        if self.output_start == self.output_end {
            let now = self.observe()?;
            let result = if self.closing {
                self.transport.drain_socket_close(&mut self.output, now)
            } else {
                self.transport.drain_tls(&mut self.output, now)
            };
            let count = self.transport_result(result)?;
            self.output_end = count;
            if count > 0 {
                self.output_deadline = Some(
                    now.checked_add(FRAME_TIMEOUT)
                        .ok_or_else(|| self.fail(SocketError::ClockRange))?,
                );
                progress = true;
            }
            self.observe()?;
        }

        if self.can_read() {
            self.observe()?;
            let result = self
                .socket
                .as_ref()
                .ok_or(SocketError::Closed)?
                .try_read(&mut self.input[..self.limits.io_chunk_bytes]);
            match result {
                Ok(0) => {
                    self.eof = true;
                    let now = self.observe()?;
                    let result = self.transport.transport_eof(now);
                    self.transport_result(result)?;
                    self.observe()?;
                    progress = true;
                }
                Ok(count) => {
                    self.input_end = count;
                    let now = self.observe()?;
                    self.last_activity = now;
                    self.input_deadline = Some(
                        now.checked_add(FRAME_TIMEOUT)
                            .ok_or_else(|| self.fail(SocketError::ClockRange))?,
                    );
                    progress = true;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => (),
                Err(_) => return Err(self.fail(SocketError::Io)),
            }
        }
        Ok(if progress {
            Step::Progress
        } else {
            Step::Pending
        })
    }

    fn can_read(&self) -> bool {
        let pending = self.transport.pending_counts();
        !self.closing
            && !self.eof
            && self.input_start == self.input_end
            && pending.decrypted_suffix_bytes == 0
            && pending.incoming_tls_plaintext_bytes == 0
    }

    async fn wait_for_io(&mut self) -> Result<(), SocketError> {
        let now = self.observe()?;
        let mut delay = CLOCK_POLL_INTERVAL;
        let idle = self
            .last_activity
            .checked_add(self.limits.idle_timeout)
            .ok_or_else(|| self.fail(SocketError::ClockRange))?;
        for deadline in [
            Some(self.absolute_deadline),
            Some(idle),
            self.frame_deadline,
            self.input_deadline,
            self.output_deadline,
            self.close_deadline,
        ]
        .into_iter()
        .flatten()
        {
            delay = delay.min(deadline.saturating_duration_since(now));
        }
        let can_read = self.can_read();
        let can_write = self.output_start < self.output_end;
        let socket = self.socket.as_ref().ok_or(SocketError::Closed)?;
        let result = tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(SocketError::Cancelled),
            _ = tokio::time::sleep(delay) => Ok(()),
            result = socket.readable(), if can_read => result.map_err(|_| SocketError::Io),
            result = socket.writable(), if can_write => result.map_err(|_| SocketError::Io),
        };
        if let Err(error) = result {
            return Err(self.fail(error));
        }
        self.observe()?;
        Ok(())
    }

    fn observe(&mut self) -> Result<Instant, SocketError> {
        if self.failure.is_some() {
            return Err(SocketError::Failed);
        }
        if self.terminal {
            return Err(SocketError::Closed);
        }
        if self.stop.is_cancelled() {
            return Err(self.fail(SocketError::Cancelled));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| self.fail(SocketError::ClockUnavailable))?;
        if now < self.last_clock {
            return Err(self.fail(SocketError::ClockRegressed));
        }
        self.last_clock = now;
        if self
            .frame_guard
            .as_ref()
            .is_some_and(|guard| guard.is_revoked())
        {
            return Err(self.fail(SocketError::OutboundRevoked));
        }
        if now >= self.absolute_deadline {
            return Err(self.fail(SocketError::AbsoluteDeadline));
        }
        let idle = self
            .last_activity
            .checked_add(self.limits.idle_timeout)
            .ok_or_else(|| self.fail(SocketError::ClockRange))?;
        if now >= idle {
            return Err(self.fail(SocketError::IdleDeadline));
        }
        if self.frame_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(self.fail(SocketError::SendDeadline));
        }
        if self.input_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(self.fail(SocketError::InputDeadline));
        }
        if self.output_deadline.is_some_and(|deadline| now >= deadline)
            || self.close_deadline.is_some_and(|deadline| now >= deadline)
        {
            return Err(self.fail(SocketError::WriteDeadline));
        }
        Ok(now)
    }

    fn transport_result<T>(&mut self, result: Result<T, TransportError>) -> Result<T, SocketError> {
        result.map_err(|error| self.fail(SocketError::Transport(error)))
    }

    fn finish_socket(&mut self) {
        self.socket = None;
        self.transport.discard_socket_state();
        self.input.fill(0);
        self.output.fill(0);
        self.input_start = 0;
        self.input_end = 0;
        self.output_start = 0;
        self.output_end = 0;
        self.input_deadline = None;
        self.output_deadline = None;
        self.frame_deadline = None;
        self.frame_guard = None;
        self.close_deadline = None;
        self.terminal = true;
    }

    fn fail(&mut self, error: SocketError) -> SocketError {
        self.finish_socket();
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SocketError {
    #[error(transparent)]
    Transport(TransportError),
    #[error("socket driver requires a fresh unused handshaking transport")]
    InvalidTransportState,
    #[error("socket I/O could not complete")]
    Io,
    #[error("socket accepted no bytes from a nonempty write")]
    WriteZero,
    #[error("socket operation was cancelled")]
    Cancelled,
    #[error("socket connection was locally aborted")]
    Aborted,
    #[error("trusted native socket clock is unavailable")]
    ClockUnavailable,
    #[error("trusted native socket clock regressed")]
    ClockRegressed,
    #[error("trusted native socket deadline is out of range")]
    ClockRange,
    #[error("socket inactivity deadline expired")]
    IdleDeadline,
    #[error("socket absolute lifetime expired")]
    AbsoluteDeadline,
    #[error("original frame socket-send deadline expired")]
    SendDeadline,
    #[error("outbound frame was revoked before socket completion")]
    OutboundRevoked,
    #[error("retained socket input deadline expired")]
    InputDeadline,
    #[error("pending socket write or close deadline expired")]
    WriteDeadline,
    #[error("socket is locally closing")]
    Closing,
    #[error("socket is closed")]
    Closed,
    #[error("socket owner has irreversibly failed")]
    Failed,
}
