// SPDX-License-Identifier: GPL-2.0-or-later
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use secure_channel::{
    Channel, ChannelError, ChannelStatus, EofDisposition, MAX_INGRESS_BYTES,
    MAX_PLAINTEXT_WRITE_BYTES, PlaintextRead, TlsIdentity, TlsPublicKey,
};
use service_protocol::{FrameDecoder, FrameError, MAX_PC_EVENT_BYTES};
use thiserror::Error;

use crate::{
    ConnectionBudget, ConnectionBudgetError, FRAME_TIMEOUT, MAX_DECRYPTED_SUFFIX_BYTES,
    MAX_QUEUED_FRAME_BYTES, MAX_RECEIVED_FRAMES_PER_WINDOW, RECEIVE_WINDOW, budget::Reservation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportStatus {
    Handshaking,
    AwaitingReadiness,
    Ready,
    /// TLS close_notify arrived, but authenticated bytes still need framing.
    PeerClosing,
    /// All authenticated bytes were framed and FrameDecoder::finish succeeded.
    PeerClosed,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PendingCounts {
    pub outbound_frame: bool,
    pub outbound_plaintext_bytes: usize,
    pub outbound_tls_bytes: usize,
    pub incoming_frame_bytes: usize,
    pub decrypted_suffix_bytes: usize,
    pub incoming_tls_plaintext_bytes: usize,
}

/// Complete framing only; not a decoded/verified protocol message or authority.
/// Consume/process or drop before polling again; no Clone/borrowed bypass API.
pub struct ReceivedFrame(Vec<u8>);

impl ReceivedFrame {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for ReceivedFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivedFrame([redacted])")
    }
}

struct OutboundFrame {
    bytes: Vec<u8>,
    accepted: usize,
    deadline: Instant,
}

/// One TLS channel, one owned outgoing frame, one partial decoder and one
/// 16-KiB decrypted suffix. There is no completed-frame queue or inner extraction.
pub struct PeerTransport {
    channel: Option<Channel>,
    _reservation: Reservation,
    socket_adoption_available: bool,
    decoder: FrameDecoder,
    // Fixed-size heap storage keeps async/native owners and return values small;
    // allocate only after the shared connection reservation has succeeded.
    suffix: Box<[u8]>,
    suffix_start: usize,
    suffix_end: usize,
    suffix_received_at: Option<Instant>,
    first_unread_at: Option<Instant>,
    last_feed_at: Option<Instant>,
    incoming_started: Option<Instant>,
    incoming_consumed: usize,
    outbound: Option<OutboundFrame>,
    receive_finished: bool,
    local_closed: bool,
    failure: Option<TransportError>,
    rate_window_start: Instant,
    received_in_window: usize,
}

impl fmt::Debug for PeerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerTransport")
            .field("status", &self.status())
            .field("pending", &self.pending_counts())
            .finish_non_exhaustive()
    }
}

impl PeerTransport {
    pub fn client(
        budget: Arc<ConnectionBudget>,
        identity: TlsIdentity,
        enrolled_pc: TlsPublicKey,
        now: Instant,
    ) -> Result<Self, TransportError> {
        let reservation = budget.reserve()?;
        let channel = Channel::client(identity, enrolled_pc, now)?;
        Ok(Self::new(channel, reservation, now))
    }

    pub fn server(
        budget: Arc<ConnectionBudget>,
        identity: TlsIdentity,
        enrolled_phone: TlsPublicKey,
        now: Instant,
    ) -> Result<Self, TransportError> {
        let reservation = budget.reserve()?;
        let channel = Channel::server(identity, enrolled_phone, now)?;
        Ok(Self::new(channel, reservation, now))
    }

    fn new(channel: Channel, reservation: Reservation, now: Instant) -> Self {
        Self {
            channel: Some(channel),
            _reservation: reservation,
            socket_adoption_available: true,
            decoder: FrameDecoder::new(),
            suffix: vec![0; MAX_DECRYPTED_SUFFIX_BYTES].into_boxed_slice(),
            suffix_start: 0,
            suffix_end: 0,
            suffix_received_at: None,
            first_unread_at: None,
            last_feed_at: None,
            incoming_started: None,
            incoming_consumed: 0,
            outbound: None,
            receive_finished: false,
            local_closed: false,
            failure: None,
            rate_window_start: now,
            received_in_window: 0,
        }
    }

    pub fn status(&self) -> TransportStatus {
        if self.failure.is_some() {
            return TransportStatus::Failed;
        }
        if self.local_closed {
            return TransportStatus::Closed;
        }
        if self.receive_finished {
            return TransportStatus::PeerClosed;
        }
        match self.channel.as_ref().map(Channel::status) {
            Some(ChannelStatus::Handshaking) => TransportStatus::Handshaking,
            Some(ChannelStatus::AwaitingReadiness) => TransportStatus::AwaitingReadiness,
            Some(ChannelStatus::Ready) => TransportStatus::Ready,
            Some(ChannelStatus::PeerClosed) => TransportStatus::PeerClosing,
            Some(ChannelStatus::Failed) => TransportStatus::Failed,
            Some(ChannelStatus::Closed) | None => TransportStatus::Closed,
        }
    }

    pub fn pending_counts(&self) -> PendingCounts {
        PendingCounts {
            outbound_frame: self.outbound.is_some(),
            outbound_plaintext_bytes: self
                .outbound
                .as_ref()
                .map_or(0, |frame| frame.bytes.len() - frame.accepted),
            outbound_tls_bytes: self.channel.as_ref().map_or(0, Channel::buffered_tls_bytes),
            incoming_frame_bytes: self.incoming_consumed,
            decrypted_suffix_bytes: self.suffix_end - self.suffix_start,
            incoming_tls_plaintext_bytes: self
                .channel
                .as_ref()
                .map_or(0, Channel::buffered_plaintext_bytes),
        }
    }

    pub fn failure_reason(&self) -> Option<TransportError> {
        self.failure
    }

    /// Consume a TLS chunk prefix. Empty input is not EOF. A zero result leaves
    /// all bytes with the caller; retain/retry the suffix after backpressure.
    pub fn feed_tls(&mut self, chunk: &[u8], now: Instant) -> Result<usize, TransportError> {
        self.begin(now)?;
        if chunk.len() > MAX_INGRESS_BYTES {
            return Err(self.fail(TransportError::Channel(ChannelError::IngressTooLarge)));
        }
        // Do not mix ciphertext admissions from different times into an unread
        // plaintext batch. Poll before retrying this unconsumed input; no second
        // plaintext/timestamp queue is introduced to recover frame start times.
        if self.suffix_start < self.suffix_end
            || self
                .channel
                .as_ref()
                .is_some_and(|channel| channel.buffered_plaintext_bytes() > 0)
        {
            return Ok(0);
        }
        self.flush_one(now)?;
        let result = self.channel_mut()?.feed_tls(chunk, now);
        let consumed = self.channel_result(result)?;
        if consumed > 0 {
            self.last_feed_at = Some(now);
        }
        self.note_pending_input(now);
        self.finish_if_drained()?;
        // No post-feed Channel call reuses this pre-signing timestamp. The next
        // external operation provides fresh time before readiness/app release.
        Ok(consumed)
    }

    /// Drain at most the Channel's bounded ciphertext chunk. Bytes copied here
    /// are not confirmed socket delivery; native writer deadlines remain required.
    pub fn drain_tls(&mut self, output: &mut [u8], now: Instant) -> Result<usize, TransportError> {
        self.begin(now)?;
        self.flush_one(now)?;
        let result = self.channel_mut()?.drain_tls(output, now);
        let count = self.channel_result(result)?;
        self.clear_sent();
        self.note_pending_input(now);
        Ok(count)
    }

    /// Accept exactly one already length-prefixed owned frame. Busy/NotReady
    /// consume and drop the rejected Vec; do not generate another frame while
    /// outbound_frame is true. No retry queue or optimistic delivery result.
    pub fn queue_frame(&mut self, frame: Vec<u8>, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        if self.status() != TransportStatus::Ready {
            return Err(TransportError::NotReady);
        }
        if self.outbound.is_some() {
            return Err(TransportError::Busy);
        }
        if !valid_outbound(&frame, frame.capacity()) {
            return Err(self.fail(TransportError::InvalidOutboundFrame));
        }
        let deadline = now
            .checked_add(FRAME_TIMEOUT)
            .ok_or_else(|| self.fail(TransportError::ClockRange))?;
        self.outbound = Some(OutboundFrame {
            bytes: frame,
            accepted: 0,
            deadline,
        });
        self.flush_one(now)
    }

    /// Return at most one frame and process at most one decrypted chunk. A
    /// returned frame still needs expected-PC/signature/protocol verification.
    pub fn poll_frame(&mut self, now: Instant) -> Result<Option<ReceivedFrame>, TransportError> {
        self.begin(now)?;
        self.flush_one(now)?;
        if self.receive_finished {
            return Ok(None);
        }
        if !matches!(
            self.status(),
            TransportStatus::Ready | TransportStatus::PeerClosing
        ) {
            return Ok(None);
        }
        if self.suffix_start == self.suffix_end {
            let result = self
                .channel
                .as_mut()
                .ok_or(TransportError::Closed)?
                .read_plaintext(&mut self.suffix, now);
            match self.channel_result(result)? {
                PlaintextRead::Data(count) => {
                    self.suffix_start = 0;
                    self.suffix_end = count;
                    self.suffix_received_at =
                        Some(self.first_unread_at.or(self.last_feed_at).unwrap_or(now));
                    if self
                        .channel
                        .as_ref()
                        .is_none_or(|channel| channel.buffered_plaintext_bytes() == 0)
                    {
                        self.first_unread_at = None;
                    }
                }
                PlaintextRead::WouldBlock => return Ok(None),
                PlaintextRead::PeerClosed => {
                    self.finish_if_drained()?;
                    return Ok(None);
                }
            }
        }
        if self.incoming_started.is_none() {
            self.incoming_started = self.suffix_received_at;
        }
        self.check_deadlines(now)?;
        let result = self
            .decoder
            .feed(&self.suffix[self.suffix_start..self.suffix_end]);
        let fed = match result {
            Ok(fed) => fed,
            Err(error) => return Err(self.fail(TransportError::Frame(error))),
        };
        if fed.consumed == 0 {
            return Err(self.fail(TransportError::DecoderStalled));
        }
        self.suffix_start += fed.consumed;
        self.incoming_consumed += fed.consumed;
        if let Some(frame) = fed.frame {
            self.accept_rate(now)?;
            self.incoming_started = None;
            self.incoming_consumed = 0;
            self.note_pending_input(now);
            self.finish_if_drained()?;
            return Ok(Some(ReceivedFrame(frame)));
        }
        self.finish_if_drained()?;
        Ok(None)
    }

    pub fn tick(&mut self, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        self.flush_one(now)
    }

    /// Parked socket maintenance only: no packet processing, frame consumption,
    /// plaintext flushing or native signing. Existing receive/send and TLS
    /// deadlines remain in force while the application waits for admission.
    pub(crate) fn observe_liveness(&mut self, now: Instant) -> Result<(), TransportError> {
        self.socket_adoption_available = false;
        if self.failure.is_some() {
            return Err(TransportError::Failed);
        }
        if self.local_closed {
            return Err(TransportError::Closed);
        }
        let result = self.channel_mut()?.observe_liveness(now);
        self.channel_result(result)?;
        self.note_pending_input(now);
        self.check_deadlines(now)
    }

    /// Actual relay EOF, not an empty chunk. A TLS truncation or any final
    /// partial application frame poisons the transport. Poll complete frames
    /// still buffered after authenticated close_notify before dropping the owner.
    pub fn transport_eof(&mut self, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        let result = self.channel_mut()?.transport_eof(now);
        match self.channel_result(result)? {
            EofDisposition::AuthenticatedPeerClose => self.finish_if_drained(),
            EofDisposition::LocalAlreadyClosed => Err(self.fail(TransportError::Closed)),
        }
    }

    /// Immediate irreversible local abort. The budget reservation is retained
    /// until Self drops; the native owner must close its actual relay/socket.
    pub fn close(&mut self, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        let result = self.channel_mut()?.close(now);
        self.channel_result(result)?;
        self.clear_buffers();
        self.local_closed = true;
        Ok(())
    }

    /// Call when the expected-PC signature, decision or application decoder
    /// rejects a ReceivedFrame. Framing never marks unknown payloads accepted.
    pub fn reject_protocol_message(&mut self, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        Err(self.fail(TransportError::ProtocolRejected))
    }

    // Narrow socket-owner cleanup. This only withdraws state, even when a fresh
    // native clock is unavailable; it cannot release a frame or confer authority.
    pub(crate) fn discard_socket_state(&mut self) {
        self.socket_adoption_available = false;
        self.clear_buffers();
        self.local_closed = true;
    }

    pub(crate) fn can_adopt_socket(&self) -> bool {
        self.socket_adoption_available && self.status() == TransportStatus::Handshaking
    }

    pub(crate) fn start_socket_close(&mut self, now: Instant) -> Result<(), TransportError> {
        self.begin(now)?;
        if self.status() != TransportStatus::Ready {
            return Err(TransportError::NotReady);
        }
        let pending = self.pending_counts();
        if pending.outbound_frame
            || pending.outbound_tls_bytes != 0
            || pending.incoming_frame_bytes != 0
            || pending.decrypted_suffix_bytes != 0
            || pending.incoming_tls_plaintext_bytes != 0
        {
            return Err(TransportError::Busy);
        }
        let result = self.channel_mut()?.close_gracefully(now);
        self.channel_result(result)?;
        self.local_closed = true;
        Ok(())
    }

    // Regular public operations reject local closure. Only this private path
    // can drain Channel's existing close_notify, never more application bytes.
    pub(crate) fn drain_socket_close(
        &mut self,
        output: &mut [u8],
        now: Instant,
    ) -> Result<usize, TransportError> {
        if self.failure.is_some() {
            return Err(TransportError::Failed);
        }
        if !self.local_closed {
            return Err(TransportError::NotReady);
        }
        let result = self.channel_mut()?.drain_tls(output, now);
        self.channel_result(result)
    }

    fn begin(&mut self, now: Instant) -> Result<(), TransportError> {
        // Any caller-driven mutation may have admitted/drained bytes or started
        // an application deadline that a later socket owner cannot reconstruct.
        self.socket_adoption_available = false;
        if self.failure.is_some() {
            return Err(TransportError::Failed);
        }
        if self.local_closed {
            return Err(TransportError::Closed);
        }
        let result = self.channel_mut()?.tick(now);
        self.channel_result(result)?;
        self.clear_sent();
        self.note_pending_input(now);
        self.check_deadlines(now)?;
        self.finish_if_drained()
    }

    fn channel_mut(&mut self) -> Result<&mut Channel, TransportError> {
        self.channel.as_mut().ok_or(TransportError::Closed)
    }

    fn channel_result<T>(&mut self, result: Result<T, ChannelError>) -> Result<T, TransportError> {
        match result {
            Ok(value) => Ok(value),
            Err(ChannelError::NotReady) => Err(TransportError::NotReady),
            Err(ChannelError::PeerClosed) => Err(TransportError::PeerClosed),
            Err(error) => Err(self.fail(TransportError::Channel(error))),
        }
    }

    fn flush_one(&mut self, now: Instant) -> Result<(), TransportError> {
        let Some(frame) = self.outbound.as_ref() else {
            return Ok(());
        };
        if frame.accepted == frame.bytes.len() {
            self.clear_sent();
            return Ok(());
        }
        if self
            .channel
            .as_ref()
            .is_some_and(|channel| channel.status() == ChannelStatus::PeerClosed)
        {
            // Normal TLS half-close must not discard already authenticated
            // incoming frames. Stop new plaintext writes, but retain the fixed
            // outgoing deadline until sent or the owner aborts/drops the peer.
            return Ok(());
        }
        // Keep room for peer control traffic and avoid two large simultaneous
        // frames filling both TLS write queues while each side waits to read.
        // One bounded chunk is added only below this low-water threshold.
        if self
            .channel
            .as_ref()
            .is_some_and(|channel| channel.buffered_tls_bytes() >= MAX_PLAINTEXT_WRITE_BYTES)
        {
            return Ok(());
        }
        let end = (frame.accepted + MAX_PLAINTEXT_WRITE_BYTES).min(frame.bytes.len());
        let result = self
            .channel
            .as_mut()
            .ok_or(TransportError::Closed)?
            .write_plaintext(&frame.bytes[frame.accepted..end], now);
        let accepted = self.channel_result(result)?;
        if let Some(frame) = self.outbound.as_mut() {
            frame.accepted += accepted;
        }
        self.clear_sent();
        Ok(())
    }

    fn clear_sent(&mut self) {
        if self
            .outbound
            .as_ref()
            .is_some_and(|frame| frame.accepted == frame.bytes.len())
            && self
                .channel
                .as_ref()
                .is_some_and(|channel| channel.buffered_tls_bytes() == 0)
        {
            self.outbound = None;
        }
    }

    fn note_pending_input(&mut self, now: Instant) {
        if self
            .channel
            .as_ref()
            .is_some_and(|channel| channel.buffered_plaintext_bytes() > 0)
            && self.first_unread_at.is_none()
        {
            self.first_unread_at = Some(self.last_feed_at.unwrap_or(now));
        }
        if self.incoming_started.is_none() {
            self.incoming_started = if self.suffix_start < self.suffix_end {
                self.suffix_received_at
            } else {
                self.first_unread_at
            };
        }
    }

    fn check_deadlines(&mut self, now: Instant) -> Result<(), TransportError> {
        if self
            .outbound
            .as_ref()
            .is_some_and(|frame| now >= frame.deadline)
        {
            return Err(self.fail(TransportError::SendDeadline));
        }
        if let Some(started) = self.incoming_started {
            let deadline = started
                .checked_add(FRAME_TIMEOUT)
                .ok_or_else(|| self.fail(TransportError::ClockRange))?;
            if now >= deadline {
                return Err(self.fail(TransportError::ReceiveDeadline));
            }
        }
        Ok(())
    }

    fn finish_if_drained(&mut self) -> Result<(), TransportError> {
        if !self.receive_finished
            && self.suffix_start == self.suffix_end
            && self.channel.as_ref().is_some_and(|channel| {
                channel.status() == ChannelStatus::PeerClosed
                    && channel.buffered_plaintext_bytes() == 0
            })
        {
            if let Err(error) = self.decoder.finish() {
                return Err(self.fail(TransportError::Frame(error)));
            }
            self.receive_finished = true;
            self.incoming_started = None;
            self.first_unread_at = None;
        }
        Ok(())
    }

    fn accept_rate(&mut self, now: Instant) -> Result<(), TransportError> {
        let elapsed = now
            .checked_duration_since(self.rate_window_start)
            .ok_or_else(|| self.fail(TransportError::ClockRange))?;
        if elapsed >= RECEIVE_WINDOW {
            let whole_windows = Duration::from_secs(elapsed.as_secs());
            self.rate_window_start = self
                .rate_window_start
                .checked_add(whole_windows)
                .ok_or_else(|| self.fail(TransportError::ClockRange))?;
            self.received_in_window = 0;
        }
        if self.received_in_window >= MAX_RECEIVED_FRAMES_PER_WINDOW {
            return Err(self.fail(TransportError::RateExceeded));
        }
        self.received_in_window += 1;
        Ok(())
    }

    fn clear_buffers(&mut self) {
        self.channel = None;
        self.outbound = None;
        self.decoder = FrameDecoder::new();
        self.suffix.fill(0);
        self.suffix_start = 0;
        self.suffix_end = 0;
        self.suffix_received_at = None;
        self.first_unread_at = None;
        self.last_feed_at = None;
        self.incoming_started = None;
        self.incoming_consumed = 0;
    }

    fn fail(&mut self, error: TransportError) -> TransportError {
        self.clear_buffers();
        self.failure = Some(error);
        error
    }
}

fn valid_outbound(bytes: &[u8], retained_capacity: usize) -> bool {
    if bytes.len() < 5
        || bytes.len() > MAX_QUEUED_FRAME_BYTES
        || retained_capacity > MAX_QUEUED_FRAME_BYTES
    {
        return false;
    }
    let header: [u8; 4] = match bytes[..4].try_into() {
        Ok(header) => header,
        Err(_) => return false,
    };
    let length = u32::from_be_bytes(header) as usize;
    length > 0 && length <= MAX_PC_EVENT_BYTES && length == bytes.len() - 4
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TransportError {
    #[error(transparent)]
    Budget(#[from] ConnectionBudgetError),
    #[error(transparent)]
    Channel(#[from] ChannelError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("transport is not ready for application frames")]
    NotReady,
    #[error("one outbound frame is already pending")]
    Busy,
    #[error("outbound frame length, encoding or allocation exceeds the bound")]
    InvalidOutboundFrame,
    #[error("incoming frame assembly deadline expired")]
    ReceiveDeadline,
    #[error("outgoing frame drain deadline expired")]
    SendDeadline,
    #[error("per-peer frame receive budget exceeded")]
    RateExceeded,
    #[error("trusted frame clock is outside the supported range")]
    ClockRange,
    #[error("frame decoder did not consume bounded input")]
    DecoderStalled,
    #[error("application protocol message was rejected")]
    ProtocolRejected,
    #[error("transport peer has closed")]
    PeerClosed,
    #[error("transport owner is locally closed")]
    Closed,
    #[error("transport owner has irreversibly failed")]
    Failed,
}
