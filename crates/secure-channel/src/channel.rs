// SPDX-License-Identifier: GPL-2.0-or-later
use std::{
    fmt,
    io::{self, Read, Write},
    time::Instant,
};

use rustls::{Connection, ProtocolVersion};
use thiserror::Error;

use crate::{
    ALPN, EndpointRole, HANDSHAKE_TIMEOUT, MAX_BUFFERED_BYTES, MAX_DRAIN_BYTES, MAX_INGRESS_BYTES,
    MAX_PLAINTEXT_WRITE_BYTES, READY_PREFACE, TlsIdentity, TlsPublicKey, config,
};

// rustls applies its writer limit before adding record overhead. Keep explicit
// headroom, and check the actual encrypted queue after every processing step.
const SEND_BUFFER_LIMIT: usize = MAX_BUFFERED_BYTES - 256;
// Do not process another ingress chunk while output is nearly full: processing
// can itself produce handshake/control records. Caller must drain output first.
const READ_OUTPUT_HIGH_WATER: usize = MAX_BUFFERED_BYTES - MAX_INGRESS_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStatus {
    Handshaking,
    /// Local TLS is authenticated, but the encrypted PC readiness preface or a
    /// fresh caller time check is still outstanding. Not application-ready.
    AwaitingReadiness,
    Ready,
    /// Authenticated close_notify received; already buffered plaintext can be
    /// drained, but no further application writes are accepted.
    PeerClosed,
    /// Locally closed. This does not assert peer acknowledgment of closure.
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaintextRead {
    Data(usize),
    WouldBlock,
    PeerClosed,
}

/// A local close no-op must never be mistaken for authenticated peer EOF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofDisposition {
    AuthenticatedPeerClose,
    LocalAlreadyClosed,
}

/// Exclusively owned, bounded sans-I/O channel. No inner configuration, raw
/// Rustls connection, verifier injection or TLS secret extraction is exposed.
pub struct Channel {
    connection: Option<Connection>,
    role: EndpointRole,
    peer: TlsPublicKey,
    last_observed: Instant,
    deadline: Instant,
    tls_authenticated: bool,
    ready_candidate: bool,
    ready: bool,
    local_closed: bool,
    peer_closed: bool,
    failure: Option<ChannelError>,
    preface: [u8; READY_PREFACE.len()],
    preface_progress: usize,
    outgoing: usize,
    incoming: usize,
}

impl fmt::Debug for Channel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Channel")
            .field("role", &self.role)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl Channel {
    pub fn client(
        identity: TlsIdentity,
        enrolled_pc: TlsPublicKey,
        now: Instant,
    ) -> Result<Self, ChannelError> {
        let connection = config::client(identity, enrolled_pc.clone())?;
        Self::new(connection, EndpointRole::Client, enrolled_pc, now)
    }

    pub fn server(
        identity: TlsIdentity,
        enrolled_phone: TlsPublicKey,
        now: Instant,
    ) -> Result<Self, ChannelError> {
        let connection = config::server(identity, enrolled_phone.clone())?;
        Self::new(connection, EndpointRole::Server, enrolled_phone, now)
    }

    fn new(
        mut connection: Connection,
        role: EndpointRole,
        peer: TlsPublicKey,
        now: Instant,
    ) -> Result<Self, ChannelError> {
        connection.set_buffer_limit(Some(SEND_BUFFER_LIMIT));
        let deadline = now
            .checked_add(HANDSHAKE_TIMEOUT)
            .ok_or(ChannelError::ClockRange)?;
        let mut channel = Self {
            connection: Some(connection),
            role,
            peer,
            last_observed: now,
            deadline,
            tls_authenticated: false,
            ready_candidate: false,
            ready: false,
            local_closed: false,
            peer_closed: false,
            failure: None,
            preface: [0; READY_PREFACE.len()],
            preface_progress: 0,
            outgoing: 0,
            incoming: 0,
        };
        channel.process_packets()?;
        Ok(channel)
    }

    pub fn status(&self) -> ChannelStatus {
        if self.failure.is_some() {
            ChannelStatus::Failed
        } else if self.local_closed {
            ChannelStatus::Closed
        } else if self.ready && self.peer_closed {
            ChannelStatus::PeerClosed
        } else if self.ready {
            ChannelStatus::Ready
        } else if self.tls_authenticated {
            ChannelStatus::AwaitingReadiness
        } else {
            ChannelStatus::Handshaking
        }
    }

    pub fn buffered_tls_bytes(&self) -> usize {
        self.outgoing
    }
    pub fn buffered_plaintext_bytes(&self) -> usize {
        if self.ready { self.incoming } else { 0 }
    }
    pub fn failure_reason(&self) -> Option<ChannelError> {
        self.failure
    }

    /// Feed at most 16 KiB of relay bytes and return the consumed count. The
    /// caller retains any unconsumed suffix. Empty input is not EOF. Ok(0)
    /// means bounded backpressure: drain TLS output/application input, then retry.
    pub fn feed_tls(&mut self, bytes: &[u8], now: Instant) -> Result<usize, ChannelError> {
        self.observe(now)?;
        self.ensure_open()?;
        if bytes.len() > MAX_INGRESS_BYTES {
            return Err(self.fail(ChannelError::IngressTooLarge));
        }
        if self.peer_closed {
            return Err(ChannelError::PeerClosed);
        }
        if bytes.is_empty() || self.outgoing >= READ_OUTPUT_HIGH_WATER {
            return Ok(0);
        }
        let mut input = bytes;
        let read = self.connection_mut()?.read_tls(&mut input);
        let consumed = match read {
            Ok(consumed) => consumed,
            Err(error) if error.kind() == io::ErrorKind::Other && self.incoming > 0 => {
                return Ok(0);
            }
            Err(_) => return Err(self.fail(ChannelError::TlsRejected)),
        };
        self.advance()?;
        Ok(consumed)
    }

    /// Copy at most 16 KiB of queued ciphertext into caller-owned output. This
    /// does not transmit it. It remains available after close_gracefully only
    /// to drain its close_notify; fatal and abort-close never retain output.
    pub fn drain_tls(&mut self, output: &mut [u8], now: Instant) -> Result<usize, ChannelError> {
        self.observe(now)?;
        if output.is_empty() || self.connection.is_none() {
            return Ok(0);
        }
        let length = output.len().min(MAX_DRAIN_BYTES);
        let mut destination = &mut output[..length];
        let written = self
            .connection_mut()?
            .write_tls(&mut destination)
            .map_err(|_| ChannelError::TlsRejected);
        let written = match written {
            Ok(n) => n,
            Err(error) => return Err(self.fail(error)),
        };
        self.outgoing = self.outgoing.saturating_sub(written);
        if self.local_closed {
            if self.outgoing == 0 {
                self.connection = None;
            }
        } else {
            self.advance()?;
        }
        Ok(written)
    }

    /// Write at most 16 KiB of application plaintext. Returns the accepted
    /// prefix length; Ok(0) is output backpressure. No pre-handshake buffering.
    pub fn write_plaintext(&mut self, bytes: &[u8], now: Instant) -> Result<usize, ChannelError> {
        self.observe(now)?;
        self.ensure_ready()?;
        if self.peer_closed {
            return Err(ChannelError::PeerClosed);
        }
        if bytes.len() > MAX_PLAINTEXT_WRITE_BYTES {
            return Err(ChannelError::PlaintextTooLarge);
        }
        let written = self
            .connection_mut()?
            .writer()
            .write(bytes)
            .map_err(|_| ChannelError::TlsRejected);
        let written = match written {
            Ok(n) => n,
            Err(error) => return Err(self.fail(error)),
        };
        self.process_packets()?;
        Ok(written)
    }

    /// Read only authenticated application bytes, never the internal readiness
    /// preface. This is a stream: callers must separately validate whole frames.
    pub fn read_plaintext(
        &mut self,
        output: &mut [u8],
        now: Instant,
    ) -> Result<PlaintextRead, ChannelError> {
        self.observe(now)?;
        self.ensure_ready()?;
        if output.is_empty() {
            return Ok(PlaintextRead::WouldBlock);
        }
        let length = output.len().min(MAX_PLAINTEXT_WRITE_BYTES);
        let result = self.connection_mut()?.reader().read(&mut output[..length]);
        match result {
            Ok(0) if self.peer_closed => Ok(PlaintextRead::PeerClosed),
            Ok(0) => Ok(PlaintextRead::WouldBlock),
            Ok(count) => {
                self.incoming = self.incoming.saturating_sub(count);
                Ok(PlaintextRead::Data(count))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Ok(PlaintextRead::WouldBlock)
            }
            Err(_) => Err(self.fail(ChannelError::Truncated)),
        }
    }

    /// Observe a fresh host timestamp even when no relay bytes arrive. The
    /// 10-second deadline covers TLS and the client's encrypted ready preface.
    pub fn tick(&mut self, now: Instant) -> Result<(), ChannelError> {
        self.observe(now)?;
        self.ensure_open()?;
        self.advance()
    }

    /// Check only original time bounds and failure/close state. Does not process
    /// TLS packets, invoke a signer, consume plaintext, or promote readiness.
    /// Success is not a new peer-authentication or network-liveness observation.
    pub fn observe_liveness(&mut self, now: Instant) -> Result<(), ChannelError> {
        self.observe_time(now)?;
        self.ensure_open()
    }

    /// Immediate irreversible local abort. Drops the connection and buffered
    /// data; the owner must also close the relay. Use this for revocation.
    /// It does not assert that the peer received TLS close_notify.
    pub fn close(&mut self, now: Instant) -> Result<(), ChannelError> {
        self.observe(now)?;
        self.connection = None;
        self.local_closed = true;
        self.ready = false;
        self.ready_candidate = false;
        self.outgoing = 0;
        self.incoming = 0;
        Ok(())
    }

    /// Graceful closure is available only after readiness and with no queued
    /// output. It never flushes queued application bytes as part of revocation.
    /// On Backpressure the owner may instead abort with close immediately.
    pub fn close_gracefully(&mut self, now: Instant) -> Result<(), ChannelError> {
        self.observe(now)?;
        self.ensure_ready()?;
        if self.outgoing != 0 {
            return Err(ChannelError::Backpressure);
        }
        self.connection_mut()?.send_close_notify();
        self.process_packets()?;
        self.local_closed = true;
        self.ready = false;
        self.ready_candidate = false;
        self.incoming = 0;
        Ok(())
    }

    /// Report actual relay EOF separately from an empty chunk. EOF without an
    /// authenticated peer close_notify is fatal, even after some valid records.
    /// An already locally closed channel reports a distinct non-authenticating
    /// no-op; it cannot be used to finish a received application frame.
    pub fn transport_eof(&mut self, now: Instant) -> Result<EofDisposition, ChannelError> {
        self.observe(now)?;
        if self.local_closed {
            Ok(EofDisposition::LocalAlreadyClosed)
        } else if self.peer_closed {
            Ok(EofDisposition::AuthenticatedPeerClose)
        } else {
            Err(self.fail(ChannelError::Truncated))
        }
    }

    fn observe(&mut self, now: Instant) -> Result<(), ChannelError> {
        self.observe_time(now)?;
        // A potentially blocking native signer must not make a completed
        // handshake silently evade its deadline. A subsequent public operation
        // supplies fresh time before any application data is exposed.
        if self.ready_candidate {
            self.ready_candidate = false;
            self.ready = true;
        }
        Ok(())
    }

    fn observe_time(&mut self, now: Instant) -> Result<(), ChannelError> {
        if self.failure.is_some() {
            return Err(ChannelError::Failed);
        }
        if now < self.last_observed {
            return Err(self.fail(ChannelError::ClockWentBackwards));
        }
        self.last_observed = now;
        if !self.ready && !self.local_closed && now >= self.deadline {
            return Err(self.fail(ChannelError::HandshakeExpired));
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), ChannelError> {
        if self.local_closed {
            Err(ChannelError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_ready(&self) -> Result<(), ChannelError> {
        self.ensure_open()?;
        if self.ready {
            Ok(())
        } else {
            Err(ChannelError::NotReady)
        }
    }

    fn connection_mut(&mut self) -> Result<&mut Connection, ChannelError> {
        self.connection.as_mut().ok_or(ChannelError::Closed)
    }

    fn fail(&mut self, error: ChannelError) -> ChannelError {
        self.failure = Some(error);
        self.connection = None;
        self.ready = false;
        self.ready_candidate = false;
        self.outgoing = 0;
        self.incoming = 0;
        error
    }

    fn process_packets(&mut self) -> Result<(), ChannelError> {
        let result = self.connection_mut()?.process_new_packets();
        let state = match result {
            Ok(state) => state,
            Err(_) => return Err(self.fail(ChannelError::TlsRejected)),
        };
        if state.tls_bytes_to_write() > MAX_BUFFERED_BYTES
            || state.plaintext_bytes_to_read() > MAX_BUFFERED_BYTES
        {
            return Err(self.fail(ChannelError::BufferLimit));
        }
        self.outgoing = state.tls_bytes_to_write();
        self.incoming = state.plaintext_bytes_to_read();
        self.peer_closed |= state.peer_has_closed();
        Ok(())
    }

    fn advance(&mut self) -> Result<(), ChannelError> {
        self.process_packets()?;
        if !self.tls_authenticated {
            let connection = self.connection.as_ref().ok_or(ChannelError::Closed)?;
            if connection.is_handshaking() {
                return Ok(());
            }
            let peer_matches = connection
                .peer_certificates()
                .is_some_and(|keys| keys.len() == 1 && keys[0].as_ref() == self.peer.as_spki_der());
            if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3)
                || connection.alpn_protocol() != Some(ALPN)
                || !peer_matches
            {
                return Err(self.fail(ChannelError::NegotiationRejected));
            }
            self.tls_authenticated = true;
        }
        if self.ready || self.ready_candidate {
            return Ok(());
        }
        if self.peer_closed && self.role == EndpointRole::Server {
            return Err(self.fail(ChannelError::ReadinessRejected));
        }
        match self.role {
            EndpointRole::Server => {
                let start = self.preface_progress;
                let result = self
                    .connection_mut()?
                    .writer()
                    .write(&READY_PREFACE[start..]);
                match result {
                    Ok(count) => self.preface_progress += count,
                    Err(_) => return Err(self.fail(ChannelError::TlsRejected)),
                }
            }
            EndpointRole::Client => {
                // close_notify may arrive in the same relay chunk as the
                // complete preface and application data. Consume only the
                // fixed preface first; reject an incomplete prefix at EOF.
                // Each iteration consumes >=1 byte, so this loop is <=18 reads.
                while self.preface_progress < READY_PREFACE.len() {
                    let mut part = [0; READY_PREFACE.len()];
                    let needed = READY_PREFACE.len() - self.preface_progress;
                    let result = self.connection_mut()?.reader().read(&mut part[..needed]);
                    match result {
                        Ok(0) => return Err(self.fail(ChannelError::ReadinessRejected)),
                        Ok(count) => {
                            let end = self.preface_progress + count;
                            self.preface[self.preface_progress..end]
                                .copy_from_slice(&part[..count]);
                            self.preface_progress = end;
                            if self.preface[..end] != READY_PREFACE[..end] {
                                return Err(self.fail(ChannelError::ReadinessRejected));
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                        Err(_) => return Err(self.fail(ChannelError::ReadinessRejected)),
                    }
                }
            }
        }
        self.process_packets()?;
        if self.preface_progress == READY_PREFACE.len() {
            self.ready_candidate = true;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("transport configuration could not be created")]
    Configuration,
    #[error("local transport identity has the wrong endpoint role")]
    WrongIdentityRole,
    #[error("local and enrolled peer transport keys must be distinct")]
    KeyReuse,
    #[error("transport input chunk exceeds its bound")]
    IngressTooLarge,
    #[error("application write exceeds its bound")]
    PlaintextTooLarge,
    #[error("transport buffering exceeded its bound")]
    BufferLimit,
    #[error("drain queued transport output before this operation")]
    Backpressure,
    #[error("authenticated transport readiness has not completed")]
    NotReady,
    #[error("transport authentication or record processing failed")]
    TlsRejected,
    #[error("required transport version, peer key or ALPN was not negotiated")]
    NegotiationRejected,
    #[error("authenticated PC readiness preface was invalid or missing")]
    ReadinessRejected,
    #[error("trusted transport clock went backwards")]
    ClockWentBackwards,
    #[error("trusted transport clock cannot represent the handshake deadline")]
    ClockRange,
    #[error("transport handshake or readiness deadline expired")]
    HandshakeExpired,
    #[error("transport ended without authenticated close_notify")]
    Truncated,
    #[error("transport peer has closed its sending direction")]
    PeerClosed,
    #[error("transport channel is locally closed")]
    Closed,
    #[error("transport channel has irreversibly failed")]
    Failed,
}
