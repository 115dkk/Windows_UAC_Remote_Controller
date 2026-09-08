// SPDX-License-Identifier: GPL-2.0-or-later
//! One bounded owner for enrolled TLS peers and length-prefixed protocol frames.
//!
//! Use one shared ConnectionBudget for all transports in the containing actor.
//! A slot is reserved before TLS allocation and remains reserved until the
//! PeerTransport is dropped, including after failure or local close. This does
//! not count sockets accepted outside this API; their native owner must limit
//! and close them independently.
//!
//! ReceivedFrame proves only complete bounded framing inside authenticated TLS,
//! not a PC message signature, enrollment, user approval or Windows result.
//! Verify the expected PC/key and message before use, and call
//! reject_protocol_message on any signature/decision/protocol decoding error.
//! Never retain an unbounded queue of returned frames outside this owner.
//!
//! Every operation takes a fresh trusted suspend-inclusive Instant projection.
//! On Android, consistently project elapsedRealtimeNanos from one anchor using
//! checked arithmetic; do not mix raw Instant::now with projected values. Call
//! tick while idle so handshake/frame/queue deadlines cannot be forgotten.

#![forbid(unsafe_code)]

mod budget;
mod socket;
mod transport;

pub use budget::{ConnectionBudget, ConnectionBudgetError};
pub use socket::{
    MAX_SOCKET_IDLE_TIMEOUT, MAX_SOCKET_LIFETIME, SocketClock, SocketClockUnavailable,
    SocketDriver, SocketError, SocketEvent, SocketLimits, SocketLimitsError, SocketPending,
};
pub use tokio_util::sync::CancellationToken;
pub use transport::{PeerTransport, PendingCounts, ReceivedFrame, TransportError, TransportStatus};

pub const MAX_CONNECTIONS: usize = 32;
pub const MAX_QUEUED_FRAME_BYTES: usize = service_protocol::MAX_PC_EVENT_BYTES + 4;
pub const MAX_DECRYPTED_SUFFIX_BYTES: usize = 16 * 1024;
pub const FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
pub const RECEIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
pub const MAX_RECEIVED_FRAMES_PER_WINDOW: usize = 128;

const _: () = assert!(MAX_DECRYPTED_SUFFIX_BYTES <= service_protocol::MAX_STREAM_CHUNK_BYTES);
const _: () = assert!(MAX_DECRYPTED_SUFFIX_BYTES <= secure_channel::MAX_PLAINTEXT_WRITE_BYTES);

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
