// SPDX-License-Identifier: GPL-2.0-or-later
//! Signed service-origin events inside an authenticated confidential channel.
//!
//! A signature is not enrollment, a native Windows observation, or permission to
//! execute anything. The trusted host owns those facts and the enrolled PC/key
//! mapping. Neither keys nor a generic native signing/execution API live here.
#![forbid(unsafe_code)]

mod clock;
mod codec;
mod frame;
mod message;

pub use clock::{
    ClockCorrelation, ClockError, ClockProbe, MAX_CLOCK_CORRELATION_AGE_NANOS,
    MAX_CLOCK_PROBE_RTT_NANOS, MappedRequestWindow,
};
pub use frame::{FrameDecoder, FrameError, FrameFeed, MAX_STREAM_CHUNK_BYTES, encode_frame};
pub use message::{
    ClockProbeNonce, MAX_PC_EVENT_BYTES, MAX_REQUEST_LIFETIME_NANOS, PcEvent, PcEventError,
    PcPublicKey, RequestResolution, ServiceTick, SignedPcEvent, UnsignedPcEvent, VerifiedPcEvent,
};
