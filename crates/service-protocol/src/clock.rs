// SPDX-License-Identifier: GPL-2.0-or-later
//! Conservative service-tick to phone-monotonic correlation.
//!
//! The native owner supplies fresh processing-time `elapsedRealtimeNanos` (or
//! its own consistent monotonic clock), never wall time, a UI value, or a peer's
//! claimed phone timestamp. A signed clock response is correlated only with one
//! newly generated, consumed probe. Sending time is the lower-bound anchor; no
//! receive-time TTL reset, midpoint estimate or latency correction is applied.

#![forbid(unsafe_code)]

use std::fmt;

use approval_protocol::{BootEpoch, PcIdentity, RequestBinding};
use thiserror::Error;

use crate::{ClockProbeNonce, PcEvent, ServiceTick, VerifiedPcEvent};

pub const MAX_CLOCK_PROBE_RTT_NANOS: u64 = 10_000_000_000;
pub const MAX_CLOCK_CORRELATION_AGE_NANOS: u64 = 300_000_000_000;

/// A newly generated challenge and its trusted native send observation.
///
/// Deliberately neither Clone nor Copy. Complete consumes the probe on success
/// or error, so retrying requires a fresh CSPRNG challenge and a new send time.
///
/// ```compile_fail
/// use service_protocol::{ClockProbe, VerifiedPcEvent};
/// fn cannot_replay_probe(probe: ClockProbe, reply: &VerifiedPcEvent, now: u64) {
///     let _ = probe.complete(reply, now);
///     let _ = probe.complete(reply, now);
/// }
/// ```
pub struct ClockProbe {
    expected_pc: PcIdentity,
    nonce: ClockProbeNonce,
    phone_sent_nanos: u64,
}

impl ClockProbe {
    /// Call immediately before sending the resulting nonce over the enrolled
    /// authenticated transport. An RNG error/invalid all-zero result fails
    /// closed, without a predictable nonce or a silently reused challenge.
    pub fn start(expected_pc: PcIdentity, phone_sent_nanos: u64) -> Result<Self, ClockError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| ClockError::EntropyUnavailable)?;
        let nonce =
            ClockProbeNonce::from_bytes(bytes).map_err(|_| ClockError::EntropyUnavailable)?;
        Ok(Self {
            expected_pc,
            nonce,
            phone_sent_nanos,
        })
    }

    pub const fn nonce(&self) -> ClockProbeNonce {
        self.nonce
    }

    /// Fixed request for this exact pending probe. Its bytes must be queued only
    /// on the same enrolled peer connection whose response completes the probe.
    pub const fn request(&self) -> crate::ClockProbeRequest {
        crate::ClockProbeRequest::from_probe(self.expected_pc, self)
    }

    /// Accept only a signature-verified clock event matching this PC and nonce.
    /// The caller must have verified with the enrolled PC's current key, not an
    /// arbitrary key that happens to verify the event. Revocation remains the
    /// transport/identity owner's responsibility.
    pub fn complete(
        self,
        response: &VerifiedPcEvent,
        phone_received_nanos: u64,
    ) -> Result<ClockCorrelation, ClockError> {
        let PcEvent::Clock {
            pc,
            epoch,
            probe,
            sampled_at,
        } = response.event()
        else {
            return Err(ClockError::WrongEventKind);
        };
        if *pc != self.expected_pc {
            return Err(ClockError::WrongPc);
        }
        if *probe != self.nonce {
            return Err(ClockError::WrongProbe);
        }
        let round_trip = phone_received_nanos
            .checked_sub(self.phone_sent_nanos)
            .ok_or(ClockError::LocalClockRegressed)?;
        if round_trip > MAX_CLOCK_PROBE_RTT_NANOS {
            return Err(ClockError::ProbeTooSlow);
        }
        Ok(ClockCorrelation {
            pc: *pc,
            epoch: *epoch,
            service_sample: *sampled_at,
            phone_anchor_nanos: self.phone_sent_nanos,
            phone_probe_received_nanos: phone_received_nanos,
            last_observed_nanos: phone_received_nanos,
            faulted: false,
        })
    }
}

impl fmt::Debug for ClockProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClockProbe([redacted])")
    }
}

/// Immutable correlation anchors with a private local-observation watermark.
///
/// Mapping requires exclusive access to the single receiving owner; this type
/// is neither Clone nor Copy. A real native-clock regression latches a fault.
/// The owner must reconcile state and perform a new authenticated probe instead
/// of clearing that latch or switching epochs inside this correlation.
pub struct ClockCorrelation {
    pc: PcIdentity,
    epoch: BootEpoch,
    service_sample: ServiceTick,
    phone_anchor_nanos: u64,
    phone_probe_received_nanos: u64,
    last_observed_nanos: u64,
    faulted: bool,
}

impl ClockCorrelation {
    pub const fn pc(&self) -> PcIdentity {
        self.pc
    }

    pub const fn epoch(&self) -> BootEpoch {
        self.epoch
    }

    pub const fn service_sample(&self) -> ServiceTick {
        self.service_sample
    }

    pub const fn phone_anchor_nanos(&self) -> u64 {
        self.phone_anchor_nanos
    }

    pub const fn phone_probe_received_nanos(&self) -> u64 {
        self.phone_probe_received_nanos
    }

    pub const fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// Map a first-seen request's ORIGINAL signed issuance and expiry.
    ///
    /// `phone_received_nanos` must be a fresh native observation taken at this
    /// validation/processing step, not an old queued packet's arrival timestamp.
    /// The owner retains this mapping for duplicate deliveries/resolutions; it
    /// must never remap an existing request after a new probe to extend expiry
    /// or revive an off-hours/discarded request. This method itself is not a
    /// replay registry, notification permission, decision, or OS authorization.
    pub fn map_request(
        &mut self,
        event: &VerifiedPcEvent,
        phone_received_nanos: u64,
    ) -> Result<MappedRequestWindow, ClockError> {
        if self.faulted {
            return Err(ClockError::CorrelationFaulted);
        }
        let (binding, issued_at) = match event.event() {
            PcEvent::Opened {
                binding, issued_at, ..
            }
            | PcEvent::Resolved {
                binding, issued_at, ..
            } => (*binding, *issued_at),
            PcEvent::Clock { .. } => return Err(ClockError::WrongEventKind),
        };
        if binding.pc() != self.pc {
            return Err(ClockError::WrongPc);
        }
        if binding.epoch() != self.epoch {
            return Err(ClockError::WrongEpoch);
        }

        // Validate the signed event kind/identity before observing local time.
        // Unrelated events cannot advance the watermark or fault this owner.
        // For an authentic matching request, a fresh native observation remains
        // real even if its expiry or service-tick mapping is subsequently bad.
        if phone_received_nanos < self.last_observed_nanos {
            self.faulted = true;
            return Err(ClockError::LocalClockRegressed);
        }
        self.last_observed_nanos = phone_received_nanos;
        let age = phone_received_nanos
            .checked_sub(self.phone_anchor_nanos)
            .ok_or(ClockError::LocalClockRegressed)?;
        if age > MAX_CLOCK_CORRELATION_AGE_NANOS {
            return Err(ClockError::CorrelationTooOld);
        }

        let sample = self.service_sample.as_nanos_since_epoch();
        let expiry = binding.expiry().as_nanos_since_epoch();
        let remaining_from_sample = expiry
            .checked_sub(sample)
            .filter(|remaining| *remaining > 0)
            .ok_or(ClockError::RequestExpired)?;
        let phone_expiry_nanos = self
            .phone_anchor_nanos
            .checked_add(remaining_from_sample)
            .ok_or(ClockError::ArithmeticOverflow)?;
        if phone_expiry_nanos <= phone_received_nanos {
            return Err(ClockError::RequestExpired);
        }

        let issued = issued_at.as_nanos_since_epoch();
        let phone_issued_nanos = if issued >= sample {
            self.phone_anchor_nanos
                .checked_add(issued - sample)
                .ok_or(ClockError::ArithmeticOverflow)?
        } else {
            // Pre-sample issuance can precede the phone's own monotonic origin.
            // Saturating to zero shortens the observable window; it does not
            // invent a positive timestamp or add lifetime to the expiry.
            self.phone_anchor_nanos.saturating_sub(sample - issued)
        };
        if phone_issued_nanos > phone_received_nanos {
            return Err(ClockError::IssuedInFuture);
        }
        Ok(MappedRequestWindow {
            binding,
            service_issued_at: issued_at,
            phone_issued_nanos,
            phone_expiry_nanos,
        })
    }
}

impl fmt::Debug for ClockCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClockCorrelation")
            .field("faulted", &self.faulted)
            .finish_non_exhaustive()
    }
}

/// One immutable original request mapping. Retain it in the request owner's
/// bounded lifecycle registry. It is not a permission to display or approve.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MappedRequestWindow {
    binding: RequestBinding,
    service_issued_at: ServiceTick,
    phone_issued_nanos: u64,
    phone_expiry_nanos: u64,
}

impl MappedRequestWindow {
    /// Reconstruct previously computed metadata from trusted private storage.
    /// This validates shape only: it proves neither storage provenance, a
    /// matching native boot, freshness, peer enrollment nor permission. The
    /// receiving owner must validate those separately and reverify request
    /// content before exposing a recovered view. Never use this on wire input.
    pub fn from_trusted_checkpoint(
        binding: RequestBinding,
        service_issued_at: ServiceTick,
        phone_issued_nanos: u64,
        phone_expiry_nanos: u64,
    ) -> Result<Self, ClockError> {
        let service_lifetime = binding
            .expiry()
            .as_nanos_since_epoch()
            .checked_sub(service_issued_at.as_nanos_since_epoch())
            .filter(|value| *value > 0 && *value <= crate::MAX_REQUEST_LIFETIME_NANOS)
            .ok_or(ClockError::InvalidRecoveredWindow)?;
        phone_expiry_nanos
            .checked_sub(phone_issued_nanos)
            .filter(|value| *value > 0 && *value <= service_lifetime)
            .ok_or(ClockError::InvalidRecoveredWindow)?;
        Ok(Self {
            binding,
            service_issued_at,
            phone_issued_nanos,
            phone_expiry_nanos,
        })
    }

    pub const fn binding(&self) -> RequestBinding {
        self.binding
    }

    pub const fn service_issued_at(&self) -> ServiceTick {
        self.service_issued_at
    }

    pub const fn phone_issued_nanos(&self) -> u64 {
        self.phone_issued_nanos
    }

    pub const fn phone_expiry_nanos(&self) -> u64 {
        self.phone_expiry_nanos
    }
}

impl fmt::Debug for MappedRequestWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MappedRequestWindow([redacted])")
    }
}

/// Fixed failure classes only; no raw entropy, signature, peer or request data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClockError {
    #[error("the recovered original mapping has invalid bounds")]
    InvalidRecoveredWindow,
    #[error("fresh clock-probe entropy is unavailable")]
    EntropyUnavailable,
    #[error("the verified event is not the required clock or request kind")]
    WrongEventKind,
    #[error("the verified event belongs to a different PC")]
    WrongPc,
    #[error("the clock response does not match this fresh probe")]
    WrongProbe,
    #[error("the verified request belongs to a different service epoch")]
    WrongEpoch,
    #[error("the native phone clock moved backwards")]
    LocalClockRegressed,
    #[error("this clock correlation is faulted and requires owner reconciliation")]
    CorrelationFaulted,
    #[error("the clock-probe round trip exceeded ten seconds")]
    ProbeTooSlow,
    #[error("the clock correlation is more than five minutes old")]
    CorrelationTooOld,
    #[error("the clock mapping exceeds its integer range")]
    ArithmeticOverflow,
    #[error("the request is no longer live under the conservative clock mapping")]
    RequestExpired,
    #[error("the request issuance maps after the current native phone observation")]
    IssuedInFuture,
}
