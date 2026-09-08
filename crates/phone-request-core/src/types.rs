// SPDX-License-Identifier: GPL-2.0-or-later

use std::{fmt, sync::Arc};

use approval_protocol::{RequestBinding, RequestContent};
use notification_policy::{ClockReading, Effect, EngineFault, PendingNotification, RequestKey};
use service_protocol::{ClockError, MappedRequestWindow};
use thiserror::Error;

pub(crate) const NANOS_PER_MILLI: u64 = 1_000_000;

/// Coherent observations from one native phone monotonic epoch and timezone.
/// Construction checks units only, not OS provenance or screen-lock readiness.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InboxClock {
    pub(crate) reading: ClockReading,
    pub(crate) nanos: u64,
}

impl InboxClock {
    pub fn new(reading: ClockReading, phone_monotonic_nanos: u64) -> Result<Self, InboxIssue> {
        if reading.monotonic.as_millis() != phone_monotonic_nanos / NANOS_PER_MILLI {
            return Err(InboxIssue::IncoherentClock);
        }
        Ok(Self {
            reading,
            nanos: phone_monotonic_nanos,
        })
    }

    pub const fn reading(self) -> ClockReading {
        self.reading
    }
    pub const fn phone_monotonic_nanos(self) -> u64 {
        self.nanos
    }
}

impl fmt::Debug for InboxClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InboxClock(native_observation)")
    }
}

/// Latched failures require receiving-owner reconciliation, not clearing a flag.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboxFault {
    #[error("the receiving owner is unavailable and stopped this inbox")]
    ReceivingOwnerStopped,
    #[error("the native phone monotonic clock moved backwards")]
    NativeClockRegressed,
    #[error("the supplied clock correlation is faulted")]
    ClockCorrelationFaulted,
    #[error("the clock guard exceeds the supported integer range")]
    ClockRangeExceeded,
    #[error("the verified request cannot be covered by the bounded clock guard")]
    UnboundedClockGuard,
    #[error("the bounded source-clock watermark registry is full")]
    SourceCapacityReached,
    #[error("the notification engine rejected its native clock contract: {0:?}")]
    NotificationEngine(EngineFault),
    #[error("the inbox and notification engine cannot be reconciled")]
    InconsistentState,
    #[error("a terminal outcome could not be retained; this state cannot be committed")]
    OutcomeRetentionFailed,
}

/// Fixed categories only. None contain request text, key bytes, or raw errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboxIssue {
    #[error("the phone nanosecond and millisecond observations do not match")]
    IncoherentClock,
    #[error("the verified event is not the requested opened or resolution kind")]
    WrongEventKind,
    #[error("the clock correlation belongs to another PC")]
    WrongPc,
    #[error("the clock correlation belongs to another service epoch")]
    WrongEpoch,
    #[error("the request key was reused with a different immutable binding")]
    ConflictingBinding,
    #[error("the request key was reused with a different original issuance")]
    ConflictingIssuedAt,
    #[error("the original request window could not be mapped: {0}")]
    Clock(ClockError),
    #[error("the bounded original-mapping guard cache is full")]
    GuardCapacity,
    #[error("pending outcome delivery leaves no terminal-result reservation for a new request")]
    OutcomeCapacity,
    #[error("new request identities are quarantined until untracked guards expire")]
    GuardQuarantine,
    #[error("the receiving owner is faulted: {0}")]
    Faulted(InboxFault),
}

/// Every transition carries withdrawals even when the input has an issue.
/// Native callers must apply effects before reading any current request view.
/// RecordOutcome is only a compatibility/wake hint: pending_outcomes is the
/// sole source for journal delivery, with its stable idempotency identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxUpdate {
    pub(crate) effects: Vec<Effect>,
    pub(crate) issue: Option<InboxIssue>,
    pub(crate) fault: Option<InboxFault>,
}

impl InboxUpdate {
    pub fn effects(&self) -> &[Effect] {
        &self.effects
    }
    pub const fn issue(&self) -> Option<InboxIssue> {
        self.issue
    }
    pub const fn fault(&self) -> Option<InboxFault> {
        self.fault
    }
    pub fn into_effects(self) -> Vec<Effect> {
        self.effects
    }
}

/// A read-only snapshot made only by `PhoneInbox::check_pending`.
///
/// It is not live permission. The caller must discard its copy after withdrawal
/// and recheck immediately before native display or any user decision. An Arc
/// held by the caller cannot be revoked by the inbox; the inbox itself drops its
/// body reference as soon as the request is no longer active/allowed.
#[derive(Clone)]
pub struct PendingRequest {
    pub(crate) window: MappedRequestWindow,
    pub(crate) notification: PendingNotification,
    pub(crate) content: Arc<RequestContent>,
}

impl PendingRequest {
    pub const fn key(&self) -> RequestKey {
        self.notification.key
    }
    pub const fn binding(&self) -> RequestBinding {
        self.window.binding()
    }
    pub const fn original_window(&self) -> MappedRequestWindow {
        self.window
    }
    pub const fn notification(&self) -> PendingNotification {
        self.notification
    }
    pub fn content(&self) -> &Arc<RequestContent> {
        &self.content
    }
}

impl fmt::Debug for PendingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingRequest([redacted], snapshot_not_authority)")
    }
}

#[derive(Clone, Debug)]
pub struct InboxCheck {
    pub(crate) update: InboxUpdate,
    pub(crate) request: Option<PendingRequest>,
}

impl InboxCheck {
    pub fn update(&self) -> &InboxUpdate {
        &self.update
    }
    pub fn request(&self) -> Option<&PendingRequest> {
        self.request.as_ref()
    }
    pub fn into_parts(self) -> (InboxUpdate, Option<PendingRequest>) {
        (self.update, self.request)
    }
}
