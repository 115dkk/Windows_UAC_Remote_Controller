// SPDX-License-Identifier: GPL-2.0-or-later

//! Pure phone notification scheduling and bounded request lifecycle policy.
//!
//! This crate neither verifies signatures nor posts Android notifications. The
//! authenticated transport must validate peer/session identity, replay rules and
//! the original immutable request lifetime **before** constructing metadata here.
//! Evaluate metadata before decoding/storing a notification body or adding it to
//! user-visible history. [`Effect::Drop`] is never a history entry.
//!
//! The OS adapter supplies the phone's **current** timezone's local weekday and
//! minute, separately from a trusted monotonic clock. It must call
//! [`NotificationEngine::check_pending`] immediately before display or enabling
//! a decision affordance, process withdrawal effects, and maintain independent
//! deadline and local-minute/timezone-change wakeups even if transport disconnects.
//! A pending result is presentation state, not UAC authorization or a credential.
//! A future Android adapter must additionally enforce its secure-lock/keyguard
//! requirements; none are implemented or proven by this pure module.
//!
//! [`LifecycleCheckpoint`] is opaque metadata, deliberately not directly
//! serializable. Its trusted-storage constructor validates structure, not native
//! private-storage provenance, PC signatures, boot identity, or lease continuity.
//! A restart owner must verify those properties and the full immutable bindings,
//! reconcile current policy, and reverify any body before presentation. Device
//! reboot requires a new authenticated session/epoch and withdrawal of stale OS
//! notifications; the same engine cannot reset its monotonic origin. Restoring
//! emits no effects. A recovery owner may emit [`Effect::Restore`] only for a
//! reverified, still-live request, without sounding/vibrating again. Reconstructing
//! an empty engine while accepting the old session can resurrect a still-live
//! suppressed request and is not a supported production integration.

#![forbid(unsafe_code)]

mod lifecycle;
mod schedule;

pub use lifecycle::{
    AuthenticatedPcOutcome, AuthenticatedRequestMetadata, CapacityError, CapacityLimits,
    CheckpointError, ClockReading, DropReason, Effect, EngineFault, LifecycleCheckpoint,
    LifecycleRecord, MAX_ACTIVE_REQUESTS, MAX_REQUEST_LIFETIME_MILLIS, MAX_RETAINED_REQUESTS,
    MetadataError, MonotonicTime, NotificationEngine, PendingCheck, PendingNotification,
    RequestKey, RequestOutcome, WithdrawalReason,
};
pub use schedule::{
    AlertMode, DayMask, LocalTime, MAX_SCHEDULE_WINDOWS, NotificationPolicy, Schedule,
    ScheduleError, TimeWindow, Weekday, WeeklySchedule,
};
