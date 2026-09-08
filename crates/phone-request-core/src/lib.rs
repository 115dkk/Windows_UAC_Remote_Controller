// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded phone inbox and body-free checkpoints; no Windows UAC authorization.
#![forbid(unsafe_code)]

mod checkpoint;
mod checkpoint_codec;
mod inbox;
mod types;

pub use checkpoint::{InboxCheckpoint, InboxCheckpointError, PhoneBootId};
pub use inbox::{PhoneInbox, request_key};
pub use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, Effect, LocalTime, MonotonicTime, NotificationPolicy,
    RequestKey,
};
pub use types::{InboxCheck, InboxClock, InboxFault, InboxIssue, InboxUpdate, PendingRequest};
