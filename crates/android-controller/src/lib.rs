// SPDX-License-Identifier: GPL-2.0-or-later

//! Native commit-before-effects phone inbox ownership, not authorization.
//!
//! [`DurableInbox`] exclusively owns one domain inbox and one locked byte store.
//! Every mutating call reserves durable intent before classification and commits
//! the complete body-free checkpoint before releasing an update or request view.
//! File/codec failures latch the owner and require clearing its OS request
//! notifications; no failed candidate effects or bodies escape.
//!
//! All storage I/O is blocking. Use one native background owner, not the UI or a
//! renderer command. A successful commit is neither OS delivery nor approval:
//! callers must take fresh native time after I/O, recheck current pending state,
//! enrollment, screen-lock and per-use authentication before any applicable
//! native action. This crate contains no notification, authentication, signing,
//! private-key, network, FFI or application-runtime implementation.

#![forbid(unsafe_code)]

mod owner;
mod types;

pub use owner::DurableInbox;
pub use types::{
    CommittedCheck, CommittedOutcomeAcknowledgment, CommittedUpdate, DurableFailure, DurableFault,
    InboxCounts, NotificationCleanup,
};
