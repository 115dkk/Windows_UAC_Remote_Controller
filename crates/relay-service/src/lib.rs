// SPDX-License-Identifier: GPL-2.0-or-later
//! A bounded opaque carrier. Route knowledge and READY_MARKER are not identity.
//! Endpoints must mutually pin inner TLS peers before sending application data.
#![forbid(unsafe_code)]

mod client;
mod config;
mod relay;
mod wire;

pub use client::{
    CLIENT_RENDEZVOUS_TIMEOUT, CONNECT_TIMEOUT, RendezvousCarrier, RendezvousError,
    connect_rendezvous,
};
pub use config::{
    MAX_ACCEPTED_CONNECTIONS, MAX_WAITING_ROOMS, RelayError, RelayLimits, RelayLimitsError,
    RelayReport,
};
pub use relay::run;
pub use tokio_util::sync::CancellationToken;
pub use wire::{
    HEADER_BYTES, HEADER_MAGIC, READY_MARKER, Registration, RegistrationError, Role, RouteId,
};

pub const COPY_BUFFER_BYTES: usize = 16 * 1024;
