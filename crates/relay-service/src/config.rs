// SPDX-License-Identifier: GPL-2.0-or-later

use std::time::Duration;
use thiserror::Error;

pub const MAX_ACCEPTED_CONNECTIONS: usize = 64;
pub const MAX_WAITING_ROOMS: usize = 32;
const MAX_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_WAITING_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    pub(crate) connections: usize,
    pub(crate) waiting_rooms: usize,
    pub(crate) header_timeout: Duration,
    pub(crate) waiting_timeout: Duration,
    pub(crate) inactivity_timeout: Duration,
    pub(crate) absolute_timeout: Duration,
    pub(crate) shutdown_timeout: Duration,
}

impl RelayLimits {
    pub fn new(connections: usize, waiting_rooms: usize) -> Result<Self, RelayLimitsError> {
        if !(2..=MAX_ACCEPTED_CONNECTIONS).contains(&connections) {
            return Err(RelayLimitsError::ConnectionLimit);
        }
        if waiting_rooms == 0 || waiting_rooms > MAX_WAITING_ROOMS || waiting_rooms > connections {
            return Err(RelayLimitsError::WaitingRoomLimit);
        }
        Ok(Self {
            connections,
            waiting_rooms,
            ..Self::default()
        })
    }

    /// May only tighten the public ceilings. Zero/unbounded deadlines are rejected.
    pub fn with_timeouts(
        mut self,
        header: Duration,
        waiting: Duration,
        inactivity: Duration,
        absolute: Duration,
        shutdown: Duration,
    ) -> Result<Self, RelayLimitsError> {
        for (value, maximum) in [
            (header, MAX_HEADER_TIMEOUT),
            (waiting, MAX_WAITING_TIMEOUT),
            (inactivity, MAX_INACTIVITY_TIMEOUT),
            (absolute, MAX_ABSOLUTE_TIMEOUT),
            (shutdown, MAX_SHUTDOWN_TIMEOUT),
        ] {
            if value.is_zero() || value > maximum {
                return Err(RelayLimitsError::Timeout);
            }
        }
        self.header_timeout = header;
        self.waiting_timeout = waiting;
        self.inactivity_timeout = inactivity;
        self.absolute_timeout = absolute;
        self.shutdown_timeout = shutdown;
        Ok(self)
    }

    pub const fn max_connections(self) -> usize {
        self.connections
    }
    pub const fn max_waiting_rooms(self) -> usize {
        self.waiting_rooms
    }
    pub const fn header_timeout(self) -> Duration {
        self.header_timeout
    }
    pub const fn waiting_timeout(self) -> Duration {
        self.waiting_timeout
    }
    pub const fn inactivity_timeout(self) -> Duration {
        self.inactivity_timeout
    }
    pub const fn absolute_timeout(self) -> Duration {
        self.absolute_timeout
    }
    pub const fn shutdown_timeout(self) -> Duration {
        self.shutdown_timeout
    }
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            connections: MAX_ACCEPTED_CONNECTIONS,
            waiting_rooms: MAX_WAITING_ROOMS,
            header_timeout: MAX_HEADER_TIMEOUT,
            waiting_timeout: MAX_WAITING_TIMEOUT,
            inactivity_timeout: MAX_INACTIVITY_TIMEOUT,
            absolute_timeout: MAX_ABSOLUTE_TIMEOUT,
            shutdown_timeout: MAX_SHUTDOWN_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RelayLimitsError {
    #[error("connection limit must be between two and sixty-four")]
    ConnectionLimit,
    #[error("waiting-room limit must fit the connection limit and the thirty-two-room ceiling")]
    WaitingRoomLimit,
    #[error("relay deadlines must be positive and within their fixed ceilings")]
    Timeout,
}

/// Fixed infrastructure categories; never an OS error, address, route or payload.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RelayError {
    #[error("relay listener could not accept a connection")]
    AcceptFailed,
    #[error("relay connection task failed")]
    TaskFailed,
    #[error("relay connection identifier range is exhausted")]
    IdentifierExhausted,
    #[error("relay shutdown did not complete within its bound")]
    ShutdownIncomplete,
}

/// Aggregate counts only. A routing match or forwarded byte is not authentication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayReport {
    pub accepted: u64,
    pub rejected_capacity: u64,
    pub rejected_waiting_rooms: u64,
    pub rejected_duplicates: u64,
    pub paired: u64,
    pub invalid_registrations: u64,
    pub header_timeouts: u64,
    pub waiting_timeouts: u64,
    pub rendezvous_timeouts: u64,
    pub idle_timeouts: u64,
    pub absolute_timeouts: u64,
    pub disconnected: u64,
    pub io_failures: u64,
    pub cancelled: u64,
    pub task_failures: u64,
    pub peak_connections: usize,
    pub peak_waiting_rooms: usize,
    pub remaining_connections: usize,
}
