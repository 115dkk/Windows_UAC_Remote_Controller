// SPDX-License-Identifier: GPL-2.0-or-later
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use thiserror::Error;

use crate::MAX_CONNECTIONS;

/// One immutable global budget shared by the trusted host's peer actors. It is
/// not a system-wide socket counter or an authorization to accept a connection.
pub struct ConnectionBudget {
    limit: usize,
    active: AtomicUsize,
}

impl ConnectionBudget {
    pub fn new(limit: usize) -> Result<Self, ConnectionBudgetError> {
        if !(1..=MAX_CONNECTIONS).contains(&limit) {
            return Err(ConnectionBudgetError::InvalidLimit);
        }
        Ok(Self {
            limit,
            active: AtomicUsize::new(0),
        })
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn reserve(self: &Arc<Self>) -> Result<Reservation, ConnectionBudgetError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .map_err(|_| ConnectionBudgetError::Exhausted)?;
        Ok(Reservation {
            budget: Arc::clone(self),
        })
    }
}

impl fmt::Debug for ConnectionBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionBudget")
            .field("limit", &self.limit)
            .field("active", &self.active())
            .finish()
    }
}

pub(crate) struct Reservation {
    budget: Arc<ConnectionBudget>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // Not Clone and never removed from a live PeerTransport. Each successful
        // reservation increments once and its unique owner decrements once.
        let _ = self.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ConnectionBudgetError {
    #[error("connection budget must be between one and 32")]
    InvalidLimit,
    #[error("connection budget is exhausted")]
    Exhausted,
}
