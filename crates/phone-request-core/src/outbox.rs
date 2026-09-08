// SPDX-License-Identifier: GPL-2.0-or-later
//! Body-free outcome delivery identities. No journal write or OS result is
//! performed here; the native recipient must deduplicate durable inserts by ID.

use std::fmt;

use approval_protocol::RequestBinding;
use notification_policy::{RequestKey, RequestOutcome};
use service_protocol::{MAX_REQUEST_LIFETIME_NANOS, ServiceTick};
use sha2::{Digest, Sha256};

use crate::request_key;

const DELIVERY_DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/outcome-delivery/v1\0";

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutcomeDeliveryId([u8; 32]);

impl OutcomeDeliveryId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for OutcomeDeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutcomeDeliveryId([redacted])")
    }
}

/// One pending metadata-only terminal outcome. `CompletedByPc` preserves the
/// existing lifecycle meaning and does not imply successful UAC approval.
/// The ID/binding/issuance/outcome are immutable and independent of retry time,
/// phone process/boot, checkpoint generation or the receiver's wall clock.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PendingOutcome {
    delivery_id: OutcomeDeliveryId,
    binding: RequestBinding,
    issued_at: ServiceTick,
    outcome: RequestOutcome,
}

impl PendingOutcome {
    pub const fn delivery_id(self) -> OutcomeDeliveryId {
        self.delivery_id
    }
    pub fn key(self) -> RequestKey {
        request_key(self.binding)
    }
    pub const fn binding(self) -> RequestBinding {
        self.binding
    }
    pub const fn issued_at(self) -> ServiceTick {
        self.issued_at
    }
    pub const fn outcome(self) -> RequestOutcome {
        self.outcome
    }

    pub(crate) fn new(
        binding: RequestBinding,
        issued_at: ServiceTick,
        outcome: RequestOutcome,
    ) -> Self {
        // Canonical full binding in the same fixed big-endian field order used
        // by the request protocol, followed by original issuance and a fixed
        // outcome discriminant. Never hash Debug, JSON, a body or arrival time.
        let mut digest = Sha256::new();
        digest.update(DELIVERY_DOMAIN);
        digest.update(binding.pc().as_bytes());
        digest.update(binding.epoch().as_bytes());
        digest.update(binding.session().session_id().to_be_bytes());
        digest.update(binding.session().logon_id().to_be_bytes());
        digest.update(binding.request_id().as_bytes());
        digest.update(binding.nonce().as_bytes());
        digest.update(binding.content_digest().as_bytes());
        digest.update(binding.expiry().as_nanos_since_epoch().to_be_bytes());
        digest.update(issued_at.as_nanos_since_epoch().to_be_bytes());
        digest.update([outcome_tag(outcome)]);
        Self {
            delivery_id: OutcomeDeliveryId(digest.finalize().into()),
            binding,
            issued_at,
            outcome,
        }
    }

    pub(crate) fn from_encoded(
        delivery_id: [u8; 32],
        binding: RequestBinding,
        issued_at: ServiceTick,
        outcome: RequestOutcome,
    ) -> Option<Self> {
        let result = Self::new(binding, issued_at, outcome);
        (result.delivery_id.0 == delivery_id && result.valid()).then_some(result)
    }

    pub(crate) fn valid(self) -> bool {
        self.binding
            .expiry()
            .as_nanos_since_epoch()
            .checked_sub(self.issued_at.as_nanos_since_epoch())
            .is_some_and(|lifetime| lifetime > 0 && lifetime <= MAX_REQUEST_LIFETIME_NANOS)
            && self.delivery_id == Self::new(self.binding, self.issued_at, self.outcome).delivery_id
    }
}

impl fmt::Debug for PendingOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingOutcome([redacted], not_delivery_proof)")
    }
}

/// Storage acknowledgment only. NotPending means only that this queue has no
/// matching ID, never that an unknown/repeated ID reached an OS or journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeAcknowledgment {
    Removed,
    NotPending,
}

pub(crate) const fn outcome_tag(outcome: RequestOutcome) -> u8 {
    match outcome {
        RequestOutcome::CancelledByPc => 1,
        RequestOutcome::ExpiredByPc => 2,
        RequestOutcome::ExpiredLocally => 3,
        RequestOutcome::CompletedByPc => 4,
    }
}

pub(crate) const fn outcome_from_tag(tag: u8) -> Option<RequestOutcome> {
    match tag {
        1 => Some(RequestOutcome::CancelledByPc),
        2 => Some(RequestOutcome::ExpiredByPc),
        3 => Some(RequestOutcome::ExpiredLocally),
        4 => Some(RequestOutcome::CompletedByPc),
        _ => None,
    }
}
