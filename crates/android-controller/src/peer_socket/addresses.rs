// SPDX-License-Identifier: GPL-2.0-or-later
//! Connection-bound address hints; never a permission or request deadline.
use std::sync::Arc;

use approval_protocol::BootEpoch;
use phone_request_core::InboxClock;
use secure_channel::ControlProtocol;
use service_protocol::{
    AddressQuery, ClockProbe, SignedAddressAdvertisement, VerifiedAddressAdvertisement,
};

use super::{AssociatedPcSocket, PcSocketEvent, PeerContext, PeerSocketError};
use crate::DurableInbox;

const QUERY_LIFETIME_NANOS: u64 = 10_000_000_000;

#[derive(Default)]
pub(super) struct AddressExchange {
    pending: Option<(AddressQuery, BootEpoch, u64)>,
    fresh_until: Option<(BootEpoch, u64)>,
    next_query_at: Option<u64>,
}

pub struct ReceivedAddressAdvertisement {
    context: Arc<PeerContext>,
    verified: VerifiedAddressAdvertisement,
}
impl std::fmt::Debug for ReceivedAddressAdvertisement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceivedAddressAdvertisement([redacted], current_context_required)")
    }
}

impl AssociatedPcSocket {
    /// Fixed native operation only, not exported to the renderer. The caller
    /// retains normal native readiness/admission policy around this operation.
    pub fn refresh_routing_candidates(
        &mut self,
        owner: &DurableInbox,
        clock: InboxClock,
    ) -> Result<(), PeerSocketError> {
        self.check_current(owner)?;
        if owner
            .inbox_fault()
            .map_err(PeerSocketError::Owner)?
            .is_some()
        {
            return Err(PeerSocketError::AddressContext);
        }
        if self.driver.negotiated_protocol() != Some(ControlProtocol::V2) {
            return Ok(());
        }
        let Some(correlation) = self
            .correlation
            .as_ref()
            .filter(|value| !value.is_faulted())
        else {
            return Ok(());
        };
        let epoch = correlation.epoch();
        let now = clock.phone_monotonic_nanos();
        if self
            .addresses
            .pending
            .is_some_and(|(_, previous_epoch, sent)| {
                previous_epoch != epoch
                    || now
                        .checked_sub(sent)
                        .is_some_and(|elapsed| elapsed > QUERY_LIFETIME_NANOS)
            })
        {
            self.addresses.pending = None;
        }
        if self.addresses.pending.is_some() {
            return Ok(());
        }
        // Server rate limit is independent of advertised TTL and boot epoch.
        // Keep a margin even when a new clock epoch invalidates cached freshness.
        if self
            .addresses
            .next_query_at
            .is_some_and(|deadline| now < deadline)
        {
            return Ok(());
        }
        if self
            .addresses
            .fresh_until
            .is_some_and(|(old_epoch, deadline)| old_epoch == epoch && now < deadline)
        {
            return Ok(());
        }
        let descriptor = self.context.association.descriptor();
        let Some((_, route)) = descriptor.relay() else {
            return Ok(());
        };
        // Separate fresh CSPRNG draw; the clock probe's nonce is never reused.
        let nonce = ClockProbe::start(descriptor.pc(), now)
            .map_err(PeerSocketError::Clock)?
            .nonce();
        let query = AddressQuery::new(
            descriptor.pc(),
            descriptor.recipient_device_id(),
            route,
            nonce,
        )
        .map_err(|_| PeerSocketError::AddressContext)?;
        let frame = service_protocol::encode_frame(&query.to_wire())
            .map_err(|_| PeerSocketError::AddressContext)?;
        let next_query_at = now
            .checked_add((service_protocol::ADDRESS_QUERY_MIN_INTERVAL_SECONDS + 1) * 1_000_000_000)
            .ok_or(PeerSocketError::AddressContext)?;
        self.driver
            .queue_frame(frame)
            .map_err(PeerSocketError::Socket)?;
        self.addresses.pending = Some((query, epoch, now));
        self.addresses.next_query_at = Some(next_query_at);
        Ok(())
    }

    pub(super) fn receive_addresses(
        &mut self,
        bytes: &[u8],
    ) -> Result<PcSocketEvent, PeerSocketError> {
        let result = (|| {
            if self.driver.negotiated_protocol() != Some(ControlProtocol::V2)
                || self.addresses.pending.is_none()
            {
                return Err(PeerSocketError::AddressContext);
            }
            let verified = SignedAddressAdvertisement::from_wire(bytes)
                .and_then(|message| message.verify(&self.context.verification_key))
                .map_err(|_| PeerSocketError::AddressContext)?;
            Ok(PcSocketEvent::Addresses(Box::new(
                ReceivedAddressAdvertisement {
                    context: Arc::clone(&self.context),
                    verified,
                },
            )))
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }

    pub fn apply_routing_candidates(
        &mut self,
        owner: &mut DurableInbox,
        message: ReceivedAddressAdvertisement,
        clock: InboxClock,
    ) -> Result<(), PeerSocketError> {
        let result = (|| {
            if !Arc::ptr_eq(&self.context, &message.context) {
                return Err(PeerSocketError::DifferentConnection);
            }
            self.check_current(owner)?;
            if owner
                .inbox_fault()
                .map_err(PeerSocketError::Owner)?
                .is_some()
            {
                return Err(PeerSocketError::AddressContext);
            }
            let (query, epoch, sent) = self
                .addresses
                .pending
                .take()
                .ok_or(PeerSocketError::AddressContext)?;
            let fields = message.verified.fields();
            let now = clock.phone_monotonic_nanos();
            if fields.pc != query.pc
                || fields.device != query.device
                || fields.route != query.route
                || fields.nonce != query.nonce
                || fields.epoch != epoch
                || self
                    .correlation
                    .as_ref()
                    .is_none_or(|value| value.is_faulted() || value.epoch() != epoch)
                || now
                    .checked_sub(sent)
                    .is_none_or(|elapsed| elapsed > QUERY_LIFETIME_NANOS)
            {
                return Err(PeerSocketError::AddressContext);
            }
            owner
                .record_routing_candidates(
                    self.context.association.reference(),
                    fields.endpoints.clone(),
                )
                .map_err(|error| match error {
                    crate::PeerAssociationMutationError::Owner(error) => {
                        PeerSocketError::Persistence(error)
                    }
                    _ => PeerSocketError::AddressContext,
                })?;
            // Freshness expires at the signed TTL (including immediate
            // withdrawal), independently from the minimum next-query cadence.
            // Persisted values remain untrusted coordinates across restart.
            let delay = u64::from(fields.valid_for_seconds)
                .checked_mul(1_000_000_000)
                .ok_or(PeerSocketError::AddressContext)?;
            self.addresses.fresh_until = Some((
                epoch,
                now.checked_add(delay)
                    .ok_or(PeerSocketError::AddressContext)?,
            ));
            self.addresses.next_query_at = Some(
                now.checked_add(
                    (service_protocol::ADDRESS_QUERY_MIN_INTERVAL_SECONDS + 1) * 1_000_000_000,
                )
                .ok_or(PeerSocketError::AddressContext)?,
            );
            Ok(())
        })();
        if result.is_err() {
            self.abort();
        }
        result
    }
}
