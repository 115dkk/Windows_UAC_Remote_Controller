// SPDX-License-Identifier: GPL-2.0-or-later

use std::{collections::BTreeMap, fmt, sync::Arc};

use approval_protocol::{BootEpoch, PcIdentity, RequestBinding, RequestContent};
use notification_policy::{
    AuthenticatedPcOutcome, AuthenticatedRequestMetadata, CapacityLimits, DropReason, Effect,
    LocalTime, MonotonicTime, NotificationEngine, NotificationPolicy, RequestKey, Weekday,
    WithdrawalReason,
};
use service_protocol::{
    ClockCorrelation, ClockError, MAX_CLOCK_PROBE_RTT_NANOS, MAX_REQUEST_LIFETIME_NANOS,
    MappedRequestWindow, PcEvent, RequestResolution, ServiceTick, VerifiedPcEvent,
};

use crate::{
    InboxCheck, InboxClock, InboxFault, InboxIssue, InboxUpdate, OutcomeAcknowledgment,
    OutcomeDeliveryId, PendingOutcome, PendingRequest, PhoneBootId, ReceivingGeneration,
    types::NANOS_PER_MILLI,
};

const MAX_GUARD_HORIZON_NANOS: u64 = MAX_REQUEST_LIFETIME_NANOS + MAX_CLOCK_PROBE_RTT_NANOS;

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceKey {
    pub(crate) pc: PcIdentity,
    pub(crate) epoch: BootEpoch,
}

impl SourceKey {
    fn for_binding(binding: RequestBinding) -> Self {
        Self {
            pc: binding.pc(),
            epoch: binding.epoch(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SourceState {
    // A signed source sample is evidence that this epoch reached this tick.
    // Keep the maximum after guards retire; an older correlation cannot undo it.
    pub(crate) watermark: u64,
    pub(crate) quarantine_expiry: Option<u64>,
}

pub(crate) struct RetainedRequest {
    pub(crate) binding: RequestBinding,
    pub(crate) issued_at: ServiceTick,
    // Captured only on first guard insertion, including discarded/body-free
    // requests. Never inferred, upgraded or replaced on retry/recovery.
    pub(crate) receiving_generation: Option<ReceivingGeneration>,
    pub(crate) window: Option<MappedRequestWindow>,
    pub(crate) metadata: Option<AuthenticatedRequestMetadata>,
    // Original RECEIVE-anchor upper expiry, never recalculated by a new probe.
    pub(crate) guard_until_nanos: u64,
    // Some means a body-ready active request. Recovery can also retain active
    // metadata without a body; closed/suppressed guards can never regain one.
    pub(crate) content: Option<Arc<RequestContent>>,
    // A restored active ID is not a closed ID, but has no usable body until an
    // exact newly verified PC event arrives in the current enrolled session.
    pub(crate) recovering: bool,
    // Only a recovery lease; it never extends normal request display lifetime.
    pub(crate) recovery_until_nanos: Option<u64>,
}

#[derive(Clone, Copy)]
enum EventKind<'a> {
    Opened(&'a Arc<RequestContent>),
    Resolved(RequestResolution),
}

/// One process-local owner of notification policy, lifecycle and original maps.
///
/// Callers must supply signature-verified events from the CURRENT enrolled PC
/// key/session mapping, a matching native clock correlation and coherent fresh
/// native phone time. Construction proves neither enrollment nor secure lock.
/// Screen-lock, notification-permission and native authentication requirements
/// remain upstream; this crate has no OS, signing, files, network or UI API.
///
/// Original body-free guards outlive the engine's local expiry estimate. Both
/// the original phone upper estimate and a signed source sample at/after the
/// original service expiry are required for retirement. Source watermarks remain
/// after retirement so an older correlation cannot resurrect the request.
/// Guards and source slots each have the configured max-retained bound. A full
/// guard cache quarantines new identities; source-capacity exhaustion faults.
///
/// The legacy constructor is process-local. Boot-bound checkpoints restore only
/// metadata; the receiving owner must use durable commit-before-effects storage
/// and reconcile OS notifications. Fresh TLS/probe alone is not replay state.
pub struct PhoneInbox {
    pub(crate) policy: NotificationPolicy,
    pub(crate) limits: CapacityLimits,
    pub(crate) engine: Option<NotificationEngine>,
    pub(crate) retained: BTreeMap<RequestKey, RetainedRequest>,
    pub(crate) sources: BTreeMap<SourceKey, SourceState>,
    pub(crate) guard_quarantine_until_nanos: Option<u64>,
    pub(crate) last_phone_nanos: Option<u64>,
    pub(crate) last_local: Option<LocalTime>,
    pub(crate) phone_boot: Option<PhoneBootId>,
    pub(crate) fault: Option<InboxFault>,
    pub(crate) pending_outcomes: Vec<PendingOutcome>,
    // Independent irreversible integrity latch: another domain fault must not
    // accidentally make a candidate missing an outcome encodable again.
    pub(crate) outcome_retention_failed: bool,
}

impl fmt::Debug for PhoneInbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PhoneInbox")
            .field("active_count", &self.active_count())
            .field("retained_count", &self.retained.len())
            .field("source_count", &self.sources.len())
            .field("pending_outcome_count", &self.pending_outcomes.len())
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl PhoneInbox {
    pub fn new(policy: NotificationPolicy, limits: CapacityLimits) -> Self {
        Self {
            engine: Some(NotificationEngine::new(policy.clone(), limits)),
            policy,
            limits,
            retained: BTreeMap::new(),
            sources: BTreeMap::new(),
            guard_quarantine_until_nanos: None,
            last_phone_nanos: None,
            last_local: None,
            phone_boot: None,
            fault: None,
            pending_outcomes: Vec::new(),
            outcome_retention_failed: false,
        }
    }

    /// Bind an OS-observed boot count. This creates no file or durable state.
    pub fn with_phone_boot(
        policy: NotificationPolicy,
        limits: CapacityLimits,
        boot: PhoneBootId,
    ) -> Self {
        Self {
            phone_boot: Some(boot),
            ..Self::new(policy, limits)
        }
    }

    pub fn policy(&self) -> &NotificationPolicy {
        &self.policy
    }
    pub const fn limits(&self) -> CapacityLimits {
        self.limits
    }
    pub const fn fault(&self) -> Option<InboxFault> {
        self.fault
    }

    /// Sole source for outcome delivery. In this core these are in-memory rows,
    /// not commit receipts; a native journal must use DurableInbox and insert
    /// idempotently by delivery_id before acknowledging the row.
    pub fn pending_outcomes(&self) -> &[PendingOutcome] {
        &self.pending_outcomes
    }

    /// In-memory acknowledgment only; the durable owner must commit this change
    /// before treating the row as removed. Unknown/repeated IDs are NotPending,
    /// not proof of any journal/OS delivery. No notification state is revived.
    pub fn acknowledge_outcome(&mut self, id: OutcomeDeliveryId) -> OutcomeAcknowledgment {
        if let Some(index) = self
            .pending_outcomes
            .iter()
            .position(|row| row.delivery_id() == id)
        {
            self.pending_outcomes.remove(index);
            OutcomeAcknowledgment::Removed
        } else {
            OutcomeAcknowledgment::NotPending
        }
    }

    fn reserved_outcome_slots(&self) -> usize {
        self.retained
            .values()
            .filter(|entry| entry.content.is_some() || entry.recovering)
            .count()
    }

    fn outcome_slot_available(&self) -> bool {
        self.pending_outcomes
            .len()
            .checked_add(self.reserved_outcome_slots())
            .is_some_and(|used| used < self.limits.max_retained())
    }

    /// Downward-only owner failure transition. It releases bodies and withdraws
    /// recovering requests without inventing PC outcomes or resetting authority.
    pub fn stop_for_owner_failure(&mut self) -> InboxUpdate {
        let mut update = InboxUpdate {
            effects: Vec::new(),
            issue: None,
            fault: self.fault,
        };
        self.latch_fault(InboxFault::ReceivingOwnerStopped, &mut update);
        self.finish(update)
    }

    /// Diagnostic count only; obtaining body/metadata requires check_pending.
    pub fn active_count(&self) -> usize {
        self.retained
            .values()
            .filter(|entry| entry.content.is_some())
            .count()
    }

    /// Includes body-free guards retained after the engine's lower expiry.
    pub fn retained_count(&self) -> usize {
        self.retained.len()
    }

    pub fn retained_body_count(&self) -> usize {
        self.active_count()
    }

    /// Metadata-only active requests waiting for reverified bodies; not views.
    pub fn recovering_count(&self) -> usize {
        self.retained
            .values()
            .filter(|entry| entry.recovering)
            .count()
    }

    /// Source/epoch slots are not evicted when their individual guards retire.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// May remain true with no future phone-time wakeup while source proof is missing.
    pub fn is_quarantined(&self) -> bool {
        self.guard_quarantine_until_nanos.is_some()
            || self
                .engine
                .as_ref()
                .is_some_and(|engine| engine.quarantine_until().is_some())
    }

    /// Future phone-time scheduling hint, not permission to accept traffic.
    /// None does not mean quarantine ended: it may be waiting for source proof.
    pub fn quarantine_until_nanos(&self) -> Option<u64> {
        if self.fault.is_some() {
            return None;
        }
        let engine_deadline = self
            .engine
            .as_ref()
            .and_then(NotificationEngine::quarantine_until)
            .and_then(|time| time.as_millis().checked_mul(NANOS_PER_MILLI));
        self.guard_quarantine_until_nanos
            .max(engine_deadline)
            .filter(|until| self.last_phone_nanos.is_none_or(|now| *until > now))
    }

    /// Next actionable local deadline. Never spin on a past phone upper estimate
    /// while waiting for signed source proof. Also wake on policy/timezone changes.
    pub fn next_deadline_nanos(&self) -> Option<u64> {
        if self.fault.is_some() {
            return None;
        }
        let active = self
            .engine
            .as_ref()
            .and_then(NotificationEngine::next_deadline)
            .and_then(|time| time.as_millis().checked_mul(NANOS_PER_MILLI));
        let retired = self
            .retained
            .values()
            .filter(|entry| self.source_expired(entry.binding))
            .map(|entry| entry.guard_until_nanos)
            .filter(|until| self.last_phone_nanos.is_none_or(|now| *until > now))
            .min();
        let quarantine = self
            .guard_quarantine_until_nanos
            .filter(|_| self.quarantine_sources_expired())
            .filter(|until| self.last_phone_nanos.is_none_or(|now| *until > now));
        let recovery = self
            .retained
            .values()
            .filter(|entry| entry.recovering)
            .filter_map(|entry| entry.recovery_until_nanos)
            .filter(|until| self.last_phone_nanos.is_none_or(|now| *until > now))
            .min();
        [active, retired, quarantine, recovery]
            .into_iter()
            .flatten()
            .min()
    }

    /// Observe a signature-correlated service clock without inventing an app event.
    /// The native owner supplies its CURRENT enrolled PC/key/epoch relationship.
    /// Old valid samples never lower the watermark; elapsed phone time alone is
    /// not source-expiry proof. This is not durable restart/revocation state.
    pub fn observe_service_clock(
        &mut self,
        correlation: &ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        let mut update = self.begin(clock);
        if self.fault.is_none() {
            self.observe_source(correlation, clock, &mut update);
        }
        self.finish(update)
    }

    pub fn receive_opened(
        &mut self,
        event: &VerifiedPcEvent,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        if !matches!(event.event(), PcEvent::Opened { .. }) {
            return self.rejected(InboxIssue::WrongEventKind);
        }
        self.process(event, None, correlation, clock)
    }

    /// Receive from a trusted native association context. The number itself is
    /// not authentication; callers must verify current peer/key ownership first.
    pub fn receive_opened_from(
        &mut self,
        event: &VerifiedPcEvent,
        generation: ReceivingGeneration,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        if !matches!(event.event(), PcEvent::Opened { .. }) {
            return self.rejected(InboxIssue::WrongEventKind);
        }
        self.process(event, Some(generation), correlation, clock)
    }

    pub fn resolve_pc(
        &mut self,
        event: &VerifiedPcEvent,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        if !matches!(event.event(), PcEvent::Resolved { .. }) {
            return self.rejected(InboxIssue::WrongEventKind);
        }
        self.process(event, None, correlation, clock)
    }

    pub fn resolve_pc_from(
        &mut self,
        event: &VerifiedPcEvent,
        generation: ReceivingGeneration,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        if !matches!(event.event(), PcEvent::Resolved { .. }) {
            return self.rejected(InboxIssue::WrongEventKind);
        }
        self.process(event, Some(generation), correlation, clock)
    }

    /// Read-only pre-intent relational gate for the durable owner. Binding and
    /// original issuance take precedence, then the exact original Option source
    /// must match: None is never upgraded to Some, nor Some downgraded/reassigned.
    /// This is not a policy/freshness/authentication permit. Terminal outbox-only
    /// rows retain no source field; their binding/issuance are checked here and
    /// the ordinary process path still drops them without making them active.
    pub fn check_receiving_source(
        &self,
        event: &VerifiedPcEvent,
        receiving_generation: Option<ReceivingGeneration>,
    ) -> Result<(), InboxIssue> {
        let (binding, issued_at) = match event.event() {
            PcEvent::Opened {
                binding, issued_at, ..
            }
            | PcEvent::Resolved {
                binding, issued_at, ..
            } => (*binding, *issued_at),
            PcEvent::Clock { .. } => return Err(InboxIssue::WrongEventKind),
        };
        let key = request_key(binding);
        if let Some(original) = self.retained.get(&key) {
            if original.binding != binding {
                return Err(InboxIssue::ConflictingBinding);
            }
            if original.issued_at != issued_at {
                return Err(InboxIssue::ConflictingIssuedAt);
            }
            if original.receiving_generation != receiving_generation {
                return Err(InboxIssue::ConflictingReceivingSource);
            }
        }
        if let Some(pending) = self.pending_outcomes.iter().find(|row| row.key() == key) {
            if pending.binding() != binding {
                return Err(InboxIssue::ConflictingBinding);
            }
            if pending.issued_at() != issued_at {
                return Err(InboxIssue::ConflictingIssuedAt);
            }
        }
        Ok(())
    }

    pub fn poll(&mut self, clock: InboxClock) -> InboxUpdate {
        let update = self.begin(clock);
        self.finish(update)
    }

    pub fn update_policy(&mut self, policy: NotificationPolicy, clock: InboxClock) -> InboxUpdate {
        let mut update = self.begin(clock);
        if self.fault.is_some() {
            return self.finish(update);
        }
        let Some(engine) = &mut self.engine else {
            self.latch_fault(InboxFault::InconsistentState, &mut update);
            return self.finish(update);
        };
        let effects = engine.update_policy(policy.clone(), clock.reading);
        self.policy = policy;
        self.apply_effects(effects, &mut update);
        for entry in self
            .retained
            .values_mut()
            .filter(|entry| entry.content.is_some() || entry.recovering)
        {
            if let Some(window) = entry.window {
                let lease = recovery_lease(&self.policy, clock, window.phone_expiry_nanos());
                entry.recovery_until_nanos = Some(
                    entry
                        .recovery_until_nanos
                        .map_or(lease, |old| old.min(lease)),
                );
            }
        }
        self.finish(update)
    }

    /// A body-bearing view is returned only after current policy/expiry checks.
    /// Caller-held Arc views are stale snapshots after any later transition.
    pub fn check_pending(&mut self, key: RequestKey, clock: InboxClock) -> InboxCheck {
        let mut update = self.begin(clock);
        if self.fault.is_some() {
            return InboxCheck {
                update: self.finish(update),
                request: None,
            };
        }
        let Some(engine) = &mut self.engine else {
            self.latch_fault(InboxFault::InconsistentState, &mut update);
            return InboxCheck {
                update: self.finish(update),
                request: None,
            };
        };
        let checked = engine.check_pending(key, clock.reading);
        self.apply_effects(checked.effects, &mut update);
        let request = match checked.pending {
            None => None,
            Some(notification) => match self.retained.get(&key) {
                Some(RetainedRequest {
                    window: Some(window),
                    content: Some(content),
                    receiving_generation,
                    ..
                }) => Some(PendingRequest {
                    window: *window,
                    notification,
                    content: Arc::clone(content),
                    receiving_generation: *receiving_generation,
                }),
                Some(record) if record.recovering => None,
                _ => {
                    // Never return a phantom engine-only request or fabricate a body.
                    self.latch_fault(InboxFault::InconsistentState, &mut update);
                    None
                }
            },
        };
        let update = self.finish(update);
        InboxCheck {
            request: if update.fault.is_some() {
                None
            } else {
                request
            },
            update,
        }
    }

    fn process(
        &mut self,
        event: &VerifiedPcEvent,
        receiving_generation: Option<ReceivingGeneration>,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> InboxUpdate {
        let (binding, issued_at, kind) = match event.event() {
            PcEvent::Opened {
                binding,
                issued_at,
                content,
            } => (*binding, *issued_at, EventKind::Opened(content)),
            PcEvent::Resolved {
                binding,
                issued_at,
                outcome,
            } => (*binding, *issued_at, EventKind::Resolved(*outcome)),
            PcEvent::Clock { .. } => return self.rejected(InboxIssue::WrongEventKind),
        };
        // Before begin/poll/observe_source: even a newer valid PC clock must not
        // let an event from another generation age or rebind this original guard.
        if let Err(issue) = self.check_receiving_source(event, receiving_generation) {
            return self.rejected(issue);
        }
        if binding.pc() != correlation.pc() {
            return self.rejected(InboxIssue::WrongPc);
        }
        if binding.epoch() != correlation.epoch() {
            return self.rejected(InboxIssue::WrongEpoch);
        }
        let key = request_key(binding);
        let mut update = self.begin(clock);
        if self.fault.is_some() {
            return self.finish(update);
        }
        if !self.observe_source(correlation, clock, &mut update) {
            return self.finish(update);
        }

        // A terminal outcome may outlive its retired replay guard. Never admit
        // another active binding under that still-pending delivery identity.
        if let Some(pending) = self.pending_outcomes.iter().find(|row| row.key() == key) {
            if pending.binding() != binding {
                update.issue = Some(InboxIssue::ConflictingBinding);
            } else if pending.issued_at() != issued_at {
                update.issue = Some(InboxIssue::ConflictingIssuedAt);
            } else {
                update.effects.push(Effect::Drop {
                    key,
                    // Preserve the original guard's local expiry classification;
                    // a newer correlation never supplies a replacement deadline.
                    reason: if self.source_expired(binding)
                        || self
                            .retained
                            .get(&key)
                            .and_then(|entry| entry.metadata)
                            .is_some_and(|metadata| {
                                metadata.expires_at() <= clock.reading.monotonic
                            }) {
                        DropReason::Expired
                    } else {
                        DropReason::PreviouslySuppressed
                    },
                });
            }
            return self.finish(update);
        }

        if let Some(existing) = self.retained.get(&key) {
            if existing.binding != binding {
                update.issue = Some(InboxIssue::ConflictingBinding);
                return self.finish(update);
            }
            if existing.issued_at != issued_at {
                update.issue = Some(InboxIssue::ConflictingIssuedAt);
                return self.finish(update);
            }
            if self.source_expired(binding) {
                update.effects.push(Effect::Drop {
                    key,
                    reason: DropReason::Expired,
                });
                return self.finish(update);
            }
            let metadata = existing.metadata;
            let active = existing.content.is_some() || existing.recovering;
            if !active {
                let reason = if metadata
                    .is_some_and(|value| value.expires_at() <= clock.reading.monotonic)
                {
                    DropReason::Expired
                } else {
                    DropReason::PreviouslySuppressed
                };
                update.effects.push(Effect::Drop { key, reason });
                return self.finish(update);
            }
            let Some(metadata) = metadata else {
                self.latch_fault(InboxFault::InconsistentState, &mut update);
                return self.finish(update);
            };
            if existing.recovering
                && let EventKind::Opened(content) = kind
            {
                let Some(engine) = &mut self.engine else {
                    self.latch_fault(InboxFault::InconsistentState, &mut update);
                    return self.finish(update);
                };
                let checked = engine.check_pending(key, clock.reading);
                self.apply_effects(checked.effects, &mut update);
                if let Some(pending) = checked.pending {
                    if let Some(record) = self.retained.get_mut(&key) {
                        // Preflight matched the immutable original source. Only
                        // the body/recovery state changes; its source stays put.
                        record.recovering = false;
                        record.content = Some(Arc::clone(content));
                    }
                    update.effects.push(Effect::Restore(pending));
                }
                return self.finish(update);
            }
            // Never re-map or replace an original cached lifetime on duplicates
            // or resolution. An already expired cached request was retired by
            // begin/poll above, without requiring a new live clock mapping.
            let effects = self.engine_transition(kind, metadata, clock);
            self.apply_effects(effects, &mut update);
            return self.finish(update);
        }

        // Retired IDs need no individual entry once their source watermark has
        // passed expiry. An old correlation must not make them live again.
        if self.source_expired(binding) {
            update.effects.push(Effect::Drop {
                key,
                reason: DropReason::Expired,
            });
            return self.finish(update);
        }
        let source = SourceKey::for_binding(binding);
        let service_expiry = binding.expiry().as_nanos_since_epoch();

        let guard_until_nanos = match upper_guard(correlation, binding, clock.nanos) {
            Ok(guard) => guard,
            Err(fault) => {
                self.latch_fault(fault, &mut update);
                return self.finish(update);
            }
        };
        let window = match correlation.map_request(event, clock.nanos) {
            Ok(window) => window,
            Err(ClockError::LocalClockRegressed) => {
                self.latch_fault(InboxFault::NativeClockRegressed, &mut update);
                return self.finish(update);
            }
            Err(ClockError::CorrelationFaulted) => {
                self.latch_fault(InboxFault::ClockCorrelationFaulted, &mut update);
                return self.finish(update);
            }
            Err(ClockError::ArithmeticOverflow) => {
                self.latch_fault(InboxFault::ClockRangeExceeded, &mut update);
                return self.finish(update);
            }
            Err(error) => {
                // A phone-time mapping failure is not source-expiry proof.
                // Keep a body-free guard even when its phone upper estimate
                // already passed; a newer probe must not revive this discard.
                if let Some(issue) = self.guard_admission(source, service_expiry, guard_until_nanos)
                {
                    push_guard_drop(key, issue, &mut update);
                    return self.finish(update);
                }
                self.retained.insert(
                    key,
                    RetainedRequest {
                        binding,
                        issued_at,
                        receiving_generation,
                        window: None,
                        metadata: None,
                        guard_until_nanos,
                        content: None,
                        recovering: false,
                        recovery_until_nanos: None,
                    },
                );
                let reason = if error == ClockError::RequestExpired {
                    DropReason::Expired
                } else {
                    update.issue = Some(InboxIssue::Clock(error));
                    DropReason::InvalidRequestTime
                };
                update.effects.push(Effect::Drop { key, reason });
                return self.finish(update);
            }
        };
        if let Some(issue) = self.guard_admission(source, service_expiry, guard_until_nanos) {
            push_guard_drop(key, issue, &mut update);
            return self.finish(update);
        }

        let issued_millis = window.phone_issued_nanos() / NANOS_PER_MILLI;
        let expiry_millis = window.phone_expiry_nanos() / NANOS_PER_MILLI;
        let metadata = if expiry_millis > issued_millis {
            match AuthenticatedRequestMetadata::new(
                key,
                MonotonicTime::from_millis(issued_millis),
                MonotonicTime::from_millis(expiry_millis),
            ) {
                Ok(metadata) => Some(metadata),
                Err(_) => {
                    self.latch_fault(InboxFault::InconsistentState, &mut update);
                    return self.finish(update);
                }
            }
        } else {
            None
        };
        let outcome_capacity = matches!(kind, EventKind::Opened(_))
            && self.policy.allows(clock.reading.local)
            && metadata.is_some_and(|metadata| metadata.expires_at() > clock.reading.monotonic)
            && !self.outcome_slot_available();
        let effects = if outcome_capacity {
            // Keep the original bounded non-body guard below. An ACK may free
            // capacity for a NEW request, never resurrect this suppressed one.
            update.issue = Some(InboxIssue::OutcomeCapacity);
            vec![Effect::Drop {
                key,
                reason: DropReason::ActiveCapacity,
            }]
        } else {
            match metadata {
                Some(metadata) if metadata.expires_at() > clock.reading.monotonic => {
                    self.engine_transition(kind, metadata, clock)
                }
                _ => vec![Effect::Drop {
                    key,
                    reason: DropReason::Expired,
                }],
            }
        };
        let active = effects
            .iter()
            .any(|effect| matches!(effect, Effect::Show(pending) if pending.key == key));
        let content = match (active, kind) {
            (true, EventKind::Opened(content)) => Some(Arc::clone(content)),
            _ => None,
        };
        if effects.iter().any(|effect| {
            matches!(
                effect,
                Effect::Drop {
                    reason: DropReason::RetainedCapacity | DropReason::CapacityQuarantine,
                    ..
                }
            )
        }) {
            self.extend_quarantine(source, service_expiry, guard_until_nanos);
        }
        self.retained.insert(
            key,
            RetainedRequest {
                binding,
                issued_at,
                receiving_generation,
                window: Some(window),
                metadata,
                guard_until_nanos,
                content,
                recovering: false,
                recovery_until_nanos: active
                    .then(|| recovery_lease(&self.policy, clock, window.phone_expiry_nanos())),
            },
        );
        self.apply_effects(effects, &mut update);
        self.finish(update)
    }

    fn engine_transition(
        &mut self,
        kind: EventKind<'_>,
        metadata: AuthenticatedRequestMetadata,
        clock: InboxClock,
    ) -> Vec<Effect> {
        let Some(engine) = &mut self.engine else {
            return Vec::new();
        };
        match kind {
            EventKind::Opened(_) => engine.receive(metadata, clock.reading),
            EventKind::Resolved(outcome) => engine.resolve_from_pc(
                metadata,
                match outcome {
                    RequestResolution::Cancelled => AuthenticatedPcOutcome::Cancelled,
                    RequestResolution::Expired => AuthenticatedPcOutcome::Expired,
                    // Completed means terminal PC outcome, NOT successful approval.
                    RequestResolution::Approved
                    | RequestResolution::Denied
                    | RequestResolution::Failed => AuthenticatedPcOutcome::Completed,
                },
                clock.reading,
            ),
        }
    }

    pub(crate) fn begin(&mut self, clock: InboxClock) -> InboxUpdate {
        if let Some(fault) = self.fault {
            return self.rejected(InboxIssue::Faulted(fault));
        }
        let mut update = InboxUpdate {
            effects: Vec::new(),
            issue: None,
            fault: None,
        };
        if self.last_phone_nanos.is_some_and(|last| clock.nanos < last) {
            self.latch_fault(InboxFault::NativeClockRegressed, &mut update);
            return update;
        }
        if let (Some(previous), Some(local)) = (self.last_phone_nanos, self.last_local)
            && !matches!(
                self.policy.schedule(),
                notification_policy::Schedule::Always
            )
            && !recovery_clock_continuous(previous, local, clock)
        {
            // Preserve the current runtime's ordinary policy behavior, but no
            // previously active ID may later claim uninterrupted visibility.
            for entry in self
                .retained
                .values_mut()
                .filter(|entry| entry.content.is_some() || entry.recovering)
            {
                if let Some(until) = entry.recovery_until_nanos {
                    entry.recovery_until_nanos = Some(until.min(clock.nanos));
                }
            }
        }
        self.last_phone_nanos = Some(clock.nanos);
        self.last_local = Some(clock.reading.local);
        let Some(engine) = &mut self.engine else {
            self.latch_fault(InboxFault::InconsistentState, &mut update);
            return update;
        };
        let effects = engine.poll(clock.reading);
        self.apply_effects(effects, &mut update);
        self.reject_expired_recovery(clock, &mut update);
        if self.fault.is_some() {
            return update;
        }
        self.retire_guards(clock, &mut update);
        update
    }

    fn observe_source(
        &mut self,
        correlation: &ClockCorrelation,
        clock: InboxClock,
        update: &mut InboxUpdate,
    ) -> bool {
        if correlation.is_faulted() {
            self.latch_fault(InboxFault::ClockCorrelationFaulted, update);
            return false;
        }
        if clock.nanos < correlation.phone_probe_received_nanos() {
            self.latch_fault(InboxFault::NativeClockRegressed, update);
            return false;
        }
        let source = SourceKey {
            pc: correlation.pc(),
            epoch: correlation.epoch(),
        };
        let sample = correlation.service_sample().as_nanos_since_epoch();
        if let Some(state) = self.sources.get_mut(&source) {
            state.watermark = state.watermark.max(sample);
        } else {
            if self.sources.len() >= self.limits.max_retained() {
                self.latch_fault(InboxFault::SourceCapacityReached, update);
                return false;
            }
            self.sources.insert(
                source,
                SourceState {
                    watermark: sample,
                    quarantine_expiry: None,
                },
            );
        }

        // Confirmed PC time can expire an active request before its local clock
        // estimate. Send the real typed PC-expiry transition, never a fake clock.
        let expired: Vec<_> = self
            .retained
            .values()
            .filter(|entry| {
                (entry.content.is_some() || entry.recovering) && self.source_expired(entry.binding)
            })
            .map(|entry| entry.metadata)
            .collect();
        for metadata in expired {
            let Some(metadata) = metadata else {
                self.latch_fault(InboxFault::InconsistentState, update);
                return false;
            };
            let Some(engine) = &mut self.engine else {
                self.latch_fault(InboxFault::InconsistentState, update);
                return false;
            };
            let effects =
                engine.resolve_from_pc(metadata, AuthenticatedPcOutcome::Expired, clock.reading);
            self.apply_effects(effects, update);
            if self.fault.is_some() {
                return false;
            }
        }
        self.retire_guards(clock, update);
        self.fault.is_none()
    }

    fn source_expired(&self, binding: RequestBinding) -> bool {
        self.sources
            .get(&SourceKey::for_binding(binding))
            .is_some_and(|source| source.watermark >= binding.expiry().as_nanos_since_epoch())
    }

    fn quarantine_sources_expired(&self) -> bool {
        self.sources.values().all(|source| {
            source
                .quarantine_expiry
                .is_none_or(|expiry| source.watermark >= expiry)
        })
    }

    fn retire_guards(&mut self, clock: InboxClock, update: &mut InboxUpdate) {
        if self.retained.values().any(|entry| {
            entry.guard_until_nanos <= clock.nanos && (entry.content.is_some() || entry.recovering)
        }) {
            self.latch_fault(InboxFault::InconsistentState, update);
            return;
        }
        let sources = &self.sources;
        self.retained.retain(|_, entry| {
            entry.guard_until_nanos > clock.nanos
                || !sources
                    .get(&SourceKey::for_binding(entry.binding))
                    .is_some_and(|source| {
                        source.watermark >= entry.binding.expiry().as_nanos_since_epoch()
                    })
        });
        if self
            .guard_quarantine_until_nanos
            .is_some_and(|until| until <= clock.nanos)
            && self.quarantine_sources_expired()
        {
            self.guard_quarantine_until_nanos = None;
            for source in self.sources.values_mut() {
                source.quarantine_expiry = None;
            }
        }
    }

    fn guard_admission(
        &mut self,
        source: SourceKey,
        service_expiry: u64,
        guard_until_nanos: u64,
    ) -> Option<InboxIssue> {
        if self.guard_quarantine_until_nanos.is_some() {
            self.extend_quarantine(source, service_expiry, guard_until_nanos);
            return Some(InboxIssue::GuardQuarantine);
        }
        if self.retained.len() >= self.limits.max_retained() {
            self.extend_quarantine(source, service_expiry, guard_until_nanos);
            return Some(InboxIssue::GuardCapacity);
        }
        None
    }

    fn extend_quarantine(&mut self, source: SourceKey, service_expiry: u64, until: u64) {
        self.guard_quarantine_until_nanos = Some(
            self.guard_quarantine_until_nanos
                .map_or(until, |old| old.max(until)),
        );
        if let Some(state) = self.sources.get_mut(&source) {
            state.quarantine_expiry = Some(
                state
                    .quarantine_expiry
                    .map_or(service_expiry, |old| old.max(service_expiry)),
            );
        }
    }

    fn apply_effects(&mut self, effects: Vec<Effect>, update: &mut InboxUpdate) {
        // Capture original binding/issuance before Withdraw clears activity and
        // before begin/observe_source can retire any guard. The ordinary effect
        // remains only a wake/compatibility hint, not the delivery source.
        if !self.retain_outcomes(&effects) {
            self.outcome_retention_failed = true;
            self.latch_fault(InboxFault::OutcomeRetentionFailed, update);
            update
                .effects
                .retain(|effect| matches!(effect, Effect::Withdraw { .. } | Effect::Drop { .. }));
            update.effects.extend(
                effects.into_iter().filter(|effect| {
                    matches!(effect, Effect::Withdraw { .. } | Effect::Drop { .. })
                }),
            );
            update.fault = self.fault;
            return;
        }
        for effect in &effects {
            match effect {
                Effect::Withdraw { key, .. } => {
                    if let Some(record) = self.retained.get_mut(key) {
                        record.content = None;
                        record.recovering = false;
                        record.recovery_until_nanos = None;
                    }
                }
                Effect::Fault(fault) => {
                    self.fault = Some(InboxFault::NotificationEngine(*fault));
                    for record in self.retained.values_mut() {
                        record.content = None;
                        record.recovering = false;
                        record.recovery_until_nanos = None;
                    }
                }
                _ => (),
            }
        }
        update.effects.extend(effects);
        update.fault = self.fault;
        if let Some(fault) = self.fault {
            update.issue = Some(InboxIssue::Faulted(fault));
        }
    }

    fn retain_outcomes(&mut self, effects: &[Effect]) -> bool {
        let mut additions: Vec<PendingOutcome> = Vec::new();
        for effect in effects {
            let Effect::RecordOutcome { key, outcome } = *effect else {
                continue;
            };
            let Some(original) = self.retained.get(&key) else {
                return false;
            };
            let candidate = PendingOutcome::new(original.binding, original.issued_at, outcome);
            if !candidate.valid() {
                return false;
            }
            if let Some(existing) = self
                .pending_outcomes
                .iter()
                .chain(additions.iter())
                .find(|row| row.key() == key || row.delivery_id() == candidate.delivery_id())
            {
                if *existing != candidate {
                    return false;
                }
                continue;
            }
            if self
                .pending_outcomes
                .len()
                .checked_add(additions.len())
                .is_none_or(|used| used >= self.limits.max_retained())
                || additions.try_reserve_exact(1).is_err()
            {
                return false;
            }
            additions.push(candidate);
        }
        if self
            .pending_outcomes
            .try_reserve_exact(additions.len())
            .is_err()
        {
            return false;
        }
        self.pending_outcomes.extend(additions);
        true
    }

    fn latch_fault(&mut self, fault: InboxFault, update: &mut InboxUpdate) {
        if self.fault.is_some() {
            return;
        }
        self.fault = Some(fault);
        // Dispose of the invalid engine instead of manufacturing an OS clock
        // reading to force its private fault latch. The inbox is permanently
        // closed; retained guards remain bounded, body-free and unadmissible.
        self.engine = None;
        for (key, record) in &mut self.retained {
            if record.content.take().is_some() || record.recovering {
                update.effects.push(Effect::Withdraw {
                    key: *key,
                    reason: WithdrawalReason::EngineFault,
                });
            }
            record.recovering = false;
            record.recovery_until_nanos = None;
        }
        update.issue = Some(InboxIssue::Faulted(fault));
        update.fault = Some(fault);
    }

    pub(crate) fn finish(&mut self, mut update: InboxUpdate) -> InboxUpdate {
        if self
            .pending_outcomes
            .len()
            .checked_add(self.reserved_outcome_slots())
            .is_none_or(|used| used > self.limits.max_retained())
        {
            self.outcome_retention_failed = true;
            self.latch_fault(InboxFault::OutcomeRetentionFailed, &mut update);
        }
        if self.fault.is_none() {
            let consistent = self.engine.as_ref().is_some_and(|engine| {
                engine.active_count() == self.active_count() + self.recovering_count()
                    && engine.retained_count() <= self.retained.len()
                    && self.retained.len() <= self.limits.max_retained()
                    && self.active_count() + self.recovering_count() <= self.limits.max_active()
                    && self.sources.len() <= self.limits.max_retained()
                    && self.retained.values().all(|entry| {
                        self.sources
                            .contains_key(&SourceKey::for_binding(entry.binding))
                    })
                    && (self.guard_quarantine_until_nanos.is_none()
                        || self
                            .sources
                            .values()
                            .any(|source| source.quarantine_expiry.is_some()))
            });
            if !consistent {
                self.latch_fault(InboxFault::InconsistentState, &mut update);
            }
        }
        update.fault = self.fault;
        if self.outcome_retention_failed {
            update
                .effects
                .retain(|effect| matches!(effect, Effect::Withdraw { .. } | Effect::Drop { .. }));
        }
        update
    }

    fn rejected(&self, issue: InboxIssue) -> InboxUpdate {
        InboxUpdate {
            effects: Vec::new(),
            issue: Some(issue),
            fault: self.fault,
        }
    }

    fn reject_expired_recovery(&mut self, clock: InboxClock, update: &mut InboxUpdate) {
        let expired: Vec<_> = self
            .retained
            .iter()
            .filter_map(|(key, entry)| {
                (entry.recovering
                    && entry
                        .recovery_until_nanos
                        .is_none_or(|until| until <= clock.nanos))
                .then_some(*key)
            })
            .collect();
        for key in expired {
            if let Some(engine) = &mut self.engine {
                let effects = engine.suppress_for_recovery(key, clock.reading);
                self.apply_effects(effects, update);
            }
        }
    }
}

fn recovery_lease(policy: &NotificationPolicy, clock: InboxClock, expiry: u64) -> u64 {
    const MINUTE_NANOS: u64 = 60_000_000_000;
    const DAYS: [Weekday; 7] = [
        Weekday::Monday,
        Weekday::Tuesday,
        Weekday::Wednesday,
        Weekday::Thursday,
        Weekday::Friday,
        Weekday::Saturday,
        Weekday::Sunday,
    ];
    let local = clock.reading.local;
    let index = u64::from(local.weekday() as u8) * 1440 + u64::from(local.minute());
    // Minute-only observations have an unknown sub-minute offset. Subtract one
    // minute conservatively; this limits old recovery, never new admission.
    for distance in 1..=3 {
        let next = (index + distance) % (7 * 1440);
        let next_local = LocalTime::new(DAYS[(next / 1440) as usize], (next % 1440) as u16)
            .expect("bounded minute arithmetic");
        if !policy.allows(next_local) {
            return expiry.min(clock.nanos.saturating_add((distance - 1) * MINUTE_NANOS));
        }
    }
    expiry
}

fn recovery_clock_continuous(previous_nanos: u64, previous: LocalTime, clock: InboxClock) -> bool {
    const WEEK: u64 = 7 * 1440;
    const MINUTE_NANOS: u64 = 60_000_000_000;
    let Some(elapsed) = clock.nanos.checked_sub(previous_nanos) else {
        return false;
    };
    let index =
        |local: LocalTime| u64::from(local.weekday() as u8) * 1440 + u64::from(local.minute());
    let actual = (index(clock.reading.local) + WEEK - index(previous)) % WEEK;
    // With minute-only civil observations, a continuous interval spans floor
    // or ceil minutes. This detects clear jumps, not unobserved clock history.
    let lower = (elapsed / MINUTE_NANOS) % WEEK;
    actual == lower || actual == (lower + 1) % WEEK
}

/// Preserve all 256-bit PC/epoch/request identity components without truncation.
pub const fn request_key(binding: RequestBinding) -> RequestKey {
    RequestKey::new(
        *binding.pc().as_bytes(),
        *binding.epoch().as_bytes(),
        *binding.request_id().as_bytes(),
    )
}

fn upper_guard(
    correlation: &ClockCorrelation,
    binding: RequestBinding,
    now: u64,
) -> Result<u64, InboxFault> {
    let sample = correlation.service_sample().as_nanos_since_epoch();
    let expiry = binding.expiry().as_nanos_since_epoch();
    let received = correlation.phone_probe_received_nanos();
    let upper = if expiry >= sample {
        received
            .checked_add(expiry - sample)
            .ok_or(InboxFault::ClockRangeExceeded)?
    } else {
        received.saturating_sub(sample - expiry)
    };
    if upper.saturating_sub(now) > MAX_GUARD_HORIZON_NANOS {
        return Err(InboxFault::UnboundedClockGuard);
    }
    Ok(upper)
}

fn push_guard_drop(key: RequestKey, issue: InboxIssue, update: &mut InboxUpdate) {
    let reason = if issue == InboxIssue::GuardCapacity {
        DropReason::RetainedCapacity
    } else {
        DropReason::CapacityQuarantine
    };
    update.effects.push(Effect::Drop { key, reason });
    update.issue = Some(issue);
}

#[cfg(test)]
mod outcome_integrity_tests {
    use super::*;
    use notification_policy::{ClockReading, RequestOutcome};

    #[test]
    fn an_impossible_outcome_without_original_metadata_latches_an_unencodable_state() {
        let mut state = PhoneInbox::with_phone_boot(
            NotificationPolicy::default(),
            CapacityLimits::new(1, 1).unwrap(),
            PhoneBootId::from_native_boot_count(7).unwrap(),
        );
        let clock = InboxClock::new(
            ClockReading::new(
                MonotonicTime::from_millis(0),
                LocalTime::new(Weekday::Monday, 600).unwrap(),
            ),
            0,
        )
        .unwrap();
        let mut update = state.poll(clock);
        // Fault injection only: the real engine must never emit an outcome for
        // an absent original binding. No production injection API is exposed.
        state.apply_effects(
            vec![Effect::RecordOutcome {
                key: RequestKey::new([1; 32], [2; 32], [3; 32]),
                outcome: RequestOutcome::CancelledByPc,
            }],
            &mut update,
        );
        assert_eq!(state.fault(), Some(InboxFault::OutcomeRetentionFailed));
        assert!(state.pending_outcomes().is_empty());
        assert!(update.effects().iter().all(|effect| !matches!(
            effect,
            Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
        )));
        assert_eq!(
            state.checkpoint().unwrap_err(),
            crate::InboxCheckpointError::OutcomeRetentionFailed
        );
        drop(state.stop_for_owner_failure());
        assert_eq!(
            state.checkpoint().unwrap_err(),
            crate::InboxCheckpointError::OutcomeRetentionFailed
        );
    }
}
