// SPDX-License-Identifier: GPL-2.0-or-later
//! Body-free native lifecycle checkpoints, never an authentication assertion.
use crate::{
    InboxClock, InboxFault, InboxUpdate, PendingOutcome, PhoneInbox, ReceivingGeneration,
    inbox::{RetainedRequest, SourceKey, SourceState},
    request_key,
};
use approval_protocol::{PcIdentity, RequestBinding};
use notification_policy::{
    AuthenticatedRequestMetadata, CapacityLimits, LifecycleCheckpoint, LocalTime,
    NotificationEngine, NotificationPolicy,
};
use service_protocol::{MappedRequestWindow, ServiceTick};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PhoneBootId(u32);
impl PhoneBootId {
    /// Android's nonnegative native BOOT_COUNT observation, not renderer data.
    /// The native owner must reject an unavailable observation, never use zero
    /// as an error fallback. Zero itself is a valid first native boot count.
    pub fn from_native_boot_count(value: u32) -> Result<Self, InboxCheckpointError> {
        if value > i32::MAX as u32 {
            return Err(InboxCheckpointError::InvalidBoot);
        }
        Ok(Self(value))
    }
    pub const fn as_native_boot_count(self) -> u32 {
        self.0
    }
}
impl fmt::Debug for PhoneBootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhoneBootId(native_observation)")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InboxCheckpointError {
    #[error("the native phone boot observation is invalid")]
    InvalidBoot,
    #[error("this process-only inbox has no native boot binding")]
    MissingBoot,
    #[error("the native clock moved backwards in the same phone boot")]
    ClockRegressed,
    #[error("the body-free inbox checkpoint is inconsistent")]
    InvalidState,
    #[error("the inbox checkpoint version is unsupported")]
    UnsupportedVersion,
    #[error("the inbox checkpoint exceeds its byte bound")]
    TooLarge,
    #[error("legacy request-bearing state needs explicit outcome-delivery reconciliation")]
    LegacyOutcomeReconciliationRequired,
    #[error("an outcome was not retained and the candidate cannot be checkpointed")]
    OutcomeRetentionFailed,
}

#[derive(Clone)]
pub(crate) struct RetainedCheckpoint {
    pub(crate) renewable_lineage: bool,
    pub(crate) binding: RequestBinding,
    pub(crate) receiving_generation: Option<ReceivingGeneration>,
    pub(crate) issued_at: ServiceTick,
    pub(crate) window: Option<MappedRequestWindow>,
    pub(crate) metadata: Option<AuthenticatedRequestMetadata>,
    pub(crate) guard_until_nanos: u64,
    pub(crate) was_active: bool,
    pub(crate) recovery_until_nanos: Option<u64>,
}

/// Contains no request body, command, credential, signing key or pending consent.
/// The native owner must durably store a transition before acknowledging its
/// dispositions/effects; an in-memory checkpoint is not a commit receipt.
#[derive(Clone)]
pub struct InboxCheckpoint {
    pub(crate) policy: NotificationPolicy,
    pub(crate) limits: CapacityLimits,
    pub(crate) engine: Option<LifecycleCheckpoint>,
    pub(crate) retained: Vec<RetainedCheckpoint>,
    pub(crate) sources: BTreeMap<SourceKey, SourceState>,
    pub(crate) quarantine: Option<u64>,
    pub(crate) last_phone_nanos: Option<u64>,
    pub(crate) last_local: Option<LocalTime>,
    pub(crate) phone_boot: PhoneBootId,
    pub(crate) fault: Option<InboxFault>,
    pub(crate) pending_outcomes: Vec<PendingOutcome>,
}
impl fmt::Debug for InboxCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboxCheckpoint")
            .field("retained_count", &self.retained.len())
            .field("source_count", &self.sources.len())
            .field("pending_outcome_count", &self.pending_outcomes.len())
            .finish_non_exhaustive()
    }
}
impl InboxCheckpoint {
    /// Read-only maintenance eligibility, never a clock observation or intake
    /// permission. The native caller must independently retain its current clock
    /// floor across skipped observations. No checkpoint field is advanced here.
    pub fn can_skip_empty_poll(&self, boot: PhoneBootId, clock: InboxClock) -> bool {
        self.phone_boot == boot
            && self.is_policy_only()
            && match (self.last_phone_nanos, self.last_local) {
                (Some(previous), Some(local)) => {
                    crate::inbox::recovery_clock_continuous(previous, local, clock)
                }
                _ => false,
            }
    }

    /// Staging compatibility predicate only, not authentication or readiness.
    pub fn is_policy_only(&self) -> bool {
        self.retained.is_empty()
            && self.pending_outcomes.is_empty()
            && self.sources.is_empty()
            && self.fault.is_none()
            && self.quarantine.is_none()
            && self.engine.as_ref().is_some_and(|engine| {
                engine.records().is_empty()
                    && engine.fault().is_none()
                    && engine.quarantine_until().is_none()
            })
    }
    pub fn policy(&self) -> &NotificationPolicy {
        &self.policy
    }
    /// Body-free persisted deliveries for a trusted composite owner's consistency
    /// checks. This is neither peer authority nor proof of a recipient write.
    pub fn pending_outcomes(&self) -> &[PendingOutcome] {
        &self.pending_outcomes
    }
    pub const fn phone_boot(&self) -> PhoneBootId {
        self.phone_boot
    }
    /// Original receiving-generation references, including inactive guards.
    /// These may be revoked/noncurrent; a caller must resolve current eligibility
    /// separately. None/legacy rows are never assigned a present-day association.
    pub fn receiving_sources(
        &self,
    ) -> impl Iterator<Item = (PcIdentity, ReceivingGeneration)> + '_ {
        self.retained.iter().filter_map(|entry| {
            entry
                .receiving_generation
                .map(|generation| (entry.binding.pc(), generation))
        })
    }
}

impl PhoneInbox {
    pub fn checkpoint(&self) -> Result<InboxCheckpoint, InboxCheckpointError> {
        if self.outcome_retention_failed || self.fault == Some(InboxFault::OutcomeRetentionFailed) {
            return Err(InboxCheckpointError::OutcomeRetentionFailed);
        }
        let phone_boot = self.phone_boot.ok_or(InboxCheckpointError::MissingBoot)?;
        Ok(InboxCheckpoint {
            policy: self.policy.clone(),
            limits: self.limits,
            engine: self.engine.as_ref().map(NotificationEngine::checkpoint),
            retained: self
                .retained
                .values()
                .map(|entry| RetainedCheckpoint {
                    renewable_lineage: entry.renewable_lineage,
                    binding: entry.binding,
                    receiving_generation: entry.receiving_generation,
                    issued_at: entry.issued_at,
                    window: entry.window,
                    metadata: entry.metadata,
                    guard_until_nanos: entry.guard_until_nanos,
                    was_active: entry.content.is_some() || entry.recovering,
                    recovery_until_nanos: entry.recovery_until_nanos,
                })
                .collect(),
            sources: self.sources.clone(),
            quarantine: self.guard_quarantine_until_nanos,
            last_phone_nanos: self.last_phone_nanos,
            last_local: self.last_local,
            phone_boot,
            fault: self.fault,
            pending_outcomes: self.pending_outcomes.clone(),
        })
    }

    /// Restore only native-owned metadata. No old body or signing attempt is
    /// restored. The caller must reconcile owned OS notifications at startup
    /// and commit this returned transition before applying its effects.
    pub fn restore_checkpoint(
        checkpoint: InboxCheckpoint,
        current_boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, InboxUpdate), InboxCheckpointError> {
        checkpoint.validate()?;
        let same_boot = current_boot == checkpoint.phone_boot;
        if same_boot
            && checkpoint
                .last_phone_nanos
                .is_some_and(|last| clock.phone_monotonic_nanos() < last)
        {
            return Err(InboxCheckpointError::ClockRegressed);
        }
        let mut inbox = Self {
            policy: checkpoint.policy.clone(),
            limits: checkpoint.limits,
            engine: if same_boot {
                checkpoint.engine.map(NotificationEngine::restore)
            } else if checkpoint.fault.is_none() {
                Some(NotificationEngine::new(
                    checkpoint.policy,
                    checkpoint.limits,
                ))
            } else {
                None
            },
            retained: checkpoint
                .retained
                .into_iter()
                .map(|entry| {
                    (
                        request_key(entry.binding),
                        RetainedRequest {
                            renewable_lineage: entry.renewable_lineage,
                            binding: entry.binding,
                            // Association identity is independent of phone boot
                            // and local timer comparability. Preserve even None.
                            receiving_generation: entry.receiving_generation,
                            issued_at: entry.issued_at,
                            window: same_boot.then_some(entry.window).flatten(),
                            metadata: same_boot.then_some(entry.metadata).flatten(),
                            // Zero on another boot discards an incomparable OLD local timer;
                            // source-expiry proof is still required before guard retirement.
                            guard_until_nanos: if same_boot {
                                entry.guard_until_nanos
                            } else {
                                0
                            },
                            content: None,
                            recovering: same_boot && entry.was_active,
                            recovery_until_nanos: if same_boot {
                                entry.recovery_until_nanos
                            } else {
                                None
                            },
                        },
                    )
                })
                .collect(),
            sources: checkpoint.sources,
            guard_quarantine_until_nanos: checkpoint
                .quarantine
                .map(|until| if same_boot { until } else { 0 }),
            last_phone_nanos: if same_boot {
                checkpoint.last_phone_nanos
            } else {
                Some(clock.phone_monotonic_nanos())
            },
            last_local: if same_boot {
                checkpoint.last_local
            } else {
                Some(clock.reading().local)
            },
            phone_boot: Some(current_boot),
            fault: checkpoint.fault,
            pending_outcomes: checkpoint.pending_outcomes,
            outcome_retention_failed: false,
        };
        let update = inbox.begin(clock);
        let update = inbox.finish(update);
        Ok((inbox, update))
    }
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use notification_policy::{ClockReading, MonotonicTime, Weekday};

    fn clock(nanos: u64, minute: u16) -> InboxClock {
        InboxClock::new(
            ClockReading::new(
                MonotonicTime::from_millis(nanos / 1_000_000),
                LocalTime::new(Weekday::Monday, minute).unwrap(),
            ),
            nanos,
        )
        .unwrap()
    }

    #[test]
    fn idle_eligibility_preserves_boot_clock_and_empty_state_boundaries() {
        let boot = PhoneBootId::from_native_boot_count(7).unwrap();
        let mut inbox = PhoneInbox::with_phone_boot(
            NotificationPolicy::default(),
            CapacityLimits::default(),
            boot,
        );
        let _ = inbox.poll(clock(1_000_000_000, 600));
        let checkpoint = inbox.checkpoint().unwrap();
        assert!(checkpoint.can_skip_empty_poll(boot, clock(61_000_000_000, 601)));
        assert!(!checkpoint.can_skip_empty_poll(boot, clock(999_999_999, 600)));
        assert!(!checkpoint.can_skip_empty_poll(boot, clock(1_000_000_001, 660)));
        assert!(!checkpoint.can_skip_empty_poll(
            PhoneBootId::from_native_boot_count(8).unwrap(),
            clock(61_000_000_000, 601),
        ));
        let mut guarded = checkpoint.clone();
        guarded.quarantine = Some(90_000_000_000);
        assert!(!guarded.can_skip_empty_poll(boot, clock(61_000_000_000, 601)));
        let mut faulted = checkpoint.clone();
        faulted.fault = Some(InboxFault::NativeClockRegressed);
        assert!(!faulted.can_skip_empty_poll(boot, clock(61_000_000_000, 601)));
        // Eligibility is a pure observation and does not move the saved floor.
        assert_eq!(checkpoint.last_phone_nanos, Some(1_000_000_000));
    }
}
