// SPDX-License-Identifier: GPL-2.0-or-later
//! Body-free native lifecycle checkpoints, never an authentication assertion.
use crate::{
    InboxClock, InboxFault, InboxUpdate, PhoneInbox,
    inbox::{RetainedRequest, SourceKey, SourceState},
    request_key,
};
use approval_protocol::RequestBinding;
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
}

#[derive(Clone)]
pub(crate) struct RetainedCheckpoint {
    pub(crate) binding: RequestBinding,
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
}
impl fmt::Debug for InboxCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboxCheckpoint")
            .field("retained_count", &self.retained.len())
            .field("source_count", &self.sources.len())
            .finish_non_exhaustive()
    }
}
impl InboxCheckpoint {
    /// Staging compatibility predicate only, not authentication or readiness.
    pub fn is_policy_only(&self) -> bool {
        self.retained.is_empty()
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
    pub const fn phone_boot(&self) -> PhoneBootId {
        self.phone_boot
    }
}

impl PhoneInbox {
    pub fn checkpoint(&self) -> Result<InboxCheckpoint, InboxCheckpointError> {
        let phone_boot = self.phone_boot.ok_or(InboxCheckpointError::MissingBoot)?;
        Ok(InboxCheckpoint {
            policy: self.policy.clone(),
            limits: self.limits,
            engine: self.engine.as_ref().map(NotificationEngine::checkpoint),
            retained: self
                .retained
                .values()
                .map(|entry| RetainedCheckpoint {
                    binding: entry.binding,
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
                            binding: entry.binding,
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
        };
        let update = inbox.begin(clock);
        let update = inbox.finish(update);
        Ok((inbox, update))
    }
}
