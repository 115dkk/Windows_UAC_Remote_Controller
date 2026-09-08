// SPDX-License-Identifier: GPL-2.0-or-later

use std::{collections::BTreeMap, fmt};

use thiserror::Error;

use crate::{AlertMode, LocalTime, NotificationPolicy, Schedule};

/// Five minutes: upper bound for any original authenticated request lifetime.
pub const MAX_REQUEST_LIFETIME_MILLIS: u64 = 300_000;
pub const MAX_ACTIVE_REQUESTS: usize = 32;
/// Combined bound for active requests and minimal suppression markers.
pub const MAX_RETAINED_REQUESTS: usize = 512;

/// Milliseconds in one trusted OS monotonic epoch, never wall/PC/relay time.
///
/// The adapter chooses one origin for the whole engine lifetime. It must map the
/// authenticated original lifetime once and preserve that mapping on retries;
/// using `now + ttl` separately on every delivery would extend replayed requests.
/// Device reboot/origin changes require a new authenticated session, not a clock
/// reset inside the same engine. This type is intentionally not serializable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Coherent observations from the phone OS. Local time may repeat or skip;
/// monotonic time must never move backward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockReading {
    pub monotonic: MonotonicTime,
    pub local: LocalTime,
}

impl ClockReading {
    pub const fn new(monotonic: MonotonicTime, local: LocalTime) -> Self {
        Self { monotonic, local }
    }
}

/// Nonsecret opaque identity scoped to exact PC, service boot epoch and request.
///
/// Upstream must never reuse a key for a different immutable authenticated
/// lifetime. All three components participate in ordering/equality. No body,
/// credential, executable command, or authentication key is stored here.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestKey {
    pc: [u8; 32],
    epoch: [u8; 32],
    request: [u8; 32],
}

impl RequestKey {
    /// Preserve the full protocol identifiers; never truncate them for a UI key.
    pub const fn new(pc: [u8; 32], epoch: [u8; 32], request: [u8; 32]) -> Self {
        Self { pc, epoch, request }
    }

    pub const fn pc(self) -> [u8; 32] {
        self.pc
    }

    pub const fn epoch(self) -> [u8; 32] {
        self.epoch
    }

    pub const fn request(self) -> [u8; 32] {
        self.request
    }
}

impl fmt::Debug for RequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestKey([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MetadataError {
    #[error("authenticated request expiry must be after its original issue time")]
    EmptyOrReversedLifetime,
    #[error("authenticated request lifetime exceeds the five-minute limit")]
    LifetimeTooLong,
}

/// An assertion by an authenticated upstream adapter, **not** signature verification.
///
/// The transport must verify the complete immutable identity/lifetime binding,
/// freshness and session before calling this constructor. Both times are mapped
/// into the current engine's trusted monotonic origin, not received from a relay
/// as local clock values. An original request must never be retimed on retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequestMetadata {
    key: RequestKey,
    issued_at: MonotonicTime,
    expires_at: MonotonicTime,
}

impl AuthenticatedRequestMetadata {
    pub fn new(
        key: RequestKey,
        issued_at: MonotonicTime,
        expires_at: MonotonicTime,
    ) -> Result<Self, MetadataError> {
        let Some(lifetime) = expires_at.0.checked_sub(issued_at.0) else {
            return Err(MetadataError::EmptyOrReversedLifetime);
        };
        if lifetime == 0 {
            return Err(MetadataError::EmptyOrReversedLifetime);
        }
        if lifetime > MAX_REQUEST_LIFETIME_MILLIS {
            return Err(MetadataError::LifetimeTooLong);
        }
        Ok(Self {
            key,
            issued_at,
            expires_at,
        })
    }

    pub const fn key(self) -> RequestKey {
        self.key
    }

    pub const fn issued_at(self) -> MonotonicTime {
        self.issued_at
    }

    pub const fn expires_at(self) -> MonotonicTime {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapacityError {
    #[error("active capacity must be between 1 and 32")]
    ActiveOutOfRange,
    #[error("retained capacity must be between active capacity and 512")]
    RetainedOutOfRange,
}

/// Every active request already occupies a retained slot, so completing or
/// suppressing it cannot fail to allocate its tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityLimits {
    max_active: usize,
    max_retained: usize,
}

impl CapacityLimits {
    pub fn new(max_active: usize, max_retained: usize) -> Result<Self, CapacityError> {
        if max_active == 0 || max_active > MAX_ACTIVE_REQUESTS {
            return Err(CapacityError::ActiveOutOfRange);
        }
        if max_retained < max_active || max_retained > MAX_RETAINED_REQUESTS {
            return Err(CapacityError::RetainedOutOfRange);
        }
        Ok(Self {
            max_active,
            max_retained,
        })
    }

    pub const fn max_active(self) -> usize {
        self.max_active
    }

    pub const fn max_retained(self) -> usize {
        self.max_retained
    }
}

impl Default for CapacityLimits {
    fn default() -> Self {
        Self {
            max_active: 16,
            max_retained: 256,
        }
    }
}

/// Only an authenticated PC event may supply one of these resolutions.
/// `Completed` conveys completion, not an application-generated Windows approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedPcOutcome {
    Cancelled,
    Expired,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestOutcome {
    CancelledByPc,
    ExpiredByPc,
    ExpiredLocally,
    CompletedByPc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawalReason {
    CancelledByPc,
    ExpiredByPc,
    CompletedByPc,
    ExpiredLocally,
    ScheduleBlocked,
    RecoveryRejected,
    EngineFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    OutsideAllowedTime,
    NotificationsDisabled,
    Expired,
    DuplicateActive,
    PreviouslySuppressed,
    ConflictingDeadline,
    ConflictingIssueTime,
    ActiveCapacity,
    RetainedCapacity,
    CapacityQuarantine,
    ResolutionBeforeDelivery,
    InvalidRequestTime,
    EngineFault,
}

/// Latched integration faults require a fresh authenticated epoch to recover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineFault {
    ClockMovedBackwards,
    FutureIssueTime,
}

/// Metadata-only instructions for an OS adapter; not performed by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Recheck pending state immediately before posting. Do not treat a queued
    /// Show as a durable permission: cancellation/expiry may have intervened.
    Show(PendingNotification),
    /// Repost or reconcile a reverified, still-live request without re-alerting.
    /// The native owner must recheck pending state immediately before use. This
    /// is not authentication or authority to approve a request. The lifecycle
    /// engine never emits this variant; a body-reverifying recovery owner may.
    Restore(PendingNotification),
    Withdraw {
        key: RequestKey,
        reason: WithdrawalReason,
    },
    /// Update an already-posted notification without sounding/vibrating again.
    UpdateAlert {
        key: RequestKey,
        alert: AlertMode,
    },
    /// Only admitted active-time requests produce outcomes. The adapter must not
    /// turn Drop/Withdraw alone into body history or a delayed notification.
    RecordOutcome {
        key: RequestKey,
        outcome: RequestOutcome,
    },
    Drop {
        key: RequestKey,
        reason: DropReason,
    },
    /// Stop accepting this session and remove withdrawn OS notifications.
    Fault(EngineFault),
}

/// Current presentation metadata, not an authorization token or reusable permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingNotification {
    pub key: RequestKey,
    pub expires_at: MonotonicTime,
    pub alert: AlertMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingCheck {
    pub pending: Option<PendingNotification>,
    /// Apply these before acting on `pending`.
    pub effects: Vec<Effect>,
}

/// A metadata-only storage-owner assertion, not proof of authentication.
///
/// Constructing a record does not establish a PC signature, native storage
/// provenance, or permission to present a body. The recovery owner must validate
/// those bindings separately before restoring any user-visible request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleRecord {
    metadata: AuthenticatedRequestMetadata,
    active: bool,
}

impl LifecycleRecord {
    /// The caller asserts that this state came from its trusted lifecycle store.
    /// Structural consistency is checked by `LifecycleCheckpoint::from_trusted_storage`.
    pub const fn new(metadata: AuthenticatedRequestMetadata, active: bool) -> Self {
        Self { metadata, active }
    }

    pub const fn metadata(self) -> AuthenticatedRequestMetadata {
        self.metadata
    }

    pub const fn is_active(self) -> bool {
        self.active
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CheckpointError {
    #[error("checkpoint exceeds its retained request capacity")]
    RetainedCapacityExceeded,
    #[error("checkpoint exceeds its active request capacity")]
    ActiveCapacityExceeded,
    #[error("checkpoint contains a duplicate request key")]
    DuplicateRequestKey,
    #[error("checkpoint state requires a previous monotonic observation")]
    MissingObservation,
    #[error("checkpoint request issue time is after its previous observation")]
    FutureIssueTime,
    #[error("checkpoint retains a request expired at its previous observation")]
    ExpiredRecord,
    #[error("checkpoint quarantine expired at its previous observation")]
    ExpiredQuarantine,
    #[error("checkpoint quarantine exceeds the maximum remaining request lifetime")]
    QuarantineTooLong,
    #[error("a faulted checkpoint cannot contain active requests")]
    FaultWithActiveRecords,
    #[error("a disabled notification policy cannot contain active requests")]
    DisabledPolicyWithActiveRecords,
}

/// Bounded, opaque lifecycle metadata in the original trusted monotonic epoch.
///
/// This is not a serialized format or an authentication token. Its constructor
/// verifies structural engine invariants only. The storage owner must bound its
/// decoder before allocating input, authenticate storage provenance, validate the
/// full PC/request bindings, retain a continuous native boot/clock identity and
/// lease, reconcile current policy, and reverify any PC body before presentation.
/// Restoring a checkpoint neither resets time nor emits notification effects.
#[derive(Clone, Eq, PartialEq)]
pub struct LifecycleCheckpoint {
    policy: NotificationPolicy,
    limits: CapacityLimits,
    records: Box<[LifecycleRecord]>,
    quarantine_until: Option<MonotonicTime>,
    last_observed: Option<MonotonicTime>,
    fault: Option<EngineFault>,
}

impl fmt::Debug for LifecycleCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleCheckpoint")
            .field("record_count", &self.records.len())
            .field("limits", &self.limits)
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl LifecycleCheckpoint {
    /// Accept owner-asserted storage metadata without authenticating its source.
    ///
    /// Records are canonicalized by full request key. No stale record is silently
    /// removed: doing so here could conceal an inconsistent replay store. Expiry
    /// is checked against the saved observation, not a newly supplied clock.
    pub fn from_trusted_storage(
        policy: NotificationPolicy,
        limits: CapacityLimits,
        mut records: Vec<LifecycleRecord>,
        quarantine_until: Option<MonotonicTime>,
        last_observed: Option<MonotonicTime>,
        fault: Option<EngineFault>,
    ) -> Result<Self, CheckpointError> {
        if records.len() > limits.max_retained {
            return Err(CheckpointError::RetainedCapacityExceeded);
        }
        let active_count = records.iter().filter(|record| record.active).count();
        if active_count > limits.max_active {
            return Err(CheckpointError::ActiveCapacityExceeded);
        }
        if fault.is_some() && active_count != 0 {
            return Err(CheckpointError::FaultWithActiveRecords);
        }
        if matches!(policy.schedule(), Schedule::Never) && active_count != 0 {
            return Err(CheckpointError::DisabledPolicyWithActiveRecords);
        }
        records.sort_unstable_by_key(|record| record.metadata.key);
        if records
            .windows(2)
            .any(|pair| pair[0].metadata.key == pair[1].metadata.key)
        {
            return Err(CheckpointError::DuplicateRequestKey);
        }

        if let Some(previous) = last_observed {
            for record in &records {
                if record.metadata.issued_at > previous {
                    return Err(CheckpointError::FutureIssueTime);
                }
                if record.metadata.expires_at <= previous {
                    return Err(CheckpointError::ExpiredRecord);
                }
            }
            if let Some(deadline) = quarantine_until {
                let Some(remaining) = deadline.0.checked_sub(previous.0) else {
                    return Err(CheckpointError::ExpiredQuarantine);
                };
                if remaining == 0 {
                    return Err(CheckpointError::ExpiredQuarantine);
                }
                // Checked subtraction expresses deadline <= previous + MAX_TTL
                // without rejecting reachable clocks near u64::MAX on overflow.
                if remaining > MAX_REQUEST_LIFETIME_MILLIS {
                    return Err(CheckpointError::QuarantineTooLong);
                }
            }
        } else if !records.is_empty() || quarantine_until.is_some() || fault.is_some() {
            return Err(CheckpointError::MissingObservation);
        }

        Ok(Self {
            policy,
            limits,
            // Do not retain an arbitrarily oversized caller Vec's spare capacity.
            records: records.into_boxed_slice(),
            quarantine_until,
            last_observed,
            fault,
        })
    }

    pub fn records(&self) -> &[LifecycleRecord] {
        &self.records
    }

    pub const fn limits(&self) -> CapacityLimits {
        self.limits
    }

    pub const fn policy(&self) -> &NotificationPolicy {
        &self.policy
    }

    pub const fn quarantine_until(&self) -> Option<MonotonicTime> {
        self.quarantine_until
    }

    pub const fn last_observed(&self) -> Option<MonotonicTime> {
        self.last_observed
    }

    pub const fn fault(&self) -> Option<EngineFault> {
        self.fault
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedState {
    Active,
    Suppressed,
}

/// Tombstones keep only the key, original lifetime and one policy-state bit.
#[derive(Clone, Copy, Debug)]
struct RetainedRequest {
    issued_at: MonotonicTime,
    expires_at: MonotonicTime,
    state: RetainedState,
}

/// Bounded, single-owner notification lifecycle, independent of network/UI code.
///
/// Original deadlines are never extended and live markers are never evicted.
/// When retained storage fills, an O(1) quarantine suppresses all untracked new
/// requests until every untracked drop's deadline has passed. A drop can extend
/// quarantine by at most five minutes from that observation; continued valid
/// authenticated traffic can keep it active, intentionally trading availability
/// for no replay hole. Existing active requests remain usable until their own
/// deadline, resolution or schedule withdrawal. Each call returns a bounded
/// effect list (at most twice the retained capacity plus two).
///
/// A marker can be removed at its original deadline because the same immutable
/// authenticated request is then expired. Reusing that key with another lifetime
/// violates the upstream authenticated-metadata contract. Conflicting issue
/// times and deadlines are explicitly rejected while a key is retained.
///
/// Checkpoints preserve metadata only; see the crate-level trusted restart
/// requirements. Restoring does not reauthenticate requests or emit effects.
#[derive(Debug)]
pub struct NotificationEngine {
    policy: NotificationPolicy,
    limits: CapacityLimits,
    retained: BTreeMap<RequestKey, RetainedRequest>,
    quarantine_until: Option<MonotonicTime>,
    last_observed: Option<MonotonicTime>,
    fault: Option<EngineFault>,
}

impl NotificationEngine {
    pub fn new(policy: NotificationPolicy, limits: CapacityLimits) -> Self {
        Self {
            policy,
            limits,
            retained: BTreeMap::new(),
            quarantine_until: None,
            last_observed: None,
            fault: None,
        }
    }

    /// Copy bounded metadata only. This does not poll, advance the clock, verify
    /// a body, or generate any notification effects. The owner must persist it
    /// together with its authenticated bindings and original native clock epoch.
    pub fn checkpoint(&self) -> LifecycleCheckpoint {
        LifecycleCheckpoint {
            policy: self.policy.clone(),
            limits: self.limits,
            records: self
                .retained
                .iter()
                .map(|(key, request)| {
                    LifecycleRecord::new(
                        AuthenticatedRequestMetadata {
                            key: *key,
                            issued_at: request.issued_at,
                            expires_at: request.expires_at,
                        },
                        request.state == RetainedState::Active,
                    )
                })
                .collect(),
            quarantine_until: self.quarantine_until,
            last_observed: self.last_observed,
            fault: self.fault,
        }
    }

    /// Restore an opaque, structurally valid metadata checkpoint without effects.
    ///
    /// No authentication, clock reset, policy expansion, or automatic Show/Restore
    /// occurs here. The recovery owner must establish storage/boot/lease continuity,
    /// validate all bindings, reverify bodies and recheck pending state before use.
    pub fn restore(checkpoint: LifecycleCheckpoint) -> Self {
        Self {
            policy: checkpoint.policy,
            limits: checkpoint.limits,
            retained: checkpoint
                .records
                .into_vec()
                .into_iter()
                .map(|record| {
                    (
                        record.metadata.key,
                        RetainedRequest {
                            issued_at: record.metadata.issued_at,
                            expires_at: record.metadata.expires_at,
                            state: if record.active {
                                RetainedState::Active
                            } else {
                                RetainedState::Suppressed
                            },
                        },
                    )
                })
                .collect(),
            quarantine_until: checkpoint.quarantine_until,
            last_observed: checkpoint.last_observed,
            fault: checkpoint.fault,
        }
    }

    pub fn policy(&self) -> &NotificationPolicy {
        &self.policy
    }

    /// Diagnostic count only; use `check_pending` for current presentation state.
    pub fn active_count(&self) -> usize {
        self.retained
            .values()
            .filter(|request| request.state == RetainedState::Active)
            .count()
    }

    pub fn retained_count(&self) -> usize {
        self.retained.len()
    }

    pub const fn quarantine_until(&self) -> Option<MonotonicTime> {
        self.quarantine_until
    }

    pub const fn fault(&self) -> Option<EngineFault> {
        self.fault
    }

    /// The adapter must arrange a monotonic wakeup by this time even offline.
    /// Also wake on local-minute boundaries and phone timezone changes.
    pub fn next_deadline(&self) -> Option<MonotonicTime> {
        self.retained
            .values()
            .filter(|request| request.state == RetainedState::Active)
            .map(|request| request.expires_at)
            .min()
    }

    pub fn receive(
        &mut self,
        metadata: AuthenticatedRequestMetadata,
        clock: ClockReading,
    ) -> Vec<Effect> {
        let mut effects = self.poll(clock);
        if !self.validate_arrival(metadata, clock, &mut effects) {
            return effects;
        }
        if let Some(existing) = self.retained.get(&metadata.key) {
            let reason = if existing.expires_at != metadata.expires_at {
                DropReason::ConflictingDeadline
            } else if existing.issued_at != metadata.issued_at {
                DropReason::ConflictingIssueTime
            } else if existing.state == RetainedState::Active {
                DropReason::DuplicateActive
            } else {
                DropReason::PreviouslySuppressed
            };
            effects.push(Self::drop(metadata.key, reason));
            return effects;
        }
        if let Some(reason) = self.untracked_drop_reason(metadata.expires_at) {
            effects.push(Self::drop(metadata.key, reason));
            return effects;
        }

        let rejection = if !self.policy.allows(clock.local) {
            Some(if matches!(self.policy.schedule(), Schedule::Never) {
                DropReason::NotificationsDisabled
            } else {
                DropReason::OutsideAllowedTime
            })
        } else if self.active_count() == self.limits.max_active {
            Some(DropReason::ActiveCapacity)
        } else {
            None
        };
        self.retained.insert(
            metadata.key,
            RetainedRequest {
                issued_at: metadata.issued_at,
                expires_at: metadata.expires_at,
                state: if rejection.is_some() {
                    RetainedState::Suppressed
                } else {
                    RetainedState::Active
                },
            },
        );
        if let Some(reason) = rejection {
            effects.push(Self::drop(metadata.key, reason));
        } else {
            effects.push(Effect::Show(PendingNotification {
                key: metadata.key,
                expires_at: metadata.expires_at,
                alert: self.policy.alert(),
            }));
        }
        effects
    }

    /// Authenticated cancellation/expiry/completion can arrive before delivery.
    /// Such events install a suppression marker but never create history.
    /// Repeated resolutions emit no second withdrawal or outcome.
    pub fn resolve_from_pc(
        &mut self,
        metadata: AuthenticatedRequestMetadata,
        outcome: AuthenticatedPcOutcome,
        clock: ClockReading,
    ) -> Vec<Effect> {
        let mut effects = self.poll(clock);
        if !self.validate_arrival(metadata, clock, &mut effects) {
            return effects;
        }
        if let Some(existing) = self.retained.get_mut(&metadata.key) {
            if existing.expires_at != metadata.expires_at {
                effects.push(Self::drop(metadata.key, DropReason::ConflictingDeadline));
            } else if existing.issued_at != metadata.issued_at {
                effects.push(Self::drop(metadata.key, DropReason::ConflictingIssueTime));
            } else if existing.state == RetainedState::Suppressed {
                effects.push(Self::drop(metadata.key, DropReason::PreviouslySuppressed));
            } else {
                existing.state = RetainedState::Suppressed;
                let (reason, outcome) = match outcome {
                    AuthenticatedPcOutcome::Cancelled => (
                        WithdrawalReason::CancelledByPc,
                        RequestOutcome::CancelledByPc,
                    ),
                    AuthenticatedPcOutcome::Expired => {
                        (WithdrawalReason::ExpiredByPc, RequestOutcome::ExpiredByPc)
                    }
                    AuthenticatedPcOutcome::Completed => (
                        WithdrawalReason::CompletedByPc,
                        RequestOutcome::CompletedByPc,
                    ),
                };
                effects.push(Effect::Withdraw {
                    key: metadata.key,
                    reason,
                });
                effects.push(Effect::RecordOutcome {
                    key: metadata.key,
                    outcome,
                });
            }
            return effects;
        }
        if let Some(reason) = self.untracked_drop_reason(metadata.expires_at) {
            effects.push(Self::drop(metadata.key, reason));
            return effects;
        }
        self.retained.insert(
            metadata.key,
            RetainedRequest {
                issued_at: metadata.issued_at,
                expires_at: metadata.expires_at,
                state: RetainedState::Suppressed,
            },
        );
        effects.push(Self::drop(
            metadata.key,
            DropReason::ResolutionBeforeDelivery,
        ));
        effects
    }

    /// Retire one still-active request rejected by the trusted recovery owner.
    ///
    /// This only reduces presentation state; it does not assert a PC resolution
    /// or authenticate anything. Poll effects are preserved first. Retirement
    /// itself emits one withdrawal, never a history outcome, Show, or Restore.
    /// Unknown, suppressed, expired, or faulted requests get no extra effects.
    pub fn suppress_for_recovery(&mut self, key: RequestKey, clock: ClockReading) -> Vec<Effect> {
        let mut effects = self.poll(clock);
        if self.fault.is_some() {
            return effects;
        }
        if let Some(request) = self
            .retained
            .get_mut(&key)
            .filter(|request| request.state == RetainedState::Active)
        {
            request.state = RetainedState::Suppressed;
            effects.push(Effect::Withdraw {
                key,
                reason: WithdrawalReason::RecoveryRejected,
            });
        }
        effects
    }

    /// Expiry does not need a network signal. A local-time boundary also
    /// withdraws and permanently suppresses requests no longer allowed.
    pub fn poll(&mut self, clock: ClockReading) -> Vec<Effect> {
        let mut effects = Vec::new();
        if self.fault.is_some() {
            return effects;
        }
        if self
            .last_observed
            .is_some_and(|previous| clock.monotonic < previous)
        {
            self.latch_fault(EngineFault::ClockMovedBackwards, &mut effects);
            return effects;
        }
        self.last_observed = Some(clock.monotonic);
        self.retained.retain(|key, request| {
            if request.expires_at > clock.monotonic {
                return true;
            }
            if request.state == RetainedState::Active {
                effects.push(Effect::Withdraw {
                    key: *key,
                    reason: WithdrawalReason::ExpiredLocally,
                });
                effects.push(Effect::RecordOutcome {
                    key: *key,
                    outcome: RequestOutcome::ExpiredLocally,
                });
            }
            false
        });
        if self
            .quarantine_until
            .is_some_and(|deadline| deadline <= clock.monotonic)
        {
            self.quarantine_until = None;
        }
        self.suppress_outside_schedule(clock.local, &mut effects);
        effects
    }

    /// Apply a phone user's new policy. Restricting hours/setting Never withdraws
    /// pending requests without history; later expansion never resurrects them.
    /// Alert changes update surviving notifications without re-alerting.
    pub fn update_policy(
        &mut self,
        policy: NotificationPolicy,
        clock: ClockReading,
    ) -> Vec<Effect> {
        let mut effects = self.poll(clock);
        let previous_alert = self.policy.alert();
        self.policy = policy;
        if self.fault.is_some() {
            return effects;
        }
        self.suppress_outside_schedule(clock.local, &mut effects);
        if previous_alert != self.policy.alert() {
            effects.extend(self.retained.iter().filter_map(|(key, request)| {
                (request.state == RetainedState::Active).then_some(Effect::UpdateAlert {
                    key: *key,
                    alert: self.policy.alert(),
                })
            }));
        }
        effects
    }

    /// Recheck immediately before display or presenting an actionable control.
    /// This does not authenticate/approve a decision. The service must separately
    /// verify any signed response against its own still-live exact request.
    pub fn check_pending(&mut self, key: RequestKey, clock: ClockReading) -> PendingCheck {
        let effects = self.poll(clock);
        let pending = if self.fault.is_some() {
            None
        } else {
            self.retained.get(&key).and_then(|request| {
                (request.state == RetainedState::Active).then_some(PendingNotification {
                    key,
                    expires_at: request.expires_at,
                    alert: self.policy.alert(),
                })
            })
        };
        PendingCheck { pending, effects }
    }

    fn validate_arrival(
        &mut self,
        metadata: AuthenticatedRequestMetadata,
        clock: ClockReading,
        effects: &mut Vec<Effect>,
    ) -> bool {
        if self.fault.is_some() {
            effects.push(Self::drop(metadata.key, DropReason::EngineFault));
            return false;
        }
        if metadata.issued_at > clock.monotonic {
            // A caller violated the trusted monotonic mapping contract. Latching
            // prevents a far-future deadline from extending quarantine forever
            // or becoming admissible after an unremembered rejection.
            self.latch_fault(EngineFault::FutureIssueTime, effects);
            effects.push(Self::drop(metadata.key, DropReason::InvalidRequestTime));
            return false;
        }
        if metadata.expires_at <= clock.monotonic {
            effects.push(Self::drop(metadata.key, DropReason::Expired));
            return false;
        }
        true
    }

    fn untracked_drop_reason(&mut self, expires_at: MonotonicTime) -> Option<DropReason> {
        if let Some(deadline) = self.quarantine_until {
            self.quarantine_until = Some(deadline.max(expires_at));
            return Some(DropReason::CapacityQuarantine);
        }
        if self.retained.len() == self.limits.max_retained {
            self.quarantine_until = Some(expires_at);
            return Some(DropReason::RetainedCapacity);
        }
        None
    }

    fn suppress_outside_schedule(&mut self, local: LocalTime, effects: &mut Vec<Effect>) {
        if self.policy.allows(local) {
            return;
        }
        for (key, request) in &mut self.retained {
            if request.state == RetainedState::Active {
                request.state = RetainedState::Suppressed;
                effects.push(Effect::Withdraw {
                    key: *key,
                    reason: WithdrawalReason::ScheduleBlocked,
                });
            }
        }
    }

    fn latch_fault(&mut self, fault: EngineFault, effects: &mut Vec<Effect>) {
        self.fault = Some(fault);
        for (key, request) in &mut self.retained {
            if request.state == RetainedState::Active {
                request.state = RetainedState::Suppressed;
                effects.push(Effect::Withdraw {
                    key: *key,
                    reason: WithdrawalReason::EngineFault,
                });
            }
        }
        effects.push(Effect::Fault(fault));
    }

    const fn drop(key: RequestKey, reason: DropReason) -> Effect {
        Effect::Drop { key, reason }
    }
}
