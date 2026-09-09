// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-owned decision verification and bounded, one-shot pending state.
//!
//! This is an in-process trusted-service component, NOT an IPC approval,
//! enrollment, execution, credential, or input-injection API. `*_privileged_host`
//! names mark a privilege boundary the containing Windows service must enforce;
//! a Rust constructor cannot establish Windows caller identity or ACLs.
//!
//! The host must attest/enroll two distinct, hardware-generated device keys:
//! approval requires its intended Android per-use OS-auth policy, whereas the
//! denial key does not require OS-auth. This crate verifies signatures, not
//! Android authentication, hardware provenance, transport E2EE, or Windows UAC.
//! A credential-type Windows prompt may only be handled by a later adapter that
//! supplies the credentials Windows actually requires; application approval is
//! never a replacement for Windows authentication. Unsupported prompt types
//! must be ignored by that adapter.
//!
//! A single service task must own the engine, or all access must be serialized
//! under one mutex. Every state-changing operation requires exclusive `&mut`
//! ownership. The first valid decision removes its pending request before an
//! opaque, non-Clone authorization is returned. Invalid responses do not consume
//! live state. No adapter may treat receipt of that value as Windows success.
//! Every time argument must be a fresh trusted host `Instant`, not a remote time
//! or an old queue-receipt timestamp. The adapter checks time again after crypto.
//!
//! The OS adapter must independently retain the exact verified prompt target
//! (not merely its display strings), consume an `AuthorizedDecision` by value,
//! check its complete binding, current epoch/session, live target and deadline
//! immediately before one action attempt, then discard it regardless of outcome.
//! Revocation/restart/cancellation and adapter dispatch must be serialized by the
//! service: already-issued tokens cannot be retroactively recalled by this crate.
//! Never persist, serialize, clone, retry or queue these tokens past that check.

#![forbid(unsafe_code)]

mod registry_checkpoint;

pub use registry_checkpoint::{
    RegistryCheckpoint, RegistryCheckpointEntry, RegistryCheckpointError,
};

use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use approval_protocol::{
    BootEpoch, ChallengeNonce, DecisionPublicKey, DecisionPurpose, DeviceId, ExpiryTick, OsSession,
    PcIdentity, RequestBinding, RequestContent, RequestId, SignedDecision,
};
use thiserror::Error;

pub const MAX_TRUSTED_DEVICES: usize = 32;
pub const MAX_PENDING_REQUESTS: usize = 128;
pub const MAX_REQUEST_TTL_MILLIS: u32 = 120_000;
const RANDOM_ATTEMPTS: usize = 8;

/// Small bounded lifetime in the service's monotonic time domain, not a phone's
/// wall clock or a renderer-supplied absolute timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTtl(Duration);

impl RequestTtl {
    pub fn from_millis(millis: u32) -> Result<Self, ConfigurationError> {
        if millis == 0 || millis > MAX_REQUEST_TTL_MILLIS {
            return Err(ConfigurationError::InvalidRequestTtl);
        }
        Ok(Self(Duration::from_millis(u64::from(millis))))
    }

    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

/// Two purpose-specific public keys; no private signing material is accepted.
/// Public-key parsing alone is NOT attestation or authorization to enroll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    approval: DecisionPublicKey,
    denial: DecisionPublicKey,
}

impl DeviceKeys {
    pub fn new(
        approval: DecisionPublicKey,
        denial: DecisionPublicKey,
    ) -> Result<Self, EnrollmentError> {
        if approval == denial {
            return Err(EnrollmentError::KeyReuse);
        }
        Ok(Self { approval, denial })
    }

    pub fn approval(&self) -> &DecisionPublicKey {
        &self.approval
    }

    pub fn denial(&self) -> &DecisionPublicKey {
        &self.denial
    }

    fn key_for(&self, purpose: DecisionPurpose) -> &DecisionPublicKey {
        match purpose {
            DecisionPurpose::Approve => &self.approval,
            DecisionPurpose::Deny => &self.denial,
        }
    }

    fn shares_key(&self, other: &Self) -> bool {
        self.approval == other.approval
            || self.approval == other.denial
            || self.denial == other.approval
            || self.denial == other.denial
    }
}

#[derive(Clone, Debug)]
struct Enrollment {
    revision: u64,
    keys: DeviceKeys,
}

/// Enrollment configuration constructed ONLY inside a verified privileged host.
///
/// Deliberately not Deserialize, Clone, or an externally callable enrollment
/// transport. The containing service must ensure neither its UI, relay, phone,
/// nor an unelevated process can reach these mutations. Enrollment must bind the
/// PC/device identity, obtain user-approved trust through an authenticated
/// bootstrap, verify key attestation and approval-key auth policy, and persist
/// registry data with privileged-only integrity and anti-rollback protection.
/// None of those host properties are implemented by this in-memory registry.
#[derive(Debug)]
pub struct PrivilegedDeviceRegistry {
    devices: BTreeMap<DeviceId, Enrollment>,
    capacity: usize,
    next_revision: u64,
}

impl PrivilegedDeviceRegistry {
    pub fn initialize_for_privileged_host(capacity: usize) -> Result<Self, ConfigurationError> {
        if capacity == 0 || capacity > MAX_TRUSTED_DEVICES {
            return Err(ConfigurationError::InvalidDeviceCapacity);
        }
        Ok(Self {
            devices: BTreeMap::new(),
            capacity,
            next_revision: 1,
        })
    }

    /// Existing device IDs require explicit replacement; enrollment never
    /// silently overwrites them. Keys cannot be shared across active devices.
    pub fn enroll_from_privileged_host(
        &mut self,
        device_id: DeviceId,
        keys: DeviceKeys,
    ) -> Result<(), EnrollmentError> {
        if self.devices.contains_key(&device_id) {
            return Err(EnrollmentError::AlreadyEnrolled);
        }
        if self.devices.len() >= self.capacity {
            return Err(EnrollmentError::CapacityReached);
        }
        self.ensure_unique_keys(device_id, &keys)?;
        let revision = self.allocate_revision()?;
        self.devices
            .insert(device_id, Enrollment { revision, keys });
        Ok(())
    }

    /// Even replacement with identical keys assigns a new revision. Pending
    /// snapshots cannot silently acquire replacement enrollment authority.
    pub fn replace_from_privileged_host(
        &mut self,
        device_id: DeviceId,
        keys: DeviceKeys,
    ) -> Result<(), EnrollmentError> {
        if !self.devices.contains_key(&device_id) {
            return Err(EnrollmentError::NotEnrolled);
        }
        self.ensure_unique_keys(device_id, &keys)?;
        let revision = self.allocate_revision()?;
        self.devices
            .insert(device_id, Enrollment { revision, keys });
        Ok(())
    }

    /// Removal frees capacity, but re-enrollment receives a fresh revision even
    /// if the device ID and both public keys are exactly the same.
    pub fn revoke_from_privileged_host(
        &mut self,
        device_id: DeviceId,
    ) -> Result<(), EnrollmentError> {
        self.devices
            .remove(&device_id)
            .ok_or(EnrollmentError::NotEnrolled)?;
        Ok(())
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    fn ensure_unique_keys(
        &self,
        replacing: DeviceId,
        keys: &DeviceKeys,
    ) -> Result<(), EnrollmentError> {
        if self
            .devices
            .iter()
            .any(|(device, enrollment)| *device != replacing && keys.shares_key(&enrollment.keys))
        {
            return Err(EnrollmentError::KeyReuse);
        }
        Ok(())
    }

    fn allocate_revision(&mut self) -> Result<u64, EnrollmentError> {
        let revision = self.next_revision;
        self.next_revision = revision
            .checked_add(1)
            .ok_or(EnrollmentError::RevisionExhausted)?;
        Ok(revision)
    }
}

/// Public challenge/presentation data, not permission to act on Windows.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    binding: RequestBinding,
    content: Arc<RequestContent>,
    eligible_devices: Vec<DeviceId>,
}

impl PendingChallenge {
    pub const fn binding(&self) -> RequestBinding {
        self.binding
    }

    pub fn content(&self) -> &RequestContent {
        &self.content
    }

    pub fn eligible_devices(&self) -> &[DeviceId] {
        &self.eligible_devices
    }
}

#[derive(Debug)]
struct PendingRequest {
    binding: RequestBinding,
    content: Arc<RequestContent>,
    deadline: Instant,
    eligible: BTreeMap<DeviceId, Enrollment>,
}

/// Opaque, non-Clone and non-serializable permission for the exact OS adapter
/// target to attempt one decision. It proves neither Windows success nor
/// Android OS-authentication independently of enrolled-key policy.
///
/// The privileged adapter must take this by value and check its current target
/// and epoch immediately before dispatch, under the same service serialization
/// boundary as revocation and restart. Do not turn this into a generic execute,
/// inject-input or local approval endpoint.
///
/// ```compile_fail
/// fn duplicate(decision: approval_core::AuthorizedDecision) {
///     let _: approval_core::AuthorizedDecision = decision.clone();
/// }
/// ```
#[must_use = "an authorized decision must be consumed by its matching adapter or safely dropped"]
pub struct AuthorizedDecision {
    binding: RequestBinding,
    content: Arc<RequestContent>,
    device_id: DeviceId,
    purpose: DecisionPurpose,
    deadline: Instant,
}

impl AuthorizedDecision {
    pub const fn binding(&self) -> RequestBinding {
        self.binding
    }

    pub fn content(&self) -> &RequestContent {
        &self.content
    }

    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn purpose(&self) -> DecisionPurpose {
        self.purpose
    }

    /// Host monotonic deadline; adapter dispatch is forbidden at or after it.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl fmt::Debug for AuthorizedDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedDecision")
            .field("purpose", &self.purpose)
            .field("target", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Exclusively owned service state. All wire parsing and transport limits must
/// precede this API; relay requests cannot invoke privileged host operations.
///
/// Registry mutations preserve the engine-owned revision sequence. Giving out
/// a mutable registry would let a replacement restart that sequence and revive
/// an old pending snapshot after revoke/re-enroll with identical keys.
///
/// ```compile_fail
/// fn reset_registry(
///     engine: &mut approval_core::ApprovalEngine,
///     replacement: approval_core::PrivilegedDeviceRegistry,
/// ) {
///     *engine.devices_from_privileged_host() = replacement;
/// }
/// ```
#[derive(Debug)]
pub struct ApprovalEngine {
    pc: PcIdentity,
    epoch: BootEpoch,
    epoch_start: Instant,
    last_observed_time: Instant,
    devices: PrivilegedDeviceRegistry,
    pending: BTreeMap<RequestId, PendingRequest>,
    pending_capacity: usize,
}

impl ApprovalEngine {
    pub fn initialize_for_privileged_host(
        pc: PcIdentity,
        devices: PrivilegedDeviceRegistry,
        pending_capacity: usize,
        now: Instant,
    ) -> Result<Self, EngineError> {
        if pending_capacity == 0 || pending_capacity > MAX_PENDING_REQUESTS {
            return Err(ConfigurationError::InvalidPendingCapacity.into());
        }
        let epoch =
            BootEpoch::from_bytes(random_nonzero()?).map_err(|_| EngineError::RandomUnavailable)?;
        Ok(Self {
            pc,
            epoch,
            epoch_start: now,
            last_observed_time: now,
            devices,
            pending: BTreeMap::new(),
            pending_capacity,
        })
    }

    pub const fn pc_identity(&self) -> PcIdentity {
        self.pc
    }

    pub const fn boot_epoch(&self) -> BootEpoch {
        self.epoch
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn enrolled_device_count(&self) -> usize {
        self.devices.device_count()
    }

    /// Only an already-authenticated privileged host control path may call this,
    /// never a web view, phone, notification callback or generic IPC route.
    /// The registry itself cannot be swapped or reset while requests are live.
    pub fn enroll_device_from_privileged_host(
        &mut self,
        device_id: DeviceId,
        keys: DeviceKeys,
    ) -> Result<(), EnrollmentError> {
        self.devices.enroll_from_privileged_host(device_id, keys)
    }

    pub fn replace_device_from_privileged_host(
        &mut self,
        device_id: DeviceId,
        keys: DeviceKeys,
    ) -> Result<(), EnrollmentError> {
        self.devices.replace_from_privileged_host(device_id, keys)
    }

    pub fn revoke_device_from_privileged_host(
        &mut self,
        device_id: DeviceId,
    ) -> Result<(), EnrollmentError> {
        self.devices.revoke_from_privileged_host(device_id)
    }

    /// Only a verified OS adapter may open requests from an immutable live
    /// target. Candidate strings alone do not authenticate an OS prompt.
    pub fn open_from_privileged_host(
        &mut self,
        session: OsSession,
        content: RequestContent,
        ttl: RequestTtl,
        now: Instant,
    ) -> Result<PendingChallenge, EngineError> {
        self.observe_time(now)?;
        self.remove_expired(now);
        if self.pending.len() >= self.pending_capacity {
            return Err(EngineError::PendingCapacityReached);
        }
        if self.devices.devices.is_empty() {
            return Err(EngineError::NoEligibleDevices);
        }
        let deadline = now
            .checked_add(ttl.as_duration())
            .ok_or(EngineError::ClockRangeExceeded)?;
        let tick = u64::try_from(deadline.duration_since(self.epoch_start).as_nanos())
            .map_err(|_| EngineError::ClockRangeExceeded)?;
        let expiry = ExpiryTick::from_nanos_since_epoch(tick)
            .map_err(|_| EngineError::ClockRangeExceeded)?;
        let request_id = self.fresh_request_id()?;
        let nonce = ChallengeNonce::from_bytes(random_nonzero()?)
            .map_err(|_| EngineError::RandomUnavailable)?;
        let binding = RequestBinding::new(
            self.pc,
            self.epoch,
            session,
            request_id,
            nonce,
            content.digest(),
            expiry,
        );
        // Presentation, pending state and the returned authorization share one
        // immutable payload instead of making additional command-line copies.
        let content = Arc::new(content);
        let eligible = self.devices.devices.clone();
        let challenge = PendingChallenge {
            binding,
            content: Arc::clone(&content),
            eligible_devices: eligible.keys().copied().collect(),
        };
        self.pending.insert(
            request_id,
            PendingRequest {
                binding,
                content,
                deadline,
                eligible,
            },
        );
        Ok(challenge)
    }

    /// Verify exact binding, current enrollment and its snapshotted purpose key,
    /// then atomically remove the request. Invalid live decisions never consume
    /// state. Only expiration can remove state before successful verification.
    pub fn submit_decision(
        &mut self,
        response: &SignedDecision,
        now: Instant,
    ) -> Result<AuthorizedDecision, DecisionError> {
        self.observe_time(now)?;
        let statement = response.statement();
        let binding = statement.binding();
        if binding.pc() != self.pc {
            return Err(DecisionError::WrongPc);
        }
        if binding.epoch() != self.epoch {
            return Err(DecisionError::WrongEpoch);
        }
        let request_id = binding.request_id();
        let pending = self
            .pending
            .get(&request_id)
            .ok_or(DecisionError::UnknownOrCompleted)?;
        if now >= pending.deadline {
            self.pending.remove(&request_id);
            return Err(DecisionError::Expired);
        }
        if binding != pending.binding {
            return Err(DecisionError::BindingMismatch);
        }
        let snapshot = pending
            .eligible
            .get(&statement.device_id())
            .ok_or(DecisionError::NotEligible)?;
        let current = self
            .devices
            .devices
            .get(&statement.device_id())
            .ok_or(DecisionError::EnrollmentChanged)?;
        if snapshot.revision != current.revision || snapshot.keys != current.keys {
            return Err(DecisionError::EnrollmentChanged);
        }
        response
            .verify(snapshot.keys.key_for(statement.purpose()))
            .map_err(|_| DecisionError::InvalidSignature)?;

        // Exclusive &mut access makes the verification/removal transition
        // indivisible with respect to every other decision on this engine.
        let pending = self
            .pending
            .remove(&request_id)
            .ok_or(DecisionError::UnknownOrCompleted)?;
        Ok(AuthorizedDecision {
            binding: pending.binding,
            content: pending.content,
            device_id: statement.device_id(),
            purpose: statement.purpose(),
            deadline: pending.deadline,
        })
    }

    /// Cancellation is exact-target, privileged-host only. A wrong binding does
    /// not cancel another request merely because its request ID was copied.
    pub fn cancel_from_privileged_host(
        &mut self,
        binding: &RequestBinding,
    ) -> Result<(), CancelError> {
        let pending = self
            .pending
            .get(&binding.request_id())
            .ok_or(CancelError::UnknownOrCompleted)?;
        if pending.binding != *binding {
            return Err(CancelError::BindingMismatch);
        }
        self.pending.remove(&binding.request_id());
        Ok(())
    }

    pub fn expire_from_privileged_host(
        &mut self,
        now: Instant,
    ) -> Result<Vec<RequestId>, ClockError> {
        self.observe_time(now)?;
        Ok(self.remove_expired(now))
    }

    /// New random epoch and no pending requests. Registry revisions are retained.
    /// Any adapter token from the old epoch must also be discarded by the host.
    /// Randomness failure leaves the epoch and pending requests unchanged.
    pub fn restart_from_privileged_host(&mut self, now: Instant) -> Result<BootEpoch, EngineError> {
        self.observe_time(now)?;
        let mut next_epoch = None;
        for _ in 0..RANDOM_ATTEMPTS {
            let candidate = BootEpoch::from_bytes(random_nonzero()?)
                .map_err(|_| EngineError::RandomUnavailable)?;
            if candidate != self.epoch {
                next_epoch = Some(candidate);
                break;
            }
        }
        let next_epoch = next_epoch.ok_or(EngineError::RandomUnavailable)?;
        self.pending.clear();
        self.epoch = next_epoch;
        self.epoch_start = now;
        Ok(next_epoch)
    }

    fn observe_time(&mut self, now: Instant) -> Result<(), ClockError> {
        if now < self.last_observed_time {
            return Err(ClockError::WentBackwards);
        }
        self.last_observed_time = now;
        Ok(())
    }

    fn remove_expired(&mut self, now: Instant) -> Vec<RequestId> {
        let mut expired = Vec::new();
        self.pending.retain(|request_id, request| {
            if now >= request.deadline {
                expired.push(*request_id);
                false
            } else {
                true
            }
        });
        expired
    }

    fn fresh_request_id(&self) -> Result<RequestId, EngineError> {
        for _ in 0..RANDOM_ATTEMPTS {
            let candidate = RequestId::from_bytes(random_nonzero()?)
                .map_err(|_| EngineError::RandomUnavailable)?;
            if !self.pending.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(EngineError::RandomUnavailable)
    }
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], EngineError> {
    for _ in 0..RANDOM_ATTEMPTS {
        let mut bytes = [0; N];
        getrandom::fill(&mut bytes).map_err(|_| EngineError::RandomUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(EngineError::RandomUnavailable)
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ConfigurationError {
    #[error("trusted-device capacity is outside the supported bound")]
    InvalidDeviceCapacity,
    #[error("pending-request capacity is outside the supported bound")]
    InvalidPendingCapacity,
    #[error("request lifetime is outside the supported bound")]
    InvalidRequestTtl,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("purpose-specific keys must not be reused")]
    KeyReuse,
    #[error("device is already enrolled; explicit replacement is required")]
    AlreadyEnrolled,
    #[error("device is not enrolled")]
    NotEnrolled,
    #[error("trusted-device capacity reached")]
    CapacityReached,
    #[error("enrollment revision space exhausted")]
    RevisionExhausted,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClockError {
    #[error("trusted host monotonic time went backwards")]
    WentBackwards,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error(transparent)]
    Configuration(#[from] ConfigurationError),
    #[error(transparent)]
    Clock(#[from] ClockError),
    #[error("cryptographic randomness unavailable or uniqueness attempts exhausted")]
    RandomUnavailable,
    #[error("trusted host clock is outside the supported range")]
    ClockRangeExceeded,
    #[error("pending-request capacity reached")]
    PendingCapacityReached,
    #[error("no enrolled devices are eligible")]
    NoEligibleDevices,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DecisionError {
    #[error(transparent)]
    Clock(#[from] ClockError),
    #[error("decision targets another PC")]
    WrongPc,
    #[error("decision targets another service epoch")]
    WrongEpoch,
    #[error("request is unknown or has already completed")]
    UnknownOrCompleted,
    #[error("request has expired")]
    Expired,
    #[error("decision does not match the immutable request binding")]
    BindingMismatch,
    #[error("device was not eligible when the request opened")]
    NotEligible,
    #[error("device enrollment was revoked or replaced")]
    EnrollmentChanged,
    #[error("decision signature is invalid for the enrolled purpose key")]
    InvalidSignature,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CancelError {
    #[error("request is unknown or has already completed")]
    UnknownOrCompleted,
    #[error("cancellation target does not match the request binding")]
    BindingMismatch,
}
