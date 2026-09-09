// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict, bounded, body-free metadata. Checksums belong to the byte store;
//! neither parsing nor a checksum authenticates storage/native observations.
use crate::{
    InboxCheckpoint, InboxCheckpointError as Error, InboxFault, PendingOutcome, PhoneBootId,
    ReceivingGeneration,
    checkpoint::RetainedCheckpoint,
    inbox::{SourceKey, SourceState},
    outbox::{outcome_from_tag, outcome_tag},
    request_key,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, ExpiryTick, OsSession, PcIdentity, RequestBinding,
    RequestId,
};
use notification_policy::{
    AlertMode, AuthenticatedRequestMetadata, CapacityLimits, EngineFault, LifecycleCheckpoint,
    LifecycleRecord, LocalTime, MonotonicTime, NotificationPolicy, RequestKey, Schedule, Weekday,
};
use serde::Deserialize;
use service_protocol::{MAX_REQUEST_LIFETIME_NANOS, MappedRequestWindow, ServiceTick};
use std::collections::{BTreeMap, BTreeSet};

const MAGIC: &[u8; 8] = b"UACINBX\0";
const VERSION: u16 = 3;
const OUTCOMES_LEGACY_VERSION: u16 = 2;
const POLICY_ONLY_LEGACY_VERSION: u16 = 1;
const MAX_BYTES: usize = 384 * 1024;
const MAX_POLICY: usize = 16 * 1024;
const MILLI: u64 = 1_000_000;
const MAX_GUARD: u64 = MAX_REQUEST_LIFETIME_NANOS + service_protocol::MAX_CLOCK_PROBE_RTT_NANOS;
const DAYS: [Weekday; 7] = [
    Weekday::Monday,
    Weekday::Tuesday,
    Weekday::Wednesday,
    Weekday::Thursday,
    Weekday::Friday,
    Weekday::Saturday,
    Weekday::Sunday,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredPolicy {
    schedule: Schedule,
    alert: AlertMode,
}

impl InboxCheckpoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let policy = serde_json::to_vec(&self.policy).map_err(|_| Error::InvalidState)?;
        if policy.len() > MAX_POLICY {
            return Err(Error::TooLarge);
        }
        let mut out = Writer(Vec::new());
        out.0.extend_from_slice(MAGIC);
        out.u16(VERSION);
        out.u32(self.phone_boot.as_native_boot_count());
        out.u16(self.limits.max_active() as u16);
        out.u16(self.limits.max_retained() as u16);
        out.u32(policy.len() as u32);
        out.0.extend_from_slice(&policy);
        out.optional(self.last_phone_nanos);
        out.u8(u8::from(self.last_local.is_some()));
        if let Some(local) = self.last_local {
            out.u8(local.weekday() as u8);
            out.u16(local.minute());
        }
        out.optional(self.quarantine);
        out.u8(encode_fault(self.fault));
        out.u8(u8::from(self.engine.is_some()));
        let mut engine_states = BTreeMap::new();
        if let Some(engine) = &self.engine {
            out.optional(engine.last_observed().map(MonotonicTime::as_millis));
            out.optional(engine.quarantine_until().map(MonotonicTime::as_millis));
            out.u8(match engine.fault() {
                None => 0,
                Some(EngineFault::ClockMovedBackwards) => 1,
                Some(EngineFault::FutureIssueTime) => 2,
            });
            engine_states.extend(
                engine
                    .records()
                    .iter()
                    .map(|row| (row.metadata().key(), if row.is_active() { 2 } else { 1 })),
            );
        }
        out.u16(self.sources.len() as u16);
        for (source, state) in &self.sources {
            out.0.extend_from_slice(source.pc.as_bytes());
            out.0.extend_from_slice(source.epoch.as_bytes());
            out.u64(state.watermark);
            out.optional(state.quarantine_expiry);
        }
        out.u16(self.retained.len() as u16);
        for entry in &self.retained {
            out.binding(entry.binding);
            out.u64(entry.issued_at.as_nanos_since_epoch());
            out.u8(u8::from(entry.window.is_some()));
            if let Some(window) = entry.window {
                out.u64(window.phone_issued_nanos());
                out.u64(window.phone_expiry_nanos());
            }
            out.u8(u8::from(entry.metadata.is_some()));
            out.u64(entry.guard_until_nanos);
            out.u8(u8::from(entry.was_active));
            out.optional(entry.recovery_until_nanos);
            out.u8(*engine_states.get(&request_key(entry.binding)).unwrap_or(&0));
            // Appended only in schema3. The optional nonzero scalar freezes the
            // original receiver; never encode a current registry lookup here.
            out.optional(entry.receiving_generation.map(ReceivingGeneration::get));
        }
        out.u16(self.pending_outcomes.len() as u16);
        for pending in &self.pending_outcomes {
            out.0.extend_from_slice(pending.delivery_id().as_bytes());
            out.binding(pending.binding());
            out.u64(pending.issued_at().as_nanos_since_epoch());
            out.u8(outcome_tag(pending.outcome()));
        }
        if out.0.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(out.0)
    }

    /// Decode only bytes loaded through the native private store. There is no
    /// defaulting, truncation, skipped unknown field, inferred current boot or
    /// reconstituted request body. Native storage/enrollment proof is separate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let mut input = Reader(bytes);
        if input.take(8)? != MAGIC {
            return Err(Error::InvalidState);
        }
        let version = input.u16()?;
        if ![POLICY_ONLY_LEGACY_VERSION, OUTCOMES_LEGACY_VERSION, VERSION].contains(&version) {
            return Err(Error::UnsupportedVersion);
        }
        let phone_boot = PhoneBootId::from_native_boot_count(input.u32()?)?;
        let limits = CapacityLimits::new(usize::from(input.u16()?), usize::from(input.u16()?))
            .map_err(|_| Error::InvalidState)?;
        let length = usize::try_from(input.u32()?).map_err(|_| Error::TooLarge)?;
        if length > MAX_POLICY {
            return Err(Error::TooLarge);
        }
        let policy: RequiredPolicy =
            serde_json::from_slice(input.take(length)?).map_err(|_| Error::InvalidState)?;
        let policy = NotificationPolicy::new(Some(policy.schedule), policy.alert);
        let last_phone_nanos = input.optional()?;
        let last_local = if input.boolean()? {
            let day = *DAYS
                .get(usize::from(input.u8()?))
                .ok_or(Error::InvalidState)?;
            Some(LocalTime::new(day, input.u16()?).map_err(|_| Error::InvalidState)?)
        } else {
            None
        };
        let quarantine = input.optional()?;
        let fault = decode_fault(input.u8()?)?;
        let has_engine = input.boolean()?;
        let (engine_last, engine_quarantine, engine_fault) = if has_engine {
            let last = input.optional()?.map(MonotonicTime::from_millis);
            let quarantine = input.optional()?.map(MonotonicTime::from_millis);
            let fault = match input.u8()? {
                0 => None,
                1 => Some(EngineFault::ClockMovedBackwards),
                2 => Some(EngineFault::FutureIssueTime),
                _ => return Err(Error::InvalidState),
            };
            (last, quarantine, fault)
        } else {
            (None, None, None)
        };
        let source_count = usize::from(input.u16()?);
        if source_count > limits.max_retained() {
            return Err(Error::InvalidState);
        }
        let mut sources = BTreeMap::new();
        for _ in 0..source_count {
            let source = SourceKey {
                pc: PcIdentity::from_bytes(input.array()?).map_err(|_| Error::InvalidState)?,
                epoch: BootEpoch::from_bytes(input.array()?).map_err(|_| Error::InvalidState)?,
            };
            let state = SourceState {
                watermark: input.u64()?,
                quarantine_expiry: input.optional()?,
            };
            if sources.insert(source, state).is_some() {
                return Err(Error::InvalidState);
            }
        }
        let retained_count = usize::from(input.u16()?);
        if retained_count > limits.max_retained() {
            return Err(Error::InvalidState);
        }
        let mut retained = Vec::with_capacity(retained_count);
        let mut engine_rows = Vec::new();
        for _ in 0..retained_count {
            let binding = input.binding()?;
            let issued_at = ServiceTick::from_nanos_since_epoch(input.u64()?);
            let window = if input.boolean()? {
                Some(
                    MappedRequestWindow::from_trusted_checkpoint(
                        binding,
                        issued_at,
                        input.u64()?,
                        input.u64()?,
                    )
                    .map_err(|_| Error::InvalidState)?,
                )
            } else {
                None
            };
            let metadata = if input.boolean()? {
                let window = window.ok_or(Error::InvalidState)?;
                Some(
                    AuthenticatedRequestMetadata::new(
                        request_key(binding),
                        MonotonicTime::from_millis(window.phone_issued_nanos() / MILLI),
                        MonotonicTime::from_millis(window.phone_expiry_nanos() / MILLI),
                    )
                    .map_err(|_| Error::InvalidState)?,
                )
            } else {
                None
            };
            let guard_until_nanos = input.u64()?;
            let was_active = input.boolean()?;
            let recovery_until_nanos = input.optional()?;
            let engine_state = input.u8()?;
            let receiving_generation = if version == VERSION {
                input
                    .optional()?
                    .map(ReceivingGeneration::from_trusted_owner)
                    .transpose()
                    .map_err(|_| Error::InvalidState)?
            } else {
                // Older schemas had no association field. Lack of provenance is
                // retained, not inferred from the current PC or key registry.
                None
            };
            if engine_state > 2
                || (engine_state != 0 && !has_engine)
                || was_active != (engine_state == 2)
            {
                return Err(Error::InvalidState);
            }
            if engine_state != 0 {
                engine_rows.push(LifecycleRecord::new(
                    metadata.ok_or(Error::InvalidState)?,
                    engine_state == 2,
                ));
            }
            retained.push(RetainedCheckpoint {
                binding,
                receiving_generation,
                issued_at,
                window,
                metadata,
                guard_until_nanos,
                was_active,
                recovery_until_nanos,
            });
        }
        let mut pending_outcomes = Vec::new();
        if version == OUTCOMES_LEGACY_VERSION || version == VERSION {
            let count = usize::from(input.u16()?);
            if count > limits.max_retained() {
                return Err(Error::InvalidState);
            }
            pending_outcomes
                .try_reserve_exact(count)
                .map_err(|_| Error::TooLarge)?;
            for _ in 0..count {
                let id = input.array()?;
                let binding = input.binding()?;
                let issued = ServiceTick::from_nanos_since_epoch(input.u64()?);
                let outcome = outcome_from_tag(input.u8()?).ok_or(Error::InvalidState)?;
                pending_outcomes.push(
                    PendingOutcome::from_encoded(id, binding, issued, outcome)
                        .ok_or(Error::InvalidState)?,
                );
            }
        }
        if !input.0.is_empty() {
            return Err(Error::InvalidState);
        }
        let engine = if has_engine {
            Some(
                LifecycleCheckpoint::from_trusted_storage(
                    policy.clone(),
                    limits,
                    engine_rows,
                    engine_quarantine,
                    engine_last,
                    engine_fault,
                )
                .map_err(|_| Error::InvalidState)?,
            )
        } else {
            None
        };
        let checkpoint = Self {
            policy,
            limits,
            engine,
            retained,
            sources,
            quarantine,
            last_phone_nanos,
            last_local,
            phone_boot,
            fault,
            pending_outcomes,
        };
        checkpoint.validate()?;
        // Only a fully validated, healthy policy-only schema-1 snapshot can
        // migrate. Its missing outbox is known empty; request-bearing legacy
        // state cannot establish which historical outcomes were delivered.
        if version == POLICY_ONLY_LEGACY_VERSION && !checkpoint.is_policy_only() {
            return Err(Error::LegacyOutcomeReconciliationRequired);
        }
        Ok(checkpoint)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.fault == Some(InboxFault::OutcomeRetentionFailed) {
            return Err(Error::OutcomeRetentionFailed);
        }
        if self.retained.len() > self.limits.max_retained()
            || self.sources.len() > self.limits.max_retained()
            || self
                .pending_outcomes
                .len()
                .checked_add(self.retained.iter().filter(|row| row.was_active).count())
                .is_none_or(|used| used > self.limits.max_retained())
            || self.last_phone_nanos.is_some() != self.last_local.is_some()
        {
            return Err(Error::InvalidState);
        }
        if self.last_phone_nanos.is_none()
            && (!self.retained.is_empty()
                || !self.sources.is_empty()
                || !self.pending_outcomes.is_empty()
                || self.quarantine.is_some()
                || self
                    .fault
                    .is_some_and(|fault| fault != InboxFault::ReceivingOwnerStopped))
        {
            return Err(Error::InvalidState);
        }
        let expected_engine_fault = match self.fault {
            Some(InboxFault::NotificationEngine(fault)) => Some(fault),
            _ => None,
        };
        if let Some(engine) = &self.engine {
            if engine.policy() != &self.policy
                || engine.limits() != self.limits
                || engine.fault() != expected_engine_fault
                || engine.last_observed().map(MonotonicTime::as_millis)
                    != self.last_phone_nanos.map(|value| value / MILLI)
                || (self.fault.is_some() && expected_engine_fault.is_none())
            {
                return Err(Error::InvalidState);
            }
            if let Some(lower) = engine.quarantine_until() {
                let lower = lower
                    .as_millis()
                    .checked_mul(MILLI)
                    .ok_or(Error::InvalidState)?;
                if self.quarantine.is_none_or(|upper| upper < lower) {
                    return Err(Error::InvalidState);
                }
            }
        } else if self.fault.is_none() {
            return Err(Error::InvalidState);
        }
        if self.quarantine.is_some()
            != self
                .sources
                .values()
                .any(|source| source.quarantine_expiry.is_some())
        {
            return Err(Error::InvalidState);
        }
        if let (Some(until), Some(last)) = (self.quarantine, self.last_phone_nanos)
            && until.saturating_sub(last) > MAX_GUARD
        {
            return Err(Error::InvalidState);
        }
        let mut entries = BTreeMap::new();
        let engine_records: BTreeMap<RequestKey, LifecycleRecord> = self
            .engine
            .as_ref()
            .map(|engine| {
                engine
                    .records()
                    .iter()
                    .map(|row| (row.metadata().key(), *row))
                    .collect()
            })
            .unwrap_or_default();
        for entry in &self.retained {
            let lifetime = entry
                .binding
                .expiry()
                .as_nanos_since_epoch()
                .checked_sub(entry.issued_at.as_nanos_since_epoch())
                .filter(|value| *value > 0 && *value <= MAX_REQUEST_LIFETIME_NANOS)
                .ok_or(Error::InvalidState)?;
            let source = self
                .sources
                .get(&SourceKey {
                    pc: entry.binding.pc(),
                    epoch: entry.binding.epoch(),
                })
                .ok_or(Error::InvalidState)?;
            let key = request_key(entry.binding);
            if entries.insert(key, entry).is_some() {
                return Err(Error::InvalidState);
            }
            if let Some(last) = self.last_phone_nanos
                && entry.guard_until_nanos.saturating_sub(last) > MAX_GUARD
            {
                return Err(Error::InvalidState);
            }
            if let Some(window) = entry.window {
                if window.binding() != entry.binding
                    || window.service_issued_at() != entry.issued_at
                    || window
                        .phone_expiry_nanos()
                        .checked_sub(window.phone_issued_nanos())
                        .is_none_or(|value| value == 0 || value > lifetime)
                    || entry.guard_until_nanos < window.phone_expiry_nanos()
                    || self
                        .last_phone_nanos
                        .is_none_or(|last| window.phone_issued_nanos() > last)
                {
                    return Err(Error::InvalidState);
                }
                if let Some(metadata) = entry.metadata {
                    if metadata.key() != key
                        || metadata.issued_at().as_millis() != window.phone_issued_nanos() / MILLI
                        || metadata.expires_at().as_millis() != window.phone_expiry_nanos() / MILLI
                    {
                        return Err(Error::InvalidState);
                    }
                } else if window.phone_expiry_nanos() / MILLI > window.phone_issued_nanos() / MILLI
                {
                    return Err(Error::InvalidState);
                }
            } else if entry.metadata.is_some() {
                return Err(Error::InvalidState);
            }
            let engine_active = engine_records
                .get(&key)
                .is_some_and(|record| record.is_active());
            if entry.was_active != engine_active
                || entry.was_active != entry.recovery_until_nanos.is_some()
                || (entry.was_active
                    && (self.fault.is_some()
                        || self
                            .last_local
                            .is_none_or(|local| !self.policy.allows(local))
                        || source.watermark >= entry.binding.expiry().as_nanos_since_epoch()
                        || entry.recovery_until_nanos.is_none()))
            {
                return Err(Error::InvalidState);
            }
            if let Some(until) = entry.recovery_until_nanos
                && entry
                    .window
                    .is_none_or(|window| until > window.phone_expiry_nanos())
            {
                return Err(Error::InvalidState);
            }
        }
        for row in engine_records.values() {
            if entries
                .get(&row.metadata().key())
                .is_none_or(|entry| entry.metadata != Some(row.metadata()))
            {
                return Err(Error::InvalidState);
            }
        }
        let mut delivery_ids = BTreeSet::new();
        let mut outcome_keys = BTreeSet::new();
        for pending in &self.pending_outcomes {
            if !pending.valid()
                || !delivery_ids.insert(pending.delivery_id())
                || !outcome_keys.insert(pending.key())
            {
                return Err(Error::InvalidState);
            }
            let source = self
                .sources
                .get(&SourceKey {
                    pc: pending.binding().pc(),
                    epoch: pending.binding().epoch(),
                })
                .ok_or(Error::InvalidState)?;
            if let Some(original) = entries.get(&pending.key()) {
                if original.binding != pending.binding()
                    || original.issued_at != pending.issued_at()
                    || original.was_active
                {
                    return Err(Error::InvalidState);
                }
            } else if source.watermark < pending.binding().expiry().as_nanos_since_epoch() {
                // A removed guard must still have its original source-expiry
                // proof; ACK must not delete the only protection for a live ID.
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }
}

fn encode_fault(value: Option<InboxFault>) -> u8 {
    match value {
        None => 0,
        Some(InboxFault::NativeClockRegressed) => 1,
        Some(InboxFault::ClockCorrelationFaulted) => 2,
        Some(InboxFault::ClockRangeExceeded) => 3,
        Some(InboxFault::UnboundedClockGuard) => 4,
        Some(InboxFault::SourceCapacityReached) => 5,
        Some(InboxFault::NotificationEngine(EngineFault::ClockMovedBackwards)) => 6,
        Some(InboxFault::NotificationEngine(EngineFault::FutureIssueTime)) => 7,
        Some(InboxFault::InconsistentState) => 8,
        Some(InboxFault::ReceivingOwnerStopped) => 9,
        Some(InboxFault::OutcomeRetentionFailed) => 10,
    }
}
fn decode_fault(value: u8) -> Result<Option<InboxFault>, Error> {
    Ok(match value {
        0 => None,
        1 => Some(InboxFault::NativeClockRegressed),
        2 => Some(InboxFault::ClockCorrelationFaulted),
        3 => Some(InboxFault::ClockRangeExceeded),
        4 => Some(InboxFault::UnboundedClockGuard),
        5 => Some(InboxFault::SourceCapacityReached),
        6 => Some(InboxFault::NotificationEngine(
            EngineFault::ClockMovedBackwards,
        )),
        7 => Some(InboxFault::NotificationEngine(EngineFault::FutureIssueTime)),
        8 => Some(InboxFault::InconsistentState),
        9 => Some(InboxFault::ReceivingOwnerStopped),
        10 => Some(InboxFault::OutcomeRetentionFailed),
        _ => return Err(Error::InvalidState),
    })
}
struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn optional(&mut self, value: Option<u64>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.u64(value);
        }
    }
    fn binding(&mut self, value: RequestBinding) {
        self.0.extend_from_slice(value.pc().as_bytes());
        self.0.extend_from_slice(value.epoch().as_bytes());
        self.u32(value.session().session_id());
        self.u64(value.session().logon_id());
        self.0.extend_from_slice(value.request_id().as_bytes());
        self.0.extend_from_slice(value.nonce().as_bytes());
        self.0.extend_from_slice(value.content_digest().as_bytes());
        self.u64(value.expiry().as_nanos_since_epoch());
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if length > self.0.len() {
            return Err(Error::InvalidState);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidState)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidState),
        }
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn optional(&mut self) -> Result<Option<u64>, Error> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }
    fn binding(&mut self) -> Result<RequestBinding, Error> {
        Ok(RequestBinding::new(
            PcIdentity::from_bytes(self.array()?).map_err(|_| Error::InvalidState)?,
            BootEpoch::from_bytes(self.array()?).map_err(|_| Error::InvalidState)?,
            OsSession::new(self.u32()?, self.u64()?),
            RequestId::from_bytes(self.array()?).map_err(|_| Error::InvalidState)?,
            ChallengeNonce::from_bytes(self.array()?).map_err(|_| Error::InvalidState)?,
            ContentDigest::from_bytes(self.array()?),
            ExpiryTick::from_nanos_since_epoch(self.u64()?).map_err(|_| Error::InvalidState)?,
        ))
    }
}
