// SPDX-License-Identifier: GPL-2.0-or-later
//! Volatile original-context preparation only. No grant, invitation, signature,
//! registry mutation, transport, native display or first-install entitlement.
#![forbid(unsafe_code)]

use super::CLOSE_RESERVE;
use crate::PendingElevationId;
use approval_core::RegistryCheckpoint;
use approval_protocol::{BootEpoch, DeviceId, PcIdentity};
use p256::elliptic_curve::zeroize::Zeroizing;
use relay_service::RouteId;
use secure_channel::TlsPublicKey;
use service_protocol::{PairingChallenge, PairingNonce};
use std::{
    fmt,
    time::{Duration, Instant},
};

const ORIGINAL_LIFETIME: Duration = Duration::from_secs(300);

/// Private correlation metadata, not native identity or authorization evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Origin {
    pub(super) epoch: BootEpoch,
    pub(super) generation: u64,
    pub(super) pending_id: PendingElevationId,
    pub(super) started: Instant,
    pub(super) deadline: Instant,
}
pub(super) struct Context<'a> {
    pub(super) origin: Origin,
    pub(super) pc: PcIdentity,
    pub(super) pc_key: &'a TlsPublicKey,
    pub(super) checkpoint: &'a RegistryCheckpoint,
}
impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Origin(redacted, correlation_only)")
    }
}
impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Context(redacted, not_authority)")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::peer_runtime) enum PreparationError {
    Cancelled,
    Window,
    Context,
    Random,
    Collision,
    Consumed,
    Identity,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unclaimed,
    Prepared,
    Burned,
}
struct Prepared {
    origin: Origin,
    pc: PcIdentity,
    pc_key: TlsPublicKey,
    checkpoint: RegistryCheckpoint,
    // Nonce, challenge, recipient and public route share one wiping owner.
    material: Zeroizing<[u8; 112]>,
}

pub(super) struct PreparedOriginal {
    pub(super) nonce: PairingNonce,
    pub(super) challenge: PairingChallenge,
    pub(super) recipient: DeviceId,
    pub(super) route: RouteId,
    pub(super) pc: PcIdentity,
    pub(super) pc_key: TlsPublicKey,
    pub(super) intended_revision: u64,
    pub(super) deadline: Instant,
}
impl fmt::Debug for PreparedOriginal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedOriginal([redacted], shape_only)")
    }
}
pub(super) struct OriginalCeremony {
    phase: Phase,
    prepared: Option<Prepared>,
    failure: Option<PreparationError>,
    last_observed: Option<Instant>,
}
impl fmt::Debug for OriginalCeremony {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalCeremony")
            .field("phase", &self.phase)
            .field("authority", &"none")
            .finish_non_exhaustive()
    }
}
impl OriginalCeremony {
    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Unclaimed,
            prepared: None,
            failure: None,
            last_observed: None,
        }
    }
    pub(super) fn maintain(
        &mut self,
        context: Context<'_>,
        validate_key: impl FnMut() -> Result<(), PreparationError>,
    ) -> Result<(), PreparationError> {
        self.maintain_with_validation(
            context,
            observe,
            |bytes| getrandom::fill(bytes).map_err(|_| PreparationError::Random),
            validate_key,
        )
    }
    /// The caller has already checked original native matching, both actual
    /// Bound completions and the live policy lease. No public caller can supply
    /// a synthetic observation or use this state as a native trust witness.
    fn maintain_with_validation(
        &mut self,
        context: Context<'_>,
        mut observe: impl FnMut() -> Result<Instant, PreparationError>,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), PreparationError>,
        mut validate_key: impl FnMut() -> Result<(), PreparationError>,
    ) -> Result<(), PreparationError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = (|| {
            let first = observe()?;
            if self.last_observed.is_some_and(|last| first < last) {
                return Err(PreparationError::Window);
            }
            check_origin(context.origin, first)?;
            if self.phase == Phase::Prepared {
                let original = self.prepared.as_ref().ok_or(PreparationError::Consumed)?;
                if original.origin != context.origin
                    || original.pc != context.pc
                    || original.pc_key != *context.pc_key
                    || original.checkpoint != *context.checkpoint
                {
                    return Err(PreparationError::Context);
                }
                check_material(original, context.origin.pending_id)?;
                let after = observe()?;
                if after < first {
                    return Err(PreparationError::Window);
                }
                check_origin(context.origin, after)?;
                self.last_observed = Some(after);
                return Ok(());
            }
            if self.phase != Phase::Unclaimed || self.prepared.is_some() {
                return Err(PreparationError::Consumed);
            }
            // Burn BEFORE the only random call. Failure cannot retry, regenerate
            // a recipient, reset the clock or produce a second original context.
            self.phase = Phase::Burned;
            if context.checkpoint.entries().len() >= context.checkpoint.capacity()
                || context.checkpoint.next_revision() == u64::MAX
            {
                return Err(PreparationError::Context);
            }
            validate_key()?; // Only the unclaimed path; never an idle-poll CNG loop.
            check_origin(context.origin, observe()?)?;
            let mut material = Zeroizing::new([0_u8; 112]);
            fill(&mut material[..])?;
            let original = Prepared {
                origin: context.origin,
                pc: context.pc,
                pc_key: context.pc_key.clone(),
                checkpoint: context.checkpoint.clone(),
                material,
            };
            check_material(&original, context.origin.pending_id)?;
            validate_key()?; // Failure drops/wipes the not-yet-published material.
            let after = observe()?;
            if after < first {
                return Err(PreparationError::Window);
            }
            check_origin(context.origin, after)?;
            self.last_observed = Some(after);
            self.prepared = Some(original);
            self.phase = Phase::Prepared;
            Ok(())
        })();
        result.map_err(|error| self.burn(error))
    }
    #[cfg(test)]
    fn maintain_with(
        &mut self,
        context: Context<'_>,
        observe: impl FnMut() -> Result<Instant, PreparationError>,
        fill: impl FnMut(&mut [u8]) -> Result<(), PreparationError>,
    ) -> Result<(), PreparationError> {
        self.maintain_with_validation(context, observe, fill, || Ok(()))
    }
    pub(super) fn prepared(&self) -> Result<PreparedOriginal, PreparationError> {
        let value = self.prepared.as_ref().ok_or(PreparationError::Consumed)?;
        check_material(value, value.origin.pending_id)?;
        Ok(PreparedOriginal {
            nonce: PairingNonce::from_bytes(
                value.material[..32]
                    .try_into()
                    .map_err(|_| PreparationError::Context)?,
            )
            .map_err(|_| PreparationError::Context)?,
            challenge: PairingChallenge::from_bytes(
                value.material[32..64]
                    .try_into()
                    .map_err(|_| PreparationError::Context)?,
            )
            .map_err(|_| PreparationError::Context)?,
            recipient: DeviceId::from_bytes(
                value.material[64..80]
                    .try_into()
                    .map_err(|_| PreparationError::Context)?,
            )
            .map_err(|_| PreparationError::Context)?,
            route: RouteId::new(
                value.material[80..112]
                    .try_into()
                    .map_err(|_| PreparationError::Context)?,
            )
            .map_err(|_| PreparationError::Context)?,
            pc: value.pc,
            pc_key: value.pc_key.clone(),
            intended_revision: value.checkpoint.next_revision(),
            deadline: value.origin.deadline,
        })
    }
    pub(super) fn invalidate(&mut self) {
        self.burn(PreparationError::Cancelled);
    }
    fn burn(&mut self, error: PreparationError) -> PreparationError {
        self.phase = Phase::Burned;
        self.prepared = None;
        *self.failure.get_or_insert(error)
    }
}
fn observe() -> Result<Instant, PreparationError> {
    if crate::entry::stop_requested() {
        Err(PreparationError::Cancelled)
    } else {
        Ok(Instant::now())
    }
}
pub(super) fn check_pc_pin(
    current: &TlsPublicKey,
    original: &TlsPublicKey,
) -> Result<(), PreparationError> {
    if current != original {
        Err(PreparationError::Identity)
    } else {
        Ok(())
    }
}
fn check_origin(origin: Origin, now: Instant) -> Result<(), PreparationError> {
    let duration = origin.deadline.checked_duration_since(origin.started);
    let cutoff = origin.deadline.checked_sub(CLOSE_RESERVE);
    if origin.generation == 0
        || duration != Some(ORIGINAL_LIFETIME)
        || now < origin.started
        || cutoff.is_none_or(|cutoff| now >= cutoff)
    {
        Err(PreparationError::Window)
    } else {
        Ok(())
    }
}
fn check_material(value: &Prepared, pending: PendingElevationId) -> Result<(), PreparationError> {
    let nonce = &value.material[..32];
    let challenge = &value.material[32..64];
    let recipient = &value.material[64..80];
    let route = &value.material[80..112];
    if nonce.iter().all(|byte| *byte == 0)
        || challenge.iter().all(|byte| *byte == 0)
        || recipient.iter().all(|byte| *byte == 0)
        || route.iter().all(|byte| *byte == 0)
        || nonce == challenge
        || nonce == route
        || challenge == route
        || nonce == pending.bytes()
        || challenge == pending.bytes()
        || nonce == value.origin.epoch.as_bytes()
        || challenge == value.origin.epoch.as_bytes()
        || nonce == value.pc.as_bytes()
        || challenge == value.pc.as_bytes()
        || value
            .checkpoint
            .entries()
            .iter()
            .any(|entry| entry.device_id().as_bytes().as_slice() == recipient)
    {
        Err(PreparationError::Collision)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use approval_core::{DeviceKeys, RegistryCheckpointEntry};
    use approval_protocol::{DecisionPublicKey, DeviceId};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
    use std::cell::Cell;

    fn key(seed: u8) -> TlsPublicKey {
        let secret = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = p256::PublicKey::from_sec1_bytes(
            secret.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
    }
    fn origin(started: Instant) -> Origin {
        Origin {
            epoch: BootEpoch::from_bytes([1; 32]).unwrap(),
            generation: 1,
            pending_id: PendingElevationId::from_bytes([2; 32]).unwrap(),
            started,
            deadline: started + ORIGINAL_LIFETIME,
        }
    }
    fn context<'a>(
        origin: Origin,
        key: &'a TlsPublicKey,
        checkpoint: &'a RegistryCheckpoint,
    ) -> Context<'a> {
        Context {
            origin,
            pc: PcIdentity::from_bytes([3; 32]).unwrap(),
            pc_key: key,
            checkpoint,
        }
    }
    fn fill(bytes: &mut [u8]) -> Result<(), PreparationError> {
        bytes[..32].fill(7);
        bytes[32..64].fill(8);
        bytes[64..80].fill(9);
        bytes[80..112].fill(10);
        Ok(())
    }
    #[test]
    fn original_fields_are_created_once_and_never_become_a_grant_or_new_timer() {
        let start = Instant::now();
        let origin = origin(start);
        let key = key(4);
        let checkpoint = RegistryCheckpoint::new(32, 1, []).unwrap();
        let mut owner = OriginalCeremony::new();
        owner
            .maintain_with(context(origin, &key, &checkpoint), || Ok(start), fill)
            .unwrap();
        let original = owner.prepared.as_ref().unwrap();
        assert_eq!(original.origin.deadline, origin.deadline);
        assert_eq!(&original.material[..32], &[7; 32]);
        owner
            .maintain_with(
                context(origin, &key, &checkpoint),
                || Ok(start + Duration::from_secs(1)),
                |_| panic!("must not regenerate"),
            )
            .unwrap();
        assert!(!format!("{owner:?}").contains("070707"));
        assert!(format!("{owner:?}").contains("none"));
        owner.invalidate();
        assert!(owner.prepared.is_none());
        assert_eq!(
            owner.maintain_with(context(origin, &key, &checkpoint), || Ok(start), fill),
            Err(PreparationError::Cancelled)
        );
    }
    #[test]
    fn failure_collision_or_stop_burns_before_any_second_random_attempt() {
        let start = Instant::now();
        let origin = origin(start);
        let key = key(4);
        let checkpoint = RegistryCheckpoint::new(32, 1, []).unwrap();
        for malformed in 0..8 {
            let calls = Cell::new(0);
            let mut owner = OriginalCeremony::new();
            let result = owner.maintain_with(
                context(origin, &key, &checkpoint),
                || Ok(start),
                |bytes| {
                    calls.set(calls.get() + 1);
                    fill(bytes)?;
                    match malformed {
                        0 => return Err(PreparationError::Random),
                        1 => bytes[..32].fill(0),
                        2 => bytes[32..64].fill(7),
                        3 => bytes[..32].copy_from_slice(&origin.pending_id.bytes()),
                        4 => bytes[32..64].fill(0),
                        5 => bytes[64..80].fill(0),
                        6 => bytes[..32].fill(3), // Current PC identity.
                        _ => bytes[32..64].copy_from_slice(origin.epoch.as_bytes()),
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert!(owner.prepared.is_none());
            assert!(
                owner
                    .maintain_with(
                        context(origin, &key, &checkpoint),
                        || Ok(start),
                        |_| {
                            calls.set(calls.get() + 1);
                            Ok(())
                        }
                    )
                    .is_err()
            );
            assert_eq!(calls.get(), 1);
        }
        let stopped = Cell::new(false);
        let mut owner = OriginalCeremony::new();
        assert_eq!(
            owner.maintain_with(
                context(origin, &key, &checkpoint),
                || {
                    if stopped.get() {
                        Err(PreparationError::Cancelled)
                    } else {
                        Ok(start)
                    }
                },
                |bytes| {
                    fill(bytes)?;
                    stopped.set(true);
                    Ok(())
                }
            ),
            Err(PreparationError::Cancelled)
        );
        assert!(owner.prepared.is_none());
    }
    #[test]
    fn original_reserve_expiry_and_context_change_cannot_renew_preparation() {
        let start = Instant::now();
        let origin = origin(start);
        let key = key(4);
        let checkpoint = RegistryCheckpoint::new(32, 1, []).unwrap();
        for late in [origin.deadline - CLOSE_RESERVE, origin.deadline] {
            let count = Cell::new(0);
            let mut owner = OriginalCeremony::new();
            assert_eq!(
                owner.maintain_with(
                    context(origin, &key, &checkpoint),
                    || {
                        count.set(count.get() + 1);
                        Ok(if count.get() == 1 { start } else { late })
                    },
                    fill
                ),
                Err(PreparationError::Window)
            );
            assert!(owner.prepared.is_none());
        }
        for changed in 0..4 {
            let mut owner = OriginalCeremony::new();
            owner
                .maintain_with(context(origin, &key, &checkpoint), || Ok(start), fill)
                .unwrap();
            let mut other = origin;
            match changed {
                0 => other.generation += 1,
                1 => other.epoch = BootEpoch::from_bytes([10; 32]).unwrap(),
                2 => other.pending_id = PendingElevationId::from_bytes([11; 32]).unwrap(),
                _ => {
                    other.started += Duration::from_secs(1);
                    other.deadline += Duration::from_secs(1);
                }
            }
            assert!(
                owner
                    .maintain_with(
                        context(other, &key, &checkpoint),
                        || Ok(start + Duration::from_secs(2)),
                        fill
                    )
                    .is_err()
            );
            assert!(owner.prepared.is_none());
        }
    }
    #[test]
    fn existing_recipient_collision_and_exhausted_registry_do_not_write_or_retry() {
        let start = Instant::now();
        let origin = origin(start);
        let pc_key = key(4);
        let approval = DecisionPublicKey::from_sec1_bytes(&key(5).as_spki_der()[26..]).unwrap();
        let denial = DecisionPublicKey::from_sec1_bytes(&key(6).as_spki_der()[26..]).unwrap();
        let row = RegistryCheckpointEntry::new(
            DeviceId::from_bytes([9; 16]).unwrap(),
            1,
            DeviceKeys::new(approval, denial).unwrap(),
        )
        .unwrap();
        let checkpoint = RegistryCheckpoint::new(32, 2, [row]).unwrap();
        let before = checkpoint.clone();
        let mut owner = OriginalCeremony::new();
        assert_eq!(
            owner.maintain_with(context(origin, &pc_key, &checkpoint), || Ok(start), fill),
            Err(PreparationError::Collision)
        );
        assert_eq!(checkpoint, before);
        let exhausted = RegistryCheckpoint::new(32, u64::MAX, []).unwrap();
        let mut owner = OriginalCeremony::new();
        assert_eq!(
            owner.maintain_with(
                context(origin, &pc_key, &exhausted),
                || Ok(start),
                |_| panic!("no RNG on exhausted registry")
            ),
            Err(PreparationError::Context)
        );
    }
    #[test]
    fn changed_pc_key_checkpoint_or_backward_clock_burns_retained_preparation() {
        let start = Instant::now();
        let original = origin(start);
        let pc_key = key(4);
        let other_key = key(5);
        let checkpoint = RegistryCheckpoint::new(32, 1, []).unwrap();
        let changed_checkpoint = RegistryCheckpoint::new(32, 2, []).unwrap();
        for changed in 0..4 {
            let mut owner = OriginalCeremony::new();
            owner
                .maintain_with(
                    context(original, &pc_key, &checkpoint),
                    || Ok(start + Duration::from_secs(2)),
                    fill,
                )
                .unwrap();
            let mut current = context(original, &pc_key, &checkpoint);
            match changed {
                0 => current.pc = PcIdentity::from_bytes([12; 32]).unwrap(),
                1 => current.pc_key = &other_key,
                2 => current.checkpoint = &changed_checkpoint,
                _ => (),
            }
            assert!(
                owner
                    .maintain_with(
                        current,
                        || Ok(if changed == 3 {
                            start
                        } else {
                            start + Duration::from_secs(3)
                        }),
                        |_| panic!("no second RNG")
                    )
                    .is_err()
            );
            assert!(owner.prepared.is_none());
        }
    }
    #[test]
    fn actual_key_validation_is_twice_for_one_claim_and_never_repeated_when_prepared() {
        let start = Instant::now();
        let original = origin(start);
        let pc_key = key(4);
        let checkpoint = RegistryCheckpoint::new(32, 1, []).unwrap();
        let calls = Cell::new(0);
        let mut owner = OriginalCeremony::new();
        owner
            .maintain_with_validation(
                context(original, &pc_key, &checkpoint),
                || Ok(start),
                fill,
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(calls.get(), 2);
        owner
            .maintain_with_validation(
                context(original, &pc_key, &checkpoint),
                || Ok(start + Duration::from_secs(1)),
                |_| panic!("no new material"),
                || panic!("no idle native key query"),
            )
            .unwrap();
        for failing_call in [1, 2] {
            let mut failed = OriginalCeremony::new();
            let reads = Cell::new(0);
            let rng = Cell::new(0);
            assert_eq!(
                failed.maintain_with_validation(
                    context(original, &pc_key, &checkpoint),
                    || Ok(start),
                    |bytes| {
                        rng.set(rng.get() + 1);
                        fill(bytes)
                    },
                    || {
                        reads.set(reads.get() + 1);
                        if reads.get() == failing_call {
                            Err(PreparationError::Identity)
                        } else {
                            Ok(())
                        }
                    }
                ),
                Err(PreparationError::Identity)
            );
            assert!(failed.prepared.is_none());
            assert_eq!(rng.get(), usize::from(failing_call == 2));
            assert!(
                failed
                    .maintain_with_validation(
                        context(original, &pc_key, &checkpoint),
                        || Ok(start),
                        |_| panic!("no retry RNG"),
                        || panic!("no retry query")
                    )
                    .is_err()
            );
        }
        let other_key = key(5);
        for mismatched_call in [1, 2] {
            let reads = Cell::new(0);
            let mut owner = OriginalCeremony::new();
            assert_eq!(
                owner.maintain_with_validation(
                    context(original, &pc_key, &checkpoint),
                    || Ok(start),
                    fill,
                    || {
                        reads.set(reads.get() + 1);
                        check_pc_pin(
                            if reads.get() == mismatched_call {
                                &other_key
                            } else {
                                &pc_key
                            },
                            &pc_key,
                        )
                    }
                ),
                Err(PreparationError::Identity)
            );
            assert!(owner.prepared.is_none());
        }
        let mut expired = OriginalCeremony::new();
        let elapsed = Cell::new(false);
        assert_eq!(
            expired.maintain_with_validation(
                context(original, &pc_key, &checkpoint),
                || Ok(if elapsed.get() {
                    original.deadline - CLOSE_RESERVE
                } else {
                    start
                }),
                |_| panic!("expiry after first key read precedes RNG"),
                || {
                    elapsed.set(true);
                    Ok(())
                }
            ),
            Err(PreparationError::Window)
        );
    }
    #[test]
    fn owned_material_has_drop_wiping_and_no_plain_copy_nonce_storage() {
        use p256::elliptic_curve::zeroize::{Zeroize, ZeroizeOnDrop};
        fn requires_drop_wiping<T: ZeroizeOnDrop>() {}
        requires_drop_wiping::<Zeroizing<[u8; 112]>>();
        let mut material = Zeroizing::new([7_u8; 80]);
        material.zeroize();
        assert!(material.iter().all(|byte| *byte == 0));
        // Drop-wiping is the existing library contract, not an unsafe read of
        // released memory or a claim to erase hypothetical unowned copies.
    }
}
