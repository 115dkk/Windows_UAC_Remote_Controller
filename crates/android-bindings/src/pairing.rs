// SPDX-License-Identifier: GPL-2.0-or-later
//! Native-only creation/frozen-candidate composition. No UI/startup caller, enrollment proof,
//! separate persistence owner, attestation adjudicator or key-generation retry.

use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use android_controller::{
    CommittedPairingAcceptance, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeyMutationError, LocalKeySetDescriptor, MAX_PAIRING_ACCEPTANCE_LIFETIME,
    PairingAcceptanceContext, PairingAcceptanceError, PendingPairingAcceptance,
};
use approval_protocol::{DeviceId, PcIdentity};
use framed_transport::SocketClock;
use secure_channel::TlsPublicKey;
use service_protocol::{
    FrozenCandidateContext, InvitationContextDigest, MatchedFrozenCandidate, PairingChallenge,
    PairingComparisonCode, PairingNonce, PhoneKeyDigest, SignedEnrollmentAcceptance,
    SignedFrozenCandidate,
};

use crate::{BridgeError, MobileController, native_clock::native_callback};

pub const MAX_CREATION_CERTIFICATES: usize = 8;
pub const MAX_CREATION_CERTIFICATE_BYTES: usize = 8 * 1024;
pub const MAX_CREATION_CHAIN_BYTES: usize = 32 * 1024;

/// ORIGINAL trusted-native ceremony inputs, NOT an enrollment witness.
/// The missing real ceremony owner must establish consent/QR provenance, PC
/// pins, fresh non-reused CSPRNG handle/nonce/challenge and the original lifetime.
/// `recipient_device` is the fresh PC-selected ID from the ORIGINAL invitation,
/// never a receipt assignment. `invitation_context` must be computed from that
/// canonical original invitation, never replaced with a zero/default digest.
/// All Instants MUST use this SAME captured native clock's coordinate. Neither
/// receipt fields, renderer values nor a later clock can supply these inputs.
/// This freely constructible Rust DTO is deliberately absent from UniFFI/JS.
pub struct KeyCreationContext {
    pub handle: LocalKeyHandle,
    pub challenge: LocalAttestationChallenge,
    pub ceremony_nonce: PairingNonce,
    pub pc: PcIdentity,
    pub recipient_device: DeviceId,
    pub pc_signing_key: TlsPublicKey,
    pub pc_transport_key: TlsPublicKey,
    pub invitation_context: InvitationContextDigest,
    pub clock: Arc<dyn SocketClock>,
    pub started_at: Instant,
    pub deadline: Instant,
}
impl fmt::Debug for KeyCreationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyCreationContext([redacted], native_preconditions_required)")
    }
}

pub(crate) struct CreationState {
    controller: Weak<MobileController>,
    alive: Arc<AtomicBool>,
    original: KeyCreationContext,
    observed: Mutex<Instant>,
    cancelled: AtomicBool,
}
impl CreationState {
    fn check_owner(&self, controller: &Arc<MobileController>) -> Result<(), BridgeError> {
        if self
            .controller
            .upgrade()
            .is_none_or(|original| !Arc::ptr_eq(&original, controller))
        {
            return Err(BridgeError::InvalidObservation);
        }
        self.check_current()
    }

    fn check_current(&self) -> Result<(), BridgeError> {
        self.observe_current().map(|_| ())
    }

    fn observe_current(&self) -> Result<Instant, BridgeError> {
        if !self.alive.load(Ordering::Acquire) || self.cancelled.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        // No controller/state mutex is held across this actual native callback.
        let now = self.original.clock.now().map_err(|_| {
            self.cancelled.store(true, Ordering::Release);
            BridgeError::NativeUnavailable
        })?;
        let mut floor = self.observed.lock().map_err(|_| BridgeError::Closed)?;
        if now < *floor || now < self.original.started_at || now >= self.original.deadline {
            self.cancelled.store(true, Ordering::Release);
            return Err(BridgeError::InvalidObservation);
        }
        *floor = now;
        if !self.alive.load(Ordering::Acquire) || self.cancelled.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        Ok(now)
    }
}

/// One downward restriction over the ORIGINAL provider/coordinate. No new
/// time origin, timeout, fallback, or second observation after validation.
struct CreationClock {
    state: Weak<CreationState>,
}
impl SocketClock for CreationClock {
    fn now(&self) -> Result<Instant, framed_transport::SocketClockUnavailable> {
        let state: Arc<CreationState> = Weak::<CreationState>::upgrade(&self.state)
            .ok_or(framed_transport::SocketClockUnavailable)?;
        state
            .observe_current()
            .map_err(|_| framed_transport::SocketClockUnavailable)
    }
}

/// One owner-bound attempt. No Clone/serde/foreign constructor. Dropping before
/// Preparing releases the one ceremony slot without touching metadata or keys.
/// ```compile_fail
/// fn duplicate(value: uac_android_controller::KeyCreationIntent) {
///     let _copy = value.clone();
/// }
/// ```
#[must_use]
pub struct KeyCreationIntent {
    state: Arc<CreationState>,
}
impl KeyCreationIntent {
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
    }
}
impl fmt::Debug for KeyCreationIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyCreationIntent([redacted], one_shot)")
    }
}

/// Bounded outbound inputs obtained once from a privately minted request. This
/// record itself cannot authorize creation and is not accepted by any UI API.
#[derive(uniffi::Record)]
pub struct NativeKeyCreationInput {
    pub handle: Vec<u8>,
    pub challenge: Vec<u8>,
    pub ceremony_nonce: Vec<u8>,
}
impl fmt::Debug for NativeKeyCreationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeKeyCreationInput([redacted])")
    }
}

/// Exists ONLY after successful Preparing commit in the same exclusive inbox.
/// Native callback is synchronous and must use the existing Application key
/// owner. It may not queue a later generation from copied input or retain a key
/// wrapper in its result. Generated handle copies share one consumption bit.
#[derive(uniffi::Object)]
pub struct NativeKeyCreationRequest {
    state: Arc<CreationState>,
    taken: AtomicBool,
    closed: AtomicBool,
}
impl fmt::Debug for NativeKeyCreationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeKeyCreationRequest([redacted], preparing_committed)")
    }
}
#[uniffi::export]
impl NativeKeyCreationRequest {
    /// This fresh observation, not a bare bool, gates late callback delivery.
    /// Called again immediately before native creation; no controller reentry.
    pub fn check_current(&self) -> Result<(), BridgeError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        self.state.check_current()?;
        if self.closed.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        Ok(())
    }
    pub fn take_input(&self) -> Result<NativeKeyCreationInput, BridgeError> {
        if self.taken.swap(true, Ordering::AcqRel) {
            return Err(BridgeError::InvalidObservation);
        }
        self.check_current()?;
        let original = &self.state.original;
        Ok(NativeKeyCreationInput {
            handle: original.handle.as_bytes().to_vec(),
            challenge: original.challenge.as_bytes().to_vec(),
            ceremony_nonce: original.ceremony_nonce.as_bytes().to_vec(),
        })
    }
}
struct RequestScope(Arc<NativeKeyCreationRequest>);
impl Drop for RequestScope {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
    }
}

/// Public, unverified evidence. Native bounds apply BEFORE callback conversion;
/// Rust repeats them before retention. No certificate/role trust is inferred.
#[derive(uniffi::Record)]
pub struct NativeCreatedRoleEvidence {
    pub spki: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
}
impl fmt::Debug for NativeCreatedRoleEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeCreatedRoleEvidence([redacted], unverified)")
    }
}
impl NativeCreatedRoleEvidence {
    fn validate(&self) -> Result<TlsPublicKey, BridgeError> {
        if self.certificates.is_empty()
            || self.certificates.len() > MAX_CREATION_CERTIFICATES
            || self.certificates.iter().any(|certificate| {
                certificate.is_empty() || certificate.len() > MAX_CREATION_CERTIFICATE_BYTES
            })
            || self.certificates.iter().map(Vec::len).sum::<usize>() > MAX_CREATION_CHAIN_BYTES
        {
            return Err(BridgeError::InvalidObservation);
        }
        TlsPublicKey::from_spki_der(&self.spki).map_err(|_| BridgeError::InvalidObservation)
    }
}

/// Fixed role fields prevent an open-ended map, duplicate/missing roles or a
/// fourth role. Bytes are not native-reference wrappers or attestation proof.
#[derive(uniffi::Record)]
pub struct NativeCreatedKeyEvidence {
    pub handle: Vec<u8>,
    pub challenge: Vec<u8>,
    pub ceremony_nonce: Vec<u8>,
    pub approval: NativeCreatedRoleEvidence,
    pub denial: NativeCreatedRoleEvidence,
    pub transport: NativeCreatedRoleEvidence,
}
impl fmt::Debug for NativeCreatedKeyEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeCreatedKeyEvidence([redacted], unverified)")
    }
}
impl NativeCreatedKeyEvidence {
    fn descriptor(
        &self,
        original: &KeyCreationContext,
    ) -> Result<LocalKeySetDescriptor, BridgeError> {
        if self.handle.as_slice() != original.handle.as_bytes()
            || self.challenge.as_slice() != original.challenge.as_bytes()
            || self.ceremony_nonce.as_slice() != original.ceremony_nonce.as_bytes()
        {
            return Err(BridgeError::InvalidObservation);
        }
        let descriptor = LocalKeySetDescriptor::new(
            original.handle,
            original.challenge,
            self.approval.validate()?,
            self.denial.validate()?,
            self.transport.validate()?,
        )
        .map_err(|_| BridgeError::InvalidObservation)?;
        if [
            descriptor.approval_key(),
            descriptor.denial_key(),
            descriptor.transport_key(),
        ]
        .into_iter()
        .any(|key| key == &original.pc_signing_key || key == &original.pc_transport_key)
        {
            return Err(BridgeError::InvalidObservation);
        }
        Ok(descriptor)
    }
}

/// Only CreatedUnverified was committed. Holds bounded PUBLIC evidence and the
/// existing one-shot PendingPairingAcceptance, never a hidden native key wrapper.
/// Retains the single ceremony slot until drop or acceptance consumption. Drop
/// abandons the ceremony; it does not delete keys or erase committed metadata.
/// No comparison code or final-commit capability exists before a signed frozen
/// candidate matches the independently retained original native context.
/// ```compile_fail
/// fn display_before_matching(value: uac_android_controller::CreatedPairingKeys) {
///     let _code = value.comparison_code();
/// }
/// ```
/// ```compile_fail
/// fn duplicate(value: uac_android_controller::CreatedPairingKeys) {
///     let _copy = value.clone();
/// }
/// ```
#[must_use]
pub struct CreatedPairingKeys {
    state: Arc<CreationState>,
    local_keys: LocalKeySetDescriptor,
    evidence: NativeCreatedKeyEvidence,
    pending: PendingPairingAcceptance,
}
impl CreatedPairingKeys {
    pub fn local_keys(&self) -> &LocalKeySetDescriptor {
        &self.local_keys
    }
    pub fn unverified_evidence(&self) -> &NativeCreatedKeyEvidence {
        &self.evidence
    }
    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Release);
        self.pending.cancel();
    }
}
impl fmt::Debug for CreatedPairingKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreatedPairingKeys([redacted], not_paired)")
    }
}

/// One matched signed candidate retains the original CreatedUnverified result
/// and its existing one-shot acceptance reservation. Private fields prevent a
/// caller from supplying an expected tuple, replacing the candidate or bypassing
/// the original clock/controller. No Clone, serialization or foreign surface.
/// This is not proof of native display, consent, attestation or a remote commit.
/// ```compile_fail
/// fn duplicate(value: uac_android_controller::FrozenCreatedPairing) {
///     let _copy = value.clone();
/// }
/// ```
/// ```compile_fail
/// fn commit_before_matching(
///     controller: std::sync::Arc<uac_android_controller::MobileController>,
///     created: uac_android_controller::CreatedPairingKeys,
///     wire: &[u8],
/// ) {
///     let _ = controller.commit_created_pairing(created, wire);
/// }
/// ```
#[must_use]
pub struct FrozenCreatedPairing {
    created: CreatedPairingKeys,
    matched: MatchedFrozenCandidate,
}
impl FrozenCreatedPairing {
    /// Public comparison metadata only, freshly guarded by the same original
    /// native clock before and after derivation. A returned code is not a live
    /// display/confirmation capability and must not be used as authorization.
    pub fn comparison_code(&self) -> Result<PairingComparisonCode, BridgeError> {
        let controller = self
            .created
            .state
            .controller
            .upgrade()
            .ok_or(BridgeError::Closed)?;
        let _admission = controller.enter()?;
        self.created.state.check_owner(&controller)?;
        let code = self.matched.comparison_code();
        self.created.state.check_current()?;
        Ok(code)
    }

    pub fn cancel(&self) {
        self.created.cancel();
    }

    fn check_acceptance(&self, wire: &[u8]) -> Result<(), BridgeError> {
        // The pin remains independent of BOTH received statements. This guard
        // supplements, rather than replaces, the durable owner's original
        // signature/context/key-lifecycle verification below.
        let acceptance = SignedEnrollmentAcceptance::from_wire(wire)
            .and_then(|signed| signed.verify(&self.created.state.original.pc_signing_key))
            .map_err(|_| BridgeError::InvalidObservation)?;
        let fields = acceptance.fields();
        let frozen = self.matched.fields();
        let expected = &frozen.context;
        if fields.ceremony_nonce != expected.ceremony_nonce
            || fields.attestation_challenge != expected.attestation_challenge
            || fields.pc != expected.pc
            || fields.recipient_device != expected.recipient_device
            || fields.phone_keys != expected.phone_keys
            || fields.pc_signing_key != expected.pc_signing_key
            || fields.pc_transport_key != expected.pc_transport_key
            || fields.registry_revision != frozen.intended_registry_revision
        {
            return Err(BridgeError::InvalidObservation);
        }
        Ok(())
    }
}
impl fmt::Debug for FrozenCreatedPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrozenCreatedPairing([redacted], matched_not_paired)")
    }
}

/// Rust-only disposition, never serialized or exported through UniFFI. An
/// uncertain storage rejection is not a rollback claim. If a receipt exists,
/// late loss of original liveness MUST preserve that observed local commit.
#[derive(thiserror::Error)]
pub enum CreatedPairingCommitError {
    #[error("pairing acceptance did not produce a confirmed local receipt")]
    Rejected(BridgeError),
    #[error("the local association committed but the original ceremony is no longer live")]
    CommittedButNotLive {
        committed: CommittedPairingAcceptance,
        cause: BridgeError,
    },
}
impl fmt::Debug for CreatedPairingCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Rejected(_) => "CreatedPairingCommitError::Rejected([redacted])",
            Self::CommittedButNotLive { .. } => {
                "CreatedPairingCommitError::CommittedButNotLive([redacted])"
            }
        })
    }
}

// Deliberately NOT #[uniffi::export]: only future trusted native Rust ceremony
// composition may start/finish this flow. No UI, boot or Activity caller exists.
impl MobileController {
    pub fn begin_key_creation_from_trusted_host(
        self: &Arc<Self>,
        original: KeyCreationContext,
    ) -> Result<KeyCreationIntent, BridgeError> {
        let _admission = self.enter()?;
        self.read_clock()?;
        if original
            .deadline
            .checked_duration_since(original.started_at)
            .is_none_or(|duration| duration.is_zero() || duration > MAX_PAIRING_ACCEPTANCE_LIFETIME)
        {
            return Err(BridgeError::InvalidObservation);
        }
        let state = Arc::new(CreationState {
            controller: Arc::downgrade(self),
            alive: Arc::clone(&self.approval_alive),
            observed: Mutex::new(original.started_at),
            original,
            cancelled: AtomicBool::new(false),
        });
        state.check_owner(self)?;
        self.with_inbox(|owner| require_unused(owner, &state.original))?;
        let mut slot = self.creation_slot.lock().map_err(|_| BridgeError::Closed)?;
        if Weak::<CreationState>::upgrade(&*slot).is_some() {
            return Err(BridgeError::Busy);
        }
        *slot = Arc::downgrade(&state);
        Ok(KeyCreationIntent { state })
    }

    pub fn create_pairing_keys(
        self: &Arc<Self>,
        intent: KeyCreationIntent,
    ) -> Result<CreatedPairingKeys, BridgeError> {
        let _admission = self.enter()?;
        intent.state.check_owner(self)?;
        self.read_clock()?;
        let mut prepared = false;
        let result = self.with_inbox(|owner| {
            require_unused(owner, &intent.state.original)?;
            intent.state.check_current()?;
            let _ = owner
                .begin_local_key_creation(
                    intent.state.original.handle,
                    intent.state.original.challenge,
                )
                .map_err(local_error)?;
            prepared = true;
            // Before ANY callback: failure/unwind may follow native publication.
            self.key_cleanup_pending.store(true, Ordering::Release);
            // A blocking Preparing flush may have consumed the whole lifetime.
            intent.state.check_current()?;
            let request = Arc::new(NativeKeyCreationRequest {
                state: Arc::clone(&intent.state),
                taken: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            });
            let scope = RequestScope(Arc::clone(&request));
            let evidence =
                native_callback(|| self.platform.create_local_key_set(Arc::clone(&request)));
            drop(scope); // Late native handle copies can never obtain another input.
            let evidence = evidence?;
            if !request.taken.load(Ordering::Acquire) {
                return Err(BridgeError::InvalidObservation);
            }
            let descriptor = evidence.descriptor(&intent.state.original)?;
            intent.state.check_current()?;
            let _ = owner
                .record_local_key_creation(descriptor.clone())
                .map_err(local_error)?;
            let original = &intent.state.original;
            let pending = owner
                .begin_pairing_acceptance_from_trusted_host(PairingAcceptanceContext {
                    local_keys: descriptor.clone(),
                    pc: original.pc,
                    pc_signing_key: original.pc_signing_key.clone(),
                    pc_transport_key: original.pc_transport_key.clone(),
                    ceremony_nonce: original.ceremony_nonce,
                    clock: Arc::new(CreationClock {
                        state: Arc::downgrade(&intent.state),
                    }),
                    started_at: original.started_at,
                    deadline: original.deadline,
                })
                .map_err(pairing_error)?;
            // A blocking final flush or native stop can outlast the previously
            // checked mutation point. Retain actual committed metadata, but do
            // not publish live ceremony state after original liveness expires.
            intent.state.check_current()?;
            Ok(CreatedPairingKeys {
                state: Arc::clone(&intent.state),
                local_keys: descriptor,
                evidence,
                pending,
            })
        });
        if prepared && let Err(error) = result {
            // No retry/create-on-error. Preparing (or an already completed
            // final commit) remains for explicit reconciliation; no rollback.
            intent.state.cancelled.store(true, Ordering::Release);
            if matches!(
                error,
                BridgeError::StorageUnavailable | BridgeError::OwnerFaulted | BridgeError::Closed
            ) {
                // with_inbox already restored/closed the owner for these faults.
                // Preserve the primary error; do not repeat native cleanup.
                return Err(error);
            }
            return self.fail_closed(BridgeError::LocalKeysReconciliationRequired);
        }
        result
    }

    /// Consume one created result and one bounded candidate wire. Its expected
    /// context comes ONLY from the original native inputs and actual retained
    /// three-role descriptor, never from this reply or caller-supplied fields.
    /// Rejection consumes the attempt without changing CreatedUnverified bytes.
    pub fn match_frozen_candidate(
        self: &Arc<Self>,
        created: CreatedPairingKeys,
        wire: &[u8],
    ) -> Result<FrozenCreatedPairing, BridgeError> {
        let _admission = self.enter()?;
        created.state.check_owner(self)?;
        let original = &created.state.original;
        let expected = FrozenCandidateContext {
            ceremony_nonce: original.ceremony_nonce,
            attestation_challenge: PairingChallenge::from_bytes(*original.challenge.as_bytes())
                .map_err(|_| BridgeError::InvalidObservation)?,
            pc: original.pc,
            recipient_device: original.recipient_device,
            phone_keys: PhoneKeyDigest::from_keys(
                created.local_keys.approval_key(),
                created.local_keys.denial_key(),
                created.local_keys.transport_key(),
            )
            .map_err(|_| BridgeError::InvalidObservation)?,
            pc_signing_key: original.pc_signing_key.clone(),
            pc_transport_key: original.pc_transport_key.clone(),
            invitation_context: original.invitation_context,
        };
        let matched = SignedFrozenCandidate::from_wire(wire)
            .and_then(|signed| signed.verify(&original.pc_signing_key))
            .and_then(|verified| verified.match_original(&expected))
            .map_err(|_| BridgeError::InvalidObservation)?;
        // Native cancellation, stop, expiry or regression during parsing and
        // signature work cannot publish a live code/commit-bearing wrapper.
        created.state.check_owner(self)?;
        Ok(FrozenCreatedPairing { created, matched })
    }

    /// Requires the exact retained frozen candidate, then reuses the existing
    /// signed-acceptance codec/checkpoint owner unchanged. There is no legacy
    /// overload accepting a merely created or signature-only candidate.
    /// A successful result witnesses only this phone's LOCAL association commit.
    pub fn commit_created_pairing(
        self: &Arc<Self>,
        frozen: FrozenCreatedPairing,
        wire: &[u8],
    ) -> Result<CommittedPairingAcceptance, CreatedPairingCommitError> {
        let _admission = self.enter().map_err(CreatedPairingCommitError::Rejected)?;
        frozen
            .created
            .state
            .check_owner(self)
            .map_err(CreatedPairingCommitError::Rejected)?;
        frozen
            .check_acceptance(wire)
            .map_err(CreatedPairingCommitError::Rejected)?;
        frozen
            .created
            .state
            .check_current()
            .map_err(CreatedPairingCommitError::Rejected)?;
        let created = frozen.created;
        let committed = self
            .with_inbox(|owner| {
                owner
                    .commit_pairing_acceptance(created.pending, wire)
                    .map_err(pairing_error)
            })
            .map_err(CreatedPairingCommitError::Rejected)?;
        // Preserve an actual completed local commit if stop/expiry arrives
        // during blocking flush or this final native observation. Never return
        // Ok for lost liveness and never report that its bytes rolled back.
        if let Err(cause) = created.state.check_current() {
            return Err(CreatedPairingCommitError::CommittedButNotLive { committed, cause });
        }
        Ok(committed)
    }
}

fn require_unused(owner: &DurableInbox, context: &KeyCreationContext) -> Result<(), BridgeError> {
    if owner
        .inbox_fault()
        .map_err(|_| BridgeError::StorageUnavailable)?
        .is_some()
    {
        return Err(BridgeError::OwnerFaulted);
    }
    let keys = owner
        .local_keys()
        .map_err(|_| BridgeError::StorageUnavailable)?;
    let mut candidate = keys.clone();
    candidate
        .begin_creation(context.handle, context.challenge)
        .map_err(|_| BridgeError::InvalidObservation)?;
    let peers = owner
        .peer_associations()
        .map_err(|_| BridgeError::StorageUnavailable)?;
    for peer in peers.entries() {
        let peer = peer.descriptor();
        if peer.pc() == context.pc
            || [peer.pc_signing_key(), peer.pc_transport_key()]
                .into_iter()
                .any(|key| key == &context.pc_signing_key || key == &context.pc_transport_key)
        {
            return Err(BridgeError::InvalidObservation);
        }
    }
    for key in keys.entries().filter_map(|phase| phase.descriptor()) {
        if [key.approval_key(), key.denial_key(), key.transport_key()]
            .into_iter()
            .any(|key| key == &context.pc_signing_key || key == &context.pc_transport_key)
        {
            return Err(BridgeError::InvalidObservation);
        }
    }
    Ok(())
}
fn local_error(error: LocalKeyMutationError) -> BridgeError {
    match error {
        LocalKeyMutationError::Owner(_) => BridgeError::StorageUnavailable,
        _ => BridgeError::InvalidObservation,
    }
}
fn pairing_error(error: PairingAcceptanceError) -> BridgeError {
    match error {
        PairingAcceptanceError::DomainFault(_) => BridgeError::OwnerFaulted,
        PairingAcceptanceError::Association(
            android_controller::PeerAssociationMutationError::Owner(_),
        ) => BridgeError::StorageUnavailable,
        _ => BridgeError::InvalidObservation,
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests;
