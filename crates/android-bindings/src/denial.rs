// SPDX-License-Identifier: GPL-2.0-or-later
//! Native-only, request-scoped denial fences. Prepared data is UNSENT: there
//! is no transport map, positive intake activation, renderer API or OS result.
use crate::{BridgeError, MobileController, NativeLocalKeySet, NativeRequestSelection};
use android_controller::{
    AssociatedPendingRequest, DenialAttempt, DenialError, DenialOwner, DenialTransition,
    DurableInbox, LocalKeySetDescriptor, PeerAssociation, PreparedDenial,
};
use notification_policy::RequestKey;
use phone_request_core::PhoneBootId;
use service_protocol::MappedRequestWindow;
use std::{
    fmt,
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

const MAX_SCOPES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeApprovalDrainState {
    NoMatchingSession,
    Pending,
    Retired,
    Failed,
}
/// Quiescent requires a registered exact operation, terminal/no restart, all
/// actually started provider calls returned (zero calls allowed), and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeDenialOperationState {
    NotStarted,
    Running,
    Quiescent,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeDenialWait {
    ApprovalNative,
    ApprovalCore,
    DenialSlot,
    Transport,
}
#[derive(Debug, uniffi::Enum)]
pub enum NativeDenialAdvance {
    Waiting {
        reason: NativeDenialWait,
    },
    Ready {
        attempt: Arc<NativeDenialAttempt>,
    },
    Prepared,
    /// Reserved for future actual private transport integration; never produced
    /// by this prepared-unsent implementation.
    AwaitingOutcome,
    CleanupPending,
    CleanupFailed,
    Released,
}

#[derive(Clone)]
struct BoundScope {
    window: MappedRequestWindow,
    boot: PhoneBootId,
    deadline: u64,
    association: PeerAssociation,
    keys: LocalKeySetDescriptor,
}
impl BoundScope {
    fn capture(request: &AssociatedPendingRequest, boot: PhoneBootId) -> Result<Self, BridgeError> {
        let pending = request.request();
        if pending
            .receiving_generation()
            .is_none_or(|generation| generation.get() != request.association().generation())
        {
            return Err(BridgeError::DenialRejected);
        }
        let floor = pending
            .notification()
            .expires_at
            .as_millis()
            .checked_mul(1_000_000)
            .ok_or(BridgeError::InvalidObservation)?;
        Ok(Self {
            window: pending.original_window(),
            boot,
            deadline: pending.original_window().phone_expiry_nanos().min(floor),
            association: request.association().clone(),
            keys: request.local_keys().clone(),
        })
    }
    fn key(&self) -> RequestKey {
        phone_request_core::request_key(self.window.binding())
    }
    fn matches(&self, other: &Self) -> bool {
        self.window == other.window
            && self.boot == other.boot
            && self.deadline == other.deadline
            && self.association == other.association
            && self.keys == other.keys
    }
    fn matches_attempt(&self, attempt: &DenialAttempt) -> bool {
        self.window == attempt.original_window()
            && self.boot == attempt.phone_boot()
            && self.deadline == attempt.deadline_nanos()
            && &self.association == attempt.association()
            && &self.keys == attempt.local_keys()
    }
}
struct ScopeSignal {
    bound: BoundScope,
    controller_alive: Arc<AtomicBool>,
    cancelled: AtomicBool,
    released: AtomicBool,
    attempt: OnceLock<Arc<AttemptControl>>,
}
impl ScopeSignal {
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || !self.controller_alive.load(Ordering::Acquire)
            || self.released.load(Ordering::Acquire)
    }
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(attempt) = self.attempt.get() {
            attempt.core.cancel();
        }
    }
}
#[derive(uniffi::Object)]
pub struct NativeDenialScope {
    signal: Arc<ScopeSignal>,
}
impl fmt::Debug for NativeDenialScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeDenialScope([redacted], not_quiescence)")
    }
}
#[uniffi::export]
impl NativeDenialScope {
    pub fn request(&self) -> NativeRequestSelection {
        NativeRequestSelection::from_key(self.signal.bound.key())
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.signal.bound.deadline
    }
    pub fn same_scope(&self, other: Arc<NativeDenialScope>) -> bool {
        Arc::ptr_eq(&self.signal, &other.signal)
    }
    pub fn is_cancelled(&self) -> bool {
        self.signal.cancelled()
    }
    pub fn cancel(&self) {
        self.signal.cancel();
    }
}
struct AttemptControl {
    core: DenialAttempt,
    scope: Weak<ScopeSignal>,
    bytes_taken: AtomicBool,
    finish_taken: AtomicBool,
    native_closed: AtomicBool,
}
#[derive(uniffi::Object)]
pub struct NativeDenialAttempt {
    control: Arc<AttemptControl>,
}
impl fmt::Debug for NativeDenialAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeDenialAttempt([redacted])")
    }
}
#[uniffi::export]
impl NativeDenialAttempt {
    pub fn belongs_to(&self, scope: Arc<NativeDenialScope>) -> bool {
        self.control
            .scope
            .upgrade()
            .is_some_and(|own| Arc::ptr_eq(&own, &scope.signal))
    }
    pub fn local_keys(&self) -> Result<NativeLocalKeySet, BridgeError> {
        if self.is_cancelled() {
            return Err(BridgeError::DenialRejected);
        }
        Ok(NativeLocalKeySet::from_descriptor(
            self.control.core.local_keys(),
        ))
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.control.core.deadline_nanos()
    }
    pub fn is_cancelled(&self) -> bool {
        self.control.native_closed.load(Ordering::Acquire)
            || self.control.core.is_cancelled()
            || self
                .control
                .scope
                .upgrade()
                .is_none_or(|scope| scope.cancelled())
    }
    pub fn cancel(&self) {
        self.control.core.cancel();
        if let Some(scope) = self.control.scope.upgrade() {
            scope.cancel();
        }
    }
    pub fn take_signing_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        if self.is_cancelled()
            || self
                .control
                .bytes_taken
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(BridgeError::DenialRejected);
        }
        let bytes = self
            .control
            .core
            .signing_bytes()
            .map_err(|_| BridgeError::DenialRejected)?;
        if self.is_cancelled() {
            return Err(BridgeError::DenialRejected);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Drain,
    Ready,
    Finished,
    Settling,
}
struct ScopeEntry {
    scope: Arc<NativeDenialScope>,
    phase: Phase,
    failed: bool,
    approval_drained: bool,
    operation_quiescent: bool,
    native_retired: bool,
    prepared: Option<PreparedDenial>,
}
pub(crate) struct DenialState {
    owner: Option<DenialOwner>,
    scopes: Vec<ScopeEntry>,
    uncertain: bool,
}
impl DenialState {
    pub(crate) fn new(owner: &DurableInbox, boot: PhoneBootId) -> Result<Self, BridgeError> {
        Ok(Self {
            owner: Some(DenialOwner::new(owner, boot).map_err(|_| BridgeError::OwnerFaulted)?),
            scopes: Vec::new(),
            uncertain: false,
        })
    }
}

#[uniffi::export]
impl MobileController {
    pub fn reserve_denial(
        &self,
        request: NativeRequestSelection,
    ) -> Result<Arc<NativeDenialScope>, BridgeError> {
        let key = request.key()?;
        let _admission = self.enter()?;
        self.require_live_denial_owner()?;
        {
            let mut state = self.denial_state.lock().map_err(|_| BridgeError::Closed)?;
            if let Some(entry) = state
                .scopes
                .iter()
                .find(|entry| entry.scope.signal.bound.key() == key)
            {
                return Ok(Arc::clone(&entry.scope));
            }
            if state.scopes.len() >= MAX_SCOPES {
                return Err(BridgeError::Busy);
            }
            state
                .scopes
                .try_reserve_exact(1)
                .map_err(|_| BridgeError::NativeUnavailable)?;
        }
        let bound = self.check_denial_bound(key, None)?;
        let scope = Arc::new(NativeDenialScope {
            signal: Arc::new(ScopeSignal {
                bound,
                controller_alive: Arc::clone(&self.approval_alive),
                cancelled: AtomicBool::new(false),
                released: AtomicBool::new(false),
                attempt: OnceLock::new(),
            }),
        });
        // Fence is retained BEFORE cancellation. Any later failure keeps it.
        self.denial_state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .scopes
            .push(ScopeEntry {
                scope: Arc::clone(&scope),
                phase: Phase::Drain,
                failed: false,
                approval_drained: false,
                operation_quiescent: false,
                native_retired: false,
                prepared: None,
            });
        let cancelled = (|| {
            let mut plans = self
                .approval_owner
                .lock()
                .map_err(|_| BridgeError::Closed)?;
            let receipt = plans
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .cancel_request(key);
            let _ = receipt;
            Ok::<_, BridgeError>(())
        })();
        if let Err(error) = cancelled {
            scope.cancel();
            return self.fail_closed(error);
        }
        Ok(scope)
    }

    pub fn advance_denial(
        &self,
        scope: Arc<NativeDenialScope>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        let _admission = self.enter()?;
        self.require_scope(&scope)?;
        if scope.signal.released.load(Ordering::Acquire) {
            return Ok(NativeDenialAdvance::Released);
        }
        if self.with_scope(&scope, |entry| entry.failed)? {
            return Ok(NativeDenialAdvance::CleanupFailed);
        }
        if scope.is_cancelled() {
            return self.settle_denial_admitted(&scope);
        }
        let phase = self.with_scope(&scope, |entry| {
            if entry
                .prepared
                .as_ref()
                .is_some_and(PreparedDenial::is_cancelled)
            {
                entry.scope.cancel();
            }
            entry.phase
        })?;
        if scope.is_cancelled() {
            return self.settle_denial_admitted(&scope);
        }
        if matches!(phase, Phase::Ready | Phase::Finished)
            && let Err(error) = self.seal_denial_bound(&scope.signal.bound)
        {
            scope.cancel();
            return Err(error);
        }
        if phase == Phase::Finished {
            if scope.is_cancelled()
                || self.with_scope(&scope, |entry| {
                    entry
                        .prepared
                        .as_ref()
                        .is_none_or(PreparedDenial::is_cancelled)
                })?
            {
                scope.cancel();
                return Err(BridgeError::DenialRejected);
            }
            return Ok(NativeDenialAdvance::Prepared);
        }
        if phase == Phase::Settling {
            return self.settle_denial_admitted(&scope);
        }
        if let Some(control) = scope.signal.attempt.get() {
            let attempt = Arc::new(NativeDenialAttempt {
                control: Arc::clone(control),
            });
            if attempt.is_cancelled() {
                scope.cancel();
                return Err(BridgeError::DenialRejected);
            }
            return Ok(NativeDenialAdvance::Ready { attempt });
        }
        if let Some(wait) = self.observe_approval_drain(&scope)? {
            return Ok(wait);
        }
        if let Err(error) =
            self.check_denial_bound(scope.signal.bound.key(), Some(&scope.signal.bound))
        {
            scope.cancel();
            return Err(error);
        }
        let result = self.run_denial(
            |owner, inbox, clock| owner.begin(inbox, scope.signal.bound.key(), clock),
            |core| {
                let matches = scope.signal.bound.matches_attempt(&core);
                let control = Arc::new(AttemptControl {
                    core,
                    scope: Arc::downgrade(&scope.signal),
                    bytes_taken: AtomicBool::new(false),
                    finish_taken: AtomicBool::new(false),
                    native_closed: AtomicBool::new(false),
                });
                if scope.signal.attempt.set(Arc::clone(&control)).is_err() {
                    scope.cancel();
                    return Err(BridgeError::DenialRejected);
                }
                if scope.is_cancelled() || !matches {
                    scope.cancel();
                }
                self.with_scope(&scope, |entry| entry.phase = Phase::Ready)?;
                Ok(Arc::new(NativeDenialAttempt { control }))
            },
        );
        match result {
            Ok(attempt) => {
                if let Err(error) = self.seal_denial_bound(&scope.signal.bound) {
                    scope.cancel();
                    return Err(error);
                }
                if scope.is_cancelled() || attempt.is_cancelled() {
                    scope.cancel();
                    return Err(BridgeError::DenialRejected);
                }
                Ok(NativeDenialAdvance::Ready { attempt })
            }
            Err(BridgeError::Busy) => Ok(NativeDenialAdvance::Waiting {
                reason: NativeDenialWait::DenialSlot,
            }),
            Err(error) => {
                scope.cancel();
                Err(error)
            }
        }
    }

    pub fn finish_denial(
        &self,
        attempt: Arc<NativeDenialAttempt>,
        der: Vec<u8>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        let _admission = self.enter()?;
        self.require_live_denial_owner()?;
        let signal = attempt
            .control
            .scope
            .upgrade()
            .ok_or(BridgeError::DenialRejected)?;
        let scope = Arc::new(NativeDenialScope { signal });
        self.require_scope(&scope)?;
        if !attempt.control.bytes_taken.load(Ordering::Acquire)
            || attempt
                .control
                .finish_taken
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            scope.cancel();
            return Err(BridgeError::DenialRejected);
        }
        let result = self.run_denial(
            |owner, inbox, clock| owner.finish(inbox, &attempt.control.core, &der, clock),
            |prepared| {
                self.with_scope(&scope, |entry| {
                    entry.prepared = Some(prepared);
                    entry.phase = Phase::Finished;
                })
            },
        );
        attempt.control.native_closed.store(true, Ordering::Release);
        if let Err(error) = result {
            scope.cancel();
            return Err(error);
        }
        if let Err(error) = self.seal_denial_bound(&scope.signal.bound) {
            scope.cancel();
            return Err(error);
        }
        if scope.is_cancelled() {
            return Err(BridgeError::DenialRejected);
        }
        Ok(NativeDenialAdvance::Prepared)
    }

    pub fn retire_denial_native(
        &self,
        scope: Arc<NativeDenialScope>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        let _admission = self.enter()?;
        self.require_scope(&scope)?;
        if scope.signal.released.load(Ordering::Acquire) {
            return Ok(NativeDenialAdvance::Released);
        }
        if !scope.is_cancelled()
            && self.with_scope(&scope, |entry| {
                entry.phase != Phase::Finished || entry.prepared.is_none()
            })?
        {
            return Ok(NativeDenialAdvance::CleanupPending);
        }
        if let Some(wait) = self.retire_denial_admitted(&scope)? {
            return Ok(wait);
        }
        if scope.is_cancelled() {
            return self.settle_denial_admitted(&scope);
        }
        if self.seal_denial_bound(&scope.signal.bound).is_err() {
            scope.cancel();
            return self.settle_denial_admitted(&scope);
        }
        if scope.is_cancelled()
            || self.with_scope(&scope, |entry| {
                entry
                    .prepared
                    .as_ref()
                    .is_none_or(PreparedDenial::is_cancelled)
            })?
        {
            scope.cancel();
            return self.settle_denial_admitted(&scope);
        }
        Ok(NativeDenialAdvance::Prepared)
    }

    /// Prepared state is UNSENT. Settlement requires explicit cancellation;
    /// merely retiring the native slot never drops the signature or fence.
    pub fn settle_denial(
        &self,
        scope: Arc<NativeDenialScope>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        let _admission = self.enter()?;
        self.require_scope(&scope)?;
        self.settle_denial_admitted(&scope)
    }

    /// Caller must first explicitly resume any native failed cursor outside
    /// admission. One retry, permanently cancelled, never another signing grant.
    pub fn retry_denial_cleanup(
        &self,
        scope: Arc<NativeDenialScope>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        let _admission = self.enter()?;
        self.require_scope(&scope)?;
        if scope.signal.released.load(Ordering::Acquire) {
            return Ok(NativeDenialAdvance::Released);
        }
        scope.cancel();
        self.with_scope(&scope, |entry| entry.failed = false)?;
        self.settle_denial_admitted(&scope)
    }
}

impl MobileController {
    pub(crate) fn denial_fence(&self, key: RequestKey) -> Result<(), BridgeError> {
        if self
            .denial_state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .scopes
            .iter()
            .any(|entry| entry.scope.signal.bound.key() == key)
        {
            return Err(BridgeError::ApprovalRejected);
        }
        Ok(())
    }
    pub(crate) fn cancel_denial_request(&self, key: RequestKey) {
        let state = self
            .denial_state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for entry in &state.scopes {
            if entry.scope.signal.bound.key() == key {
                entry.scope.cancel();
            }
        }
    }
    fn require_live_denial_owner(&self) -> Result<(), BridgeError> {
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        Ok(())
    }
    fn require_scope(&self, scope: &NativeDenialScope) -> Result<(), BridgeError> {
        if !Arc::ptr_eq(&self.approval_alive, &scope.signal.controller_alive) {
            return Err(BridgeError::DenialRejected);
        }
        if scope.signal.released.load(Ordering::Acquire) {
            return Ok(());
        }
        self.with_scope(scope, |_| ())
    }
    fn with_scope<T>(
        &self,
        scope: &NativeDenialScope,
        action: impl FnOnce(&mut ScopeEntry) -> T,
    ) -> Result<T, BridgeError> {
        let mut state = self.denial_state.lock().map_err(|_| BridgeError::Closed)?;
        let entry = state
            .scopes
            .iter_mut()
            .find(|entry| Arc::ptr_eq(&entry.scope.signal, &scope.signal))
            .ok_or(BridgeError::DenialRejected)?;
        Ok(action(entry))
    }
    fn fail_scope(&self, scope: &NativeDenialScope) -> Result<NativeDenialAdvance, BridgeError> {
        scope.cancel();
        self.with_scope(scope, |entry| {
            entry.failed = true;
            entry.phase = Phase::Settling;
            entry.prepared.take();
        })?;
        Ok(NativeDenialAdvance::CleanupFailed)
    }
    fn observe_approval_drain(
        &self,
        scope: &Arc<NativeDenialScope>,
    ) -> Result<Option<NativeDenialAdvance>, BridgeError> {
        if self.with_scope(scope, |entry| entry.failed)? {
            return Ok(Some(NativeDenialAdvance::CleanupFailed));
        }
        if !self.with_scope(scope, |entry| entry.approval_drained)? {
            match self
                .platform
                .advance_approval_drain_for_denial(Arc::clone(scope))
            {
                Ok(
                    NativeApprovalDrainState::NoMatchingSession | NativeApprovalDrainState::Retired,
                ) => self.with_scope(scope, |entry| entry.approval_drained = true)?,
                Ok(NativeApprovalDrainState::Pending) => {
                    return Ok(Some(NativeDenialAdvance::Waiting {
                        reason: NativeDenialWait::ApprovalNative,
                    }));
                }
                Ok(NativeApprovalDrainState::Failed) | Err(_) => {
                    return self.fail_scope(scope).map(Some);
                }
            }
        }
        let plans = self
            .approval_owner
            .lock()
            .map_err(|_| BridgeError::Closed)?;
        if plans
            .as_ref()
            .is_some_and(|plans| plans.has_native_slot_for(scope.signal.bound.key()))
        {
            return Ok(Some(NativeDenialAdvance::Waiting {
                reason: NativeDenialWait::ApprovalCore,
            }));
        }
        Ok(None)
    }
    fn retire_denial_admitted(
        &self,
        scope: &Arc<NativeDenialScope>,
    ) -> Result<Option<NativeDenialAdvance>, BridgeError> {
        if self.with_scope(scope, |entry| entry.failed)? {
            return Ok(Some(NativeDenialAdvance::CleanupFailed));
        }
        if self.with_scope(scope, |entry| entry.native_retired)? {
            return Ok(None);
        }
        let Some(control) = scope.signal.attempt.get() else {
            self.with_scope(scope, |entry| entry.native_retired = true)?;
            return Ok(None);
        };
        if !self.with_scope(scope, |entry| entry.operation_quiescent)? {
            let attempt = Arc::new(NativeDenialAttempt {
                control: Arc::clone(control),
            });
            match self.platform.observe_denial_operation(attempt) {
                Ok(NativeDenialOperationState::Quiescent) => (),
                Ok(NativeDenialOperationState::NotStarted)
                    if scope.is_cancelled() && !control.bytes_taken.load(Ordering::Acquire) => {}
                Ok(NativeDenialOperationState::Running) => {
                    return Ok(Some(NativeDenialAdvance::CleanupPending));
                }
                _ => return self.fail_scope(scope).map(Some),
            }
            self.with_scope(scope, |entry| entry.operation_quiescent = true)?;
        }
        let result = self
            .denial_state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .owner
            .as_mut()
            .ok_or(BridgeError::Closed)?
            .retire_after_native_cleanup(&control.core);
        if result.is_err() {
            return self.fail_scope(scope).map(Some);
        }
        control.native_closed.store(true, Ordering::Release);
        self.with_scope(scope, |entry| entry.native_retired = true)?;
        Ok(None)
    }
    fn settle_denial_admitted(
        &self,
        scope: &Arc<NativeDenialScope>,
    ) -> Result<NativeDenialAdvance, BridgeError> {
        if scope.signal.released.load(Ordering::Acquire) {
            return Ok(NativeDenialAdvance::Released);
        }
        if self.with_scope(scope, |entry| entry.failed)? {
            return Ok(NativeDenialAdvance::CleanupFailed);
        }
        if !scope.is_cancelled() {
            if self.seal_denial_bound(&scope.signal.bound).is_ok() && !scope.is_cancelled() {
                if self.with_scope(scope, |entry| {
                    entry
                        .prepared
                        .as_ref()
                        .is_some_and(PreparedDenial::is_cancelled)
                })? {
                    scope.cancel();
                } else {
                    return Ok(
                        if self.with_scope(scope, |entry| entry.prepared.is_some())? {
                            NativeDenialAdvance::Prepared
                        } else {
                            NativeDenialAdvance::CleanupPending
                        },
                    );
                }
            }
            scope.cancel();
        }
        self.with_scope(scope, |entry| {
            entry.phase = Phase::Settling;
            entry.prepared.take();
        })?;
        if let Some(wait) = self.observe_approval_drain(scope)? {
            return Ok(wait);
        }
        if let Some(wait) = self.retire_denial_admitted(scope)? {
            return Ok(wait);
        }
        if self
            .platform
            .release_denial_scope(Arc::clone(scope))
            .is_err()
        {
            return self.fail_scope(scope);
        }
        // No transport exists in this ABI: any prepared value was never admitted
        // and has now been discarded. Native retirement alone was not enough.
        scope.signal.released.store(true, Ordering::Release);
        let mut state = self.denial_state.lock().map_err(|_| BridgeError::Closed)?;
        state
            .scopes
            .retain(|entry| !Arc::ptr_eq(&entry.scope.signal, &scope.signal));
        Ok(NativeDenialAdvance::Released)
    }

    fn check_denial_bound(
        &self,
        key: RequestKey,
        expected: Option<&BoundScope>,
    ) -> Result<BoundScope, BridgeError> {
        let before = self.read_clock()?;
        let checked = self
            .state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .as_mut()
            .ok_or(BridgeError::Closed)?
            .check_associated_pending(key, before);
        let checked = match checked {
            Ok(value) => value,
            Err(_) => return self.fail_closed(BridgeError::StorageUnavailable),
        };
        let result = checked
            .request()
            .ok_or(BridgeError::DenialRejected)
            .and_then(|request| BoundScope::capture(request, self.boot))
            .and_then(|bound| {
                if expected.is_some_and(|value| !value.matches(&bound)) {
                    Err(BridgeError::DenialRejected)
                } else {
                    Ok(bound)
                }
            });
        self.dispatch_approval_checks(vec![checked])?;
        let bound = result?;
        self.seal_denial_bound(&bound)?;
        Ok(bound)
    }
    fn seal_denial_bound(&self, bound: &BoundScope) -> Result<(), BridgeError> {
        self.require_live_denial_owner()?;
        let clock = self.read_clock()?; // No owner mutex held across callback.
        let late = {
            let state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let inbox = state.as_ref().ok_or(BridgeError::Closed)?;
            if inbox
                .peer_associations()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .resolve(bound.association.reference())
                != Some(&bound.association)
                || inbox
                    .local_keys()
                    .map_err(|_| BridgeError::StorageUnavailable)?
                    .get(bound.keys.handle())
                    .and_then(|phase| phase.descriptor())
                    != Some(&bound.keys)
            {
                return Err(BridgeError::DenialRejected);
            }
            clock.phone_monotonic_nanos() >= bound.deadline
                || !inbox
                    .policy()
                    .map_err(|_| BridgeError::StorageUnavailable)?
                    .allows(clock.reading().local)
        };
        if late {
            let checked = self
                .state
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .as_mut()
                .ok_or(BridgeError::Closed)?
                .check_associated_pending(bound.key(), clock);
            match checked {
                Ok(check) => self.dispatch_approval_checks(vec![check])?,
                Err(_) => return self.fail_closed(BridgeError::StorageUnavailable),
            }
            return Err(BridgeError::DenialRejected);
        }
        Ok(())
    }

    fn run_denial<T, U>(
        &self,
        action: impl FnOnce(
            &mut DenialOwner,
            &mut DurableInbox,
            &mut dyn android_controller::ApprovalClock,
        ) -> DenialTransition<T>,
        retain: impl FnOnce(T) -> Result<U, BridgeError>,
    ) -> Result<U, BridgeError> {
        let (inbox, owner) = {
            let mut state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let mut denial = self.denial_state.lock().map_err(|_| BridgeError::Closed)?;
            if state.is_none() || denial.owner.is_none() {
                return Err(BridgeError::Closed);
            }
            self.cleanup_pending.store(true, Ordering::Release);
            (
                state.take().ok_or(BridgeError::Closed)?,
                denial.owner.take().ok_or(BridgeError::Closed)?,
            )
        };
        let mut detached = DetachedDenial {
            controller: self,
            inbox: Some(inbox),
            owner: Some(owner),
            armed: true,
        };
        let mut clock = crate::approval::NativeApprovalClock::new(self);
        let result = action(
            detached.owner.as_mut().ok_or(BridgeError::Closed)?,
            detached.inbox.as_mut().ok_or(BridgeError::Closed)?,
            &mut clock,
        );
        let clock_error = clock.error();
        let faulted = !matches!(
            detached
                .inbox
                .as_ref()
                .ok_or(BridgeError::Closed)?
                .inbox_fault(),
            Ok(None)
        );
        {
            let mut state = self.state.lock().map_err(|_| BridgeError::Closed)?;
            let mut denial = self.denial_state.lock().map_err(|_| BridgeError::Closed)?;
            if state.is_some() || denial.owner.is_some() {
                return Err(BridgeError::Closed);
            }
            *state = detached.inbox.take();
            denial.owner = detached.owner.take();
            self.cleanup_pending.store(false, Ordering::Release);
            detached.armed = false;
        }
        let (checks, outcome) = result.into_parts();
        // Retain core attempt/prepared ownership BEFORE foreign dispatch. A
        // failed/throwing callback cannot orphan an unescaped native slot.
        let outcome = outcome.map_err(map_denial_error).and_then(retain);
        self.dispatch_approval_checks(checks)?;
        if let Some(error) = clock_error {
            return self.fail_closed(error);
        }
        if faulted {
            return self.fail_closed(BridgeError::StorageUnavailable);
        }
        match outcome {
            Err(
                error @ (BridgeError::StorageUnavailable
                | BridgeError::InvalidObservation
                | BridgeError::OwnerFaulted
                | BridgeError::Closed),
            ) => self.fail_closed(error),
            other => other,
        }
    }

    pub(crate) fn close_denial_state(&self) {
        let mut state = self
            .denial_state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(owner) = &mut state.owner {
            owner.close();
        }
        for entry in &mut state.scopes {
            entry.scope.cancel();
            entry.prepared.take();
            entry.phase = Phase::Settling;
        }
    }
    pub(crate) fn grant_denial_shutdown_retry(&self) {
        for entry in &mut self
            .denial_state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .scopes
        {
            entry.failed = false;
        }
    }
    pub(crate) fn finish_denial_cleanup(&self) -> Result<(), BridgeError> {
        let scopes: Vec<_> = self
            .denial_state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .scopes
            .iter()
            .map(|entry| Arc::clone(&entry.scope))
            .collect();
        let mut complete = true;
        for scope in scopes {
            if !matches!(
                self.settle_denial_admitted(&scope),
                Ok(NativeDenialAdvance::Released)
            ) {
                complete = false;
            }
        }
        if self
            .denial_state
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .uncertain
        {
            complete = false;
        }
        if complete {
            Ok(())
        } else {
            Err(BridgeError::NativeUnavailable)
        }
    }
    pub(crate) fn destroy_clean_denial_owner(&self) {
        let mut state = self
            .denial_state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.scopes.is_empty() && !state.uncertain {
            state.owner.take();
        }
    }
}
fn map_denial_error(error: DenialError) -> BridgeError {
    match error {
        DenialError::Busy | DenialError::Lease(android_controller::PeerLeaseError::Capacity) => {
            BridgeError::Busy
        }
        DenialError::ClockUnavailable | DenialError::ClockRegressed | DenialError::BootChanged => {
            BridgeError::InvalidObservation
        }
        DenialError::Owner(_) | DenialError::Persistence(_) | DenialError::DomainFault(_) => {
            BridgeError::StorageUnavailable
        }
        DenialError::Closed => BridgeError::Closed,
        _ => BridgeError::DenialRejected,
    }
}
// No foreign call on unwind. Keep the closed native retirement owner/cursor;
// drop the possibly uncertain inbox and make cleanup uncertainty explicit.
struct DetachedDenial<'a> {
    controller: &'a MobileController,
    inbox: Option<DurableInbox>,
    owner: Option<DenialOwner>,
    armed: bool,
}
impl Drop for DetachedDenial<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.controller
                .approval_alive
                .store(false, Ordering::Release);
            self.controller
                .cleanup_pending
                .store(true, Ordering::Release);
            if let Some(owner) = &mut self.owner {
                owner.close();
            }
            let mut state = self
                .controller
                .denial_state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.owner.is_none() {
                state.owner = self.owner.take();
            } else {
                state.uncertain = true;
            }
            for entry in &state.scopes {
                entry.scope.cancel();
            }
        }
    }
}
