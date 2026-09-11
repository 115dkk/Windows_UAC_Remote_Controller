// SPDX-License-Identifier: GPL-2.0-or-later
//! Native camera intake into the existing key-creation INTENT, not generation,
//! Preparing, attestation, connection, signing, frozen acceptance or enrollment.
//! No invitation field or raw payload leaves the generated foreign object.

use super::{KeyCreationContext, KeyCreationIntent};
use crate::{
    BridgeError, MobileController, OwnerLease,
    native_clock::{NativeSocketClock, ProjectionAnchor, callback_active, native_callback},
};
use android_controller::{
    LocalAttestationChallenge, LocalKeyHandle, MAX_PAIRING_ACCEPTANCE_LIFETIME,
};
use framed_transport::{SocketClock, SocketClockUnavailable};
use service_protocol::{MAX_PAIRING_INVITATION_QR_TEXT_BYTES, PairingInvitation};
use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

// Capacity only, under the existing process-wide OwnerLease. It never grants
// key creation: the existing controller admission/creation_slot still decides.
static SCAN_RESERVED: AtomicBool = AtomicBool::new(false);
struct ScanReservation;
impl ScanReservation {
    fn acquire() -> Result<Self, BridgeError> {
        SCAN_RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| BridgeError::Busy)
    }
}
impl Drop for ScanReservation {
    fn drop(&mut self) {
        SCAN_RESERVED.store(false, Ordering::Release);
    }
}

struct ScanGuard {
    controller: Weak<MobileController>,
    alive: Arc<AtomicBool>,
    clock: Arc<NativeSocketClock>,
    started: Instant,
    deadline: Instant,
    cancelled: AtomicBool,
    // These outlive foreign copies and the actual retained CreationState clock.
    // No second business/store owner is constructed during scan or handoff.
    _reservation: ScanReservation,
    _owner_lease: Arc<OwnerLease>,
}
impl ScanGuard {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    fn ensure_open(&self) -> Result<(), BridgeError> {
        if self.cancelled.load(Ordering::Acquire) || !self.alive.load(Ordering::Acquire) {
            Err(BridgeError::Closed)
        } else {
            Ok(())
        }
    }
    fn belongs_to(&self, owner: &Arc<MobileController>) -> Result<(), BridgeError> {
        if self
            .controller
            .upgrade()
            .is_none_or(|original| !Arc::ptr_eq(&original, owner))
        {
            self.cancel();
            return Err(BridgeError::InvalidObservation);
        }
        Ok(())
    }
    fn observe(&self) -> Result<Instant, BridgeError> {
        struct Observation<'a> {
            guard: &'a ScanGuard,
            complete: bool,
        }
        impl Drop for Observation<'_> {
            fn drop(&mut self) {
                if !self.complete {
                    self.guard.cancel();
                }
            }
        }
        // A foreign callback unwind must revoke direct check_current and the
        // retained intent's clock too, not just an accept-invitation worker.
        let mut observation = Observation {
            guard: self,
            complete: false,
        };
        let result = (|| {
            self.ensure_open()?;
            if callback_active() {
                return Err(BridgeError::Busy);
            }
            let owner = self.controller.upgrade().ok_or(BridgeError::Closed)?;
            let before = self
                .clock
                .now()
                .map_err(|_| BridgeError::NativeUnavailable)?;
            if before < self.started || before >= self.deadline {
                return Err(BridgeError::Closed);
            }
            self.ensure_open()?;
            // No controller/input mutex is held across either native callback.
            // This observation is configuration, never biometric/auth success.
            if !native_callback(|| owner.platform.secure_lock_configured())? {
                return Err(BridgeError::NativeUnavailable);
            }
            self.ensure_open()?;
            let after = self
                .clock
                .now()
                .map_err(|_| BridgeError::NativeUnavailable)?;
            if after < before || after < self.started || after >= self.deadline {
                return Err(BridgeError::Closed);
            }
            self.ensure_open()?;
            Ok(after)
        })();
        observation.complete = result.is_ok();
        result
    }
}
struct ScanClock(Arc<ScanGuard>);
impl SocketClock for ScanClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        self.0.observe().map_err(|_| SocketClockUnavailable)
    }
}
struct Accepted {
    invitation: PairingInvitation,
    intent: KeyCreationIntent,
}

/// Read means original invitation + the existing creation INTENT were retained.
/// It is not Preparing, generated keys, a PC receipt, pairing or connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativePairingScanResult {
    Read,
    Invalid,
    Unavailable,
}

/// Application-owned generated handle; never place it in JS, an Intent, saved
/// state or a reusable QR DTO. Foreign clones share the same one-take state.
/// The original scan owner must remain live while its taken intent is in use.
#[derive(uniffi::Object)]
pub struct NativePairingScan {
    guard: Arc<ScanGuard>,
    input_taken: AtomicBool,
    accepted: Mutex<Option<Accepted>>,
}
impl fmt::Debug for NativePairingScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePairingScan(redacted, not_paired)")
    }
}
impl Drop for NativePairingScan {
    fn drop(&mut self) {
        // Losing the last original cancellation handle is downward retirement,
        // not permission for a taken intent to outlive its native UI owner.
        // That intent still retains the guard/lease/reservation until it drops.
        self.guard.cancel();
        self.clear_retained();
    }
}
#[uniffi::export]
impl NativePairingScan {
    pub fn accept_invitation(&self, text: String) -> NativePairingScanResult {
        self.accept_with(text, |bytes| {
            getrandom::fill(bytes).map_err(|_| BridgeError::NativeUnavailable)
        })
    }
    pub fn check_current(&self) -> Result<(), BridgeError> {
        self.guard.observe().map(|_| ())
    }
    /// Immediate downward invalidation, including while a worker/provider is
    /// busy. It never waits for controller admission or a native callback.
    pub fn cancel(&self) {
        self.guard.cancel();
        self.clear_retained();
    }
}
enum AcceptError {
    Invalid,
    Unavailable,
}
impl From<BridgeError> for AcceptError {
    fn from(_: BridgeError) -> Self {
        Self::Unavailable
    }
}
impl NativePairingScan {
    fn accept_with(
        &self,
        text: String,
        fill: impl FnOnce(&mut [u8]) -> Result<(), BridgeError>,
    ) -> NativePairingScanResult {
        if self.input_taken.swap(true, Ordering::AcqRel) {
            self.cancel();
            return NativePairingScanResult::Unavailable;
        }
        struct Work<'a> {
            guard: &'a ScanGuard,
            complete: bool,
        }
        impl Drop for Work<'_> {
            fn drop(&mut self) {
                if !self.complete {
                    self.guard.cancel();
                }
            }
        }
        let mut work = Work {
            guard: &self.guard,
            complete: false,
        };
        let result = (|| {
            self.guard.observe()?;
            // Native scanner must also bound before its foreign String copy;
            // this bound is before Rust decoding, key parsing or handle RNG.
            if text.len() > MAX_PAIRING_INVITATION_QR_TEXT_BYTES {
                return Err(AcceptError::Invalid);
            }
            let invitation =
                PairingInvitation::from_qr_text(&text).map_err(|_| AcceptError::Invalid)?;
            self.guard.observe()?;
            let mut handle = [0_u8; 32];
            fill(&mut handle)?; // Exactly ONE fill, after valid original input.
            let handle =
                LocalKeyHandle::from_bytes(handle).map_err(|_| AcceptError::Unavailable)?;
            self.guard.observe()?;
            let owner = self
                .guard
                .controller
                .upgrade()
                .ok_or(AcceptError::Unavailable)?;
            let fields = invitation.fields();
            let original = KeyCreationContext {
                handle,
                challenge: LocalAttestationChallenge::from_bytes(
                    *fields.attestation_challenge.as_bytes(),
                )
                .map_err(|_| AcceptError::Unavailable)?,
                ceremony_nonce: fields.ceremony_nonce,
                pc: fields.pc,
                recipient_device: fields.recipient_device,
                pc_signing_key: fields.pc_signing_key.clone(),
                pc_transport_key: fields.pc_transport_key.clone(),
                invitation_context: invitation.context_digest(),
                clock: Arc::new(ScanClock(Arc::clone(&self.guard))),
                started_at: self.guard.started,
                deadline: self.guard.deadline,
            };
            // Reuse the ACTUAL existing admission/creation reservation. No input
            // mutex/admission is held here and no special bypass is introduced.
            // Concurrent Rust-only creation wins or loses that same one slot.
            let intent = owner.begin_key_creation_from_trusted_host(original)?;
            self.guard.observe()?;
            {
                let mut accepted = self.accepted.lock().map_err(|_| AcceptError::Unavailable)?;
                self.guard.ensure_open()?;
                if accepted.is_some() {
                    return Err(AcceptError::Unavailable);
                }
                *accepted = Some(Accepted { invitation, intent });
            }
            // Cancellation/clock/native changes during the shared intent call
            // or publication cannot leave an eligible late result.
            self.guard.observe()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                work.complete = true;
                NativePairingScanResult::Read
            }
            Err(error) => {
                self.cancel();
                match error {
                    AcceptError::Invalid => NativePairingScanResult::Invalid,
                    AcceptError::Unavailable => NativePairingScanResult::Unavailable,
                }
            }
        }
    }
    fn clear_retained(&self) {
        let retained = match self.accepted.try_lock() {
            Ok(mut slot) => slot.take(),
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner().take(),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        // The clock's atomic guard already revoked any busy/externally retained
        // intent. Drop memory outside the input mutex, never mutate the store.
        if let Some(retained) = retained {
            retained.intent.cancel();
        }
    }
}

#[uniffi::export]
impl MobileController {
    /// Original native MainActivity user action only. Capture before camera/
    /// permission delays; this is the phone's original bound, not PC remaining time.
    pub fn begin_pairing_scan(self: &Arc<Self>) -> Result<Arc<NativePairingScan>, BridgeError> {
        let _admission = self.enter()?;
        if !self.approval_alive.load(Ordering::Acquire) {
            return Err(BridgeError::Closed);
        }
        self.read_clock()?;
        self.with_inbox(|owner| {
            if owner
                .inbox_fault()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .is_some()
            {
                Err(BridgeError::OwnerFaulted)
            } else {
                Ok(())
            }
        })?;
        if self
            .creation_slot
            .lock()
            .map_err(|_| BridgeError::Closed)?
            .upgrade()
            .is_some()
        {
            return Err(BridgeError::Busy);
        }
        let reservation = ScanReservation::acquire()?;
        let anchor = ProjectionAnchor::capture(&*self.platform, self.boot)?;
        let started = anchor.coordinate();
        let deadline = started
            .checked_add(MAX_PAIRING_ACCEPTANCE_LIFETIME)
            .ok_or(BridgeError::InvalidObservation)?;
        let guard = Arc::new(ScanGuard {
            controller: Arc::downgrade(self),
            alive: Arc::clone(&self.approval_alive),
            clock: anchor.clock(Arc::clone(&self.platform)),
            started,
            deadline,
            cancelled: AtomicBool::new(false),
            _reservation: reservation,
            _owner_lease: Arc::clone(&self._owner_lease),
        });
        guard.observe()?;
        let scan = Arc::new(NativePairingScan {
            guard,
            input_taken: AtomicBool::new(false),
            accepted: Mutex::new(None),
        });
        scan.check_current()?;
        Ok(scan)
    }
}
// NOT UniFFI-exported. A later trusted native Rust enrollment owner may consume
// the exact original and existing intent once; this is not a foreign grant API.
// It must also retain this original scan owner/cancellation handle. Moving the
// payload does not detach its lifetime or make a new native ceremony owner.
impl MobileController {
    pub fn take_pairing_scan(
        self: &Arc<Self>,
        scan: &Arc<NativePairingScan>,
    ) -> Result<(PairingInvitation, KeyCreationIntent), BridgeError> {
        let result = (|| {
            scan.guard.belongs_to(self)?;
            let _admission = self.enter()?;
            scan.check_current()?;
            let accepted = scan
                .accepted
                .lock()
                .map_err(|_| BridgeError::Closed)?
                .take()
                .ok_or(BridgeError::Closed)?;
            scan.check_current()?;
            // A last scan-handle drop cancels this intent. Its strong ScanClock
            // still retains original cleanup ownership until the intent drops.
            Ok((accepted.invitation, accepted.intent))
        })();
        if result.is_err() {
            scan.cancel();
        }
        result
    }
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests;
