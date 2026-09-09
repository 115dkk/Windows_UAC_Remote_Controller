// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded revocable presentation snapshots, never signing/action permits.
use crate::{
    BridgeError, NativeRequestSelection,
    native_clock::{self, NativePresentationClock, PresentationTime},
};
use android_controller::{AssociatedPendingRequest, DurableInbox, NativePeerLease};
use approval_protocol::RequestContent;
use notification_policy::{AlertMode, NotificationPolicy, RequestKey};
use phone_request_core::PhoneBootId;
use service_protocol::MappedRequestWindow;
use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeRequestPresentation {
    Fresh,
    Restore,
    Update,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeRequestAlert {
    Sound,
    VibrationOnly,
    Silent,
}
impl From<AlertMode> for NativeRequestAlert {
    fn from(value: AlertMode) -> Self {
        match value {
            AlertMode::Sound => Self::Sound,
            AlertMode::VibrateOnly => Self::VibrationOnly,
            AlertMode::Silent => Self::Silent,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeRequestNotPosted {
    NotificationsDisabled,
    PermissionMissing,
    SecureLockMissing,
    NoForegroundSurface,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeRequestSinkOutcome {
    RetainedAndPostRequested,
    RetainedNotPosted { reason: NativeRequestNotPosted },
    DiscardedStale,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeRequestCatalogState {
    Unavailable,
    Reconciling,
    Ready,
}
#[derive(Clone, Copy, Debug, uniffi::Record)]
pub struct NativeRequestCatalogStatus {
    pub state: NativeRequestCatalogState,
    pub revision: u64,
    pub request_count: u8,
    pub configured_peers: u8,
    pub attached_peers: u8,
    pub connected_peers: u8,
}
#[derive(Clone, uniffi::Record)]
pub struct NativeRequestPreview {
    pub selection: NativeRequestSelection,
    pub deadline_nanos: u64,
    pub valid_until_nanos: u64,
    pub time_epoch: u64,
    pub program: String,
    pub path: String,
    pub program_elided: bool,
    pub path_elided: bool,
    pub has_details: bool,
    pub pc_identity_hint: String,
}
impl fmt::Debug for NativeRequestPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeRequestPreview([redacted], display_only)")
    }
}
#[derive(Clone, uniffi::Record)]
pub struct NativeRequestDetails {
    pub program: String,
    pub path: String,
    pub details: String,
}
impl fmt::Debug for NativeRequestDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeRequestDetails([redacted], display_only)")
    }
}

#[derive(uniffi::Object)]
pub struct NativePendingRequest {
    window: MappedRequestWindow,
    boot: PhoneBootId,
    deadline: u64,
    time_epoch: u64,
    policy: NotificationPolicy,
    lease: NativePeerLease,
    controller_alive: Arc<AtomicBool>,
    revoked: AtomicBool,
    floor: AtomicU64,
    body: Mutex<Option<Arc<RequestContent>>>,
}
impl fmt::Debug for NativePendingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePendingRequest([redacted], not_authorization)")
    }
}
#[uniffi::export]
impl NativePendingRequest {
    pub fn same_handle(&self, other: Arc<NativePendingRequest>) -> bool {
        std::ptr::eq(self, Arc::as_ptr(&other))
    }
    pub fn selection(&self) -> NativeRequestSelection {
        NativeRequestSelection::from_key(self.key())
    }
    pub fn deadline_nanos(&self) -> u64 {
        self.deadline
    }
    pub fn is_revoked(&self) -> bool {
        let revoked = self.revoked.load(Ordering::Acquire)
            || !self.controller_alive.load(Ordering::Acquire)
            || self.lease.is_revoked();
        if revoked {
            self.revoke();
        }
        revoked
    }
    pub fn preview(
        &self,
        observed: NativePresentationClock,
    ) -> Result<NativeRequestPreview, BridgeError> {
        let sample = self.check(observed)?;
        let body = self.body()?;
        let (program, program_elided) = elide(body.program_name(), 512);
        let (path, path_elided) = elide(body.path(), 1024);
        if self.is_revoked() {
            return Err(BridgeError::RequestUnavailable);
        }
        let mut hint = String::with_capacity(12);
        for byte in &self.window.binding().pc().as_bytes()[..6] {
            use std::fmt::Write;
            let _ = write!(hint, "{byte:02X}");
        }
        Ok(NativeRequestPreview {
            selection: self.selection(),
            deadline_nanos: self.deadline,
            valid_until_nanos: self.deadline.min(sample.minute_cutoff),
            time_epoch: sample.time_epoch,
            has_details: !body.details().is_empty() || program_elided || path_elided,
            program,
            path,
            program_elided,
            path_elided,
            pc_identity_hint: hint,
        })
    }
    pub fn details(
        &self,
        observed: NativePresentationClock,
    ) -> Result<NativeRequestDetails, BridgeError> {
        self.check(observed)?;
        let body = self.body()?;
        let result = NativeRequestDetails {
            program: body.program_name().to_owned(),
            path: body.path().to_owned(),
            details: body.details().to_owned(),
        };
        if self.is_revoked() {
            return Err(BridgeError::RequestUnavailable);
        }
        Ok(result)
    }
}
impl NativePendingRequest {
    pub(crate) fn new(
        owner: &mut DurableInbox,
        request: &AssociatedPendingRequest,
        alive: Arc<AtomicBool>,
        sample: PresentationTime,
    ) -> Result<Arc<Self>, BridgeError> {
        if !request.belongs_to_owner(owner) {
            return Err(BridgeError::RequestUnavailable);
        }
        let window = request.request().original_window();
        let deadline = request
            .request()
            .notification()
            .expires_at
            .as_millis()
            .checked_mul(1_000_000)
            .ok_or(BridgeError::InvalidObservation)?
            .min(window.phone_expiry_nanos());
        let policy = owner
            .policy()
            .map_err(|_| BridgeError::StorageUnavailable)?
            .clone();
        if sample.clock.phone_monotonic_nanos() >= deadline
            || !policy.allows(sample.clock.reading().local)
        {
            return Err(BridgeError::RequestUnavailable);
        }
        let lease = owner
            .lease_pending_request(request)
            .map_err(|_| BridgeError::NativeUnavailable)?;
        Ok(Arc::new(Self {
            window,
            boot: sample.boot,
            deadline,
            time_epoch: sample.time_epoch,
            policy,
            lease,
            controller_alive: alive,
            revoked: AtomicBool::new(false),
            floor: AtomicU64::new(sample.clock.phone_monotonic_nanos()),
            body: Mutex::new(Some(Arc::clone(request.request().content()))),
        }))
    }
    pub(crate) fn key(&self) -> RequestKey {
        phone_request_core::request_key(self.window.binding())
    }
    pub(crate) fn window(&self) -> MappedRequestWindow {
        self.window
    }
    pub(crate) fn lease(&self) -> &NativePeerLease {
        &self.lease
    }
    pub(crate) fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        self.body
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
    fn body(&self) -> Result<Arc<RequestContent>, BridgeError> {
        self.body
            .lock()
            .map_err(|_| BridgeError::RequestUnavailable)?
            .as_ref()
            .cloned()
            .ok_or(BridgeError::RequestUnavailable)
    }
    fn check(&self, observed: NativePresentationClock) -> Result<PresentationTime, BridgeError> {
        if self.is_revoked() {
            return Err(BridgeError::RequestUnavailable);
        }
        let sample = native_clock::validate(observed)?;
        let now = sample.clock.phone_monotonic_nanos();
        if sample.boot != self.boot
            || sample.time_epoch != self.time_epoch
            || now >= self.deadline
            || now >= sample.minute_cutoff
            || !self.policy.allows(sample.clock.reading().local)
        {
            return Err(BridgeError::RequestUnavailable);
        }
        self.floor
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous| {
                (now >= previous).then_some(now)
            })
            .map_err(|_| BridgeError::RequestUnavailable)?;
        Ok(sample)
    }
}
fn elide(value: &str, max_units: usize) -> (String, bool) {
    let mut units = 0;
    let mut end = value.len();
    for (offset, scalar) in value.char_indices() {
        units += scalar.len_utf16();
        if units > max_units {
            end = offset;
            break;
        }
    }
    (value[..end].to_owned(), end != value.len())
}

pub(crate) struct ProjectionRegistry {
    entries: Vec<Arc<NativePendingRequest>>,
    historical: Vec<Weak<NativePendingRequest>>,
    pub initialized: bool,
    pub revision: u64,
    pub time_epoch: Option<u64>,
    refresh: Vec<(RequestKey, u64)>,
}
impl Default for ProjectionRegistry {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            historical: Vec::new(),
            initialized: false,
            revision: 1,
            time_epoch: None,
            refresh: Vec::new(),
        }
    }
}
impl ProjectionRegistry {
    pub(crate) fn keys(&self) -> Vec<RequestKey> {
        self.entries.iter().map(|entry| entry.key()).collect()
    }
    pub(crate) fn count(&self) -> usize {
        self.entries.len()
    }
    pub(crate) fn current(&self, handle: &Arc<NativePendingRequest>) -> bool {
        self.entries
            .iter()
            .any(|current| Arc::ptr_eq(current, handle))
    }
    pub(crate) fn defer_refresh(&mut self, key: RequestKey, due: u64) -> Result<(), BridgeError> {
        if let Some(entry) = self.refresh.iter_mut().find(|entry| entry.0 == key) {
            entry.1 = entry.1.max(due);
        } else {
            if self.refresh.len() >= 32 {
                return Err(BridgeError::Busy);
            }
            self.refresh
                .try_reserve(1)
                .map_err(|_| BridgeError::NativeUnavailable)?;
            self.refresh.push((key, due));
        }
        Ok(())
    }
    pub(crate) fn take_due_refresh(&mut self, now: u64) -> Vec<RequestKey> {
        let mut keys = Vec::new();
        let mut index = 0;
        while index < self.refresh.len() {
            if self.refresh[index].1 <= now {
                keys.push(self.refresh.swap_remove(index).0);
            } else {
                index += 1;
            }
        }
        keys
    }
    pub(crate) fn refresh_deadline(&self) -> Option<u64> {
        self.refresh.iter().map(|entry| entry.1).min()
    }
    pub(crate) fn reserve(&mut self, key: RequestKey) -> Result<(), BridgeError> {
        self.historical
            .retain(|entry: &Weak<NativePendingRequest>| entry.strong_count() != 0);
        if self.historical.len() >= 64
            || (self.entries.len() >= 32 && !self.entries.iter().any(|entry| entry.key() == key))
        {
            return Err(BridgeError::Busy);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| BridgeError::NativeUnavailable)?;
        self.historical
            .try_reserve(1)
            .map_err(|_| BridgeError::NativeUnavailable)?;
        Ok(())
    }
    pub(crate) fn insert(&mut self, value: Arc<NativePendingRequest>) -> Result<(), BridgeError> {
        self.refresh.retain(|entry| entry.0 != value.key());
        self.remove(value.key())?;
        self.historical.push(Arc::downgrade(&value));
        self.entries.push(value);
        self.bump()
    }
    pub(crate) fn remove(&mut self, key: RequestKey) -> Result<(), BridgeError> {
        if let Some(index) = self.entries.iter().position(|entry| entry.key() == key) {
            self.entries.swap_remove(index).revoke();
            self.bump()?;
        }
        Ok(())
    }
    pub(crate) fn revoke_all(&mut self) -> Result<(), BridgeError> {
        for entry in self.entries.drain(..) {
            entry.revoke();
        }
        self.bump()
    }
    pub(crate) fn prune(&mut self) -> Result<Vec<RequestKey>, BridgeError> {
        let mut removed = Vec::new();
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].is_revoked() {
                let entry = self.entries.swap_remove(index);
                removed.push(entry.key());
                self.bump()?;
            } else {
                index += 1;
            }
        }
        Ok(removed)
    }
    fn bump(&mut self) -> Result<(), BridgeError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(BridgeError::NativeUnavailable)?;
        Ok(())
    }
}
impl Drop for ProjectionRegistry {
    fn drop(&mut self) {
        let _ = self.revoke_all();
    }
}
