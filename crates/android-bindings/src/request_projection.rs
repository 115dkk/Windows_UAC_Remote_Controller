// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded revocable presentation snapshots, never signing/action permits.
use crate::{
    BridgeError, NativeRequestSelection,
    native_clock::{self, NativePresentationClock, PresentationTime},
};
use android_controller::{AssociatedPendingRequest, DurableInbox, NativePeerLease};
use approval_protocol::RequestContent;
use notification_policy::{
    AlertMode, LocalTime, NotificationPolicy, RequestKey, RequestOutcome, Weekday,
};
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
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeRequestCatalogStatus {
    pub state: NativeRequestCatalogState,
    pub revision: u64,
    pub request_count: u8,
    pub configured_peers: u8,
    pub attached_peers: u8,
    pub connected_peers: u8,
    pub peers: Vec<NativePairedPc>,
    pub outcome_receipts: Vec<NativeOutcomeReceipt>,
    /// None when no PC is paired. Display only, like `peers`.
    pub connection: Option<crate::NativePcConnection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeOutcomeKind {
    Approved,
    Denied,
    Failed,
    Cancelled,
    Expired,
    ExpiredLocally,
    PcCompleted,
}

/// In-process, body-free observation of an owner-accepted terminal result.
/// A receipt is neither an action capability nor hardware authentication proof.
#[derive(Clone, uniffi::Record)]
pub struct NativeOutcomeReceipt {
    pub delivery_id: Vec<u8>,
    pub outcome: NativeOutcomeKind,
    pub observed_at_nanos: u64,
}
impl fmt::Debug for NativeOutcomeReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeOutcomeReceipt([redacted], display_only)")
    }
}

/// Public display metadata only. These fields are not accepted by any action API.
#[derive(Clone, uniffi::Record)]
pub struct NativePairedPc {
    pub id: String,
    pub revision: u64,
    pub route_present: bool,
    pub connected: bool,
}
impl fmt::Debug for NativePairedPc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativePairedPc")
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
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
    /// Expected identities, not outcomes. Includes full binding and issuance,
    /// so a revised/reissued request cannot complete an earlier local action.
    pub fn outcome_delivery_ids(&self) -> Vec<Vec<u8>> {
        [
            RequestOutcome::ApprovedByPc,
            RequestOutcome::DeniedByPc,
            RequestOutcome::FailedByPc,
            RequestOutcome::CancelledByPc,
            RequestOutcome::ExpiredByPc,
            RequestOutcome::ExpiredLocally,
            RequestOutcome::CompletedByPc,
        ]
        .into_iter()
        .map(|outcome| {
            phone_request_core::PendingOutcome::delivery_id_for(
                self.window.binding(),
                self.window.service_issued_at(),
                outcome,
            )
            .as_bytes()
            .to_vec()
        })
        .collect()
    }

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
            valid_until_nanos: display_until(
                &self.policy,
                sample.clock.reading().local,
                sample.minute_cutoff,
                self.deadline,
            ),
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
const MINUTE_NANOS: u64 = 60_000_000_000;
/// No request lives longer than `MAX_REQUEST_LIFETIME_MILLIS`, five minutes.
/// The walk below stops at the deadline long before this; the bound is for a
/// deadline that is not what the protocol says it is.
const MAX_DISPLAY_MINUTES: u32 = 5;

/// The local minute after `local`, in the same wall calendar the policy uses.
fn next_minute(local: LocalTime) -> Option<LocalTime> {
    let minute = local.minute().checked_add(1)?;
    if let Ok(same_day) = LocalTime::new(local.weekday(), minute) {
        return Some(same_day);
    }
    let tomorrow = match local.weekday() {
        Weekday::Monday => Weekday::Tuesday,
        Weekday::Tuesday => Weekday::Wednesday,
        Weekday::Wednesday => Weekday::Thursday,
        Weekday::Thursday => Weekday::Friday,
        Weekday::Friday => Weekday::Saturday,
        Weekday::Saturday => Weekday::Sunday,
        Weekday::Sunday => Weekday::Monday,
    };
    LocalTime::new(tomorrow, 0).ok()
}

/// How long this preview may stay on screen: to the request's own deadline, or
/// to the end of the last local minute this policy allows, whichever is first.
///
/// It used to stop at the end of the current minute whatever the next one
/// allowed, so every request left the screen at each minute boundary for as
/// long as the next read took, and a request that arrived at :58 was on screen
/// for two seconds. The schedule is the only thing that changes at a minute
/// boundary, and it is the same policy snapshot `check` enforces, so the
/// minutes it allows are read from it here rather than assumed to be zero.
///
/// This widens nothing an action relies on. A wall-clock or zone change moves
/// `time_epoch`, which fails `check` and the display cache at once; a changed
/// policy withdraws the request through the inbox; and approval and denial are
/// each checked again by their own owner, never by this value.
fn display_until(
    policy: &NotificationPolicy,
    local: LocalTime,
    minute_cutoff: u64,
    deadline: u64,
) -> u64 {
    let mut cutoff = minute_cutoff;
    let mut local = local;
    for _ in 0..MAX_DISPLAY_MINUTES {
        if cutoff >= deadline {
            break;
        }
        let Some(next) = next_minute(local) else {
            break;
        };
        if !policy.allows(next) {
            break;
        }
        let Some(extended) = cutoff.checked_add(MINUTE_NANOS) else {
            break;
        };
        cutoff = extended;
        local = next;
    }
    cutoff.min(deadline)
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
    receipts: Vec<NativeOutcomeReceipt>,
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
            receipts: Vec::new(),
        }
    }
}
impl ProjectionRegistry {
    pub(crate) fn outcome_receipts(&self) -> Vec<NativeOutcomeReceipt> {
        self.receipts.clone()
    }

    /// Caller holds owner admission and supplies only actual pending outcomes
    /// after native authenticated protocol/lifecycle acceptance. No UI input.
    pub(crate) fn observe_outcome(
        &mut self,
        outcome: phone_request_core::PendingOutcome,
        observed_at_nanos: u64,
    ) -> Result<(), BridgeError> {
        if self
            .receipts
            .iter()
            .any(|receipt| receipt.delivery_id.as_slice() == outcome.delivery_id().as_bytes())
        {
            return Ok(());
        }
        let kind = match outcome.outcome() {
            RequestOutcome::ApprovedByPc => NativeOutcomeKind::Approved,
            RequestOutcome::DeniedByPc => NativeOutcomeKind::Denied,
            RequestOutcome::FailedByPc => NativeOutcomeKind::Failed,
            RequestOutcome::CancelledByPc => NativeOutcomeKind::Cancelled,
            RequestOutcome::ExpiredByPc => NativeOutcomeKind::Expired,
            RequestOutcome::ExpiredLocally => NativeOutcomeKind::ExpiredLocally,
            RequestOutcome::CompletedByPc => NativeOutcomeKind::PcCompleted,
        };
        // Same bound as the live native request catalog, independent of history.
        if self.receipts.len() == 32 {
            self.receipts.remove(0);
        }
        self.receipts.push(NativeOutcomeReceipt {
            delivery_id: outcome.delivery_id().as_bytes().to_vec(),
            outcome: kind,
            observed_at_nanos,
        });
        self.bump()
    }

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
            .retain(|entry| Weak::<NativePendingRequest>::strong_count(entry) != 0);
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

#[cfg(test)]
mod tests {
    use super::*;
    use notification_policy::{DayMask, Schedule, TimeWindow, WeeklySchedule};

    const SECOND: u64 = 1_000_000_000;

    fn at(weekday: Weekday, minute: u16) -> LocalTime {
        LocalTime::new(weekday, minute).unwrap()
    }
    fn weekly(days: DayMask, start: u16, end: u16) -> NotificationPolicy {
        let window = TimeWindow::new(days, start, end).unwrap();
        NotificationPolicy::new(
            Some(Schedule::Weekly(WeeklySchedule::new([window]).unwrap())),
            AlertMode::Silent,
        )
    }

    #[test]
    fn an_always_on_policy_keeps_the_preview_until_the_request_deadline() {
        let policy = NotificationPolicy::default();
        assert!(policy.allows(at(Weekday::Monday, 600)));
        // Two seconds of the minute are left and the request has ninety.
        let cutoff = 100 * SECOND + 2 * SECOND;
        let deadline = 100 * SECOND + 90 * SECOND;
        assert_eq!(
            display_until(&policy, at(Weekday::Monday, 600), cutoff, deadline),
            deadline
        );
    }

    #[test]
    fn the_preview_ends_with_the_last_minute_the_schedule_allows() {
        // Allowed 10:00 to 10:02, so 10:01 is the last allowed minute.
        let policy = weekly(DayMask::ALL, 600, 602);
        let cutoff = 100 * SECOND + 2 * SECOND;
        let deadline = cutoff + 300 * SECOND;
        assert_eq!(
            display_until(&policy, at(Weekday::Monday, 600), cutoff, deadline),
            cutoff + MINUTE_NANOS
        );
        // In the last allowed minute nothing is added to it.
        assert_eq!(
            display_until(&policy, at(Weekday::Monday, 601), cutoff, deadline),
            cutoff
        );
    }

    #[test]
    fn a_deadline_inside_the_current_minute_is_never_extended() {
        let policy = NotificationPolicy::default();
        let cutoff = 100 * SECOND + 30 * SECOND;
        let deadline = 100 * SECOND + 5 * SECOND;
        assert_eq!(
            display_until(&policy, at(Weekday::Monday, 600), cutoff, deadline),
            deadline
        );
    }

    #[test]
    fn the_minute_after_the_last_one_of_a_day_is_the_first_of_the_next_day() {
        assert_eq!(
            next_minute(at(Weekday::Monday, 1439)),
            Some(at(Weekday::Tuesday, 0))
        );
        assert_eq!(
            next_minute(at(Weekday::Sunday, 1439)),
            Some(at(Weekday::Monday, 0))
        );
        assert_eq!(
            next_minute(at(Weekday::Friday, 600)),
            Some(at(Weekday::Friday, 601))
        );
        // All of Sunday and nothing else: a preview shown in Sunday's last
        // minute ends with it, and one shown a minute earlier gets that minute.
        let sunday = DayMask::from_days(&[Weekday::Sunday]).unwrap();
        let policy = weekly(sunday, 0, 1440);
        let cutoff = 10 * SECOND;
        let deadline = cutoff + 300 * SECOND;
        assert_eq!(
            display_until(&policy, at(Weekday::Sunday, 1439), cutoff, deadline),
            cutoff
        );
        assert_eq!(
            display_until(&policy, at(Weekday::Sunday, 1438), cutoff, deadline),
            cutoff + MINUTE_NANOS
        );
    }

    #[test]
    fn a_deadline_that_is_not_a_request_lifetime_cannot_stretch_the_preview_past_five_minutes() {
        let policy = NotificationPolicy::default();
        let cutoff = 10 * SECOND;
        assert_eq!(
            display_until(&policy, at(Weekday::Monday, 600), cutoff, u64::MAX),
            cutoff + u64::from(MAX_DISPLAY_MINUTES) * MINUTE_NANOS
        );
    }
}
