// SPDX-License-Identifier: GPL-2.0-or-later
//! Local exact-existing-Activity extension. No caller-supplied ID can mint a lease.
use super::ndk_glue::ActivityId;
use jni::{
  objects::{GlobalRef, JObject},
  JNIEnv, JavaVM,
};
use once_cell::sync::Lazy;
use std::{
  collections::BTreeMap,
  fmt,
  sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
  },
};

const MAX_ACTIVITIES: usize = 32;
static GENERATION: AtomicU64 = AtomicU64::new(1);
static REGISTRATIONS: Lazy<Mutex<BTreeMap<ActivityId, ExistingActivity>>> =
  Lazy::new(Default::default);
type Observer = Arc<dyn Fn(ExistingActivityEvent) + Send + Sync>;
static OBSERVER: Lazy<Mutex<Option<Observer>>> = Lazy::new(Default::default);

#[derive(Default)]
struct ClaimState {
  claimed: bool,
  closed: bool,
}
impl ClaimState {
  fn claim(&mut self) -> bool {
    if self.claimed || self.closed {
      return false;
    }
    self.claimed = true;
    true
  }
  fn retire(&mut self, configuration: bool) {
    if !configuration {
      self.closed = true;
    }
  }
}

struct LogicalActivity {
  id: ActivityId,
  window_id: u64,
  name: String,
  claim: Mutex<ClaimState>,
}
impl LogicalActivity {
  fn name(&self) -> &str {
    &self.name
  }
}

/// A geometry-only logical identity, not an attachment permit or raw handle.
/// Configuration replacement may supply its current physical registration;
/// normal finish/reopen must never redirect an old target to a different Arc.
#[derive(Clone)]
pub(super) struct GeometryTarget(Arc<LogicalActivity>);
impl fmt::Debug for GeometryTarget {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("GeometryTarget([opaque])")
  }
}
impl PartialEq for GeometryTarget {
  fn eq(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
}
impl Eq for GeometryTarget {}
impl PartialOrd for GeometryTarget {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}
impl Ord for GeometryTarget {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
  }
}
impl std::hash::Hash for GeometryTarget {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    std::hash::Hash::hash(&Arc::as_ptr(&self.0), state);
  }
}
impl GeometryTarget {
  fn accepts(&self, logical: &Arc<LogicalActivity>, live: bool) -> bool {
    Arc::ptr_eq(&self.0, logical)
      && live
      && self
        .0
        .claim
        .lock()
        .map(|claim| !claim.closed)
        .unwrap_or(false)
  }
  fn current(&self) -> Result<ExistingActivity, ExistingActivityError> {
    let registrations = REGISTRATIONS
      .lock()
      .map_err(|_| ExistingActivityError::Unavailable)?;
    registrations
      .get(&self.0.id)
      .filter(|current| self.accepts(&current.0.logical, current.is_live()))
      .cloned()
      .ok_or(ExistingActivityError::Unavailable)
  }
  fn check_current(&self, physical: &ExistingActivity) -> Result<(), ExistingActivityError> {
    if self.current()?.same_instance(physical) {
      Ok(())
    } else {
      Err(ExistingActivityError::Unavailable)
    }
  }
  /// Owns one current physical snapshot only for this read. All registry/claim
  /// locks are released before JNI. A retirement/replacement during the read
  /// discards its result; the original creation lease is never rebound.
  pub(super) fn with_window_manager<T>(
    &self,
    callback: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> T,
  ) -> Result<T, ExistingActivityError> {
    let physical = self.current()?;
    let mut env = physical
      .0
      .vm
      .attach_current_thread()
      .map_err(|_| ExistingActivityError::Unavailable)?;
    let result = (|| {
      physical.check_native(&mut env)?;
      self.check_current(&physical)?;
      let value = callback(&mut env, physical.0.window_manager.as_obj());
      physical.check_native(&mut env)?;
      self.check_current(&physical)?;
      Ok(value)
    })();
    if result.is_err() && env.exception_check().unwrap_or(false) {
      let _ = env.exception_clear();
    }
    result
  }
}

struct PhysicalActivity {
  generation: u64,
  activity: GlobalRef,
  window_manager: GlobalRef,
  vm: JavaVM,
  alive: AtomicBool,
  ready: AtomicBool,
  configuration_retired: AtomicBool,
  logical: Arc<LogicalActivity>,
}

/// Owned identity of one actual framework-registered Activity incarnation.
/// Clones share liveness and the one logical-window claim; they are not new permits.
#[derive(Clone)]
pub struct ExistingActivity(Arc<PhysicalActivity>);
impl fmt::Debug for ExistingActivity {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("ExistingActivity([opaque])")
  }
}
impl PartialEq for ExistingActivity {
  fn eq(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
}
impl Eq for ExistingActivity {}

/// Fixed failure categories; never contains JNI exception text or object pointers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExistingActivityError {
  Unavailable,
  AlreadyObserved,
}
impl fmt::Display for ExistingActivityError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Unavailable => "existing Android Activity unavailable",
      Self::AlreadyObserved => "Android Activity observer already installed",
    })
  }
}
impl std::error::Error for ExistingActivityError {}

impl ExistingActivity {
  /// Atomic lifetime observation, not proof that a native view was attached.
  pub fn is_live(&self) -> bool {
    self.0.alive.load(Ordering::Acquire) && self.0.ready.load(Ordering::Acquire)
  }
  /// Exact physical generation, never Java's reusable integer Activity ID.
  pub fn same_instance(&self, other: &Self) -> bool {
    self.0.generation == other.0.generation && self == other
  }
  /// Framework-resolved local class name, not an intent or caller-selected class.
  pub fn activity_name(&self) -> &str {
    self.0.logical.name()
  }
  /// False for configuration recreation of an already claimed logical window.
  pub fn needs_window(&self) -> bool {
    self.is_live()
      && self
        .0
        .logical
        .claim
        .lock()
        .map(|state| !state.claimed && !state.closed)
        .unwrap_or(false)
  }
  /// Runs a safe composition callback with only the ORIGINAL retained Activity.
  /// JNI local references and JNIEnv must not escape; returned values must own
  /// any GlobalRefs they need. The callback runs without registry/state locks.
  pub fn with_original_activity<T>(
    &self,
    callback: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> T,
  ) -> Result<T, ExistingActivityError> {
    if !self.is_live() {
      return Err(ExistingActivityError::Unavailable);
    }
    let mut env = self
      .0
      .vm
      .attach_current_thread_as_daemon()
      .map_err(|_| ExistingActivityError::Unavailable)?;
    self.check_native(&mut env)?;
    let result = callback(&mut env, self.0.activity.as_obj());
    self.check_native(&mut env)?;
    Ok(result)
  }
  fn check_native(&self, env: &mut JNIEnv<'_>) -> Result<(), ExistingActivityError> {
    if !self.is_live() {
      return Err(ExistingActivityError::Unavailable);
    }
    for method in ["isDestroyed", "isFinishing"] {
      if env
        .call_method(self.0.activity.as_obj(), method, "()Z", &[])
        .and_then(|value| value.z())
        .map_err(|_| ExistingActivityError::Unavailable)?
      {
        return Err(ExistingActivityError::Unavailable);
      }
    }
    Ok(())
  }
  pub(super) fn id(&self) -> ActivityId {
    self.0.logical.id
  }
  pub(super) fn window_id(&self) -> u64 {
    self.0.logical.window_id
  }
  pub(super) fn geometry_target(&self) -> GeometryTarget {
    GeometryTarget(Arc::clone(&self.0.logical))
  }
  pub(super) fn matches_context(&self, context: *mut std::ffi::c_void) -> bool {
    // AndroidContext was populated from a clone of this exact GlobalRef. This
    // comparison never dereferences or constructs a JNI object from the pointer.
    context == self.0.activity.as_obj().as_raw().cast()
  }
  pub(super) fn matches_window_manager(&self, env: &JNIEnv<'_>, manager: &JObject<'_>) -> bool {
    env
      .is_same_object(self.0.window_manager.as_obj(), manager)
      .unwrap_or(false)
  }
  pub(super) fn claimed(&self) -> bool {
    self
      .0
      .logical
      .claim
      .lock()
      .map(|state| state.claimed)
      .unwrap_or(true)
  }
  pub(super) fn window_manager(&self) -> Option<&GlobalRef> {
    self.is_live().then_some(&self.0.window_manager)
  }
  pub(super) fn claim(&self) -> Result<(), ExistingActivityError> {
    self.with_original_activity(|_, _| ())?;
    let registrations = REGISTRATIONS
      .lock()
      .map_err(|_| ExistingActivityError::Unavailable)?;
    if !self.is_live()
      || !registrations
        .get(&self.0.logical.id)
        .is_some_and(|current| self.same_instance(current))
    {
      return Err(ExistingActivityError::Unavailable);
    }
    if !self
      .0
      .logical
      .claim
      .lock()
      .map_err(|_| ExistingActivityError::Unavailable)?
      .claim()
    {
      return Err(ExistingActivityError::Unavailable);
    }
    Ok(())
  }
}

/// Actual lifecycle observations only. A destroyed lease is already invalid.
#[derive(Clone, Debug)]
pub enum ExistingActivityEvent {
  Created(ExistingActivity),
  Destroyed {
    activity: ExistingActivity,
    configuration_change: bool,
  },
}

/// One observer registration, removed on drop. Dropping never changes Android state.
pub struct ExistingActivityObserver {
  observer: Observer,
}
impl Drop for ExistingActivityObserver {
  fn drop(&mut self) {
    if let Ok(mut current) = OBSERVER.lock() {
      if current
        .as_ref()
        .is_some_and(|value| Arc::ptr_eq(value, &self.observer))
      {
        *current = None;
      }
    }
  }
}
/// Installs one process observer and reports already registered live instances.
/// The callback must only enqueue bounded work, never wait for the Android UI thread.
pub fn observe_existing_activities(
  callback: impl Fn(ExistingActivityEvent) + Send + Sync + 'static,
) -> Result<ExistingActivityObserver, ExistingActivityError> {
  let observer: Observer = Arc::new(callback);
  {
    let mut slot = OBSERVER
      .lock()
      .map_err(|_| ExistingActivityError::Unavailable)?;
    if slot.is_some() {
      return Err(ExistingActivityError::AlreadyObserved);
    }
    *slot = Some(Arc::clone(&observer));
  }
  // The guard also unregisters if snapshot collection below fails.
  let registration = ExistingActivityObserver {
    observer: Arc::clone(&observer),
  };
  let current: Vec<_> = REGISTRATIONS
    .lock()
    .map_err(|_| ExistingActivityError::Unavailable)?
    .values()
    .filter(|value| value.is_live())
    .cloned()
    .collect();
  for activity in current {
    notify_to(&observer, ExistingActivityEvent::Created(activity));
  }
  Ok(registration)
}
fn notify_to(observer: &Observer, event: ExistingActivityEvent) {
  // A foreign lifecycle callback must not unwind the JNI lifecycle entry point.
  let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer(event)));
}
fn notify(event: ExistingActivityEvent) {
  let observer = OBSERVER.lock().ok().and_then(|value| value.clone());
  if let Some(observer) = observer {
    notify_to(&observer, event);
  }
}

pub(super) fn register(
  env: &mut JNIEnv<'_>,
  id: ActivityId,
  name: String,
  activity: GlobalRef,
  window_manager: GlobalRef,
) -> Result<ExistingActivity, ExistingActivityError> {
  if name.is_empty() || name.len() > 512 {
    return Err(ExistingActivityError::Unavailable);
  }
  let mut slots = REGISTRATIONS
    .lock()
    .map_err(|_| ExistingActivityError::Unavailable)?;
  let previous = slots.get(&id);
  // A live ID collision cannot replace a different original Activity.
  if previous.is_some_and(|value| value.0.alive.load(Ordering::Acquire)) {
    return Err(ExistingActivityError::Unavailable);
  }
  if previous.is_none() && slots.len() >= MAX_ACTIVITIES {
    return Err(ExistingActivityError::Unavailable);
  }
  let generation = GENERATION
    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
      value.checked_add(1)
    })
    .map_err(|_| ExistingActivityError::Unavailable)?;
  let logical = if let Some(previous) = previous.filter(|value| {
    value.0.configuration_retired.load(Ordering::Acquire) && value.activity_name() == name
  }) {
    Arc::clone(&previous.0.logical)
  } else {
    Arc::new(LogicalActivity {
      id,
      window_id: generation,
      name,
      claim: Mutex::new(ClaimState::default()),
    })
  };
  let current = ExistingActivity(Arc::new(PhysicalActivity {
    generation,
    activity,
    window_manager,
    vm: env
      .get_java_vm()
      .map_err(|_| ExistingActivityError::Unavailable)?,
    alive: AtomicBool::new(true),
    ready: AtomicBool::new(false),
    configuration_retired: AtomicBool::new(false),
    logical,
  }));
  slots.insert(id, current.clone());
  Ok(current)
}
pub(super) fn registered(activity: &ExistingActivity) {
  activity.0.ready.store(true, Ordering::Release);
  notify(ExistingActivityEvent::Created(activity.clone()));
}
pub(super) fn claim_next() -> Result<ExistingActivity, ExistingActivityError> {
  let next = REGISTRATIONS
    .lock()
    .map_err(|_| ExistingActivityError::Unavailable)?
    .values()
    .find(|value| value.needs_window())
    .cloned()
    .ok_or(ExistingActivityError::Unavailable)?;
  next.claim()?;
  Ok(next)
}
pub(super) fn claim_id(id: ActivityId) -> Result<ExistingActivity, ExistingActivityError> {
  let activity = REGISTRATIONS
    .lock()
    .map_err(|_| ExistingActivityError::Unavailable)?
    .get(&id)
    .cloned()
    .ok_or(ExistingActivityError::Unavailable)?;
  activity.claim()?;
  Ok(activity)
}
/// Invalidates only the exact callback object before any deferred destruction.
pub(super) fn retire(
  env: &mut JNIEnv<'_>,
  id: ActivityId,
  original: &JObject<'_>,
  configuration: bool,
) -> Option<ExistingActivity> {
  let activity = {
    let mut slots = REGISTRATIONS.lock().ok()?;
    let activity = slots.get(&id)?.clone();
    if !env
      .is_same_object(activity.0.activity.as_obj(), original)
      .unwrap_or(false)
    {
      return None;
    }
    if !activity.0.alive.swap(false, Ordering::AcqRel) {
      return None;
    }
    activity
      .0
      .configuration_retired
      .store(configuration, Ordering::Release);
    if let Ok(mut claim) = activity.0.logical.claim.lock() {
      claim.retire(configuration);
    }
    if !configuration {
      slots.remove(&id);
    }
    activity
  };
  notify(ExistingActivityEvent::Destroyed {
    activity: activity.clone(),
    configuration_change: configuration,
  });
  Some(activity)
}
pub(super) fn original_window_id(
  env: &JNIEnv<'_>,
  id: ActivityId,
  original: &JObject<'_>,
) -> Option<u64> {
  let slots = REGISTRATIONS.lock().ok()?;
  let activity = slots.get(&id)?;
  (activity.is_live()
    && env
      .is_same_object(activity.0.activity.as_obj(), original)
      .unwrap_or(false))
  .then(|| activity.window_id())
}

pub(super) fn live_geometry_targets() -> Vec<GeometryTarget> {
  let Ok(slots) = REGISTRATIONS.lock() else {
    return Vec::new();
  };
  slots
    .values()
    .filter_map(|physical| {
      let target = physical.geometry_target();
      target
        .accepts(&physical.0.logical, physical.is_live())
        .then_some(target)
    })
    .collect()
}
pub(super) fn geometry_target_for_window(window_id: u64) -> Option<GeometryTarget> {
  let slots = REGISTRATIONS.lock().ok()?;
  let physical = slots
    .values()
    .find(|physical| physical.window_id() == window_id)?;
  let target = physical.geometry_target();
  target
    .accepts(&physical.0.logical, physical.is_live())
    .then_some(target)
}

#[cfg(test)]
mod tests {
  use super::{ClaimState, GeometryTarget, LogicalActivity};
  use std::sync::{Arc, Mutex};

  fn logical() -> Arc<LogicalActivity> {
    Arc::new(LogicalActivity {
      id: 7,
      window_id: 11,
      name: "MainActivity".to_owned(),
      claim: Mutex::new(ClaimState::default()),
    })
  }
  #[test]
  fn one_logical_claim_never_reopens() {
    let mut state = ClaimState::default();
    assert!(state.claim());
    assert!(!state.claim());
    state.closed = true;
    assert!(!state.claim());
  }
  #[test]
  fn destroyed_unclaimed_generation_cannot_claim() {
    let mut state = ClaimState {
      claimed: false,
      closed: true,
    };
    assert!(!state.claim());
  }
  #[test]
  fn configuration_retirement_preserves_claim_without_resetting_it() {
    let mut claimed = ClaimState::default();
    assert!(claimed.claim());
    claimed.retire(true);
    assert!(!claimed.closed);
    assert!(!claimed.claim());
    claimed.retire(false);
    assert!(claimed.closed);
    assert!(!claimed.claim());
    let mut unclaimed = ClaimState::default();
    unclaimed.retire(false);
    assert!(!unclaimed.claim());
  }
  #[test]
  fn geometry_follows_only_the_same_logical_arc_after_configuration() {
    let logical = logical();
    let target = GeometryTarget(Arc::clone(&logical));
    {
      let mut claim = logical.claim.lock().unwrap();
      assert!(claim.claim());
      claim.retire(true);
    }
    assert!(
      !target.accepts(&logical, false),
      "retired or not-yet-ready physical state is unavailable"
    );
    assert!(
      target.accepts(&Arc::clone(&logical), true),
      "a live configuration replacement may serve geometry"
    );
    assert!(
      !logical.claim.lock().unwrap().claim(),
      "geometry does not reopen the attachment claim"
    );
  }
  #[test]
  fn geometry_rejects_reused_ids_and_normal_finish() {
    let original = logical();
    let unrelated_same_ids_and_name = logical();
    let target = GeometryTarget(Arc::clone(&original));
    assert!(!target.accepts(&unrelated_same_ids_and_name, true));
    original.claim.lock().unwrap().retire(false);
    assert!(
      !target.accepts(&original, true),
      "a closed logical window cannot be revived by a live flag"
    );
    assert!(!target.accepts(&unrelated_same_ids_and_name, true));
  }
  #[test]
  fn geometry_target_identity_does_not_collapse_equal_numeric_ids() {
    let target = GeometryTarget(logical());
    let clone = target.clone();
    let unrelated = GeometryTarget(logical());
    assert_eq!(target, clone);
    assert_eq!(target.cmp(&clone), std::cmp::Ordering::Equal);
    assert_ne!(target, unrelated);
    assert_ne!(target.cmp(&unrelated), std::cmp::Ordering::Equal);
  }
}
