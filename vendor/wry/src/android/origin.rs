// Copyright 2026 Windows-UAC-Remote-Controller contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Native physical-instance provenance. Never reconstructed from labels, IDs,
//! URLs, IPC headers or a later current-Activity lookup.
use super::handlers::{self, HandlerRegistration};
use super::main_pipe::{self, ActivityId, MainPipe, WebViewMessage};
use crate::{Error, Result};
use jni::{
  objects::{GlobalRef, JObject},
  JNIEnv, JavaVM,
};
use std::{
  fmt,
  sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Weak,
  },
};

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
fn generation() -> Result<u64> {
  NEXT_GENERATION
    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
      value.checked_add(1)
    })
    .map_err(|_| Error::ActivityNotFound)
}

struct ActivityInner {
  id: ActivityId,
  _generation: u64,
  alive: AtomicBool,
  vm: JavaVM,
  activity: GlobalRef,
  window_manager: GlobalRef,
}

/// Exact registered physical Activity. Clones retain the original references;
/// retirement is irreversible and a reused integer ID cannot revive them.
#[derive(Clone)]
pub struct AndroidActivityOrigin(Arc<ActivityInner>);
pub(crate) struct WeakActivityOrigin(Weak<ActivityInner>);
impl WeakActivityOrigin {
  pub(crate) fn upgrade(&self) -> Option<AndroidActivityOrigin> {
    Weak::<ActivityInner>::upgrade(&self.0).map(AndroidActivityOrigin)
  }
}
impl fmt::Debug for AndroidActivityOrigin {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("AndroidActivityOrigin([redacted])")
  }
}
impl AndroidActivityOrigin {
  pub(crate) fn new(
    env: &mut JNIEnv<'_>,
    id: ActivityId,
    activity: GlobalRef,
    window_manager: GlobalRef,
  ) -> Result<Self> {
    Ok(Self(Arc::new(ActivityInner {
      id,
      _generation: generation()?,
      alive: AtomicBool::new(true),
      vm: env.get_java_vm()?,
      activity,
      window_manager,
    })))
  }
  pub fn is_live(&self) -> bool {
    self.0.alive.load(Ordering::Acquire)
  }
  pub(crate) fn downgrade(&self) -> WeakActivityOrigin {
    WeakActivityOrigin(Arc::downgrade(&self.0))
  }
  pub(crate) fn retire(&self) {
    self.0.alive.store(false, Ordering::Release);
  }
  pub(crate) fn id(&self) -> ActivityId {
    self.0.id
  }
  pub(crate) fn same(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
  pub(crate) fn activity(&self) -> &JObject<'static> {
    self.0.activity.as_obj()
  }
  pub(crate) fn activity_reference(&self) -> GlobalRef {
    self.0.activity.clone()
  }
  pub(crate) fn matches_activity(
    &self,
    env: &JNIEnv<'_>,
    activity: &JObject<'_>,
  ) -> jni::errors::Result<bool> {
    env.is_same_object(self.activity(), activity)
  }
  pub(crate) fn live_on_main(&self, env: &mut JNIEnv<'_>) -> jni::errors::Result<bool> {
    if !self.is_live() {
      return Ok(false);
    }
    let destroyed = env
      .call_method(self.activity(), "isDestroyed", "()Z", &[])?
      .z()?;
    let finishing = env
      .call_method(self.activity(), "isFinishing", "()Z", &[])?
      .z()?;
    Ok(!destroyed && !finishing && self.is_live())
  }
  pub(crate) fn matches_window_manager(&self, manager: &JObject<'_>) -> Result<bool> {
    let mut env = self.0.vm.attach_current_thread_as_daemon()?;
    Ok(
      self.live_on_main(&mut env)?
        && env.is_same_object(self.0.window_manager.as_obj(), manager)?,
    )
  }
}

/// Finds only the origin whose retained Activity is the supplied original JNI
/// object. The caller must hold that original object, not a current-ID selector.
pub fn android_activity_origin(
  env: &mut JNIEnv<'_>,
  activity: &JObject<'_>,
) -> Result<AndroidActivityOrigin> {
  if let Some(origin) = main_pipe::origin_for_activity(env, activity)? {
    if origin.live_on_main(env)? {
      return Ok(origin);
    }
  }
  Err(Error::ActivityNotFound)
}

struct WebviewInner {
  _generation: u64,
  alive: AtomicBool,
  activity: AndroidActivityOrigin,
  registration: HandlerRegistration,
  webview: GlobalRef,
  logical_id: String,
}
/// Opaque physical WebView IPC origin. It has no public constructor, identifier
/// conversion, serialization, or replacement/current-view lookup.
#[derive(Clone)]
pub struct AndroidWebviewOrigin(Arc<WebviewInner>);
impl fmt::Debug for AndroidWebviewOrigin {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("AndroidWebviewOrigin([redacted])")
  }
}
impl AndroidWebviewOrigin {
  pub(crate) fn new(
    env: &mut JNIEnv<'_>,
    activity: AndroidActivityOrigin,
    registration: HandlerRegistration,
    webview: &JObject<'_>,
    logical_id: String,
  ) -> Result<Self> {
    if !activity.live_on_main(env)?
      || !registration.activity().same(&activity)
      || registration.label() != logical_id
      || !handlers::current(&registration)
    {
      return Err(Error::ActivityNotFound);
    }
    Ok(Self(Arc::new(WebviewInner {
      _generation: generation()?,
      alive: AtomicBool::new(true),
      activity,
      registration,
      webview: env.new_global_ref(webview)?,
      logical_id,
    })))
  }
  pub fn is_live(&self) -> bool {
    self.0.alive.load(Ordering::Acquire)
      && self.0.activity.is_live()
      && self.0.registration.is_live()
  }
  pub(crate) fn retire(&self) {
    self.0.alive.store(false, Ordering::Release);
  }
  pub(crate) fn activity_origin(&self) -> &AndroidActivityOrigin {
    &self.0.activity
  }
  pub(crate) fn registration(&self) -> &HandlerRegistration {
    &self.0.registration
  }
  pub(crate) fn webview(&self) -> &JObject<'static> {
    self.0.webview.as_obj()
  }
  pub(crate) fn view_reference(&self) -> GlobalRef {
    self.0.webview.clone()
  }
  pub(crate) fn same(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
  pub(crate) fn matches_id(&self, id: &str) -> bool {
    self.0.logical_id == id
  }
  pub(crate) fn matches(
    &self,
    env: &JNIEnv<'_>,
    webview: &JObject<'_>,
  ) -> jni::errors::Result<bool> {
    env.is_same_object(self.webview(), webview)
  }
  pub(crate) fn live_on_main(&self, env: &mut JNIEnv<'_>) -> jni::errors::Result<bool> {
    Ok(
      self.is_live()
        && self.0.activity.live_on_main(env)?
        && main_pipe::view_origin_current(self)
        && handlers::current(&self.0.registration),
    )
  }
  /// Schedules against the retained original objects. A retired/invalid origin
  /// invokes the callback with null objects so the caller can reject its pending
  /// operation; it never substitutes a newly registered Activity or WebView.
  pub fn exec<F>(&self, callback: F) -> Result<()>
  where
    F: FnOnce(&mut JNIEnv<'_>, &JObject<'_>, &JObject<'_>) + Send + 'static,
  {
    if !self.is_live() {
      return Err(Error::ActivityNotFound);
    }
    MainPipe::send(
      self.0.activity.id(),
      WebViewMessage::OriginJni(self.clone(), Box::new(callback)),
    )
  }
  /// Response delivery remains tied to the original physical view, including
  /// when a logical ID is reused by Android configuration recreation.
  pub fn eval(&self, script: String) -> Result<()> {
    self.exec(move |env, _, webview| {
      if webview.is_null() {
        return;
      }
      if let Ok(script) = env.new_string(script) {
        let _ = env.call_method(
          webview,
          "evaluateJavascript",
          "(Ljava/lang/String;Landroid/webkit/ValueCallback;)V",
          &[(&script).into(), (&JObject::null()).into()],
        );
      }
    })
  }
}

pub(crate) fn capture_webview_origin(
  env: &mut JNIEnv<'_>,
  webview: &JObject<'_>,
) -> Result<AndroidWebviewOrigin> {
  if let Some(origin) = main_pipe::origin_for_view(env, webview)? {
    if origin.live_on_main(env)? {
      return Ok(origin);
    }
  }
  Err(Error::ActivityNotFound)
}
