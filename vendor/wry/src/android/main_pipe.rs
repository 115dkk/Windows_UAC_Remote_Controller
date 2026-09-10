// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use crate::{Error, InitializationScript, RGBA};
use crossbeam_channel::*;
use jni::{
  errors::Result as JniResult,
  objects::{GlobalRef, JMap, JObject, JString},
  JNIEnv,
};
use once_cell::sync::{Lazy, OnceCell};
use std::{
  collections::{BTreeMap, VecDeque},
  os::unix::prelude::*,
  sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
  },
  thread::ThreadId,
};

use super::{
  find_class,
  handlers::{self, HandlerRegistration},
  origin::WeakActivityOrigin,
  AndroidActivityOrigin, AndroidWebviewOrigin, EvalCallback, PendingEval, EVAL_CALLBACKS, PACKAGE,
};

pub type ActivityId = i32;

type Envelope = (ActivityId, Option<AndroidActivityOrigin>, WebViewMessage);
const QUEUE_CAPACITY: usize = 8;
static QUEUE: Lazy<Mutex<VecDeque<Envelope>>> = Lazy::new(|| Mutex::new(VecDeque::new()));
static QUEUE_CLOSED: AtomicBool = AtomicBool::new(false);
pub static MAIN_PIPE: Lazy<[OwnedFd; 2]> = Lazy::new(|| {
  let mut pipe: [RawFd; 2] = [-1; 2];
  // Both queue admission and its wake must be nonblocking on Android main.
  // No OwnedFd is constructed unless both pipe descriptors were initialized.
  let result = unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
  assert_eq!(result, 0, "Wry main pipe initialization failed");
  unsafe { pipe.map(|fd| OwnedFd::from_raw_fd(fd)) }
});
static MAIN_THREAD: OnceCell<ThreadId> = OnceCell::new();
enum Bootstrap {
  Waiting,
  Registered(WeakActivityOrigin),
  Failed,
}
static BOOTSTRAP: Lazy<(Mutex<Bootstrap>, Condvar)> =
  Lazy::new(|| (Mutex::new(Bootstrap::Waiting), Condvar::new()));

pub(crate) fn initialize_main_thread() -> bool {
  MAIN_THREAD.set(std::thread::current().id()).is_ok()
}
pub(crate) fn publish_initial_activity(origin: &AndroidActivityOrigin) {
  let mut bootstrap = BOOTSTRAP.0.lock().unwrap();
  if matches!(*bootstrap, Bootstrap::Waiting) {
    *bootstrap = Bootstrap::Registered(origin.downgrade());
    BOOTSTRAP.1.notify_all();
  }
}
/// Only the initial Rust-thread/bootstrap race may wait. Android main never
/// waits for itself, and no post-registration gap waits for a future Activity.
pub(crate) fn dispatch_activity() -> Option<AndroidActivityOrigin> {
  let bootstrap = BOOTSTRAP.0.lock().unwrap();
  match &*bootstrap {
    Bootstrap::Failed => None,
    Bootstrap::Registered(_) => {
      drop(bootstrap);
      first_activity_origin()
    }
    Bootstrap::Waiting => {
      let main_thread = MAIN_THREAD.get()?;
      if *main_thread == std::thread::current().id() {
        return None;
      }
      let (mut bootstrap, _) = BOOTSTRAP
        .1
        .wait_timeout_while(bootstrap, super::MAIN_PIPE_TIMEOUT, |state| {
          matches!(state, Bootstrap::Waiting)
        })
        .unwrap();
      match &*bootstrap {
        Bootstrap::Registered(original) => original.upgrade().filter(activity_origin_current),
        Bootstrap::Waiting => {
          *bootstrap = Bootstrap::Failed;
          BOOTSTRAP.1.notify_all();
          None
        }
        Bootstrap::Failed => None,
      }
    }
  }
}

#[derive(Clone)]
pub struct ActivityProxy {
  pub origin: AndroidActivityOrigin,
  pub view_origin: Option<AndroidWebviewOrigin>,
  pub activity: GlobalRef,
  pub webview: Option<GlobalRef>,
  pub webchrome_client: GlobalRef,
}

impl ActivityProxy {
  pub fn new(
    activity: GlobalRef,
    webchrome_client: GlobalRef,
    origin: AndroidActivityOrigin,
  ) -> Self {
    Self {
      origin,
      view_origin: None,
      activity,
      webview: None,
      webchrome_client,
    }
  }
}

static ACTIVITY_PROXY: once_cell::sync::Lazy<Mutex<BTreeMap<ActivityId, ActivityProxy>>> =
  Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn activity_proxy(id: ActivityId) -> Option<ActivityProxy> {
  ACTIVITY_PROXY.lock().unwrap().get(&id).cloned()
}
fn activity_proxy_for_origin(origin: &AndroidActivityOrigin) -> Option<ActivityProxy> {
  ACTIVITY_PROXY
    .lock()
    .unwrap()
    .get(&origin.id())
    .filter(|proxy| proxy.origin.same(origin))
    .cloned()
}

pub(crate) fn remove_activity_proxy(origin: &AndroidActivityOrigin) {
  let removed = {
    let mut proxies = ACTIVITY_PROXY.lock().unwrap();
    if proxies
      .get(&origin.id())
      .is_some_and(|proxy| proxy.origin.same(origin))
    {
      proxies.remove(&origin.id())
    } else {
      None
    }
  };
  if let Some(proxy) = removed {
    proxy.origin.retire();
    if let Some(view) = proxy.view_origin {
      view.retire();
    }
  }
}

pub fn register_activity_proxy(
  id: ActivityId,
  activity: GlobalRef,
  webchrome_client: GlobalRef,
  origin: AndroidActivityOrigin,
) -> bool {
  let mut activity_proxy = ACTIVITY_PROXY.lock().unwrap();
  if !activity_proxy.contains_key(&id) && activity_proxy.len() >= 32 {
    origin.retire();
    return false;
  }
  let previous = activity_proxy.remove(&id);
  if let Some(previous) = &previous {
    previous.origin.retire();
    if let Some(view) = &previous.view_origin {
      view.retire();
    }
  }
  activity_proxy.insert(id, ActivityProxy::new(activity, webchrome_client, origin));
  drop(activity_proxy);
  if let Some(previous) = previous {
    super::cancel_evals_for_activity(&previous.origin);
  }
  true
}

pub(crate) fn activity_origins() -> Vec<AndroidActivityOrigin> {
  ACTIVITY_PROXY
    .lock()
    .unwrap()
    .values()
    .map(|proxy| proxy.origin.clone())
    .collect()
}
pub(crate) fn origin_for_activity(
  env: &JNIEnv<'_>,
  activity: &JObject<'_>,
) -> JniResult<Option<AndroidActivityOrigin>> {
  for proxy in ACTIVITY_PROXY.lock().unwrap().values() {
    if proxy.origin.matches_activity(env, activity)? {
      return Ok(Some(proxy.origin.clone()));
    }
  }
  Ok(None)
}
pub(crate) fn origin_for_view(
  env: &JNIEnv<'_>,
  webview: &JObject<'_>,
) -> JniResult<Option<AndroidWebviewOrigin>> {
  for proxy in ACTIVITY_PROXY.lock().unwrap().values() {
    if let Some(origin) = &proxy.view_origin {
      if origin.matches(env, webview)? {
        return Ok(Some(origin.clone()));
      }
    }
  }
  Ok(None)
}
pub(crate) fn view_origin_current(origin: &AndroidWebviewOrigin) -> bool {
  ACTIVITY_PROXY
    .lock()
    .unwrap()
    .get(&origin.activity_origin().id())
    .is_some_and(|proxy| {
      proxy.origin.same(origin.activity_origin())
        && proxy
          .view_origin
          .as_ref()
          .is_some_and(|view| view.same(origin))
    })
}
fn activity_origin_current(origin: &AndroidActivityOrigin) -> bool {
  ACTIVITY_PROXY
    .lock()
    .unwrap()
    .get(&origin.id())
    .is_some_and(|proxy| proxy.origin.same(origin) && proxy.origin.is_live())
}
pub(crate) fn retire_activity(
  env: &JNIEnv<'_>,
  activity: &JObject<'_>,
) -> Option<AndroidActivityOrigin> {
  let proxies = ACTIVITY_PROXY.lock().unwrap();
  let proxy = proxies.values().find(|proxy| {
    proxy
      .origin
      .matches_activity(env, activity)
      .unwrap_or(false)
  })?;
  proxy.origin.retire();
  if let Some(view) = &proxy.view_origin {
    view.retire();
  }
  Some(proxy.origin.clone())
}
fn register_view(origin: &AndroidWebviewOrigin) -> bool {
  let mut proxies = ACTIVITY_PROXY.lock().unwrap();
  let Some(proxy) = proxies.get_mut(&origin.activity_origin().id()) else {
    return false;
  };
  if !proxy.origin.same(origin.activity_origin())
    || !origin.is_live()
    || proxy
      .view_origin
      .as_ref()
      .is_some_and(|view| view.is_live())
  {
    return false;
  }
  proxy.webview = Some(origin.view_reference());
  proxy.view_origin = Some(origin.clone());
  true
}

struct ViewCreation(AndroidWebviewOrigin, bool);
impl Drop for ViewCreation {
  fn drop(&mut self) {
    if !self.1 {
      self.0.retire();
    }
  }
}
struct RegistrationCreation(HandlerRegistration, bool);
impl Drop for RegistrationCreation {
  fn drop(&mut self) {
    if !self.1 {
      handlers::rollback(&self.0);
    }
  }
}

fn first_activity_origin() -> Option<AndroidActivityOrigin> {
  ACTIVITY_PROXY
    .lock()
    .unwrap()
    .values()
    .find(|proxy| proxy.origin.is_live())
    .map(|proxy| proxy.origin.clone())
}

pub fn get_webview(activity_id: ActivityId) -> Option<GlobalRef> {
  let proxies = ACTIVITY_PROXY.lock().unwrap();
  let proxy = proxies.get(&activity_id)?;
  if !proxy.origin.is_live()
    || !proxy
      .view_origin
      .as_ref()
      .is_some_and(|origin| origin.is_live())
  {
    return None;
  }
  proxy.webview.clone()
}

pub struct MainPipe<'a> {
  pub env: JNIEnv<'a>,
}

impl<'a> MainPipe<'a> {
  pub(crate) fn send(activity_id: ActivityId, message: WebViewMessage) -> crate::Result<()> {
    // Generic logical operations fence the physical generation at enqueue.
    // OriginJni/Create carry their stronger explicit original witness.
    let stamp = if matches!(
      &message,
      WebViewMessage::CreateWebView(_) | WebViewMessage::OriginJni(_, _)
    ) {
      None // These variants retain their original typed witness already.
    } else {
      activity_proxy(activity_id)
        .map(|proxy| proxy.origin)
        .filter(|origin| origin.is_live())
    };
    Self::enqueue(activity_id, stamp, message)
  }

  pub(crate) fn send_to_origin(
    origin: AndroidActivityOrigin,
    message: WebViewMessage,
  ) -> crate::Result<()> {
    Self::enqueue(origin.id(), Some(origin), message)
  }

  pub(crate) fn send_without_activity(message: WebViewMessage) -> crate::Result<()> {
    if MAIN_THREAD.get().is_none() || matches!(*BOOTSTRAP.0.lock().unwrap(), Bootstrap::Failed) {
      return Err(Error::ActivityNotFound);
    }
    Self::enqueue(0, None, message)
  }

  fn enqueue(
    activity_id: ActivityId,
    stamp: Option<AndroidActivityOrigin>,
    message: WebViewMessage,
  ) -> crate::Result<()> {
    // Never block the thread which consumes this queue. On every rejection the
    // captures are dropped outside the lock and can never execute afterwards.
    let Ok(mut queue) = QUEUE.try_lock() else {
      return Err(Error::ActivityNotFound);
    };
    if QUEUE_CLOSED.load(Ordering::Acquire) || queue.len() >= QUEUE_CAPACITY {
      drop(queue);
      return Err(Error::ActivityNotFound);
    }
    queue.push_back((activity_id, stamp, message));
    let wake: u8 = 1;
    let written =
      unsafe { libc::write(MAIN_PIPE[1].as_raw_fd(), &wake as *const _ as *const _, 1) };
    if written != 1 {
      let error = std::io::Error::last_os_error();
      if error.kind() != std::io::ErrorKind::WouldBlock {
        let rejected = queue.pop_back();
        drop(queue);
        drop(rejected);
        return Err(error.into());
      }
      // EAGAIN means the nonblocking pipe already has a pending wake. The
      // receiver drains the bounded queue on that wake.
    }
    Ok(())
  }

  pub(crate) fn close_queue() {
    let cancelled = {
      let mut queue = QUEUE.lock().unwrap();
      QUEUE_CLOSED.store(true, Ordering::Release);
      std::mem::take(&mut *queue)
    };
    for (_, _, message) in cancelled {
      if let WebViewMessage::CreateWebView(attributes) = &message {
        handlers::rollback(&attributes.registration);
      }
      // Pending command captures cancel their exact SDK entry when dropped.
      drop(message);
    }
  }

  pub fn recv(&mut self) -> JniResult<()> {
    let next = QUEUE.lock().unwrap().pop_front();
    if let Some((activity_id, stamp, message)) = next {
      let explicit_origin = matches!(
        &message,
        WebViewMessage::CreateWebView(_) | WebViewMessage::OriginJni(_, _)
      );
      if !explicit_origin {
        let live = match stamp {
          Some(origin) => {
            activity_origin_current(&origin) && origin.live_on_main(&mut self.env).unwrap_or(false)
          }
          None => false,
        };
        if !live {
          let _ = self.env.exception_clear();
          match message {
            WebViewMessage::Jni(callback) => {
              callback(&mut self.env, &JObject::null(), &JObject::null())
            }
            WebViewMessage::GetWebViewVersion(sender) => {
              let _ = sender.send(Err(Error::ActivityNotFound));
            }
            WebViewMessage::GetUrl(sender) => drop(sender),
            WebViewMessage::GetCookies(sender, _) => drop(sender),
            // This callback API has no error value. Cancellation drops its
            // captures instead of inventing a successful JavaScript result.
            WebViewMessage::Eval(_, callback) => drop(callback),
            _ => (),
          }
          return Ok(());
        }
      }
      match message {
        WebViewMessage::CreateWebView(attrs) => {
          let mut registered = RegistrationCreation(attrs.registration.clone(), false);
          if !handlers::current(&attrs.registration) {
            return Ok(());
          }
          let Some((activity, web_chrome_client)) =
            activity_proxy_for_origin(&attrs.activity_origin).map(|proxy| {
              (
                attrs.activity_origin.activity_reference(),
                proxy.webchrome_client.clone(),
              )
            })
          else {
            #[cfg(debug_assertions)]
            eprintln!("no activity found for activity id: {}", activity_id);
            return Ok(());
          };
          if !attrs.activity_origin.live_on_main(&mut self.env)? {
            return Ok(());
          }
          let activity_origin = attrs.activity_origin.clone();
          let registration = attrs.registration.clone();
          let CreateWebViewAttributes {
            url,
            html,
            #[cfg(any(debug_assertions, feature = "devtools"))]
            devtools,
            transparent,
            background_color,
            headers,
            on_webview_created,
            autoplay,
            user_agent,
            initialization_scripts,
            id,
            javascript_disabled,
            ..
          } = attrs;

          let string_class = self.env.find_class("java/lang/String")?;
          let initialization_scripts_array = self.env.new_object_array(
            initialization_scripts.len() as i32,
            string_class,
            self.env.new_string("")?,
          )?;
          for (i, init_script) in initialization_scripts.into_iter().enumerate() {
            self.env.set_object_array_element(
              &initialization_scripts_array,
              i as i32,
              self.env.new_string(init_script.script)?,
            )?;
          }
          let logical_id = id.clone();
          let id = self.env.new_string(id)?;
          // Create webview
          let rust_webview_class = find_class(
            &mut self.env,
            &activity,
            format!("{}/RustWebView", PACKAGE.get().unwrap()),
          )?;
          let webview = self.env.new_object(
            &rust_webview_class,
            "(Landroid/content/Context;[Ljava/lang/String;Ljava/lang/String;)V",
            &[
              (&activity).into(),
              (&initialization_scripts_array).into(),
              (&id).into(),
            ],
          )?;
          let Ok(view_origin) = AndroidWebviewOrigin::new(
            &mut self.env,
            activity_origin,
            registration,
            &webview,
            logical_id,
          ) else {
            return Ok(());
          };
          let mut creation = ViewCreation(view_origin, false);
          if !register_view(&creation.0) {
            return Ok(());
          }
          // get settings
          let web_settings = self
            .env
            .call_method(
              &webview,
              "getSettings",
              "()Landroid/webkit/WebSettings;",
              &[],
            )?
            .l()?;
          // set media autoplay
          self.env.call_method(
            &web_settings,
            "setMediaPlaybackRequiresUserGesture",
            "(Z)V",
            &[(!autoplay).into()],
          )?;
          // set user-agent
          if let Some(user_agent) = user_agent {
            let user_agent = self.env.new_string(user_agent)?;
            self.env.call_method(
              &web_settings,
              "setUserAgentString",
              "(Ljava/lang/String;)V",
              &[(&user_agent).into()],
            )?;
          }

          // disable javascript
          if javascript_disabled {
            self.env.call_method(
              &web_settings,
              "setJavaScriptEnabled",
              "(Z)V",
              &[false.into()],
            )?;
          }

          let webview_class_name = format!("{}/RustWebView", PACKAGE.get().unwrap());
          if !creation.0.live_on_main(&mut self.env)? {
            return Ok(());
          }
          self.env.call_method(
            &activity,
            "setWebView",
            format!("(L{webview_class_name};)V"),
            &[(&webview).into()],
          )?;
          // Navigation
          if let Some(u) = url {
            if let Ok(url) = self.env.new_string(u) {
              load_url(&mut self.env, &webview, &url, headers, true)?;
            }
          } else if let Some(h) = html {
            if let Ok(html) = self.env.new_string(h) {
              load_html(&mut self.env, &webview, &html)?;
            }
          }
          // Enable devtools
          #[cfg(any(debug_assertions, feature = "devtools"))]
          self.env.call_static_method(
            &rust_webview_class,
            "setWebContentsDebuggingEnabled",
            "(Z)V",
            &[devtools.into()],
          )?;
          if transparent {
            set_background_color(&mut self.env, &webview, (0, 0, 0, 0))?;
          } else if let Some(color) = background_color {
            set_background_color(&mut self.env, &webview, color)?;
          }
          // Create and set webview client
          let client_class_name = format!("{}/RustWebViewClient", PACKAGE.get().unwrap());
          let rust_webview_client_class =
            find_class(&mut self.env, &activity, client_class_name.clone())?;
          let webview_client = self.env.new_object(
            &rust_webview_client_class,
            format!("(L{webview_class_name};Landroid/content/Context;)V"),
            &[(&webview).into(), (&activity).into()],
          )?;
          self.env.call_method(
            &webview,
            "setWebViewClient",
            "(Landroid/webkit/WebViewClient;)V",
            &[(&webview_client).into()],
          )?;
          // set webchrome client
          self.env.call_method(
            &webview,
            "setWebChromeClient",
            "(Landroid/webkit/WebChromeClient;)V",
            &[web_chrome_client.as_obj().into()],
          )?;

          // Add javascript interface (IPC)
          let ipc_class = find_class(
            &mut self.env,
            &activity,
            format!("{}/Ipc", PACKAGE.get().unwrap()),
          )?;
          let ipc = self.env.new_object(
            ipc_class,
            format!("(L{webview_class_name};L{client_class_name};)V"),
            &[(&webview).into(), (&webview_client).into()],
          )?;
          let ipc_str = self.env.new_string("ipc")?;
          self.env.call_method(
            &webview,
            "addJavascriptInterface",
            "(Ljava/lang/Object;Ljava/lang/String;)V",
            &[(&ipc).into(), (&ipc_str).into()],
          )?;

          // Set content view
          if !creation.0.live_on_main(&mut self.env)? {
            return Ok(());
          }
          self.env.call_method(
            &activity,
            "setContentView",
            "(Landroid/view/View;)V",
            &[(&webview).into()],
          )?;

          if let Some(on_webview_created) = on_webview_created {
            if let Err(_e) = on_webview_created(super::Context {
              env: &mut self.env,
              activity: &activity,
              webview: &webview,
            }) {
              #[cfg(feature = "tracing")]
              tracing::warn!("failed to run webview created hook: {_e}");
            }
          }

          if !creation.0.live_on_main(&mut self.env)? {
            return Ok(());
          }
          creation.1 = true;
          registered.1 = true;
        }
        WebViewMessage::Eval(script, callback) => {
          if let Some(webview) = get_webview(activity_id) {
            let Ok(origin) = super::origin::capture_webview_origin(&mut self.env, webview.as_obj())
            else {
              return Ok(());
            };
            let Some(callback) = callback else {
              let s = self.env.new_string(script)?;
              self.env.call_method(
                webview.as_obj(),
                "evaluateJavascript",
                "(Ljava/lang/String;Landroid/webkit/ValueCallback;)V",
                &[(&s).into(), (&JObject::null()).into()],
              )?;
              return Ok(());
            };
            let Some(id) = super::next_eval_id() else {
              return Ok(());
            };

            #[cfg(feature = "tracing")]
            let span = std::sync::Mutex::new(Some(SendEnteredSpan(
              tracing::debug_span!("wry::eval").entered(),
            )));

            let callback: EvalCallback = Box::new(move |result: String| {
              #[cfg(feature = "tracing")]
              span.lock().unwrap().take();
              callback(result);
            });
            {
              let mut pending = EVAL_CALLBACKS.get_or_init(Default::default).lock().unwrap();
              if pending.len() >= 64 || pending.contains_key(&id) {
                return Ok(());
              }
              pending.insert(id, PendingEval { origin, callback });
            }
            let evaluated = (|| -> JniResult<()> {
              let s = self.env.new_string(script)?;
              self.env.call_method(
                webview.as_obj(),
                "evalScript",
                "(ILjava/lang/String;)V",
                &[id.into(), (&s).into()],
              )?;
              Ok(())
            })();
            if evaluated.is_err() {
              let cancelled = EVAL_CALLBACKS
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .remove(&id);
              drop(cancelled);
            }
            evaluated?;
          }
        }
        WebViewMessage::SetBackgroundColor(background_color) => {
          if let Some(webview) = get_webview(activity_id) {
            set_background_color(&mut self.env, webview.as_obj(), background_color)?;
          }
        }
        WebViewMessage::GetWebViewVersion(tx) => {
          if let Some(activity) = activity_proxy(activity_id).map(|p| p.activity.clone()) {
            match self
              .env
              .call_method(activity, "getVersion", "()Ljava/lang/String;", &[])
              .and_then(|v| v.l())
              .and_then(|s| {
                let s = JString::from(s);
                self
                  .env
                  .get_string(&s)
                  .map(|v| v.to_string_lossy().to_string())
              }) {
              Ok(version) => {
                let _ = tx.send(Ok(version));
              }
              Err(e) => {
                let _ = tx.send(Err(e.into()));
              }
            }
          } else {
            let _ = tx.send(Err(Error::ActivityNotFound));
          }
        }
        WebViewMessage::GetUrl(tx) => {
          if let Some(webview) = get_webview(activity_id) {
            let url = self
              .env
              .call_method(webview.as_obj(), "getUrl", "()Ljava/lang/String;", &[])
              .and_then(|v| v.l())
              .and_then(|s| {
                let s = JString::from(s);
                self
                  .env
                  .get_string(&s)
                  .map(|v| v.to_string_lossy().to_string())
              })
              .unwrap_or_default();

            let _ = tx.send(url);
          }
        }
        WebViewMessage::Jni(f) => {
          match activity_proxy(activity_id).map(|p| {
            let webview = if p
              .view_origin
              .as_ref()
              .is_some_and(|origin| origin.is_live())
            {
              p.webview.clone()
            } else {
              None
            };
            (p.activity.clone(), webview)
          }) {
            Some((activity, Some(webview))) => {
              f(&mut self.env, &activity, webview.as_obj());
            }
            Some((activity, None)) => {
              f(&mut self.env, &activity, &JObject::null());
            }
            _ => {
              f(&mut self.env, &JObject::null(), &JObject::null());
            }
          }
        }
        WebViewMessage::OriginJni(origin, f) => {
          if origin.live_on_main(&mut self.env).unwrap_or(false) {
            f(
              &mut self.env,
              origin.activity_origin().activity(),
              origin.webview(),
            );
          } else {
            let _ = self.env.exception_clear();
            f(&mut self.env, &JObject::null(), &JObject::null());
          }
        }
        WebViewMessage::LoadUrl(url, headers) => {
          if let Some(webview) = get_webview(activity_id) {
            let url = self.env.new_string(url)?;
            load_url(&mut self.env, webview.as_obj(), &url, headers, false)?;
          }
        }
        WebViewMessage::ClearAllBrowsingData => {
          if let Some(webview) = get_webview(activity_id) {
            self
              .env
              .call_method(webview, "clearAllBrowsingData", "()V", &[])?;
          }
        }
        WebViewMessage::LoadHtml(html) => {
          if let Some(webview) = get_webview(activity_id) {
            let html = self.env.new_string(html)?;
            load_html(&mut self.env, webview.as_obj(), &html)?;
          }
        }
        WebViewMessage::Reload => {
          if let Some(webview) = get_webview(activity_id) {
            reload(&mut self.env, webview.as_obj())?;
          }
        }
        WebViewMessage::GetCookies(tx, url) => {
          if let Some(webview) = get_webview(activity_id) {
            let url = self.env.new_string(url)?;
            let cookies = self
              .env
              .call_method(
                webview,
                "getCookies",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[(&url).into()],
              )
              .and_then(|v| v.l())
              .and_then(|s| {
                let s = JString::from(s);
                self
                  .env
                  .get_string(&s)
                  .map(|v| v.to_string_lossy().to_string())
              })
              .unwrap_or_default();

            let _ = tx.send(
              cookies
                .split("; ")
                .flat_map(|c| cookie::Cookie::parse(c.to_string()))
                .collect(),
            );
          }
        }
      }
    }
    Ok(())
  }
}

fn load_url<'a>(
  env: &mut JNIEnv<'a>,
  webview: &JObject<'a>,
  url: &JString<'a>,
  headers: Option<http::HeaderMap>,
  main_thread: bool,
) -> JniResult<()> {
  let function = if main_thread {
    "loadUrlMainThread"
  } else {
    "loadUrl"
  };
  if let Some(headers) = headers {
    let obj = env.new_object("java/util/HashMap", "()V", &[])?;
    let headers_map = {
      let headers_map = JMap::from_env(env, &obj)?;
      for (name, value) in headers.iter() {
        let key = env.new_string(name)?;
        let value = env.new_string(value.to_str().unwrap_or_default())?;
        headers_map.put(env, &key, &value)?;
      }
      headers_map
    };
    env.call_method(
      webview,
      function,
      "(Ljava/lang/String;Ljava/util/Map;)V",
      &[url.into(), (&headers_map).into()],
    )?;
  } else {
    env.call_method(webview, function, "(Ljava/lang/String;)V", &[url.into()])?;
  }
  Ok(())
}

fn load_html<'a>(env: &mut JNIEnv<'a>, webview: &JObject<'a>, html: &JString<'a>) -> JniResult<()> {
  env.call_method(
    webview,
    "loadHTMLMainThread",
    "(Ljava/lang/String;)V",
    &[html.into()],
  )?;
  Ok(())
}

fn reload<'a>(env: &mut JNIEnv<'a>, webview: &JObject<'a>) -> JniResult<()> {
  env.call_method(webview, "reload", "()V", &[])?;
  Ok(())
}

fn set_background_color<'a>(
  env: &mut JNIEnv<'a>,
  webview: &JObject<'a>,
  (r, g, b, a): RGBA,
) -> JniResult<()> {
  let color = (a as i32) << 24 | (r as i32) << 16 | (g as i32) << 8 | (b as i32);
  env.call_method(webview, "setBackgroundColor", "(I)V", &[color.into()])?;
  Ok(())
}

pub(crate) enum WebViewMessage {
  CreateWebView(CreateWebViewAttributes),
  Eval(String, Option<EvalCallback>),
  SetBackgroundColor(RGBA),
  GetWebViewVersion(Sender<Result<String, Error>>),
  GetUrl(Sender<String>),
  GetCookies(Sender<Vec<cookie::Cookie<'static>>>, String),
  Jni(Box<dyn FnOnce(&mut JNIEnv, &JObject, &JObject) + Send>),
  OriginJni(
    AndroidWebviewOrigin,
    Box<dyn FnOnce(&mut JNIEnv, &JObject, &JObject) + Send>,
  ),
  LoadUrl(String, Option<http::HeaderMap>),
  LoadHtml(String),
  Reload,
  ClearAllBrowsingData,
}

#[derive(Clone)]
pub(crate) struct CreateWebViewAttributes {
  pub activity_origin: AndroidActivityOrigin,
  pub registration: HandlerRegistration,
  pub configuration_recreate: bool,
  pub id: String,
  pub url: Option<String>,
  pub html: Option<String>,
  #[cfg(any(debug_assertions, feature = "devtools"))]
  pub devtools: bool,
  pub transparent: bool,
  pub background_color: Option<RGBA>,
  pub headers: Option<http::HeaderMap>,
  pub autoplay: bool,
  pub on_webview_created:
    Option<Arc<dyn Fn(super::Context) -> JniResult<()> + Send + Sync + 'static>>,
  pub user_agent: Option<String>,
  pub initialization_scripts: Vec<InitializationScript>,
  pub javascript_disabled: bool,
}

// SAFETY: only use this when you are sure the span will be dropped on the same thread it was entered
#[cfg(feature = "tracing")]
struct SendEnteredSpan(tracing::span::EnteredSpan);

#[cfg(feature = "tracing")]
unsafe impl Send for SendEnteredSpan {}
