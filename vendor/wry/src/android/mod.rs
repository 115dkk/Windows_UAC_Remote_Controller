// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::{PageLoadEvent, WebViewAttributes, RGBA};
use crate::{
  custom_protocol_workaround, inject_initialization_scripts::inject_scripts_into_html, Error,
  RequestAsyncResponder, Result,
};
use crossbeam_channel::*;

use http::{Request, Response as HttpResponse};
use jni::{
  errors::Result as JniResult,
  objects::{GlobalRef, JClass, JObject},
  JNIEnv,
};
use ndk::looper::ThreadLooper;
use once_cell::sync::OnceCell;
use raw_window_handle::HasWindowHandle;
use std::{
  borrow::Cow,
  collections::HashMap,
  sync::{
    mpsc::{channel, Receiver as ResponseReceiver},
    Mutex,
  },
  time::Duration,
};

pub(crate) mod binding;
mod handlers;
mod main_pipe;
mod origin;
use main_pipe::{
  register_activity_proxy, ActivityId, CreateWebViewAttributes, MainPipe, WebViewMessage,
};
pub use origin::{android_activity_origin, AndroidActivityOrigin, AndroidWebviewOrigin};

use crate::util::Counter;

static COUNTER: Counter = Counter::new();
const MAIN_PIPE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Context<'a, 'b> {
  pub env: &'a mut JNIEnv<'b>,
  pub activity: &'a JObject<'b>,
  pub webview: &'a JObject<'b>,
}

type WebviewId = String;

macro_rules! define_handlers {
  ($($type_name:ident { $($fields:ident:$types:ty),+ $(,)? });+ $(;)?) => {
    $(
    pub struct $type_name {
      $($fields: $types,)*
    }
    impl $type_name {
      pub fn new($($fields: $types,)*) -> Self {
        Self {
          $($fields,)*
        }
      }
    }
    // Retain Wry's existing erased callback thread-transfer contract. These
    // values are NEVER shared directly: one per-registration mutex serializes
    // invocation, including across configuration restoration.
    unsafe impl Send for $type_name {})*
  };
}

define_handlers! {
  UnsafeIpc { handler: Box<dyn Fn(Request<String>)> };
  UnsafeRequestHandler { handler: Box<dyn Fn(&str, Request<Vec<u8>>, bool) -> Option<ResponseReceiver<HttpResponse<Cow<'static, [u8]>>>>> };
  UnsafeTitleHandler { handler: Box<dyn Fn(String)> };
  UnsafeUrlLoadingOverride { handler: Box<dyn Fn(String) -> bool> };
  UnsafeOnPageLoadHandler { handler: Box<dyn Fn(PageLoadEvent, String)> };
}

pub(crate) static PACKAGE: OnceCell<String> = OnceCell::new();

type EvalCallback = Box<dyn Fn(String) + Send + 'static>;

pub(crate) struct PendingEval {
  pub origin: AndroidWebviewOrigin,
  pub callback: EvalCallback,
}
pub(crate) static EVAL_CALLBACKS: OnceCell<Mutex<HashMap<i32, PendingEval>>> = OnceCell::new();
pub(crate) fn next_eval_id() -> Option<i32> {
  use std::sync::atomic::{AtomicI32, Ordering};
  static NEXT: AtomicI32 = AtomicI32::new(1);
  NEXT
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
    .ok()
}
pub(crate) fn cancel_evals_for_activity(origin: &AndroidActivityOrigin) {
  let cancelled = {
    let mut pending = EVAL_CALLBACKS.get_or_init(Default::default).lock().unwrap();
    let ids = pending
      .iter()
      .filter(|(_, entry)| entry.origin.activity_origin().same(origin))
      .map(|(id, _)| *id)
      .collect::<Vec<_>>();
    ids
      .into_iter()
      .filter_map(|id| pending.remove(&id))
      .collect::<Vec<_>>()
  };
  // Drop callback captures outside registry locks. There is no successful
  // substitute value for a JavaScript evaluation cancelled by destruction.
  drop(cancelled);
}

/// Sets up the necessary logic for wry to be able to create the webviews later.
///
/// This function must be run on the thread where the [`JNIEnv`] is registered and the looper is local,
/// hence the requirement for a [`ThreadLooper`].
pub unsafe fn android_setup(
  package: &str,
  mut env: JNIEnv,
  _looper: &ThreadLooper,
  activity: GlobalRef,
) {
  PACKAGE.get_or_init(move || package.to_string());

  let activity_id = env
    .call_method(activity.as_obj(), "getId", "()I", &[])
    .unwrap()
    .i()
    .unwrap();

  let window_manager = env
    .call_method(
      &activity,
      "getWindowManager",
      "()Landroid/view/WindowManager;",
      &[],
    )
    .unwrap()
    .l()
    .unwrap();
  let window_manager = env.new_global_ref(window_manager).unwrap();

  // we must create the WebChromeClient here because it calls `registerForActivityResult`,
  // which gives an `LifecycleOwners must call register before they are STARTED.` error when called outside the onCreate hook
  let rust_webchrome_client_class = find_class(
    &mut env,
    activity.as_obj(),
    format!("{}/RustWebChromeClient", PACKAGE.get().unwrap()),
  )
  .unwrap();
  let webchrome_client = env
    .new_object(
      &rust_webchrome_client_class,
      format!("(L{}/WryActivity;)V", PACKAGE.get().unwrap()),
      &[activity.as_obj().into()],
    )
    .unwrap();

  let webchrome_client = env.new_global_ref(webchrome_client).unwrap();

  let Ok(origin) = AndroidActivityOrigin::new(
    &mut env,
    activity_id,
    activity.clone(),
    window_manager.clone(),
  ) else {
    return;
  };
  if !register_activity_proxy(activity_id, activity, webchrome_client, origin.clone()) {
    return;
  }

  if !origin.live_on_main(&mut env).unwrap_or(false) {
    main_pipe::remove_activity_proxy(&origin);
    return;
  }
  // Publish bootstrap readiness only after this actual original registration.
  main_pipe::publish_initial_activity(&origin);
  if let Some((attributes, rollback)) = handlers::prepare_configuration(&origin) {
    // No registry lock crosses enqueue. A rejected enqueue restores only the
    // dormant definition/permission; it does not revive an old physical view.
    if MainPipe::send(activity_id, WebViewMessage::CreateWebView(attributes)).is_err() {
      handlers::rollback_configuration(rollback);
      main_pipe::remove_activity_proxy(&origin);
    }
  }
}

pub(crate) struct InnerWebView {
  id: String,
  pub activity_id: ActivityId,
}

impl InnerWebView {
  pub fn new_as_child(
    window: &impl HasWindowHandle,
    attributes: WebViewAttributes,
    pl_attrs: super::PlatformSpecificWebViewAttributes,
  ) -> Result<Self> {
    Self::new(window, attributes, pl_attrs)
  }

  pub fn new(
    window: &impl HasWindowHandle,
    attributes: WebViewAttributes,
    mut pl_attrs: super::PlatformSpecificWebViewAttributes,
  ) -> Result<Self> {
    let window_manager = match window.window_handle()?.as_raw() {
      raw_window_handle::RawWindowHandle::AndroidNdk(window_manager) => {
        window_manager.a_native_window
      }
      _ => return Err(Error::UnsupportedWindowHandle),
    };
    let window_manager = unsafe { JObject::from_raw(window_manager.as_ptr().cast()) };
    let origin = if let Some(origin) = pl_attrs.android_activity_origin.take() {
      if !origin.matches_window_manager(&window_manager)? {
        return Err(Error::ActivityNotFound);
      }
      origin
    } else {
      main_pipe::activity_origins()
        .into_iter()
        .find(|origin| {
          origin
            .matches_window_manager(&window_manager)
            .unwrap_or(false)
        })
        .ok_or(Error::ActivityNotFound)?
    };
    let activity_id = origin.id();
    let WebViewAttributes {
      url,
      html,
      initialization_scripts,
      ipc_handler,
      #[cfg(any(debug_assertions, feature = "devtools"))]
      devtools,
      custom_protocols,
      background_color,
      transparent,
      headers,
      autoplay,
      user_agent,
      javascript_disabled,
      ..
    } = attributes;

    let super::PlatformSpecificWebViewAttributes {
      on_webview_created,
      with_asset_loader,
      asset_loader_domain,
      https_scheme,
      android_activity_origin: _,
    } = pl_attrs;

    let http_or_https = if https_scheme { "https" } else { "http" };

    let url = if let Some(mut url) = url {
      if let Some((protocol, _)) = url.split_once("://") {
        if custom_protocols.contains_key(protocol) {
          url = custom_protocol_workaround::apply_uri_work_around(&url, http_or_https, protocol)
        }
      }

      Some(url)
    } else {
      None
    };

    let id = attributes
      .id
      .map(|id| id.to_string())
      .unwrap_or_else(|| COUNTER.next().to_string());

    let initialization_scripts_ = initialization_scripts.clone();
    let request_handler = UnsafeRequestHandler::new(Box::new(
      move |webview_id: &str, mut request, is_document_start_script_enabled| {
        let uri = request.uri().to_string();
        if let Some((custom_protocol, custom_protocol_handler)) =
          custom_protocols.iter().find(|(protocol, _)| {
            custom_protocol_workaround::is_work_around_uri(&uri, http_or_https, protocol)
          })
        {
          let uri_res = custom_protocol_workaround::revert_uri_work_around(
            &uri,
            http_or_https,
            custom_protocol,
          )
          .parse();

          if let Ok(uri) = uri_res {
            *request.uri_mut() = uri;
          }

          let (tx, rx) = channel();
          let initialization_scripts = initialization_scripts_.clone();
          let responder: Box<dyn FnOnce(HttpResponse<Cow<'static, [u8]>>)> = Box::new(
            move |mut response| {
              if !is_document_start_script_enabled {
                #[cfg(feature = "tracing")]
                tracing::info!("`addDocumentStartJavaScript` is not supported; injecting initialization scripts via custom protocol handler");
                response = inject_scripts_into_html(response, &initialization_scripts);
              }
              let _ = tx.send(response);
            },
          );

          (custom_protocol_handler)(webview_id, request, RequestAsyncResponder { responder });
          // The JNI caller releases this callback's serialization guard
          // BEFORE waiting for its asynchronous response.
          return Some(rx);
        }
        None
      },
    ));
    let handler_set = handlers::HandlerSet {
      request: Mutex::new(request_handler),
      ipc: ipc_handler.map(|handler| Mutex::new(UnsafeIpc::new(Box::new(handler)))),
      title: attributes
        .document_title_changed_handler
        .map(|handler| Mutex::new(UnsafeTitleHandler::new(handler))),
      navigation: attributes
        .navigation_handler
        .map(|handler| Mutex::new(UnsafeUrlLoadingOverride::new(handler))),
      load: attributes
        .on_page_load_handler
        .map(|handler| Mutex::new(UnsafeOnPageLoadHandler::new(handler))),
      asset_loader: with_asset_loader,
      asset_domain: asset_loader_domain,
    };
    let registration = handlers::HandlerRegistration::new(origin.clone(), id.clone());

    let attributes = CreateWebViewAttributes {
      activity_origin: origin,
      registration: registration.clone(),
      configuration_recreate: false,
      id: id.clone(),
      url,
      html,
      #[cfg(any(debug_assertions, feature = "devtools"))]
      devtools,
      background_color,
      transparent,
      headers,
      on_webview_created,
      autoplay,
      user_agent,
      initialization_scripts,
      javascript_disabled,
    };

    handlers::publish(attributes.clone(), handler_set)?;
    if let Err(error) = MainPipe::send(activity_id, WebViewMessage::CreateWebView(attributes)) {
      handlers::rollback(&registration);
      return Err(error);
    }

    Ok(Self { id, activity_id })
  }

  pub fn print(&self) -> crate::Result<()> {
    Ok(())
  }

  pub fn id(&self) -> crate::WebViewId<'_> {
    &self.id
  }

  pub fn url(&self) -> crate::Result<String> {
    let (tx, rx) = bounded(1);
    MainPipe::send(self.activity_id, WebViewMessage::GetUrl(tx))?;
    rx.recv_timeout(MAIN_PIPE_TIMEOUT).map_err(Into::into)
  }

  pub fn eval(&self, js: &str, callback: Option<impl Fn(String) + Send + 'static>) -> Result<()> {
    MainPipe::send(
      self.activity_id,
      WebViewMessage::Eval(
        js.into(),
        callback.map(|c| Box::new(c) as Box<dyn Fn(String) + Send + 'static>),
      ),
    )
  }

  #[cfg(any(debug_assertions, feature = "devtools"))]
  pub fn open_devtools(&self) {}

  #[cfg(any(debug_assertions, feature = "devtools"))]
  pub fn close_devtools(&self) {}

  #[cfg(any(debug_assertions, feature = "devtools"))]
  pub fn is_devtools_open(&self) -> bool {
    false
  }

  pub fn zoom(&self, _scale_factor: f64) -> Result<()> {
    Ok(())
  }

  pub fn set_background_color(&self, background_color: RGBA) -> Result<()> {
    MainPipe::send(
      self.activity_id,
      WebViewMessage::SetBackgroundColor(background_color),
    )
  }

  pub fn load_url(&self, url: &str) -> Result<()> {
    MainPipe::send(
      self.activity_id,
      WebViewMessage::LoadUrl(url.to_string(), None),
    )
  }

  pub fn load_url_with_headers(&self, url: &str, headers: http::HeaderMap) -> Result<()> {
    MainPipe::send(
      self.activity_id,
      WebViewMessage::LoadUrl(url.to_string(), Some(headers)),
    )
  }

  pub fn load_html(&self, html: &str) -> Result<()> {
    MainPipe::send(self.activity_id, WebViewMessage::LoadHtml(html.to_string()))
  }

  pub fn reload(&self) -> Result<()> {
    MainPipe::send(self.activity_id, WebViewMessage::Reload)
  }

  pub fn clear_all_browsing_data(&self) -> Result<()> {
    MainPipe::send(self.activity_id, WebViewMessage::ClearAllBrowsingData)
  }

  pub fn cookies_for_url(&self, url: &str) -> Result<Vec<cookie::Cookie<'static>>> {
    let (tx, rx) = bounded(1);
    MainPipe::send(
      self.activity_id,
      WebViewMessage::GetCookies(tx, url.to_string()),
    )?;
    rx.recv_timeout(MAIN_PIPE_TIMEOUT).map_err(Into::into)
  }

  pub fn set_cookie(&self, #[allow(unused)] cookie: &cookie::Cookie<'_>) -> Result<()> {
    // Unsupported
    Ok(())
  }

  pub fn delete_cookie(&self, #[allow(unused)] cookie: &cookie::Cookie<'_>) -> Result<()> {
    // Unsupported
    Ok(())
  }

  pub fn cookies(&self) -> Result<Vec<cookie::Cookie<'static>>> {
    Ok(Vec::new())
  }

  pub fn bounds(&self) -> Result<crate::Rect> {
    Ok(crate::Rect::default())
  }

  pub fn set_bounds(&self, _bounds: crate::Rect) -> Result<()> {
    // Unsupported
    Ok(())
  }

  pub fn set_visible(&self, _visible: bool) -> Result<()> {
    // Unsupported
    Ok(())
  }

  pub fn focus(&self) -> Result<()> {
    // Unsupported
    Ok(())
  }

  pub fn focus_parent(&self) -> Result<()> {
    // Unsupported
    Ok(())
  }
}

#[derive(Clone, Copy)]
pub struct JniHandle {
  pub(crate) activity_id: ActivityId,
}

impl JniHandle {
  /// Execute jni code on the thread of the webview.
  /// Provided function will be provided with the jni evironment, Android activity and WebView
  pub fn exec<F>(&self, func: F)
  where
    F: FnOnce(&mut JNIEnv, &JObject, &JObject) + Send + 'static,
  {
    // The legacy void API cancels by dropping captures on enqueue failure.
    let _ = MainPipe::send(self.activity_id, WebViewMessage::Jni(Box::new(func)));
  }
}

pub fn platform_webview_version() -> Result<String> {
  let (tx, rx) = bounded(1);
  let origin = main_pipe::dispatch_activity().ok_or(Error::ActivityNotFound)?;
  MainPipe::send_to_origin(origin, WebViewMessage::GetWebViewVersion(tx))?;
  rx.recv_timeout(MAIN_PIPE_TIMEOUT)?
}

/// Finds a class in the project scope.
pub fn find_class<'a>(
  env: &mut JNIEnv<'a>,
  activity: &JObject<'_>,
  name: String,
) -> JniResult<JClass<'a>> {
  let class_name = env.new_string(name.replace('/', "."))?;
  let my_class = env
    .call_method(
      activity,
      "getAppClass",
      "(Ljava/lang/String;)Ljava/lang/Class;",
      &[(&class_name).into()],
    )?
    .l()?;
  Ok(my_class.into())
}

/// Dispatch a closure to run on the Android context.
///
/// The closure takes the JNI env, the Android activity instance and the possibly null webview.
pub fn dispatch<F>(func: F)
where
  F: FnOnce(&mut JNIEnv, &JObject, &JObject) + Send + 'static,
{
  if let Some(origin) = main_pipe::dispatch_activity() {
    let _ = MainPipe::send_to_origin(origin, WebViewMessage::Jni(Box::new(func)));
  } else {
    // The process/looper may outlive its last Activity. Complete with absent
    // context on that looper; never panic or acquire a future replacement.
    let _ = MainPipe::send_without_activity(WebViewMessage::Jni(Box::new(func)));
  }
}
