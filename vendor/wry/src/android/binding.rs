// Copyright 2020-2023 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use http::{
  header::{HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE},
  Request,
};
use jni::errors::Result as JniResult;
pub use jni::{
  self,
  objects::{GlobalRef, JClass, JMap, JObject, JString},
  sys::{jboolean, jint, jobject, jstring},
  JNIEnv,
};
pub use ndk;
use ndk::looper::{FdEvent, ThreadLooper};
use std::os::fd::{AsFd, AsRawFd};

use super::{
  handlers,
  main_pipe::{MainPipe, MAIN_PIPE},
  EVAL_CALLBACKS,
};

use crate::PageLoadEvent;

#[macro_export]
macro_rules! android_binding {
  ($domain:ident, $package:ident) => {
    ::wry::android_binding!($domain, $package, ::wry)
  };
  // use imported `android_setup` just to force the import path to use `wry::{}`
  // as the macro breaks without braces
  ($domain:ident, $package:ident, $wry:path) => {{
    use $wry::{android_setup as _, prelude::*};

    android_fn!($domain, $package, Rust, wryCreate, []);
    android_fn!(
      $domain,
      $package,
      Rust,
      onWebviewDestroy,
      [JObject, JString]
    );

    android_fn!(
      $domain,
      $package,
      Rust,
      handleRequest,
      [JObject, JString, JObject, jboolean],
      jobject
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      withAssetLoader,
      [JObject, JString],
      jboolean
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      assetLoaderDomain,
      [JObject, JString],
      jstring
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      shouldOverride,
      [JObject, JString, JString],
      jboolean
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      onEval,
      [JObject, JString, jint, JString]
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      onPageLoading,
      [JObject, JString, JString]
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      onPageLoaded,
      [JObject, JString, JString]
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      ipc,
      [JObject, JString, JString, JString]
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      isCurrentWebView,
      [JObject, JString],
      jboolean
    );
    android_fn!(
      $domain,
      $package,
      Rust,
      handleReceivedTitle,
      [JObject, JString, JString],
    );
  }};
}

fn handle_request(
  env: &mut JNIEnv,
  webview: JObject,
  webview_id: JString,
  request: JObject,
  is_document_start_script_enabled: jboolean,
) -> JniResult<jobject> {
  let webview_id = env.get_string(&webview_id)?;
  let webview_id = webview_id.to_str().ok().unwrap_or_default();
  let Ok(origin) = super::origin::capture_webview_origin(env, &webview) else {
    return Ok(*JObject::null());
  };
  if !origin.matches_id(webview_id) {
    return Ok(*JObject::null());
  }

  if let Some(registered) = handlers::lookup(&origin) {
    #[cfg(feature = "tracing")]
    let span =
      tracing::info_span!(parent: None, "wry::custom_protocol::handle", uri = tracing::field::Empty).entered();

    let mut request_builder = Request::builder().extension(origin);

    let uri = env
      .call_method(&request, "getUrl", "()Landroid/net/Uri;", &[])?
      .l()?;
    let url: JString = env
      .call_method(&uri, "toString", "()Ljava/lang/String;", &[])?
      .l()?
      .into();
    let url = env.get_string(&url)?.to_string_lossy().to_string();

    #[cfg(feature = "tracing")]
    span.record("uri", &url);

    request_builder = request_builder.uri(&url);

    let method = env
      .call_method(&request, "getMethod", "()Ljava/lang/String;", &[])?
      .l()
      .map(JString::from)?;
    request_builder = request_builder.method(
      env
        .get_string(&method)?
        .to_string_lossy()
        .to_string()
        .as_str(),
    );

    let request_headers = env
      .call_method(request, "getRequestHeaders", "()Ljava/util/Map;", &[])?
      .l()?;
    let request_headers = JMap::from_env(env, &request_headers)?;
    let mut iter = request_headers.iter(env)?;
    while let Some((header, value)) = iter.next(env)? {
      let header = JString::from(header);
      let value = JString::from(value);
      let header = env.get_string(&header)?;
      let value = env.get_string(&value)?;
      if let (Ok(header), Ok(value)) = (
        HeaderName::from_bytes(header.to_bytes()),
        HeaderValue::from_bytes(value.to_bytes()),
      ) {
        request_builder = request_builder.header(header, value);
      }
    }

    let final_request = match request_builder.body(Vec::new()) {
      Ok(req) => req,
      Err(_e) => {
        #[cfg(feature = "tracing")]
        tracing::warn!("Failed to build response: {_e}");
        return Ok(*JObject::null());
      }
    };

    let response_receiver = {
      #[cfg(feature = "tracing")]
      let _span = tracing::info_span!("wry::custom_protocol::call_handler").entered();
      let handler = registered.handlers.request.lock().unwrap();
      if !handlers::current(&registered.registration) {
        return Ok(*JObject::null());
      }
      (handler.handler)(
        webview_id,
        final_request,
        is_document_start_script_enabled != 0,
      )
    };
    // No ownership-registry or callback-cell lock is held while the response
    // may need Android-main plugin dispatch. Configuration shares the same
    // serialized callback cell, not a concurrent non-Sync Fn clone.
    let response = response_receiver
      .and_then(|receiver| receiver.recv_timeout(super::MAIN_PIPE_TIMEOUT * 3).ok());
    if !handlers::current(&registered.registration) {
      return Ok(*JObject::null());
    }
    if let Some(response) = response {
      let status = response.status();
      let status_code = status.as_u16() as i32;
      let status_err = if status_code < 100 {
        Some("Status code can't be less than 100")
      } else if status_code > 599 {
        Some("statusCode can't be greater than 599.")
      } else if status_code > 299 && status_code < 400 {
        Some("statusCode can't be in the [300, 399] range.")
      } else {
        None
      };
      if let Some(_err) = status_err {
        #[cfg(feature = "tracing")]
        tracing::warn!("{_err}");
        return Ok(*JObject::null());
      }

      let reason_phrase = status.canonical_reason().unwrap_or("OK");
      let (mime_type, encoding) = if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        let content_type = content_type.to_str().unwrap().trim();
        let mut s = content_type.split(';');
        let mime_type = s.next().unwrap().trim();
        let mut encoding = None;
        for token in s {
          let token = token.trim();
          if token.starts_with("charset=") {
            encoding.replace(token.split('=').nth(1).unwrap());
            break;
          }
        }
        (
          env.new_string(mime_type)?,
          if let Some(encoding) = encoding {
            env.new_string(encoding)?
          } else {
            JString::default()
          },
        )
      } else {
        (JString::default(), JString::default())
      };

      let headers = response.headers();
      let obj = env.new_object("java/util/HashMap", "()V", &[])?;
      let response_headers = {
        let headers_map = JMap::from_env(env, &obj)?;
        for (name, value) in headers.iter() {
          // WebResourceResponse will automatically generate Content-Type and
          // Content-Length headers so we should skip them to avoid duplication.
          if name == CONTENT_TYPE || name == CONTENT_LENGTH {
            continue;
          }
          let key = env.new_string(name)?;
          let value = env.new_string(value.to_str().unwrap_or_default())?;
          headers_map.put(env, &key, &value)?;
        }
        headers_map
      };

      let bytes = response.body();

      let byte_array_input_stream = env.find_class("java/io/ByteArrayInputStream")?;
      let byte_array = env.byte_array_from_slice(bytes)?;
      let stream = env.new_object(byte_array_input_stream, "([B)V", &[(&byte_array).into()])?;

      let reason_phrase = env.new_string(reason_phrase)?;

      let web_resource_response_class = env.find_class("android/webkit/WebResourceResponse")?;
      let web_resource_response = env.new_object(
        web_resource_response_class,
        "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/util/Map;Ljava/io/InputStream;)V",
        &[(&mime_type).into(), (&encoding).into(), status_code.into(), (&reason_phrase).into(), (&response_headers).into(), (&stream).into()],
      )?;

      return Ok(*web_resource_response);
    }
  }

  Ok(*JObject::null())
}

#[allow(non_snake_case)]
pub unsafe fn wryCreate(env: JNIEnv, _: JClass) {
  if !super::main_pipe::initialize_main_thread() {
    return;
  }
  let mut main_pipe = MainPipe { env };

  let looper = ThreadLooper::for_thread().unwrap();

  looper
    .add_fd_with_callback(MAIN_PIPE[0].as_fd(), FdEvent::INPUT, move |fd, _event| {
      let mut wakes = [0u8; 8];
      let count = libc::read(fd.as_raw_fd(), wakes.as_mut_ptr().cast(), wakes.len());
      if count > 0 {
        // Bound each looper callback. JNI failure cancels that message, but
        // cannot unregister the consumer and strand all later pending calls.
        for _ in 0..8 {
          if main_pipe.recv().is_err() {
            let _ = main_pipe.env.exception_clear();
          }
        }
        true
      } else if count < 0
        && matches!(
          std::io::Error::last_os_error().kind(),
          std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        )
      {
        true
      } else {
        MainPipe::close_queue();
        false
      }
    })
    .unwrap();
}

#[allow(non_snake_case)]
pub unsafe fn onWebviewDestroy(
  mut env: JNIEnv,
  _: JClass,
  activity: JObject,
  _webview_id: JString,
) {
  let is_changing_configurations = env
    .call_method(&activity, "isChangingConfigurations", "()Z", &[])
    .unwrap()
    .z()
    .unwrap();

  let Some(origin) = super::main_pipe::retire_activity(&env, &activity) else {
    return;
  };
  super::cancel_evals_for_activity(&origin);
  // The actual callback owns retirement. It needs neither queue capacity nor
  // a callback-cell lock, and an old same-label owner cannot erase a new one.
  handlers::retire_activity(&origin, is_changing_configurations);
  super::main_pipe::remove_activity_proxy(&origin);
}

#[allow(non_snake_case)]
pub unsafe fn handleRequest(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  request: JObject,
  is_document_start_script_enabled: jboolean,
) -> jobject {
  match handle_request(
    &mut env,
    webview,
    webview_id,
    request,
    is_document_start_script_enabled,
  ) {
    Ok(response) => response,
    Err(_e) => {
      #[cfg(feature = "tracing")]
      tracing::warn!("Failed to handle request: {_e}");
      JObject::null().as_raw()
    }
  }
}

#[allow(non_snake_case)]
pub unsafe fn shouldOverride(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  url: JString,
) -> jboolean {
  let Some(registered) = registered_for_view(&mut env, &webview, &webview_id) else {
    return true.into();
  };
  let Ok(url) = env.get_string(&url) else {
    return true.into();
  };
  if let Some(handler) = &registered.handlers.navigation {
    let handler = handler.lock().unwrap();
    if !handlers::current(&registered.registration) {
      return true.into();
    }
    // Android's true means block; Wry's true means permit navigation.
    (!(handler.handler)(url.to_string_lossy().to_string())).into()
  } else {
    (!handlers::current(&registered.registration)).into()
  }
}

#[allow(non_snake_case)]
pub unsafe fn onEval(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  id: jint,
  result: JString,
) {
  let Ok(origin) = super::origin::capture_webview_origin(&mut env, &webview) else {
    return;
  };
  let Ok(logical_id) = env.get_string(&webview_id) else {
    return;
  };
  if !origin.matches_id(logical_id.to_str().ok().unwrap_or_default()) {
    return;
  }
  let pending = {
    let mut callbacks = EVAL_CALLBACKS.get_or_init(Default::default).lock().unwrap();
    if !callbacks
      .get(&id)
      .is_some_and(|entry| entry.origin.same(&origin))
    {
      return;
    }
    callbacks.remove(&id)
  };
  if let Some(pending) = pending {
    if pending.origin.is_live() {
      if let Ok(result) = env.get_string(&result) {
        (pending.callback)(result.into());
      }
    }
  }
}

pub unsafe fn ipc(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  url: JString,
  body: JString,
) {
  let Ok(origin) = super::origin::capture_webview_origin(&mut env, &webview) else {
    return;
  };
  match (
    env.get_string(&url),
    env.get_string(&body),
    env.get_string(&webview_id),
  ) {
    (Ok(url), Ok(body), Ok(webview_id)) => {
      #[cfg(feature = "tracing")]
      let _span = tracing::info_span!(parent: None, "wry::ipc::handle").entered();

      let url = url.to_string_lossy().to_string();
      let body = body.to_string_lossy().to_string();
      let webview_id = webview_id.to_string_lossy().to_string();
      if !origin.matches_id(&webview_id) {
        return;
      }
      if let Some(registered) = handlers::lookup(&origin) {
        if let Some(ipc) = &registered.handlers.ipc {
          let ipc = ipc.lock().unwrap();
          if !handlers::current(&registered.registration) {
            return;
          }
          if let Ok(request) = Request::builder().uri(url).extension(origin).body(body) {
            (ipc.handler)(request);
          }
        }
      }
    }
    (Err(_e), _, _) | (_, Err(_e), _) | (_, _, Err(_e)) => {
      #[cfg(feature = "tracing")]
      tracing::warn!("Failed to parse JString: {_e}")
    }
  }
}

#[allow(non_snake_case)]
pub unsafe fn handleReceivedTitle(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  title: JString,
) {
  let Some(registered) = registered_for_view(&mut env, &webview, &webview_id) else {
    return;
  };
  let Ok(title) = env.get_string(&title) else {
    return;
  };
  if let Some(handler) = &registered.handlers.title {
    let handler = handler.lock().unwrap();
    if handlers::current(&registered.registration) {
      (handler.handler)(title.to_string_lossy().to_string());
    }
  }
}

#[allow(non_snake_case)]
pub unsafe fn isCurrentWebView(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
) -> jboolean {
  registered_for_view(&mut env, &webview, &webview_id)
    .is_some_and(|registered| handlers::current(&registered.registration))
    .into()
}

#[allow(non_snake_case)]
pub unsafe fn withAssetLoader(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
) -> jboolean {
  registered_for_view(&mut env, &webview, &webview_id)
    .is_some_and(|registered| {
      handlers::current(&registered.registration) && registered.handlers.asset_loader
    })
    .into()
}

#[allow(non_snake_case)]
pub unsafe fn assetLoaderDomain(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
) -> jstring {
  let registered = registered_for_view(&mut env, &webview, &webview_id);
  let domain = registered
    .as_ref()
    .filter(|entry| handlers::current(&entry.registration))
    .and_then(|entry| entry.handlers.asset_domain.as_deref())
    .unwrap_or("wry.assets");
  env
    .new_string(domain)
    .map(|value| value.as_raw())
    .unwrap_or(std::ptr::null_mut())
}

#[allow(non_snake_case)]
pub unsafe fn onPageLoading(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  url: JString,
) {
  on_page_load(
    &mut env,
    &webview,
    &webview_id,
    &url,
    PageLoadEvent::Started,
  );
}

#[allow(non_snake_case)]
pub unsafe fn onPageLoaded(
  mut env: JNIEnv,
  _: JClass,
  webview: JObject,
  webview_id: JString,
  url: JString,
) {
  on_page_load(
    &mut env,
    &webview,
    &webview_id,
    &url,
    PageLoadEvent::Finished,
  );
}

fn registered_for_view(
  env: &mut JNIEnv<'_>,
  webview: &JObject<'_>,
  webview_id: &JString<'_>,
) -> Option<handlers::RegisteredHandlers> {
  let origin = super::origin::capture_webview_origin(env, webview).ok()?;
  let logical_id = env.get_string(webview_id).ok()?;
  if !origin.matches_id(logical_id.to_str().ok()?) {
    return None;
  }
  handlers::lookup(&origin)
}

fn on_page_load(
  env: &mut JNIEnv<'_>,
  webview: &JObject<'_>,
  webview_id: &JString<'_>,
  url: &JString<'_>,
  event: PageLoadEvent,
) {
  let Some(registered) = registered_for_view(env, webview, webview_id) else {
    return;
  };
  let Ok(url) = env.get_string(url) else {
    return;
  };
  if let Some(handler) = &registered.handlers.load {
    let handler = handler.lock().unwrap();
    if handlers::current(&registered.registration) {
      (handler.handler)(event, url.to_string_lossy().to_string());
    }
  }
}
