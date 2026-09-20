// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use super::{PluginApi, PluginHandle};

use crate::{ipc::Channel, AppHandle, Runtime};
#[cfg(target_os = "android")]
use crate::{
  runtime::RuntimeHandle,
  sealed::{ManagerBase, RuntimeOrDispatch},
};

#[cfg(mobile)]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(mobile)]
use tokio::sync::oneshot;

use serde::{de::DeserializeOwned, Serialize};

use std::{
  collections::HashMap,
  fmt,
  sync::{mpsc::channel, Mutex, OnceLock},
};

type PluginResponse = Result<serde_json::Value, serde_json::Value>;

type PendingPluginCallHandler = Box<dyn FnOnce(PluginResponse) + Send + 'static>;

#[cfg(mobile)]
static PENDING_PLUGIN_CALLS_ID: AtomicI32 = AtomicI32::new(0);
static PENDING_PLUGIN_CALLS: OnceLock<Mutex<HashMap<i32, PendingPluginCallHandler>>> =
  OnceLock::new();
static CHANNELS: OnceLock<Mutex<HashMap<u32, Channel<serde_json::Value>>>> = OnceLock::new();

/// Own the pending callback until a native command is actually dispatched.
/// Rejected/dropped JNI jobs cancel the waiter without a fabricated response.
#[cfg(target_os = "android")]
struct PendingCommandDispatch {
  id: i32,
  armed: bool,
}

#[cfg(target_os = "android")]
impl PendingCommandDispatch {
  fn new(id: i32) -> Self {
    Self { id, armed: true }
  }
  fn dispatched(&mut self) {
    self.armed = false;
  }
}

#[cfg(target_os = "android")]
impl Drop for PendingCommandDispatch {
  fn drop(&mut self) {
    if self.armed {
      let callback = PENDING_PLUGIN_CALLS.get().and_then(|pending| {
        pending
          .lock()
          .ok()
          .and_then(|mut pending| pending.remove(&self.id))
      });
      // Captured values may have destructors: never run them under the map lock.
      drop(callback);
    }
  }
}

/// Possible errors when invoking a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginInvokeError {
  /// Failed to reach platform webview handle.
  #[error("the webview is unreachable")]
  UnreachableWebview,
  /// JNI error.
  #[cfg(target_os = "android")]
  #[error("jni error: {0}")]
  Jni(#[from] jni::errors::Error),
  /// Error returned from direct mobile plugin invoke.
  #[error(transparent)]
  InvokeRejected(#[from] ErrorResponse),
  /// Failed to deserialize response.
  #[error("failed to deserialize response: {0}")]
  CannotDeserializeResponse(serde_json::Error),
  /// Failed to serialize request payload.
  #[error("failed to serialize payload: {0}")]
  CannotSerializePayload(serde_json::Error),
}

pub(crate) fn register_channel(channel: Channel<serde_json::Value>) {
  CHANNELS
    .get_or_init(Default::default)
    .lock()
    .unwrap()
    .insert(channel.id(), channel);
}

/// Glue between Rust and the Kotlin code that sends the plugin response back.
#[cfg(target_os = "android")]
pub fn handle_android_plugin_response(
  env: &mut jni::JNIEnv<'_>,
  id: i32,
  success: jni::objects::JString<'_>,
  error: jni::objects::JString<'_>,
) {
  let (payload, is_ok): (serde_json::Value, bool) = match (
    env
      .is_same_object(&success, jni::objects::JObject::default())
      .unwrap_or_default(),
    env
      .is_same_object(&error, jni::objects::JObject::default())
      .unwrap_or_default(),
  ) {
    // both null
    (true, true) => (serde_json::Value::Null, true),
    // error null
    (false, true) => (
      serde_json::from_str(env.get_string(&success).unwrap().to_str().unwrap()).unwrap(),
      true,
    ),
    // success null
    (true, false) => (
      serde_json::from_str(env.get_string(&error).unwrap().to_str().unwrap()).unwrap(),
      false,
    ),
    // both are set - impossible in the Kotlin code
    (false, false) => unreachable!(),
  };

  // Drop the lock before invoking the handler: it delivers the command response
  // to the webview (which can block on the UI thread), and holding
  // PENDING_PLUGIN_CALLS across that call deadlocks a concurrent `run_command`.
  let handler = PENDING_PLUGIN_CALLS
    .get_or_init(Default::default)
    .lock()
    .unwrap()
    .remove(&id);
  if let Some(handler) = handler {
    handler(if is_ok { Ok(payload) } else { Err(payload) });
  }
}

/// Glue between Rust and the Kotlin code that sends the channel data.
#[cfg(target_os = "android")]
pub fn send_channel_data(
  env: &mut jni::JNIEnv<'_>,
  channel_id: i64,
  data_str: jni::objects::JString<'_>,
) {
  let data: serde_json::Value =
    serde_json::from_str(env.get_string(&data_str).unwrap().to_str().unwrap()).unwrap();

  // Clone the channel out and drop the lock before send(): send() can block
  // delivering to the webview, and holding CHANNELS across it deadlocks a
  // concurrent channel registration/send.
  let channel = CHANNELS
    .get_or_init(Default::default)
    .lock()
    .unwrap()
    .get(&(channel_id as u32))
    .cloned();
  if let Some(channel) = channel {
    let _ = channel.send(data);
  }
}

/// Error response from the Kotlin and Swift backends.
#[derive(Debug, thiserror::Error, Clone, serde::Deserialize)]
pub struct ErrorResponse<T = ()> {
  /// Error code.
  pub code: Option<String>,
  /// Error message.
  pub message: Option<String>,
  /// Optional error data.
  #[serde(flatten)]
  pub data: T,
}

impl<T> fmt::Display for ErrorResponse<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if let Some(code) = &self.code {
      write!(f, "[{code}]")?;
      if self.message.is_some() {
        write!(f, " - ")?;
      }
    }
    if let Some(message) = &self.message {
      write!(f, "{message}")?;
    }
    Ok(())
  }
}

impl<R: Runtime, C: DeserializeOwned> PluginApi<R, C> {
  /// Registers an iOS plugin.
  #[cfg(all(target_os = "ios", feature = "wry"))]
  pub fn register_ios_plugin(
    &self,
    init_fn: unsafe fn() -> *const std::ffi::c_void,
  ) -> Result<PluginHandle<R>, PluginInvokeError> {
    if let Some(webview) = self.handle.manager.webviews().values().next() {
      let (tx, rx) = channel();
      let name = self.name;
      let config = self.raw_config.clone();
      webview
        .with_webview(move |w| {
          unsafe {
            crate::ios::register_plugin(
              &name.into(),
              init_fn(),
              &serde_json::to_string(&config).unwrap().as_str().into(),
              w.inner() as _,
            )
          };
          tx.send(()).unwrap();
        })
        .map_err(|_| PluginInvokeError::UnreachableWebview)?;
      rx.recv().unwrap();
    } else {
      unsafe {
        crate::ios::register_plugin(
          &self.name.into(),
          init_fn(),
          &serde_json::to_string(&self.raw_config)
            .unwrap()
            .as_str()
            .into(),
          std::ptr::null(),
        )
      };
    }
    Ok(PluginHandle {
      name: self.name,
      handle: self.handle.clone(),
    })
  }

  /// Registers an Android plugin.
  #[cfg(target_os = "android")]
  pub fn register_android_plugin(
    &self,
    plugin_identifier: &str,
    class_name: &str,
  ) -> Result<PluginHandle<R>, PluginInvokeError> {
    use jni::{errors::Error as JniError, objects::JObject, JNIEnv};

    fn initialize_plugin<R: Runtime>(
      env: &mut JNIEnv<'_>,
      activity: &JObject<'_>,
      webview: &JObject<'_>,
      runtime_handle: &R::Handle,
      plugin_name: &'static str,
      plugin_class: String,
      plugin_config: &serde_json::Value,
    ) -> Result<(), JniError> {
      // instantiate plugin
      let plugin_class = runtime_handle.find_class(env, activity, plugin_class)?;
      let plugin = env.new_object(
        plugin_class,
        "(Landroid/app/Activity;)V",
        &[activity.into()],
      )?;

      // load plugin

      let plugin_manager = env
        .call_method(
          activity,
          "getPluginManager",
          "()Lapp/tauri/plugin/PluginManager;",
          &[],
        )?
        .l()?;

      let plugin_name = env.new_string(plugin_name)?;
      let config = env.new_string(&serde_json::to_string(plugin_config).unwrap())?;
      env.call_method(
        plugin_manager,
        "load",
        "(Landroid/webkit/WebView;Ljava/lang/String;Lapp/tauri/plugin/Plugin;Ljava/lang/String;)V",
        &[
          webview.into(),
          (&plugin_name).into(),
          (&plugin).into(),
          (&config).into(),
        ],
      )?;

      Ok(())
    }

    let plugin_class = format!("{}/{}", plugin_identifier.replace('.', "/"), class_name);
    let plugin_name = self.name;
    let plugin_config = self.raw_config.clone();
    let runtime_handle = self.handle.runtime_handle.clone();
    let (tx, rx) = channel();
    self
      .handle
      .runtime_handle
      .run_on_android_context(move |env, activity, webview| {
        let result = initialize_plugin::<R>(
          env,
          activity,
          webview,
          &runtime_handle,
          plugin_name,
          plugin_class,
          &plugin_config,
        );
        let _ = tx.send(result);
      });

    rx.recv()
      .map_err(|_| PluginInvokeError::UnreachableWebview)??;

    Ok(PluginHandle {
      name: self.name,
      handle: self.handle.clone(),
    })
  }
}

impl<R: Runtime> PluginHandle<R> {
  /// Invoke using the physical Android IPC origin captured before application
  /// worker queues. No current-Activity or label lookup is performed here.
  #[cfg(all(target_os = "android", feature = "wry"))]
  pub fn run_mobile_plugin_from_origin<T: DeserializeOwned>(
    &self,
    origin: &crate::ipc::AndroidInvokeOrigin,
    command: impl AsRef<str>,
    payload: impl Serialize,
  ) -> Result<T, PluginInvokeError> {
    let (tx, rx) = channel();
    run_command_from_origin(
      self.name,
      origin,
      command.as_ref(),
      serde_json::to_value(payload).map_err(PluginInvokeError::CannotSerializePayload)?,
      move |response| {
        let _ = tx.send(response);
      },
    )?;
    match rx
      .recv()
      .map_err(|_| PluginInvokeError::UnreachableWebview)?
    {
      Ok(value) => {
        serde_json::from_value(value).map_err(PluginInvokeError::CannotDeserializeResponse)
      }
      Err(value) => Err(
        serde_json::from_value::<ErrorResponse>(value)
          .map(Into::into)
          .map_err(PluginInvokeError::CannotDeserializeResponse)?,
      ),
    }
  }

  /// Executes the given mobile command.
  /// This is an async optimized variant of run_mobile_plugin
  pub async fn run_mobile_plugin_async<T: DeserializeOwned>(
    &self,
    command: impl AsRef<str>,
    payload: impl Serialize,
  ) -> Result<T, PluginInvokeError> {
    let (tx, rx) = oneshot::channel();
    // the closure is an FnOnce but on Android we need to clone it (error handling)
    let tx = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));
    run_command(
      self.name,
      &self.handle,
      command,
      serde_json::to_value(payload).map_err(PluginInvokeError::CannotSerializePayload)?,
      move |response| {
        if let Ok(mut pending) = tx.lock() {
          if let Some(sender) = pending.take() {
            let _ = sender.send(response);
          }
        }
      },
    )?;

    let response = rx
      .await
      .map_err(|_| PluginInvokeError::UnreachableWebview)?;

    match response {
      Ok(r) => serde_json::from_value(r).map_err(PluginInvokeError::CannotDeserializeResponse),
      Err(r) => Err(
        serde_json::from_value::<ErrorResponse>(r)
          .map(Into::into)
          .map_err(PluginInvokeError::CannotDeserializeResponse)?,
      ),
    }
  }

  /// Executes the given mobile command.
  pub fn run_mobile_plugin<T: DeserializeOwned>(
    &self,
    command: impl AsRef<str>,
    payload: impl Serialize,
  ) -> Result<T, PluginInvokeError> {
    let (tx, rx) = channel();
    run_command(
      self.name,
      &self.handle,
      command,
      serde_json::to_value(payload).map_err(PluginInvokeError::CannotSerializePayload)?,
      move |response| {
        let _ = tx.send(response);
      },
    )?;

    let response = rx
      .recv()
      .map_err(|_| PluginInvokeError::UnreachableWebview)?;
    match response {
      Ok(r) => serde_json::from_value(r).map_err(PluginInvokeError::CannotDeserializeResponse),
      Err(r) => Err(
        serde_json::from_value::<ErrorResponse>(r)
          .map(Into::into)
          .map_err(PluginInvokeError::CannotDeserializeResponse)?,
      ),
    }
  }
}

#[cfg(all(target_os = "android", feature = "wry"))]
pub(crate) fn run_command_from_origin(
  name: &str,
  origin: &crate::ipc::AndroidInvokeOrigin,
  command: &str,
  payload: serde_json::Value,
  handler: impl FnOnce(PluginResponse) + Send + 'static,
) -> Result<(), PluginInvokeError> {
  if !origin.is_live() {
    return Err(PluginInvokeError::UnreachableWebview);
  }
  let id = PENDING_PLUGIN_CALLS_ID
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
    .map_err(|_| PluginInvokeError::UnreachableWebview)?;
  {
    let mut pending = PENDING_PLUGIN_CALLS
      .get_or_init(Default::default)
      .lock()
      .unwrap();
    if pending.len() >= 64 || pending.contains_key(&id) {
      return Err(PluginInvokeError::UnreachableWebview);
    }
    pending.insert(id, Box::new(handler));
  }
  let name = name.to_owned();
  let command = command.to_owned();
  let dispatch = PendingCommandDispatch::new(id);
  let result = origin.0.exec(move |env, activity, webview| {
    let mut dispatch = dispatch;
    let invoke = || -> Result<(), jni::errors::Error> {
      if activity.is_null() || webview.is_null() {
        return Err(jni::errors::Error::NullPtr("retired Android origin"));
      }
      let name = env.new_string(name)?;
      let command = env.new_string(command)?;
      let data = env.new_string(serde_json::to_string(&payload).unwrap())?;
      let manager = env
        .call_method(
          activity,
          "getPluginManager",
          "()Lapp/tauri/plugin/PluginManager;",
          &[],
        )?
        .l()?;
      env.call_method(
        manager,
        "runCommandForOrigin",
        "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/webkit/WebView;)V",
        &[
          id.into(),
          (&name).into(),
          (&command).into(),
          (&data).into(),
          webview.into(),
        ],
      )?;
      Ok(())
    };
    if invoke().is_err() {
      let _ = env.exception_clear();
      let handler = PENDING_PLUGIN_CALLS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .remove(&id);
      if let Some(handler) = handler {
        handler(Err(
          serde_json::json!({"message":"originating Android view is unavailable"}),
        ));
      }
    } else {
      dispatch.dispatched();
    }
  });
  if result.is_err() {
    // Rejected exec owns and drops the closure, whose dispatch guard cancels it.
    return Err(PluginInvokeError::UnreachableWebview);
  }
  Ok(())
}

#[cfg(target_os = "ios")]
pub(crate) fn run_command<R: Runtime, C: AsRef<str>, F: FnOnce(PluginResponse) + Send + 'static>(
  name: &str,
  _handle: &AppHandle<R>,
  command: C,
  payload: serde_json::Value,
  handler: F,
) -> Result<(), PluginInvokeError> {
  use std::{
    ffi::CStr,
    os::raw::{c_char, c_int, c_ulonglong},
  };

  let id: i32 = PENDING_PLUGIN_CALLS_ID.fetch_add(1, Ordering::Relaxed);
  PENDING_PLUGIN_CALLS
    .get_or_init(Default::default)
    .lock()
    .unwrap()
    .insert(id, Box::new(handler));

  unsafe {
    extern "C" fn plugin_command_response_handler(
      id: c_int,
      success: c_int,
      payload: *const c_char,
    ) {
      let payload = unsafe {
        assert!(!payload.is_null());
        CStr::from_ptr(payload)
      };

      let handler = PENDING_PLUGIN_CALLS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .remove(&id);
      if let Some(handler) = handler {
        let json = payload.to_str().unwrap();
        match serde_json::from_str(json) {
          Ok(payload) => {
            handler(if success == 1 {
              Ok(payload)
            } else {
              Err(payload)
            });
          }
          Err(err) => {
            handler(Err(format!("{err}, data: {}", json).into()));
          }
        }
      }
    }

    extern "C" fn send_channel_data_handler(id: c_ulonglong, payload: *const c_char) {
      let payload = unsafe {
        assert!(!payload.is_null());
        CStr::from_ptr(payload)
      };

      // Clone the channel out and drop the lock before send(): send() can block
      // delivering to the webview, and holding CHANNELS across it deadlocks a
      // concurrent channel registration/send.
      let channel = CHANNELS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .get(&(id as u32))
        .cloned();
      if let Some(channel) = channel {
        let payload: serde_json::Value = serde_json::from_str(payload.to_str().unwrap()).unwrap();
        let _ = channel.send(payload);
      }
    }

    crate::ios::run_plugin_command(
      id,
      &name.into(),
      &command.as_ref().into(),
      &serde_json::to_string(&payload).unwrap().as_str().into(),
      crate::ios::PluginMessageCallback(plugin_command_response_handler),
      crate::ios::ChannelSendDataCallback(send_channel_data_handler),
    );
  }

  Ok(())
}

#[cfg(target_os = "android")]
pub(crate) fn run_command<
  R: Runtime,
  C: AsRef<str>,
  F: FnOnce(PluginResponse) + Send + Clone + 'static,
>(
  name: &str,
  handle: &AppHandle<R>,
  command: C,
  payload: serde_json::Value,
  handler: F,
) -> Result<(), PluginInvokeError> {
  use jni::{errors::Error as JniError, objects::JObject, JNIEnv};

  fn run<R: Runtime>(
    id: i32,
    plugin: &str,
    command: String,
    payload: &serde_json::Value,
    env: &mut JNIEnv<'_>,
    activity: &JObject<'_>,
  ) -> Result<(), JniError> {
    let plugin = env.new_string(plugin)?;
    let command = env.new_string(&command)?;
    let data = env.new_string(&serde_json::to_string(payload).unwrap())?;
    let plugin_manager = env
      .call_method(
        activity,
        "getPluginManager",
        "()Lapp/tauri/plugin/PluginManager;",
        &[],
      )?
      .l()?;

    env.call_method(
      plugin_manager,
      "runCommand",
      "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
      &[
        id.into(),
        (&plugin).into(),
        (&command).into(),
        (&data).into(),
      ],
    )?;

    Ok(())
  }

  let handle = match handle.runtime() {
    RuntimeOrDispatch::Runtime(r) => r.handle(),
    RuntimeOrDispatch::RuntimeHandle(h) => h,
    _ => unreachable!(),
  };

  let id = PENDING_PLUGIN_CALLS_ID
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
    .map_err(|_| PluginInvokeError::UnreachableWebview)?;
  let plugin_name = name.to_string();
  let command = command.as_ref().to_string();

  {
    let mut pending = PENDING_PLUGIN_CALLS
      .get_or_init(Default::default)
      .lock()
      .unwrap();
    if pending.len() >= 64 || pending.contains_key(&id) {
      return Err(PluginInvokeError::UnreachableWebview);
    }
    pending.insert(id, Box::new(handler));
  }

  let dispatch = PendingCommandDispatch::new(id);
  handle.run_on_android_context(move |env, activity, _webview| {
    let mut dispatch = dispatch;
    if run::<R>(id, &plugin_name, command, &payload, env, activity).is_err() {
      let _ = env.exception_clear();
      let handler = PENDING_PLUGIN_CALLS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .remove(&id);
      if let Some(handler) = handler {
        handler(Err(
          serde_json::json!({"message":"Android plugin context is unavailable"}),
        ));
      }
    } else {
      dispatch.dispatched();
    }
  });

  Ok(())
}
