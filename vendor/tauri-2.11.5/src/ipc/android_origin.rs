// SPDX-License-Identifier: GPL-2.0-or-later
//! Opaque native IPC origin, captured by Wry before command dispatch.
use super::{CommandArg, CommandItem, InvokeError};
use crate::Runtime;

/// The original physical Android WebView/Activity generation for this invoke.
/// No Deserialize/Serialize implementation or public constructor exists.
#[derive(Clone, Debug)]
pub struct AndroidInvokeOrigin(pub(crate) tauri_runtime_wry::wry::AndroidWebviewOrigin);

impl AndroidInvokeOrigin {
  pub(crate) fn from_extensions(extensions: &http::Extensions) -> Option<Self> {
    extensions
      .get::<tauri_runtime_wry::wry::AndroidWebviewOrigin>()
      .filter(|origin| origin.is_live())
      .cloned()
      .map(Self)
  }
  pub fn is_live(&self) -> bool {
    self.0.is_live()
  }
}

impl<'de, R: Runtime> CommandArg<'de, R> for AndroidInvokeOrigin {
  fn from_command(command: CommandItem<'de, R>) -> Result<Self, InvokeError> {
    command
      .message
      .android_origin
      .as_ref()
      .filter(|origin| origin.is_live())
      .cloned()
      .ok_or_else(|| InvokeError::from("originating Android view is unavailable"))
  }
}
