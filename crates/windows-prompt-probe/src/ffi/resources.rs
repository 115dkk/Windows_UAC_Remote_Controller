// SPDX-License-Identifier: GPL-2.0-or-later
//! Private native owners. No broad handle type receives Send/Sync implementations.
use crate::{CleanupFailure, NativeOperation, ProbeError, ProbeFailure};
use std::{
    fmt,
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::StationsAndDesktops::{CloseDesktop, HDESK},
    },
    core::Error as WinError,
};

pub(super) type CleanupLog = Arc<Mutex<Option<CleanupFailure>>>;

pub(super) fn record_cleanup(log: &CleanupLog, operation: NativeOperation, error: WinError) {
    let mut value = log.lock().unwrap_or_else(|poison| poison.into_inner());
    match &mut *value {
        Some(value) => value.failures = value.failures.saturating_add(1),
        None => {
            *value = Some(CleanupFailure {
                failures: 1,
                first_operation: operation,
                first_hresult: error.code().0,
            })
        }
    }
}

pub(super) struct OwnedHandle {
    value: Option<HANDLE>,
    operation: NativeOperation,
    cleanup: CleanupLog,
    _thread: PhantomData<Rc<()>>,
}
impl OwnedHandle {
    pub(super) fn acquired(
        value: HANDLE,
        operation: NativeOperation,
        cleanup: &CleanupLog,
    ) -> Result<Self, ProbeError> {
        if value.is_invalid() {
            return Err(ProbeError::new(ProbeFailure::MalformedNativeData(
                operation,
            )));
        }
        Ok(Self {
            value: Some(value),
            operation,
            cleanup: Arc::clone(cleanup),
            _thread: PhantomData,
        })
    }
    pub(super) fn raw(&self) -> HANDLE {
        self.value.unwrap_or_default()
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            // SAFETY: exclusively acquired real token/process handle, never a
            // pseudo-handle. All synchronous borrows have ended. Taking first
            // prevents a second close; failure is reported through bounded log.
            if let Err(error) = unsafe { CloseHandle(value) } {
                record_cleanup(&self.cleanup, self.operation, error);
            }
        }
    }
}
impl fmt::Debug for OwnedHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedHandle([redacted])")
    }
}

pub(super) struct OwnedDesktop {
    value: Option<HDESK>,
    cleanup: CleanupLog,
    _thread: PhantomData<Rc<()>>,
}
impl OwnedDesktop {
    pub(super) fn acquired(value: HDESK, cleanup: &CleanupLog) -> Result<Self, ProbeError> {
        if value.is_invalid() {
            return Err(ProbeError::new(ProbeFailure::MalformedNativeData(
                NativeOperation::OpenInputDesktop,
            )));
        }
        Ok(Self {
            value: Some(value),
            cleanup: Arc::clone(cleanup),
            _thread: PhantomData,
        })
    }
    pub(super) fn raw(&self) -> HDESK {
        self.value.unwrap_or_default()
    }
}
impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            // SAFETY: only OpenInputDesktop's owned, noninherited handle is
            // closed. The parent retains this owner until scoped worker exit;
            // no worker is still assigned this handle and no borrowed original
            // thread/window-station handle is passed here. No double-close.
            if let Err(error) = unsafe { CloseDesktop(value) } {
                record_cleanup(&self.cleanup, NativeOperation::CloseDesktop, error);
            }
        }
    }
}
impl fmt::Debug for OwnedDesktop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedDesktop([redacted])")
    }
}
