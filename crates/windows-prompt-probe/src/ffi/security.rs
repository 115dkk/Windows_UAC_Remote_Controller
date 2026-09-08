// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed native token queries. No adjustment, duplication or impersonation API.
use super::{
    malformed, native_error,
    resources::{CleanupLog, OwnedHandle},
};
use crate::{NativeOperation, ProbeError, ProbeFailure, policy};
use std::{ffi::c_void, mem};
use windows::{
    Win32::{
        Foundation::{ERROR_NO_TOKEN, HANDLE},
        Security::{
            GetTokenInformation, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
            TOKEN_USER, TokenIntegrityLevel, TokenSessionId, TokenUser,
        },
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            SystemInformation::{
                IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
                IMAGE_FILE_MACHINE_UNKNOWN,
            },
            Threading::{GetCurrentThread, IsWow64Process2, OpenProcessToken, OpenThreadToken},
        },
    },
    core::HRESULT,
};

const MAX_TOKEN_BYTES: usize = 4096;
const SYSTEM_USER: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const SYSTEM_INTEGRITY: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 16, 0, 64, 0, 0];

pub(super) fn reject_impersonation(cleanup: &CleanupLog) -> Result<(), ProbeError> {
    let mut token = HANDLE::default();
    // SAFETY: borrowed current-thread pseudo-handle is never closed. QUERY only,
    // initialized exclusive HANDLE output; open-as-self only controls the query's
    // access check and does not remove an impersonation token.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    match result {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0) => Ok(()),
        Err(error) => Err(native_error(NativeOperation::OpenThreadToken, error)),
        Ok(()) => {
            let _token = OwnedHandle::acquired(token, NativeOperation::CloseToken, cleanup)?;
            Err(ProbeError::new(ProbeFailure::ThreadImpersonationPresent))
        }
    }
}

pub(super) fn native64(process: HANDLE) -> Result<(), ProbeError> {
    let mut process_machine = IMAGE_FILE_MACHINE::default();
    let mut native_machine = IMAGE_FILE_MACHINE::default();
    // SAFETY: process is a borrowed live current/QUERY_LIMITED process handle;
    // the two exclusive initialized scalar outputs are valid for this call.
    unsafe { IsWow64Process2(process, &mut process_machine, Some(&mut native_machine)) }
        .map_err(|error| native_error(NativeOperation::NativeArchitecture, error))?;
    if process_machine != IMAGE_FILE_MACHINE_UNKNOWN
        || !matches!(
            native_machine,
            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64
        )
    {
        return Err(ProbeError::new(ProbeFailure::Native64Unsupported));
    }
    Ok(())
}

pub(super) fn process_identity(
    process: HANDLE,
    pid: u32,
    expected_session: Option<u32>,
    cleanup: &CleanupLog,
) -> Result<u32, ProbeError> {
    let mut raw_token = HANDLE::default();
    // SAFETY: borrowed live process handle, fixed QUERY access, initialized
    // exclusive token output. The acquired real token is uniquely adopted.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) }
        .map_err(|error| native_error(NativeOperation::OpenProcessToken, error))?;
    let token = OwnedHandle::acquired(raw_token, NativeOperation::CloseToken, cleanup)?;
    let user = TokenBuffer::read(token.raw(), TokenUser, NativeOperation::TokenUser)?;
    if user.bytes().len() < mem::size_of::<TOKEN_USER>() {
        return Err(malformed(NativeOperation::TokenUser));
    }
    // SAFETY: the successful fixed TokenUser query filled TOKEN_USER. Copy its
    // C-layout pointer/scalar fields without dereferencing the SID; sid() checks
    // the pointed range against this same still-owned stable allocation.
    let user_info = unsafe { std::ptr::read_unaligned(user.bytes().as_ptr().cast::<TOKEN_USER>()) };
    if user.sid(user_info.User.Sid.0)? != SYSTEM_USER {
        return Err(ProbeError::new(ProbeFailure::SystemUserRequired));
    }
    let integrity = TokenBuffer::read(
        token.raw(),
        TokenIntegrityLevel,
        NativeOperation::TokenIntegrity,
    )?;
    if integrity.bytes().len() < mem::size_of::<TOKEN_MANDATORY_LABEL>() {
        return Err(malformed(NativeOperation::TokenIntegrity));
    }
    // SAFETY: same bounded C-layout copy rule for the fixed integrity query;
    // only sid() subsequently reads the validated in-buffer SID prefix.
    let label = unsafe {
        std::ptr::read_unaligned(integrity.bytes().as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
    };
    if integrity.sid(label.Label.Sid.0)? != SYSTEM_INTEGRITY {
        return Err(ProbeError::new(ProbeFailure::SystemIntegrityRequired));
    }
    let session = TokenBuffer::read(token.raw(), TokenSessionId, NativeOperation::TokenSession)?;
    let token_session = u32::from_ne_bytes(
        session
            .bytes()
            .try_into()
            .map_err(|_| malformed(NativeOperation::TokenSession))?,
    );
    let mut process_session = 0;
    // SAFETY: pid was the current process or captured HWND owner associated with
    // the retained process handle; exclusive initialized scalar output. A later
    // HWND/process recheck remains necessary; this query is not atomic identity.
    unsafe { ProcessIdToSessionId(pid, &mut process_session) }
        .map_err(|error| native_error(NativeOperation::ProcessSession, error))?;
    if token_session == 0
        || token_session != process_session
        || expected_session.is_some_and(|expected| expected != token_session)
    {
        return Err(ProbeError::new(ProbeFailure::InteractiveSessionRequired));
    }
    Ok(token_session)
}

struct TokenBuffer {
    words: Vec<usize>,
    length: usize,
    operation: NativeOperation,
}
impl TokenBuffer {
    fn read(
        token: HANDLE,
        class: TOKEN_INFORMATION_CLASS,
        operation: NativeOperation,
    ) -> Result<Self, ProbeError> {
        let mut value = Self {
            words: vec![0; MAX_TOKEN_BYTES / mem::size_of::<usize>()],
            length: MAX_TOKEN_BYTES,
            operation,
        };
        let mut returned = 0;
        // SAFETY: fixed QUERY token/information class, aligned initialized heap
        // storage of exactly 4096 bytes, and initialized exclusive length output.
        // Allocation never moves or reallocates while contained native SID
        // pointers are interpreted. Oversize/racing output fails without retry.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(value.words.as_mut_ptr().cast()),
                MAX_TOKEN_BYTES as u32,
                &mut returned,
            )
        }
        .map_err(|error| native_error(operation, error))?;
        if returned == 0 || returned as usize > MAX_TOKEN_BYTES {
            return Err(malformed(operation));
        }
        value.length = returned as usize;
        Ok(value)
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: the initialized usize allocation contains at least length
        // bytes; this immutable byte view ends before any mutation or drop.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn sid(&self, pointer: *mut c_void) -> Result<&[u8], ProbeError> {
        let offset = (pointer as usize)
            .checked_sub(self.words.as_ptr() as usize)
            .ok_or_else(|| malformed(self.operation))?;
        self.bytes()
            .get(offset..)
            .and_then(policy::sid_prefix)
            .ok_or_else(|| malformed(self.operation))
    }
}
