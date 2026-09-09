// SPDX-License-Identifier: GPL-2.0-or-later
//! Current-service token only. No activation, impersonation or foreign-token duplication.
use super::{Handle, native};
use crate::{LaunchPrivilege, ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::mem;
use windows::{
    Win32::{
        Foundation::{ERROR_NO_TOKEN, HANDLE, LUID},
        Security::{
            DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueW,
            SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME, SID_AND_ATTRIBUTES,
            SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_SESSIONID,
            TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
            TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenGroups,
            TokenHasRestrictions, TokenIntegrityLevel, TokenPrimary, TokenPrivileges,
            TokenRestrictedSids, TokenSessionId, TokenType, TokenUser,
        },
        System::{
            SystemInformation::{
                IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
                IMAGE_FILE_MACHINE_UNKNOWN,
            },
            Threading::{
                GetCurrentProcess, GetCurrentThread, IsWow64Process2, OpenProcessToken,
                OpenThreadToken,
            },
        },
    },
    core::{HRESULT, PCWSTR},
};

const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const SYSTEM_IL: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 16, 0, 64, 0, 0];
const MAX_TOKEN: usize = 65536;
const MAX_GROUPS: usize = 128;
const GROUP_ENABLED: u32 = 4;
const GROUP_DENY_ONLY: u32 = 16;

#[derive(Eq, PartialEq)]
struct Facts {
    groups: Vec<(Vec<u8>, u32)>,
    restricted: Vec<(Vec<u8>, u32)>,
    privileges: Vec<(u64, u32)>,
    has_restrictions: u32,
}

pub(super) struct CurrentToken {
    handle: Handle,
    facts: Facts,
}
impl CurrentToken {
    pub(super) fn observe(service_sid: &[u8]) -> Result<Self, Error> {
        reject_impersonation()?;
        // SAFETY: borrowed live current-process pseudo-handle, never closed.
        let process = unsafe { GetCurrentProcess() };
        native64(process)?;
        let mut token = HANDLE::default();
        // SAFETY: own process only, QUERY/DUPLICATE only, initialized token out.
        unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) }
            .map_err(|error| native(Stage::TokenQuery, error))?;
        let handle = Handle::new(token, Stage::TokenQuery)?;
        let facts = facts(handle.raw(), 0, service_sid)?;
        require_privileges(&facts)?;
        reject_impersonation()?;
        Ok(Self { handle, facts })
    }

    pub(super) fn for_session(&self, session: u32, service_sid: &[u8]) -> Result<Handle, Error> {
        if session == 0 {
            return Err(Error::NoInteractiveSession);
        }
        reject_impersonation()?;
        let mut duplicate = HANDLE::default();
        // SAFETY: duplicate ONLY our retained own primary SYSTEM token. The
        // kernel retains restrictions; no group/privilege/DACL adjustment or
        // foreign token occurs. New token is primary/noninherited, fixed rights.
        unsafe {
            DuplicateTokenEx(
                self.handle.raw(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut duplicate,
            )
        }
        .map_err(|error| native(Stage::DuplicateOwnToken, error))?;
        let duplicate = Handle::new(duplicate, Stage::DuplicateOwnToken)?;
        if facts(duplicate.raw(), 0, service_sid)? != self.facts {
            return Err(Error::RestrictedTokenMismatch);
        }
        // SAFETY: only the new owned token's session scalar is changed. Caller
        // SeTcb was observed ALREADY enabled; no privilege activation is used.
        unsafe {
            SetTokenInformation(
                duplicate.raw(),
                TokenSessionId,
                (&session as *const u32).cast(),
                4,
            )
        }
        .map_err(|error| native(Stage::SetSession, error))?;
        if facts(duplicate.raw(), session, service_sid)? != self.facts {
            return Err(Error::RestrictedTokenMismatch);
        }
        self.recheck(service_sid)?;
        Ok(duplicate)
    }
    pub(super) fn recheck(&self, service_sid: &[u8]) -> Result<(), Error> {
        let current = Self::observe(service_sid)?;
        if current.facts != self.facts {
            return Err(Error::RestrictedTokenMismatch);
        }
        Ok(())
    }
    pub(super) fn verify_child(
        &self,
        process: HANDLE,
        session: u32,
        service_sid: &[u8],
    ) -> Result<(), Error> {
        let mut token = HANDLE::default();
        // SAFETY: retained CREATED child process only; query token without copying it.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|error| native(Stage::AuthenticatePeer, error))?;
        let token = Handle::new(token, Stage::AuthenticatePeer)?;
        native64(process)?;
        if facts(token.raw(), session, service_sid)? != self.facts {
            return Err(Error::RestrictedTokenMismatch);
        }
        Ok(())
    }
}

fn reject_impersonation() -> Result<(), Error> {
    let mut token = HANDLE::default();
    // SAFETY: borrowed current-thread pseudo-handle; QUERY only. Open-as-self
    // does not bypass the presence check. Only actual ERROR_NO_TOKEN is absence.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0) => Ok(()),
        Err(error) => Err(native(Stage::TokenQuery, error)),
        Ok(()) => {
            let _token = Handle::new(token, Stage::TokenQuery)?;
            Err(Error::ImpersonationPresent)
        }
    }
}
fn native64(process: HANDLE) -> Result<(), Error> {
    let mut process_machine = IMAGE_FILE_MACHINE::default();
    let mut native_machine = IMAGE_FILE_MACHINE::default();
    // SAFETY: live borrowed process and exclusive initialized machine outputs.
    unsafe { IsWow64Process2(process, &mut process_machine, Some(&mut native_machine)) }
        .map_err(|error| native(Stage::TokenQuery, error))?;
    if process_machine != IMAGE_FILE_MACHINE_UNKNOWN
        || !matches!(
            native_machine,
            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64
        )
    {
        return Err(Error::UnsupportedToken);
    }
    Ok(())
}

struct TokenBuffer {
    words: Vec<usize>,
    length: usize,
}
impl TokenBuffer {
    fn read(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Self, Error> {
        let mut value = Self {
            words: vec![0; MAX_TOKEN / mem::size_of::<usize>()],
            length: MAX_TOKEN,
        };
        let mut length = 0;
        // SAFETY: QUERY token, fixed classes only, stable aligned initialized
        // 64KiB allocation. Output pointers stay inside this live heap allocation.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(value.words.as_mut_ptr().cast()),
                MAX_TOKEN as u32,
                &mut length,
            )
        }
        .map_err(|error| native(Stage::TokenQuery, error))?;
        if length == 0 || length as usize > MAX_TOKEN {
            return Err(Error::UnsupportedToken);
        }
        value.length = length as usize;
        Ok(value)
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: initialized allocation at least length bytes; immutable borrow
        // ends before drop and no native operation retains this buffer.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn sid(&self, pointer: *mut std::ffi::c_void) -> Result<Vec<u8>, Error> {
        let offset = (pointer as usize)
            .checked_sub(self.words.as_ptr() as usize)
            .ok_or(Error::UnsupportedToken)?;
        let bytes = self.bytes().get(offset..).ok_or(Error::UnsupportedToken)?;
        if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
            return Err(Error::UnsupportedToken);
        }
        Ok(bytes
            .get(..8 + usize::from(bytes[1]) * 4)
            .ok_or(Error::UnsupportedToken)?
            .to_vec())
    }
    fn scalar(&self) -> Result<u32, Error> {
        Ok(u32::from_ne_bytes(
            self.bytes()
                .try_into()
                .map_err(|_| Error::UnsupportedToken)?,
        ))
    }
}

fn groups(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<(Vec<u8>, u32)>, Error> {
    let buffer = TokenBuffer::read(token, class)?;
    let bytes = buffer.bytes();
    let count = u32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or(Error::UnsupportedToken)?
            .try_into()
            .map_err(|_| Error::UnsupportedToken)?,
    ) as usize;
    if count > MAX_GROUPS {
        return Err(Error::UnsupportedToken);
    }
    let start = mem::offset_of!(TOKEN_GROUPS, Groups);
    let size = mem::size_of::<SID_AND_ATTRIBUTES>();
    let rows = bytes
        .get(start..start + count * size)
        .ok_or(Error::UnsupportedToken)?;
    let mut output = Vec::with_capacity(count);
    for row in rows.chunks_exact(size) {
        // SAFETY: exact C-layout row inside initialized bounded buffer; contained
        // SID pointer is range-checked against that same allocation before reading.
        let entry = unsafe { std::ptr::read_unaligned(row.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
        output.push((buffer.sid(entry.Sid.0)?, entry.Attributes));
    }
    output.sort();
    Ok(output)
}

fn facts(token: HANDLE, session: u32, service_sid: &[u8]) -> Result<Facts, Error> {
    if TokenBuffer::read(token, TokenType)?.scalar()? != TokenPrimary.0 as u32 {
        return Err(Error::UnsupportedToken);
    }
    let user = TokenBuffer::read(token, TokenUser)?;
    if user.length < mem::size_of::<TOKEN_USER>() {
        return Err(Error::UnsupportedToken);
    }
    // SAFETY: fixed TokenUser C-layout output; SID reads are independently bounded.
    let user_value =
        unsafe { std::ptr::read_unaligned(user.bytes().as_ptr().cast::<TOKEN_USER>()) };
    if user.sid(user_value.User.Sid.0)? != SYSTEM {
        return Err(Error::NotRunningService);
    }
    let integrity = TokenBuffer::read(token, TokenIntegrityLevel)?;
    if integrity.length < mem::size_of::<TOKEN_MANDATORY_LABEL>() {
        return Err(Error::UnsupportedToken);
    }
    // SAFETY: fixed integrity-label C-layout output with checked contained SID.
    let label = unsafe {
        std::ptr::read_unaligned(integrity.bytes().as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
    };
    if integrity.sid(label.Label.Sid.0)? != SYSTEM_IL
        || TokenBuffer::read(token, TokenSessionId)?.scalar()? != session
    {
        return Err(Error::UnsupportedToken);
    }
    let regular = groups(token, TokenGroups)?;
    let restricted = groups(token, TokenRestrictedSids)?;
    if !regular.iter().any(|(sid, flags)| {
        sid == service_sid && flags & GROUP_ENABLED != 0 && flags & GROUP_DENY_ONLY == 0
    }) || !restricted.iter().any(|(sid, _)| sid == service_sid)
    {
        return Err(Error::RestrictedTokenMismatch);
    }
    let privileges = TokenBuffer::read(token, TokenPrivileges)?;
    let count = u32::from_ne_bytes(
        privileges
            .bytes()
            .get(..4)
            .ok_or(Error::UnsupportedToken)?
            .try_into()
            .map_err(|_| Error::UnsupportedToken)?,
    ) as usize;
    if count > 128 {
        return Err(Error::UnsupportedToken);
    }
    let size = mem::size_of::<windows::Win32::Security::LUID_AND_ATTRIBUTES>();
    let start = mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    let mut values = Vec::with_capacity(count);
    for row in privileges
        .bytes()
        .get(start..start + count * size)
        .ok_or(Error::UnsupportedToken)?
        .chunks_exact(size)
    {
        // SAFETY: exact initialized LUID_AND_ATTRIBUTES row; scalar fields only.
        let value = unsafe {
            std::ptr::read_unaligned(
                row.as_ptr()
                    .cast::<windows::Win32::Security::LUID_AND_ATTRIBUTES>(),
            )
        };
        values.push((luid(value.Luid), value.Attributes.0));
    }
    values.sort();
    Ok(Facts {
        groups: regular,
        restricted,
        privileges: values,
        has_restrictions: TokenBuffer::read(token, TokenHasRestrictions)?.scalar()?,
    })
}
fn luid(value: LUID) -> u64 {
    (u64::from(value.HighPart as u32) << 32) | u64::from(value.LowPart)
}
fn require_privileges(facts: &Facts) -> Result<(), Error> {
    for (name, kind) in [
        (SE_TCB_NAME, LaunchPrivilege::Tcb),
        (SE_INCREASE_QUOTA_NAME, LaunchPrivilege::IncreaseQuota),
        (
            SE_ASSIGNPRIMARYTOKEN_NAME,
            LaunchPrivilege::AssignPrimaryToken,
        ),
    ] {
        let mut id = LUID::default();
        // SAFETY: fixed local privilege name, no remote computer or user input;
        // initialized scalar out. Lookup does not enable or add a privilege.
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), name, &mut id) }
            .map_err(|error| native(Stage::TokenQuery, error))?;
        let attributes = facts
            .privileges
            .iter()
            .find(|(value, _)| *value == luid(id))
            .map(|(_, flags)| *flags);
        if !kind.accepts_attributes(attributes) {
            return Err(Error::RequiredPrivilegeNotEnabled(kind));
        }
    }
    Ok(())
}
