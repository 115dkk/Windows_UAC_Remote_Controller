// SPDX-License-Identifier: GPL-2.0-or-later

use std::{mem::size_of, ptr, slice};
use windows::{
    Win32::{
        Foundation::{ERROR_NO_TOKEN, HANDLE},
        Security::{
            ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SE_FILE_OBJECT, SE_OBJECT_TYPE, SE_SERVICE,
            },
            DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation, IsValidAcl,
            IsValidSecurityDescriptor, IsValidSid, LookupAccountNameW, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE, SidTypeWellKnownGroup, TOKEN_ELEVATION,
            TOKEN_QUERY, TokenElevation,
        },
        System::{
            Services::{SC_HANDLE, SetServiceObjectSecurity},
            Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        },
    },
    core::{PCWSTR, PWSTR},
};
use windows_service::service::Service;

use super::{LocalAllocation, OwnedHandle, Wide, win_error};
use crate::{
    ServiceError, ServiceOperation,
    policy::{self, ObjectPolicy},
};

pub(super) struct SecurityDescriptor {
    allocation: LocalAllocation,
}

impl SecurityDescriptor {
    pub(super) fn from_sddl(text: &str) -> Result<Self, ServiceError> {
        let wide = Wide::new(text)?;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: fixed/generated-from-OS-SID NUL-terminated SDDL remains live;
        // successful API returns one owned LocalAlloc descriptor allocation.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.ptr(),
                1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| win_error(ServiceOperation::ReadSecurity, e))?;
        if descriptor.0.is_null() {
            return Err(ServiceError::UnsafePermissions);
        }
        Ok(Self {
            allocation: LocalAllocation(descriptor.0),
        })
    }

    pub(super) fn ptr(&self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR(self.allocation.0)
    }
}

pub(crate) fn require_elevated() -> Result<(), ServiceError> {
    reject_thread_impersonation()?;
    let mut token = HANDLE::default();
    // SAFETY: current-process pseudo-handle is borrowed only for this call;
    // token output is initialized and becomes a single owning handle on success.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| win_error(ServiceOperation::QueryToken, e))?;
    let token = OwnedHandle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: suitably aligned initialized TOKEN_ELEVATION storage and exact
    // size, valid owned query-only token, no token privileges are modified.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(ptr::from_mut(&mut elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .map_err(|e| win_error(ServiceOperation::QueryToken, e))?;
    if returned != size_of::<TOKEN_ELEVATION>() as u32 || elevation.TokenIsElevated == 0 {
        return Err(ServiceError::ElevationRequired);
    }
    reject_thread_impersonation()
}

fn reject_thread_impersonation() -> Result<(), ServiceError> {
    let mut token = HANDLE::default();
    // SAFETY: borrowed current-thread pseudo-handle, initialized aligned output,
    // QUERY only. OpenAsSelf controls access checking, not effective identity.
    // Any actual thread token is rejected; no RevertToSelf or token adjustment.
    match unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) } {
        Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_TOKEN.0) => {
            Ok(())
        }
        Err(error) => Err(win_error(ServiceOperation::QueryToken, error)),
        Ok(()) => {
            let _token = OwnedHandle(token);
            // A process elevation bit alone does not authorize an impersonated
            // call. Keep the existing fixed permission-denied public category.
            Err(ServiceError::ElevationRequired)
        }
    }
}

/// The service object itself is never publicly accessible through a raw handle.
pub(crate) fn harden_service(service: &Service) -> Result<(), ServiceError> {
    // Authenticated Users receive only QUERY_CONFIG | QUERY_STATUS. No start,
    // stop, user-defined control, DACL, owner or delete rights are granted.
    let descriptor =
        SecurityDescriptor::from_sddl("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000005;;;AU)")?;
    // SAFETY: service owns this live SCM handle with WRITE_DAC; the descriptor
    // allocation remains live for the synchronous call; only this object changes.
    unsafe {
        SetServiceObjectSecurity(
            SC_HANDLE(service.raw_handle()),
            DACL_SECURITY_INFORMATION,
            descriptor.ptr(),
        )
    }
    .map_err(|e| win_error(ServiceOperation::HardenService, e))?;
    verify_service_security(service)
}

pub(crate) fn verify_service_security(service: &Service) -> Result<(), ServiceError> {
    inspect_security(
        HANDLE(service.raw_handle()),
        SE_SERVICE,
        &policy::trusted_system_sids(),
        ObjectPolicy::Service,
    )
}

pub(super) fn inspect_file_security(
    handle: &OwnedHandle,
    trusted: &[Vec<u8>],
    policy: ObjectPolicy,
) -> Result<(), ServiceError> {
    inspect_security(handle.0, SE_FILE_OBJECT, trusted, policy)
}

fn inspect_security(
    handle: HANDLE,
    object_type: SE_OBJECT_TYPE,
    trusted: &[Vec<u8>],
    policy: ObjectPolicy,
) -> Result<(), ServiceError> {
    let mut owner = PSID::default();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: handle is owned by the caller for this call. Outputs are borrowed
    // into the one LocalAlloc descriptor; API receives valid writable outputs.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            object_type,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(ServiceError::WindowsCall {
            operation: ServiceOperation::ReadSecurity,
            code: result.0,
        });
    }
    let _allocation = LocalAllocation(descriptor.0);
    if descriptor.0.is_null() || owner.0.is_null() || acl.is_null() {
        return Err(ServiceError::UnsafePermissions);
    }
    // SAFETY: these API-owned pointers are valid through _allocation. Validate
    // structural bounds before reading the ACL header/SID contents ourselves.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool()
        || !unsafe { IsValidSid(owner) }.as_bool()
        || !unsafe { IsValidAcl(acl) }.as_bool()
    {
        return Err(ServiceError::UnsafePermissions);
    }
    // SAFETY: valid SID and ACL API allocation just checked. SID max is 68 bytes;
    // ACL length is its validated u16 length. Both slices remain borrowed here.
    let sid_len = unsafe { GetLengthSid(owner) } as usize;
    let acl_len = unsafe { (*acl).AclSize } as usize;
    if !(8..=68).contains(&sid_len) || acl_len < size_of::<ACL>() {
        return Err(ServiceError::UnsafePermissions);
    }
    // SAFETY: lengths above were validated against the Windows SID/ACL structures;
    // no pointer escapes the live descriptor guard and pure check copies no raw data.
    let owner_bytes = unsafe { slice::from_raw_parts(owner.0.cast::<u8>(), sid_len) };
    // SAFETY: same valid allocated ACL and lifetime invariant as owner_bytes.
    let acl_bytes = unsafe { slice::from_raw_parts(acl.cast::<u8>(), acl_len) };
    policy::check_acl(owner_bytes, acl_bytes, trusted, policy)
}

pub(super) struct OwnServiceSid {
    words: [u32; 17],
    length: usize,
}

impl OwnServiceSid {
    pub(super) fn lookup() -> Result<Self, ServiceError> {
        let name = Wide::new(format!("NT SERVICE\\{}", crate::SERVICE_NAME))?;
        let mut value = Self {
            words: [0; 17],
            length: 0,
        };
        let mut bytes = 68;
        let mut domain = [0u16; 256];
        let mut domain_units = domain.len() as u32;
        let mut use_kind = SID_NAME_USE::default();
        // SAFETY: local-only, constant product service name. Aligned SID and
        // domain arrays are initialized, bounded and remain live for this call.
        let output_sid = PSID(value.words.as_mut_ptr().cast());
        unsafe {
            LookupAccountNameW(
                PCWSTR::null(),
                name.ptr(),
                Some(output_sid),
                &mut bytes,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_units,
                &mut use_kind,
            )
        }
        .map_err(|e| win_error(ServiceOperation::ResolveServiceSid, e))?;
        if bytes != 32 || domain_units > domain.len() as u32 || use_kind != SidTypeWellKnownGroup {
            return Err(ServiceError::UnsafePermissions);
        }
        // SAFETY: successful lookup returned a SID within the aligned 68-byte buffer.
        if !unsafe { IsValidSid(value.ptr()) }.as_bool()
            // SAFETY: IsValidSid succeeded within the owned aligned buffer.
            || unsafe { GetLengthSid(value.ptr()) } != bytes
        {
            return Err(ServiceError::UnsafePermissions);
        }
        value.length = bytes as usize;
        let domain_end = domain
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(ServiceError::UnsafePermissions)?;
        let domain = String::from_utf16(&domain[..domain_end])
            .map_err(|_| ServiceError::UnsafePermissions)?;
        if !policy::service_sid_matches(&value.bytes(), &domain) {
            return Err(ServiceError::UnsafePermissions);
        }
        Ok(value)
    }

    fn ptr(&self) -> PSID {
        PSID(self.words.as_ptr().cast_mut().cast())
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        // SAFETY: lookup checked the valid SID's size within this owned aligned
        // buffer; copy means no pointer or borrow escapes this object.
        unsafe { slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.length) }.to_vec()
    }

    pub(super) fn private_descriptor(&self) -> Result<SecurityDescriptor, ServiceError> {
        let mut text = PWSTR::null();
        // SAFETY: owned aligned validated SID lives through conversion; returned
        // NUL-terminated string is a new LocalAlloc allocation.
        unsafe { ConvertSidToStringSidW(self.ptr(), &mut text) }
            .map_err(|e| win_error(ServiceOperation::ResolveServiceSid, e))?;
        let _allocation = LocalAllocation(text.0.cast());
        // SAFETY: ConvertSidToStringSidW guarantees a terminated allocated SID
        // string on success. It is used only in fixed SDDL, never logged/output.
        let sid = unsafe { text.to_string() }.map_err(|_| ServiceError::UnsafePermissions)?;
        SecurityDescriptor::from_sddl(&format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
        ))
    }

    /// New private supervisor kernel objects only, never a desktop/SCM ACL edit.
    #[cfg(target_pointer_width = "64")]
    pub(super) fn probe_descriptor(&self) -> Result<SecurityDescriptor, ServiceError> {
        let mut text = PWSTR::null();
        // SAFETY: bounded owned SID; returned SID string is LocalAlloc-owned.
        unsafe { ConvertSidToStringSidW(self.ptr(), &mut text) }
            .map_err(|error| win_error(ServiceOperation::ResolveServiceSid, error))?;
        let _allocation = LocalAllocation(text.0.cast());
        // SAFETY: successful converter returns a NUL-terminated SID string,
        // used only in this fixed SYSTEM/service-SID descriptor, never output.
        let sid = unsafe { text.to_string() }.map_err(|_| ServiceError::UnsafePermissions)?;
        SecurityDescriptor::from_sddl(&format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
    }
}
