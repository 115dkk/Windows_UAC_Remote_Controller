// SPDX-License-Identifier: GPL-2.0-or-later
//! Read-only SCM/session/protected-path observations; no policy or privilege writes.
use super::super::{
    filesystem::{ValidatedProbeInstallation, validate_probe_installation},
    security::OwnServiceSid,
};
use super::{native, token::CurrentToken};
use crate::{LaunchPrivilege, ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::{ffi::c_void, mem};
use windows::{
    Win32::System::{
        RemoteDesktop::{
            WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOEXW,
            WTSQuerySessionInformationW, WTSSessionInfoEx,
        },
        Services::{
            QueryServiceConfig2W, SC_HANDLE, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            SERVICE_REQUIRED_PRIVILEGES_INFOW,
        },
    },
    core::PWSTR,
};

pub(super) struct Preflight {
    pub pins: ValidatedProbeInstallation,
    pub sid: OwnServiceSid,
    pub sid_bytes: Vec<u8>,
    pub token: CurrentToken,
    pub session: SessionEpoch,
}
impl Preflight {
    pub(super) fn observe() -> Result<Self, Error> {
        let sid = OwnServiceSid::lookup().map_err(|_| Error::NotRunningService)?;
        let sid_bytes = sid.bytes();
        let token = CurrentToken::observe(&sid_bytes)?;
        let pins = validate_probe_installation().map_err(|_| Error::ProtectedHelperUnavailable)?;
        let service = crate::native::running_service_for_probe(pins.service())
            .map_err(|_| Error::NotRunningService)?;
        required_privileges(&service)?;
        let session = SessionEpoch::unique_active()?;
        Ok(Self {
            pins,
            sid,
            sid_bytes,
            token,
            session,
        })
    }
    pub(super) fn recheck(&self) -> Result<(), Error> {
        self.token.recheck(&self.sid_bytes)?;
        let service = crate::native::running_service_for_probe(self.pins.service())
            .map_err(|_| Error::NotRunningService)?;
        required_privileges(&service)?;
        if SessionEpoch::unique_active()? != self.session {
            return Err(Error::SessionChanged);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct SessionEpoch {
    pub id: u32,
    logon: i64,
    connected: i64,
}
impl SessionEpoch {
    pub(super) fn unique_active() -> Result<Self, Error> {
        let mut sessions = std::ptr::null_mut::<WTS_SESSION_INFOW>();
        let mut count = 0;
        // SAFETY: fixed local server/version and initialized exclusive outputs.
        // Successful API memory is adopted immediately and freed exactly once.
        unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut sessions, &mut count) }
            .map_err(|error| native(Stage::SessionQuery, error))?;
        let _allocation = WtsAllocation(sessions.cast());
        if count > 64 || (count != 0 && sessions.is_null()) {
            return Err(Error::SessionObservationUnsupported);
        }
        let id = if count != 0 {
            // SAFETY: successful WTS output consists of count C-layout entries;
            // count bounded before slicing, lifetime pinned by allocation guard.
            let entries = unsafe { std::slice::from_raw_parts(sessions, count as usize) };
            crate::probe_supervisor::unique_session(
                entries
                    .iter()
                    .map(|entry| (entry.SessionId, entry.State == WTSActive)),
            )?
        } else {
            return Err(Error::NoInteractiveSession);
        };
        let mut raw = PWSTR::null();
        let mut bytes = 0;
        // SAFETY: selected local OS session, fixed information class, initialized
        // buffer/length outputs. No usernames, domain text or window text is used.
        unsafe { WTSQuerySessionInformationW(None, id, WTSSessionInfoEx, &mut raw, &mut bytes) }
            .map_err(|error| native(Stage::SessionQuery, error))?;
        let _allocation = WtsAllocation(raw.0.cast());
        if raw.is_null() || bytes as usize != mem::size_of::<WTSINFOEXW>() {
            return Err(Error::SessionObservationUnsupported);
        }
        // SAFETY: complete API-owned structure of exact checked size; copied
        // fields remain private. Only Level1's session/state/times are interpreted.
        let info = unsafe { std::ptr::read_unaligned(raw.0.cast::<WTSINFOEXW>()) };
        if info.Level != 1 {
            return Err(Error::SessionObservationUnsupported);
        }
        // SAFETY: documented discriminant Level==1 selects this initialized arm.
        let level = unsafe { info.Data.WTSInfoExLevel1 };
        if level.SessionId != id || level.SessionState != WTSActive || level.LogonTime <= 0 {
            return Err(Error::SessionChanged);
        }
        Ok(Self {
            id,
            logon: level.LogonTime,
            connected: level.ConnectTime,
        })
    }
}
struct WtsAllocation(*mut c_void);
impl Drop for WtsAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: unique WTS-owned allocation, no references remain.
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

fn required_privileges(service: &windows_service::service::Service) -> Result<(), Error> {
    let mut words = vec![0usize; 8192 / mem::size_of::<usize>()];
    let mut needed = 0;
    // SAFETY: initialized aligned 8192-byte allocation and live QUERY_CONFIG
    // service handle. No configuration change is requested. Returned embedded
    // string pointer is checked against this same allocation before use.
    let buffer = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), 8192) };
    unsafe {
        QueryServiceConfig2W(
            SC_HANDLE(service.raw_handle()),
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            Some(buffer),
            &mut needed,
        )
    }
    .map_err(|error| native(Stage::ServiceConfiguration, error))?;
    // pcbBytesNeeded is specified only for ERROR_INSUFFICIENT_BUFFER, not a
    // successful byte count. The entire8192-byte output is initialized/owned;
    // successful fixed-class output and in-allocation pointers are checked below.
    // SAFETY: fixed complete C-layout prefix was filled successfully.
    let header = unsafe {
        std::ptr::read_unaligned(words.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>())
    };
    if header.pmszRequiredPrivileges.is_null() {
        return Ok(());
    } // no explicit SCM list; actual token still checked
    let offset = (header.pmszRequiredPrivileges.0 as usize)
        .checked_sub(words.as_ptr() as usize)
        .ok_or(Error::ServiceConfiguration)?;
    if offset % 2 != 0 || offset >= 8192 {
        return Err(Error::ServiceConfiguration);
    }
    // SAFETY: immutable initialized view after the native write completed.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), 8192) };
    let units: Vec<u16> = bytes[offset..]
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    let end = units
        .windows(2)
        .position(|pair| pair == [0, 0])
        .ok_or(Error::ServiceConfiguration)?;
    let mut names = Vec::new();
    for name in units[..end].split(|value| *value == 0) {
        if name.is_empty() || name.len() > 128 || names.len() == 128 {
            return Err(Error::ServiceConfiguration);
        }
        names.push(String::from_utf16(name).map_err(|_| Error::ServiceConfiguration)?);
    }
    for (name, kind) in [
        ("SeTcbPrivilege", LaunchPrivilege::Tcb),
        ("SeIncreaseQuotaPrivilege", LaunchPrivilege::IncreaseQuota),
        (
            "SeAssignPrimaryTokenPrivilege",
            LaunchPrivilege::AssignPrimaryToken,
        ),
    ] {
        if !names.iter().any(|value| value.eq_ignore_ascii_case(name)) {
            return Err(Error::RequiredPrivilegeNotEnabled(kind));
        }
    }
    Ok(())
}
