// SPDX-License-Identifier: GPL-2.0-or-later
//! Eight fixed metadata-only CREATE_NEW slots under the already pinned private
//! activity directory. No overwrite, truncation, deletion, rename or path input.

use super::{
    OwnedHandle, Wide,
    filesystem::{ActivityDirectory, inspect_open_handle, open_checked},
    security::OwnServiceSid,
};
use crate::{
    MAX_PROBE_DIAGNOSTIC_BYTES, PROBE_DIAGNOSTIC_FILES, ServiceError,
    diagnostic::ProbeDiagnosticRecord,
    policy::{self, ObjectPolicy},
};
use std::{
    fmt,
    mem::{ManuallyDrop, size_of},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
            FlushFileBuffers, WriteFile,
        },
    },
    core::HRESULT,
};

fn unavailable() -> ServiceError {
    ServiceError::ProbeUnavailable
}
fn context() -> Result<(), ServiceError> {
    windows_identity::verify_service_context().map_err(|_| unavailable())
}
fn size_ok(high: u32, low: u32) -> bool {
    high == 0 && low as usize <= MAX_PROBE_DIAGNOSTIC_BYTES
}

impl ActivityDirectory {
    /// Read metadata only. A preexisting incomplete file occupies its slot; it
    /// is never interpreted as success or silently reset. Invalid links/ACLs or
    /// locked entries reject the diagnostic facility, not the ordinary service.
    pub(crate) fn probe_slot_available(&self) -> Result<bool, ServiceError> {
        context()?;
        let sid = OwnServiceSid::lookup().map_err(|_| unavailable())?;
        let mut trusted = policy::trusted_system_sids();
        trusted.push(sid.bytes());
        let mut available = false;
        for name in PROBE_DIAGNOSTIC_FILES {
            let path = self.path().join(name);
            match open_checked(&path, false, ObjectPolicy::PrivateData, &trusted) {
                Ok(file) => {
                    let info = inspect_open_handle(
                        &file,
                        &path,
                        false,
                        ObjectPolicy::PrivateData,
                        &trusted,
                    )
                    .map_err(|_| unavailable())?;
                    if !size_ok(info.nFileSizeHigh, info.nFileSizeLow) {
                        return Err(unavailable());
                    }
                }
                Err(crate::ServiceError::WindowsCall { code, .. })
                    if code == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0).0 as u32 =>
                {
                    available = true
                }
                Err(_) => return Err(unavailable()),
            }
        }
        Ok(available)
    }

    pub(crate) fn reserve_probe_slot(&self) -> Result<ProbeDiagnosticFile<'_>, ServiceError> {
        context()?;
        let sid = OwnServiceSid::lookup().map_err(|_| unavailable())?;
        let mut trusted = policy::trusted_system_sids();
        trusted.push(sid.bytes());
        let descriptor = sid.private_descriptor().map_err(|_| unavailable())?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.ptr().0,
            bInheritHandle: false.into(),
        };
        for (index, name) in PROBE_DIAGNOSTIC_FILES.iter().enumerate() {
            let path = self.path().join(name);
            let wide = Wide::new(&path).map_err(|_| unavailable())?;
            // SAFETY: one constant leaf under retained private no-reparse parent
            // pins. Explicit protected descriptor exists before creation; no
            // inherited handle, sharing, async IO or final-link traversal. A
            // colliding file is never opened for writing or considered ours.
            let created = unsafe {
                CreateFileW(
                    wide.ptr(),
                    (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                    FILE_SHARE_MODE(0),
                    Some(&attributes),
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                    None,
                )
            };
            match created {
                Ok(raw) => {
                    let file = OwnedHandle(raw);
                    let info = inspect_open_handle(
                        &file,
                        &path,
                        false,
                        ObjectPolicy::PrivateData,
                        &trusted,
                    )
                    .map_err(|_| unavailable())?;
                    if info.nFileSizeHigh != 0 || info.nFileSizeLow != 0 {
                        return Err(unavailable());
                    }
                    return Ok(ProbeDiagnosticFile {
                        file: Some(file),
                        directory: self,
                        slot: (index + 1) as u8,
                        trusted,
                    });
                }
                Err(error)
                    if error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0)
                        || error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) =>
                {
                    let file = open_checked(&path, false, ObjectPolicy::PrivateData, &trusted)
                        .map_err(|_| unavailable())?;
                    let info = inspect_open_handle(
                        &file,
                        &path,
                        false,
                        ObjectPolicy::PrivateData,
                        &trusted,
                    )
                    .map_err(|_| unavailable())?;
                    if !size_ok(info.nFileSizeHigh, info.nFileSizeLow) {
                        return Err(unavailable());
                    }
                }
                Err(_) => return Err(unavailable()),
            }
        }
        Err(ServiceError::ProbeSlotsFull)
    }
}

/// Borrows the directory, so ancestor pins outlive the exclusive file handle.
pub(crate) struct ProbeDiagnosticFile<'a> {
    file: Option<OwnedHandle>,
    directory: &'a ActivityDirectory,
    slot: u8,
    trusted: Vec<Vec<u8>>,
}
impl fmt::Debug for ProbeDiagnosticFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeDiagnosticFile(fixed_slot)")
    }
}
impl ProbeDiagnosticFile<'_> {
    pub(crate) fn slot(&self) -> u8 {
        self.slot
    }
    pub(crate) fn write_record(
        mut self,
        record: ProbeDiagnosticRecord,
    ) -> Result<(), ServiceError> {
        context()?;
        // Only the body-free fixed type can reach this private writer.
        let bytes = record.encode()?;
        let file = self.file.as_ref().ok_or_else(unavailable)?;
        let mut offset = 0;
        while offset < bytes.len() {
            let mut written = 0;
            // SAFETY: live exclusive synchronous file, bounded initialized
            // slice and exclusive scalar output; no OVERLAPPED or retained pointer.
            unsafe { WriteFile(file.0, Some(&bytes[offset..]), Some(&mut written), None) }
                .map_err(|_| unavailable())?;
            if written == 0 || written as usize > bytes.len() - offset {
                return Err(unavailable());
            }
            offset += written as usize;
        }
        // SAFETY: this owner's live exclusive file. This is only an OS file
        // flush acknowledgment, not directory/hardware power-loss durability.
        unsafe { FlushFileBuffers(file.0) }.map_err(|_| unavailable())?;
        let path = self
            .directory
            .path()
            .join(PROBE_DIAGNOSTIC_FILES[usize::from(self.slot - 1)]);
        let info =
            inspect_open_handle(file, &path, false, ObjectPolicy::PrivateData, &self.trusted)
                .map_err(|_| unavailable())?;
        if info.nFileSizeHigh != 0 || info.nFileSizeLow as usize != bytes.len() {
            return Err(unavailable());
        }
        context()?;
        let file = ManuallyDrop::new(self.file.take().ok_or_else(unavailable)?);
        // SAFETY: normal-path unique ownership is consumed before CloseHandle;
        // no second destructor closes an uncertain already-consumed handle.
        unsafe { CloseHandle(file.0) }.map_err(|_| unavailable())
    }
}
