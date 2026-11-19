// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed public-read / privileged-write diagnostics. Each operation pins the
//! actual NTFS ancestors and directory, rejects reparse/hardlink/unsafe ACLs,
//! and validates the SAME opened file before its first write. No caller paths.
use super::{OwnedHandle, Wide, filesystem, security::SecurityDescriptor, win_error};
use crate::{
    ServiceError, ServiceOperation,
    policy::{self, ObjectPolicy},
};
use std::{
    fs::File,
    mem::{ManuallyDrop, size_of},
    os::windows::io::FromRawHandle,
    path::PathBuf,
};
use windows::{
    Win32::{
        Foundation::ERROR_DIRECTORY,
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, OPEN_ALWAYS,
        },
        System::Com::{
            COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
        },
        UI::{
            Shell::{
                Common::ITEMIDLIST, ILFree, SEE_MASK_FLAG_NO_UI, SEE_MASK_IDLIST, SEE_MASK_NOASYNC,
                SHELLEXECUTEINFOW, SHParseDisplayName, ShellExecuteExW,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    },
    core::w,
};

const DIRECTORY: &str = "UACRemoteController-Logs";
const FILE: &str = "diagnostics.jsonl";
const READABLE_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";

#[derive(Debug)]
pub(crate) struct OpenedFile {
    pub(crate) file: File,
    // File drops before path pins. No unprivileged rename/delete can cross IO.
    _pins: Vec<OwnedHandle>,
}

fn directory(create: bool) -> Result<(PathBuf, Vec<OwnedHandle>), ServiceError> {
    let trusted = policy::trusted_system_sids();
    let (base, mut pins) = filesystem::pin_program_data_root(&trusted)?;
    let path = base.join(DIRECTORY);
    if create {
        super::security::require_elevated()?;
        let descriptor = SecurityDescriptor::from_sddl(READABLE_SDDL)?;
        // Existing helper creates with the supplied explicit descriptor, never
        // repairs or takes ownership of an existing directory.
        filesystem::create_private_directory(&path, &descriptor)?;
    }
    pins.push(filesystem::open_checked(
        &path,
        true,
        ObjectPolicy::PublicDiagnostics,
        &trusted,
    )?);
    Ok((path, pins))
}

pub(crate) fn open_file() -> Result<OpenedFile, ServiceError> {
    super::security::require_elevated()?;
    let (directory, pins) = directory(true)?;
    let path = directory.join(FILE);
    let wide = Wide::new(&path)?;
    let descriptor = SecurityDescriptor::from_sddl(READABLE_SDDL)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    };
    // SAFETY: fixed leaf under retained no-delete/no-reparse parent pins. OPEN_ALWAYS
    // does not truncate. Explicit ACL applies at creation; a collision is checked
    // on this same handle before any write. Read/write sharing enables readers and
    // cross-process nonblocking File::try_lock serialization; delete stays denied.
    let raw = unsafe {
        CreateFileW(
            wide.ptr(),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&attributes),
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| win_error(ServiceOperation::OpenProtectedPath, error))?;
    let handle = OwnedHandle(raw);
    let info = filesystem::inspect_open_handle(
        &handle,
        &path,
        false,
        ObjectPolicy::PublicDiagnostics,
        &policy::trusted_system_sids(),
    )?;
    if ((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow))
        > crate::public_diagnostics::MAX_BYTES
    {
        return Err(ServiceError::OutputUnavailable);
    }
    let handle = ManuallyDrop::new(handle);
    // SAFETY: transfer exactly one checked, owning disk handle into File. The
    // original guard cannot Drop; File owns close and pins outlive all file IO.
    let file = unsafe { File::from_raw_handle(handle.0.0) };
    Ok(OpenedFile { file, _pins: pins })
}

pub(crate) fn open_folder() -> Result<(), ServiceError> {
    // Folder handlers can be user-configured. Never invoke one from an elevated
    // GUI and accidentally elevate an untrusted HKCU shell association.
    super::security::require_unelevated().map_err(|error| folder_failure(1, error))?;
    // Read-only; the UI cannot create a privileged directory or select a target.
    let (path, _pins) = directory(false).map_err(|error| folder_failure(2, error))?;
    let path = Wide::new(path).map_err(|error| folder_failure(3, error))?;
    // SAFETY: initialize this worker thread's COM apartment and balance even an
    // existing compatible apartment's S_FALSE. Never alter an incompatible one.
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }
        .ok()
        .map_err(|error| ServiceError::DiagnosticsFolderFailure {
            stage: 4,
            detail: error.code().0 as u32,
        })?;
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: created only after this thread's successful initialization.
            unsafe { CoUninitialize() };
        }
    }
    let _apartment = Apartment;
    // SAFETY: the already checked absolute directory and its ancestors remain
    // pinned against deletion/replacement throughout parsing and shell dispatch.
    let attributes = unsafe { GetFileAttributesW(path.ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(ServiceError::DiagnosticsFolderFailure {
            stage: 2,
            detail: windows::core::Error::from_thread().code().0 as u32,
        });
    }
    if attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Err(ServiceError::DiagnosticsFolderFailure {
            stage: 2,
            detail: windows::core::HRESULT::from_win32(ERROR_DIRECTORY.0).0 as u32,
        });
    }
    struct ItemIdList(*mut ITEMIDLIST);
    impl Drop for ItemIdList {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: exclusively owned absolute PIDL from SHParseDisplayName;
                // all synchronous shell borrows have ended before release.
                unsafe { ILFree(Some(self.0)) };
            }
        }
    }
    let mut item = ItemIdList(std::ptr::null_mut());
    // SAFETY: fixed absolute path, no caller bind context, initialized owned
    // output. The guard also releases any returned allocation on an error path.
    unsafe { SHParseDisplayName(path.ptr(), None, &mut item.0, 0, None) }.map_err(|error| {
        ServiceError::DiagnosticsFolderFailure {
            stage: 6,
            detail: error.code().0 as u32,
        }
    })?;
    if item.0.is_null() {
        return Err(ServiceError::DiagnosticsFolderFailure {
            stage: 6,
            detail: windows::core::HRESULT::from_win32(ERROR_DIRECTORY.0).0 as u32,
        });
    }
    let mut request = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC | SEE_MASK_IDLIST,
        lpVerb: w!("open"),
        lpIDList: item.0.cast(),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };
    // SAFETY: the validated directory's absolute PIDL and static verb, with no
    // lpFile string for executable-extension probing, arguments or elevation.
    // Pins, PIDL and apartment outlive synchronous shell acceptance. No process
    // handle is requested. Shell errors return to the existing UI error channel.
    unsafe { ShellExecuteExW(&mut request) }.map_err(|error| {
        ServiceError::DiagnosticsFolderFailure {
            stage: 5,
            detail: error.code().0 as u32,
        }
    })
}

fn folder_failure(stage: u8, error: ServiceError) -> ServiceError {
    let detail = match error {
        ServiceError::WindowsCall { code, .. } => code,
        other => other.service_diagnostic_code(),
    };
    ServiceError::DiagnosticsFolderFailure { stage, detail }
}
