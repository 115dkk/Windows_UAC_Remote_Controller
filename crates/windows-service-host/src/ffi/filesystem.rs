// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fmt,
    mem::size_of,
    path::{Path, PathBuf},
    ptr,
};
use windows::{
    Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
            FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
            GETFINALPATHNAMEBYHANDLE_FLAGS, GetDriveTypeW, GetFileInformationByHandle, GetFileType,
            GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
        },
        System::Com::CoTaskMemFree,
        UI::Shell::{
            FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
        },
    },
    core::GUID,
};

use super::{
    OwnedHandle, Wide,
    security::{OwnServiceSid, SecurityDescriptor, inspect_file_security},
    win_error,
};
use crate::{
    INSTALLATION_FOLDER, SERVICE_EXECUTABLE, ServiceError, ServiceOperation,
    policy::{self, ObjectPolicy},
};

/// Keeps every ancestor, directory and binary pinned until mutation completes.
/// Path and handle values intentionally have no Debug representation.
pub(crate) struct ValidatedInstallation {
    executable: PathBuf,
    _pins: Vec<OwnedHandle>,
}

impl fmt::Debug for ValidatedInstallation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedInstallation(protected)")
    }
}

impl ValidatedInstallation {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }
}

/// The Journal's path-based I/O is safe only while these validated parent pins
/// and private ACLs remain in force. Not an authority/key storage abstraction.
pub(crate) struct ActivityDirectory {
    path: PathBuf,
    _pins: Vec<OwnedHandle>,
}

impl fmt::Debug for ActivityDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivityDirectory(private)")
    }
}

impl ActivityDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(super) fn known_folder(id: &GUID) -> Result<PathBuf, ServiceError> {
    // No environment variable, caller path or WOW64 redirection is authority.
    // The supported package is native 64-bit Windows; 32-bit callers fail closed.
    if !cfg!(target_pointer_width = "64") {
        return Err(ServiceError::UnsupportedPlatform);
    }
    // SAFETY: fixed known-folder GUID, no token override, read-only flags. Windows
    // returns one CoTaskMem allocation with a terminated UTF-16 path.
    let raw = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }
        .map_err(|e| win_error(ServiceOperation::KnownFolder, e))?;
    // SAFETY: successful API returned its documented terminated string.
    let decoded = unsafe { raw.to_string() };
    // SAFETY: exactly the allocation returned by SHGetKnownFolderPath, and no
    // subsequent code accesses raw or references into it.
    unsafe { CoTaskMemFree(Some(raw.0.cast())) };
    let path = decoded.map_err(|_| ServiceError::UnsafePath)?;
    policy::checked_dos_path(&path)?;
    Ok(PathBuf::from(path))
}

pub(crate) fn expected_executable() -> Result<PathBuf, ServiceError> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?
        .join(INSTALLATION_FOLDER)
        .join(SERVICE_EXECUTABLE))
}

pub(crate) fn validate_installation(
    require_current_binary: bool,
) -> Result<ValidatedInstallation, ServiceError> {
    let program_files = known_folder(&FOLDERID_ProgramFiles)?;
    let directory = program_files.join(INSTALLATION_FOLDER);
    let executable = directory.join(SERVICE_EXECUTABLE);
    let trusted = policy::trusted_system_sids();
    let mut pins = pin_ancestors(&program_files, &trusted)?;
    pins.push(open_checked(
        &directory,
        true,
        ObjectPolicy::Installation,
        &trusted,
    )?);
    let binary = open_checked(&executable, false, ObjectPolicy::Installation, &trusted)?;
    if require_current_binary {
        let current = std::env::current_exe().map_err(|_| ServiceError::UntrustedInstallation)?;
        // No Workspace/Downloads current executable is allowed to register a
        // different binary. Paths AND volume/file identity must match.
        if !same_path(&current, &executable)? {
            return Err(ServiceError::UntrustedInstallation);
        }
        let current = open_checked(&current, false, ObjectPolicy::Installation, &trusted)?;
        if file_identity(&current)? != file_identity(&binary)? {
            return Err(ServiceError::UntrustedInstallation);
        }
        pins.push(current);
    }
    pins.push(binary);
    Ok(ValidatedInstallation {
        executable,
        _pins: pins,
    })
}

/// Fixed probe leaf plus the already checked running-service installation.
/// No caller path/name and no copying/provisioning occurs in this read-only proof.
#[cfg(target_pointer_width = "64")]
pub(crate) struct ValidatedProbeInstallation {
    installation: ValidatedInstallation,
    probe: PathBuf,
    _probe_pin: OwnedHandle,
}
#[cfg(target_pointer_width = "64")]
impl ValidatedProbeInstallation {
    pub(crate) fn service(&self) -> &Path {
        self.installation.executable()
    }
    pub(crate) fn probe(&self) -> &Path {
        &self.probe
    }
}
#[cfg(target_pointer_width = "64")]
impl fmt::Debug for ValidatedProbeInstallation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedProbeInstallation(protected)")
    }
}
#[cfg(target_pointer_width = "64")]
pub(crate) fn validate_probe_installation() -> Result<ValidatedProbeInstallation, ServiceError> {
    let installation = validate_installation(true)?;
    let probe = installation
        .executable()
        .parent()
        .ok_or(ServiceError::UnsafePath)?
        .join(windows_prompt_probe::supervision::PROBE_EXECUTABLE);
    let pin = open_checked(
        &probe,
        false,
        ObjectPolicy::Installation,
        &policy::trusted_system_sids(),
    )?;
    Ok(ValidatedProbeInstallation {
        installation,
        probe,
        _probe_pin: pin,
    })
}

fn same_path(a: &Path, b: &Path) -> Result<bool, ServiceError> {
    let a = a.to_str().ok_or(ServiceError::UnsafePath)?;
    let b = b.to_str().ok_or(ServiceError::UnsafePath)?;
    policy::checked_dos_path(a)?;
    policy::checked_dos_path(b)?;
    Ok(a.eq_ignore_ascii_case(b))
}

pub(super) fn pin_ancestors(
    target: &Path,
    trusted: &[Vec<u8>],
) -> Result<Vec<OwnedHandle>, ServiceError> {
    let mut paths: Vec<_> = target.ancestors().collect();
    paths.reverse();
    let mut pins = Vec::with_capacity(paths.len());
    for path in paths {
        pins.push(open_checked(path, true, ObjectPolicy::Ancestor, trusted)?);
    }
    Ok(pins)
}

fn pin_open_options(directory: bool) -> (u32, FILE_SHARE_MODE) {
    // Attribute/security-only opens do not establish the read/write/delete
    // sharing contract needed for a pin. Request an actual data-read category:
    // FILE_LIST_DIRECTORY is the directory spelling of the same access bit.
    // No data is read by this validator and no write/delete access is requested.
    let read_access = if directory {
        FILE_LIST_DIRECTORY
    } else {
        FILE_READ_DATA
    };
    let sharing = if directory {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    (
        (READ_CONTROL | FILE_READ_ATTRIBUTES | read_access).0,
        sharing,
    )
}

pub(super) fn open_checked(
    path: &Path,
    directory: bool,
    policy: ObjectPolicy,
    trusted: &[Vec<u8>],
) -> Result<OwnedHandle, ServiceError> {
    let text = path.to_str().ok_or(ServiceError::UnsafePath)?;
    policy::checked_dos_path(text)?;
    let drive = Wide::new(&text[..3])?;
    // SAFETY: bounded validated DOS root with terminating NUL. DRIVE_FIXED (3)
    // is required; UNC/removable/remote paths are not installation authorities.
    if unsafe { GetDriveTypeW(drive.ptr()) } != 3 {
        return Err(ServiceError::UnsafePath);
    }
    let wide = Wide::new(path)?;
    let (access, sharing) = pin_open_options(directory);
    // SAFETY: all buffers live through call; OPEN_EXISTING never creates or
    // follows the final reparse point; share-delete is deliberately omitted.
    // Actual data-read/list access makes sharing restrictions effective; metadata
    // rights alone are insufficient. No backup privilege is enabled here.
    let raw = unsafe {
        CreateFileW(
            wide.ptr(),
            access,
            sharing,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|e| win_error(ServiceOperation::OpenProtectedPath, e))?;
    let handle = OwnedHandle(raw);
    inspect_open_handle(&handle, path, directory, policy, trusted)?;
    Ok(handle)
}

/// Validate the caller's already-owned exact file/directory handle. This does
/// not open a second read-only file pin or alter its sharing/write permissions.
/// The caller retains ownership; no handle/path is exported outside private FFI.
pub(super) fn inspect_open_handle(
    handle: &OwnedHandle,
    path: &Path,
    directory: bool,
    policy: ObjectPolicy,
    trusted: &[Vec<u8>],
) -> Result<BY_HANDLE_FILE_INFORMATION, ServiceError> {
    let text = path.to_str().ok_or(ServiceError::UnsafePath)?;
    policy::checked_dos_path(text)?;
    let drive = Wide::new(&text[..3])?;
    // SAFETY: validated DOS root for this fixed expected path; no caller-derived
    // fallback or drive mutation. The handle's normalized path is checked below.
    if unsafe { GetDriveTypeW(drive.ptr()) } != 3 {
        return Err(ServiceError::UnsafePath);
    }
    let info = file_info(handle)?;
    // SAFETY: a live owned file handle; this call has no pointer outputs.
    if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(ServiceError::UnsafePath);
    }
    let mut normalized = [0u16; 32_768];
    // SAFETY: initialized bounded writable UTF-16 buffer and pinned handle;
    // length is checked before constructing the owned path string.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            handle.0,
            &mut normalized,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
        )
    } as usize;
    if length == 0 || length >= normalized.len() {
        return Err(ServiceError::UnsafePath);
    }
    let normalized =
        String::from_utf16(&normalized[..length]).map_err(|_| ServiceError::UnsafePath)?;
    let normalized = normalized
        .strip_prefix(r"\\?\")
        .ok_or(ServiceError::UnsafePath)?;
    if !same_path(Path::new(normalized), path)? {
        return Err(ServiceError::UnsafePath);
    }
    inspect_file_security(handle, trusted, policy)?;
    Ok(info)
}

fn file_info(handle: &OwnedHandle) -> Result<BY_HANDLE_FILE_INFORMATION, ServiceError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: valid owned handle and initialized correctly aligned output.
    unsafe { GetFileInformationByHandle(handle.0, &mut info) }
        .map_err(|e| win_error(ServiceOperation::InspectProtectedPath, e))?;
    Ok(info)
}

fn file_identity(handle: &OwnedHandle) -> Result<(u32, u32, u32), ServiceError> {
    let info = file_info(handle)?;
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

/// Elevated install-only provisioning. Existing directories are checked rather
/// than taken over. Each new directory receives its private DACL at creation,
/// never after an insecure create. Failure deliberately leaves data untouched.
pub(crate) fn provision_activity_directory() -> Result<(), ServiceError> {
    super::security::require_elevated()?;
    let program_data = known_folder(&FOLDERID_ProgramData)?;
    let sid = OwnServiceSid::lookup()?;
    let mut trusted = policy::trusted_system_sids();
    trusted.push(sid.bytes());
    let descriptor = sid.private_descriptor()?;
    let mut pins = pin_ancestors(&program_data, &trusted)?;
    let product = program_data.join(INSTALLATION_FOLDER);
    create_private_directory(&product, &descriptor)?;
    pins.push(open_checked(
        &product,
        true,
        ObjectPolicy::PrivateData,
        &trusted,
    )?);
    let activity = product.join("activity");
    create_private_directory(&activity, &descriptor)?;
    pins.push(open_checked(
        &activity,
        true,
        ObjectPolicy::PrivateData,
        &trusted,
    )?);
    validate_journal_entries(&activity, &trusted)?;
    Ok(())
}

pub(super) fn create_private_directory(
    path: &Path,
    descriptor: &SecurityDescriptor,
) -> Result<(), ServiceError> {
    let path = Wide::new(path)?;
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    };
    // SAFETY: validated fixed parent was pinned first; path/security descriptor
    // stay live through the call. No recursion, overwrite, ownership repair or
    // permissive default-DACL creation is attempted.
    match unsafe { CreateDirectoryW(path.ptr(), Some(ptr::from_ref(&security))) } {
        Ok(()) => Ok(()),
        Err(error)
            if error.code() == windows::core::HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) =>
        {
            Ok(())
        }
        Err(error) => Err(win_error(ServiceOperation::OpenProtectedPath, error)),
    }
}

pub(crate) fn open_activity_directory() -> Result<ActivityDirectory, ServiceError> {
    let program_data = known_folder(&FOLDERID_ProgramData)?;
    let sid = OwnServiceSid::lookup()?;
    let mut trusted = policy::trusted_system_sids();
    trusted.push(sid.bytes());
    let mut pins = pin_ancestors(&program_data, &trusted)?;
    let product = program_data.join(INSTALLATION_FOLDER);
    pins.push(
        open_checked(&product, true, ObjectPolicy::PrivateData, &trusted)
            .map_err(|_| ServiceError::JournalProvisioningRequired)?,
    );
    let path = product.join("activity");
    pins.push(
        open_checked(&path, true, ObjectPolicy::PrivateData, &trusted)
            .map_err(|_| ServiceError::JournalProvisioningRequired)?,
    );
    validate_journal_entries(&path, &trusted)?;
    Ok(ActivityDirectory { path, _pins: pins })
}

fn validate_journal_entries(directory: &Path, trusted: &[Vec<u8>]) -> Result<(), ServiceError> {
    for name in ["journal.lock", "activity.jsonl", "activity.staging"] {
        // No directory creation here. Pins may close after validation because
        // the private parent ACL admits only trusted writers; Journal must be
        // able to lock and atomically replace its entries subsequently.
        match open_checked(
            &directory.join(name),
            false,
            ObjectPolicy::PrivateData,
            trusted,
        ) {
            Ok(_pin) => (),
            Err(ServiceError::WindowsCall {
                operation: ServiceOperation::OpenProtectedPath,
                code,
            }) if code == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0).0 as u32 => (),
            Err(_) => return Err(ServiceError::JournalProvisioningRequired),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_SHARE_DELETE, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };

    #[test]
    fn pins_request_real_read_access_without_mutation_or_delete_sharing() {
        for directory in [false, true] {
            let (access, sharing) = pin_open_options(directory);
            assert_ne!(access & FILE_READ_DATA.0, 0);
            assert_ne!(access & READ_CONTROL.0, 0);
            assert_ne!(access & FILE_READ_ATTRIBUTES.0, 0);
            assert_eq!(
                access & (DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER).0,
                0
            );
            assert_ne!(sharing.0 & FILE_SHARE_READ.0, 0);
            assert_eq!(sharing.0 & FILE_SHARE_DELETE.0, 0);
            assert_eq!(sharing.0 & FILE_SHARE_WRITE.0 != 0, directory);
        }
    }
}
