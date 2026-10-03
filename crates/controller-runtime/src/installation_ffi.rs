// SPDX-License-Identifier: GPL-2.0-or-later
//! Windows-only read-only integrity / fixed repair elevation boundary.
//!
//! All paths descend from FOLDERID_ProgramFiles; no renderer argument, environment
//! variable or current executable contributes to a path. Ancestors are opened
//! no-follow and held without delete sharing. Files are opened no-follow without
//! write/delete sharing and inspected through those handles. This observation is
//! not authorization: the elevated repair owner checks ACLs, identity and hashes.
//! Before elevation this boundary also rejects untrusted owners/ACLs and hard
//! links, so an unelevated writer cannot substitute the manifest and launch image.
//! FFI ownership is confined to known-folder/security allocations, borrowed file
//! handles and one owned process handle. No privilege or token is changed here.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_CANCELLED, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            ACL,
            Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, GetLengthSid, IsValidAcl, IsValidSecurityDescriptor,
            IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        },
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        System::{
            Com::CoTaskMemFree,
            Threading::{GetExitCodeProcess, WaitForSingleObject},
        },
        UI::Shell::{
            FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC,
            SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHGetKnownFolderPath, ShellExecuteExW,
        },
    },
    core::{HRESULT, PCWSTR, w},
};

use crate::integrity::{
    self, FILE_NAMES, FileMatch, MAX_IMAGE_BYTES, MAX_MANIFEST_BYTES, Manifest, ManifestState,
};
use crate::{InstallationIntegrityView, IntegrityStateView, RepairOutcome};

use windows_service_host::{REPAIR_FOLDER, REPAIR_MANIFEST};
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;

fn refused() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

fn installation_path() -> io::Result<PathBuf> {
    if !cfg!(target_pointer_width = "64") {
        return Err(refused());
    }
    // SAFETY: fixed GUID, read-only flags, no impersonation token. On success
    // Windows returns one terminated CoTaskMem allocation owned by this call.
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
        .map_err(|_| refused())?;
    // SAFETY: the successful API returns a terminated UTF-16 string.
    let decoded = unsafe { raw.to_string() };
    // SAFETY: exactly the allocation above, released once, never used again.
    unsafe { CoTaskMemFree(Some(raw.0.cast())) };
    let decoded = decoded.map_err(|_| refused())?;
    if decoded.chars().any(|character| {
        character.is_control() || ['/', '"', '<', '>', '|', '?', '*'].contains(&character)
    }) || decoded.get(3..).is_none_or(|rest| {
        rest.split('\\').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || part.contains(':')
        })
    }) {
        return Err(refused());
    }
    let path = PathBuf::from(decoded);
    let text = path.as_os_str().encode_wide().collect::<Vec<_>>();
    // Native local DOS path only, matching the service's known-folder policy.
    if text.len() < 3
        || text[1] != u16::from(b':')
        || text[2] != u16::from(b'\\')
        || !matches!(text[0], 65..=90 | 97..=122)
        || !path.is_absolute()
    {
        return Err(refused());
    }
    Ok(path.join(windows_service_host::INSTALLATION_FOLDER))
}

struct LocalDescriptor(PSECURITY_DESCRIPTOR);
impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: the successful GetSecurityInfo call transferred this allocation.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn inspect_security(file: &File, ancestor: bool) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut acl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: borrowed live file handle, initialized outputs. Owner and ACL
    // borrow the one LocalAlloc descriptor, released after pure inspection.
    let result = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(refused());
    }
    let _allocation = LocalDescriptor(descriptor);
    if descriptor.0.is_null() || owner.0.is_null() || acl.is_null() {
        return Err(refused());
    }
    // SAFETY: all pointers belong to the live OS descriptor allocation.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool()
        || !unsafe { IsValidSid(owner) }.as_bool()
        || !unsafe { IsValidAcl(acl) }.as_bool()
    {
        return Err(refused());
    }
    // SAFETY: OS-validated SID and ACL headers; lengths bounded before slicing.
    let sid_length = unsafe { GetLengthSid(owner) } as usize;
    // SAFETY: ACL was validated above and the allocation is still owned.
    let acl_length = unsafe { (*acl).AclSize } as usize;
    if !(8..=68).contains(&sid_length) || acl_length < size_of::<ACL>() {
        return Err(refused());
    }
    // SAFETY: slices use the validated lengths and cannot escape the allocation.
    let owner = unsafe { std::slice::from_raw_parts(owner.0.cast::<u8>(), sid_length) };
    // SAFETY: same ownership and validated length invariant as the owner slice.
    let acl = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), acl_length) };
    if integrity::protected_acl(owner, acl, ancestor) {
        Ok(())
    } else {
        Err(refused())
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | 0x0002_0000) // READ_CONTROL for ACL inspection
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused());
    }
    Ok(file)
}

fn pin_ancestors(path: &Path) -> io::Result<Vec<File>> {
    let mut pins = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let file = open_directory(ancestor)?;
        let installation_component = ancestor.file_name().is_some_and(|name| {
            name == windows_service_host::INSTALLATION_FOLDER || name == REPAIR_FOLDER
        });
        inspect_security(&file, !installation_component)?;
        pins.push(file);
    }
    Ok(pins)
}

fn open_image(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: borrowed live file handle and initialized exact-size output.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut information) }
        .map_err(|_| refused())?;
    if information.nNumberOfLinks != 1 {
        return Err(refused());
    }
    Ok(file)
}

fn load_manifest(directory: &Path) -> Result<Manifest, ManifestState> {
    let file = open_image(&directory.join(REPAIR_MANIFEST)).map_err(manifest_error)?;
    inspect_security(&file, false).map_err(|_| ManifestState::Unavailable)?;
    if file
        .metadata()
        .map_err(|_| ManifestState::Unavailable)?
        .len()
        > MAX_MANIFEST_BYTES as u64
    {
        return Err(ManifestState::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ManifestState::Unavailable)?;
    integrity::parse_manifest(&bytes, env!("CARGO_PKG_VERSION")).ok_or(ManifestState::Invalid)
}

fn manifest_error(error: io::Error) -> ManifestState {
    if error.kind() == io::ErrorKind::NotFound {
        ManifestState::Missing
    } else {
        ManifestState::Unavailable
    }
}

fn file_error(error: io::Error) -> FileMatch {
    if error.kind() == io::ErrorKind::NotFound {
        FileMatch::Damaged
    } else {
        FileMatch::Unavailable
    }
}

fn image_matches(file: &mut File, expected: &integrity::ManifestFile) -> io::Result<bool> {
    let length = file.metadata()?.len();
    if length != expected.bytes || length > MAX_IMAGE_BYTES {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_IMAGE_BYTES || total > expected.bytes {
            return Ok(false);
        }
        hash.update(&buffer[..count]);
    }
    let digest = hash.finalize();
    let expected_bytes: Vec<_> = expected
        .sha256
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte.to_ascii_lowercase() - b'a' + 10
                }
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect();
    Ok(total == expected.bytes && digest[..] == expected_bytes[..])
}

fn observe_image(path: &Path, expected: Option<&integrity::ManifestFile>) -> FileMatch {
    let mut file = match open_image(path) {
        Ok(file) => file,
        Err(error) => return file_error(error),
    };
    if inspect_security(&file, false).is_err() {
        return FileMatch::Unavailable;
    }
    let checked = if let Some(expected) = expected {
        image_matches(&mut file, expected)
    } else {
        (|| {
            let length = file.metadata()?.len();
            let mut header = [0_u8; 4096];
            let count = usize::try_from(length.min(header.len() as u64)).map_err(|_| refused())?;
            file.read_exact(&mut header[..count])?;
            Ok(integrity::plausible_pe(&header[..count], length))
        })()
    };
    match checked {
        Ok(true) => FileMatch::Match,
        Ok(false) => FileMatch::Damaged,
        Err(_) => FileMatch::Unavailable,
    }
}

pub(crate) fn check() -> InstallationIntegrityView {
    check_inner().unwrap_or_else(|_| {
        integrity::classify(
            ManifestState::Unavailable,
            [FileMatch::Unavailable; 2],
            [FileMatch::Unavailable; 2],
        )
    })
}

fn check_inner() -> io::Result<InstallationIntegrityView> {
    let installation = installation_path()?;
    let _ancestors = pin_ancestors(&installation)?;
    let repair = installation.join(REPAIR_FOLDER);
    let repair_pin = open_directory(&repair);
    let manifest = match &repair_pin {
        Ok(pin) => {
            inspect_security(pin, false)?;
            load_manifest(&repair)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(ManifestState::Missing),
        Err(_) => Err(ManifestState::Unavailable),
    };
    let installed = std::array::from_fn(|index| {
        observe_image(
            &installation.join(FILE_NAMES[index]),
            manifest.as_ref().ok().map(|value| &value.files[index]),
        )
    });
    let source = if let Ok(manifest) = &manifest {
        std::array::from_fn(|index| {
            observe_image(
                &repair.join(FILE_NAMES[index]),
                Some(&manifest.files[index]),
            )
        })
    } else {
        [FileMatch::Unavailable; 2]
    };
    Ok(integrity::classify(
        manifest
            .as_ref()
            .map_or_else(|state| *state, |_| ManifestState::Valid),
        installed,
        source,
    ))
}

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: this is the single owned handle transferred by ShellExecuteExW.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// No path or argument accepted. Sources are rehashed and pinned through launch
/// and wait; installed target handles are deliberately not held during repair.
pub(crate) fn repair() -> RepairOutcome {
    if check().state != IntegrityStateView::Damaged {
        return RepairOutcome::SourceUnusable;
    }
    repair_inner().unwrap_or(RepairOutcome::Failed)
}

fn repair_inner() -> io::Result<RepairOutcome> {
    let installation = installation_path()?;
    let directory = installation.join(REPAIR_FOLDER);
    let _ancestors = pin_ancestors(&directory)?;
    let manifest = load_manifest(&directory).map_err(|_| refused())?;
    let mut sources = Vec::new();
    for (name, expected) in FILE_NAMES.into_iter().zip(&manifest.files) {
        let mut file = open_image(&directory.join(name))?;
        inspect_security(&file, false)?;
        if !image_matches(&mut file, expected)? {
            return Ok(RepairOutcome::SourceUnusable);
        }
        sources.push(file);
    }
    let executable: Vec<_> = directory
        .join(windows_service_host::SERVICE_EXECUTABLE)
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let directory_wide: Vec<_> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: w!("repair"),
        lpDirectory: PCWSTR(directory_wide.as_ptr()),
        nShow: 0,
        ..Default::default()
    };
    // SAFETY: all NUL-terminated strings remain owned across this synchronous
    // call. Only this fixed protected executable and literal verb can be launched.
    match unsafe { ShellExecuteExW(&mut info) } {
        Ok(()) => (),
        Err(error) if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => {
            return Ok(RepairOutcome::UserCancelled);
        }
        Err(_) => return Ok(RepairOutcome::Failed),
    }
    if info.hProcess.is_invalid() {
        return Ok(RepairOutcome::CompletionStatusUnknown);
    }
    let process = Process(info.hProcess);
    // SAFETY: NOCLOSEPROCESS transferred a live waitable process handle. A
    // timeout closes only our handle, never terminates the elevated repair.
    let wait = unsafe { WaitForSingleObject(process.0, 120_000) };
    if wait == WAIT_TIMEOUT {
        return Ok(RepairOutcome::StillRunning);
    }
    if wait != WAIT_OBJECT_0 {
        return Ok(RepairOutcome::CompletionStatusUnknown);
    }
    let mut exit_code = 0;
    // SAFETY: signaled process handle is still owned and output points to u32.
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) }.is_err() {
        return Ok(RepairOutcome::CompletionStatusUnknown);
    }
    Ok(crate::repair_exit_outcome(exit_code))
}
