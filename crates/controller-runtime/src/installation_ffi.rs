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
//! Full observations/preflight run on a dedicated STA thread with a 20-second
//! deadline. Cancellation gets a bounded exit wait; an unresponsive thread stays
//! in the single outstanding slot and can never accumulate replacement workers.

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
    sync::Mutex,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
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
            Com::{
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoTaskMemFree,
                CoUninitialize,
            },
            IO::CancelSynchronousIo,
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
const CHECK_DEADLINE: Duration = Duration::from_secs(20);
const CANCEL_JOIN_WAIT: Duration = Duration::from_millis(250);
// Includes a Windows-owned consent dialog and the existing 120-second process
// wait. Expiry here is indeterminate completion, never a retryable repair failure.
const LAUNCH_DEADLINE: Duration = Duration::from_secs(300);

// Prevent this scoped COM obligation from being moved to another thread.
struct ComApartment(std::marker::PhantomData<std::rc::Rc<()>>);
impl ComApartment {
    fn initialize() -> io::Result<Self> {
        // SAFETY: called only on a new dedicated thread, never on the shared
        // blocking pool. Both S_OK and S_FALSE acquire one uninitialize obligation.
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) }
            .ok()
            .map_err(|_| refused())?;
        Ok(Self(std::marker::PhantomData))
    }
}
impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: the owner remains on its creating thread; one successful init
        // is balanced once, after the known-folder/shell calls and their owners.
        unsafe { CoUninitialize() };
    }
}

#[derive(Clone, Copy)]
enum NativeOperation {
    Check,
    PrepareRepair,
}

enum NativeResult {
    Check(InstallationIntegrityView),
    Prepared(io::Result<PreparedRepair>),
    Repair(RepairOutcome),
}

struct NativeWorker {
    join: JoinHandle<NativeResult>,
}

// Check, preparation and shell launch share one slot. A stuck/cancelled thread
// stays owned here; no second file reader or elevation can be queued behind it.
static NATIVE_WORKER: Mutex<Option<NativeWorker>> = Mutex::new(None);

enum ThreadWait {
    Exited,
    Outstanding,
}

fn wait_thread(worker: &NativeWorker, wait: Duration) -> ThreadWait {
    // SAFETY: JoinHandle owns this thread handle throughout the bounded wait.
    // Waiting does not consume/close the handle or terminate the worker.
    let result = unsafe {
        WaitForSingleObject(
            HANDLE(worker.join.as_raw_handle()),
            wait.as_millis().min(u128::from(u32::MAX - 1)) as u32,
        )
    };
    if result == WAIT_OBJECT_0 {
        ThreadWait::Exited
    } else {
        ThreadWait::Outstanding
    }
}

fn cancel_io(worker: &NativeWorker) {
    // SAFETY: the borrowed JoinHandle handle remains owned during cancellation.
    // This requests cancellation only; it neither waits nor terminates a thread.
    // ERROR_NOT_FOUND may race with I/O submission; the outstanding slot is kept.
    let _ = unsafe { CancelSynchronousIo(HANDLE(worker.join.as_raw_handle())) };
}

fn admit_worker(slot: &mut Option<NativeWorker>) -> bool {
    let exited = slot
        .as_ref()
        .is_some_and(|worker| matches!(wait_thread(worker, Duration::ZERO), ThreadWait::Exited));
    match integrity::worker_admission(slot.is_some(), exited) {
        integrity::WorkerAdmission::Start => true,
        integrity::WorkerAdmission::Busy => {
            if let Some(worker) = slot.as_ref() {
                cancel_io(worker);
            }
            false
        }
        integrity::WorkerAdmission::Reap => {
            // A timed-out worker's late result is discarded, even if it hashed
            // successfully. Join only after the native thread handle is signaled.
            if let Some(worker) = slot.take() {
                let _ = worker.join.join();
            }
            true
        }
    }
}

fn await_worker(slot: &mut Option<NativeWorker>, deadline: Instant) -> Option<NativeResult> {
    let worker = slot.as_ref()?;
    if matches!(
        wait_thread(worker, deadline.saturating_duration_since(Instant::now())),
        ThreadWait::Exited
    ) && Instant::now() <= deadline
    {
        return slot.take()?.join.join().ok();
    }
    cancel_io(worker);
    if matches!(wait_thread(worker, CANCEL_JOIN_WAIT), ThreadWait::Exited) {
        // Never accept the result after the deadline, even if cancellation lost
        // its race. This join is bounded by the already-signaled thread handle.
        if let Some(worker) = slot.take() {
            let _ = worker.join.join();
        }
    }
    // Otherwise keep the JoinHandle in the static slot, not detached/dropped.
    None
}

fn start_observation(operation: NativeOperation) -> io::Result<NativeWorker> {
    let join = thread::Builder::new()
        .name("installation-observation".into())
        .spawn(move || {
            let apartment = ComApartment::initialize();
            match operation {
                NativeOperation::Check => NativeResult::Check(integrity::completed_check(
                    apartment.ok().and_then(|_apartment| check_inner().ok()),
                )),
                NativeOperation::PrepareRepair => {
                    NativeResult::Prepared(apartment.and_then(|_apartment| prepare_repair()))
                }
            }
        })?;
    Ok(NativeWorker { join })
}

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
    let observed = (|| {
        // Do not wait behind another caller holding the native slot.
        let mut slot = NATIVE_WORKER.try_lock().ok()?;
        if !admit_worker(&mut slot) {
            return None;
        }
        let deadline = Instant::now() + CHECK_DEADLINE;
        *slot = Some(start_observation(NativeOperation::Check).ok()?);
        match await_worker(&mut slot, deadline) {
            Some(NativeResult::Check(view)) => Some(view),
            _ => None,
        }
    })();
    integrity::completed_check(observed)
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

/// No path or argument accepted. The deadline covers the whole preflight,
/// including the installed check and second source validation. Only the waiting
/// caller can transfer validated pins to a separate shell thread: a late or
/// cancelled preflight thread can never launch an elevation by itself.
pub(crate) fn repair() -> RepairOutcome {
    let Ok(mut slot) = NATIVE_WORKER.try_lock() else {
        return RepairOutcome::Failed;
    };
    if !admit_worker(&mut slot) {
        return RepairOutcome::Failed;
    }
    let deadline = Instant::now() + CHECK_DEADLINE;
    let Ok(worker) = start_observation(NativeOperation::PrepareRepair) else {
        return RepairOutcome::Failed;
    };
    *slot = Some(worker);
    let prepared = match await_worker(&mut slot, deadline) {
        Some(NativeResult::Prepared(Ok(prepared))) => prepared,
        Some(NativeResult::Prepared(Err(error))) if error.kind() == io::ErrorKind::InvalidData => {
            return RepairOutcome::SourceUnusable;
        }
        // A deadline or I/O failure is not proof of a damaged repair source.
        _ => return RepairOutcome::Failed,
    };
    let deadline = Instant::now() + LAUNCH_DEADLINE;
    let worker = thread::Builder::new()
        .name("installation-repair-launch".into())
        .spawn(move || {
            let outcome = ComApartment::initialize().and_then(|_apartment| launch_repair(prepared));
            NativeResult::Repair(outcome.unwrap_or(RepairOutcome::Failed))
        });
    let Ok(join) = worker else {
        return RepairOutcome::Failed;
    };
    *slot = Some(NativeWorker { join });
    match await_worker(&mut slot, deadline) {
        Some(NativeResult::Repair(outcome)) => outcome,
        _ => RepairOutcome::CompletionStatusUnknown,
    }
}

struct PreparedRepair {
    directory: PathBuf,
    _ancestors: Vec<File>,
    _sources: Vec<File>,
}

fn prepare_repair() -> io::Result<PreparedRepair> {
    match check_inner()?.state {
        IntegrityStateView::Damaged => (),
        IntegrityStateView::Unknown => return Err(refused()),
        IntegrityStateView::Intact | IntegrityStateView::SourceDamaged => {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
    let installation = installation_path()?;
    let directory = installation.join(REPAIR_FOLDER);
    let _ancestors = pin_ancestors(&directory)?;
    let manifest = load_manifest(&directory).map_err(|_| refused())?;
    let mut sources = Vec::new();
    for (name, expected) in FILE_NAMES.into_iter().zip(&manifest.files) {
        let mut file = open_image(&directory.join(name))?;
        inspect_security(&file, false)?;
        if !image_matches(&mut file, expected)? {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        sources.push(file);
    }
    Ok(PreparedRepair {
        directory,
        _ancestors,
        _sources: sources,
    })
}

fn launch_repair(prepared: PreparedRepair) -> io::Result<RepairOutcome> {
    // Parent/source pins survive transfer between the dedicated threads and
    // remain held across ShellExecuteEx and the complete existing process wait.
    let directory = &prepared.directory;
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
