// SPDX-License-Identifier: GPL-2.0-or-later
//! Sole Windows-only boundary. Raw handles/tokens never leave this module tree.
use crate::{
    MAX_TOP_LEVEL_WINDOWS, NativeOperation, ProbeCounts, ProbeError, ProbeFailure, ProbeReport,
    finish_with_cleanup, policy,
};
use std::{
    ffi::c_void,
    mem,
    sync::{Arc, Mutex},
    time::Instant,
};
use windows::{
    Win32::{
        Foundation::{FILETIME, HANDLE, HWND, LPARAM, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        System::{
            StationsAndDesktops::{
                DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, EnumDesktopWindows,
                GetProcessWindowStation, GetUserObjectInformationW, HDESK, OpenInputDesktop,
                SetThreadDesktop, UOI_FLAGS, UOI_IO, UOI_NAME, USEROBJECTFLAGS,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess,
                PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
                QueryFullProcessImageNameW, WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::{GetWindowThreadProcessId, WSF_VISIBLE},
    },
    core::{BOOL, Error as WinError, PWSTR},
};
/// Lab-only fixed-token notes (counts, OS names, enum names; never prompt text).
/// Expands to nothing without the `lab-diagnostics` feature.
macro_rules! lab_note {
    ($($arg:tt)*) => {{
        #[cfg(feature = "lab-diagnostics")]
        $crate::ffi::lab_diagnostics::note(&format!($($arg)*));
    }};
}

#[cfg(feature = "lab-diagnostics")]
mod lab_diagnostics {
    use std::sync::atomic::{AtomicU32, Ordering};

    const MAX_NOTES: u32 = 6_000;
    static NOTES: AtomicU32 = AtomicU32::new(0);

    pub(super) fn note(text: &str) {
        if NOTES.fetch_add(1, Ordering::Relaxed) >= MAX_NOTES {
            return;
        }
        let Some(root) = std::env::var_os("ProgramData") else {
            return;
        };
        let path = std::path::Path::new(&root)
            .join("휴대폰 승인")
            .join("lab-helper.txt");
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            use std::io::Write as _;
            let _ = writeln!(file, "{text}");
        }
    }
}

pub(super) mod pipe_client;
mod resources;
mod security;
mod uia;
mod watch;
use resources::{CleanupLog, OwnedDesktop, OwnedHandle};

const MAX_NAME_UNITS: usize = 128;
const MAX_IMAGE_UNITS: usize = 1024;

pub(super) fn probe() -> Result<ProbeReport, ProbeError> {
    let cleanup: CleanupLog = Arc::new(Mutex::new(None));
    let result = scoped_probe(&cleanup);
    // scoped_probe returned only after worker join and all native owners dropped.
    let failures = *cleanup.lock().unwrap_or_else(|poison| poison.into_inner());
    finish_with_cleanup(result, failures)
}

fn scoped_probe(cleanup: &CleanupLog) -> Result<ProbeReport, ProbeError> {
    let began = Instant::now();
    security::reject_impersonation(cleanup)?;
    // SAFETY: borrowed process pseudo-handle and scalar ID; never closed.
    let (process, pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
    security::native64(process)?;
    let session = security::process_identity(process, pid, None, cleanup)?;
    verify_window_station()?;
    let expected_image = system_consent_path()?;
    // SAFETY: fixed zero flags, no inheritance, READOBJECTS only. No switch,
    // write/hook/message/input/security rights or fallback mask is requested.
    let raw = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
        .map_err(|error| native_error(NativeOperation::OpenInputDesktop, error))?;
    let desktop = OwnedDesktop::acquired(raw, cleanup)?;
    verify_input_desktop(desktop.raw())?;
    policy::budget(began.elapsed())?;
    // This opaque OS handle value is NOT a Rust memory pointer to dereference.
    // Only a private scoped token crosses threads. The owning !Send desktop
    // remains on this parent stack until scope/join completes, including panic.
    // No broad handle gains Send/Sync and no token can escape the public API.
    let desktop_token = desktop.raw().0 as usize;
    let worker_cleanup = Arc::clone(cleanup);
    let result = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("read-only-consent-uia".into())
            .spawn_scoped(scope, move || {
                worker_probe(
                    desktop_token,
                    session,
                    expected_image,
                    began,
                    &worker_cleanup,
                )
            })
            .map_err(|_| ProbeError::new(ProbeFailure::WorkerUnavailable))?;
        // An unbounded native/provider block is deliberately NOT turned into a
        // timed-out join success. The future PROCESS supervisor must terminate
        // the entire helper at 5s. No output occurs while this worker remains.
        worker
            .join()
            .map_err(|_| ProbeError::new(ProbeFailure::WorkerPanicked))?
    });
    drop(desktop); // Worker thread has exited; its assigned desktop can now close.
    result
}

fn worker_probe(
    token: usize,
    session: u32,
    image: Vec<u16>,
    began: Instant,
    cleanup: &CleanupLog,
) -> Result<ProbeReport, ProbeError> {
    security::reject_impersonation(cleanup)?;
    // SAFETY: borrowed pseudo-handle/current scalar ID; neither is an owned
    // resource. Recheck the actual worker's process context against parent facts.
    let (own_process, own_pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
    security::process_identity(own_process, own_pid, Some(session), cleanup)?;
    verify_window_station()?;
    // SAFETY: token is the parent's still-owned HDESK value, passed only through
    // the private scoped spawn above. This fresh thread has created no window,
    // hook or COM apartment; assignment precedes all UIA/COM work. The desktop
    // belongs to the verified current process window station. Not SwitchDesktop.
    let desktop = HDESK(token as *mut c_void);
    unsafe { SetThreadDesktop(desktop) }
        .map_err(|error| native_error(NativeOperation::AttachWorkerDesktop, error))?;
    verify_input_desktop(desktop)?;
    let windows = enumerate(desktop, began)?;
    let mut candidate = None;
    let mut qualified = 0;
    for hwnd in &windows {
        policy::budget(began.elapsed())?;
        if let Some(found) = candidate_for(*hwnd, session, &image, cleanup)? {
            qualified += 1;
            policy::unique_candidate(qualified)?;
            candidate = Some(found);
        }
    }
    policy::unique_candidate(qualified)?;
    let candidate =
        candidate.ok_or_else(|| ProbeError::new(ProbeFailure::NoQualifiedConsentWindow))?;
    let counts = ProbeCounts {
        top_level_windows: u16::try_from(windows.len())
            .map_err(|_| malformed(NativeOperation::EnumerateWindows))?,
        qualified_candidates: 1,
        ..ProbeCounts::default()
    };
    candidate.recheck(session, &image, cleanup)?;
    let report = uia::inspect(
        candidate.hwnd,
        candidate.pid,
        began,
        counts,
        cleanup,
        || {
            // Read-only context checks around EACH complete capture while the same
            // UIA root remains held. Original desktop-census seed counts are not a
            // second census or atomic target proof; traversal content/counts are new.
            candidate.recheck(session, &image, cleanup)?;
            verify_input_desktop(desktop)?;
            verify_window_station()?;
            security::reject_impersonation(cleanup)?;
            security::process_identity(own_process, own_pid, Some(session), cleanup)?;
            policy::budget(began.elapsed())
        },
    )?;
    candidate.recheck(session, &image, cleanup)?;
    verify_input_desktop(desktop)?;
    security::reject_impersonation(cleanup)?;
    security::process_identity(own_process, own_pid, Some(session), cleanup)?;
    policy::budget(began.elapsed())?;
    Ok(report)
}

pub(super) fn verify_window_station() -> Result<(), ProbeError> {
    // SAFETY: current process window station is borrowed and never closed/set.
    let station = unsafe { GetProcessWindowStation() }
        .map_err(|error| native_error(NativeOperation::WindowStation, error))?;
    let handle = HANDLE(station.0);
    let name = object_name(handle, NativeOperation::WindowStation)?;
    let mut flags = USEROBJECTFLAGS::default();
    let mut returned = 0;
    // SAFETY: borrowed valid station, fixed UOI_FLAGS with exact initialized
    // C-layout output and separate length; pointers live for this synchronous call.
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_FLAGS,
            Some((&mut flags as *mut USEROBJECTFLAGS).cast()),
            mem::size_of::<USEROBJECTFLAGS>() as u32,
            Some(&mut returned),
        )
    }
    .map_err(|error| native_error(NativeOperation::WindowStation, error))?;
    if returned as usize != mem::size_of::<USEROBJECTFLAGS>()
        || !name.eq_ignore_ascii_case("WinSta0")
        || flags.dwFlags & WSF_VISIBLE as u32 == 0
    {
        return Err(ProbeError::new(
            ProbeFailure::InteractiveWindowStationRequired,
        ));
    }
    Ok(())
}

pub(super) fn verify_input_desktop(desktop: HDESK) -> Result<(), ProbeError> {
    let name = object_name(HANDLE(desktop.0), NativeOperation::DesktopName)?;
    let mut receives_input = BOOL::default();
    let mut returned = 0;
    // SAFETY: parent-owned live desktop; UOI_IO only reads its input status.
    // Exact initialized BOOL/length outputs; no state/rights change is requested.
    unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_IO,
            Some((&mut receives_input as *mut BOOL).cast()),
            mem::size_of::<BOOL>() as u32,
            Some(&mut returned),
        )
    }
    .map_err(|error| native_error(NativeOperation::DesktopInput, error))?;
    if returned as usize != mem::size_of::<BOOL>()
        || !receives_input.as_bool()
        || !name.eq_ignore_ascii_case("Winlogon")
    {
        return Err(ProbeError::new(
            ProbeFailure::SecureInputDesktopProfileRequired,
        ));
    }
    Ok(())
}

pub(super) fn object_name(
    handle: HANDLE,
    operation: NativeOperation,
) -> Result<String, ProbeError> {
    let mut units = [0xffff_u16; MAX_NAME_UNITS];
    let mut returned = 0;
    // SAFETY: live borrowed station/desktop and fixed read-only UOI_NAME. Storage
    // is aligned, initialized and bounded; returned length is separately checked.
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(units.as_mut_ptr().cast()),
            mem::size_of_val(&units) as u32,
            Some(&mut returned),
        )
    }
    .map_err(|error| native_error(operation, error))?;
    policy::strict_name(&units, returned).ok_or_else(|| malformed(operation))
}

pub(super) fn system_consent_path() -> Result<Vec<u16>, ProbeError> {
    let mut units = [0xffff_u16; MAX_IMAGE_UNITS];
    // SAFETY: native OS directory query into initialized bounded UTF-16 storage;
    // no environment/user path or filesystem mutation is involved.
    let count = unsafe { GetSystemDirectoryW(Some(&mut units)) } as usize;
    if count == 0 || count >= units.len() || units[count] != 0 || units[..count].contains(&0) {
        return Err(malformed(NativeOperation::SystemDirectory));
    }
    String::from_utf16(&units[..count]).map_err(|_| malformed(NativeOperation::SystemDirectory))?;
    let mut path = units[..count].to_vec();
    if path.last() != Some(&(b'\\' as u16)) {
        path.push(b'\\' as u16);
    }
    path.extend("consent.exe".encode_utf16());
    Ok(path)
}

pub(super) fn image_matches(process: HANDLE, expected: &[u16]) -> Result<bool, ProbeError> {
    let mut units = [0xffff_u16; MAX_IMAGE_UNITS];
    let mut count = units.len() as u32;
    // SAFETY: retained QUERY_LIMITED process, fixed Win32 path format, exclusive
    // initialized bounded buffer/length. This path is NOT mapped-image or signer
    // proof, and is never interpreted as the executable requesting elevation.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(units.as_mut_ptr()),
            &mut count,
        )
    }
    .map_err(|error| native_error(NativeOperation::ProcessImage, error))?;
    let count = count as usize;
    if count == 0 || count >= units.len() || units[..count].contains(&0) {
        return Err(malformed(NativeOperation::ProcessImage));
    }
    String::from_utf16(&units[..count]).map_err(|_| malformed(NativeOperation::ProcessImage))?;
    // SAFETY: two valid initialized UTF-16 slices with checked bounded lengths;
    // Windows ordinal case comparison reads only these slices and retains nothing.
    let comparison = unsafe { CompareStringOrdinal(&units[..count], expected, true) };
    if comparison.0 == 0 {
        return Err(native_error(
            NativeOperation::CompareImagePath,
            WinError::from_thread(),
        ));
    }
    Ok(comparison == CSTR_EQUAL)
}

pub(super) fn window_owner(hwnd: HWND) -> Result<(u32, u32), ProbeError> {
    let mut pid = 0;
    // SAFETY: HWND is a bounded OS enumeration/UIA observation, never a pointer
    // dereference or external parameter. Invalid/recycled windows fail/recheck.
    // pid is exclusive initialized output valid for the synchronous query.
    let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    if pid == 0 || thread == 0 {
        return Err(ProbeError::new(ProbeFailure::ObservationChanged));
    }
    Ok((thread, pid))
}

pub(super) fn process_creation(process: HANDLE) -> Result<u64, ProbeError> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: live retained query process and four distinct initialized FILETIME
    // outputs; no pointers outlive this call. Only creation identity is retained.
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|error| native_error(NativeOperation::ProcessTimes, error))?;
    let identity = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if identity == 0 {
        return Err(malformed(NativeOperation::ProcessTimes));
    }
    Ok(identity)
}

pub(super) fn alive(process: HANDLE) -> Result<(), ProbeError> {
    // SAFETY: retained SYNCHRONIZE process handle, zero-time read-only wait. This
    // does not confuse a process exit code of STILL_ACTIVE with actual liveness.
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 => Err(ProbeError::new(ProbeFailure::ObservationChanged)),
        _ => Err(native_error(
            NativeOperation::ProcessLiveness,
            WinError::from_thread(),
        )),
    }
}

pub(super) struct Candidate {
    pub(super) hwnd: HWND,
    pub(super) pid: u32,
    thread: u32,
    pub(super) creation: u64,
    process: OwnedHandle,
}
impl Candidate {
    pub(super) fn recheck(
        &self,
        session: u32,
        image: &[u16],
        cleanup: &CleanupLog,
    ) -> Result<(), ProbeError> {
        alive(self.process.raw())?;
        if window_owner(self.hwnd)? != (self.thread, self.pid)
            || process_creation(self.process.raw())? != self.creation
            || !image_matches(self.process.raw(), image)?
        {
            return Err(ProbeError::new(ProbeFailure::ObservationChanged));
        }
        security::process_identity(self.process.raw(), self.pid, Some(session), cleanup)?;
        Ok(())
    }
}

pub(super) fn candidate_for(
    hwnd: HWND,
    session: u32,
    expected_image: &[u16],
    cleanup: &CleanupLog,
) -> Result<Option<Candidate>, ProbeError> {
    let (thread, pid) = window_owner(hwnd)?;
    // SAFETY: only limited query/synchronize rights for an OS-enumerated PID;
    // no inheritance, all-access, token copy, termination or write privileges.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map_err(|error| native_error(NativeOperation::OpenProcess, error))?;
    let process = OwnedHandle::acquired(raw, NativeOperation::CloseProcess, cleanup)?;
    if !image_matches(process.raw(), expected_image)? {
        lab_note!("window {:#x}: pid={pid} image mismatch", hwnd.0 as usize);
        return Ok(None);
    }
    security::native64(process.raw())?;
    security::process_identity(process.raw(), pid, Some(session), cleanup)?;
    alive(process.raw())?;
    let creation = process_creation(process.raw())?;
    let candidate = Candidate {
        hwnd,
        pid,
        thread,
        creation,
        process,
    };
    candidate.recheck(session, expected_image, cleanup)?;
    Ok(Some(candidate))
}

struct Enumeration {
    windows: Vec<HWND>,
    began: Option<Instant>,
    failure: Option<ProbeFailure>,
}

unsafe extern "system" fn enum_window(hwnd: HWND, parameter: LPARAM) -> BOOL {
    // SAFETY: EnumDesktopWindows synchronously returns this exact non-null
    // pointer to the exclusive stack collector. It is not stored anywhere and
    // no other thread accesses it until enumeration returns.
    let collector = unsafe { &mut *(parameter.0 as *mut Enumeration) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Some(began) = collector.began
            && let Err(error) = policy::budget(began.elapsed())
        {
            collector.failure = Some(error.failure());
            return false;
        }
        if collector.windows.len() == MAX_TOP_LEVEL_WINDOWS {
            collector.failure = Some(ProbeFailure::TopLevelWindowLimit);
            return false;
        }
        collector.windows.push(hwnd);
        true
    }));
    match result {
        Ok(keep_going) => BOOL::from(keep_going),
        Err(_) => {
            collector.failure = Some(ProbeFailure::WorkerPanicked);
            BOOL(0)
        }
    }
}

pub(super) fn enumerate(desktop: HDESK, began: Instant) -> Result<Vec<HWND>, ProbeError> {
    enumerate_inner(desktop, Some(began))
}

pub(super) fn enumerate_without_budget(desktop: HDESK) -> Result<Vec<HWND>, ProbeError> {
    enumerate_inner(desktop, None)
}

fn enumerate_inner(desktop: HDESK, began: Option<Instant>) -> Result<Vec<HWND>, ProbeError> {
    let mut collector = Enumeration {
        windows: Vec::with_capacity(MAX_TOP_LEVEL_WINDOWS),
        began,
        failure: None,
    };
    // SAFETY: parent's live READOBJECTS desktop and a synchronous callback with a
    // stable exclusive collector address. Callback catches Rust unwinds, performs
    // no GUI operation and never exceeds preallocated capacity. No pointer escapes.
    let result = unsafe {
        EnumDesktopWindows(
            Some(desktop),
            Some(enum_window),
            LPARAM((&mut collector as *mut Enumeration) as isize),
        )
    };
    if let Some(failure) = collector.failure {
        return Err(ProbeError::new(failure));
    }
    result.map_err(|error| native_error(NativeOperation::EnumerateWindows, error))?;
    Ok(collector.windows)
}

fn native_error(operation: NativeOperation, error: WinError) -> ProbeError {
    ProbeError::new(ProbeFailure::NativeCall {
        operation,
        hresult: error.code().0,
    })
}
fn malformed(operation: NativeOperation) -> ProbeError {
    ProbeError::new(ProbeFailure::MalformedNativeData(operation))
}
