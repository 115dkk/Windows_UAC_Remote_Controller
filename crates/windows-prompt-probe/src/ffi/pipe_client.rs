// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed helper-side channel. A name/challenge is never server authentication.
//! One-shot calls are synchronous. Watch mode retains one overlapped service read
//! and issues at most one helper write at a time. The service supervises this process.
use super::{resources::CleanupLog, security};
use crate::supervision::{
    CHALLENGE_BYTES, Challenge, HelperExit, HelperMessage, INSTALLATION_FOLDER,
    MAX_WATCH_MESSAGE_BYTES, PIPE_PREFIX, PROBE_EXECUTABLE, SERVICE_EXECUTABLE, SERVICE_NAME,
    ServiceMessage, encode_report,
};
use std::{
    cell::{Cell, UnsafeCell},
    mem,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_MORE_DATA,
            ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, HANDLE,
        },
        Security::{LookupAccountNameW, PSID, SID_NAME_USE, SidTypeWellKnownGroup},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_MODE, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION,
            SECURITY_SQOS_PRESENT, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Pipes::{
                GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_MESSAGE,
                SetNamedPipeHandleState,
            },
            Services::{
                CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
                QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
                SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
                SERVICE_RUNNING, SERVICE_STATUS_PROCESS, SERVICE_WIN32_OWN_PROCESS,
            },
            Threading::{
                CreateEventW, GetCurrentProcess, GetCurrentProcessId, OpenProcess,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, ResetEvent,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

type Result<T> = std::result::Result<T, ()>;
type CloseLog = Rc<Cell<bool>>;

pub(crate) fn run() -> HelperExit {
    let cleanup: CleanupLog = Arc::new(Mutex::new(None));
    let close = Rc::new(Cell::new(false));
    let result = scoped(&cleanup, &close);
    // All scoped process/pipe/SCM/token owners were dropped before the exit code
    // becomes visible. A report already written is NOT accepted by the service
    // if final cleanup changes this exit to3; no stdout/native handle escapes.
    if close.get()
        || cleanup
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
    {
        HelperExit::CleanupUnconfirmed
    } else {
        result.unwrap_or(HelperExit::Rejected)
    }
}

pub(crate) fn run_watch() -> HelperExit {
    let cleanup: CleanupLog = Arc::new(Mutex::new(None));
    let close = Rc::new(Cell::new(false));
    let result = scoped_watch(&cleanup, &close);
    if close.get()
        || cleanup
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
    {
        HelperExit::CleanupUnconfirmed
    } else {
        result.unwrap_or(HelperExit::Rejected)
    }
}

fn scoped(cleanup: &CleanupLog, close: &CloseLog) -> Result<HelperExit> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: own borrowed process pseudo-handle and scalar PID, never closed.
    let (own, own_pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
    security::native64(own).map_err(|_| ())?;
    let session = security::process_identity(own, own_pid, None, cleanup).map_err(|_| ())?;
    let service_sid = service_sid()?;
    security::service_identity(own, own_pid, session, &service_sid, cleanup).map_err(|_| ())?;
    let expected = expected_service()?;
    let service = Scm::open(close)?;
    let expected_pid = service.verify(&expected)?;
    let name: Vec<u16> = format!("{PIPE_PREFIX}{own_pid}\0").encode_utf16().collect();
    // SAFETY: one fixed local pipe derived only from our own PID. Parent creates
    // it before resuming us; no wait/retry/alternate endpoint. Identification QoS
    // prevents a server from impersonating this SYSTEM client. No handle inherit.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )
    }
    .map_err(|_| ())?;
    let pipe = Kernel::new(raw, close)?;
    let (mut pid, mut server_session) = (0, u32::MAX);
    // SAFETY: connected owned local pipe, exact initialized scalar outputs.
    unsafe { GetNamedPipeServerProcessId(pipe.raw, &mut pid) }.map_err(|_| ())?;
    // SAFETY: same retained connected endpoint, no impersonation call.
    unsafe { GetNamedPipeServerSessionId(pipe.raw, &mut server_session) }.map_err(|_| ())?;
    if pid == 0 || pid != expected_pid || server_session != 0 {
        return Err(());
    }
    // SAFETY: query/synchronize ONLY the actual pipe server PID matched to SCM;
    // retaining this process prevents identity from being replaced by PID reuse.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map_err(|_| ())?;
    let server = Kernel::new(raw, close)?;
    let creation = super::process_creation(server.raw).map_err(|_| ())?;
    let peer = Peer {
        process: server,
        pid,
        creation,
        expected,
        service,
        sid: service_sid,
    };
    peer.recheck(cleanup)?;
    // SAFETY: owned endpoint only; message-read mode preserves exact one-message
    // framing. This changes no security/desktop/window state.
    unsafe { SetNamedPipeHandleState(pipe.raw, Some(&PIPE_READMODE_MESSAGE), None, None) }
        .map_err(|_| ())?;
    let mut challenge_bytes = [0u8; CHALLENGE_BYTES + 1];
    let mut count = 0;
    // SAFETY: synchronous read into initialized bounded buffer; no borrowed data
    // outlives the call. Oversized messages/ERROR_MORE_DATA fail, not truncate.
    unsafe { ReadFile(pipe.raw, Some(&mut challenge_bytes), Some(&mut count), None) }
        .map_err(|_| ())?;
    if count as usize != CHALLENGE_BYTES {
        return Err(());
    }
    let challenge = Challenge::decode(&challenge_bytes[..CHALLENGE_BYTES]).map_err(|_| ())?;
    peer.recheck(cleanup)?;
    if close.get()
        || cleanup
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
    {
        return Ok(HelperExit::CleanupUnconfirmed);
    }
    let result = super::probe();
    if result
        .as_ref()
        .err()
        .is_some_and(|error| error.cleanup().is_some())
    {
        return Ok(HelperExit::CleanupUnconfirmed);
    }
    let exit = if result.is_ok() {
        HelperExit::Observed
    } else {
        HelperExit::Unavailable
    };
    let report = encode_report(challenge, result).map_err(|_| ())?;
    peer.recheck(cleanup)?;
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    if close.get()
        || cleanup
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .is_some()
    {
        return Ok(HelperExit::CleanupUnconfirmed);
    }
    let mut written = 0;
    // SAFETY: one immutable bounded v2 observation on the authenticated owned
    // pipe. The encoder rejects malformed/oversized content; do not split it
    // into multiple pipe messages or expose the visible labels through stdout.
    // Native capture excludes edit/value/password subtrees, not all possible
    // sensitive text an application may have placed in a visible static label.
    unsafe { WriteFile(pipe.raw, Some(&report), Some(&mut written), None) }.map_err(|_| ())?;
    if written as usize != report.len() {
        return Err(());
    }
    // Closing the endpoint gives EOF. Parent still waits actual process exit and
    // checks code0/1 before releasing this already-buffered report.
    Ok(exit)
}

fn scoped_watch(cleanup: &CleanupLog, close: &CloseLog) -> Result<HelperExit> {
    let (pipe, peer) = connect_authenticated(cleanup, close)?;
    let mut channel = WatchChannel::new(pipe)?;
    crate::ffi::watch::run(&mut channel, cleanup, || peer.recheck(cleanup))?;
    Ok(HelperExit::Observed)
}

fn connect_authenticated(cleanup: &CleanupLog, close: &CloseLog) -> Result<(Kernel, Peer)> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: borrowed current-process pseudo-handle and scalar ID, never closed.
    let (own, own_pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
    security::native64(own).map_err(|_| ())?;
    let session = security::process_identity(own, own_pid, None, cleanup).map_err(|_| ())?;
    let service_sid = service_sid()?;
    security::service_identity(own, own_pid, session, &service_sid, cleanup).map_err(|_| ())?;
    let expected = expected_service()?;
    let service = Scm::open(close)?;
    let expected_pid = service.verify(&expected)?;
    let name: Vec<u16> = format!("{PIPE_PREFIX}{own_pid}\0").encode_utf16().collect();
    // SAFETY: fixed local pipe from our PID, no wait or fallback. Identification
    // QoS forbids service impersonation of this SYSTEM client.
    let raw = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )
    }
    .map_err(|_| ())?;
    let pipe = Kernel::new(raw, close)?;
    let (mut pid, mut server_session) = (0, u32::MAX);
    // SAFETY: connected owned local pipe and distinct scalar outputs.
    unsafe { GetNamedPipeServerProcessId(pipe.raw, &mut pid) }.map_err(|_| ())?;
    // SAFETY: same retained endpoint, query only.
    unsafe { GetNamedPipeServerSessionId(pipe.raw, &mut server_session) }.map_err(|_| ())?;
    if pid == 0 || pid != expected_pid || server_session != 0 {
        return Err(());
    }
    // SAFETY: query/synchronize only the authenticated server PID.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map_err(|_| ())?;
    let server = Kernel::new(raw, close)?;
    let creation = super::process_creation(server.raw).map_err(|_| ())?;
    let peer = Peer {
        process: server,
        pid,
        creation,
        expected,
        service,
        sid: service_sid,
    };
    peer.recheck(cleanup)?;
    // SAFETY: retained endpoint, message mode only.
    unsafe { SetNamedPipeHandleState(pipe.raw, Some(&PIPE_READMODE_MESSAGE), None, None) }
        .map_err(|_| ())?;
    Ok((pipe, peer))
}

pub(super) enum WatchRead {
    Pending,
    Message(ServiceMessage),
    Eof,
}

struct IoStorage {
    overlapped: OVERLAPPED,
    bytes: Box<[u8]>,
}

pub(super) struct WatchChannel {
    pipe: Kernel,
    read_event: Kernel,
    read: Box<UnsafeCell<IoStorage>>,
    in_flight: bool,
}
impl WatchChannel {
    fn new(pipe: Kernel) -> Result<Self> {
        // SAFETY: private unnamed manual-reset event, noninheritable and initially clear.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(|_| ())?;
        let event = match Kernel::new(event, &pipe.close) {
            Ok(event) => event,
            Err(()) => {
                // SAFETY: CreateEventW succeeded but the defensive validity check failed.
                let _ = unsafe { CloseHandle(event) };
                return Err(());
            }
        };
        let mut channel = Self {
            pipe,
            read_event: event,
            read: Box::new(UnsafeCell::new(IoStorage {
                overlapped: OVERLAPPED::default(),
                bytes: vec![0; MAX_WATCH_MESSAGE_BYTES].into_boxed_slice(),
            })),
            in_flight: false,
        };
        channel.start_read()?;
        Ok(channel)
    }

    fn start_read(&mut self) -> Result<()> {
        if self.in_flight {
            return Err(());
        }
        // SAFETY: owned manual-reset event, no prior read remains pending.
        unsafe { ResetEvent(self.read_event.raw) }.map_err(|_| ())?;
        // SAFETY: unique channel access, stable boxed storage and one read operation.
        let storage = unsafe { &mut *self.read.get() };
        storage.overlapped = OVERLAPPED {
            hEvent: self.read_event.raw,
            ..OVERLAPPED::default()
        };
        match unsafe {
            ReadFile(
                self.pipe.raw,
                Some(&mut storage.bytes),
                None,
                Some(&mut storage.overlapped),
            )
        } {
            Ok(()) => self.in_flight = true,
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) =>
            {
                self.in_flight = true;
            }
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_BROKEN_PIPE.0) =>
            {
                self.in_flight = false;
            }
            Err(_) => return Err(()),
        }
        Ok(())
    }

    pub(super) fn poll_read(&mut self) -> Result<WatchRead> {
        if !self.in_flight {
            return Ok(WatchRead::Eof);
        }
        let mut count = 0;
        // SAFETY: exact retained pipe and stable pending OVERLAPPED, no waiting.
        let result = unsafe {
            GetOverlappedResult(
                self.pipe.raw,
                std::ptr::addr_of!((*self.read.get()).overlapped),
                &mut count,
                false,
            )
        };
        match result {
            Ok(()) => {
                self.in_flight = false;
                let count = count as usize;
                if count == 0 || count > MAX_WATCH_MESSAGE_BYTES {
                    return Err(());
                }
                // SAFETY: successful completion ended kernel writes; count is bounded.
                let message = &unsafe { &*self.read.get() }.bytes[..count];
                let message = ServiceMessage::from_wire(message).map_err(|_| ())?;
                self.start_read()?;
                Ok(WatchRead::Message(message))
            }
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_IO_INCOMPLETE.0) =>
            {
                Ok(WatchRead::Pending)
            }
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_BROKEN_PIPE.0) =>
            {
                self.in_flight = false;
                Ok(WatchRead::Eof)
            }
            Err(error)
                if [ERROR_MORE_DATA.0, ERROR_OPERATION_ABORTED.0]
                    .into_iter()
                    .any(|code| error.code() == windows::core::HRESULT::from_win32(code)) =>
            {
                self.in_flight = false;
                Err(())
            }
            Err(_) => Err(()),
        }
    }

    pub(super) fn write(&mut self, message: &HelperMessage) -> Result<()> {
        let bytes = message.to_wire().map_err(|_| ())?;
        // SAFETY: private unnamed manual-reset event, noninheritable and clear.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.map_err(|_| ())?;
        let event = match Kernel::new(event, &self.pipe.close) {
            Ok(event) => event,
            Err(()) => {
                // SAFETY: CreateEventW succeeded but the defensive validity check failed.
                let _ = unsafe { CloseHandle(event) };
                return Err(());
            }
        };
        let storage = Box::new(UnsafeCell::new(IoStorage {
            overlapped: OVERLAPPED {
                hEvent: event.raw,
                ..OVERLAPPED::default()
            },
            bytes: bytes.into_boxed_slice(),
        }));
        // SAFETY: stable storage and event remain owned through terminal completion.
        let result = unsafe {
            let storage = &mut *storage.get();
            WriteFile(
                self.pipe.raw,
                Some(&storage.bytes),
                None,
                Some(&mut storage.overlapped),
            )
        };
        match result {
            Ok(()) => {}
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_IO_PENDING.0) => {}
            Err(_) => return Err(()),
        }
        let mut written = 0;
        // SAFETY: exact write storage and pipe are retained; wait ends the kernel borrow.
        unsafe {
            GetOverlappedResult(
                self.pipe.raw,
                std::ptr::addr_of!((*storage.get()).overlapped),
                &mut written,
                true,
            )
        }
        .map_err(|_| ())?;
        // SAFETY: terminal completion permits immutable buffer length inspection.
        if written as usize != unsafe { &*storage.get() }.bytes.len() {
            return Err(());
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if !self.in_flight {
            return Ok(());
        }
        // SAFETY: cancel only this channel's retained pending read.
        let cancel_failed = match unsafe {
            CancelIoEx(
                self.pipe.raw,
                Some(std::ptr::addr_of!((*self.read.get()).overlapped)),
            )
        } {
            Ok(()) => false,
            Err(error) if error.code() == windows::core::HRESULT::from_win32(ERROR_NOT_FOUND.0) => {
                false
            }
            Err(_) => true,
        };
        let mut count = 0;
        // SAFETY: wait for the cancelled or concurrently completed exact operation.
        let result = unsafe {
            GetOverlappedResult(
                self.pipe.raw,
                std::ptr::addr_of!((*self.read.get()).overlapped),
                &mut count,
                true,
            )
        };
        self.in_flight = false;
        if cancel_failed {
            return Err(());
        }
        match result {
            Ok(()) => Ok(()),
            Err(error)
                if error.code()
                    == windows::core::HRESULT::from_win32(ERROR_OPERATION_ABORTED.0) =>
            {
                Ok(())
            }
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_BROKEN_PIPE.0) =>
            {
                Ok(())
            }
            Err(_) => Err(()),
        }
    }
}
impl Drop for WatchChannel {
    fn drop(&mut self) {
        if self.in_flight {
            // Keep kernel-borrowed storage and pipe alive if explicit drain failed.
            let read = std::mem::replace(
                &mut self.read,
                Box::new(UnsafeCell::new(IoStorage {
                    overlapped: OVERLAPPED::default(),
                    bytes: Box::new([]),
                })),
            );
            let event = std::mem::replace(&mut self.read_event, Kernel::invalid());
            let pipe = std::mem::replace(&mut self.pipe, Kernel::invalid());
            std::mem::forget(read);
            std::mem::forget(event);
            std::mem::forget(pipe);
        }
    }
}

struct Peer {
    process: Kernel,
    pid: u32,
    creation: u64,
    expected: PathBuf,
    service: Scm,
    sid: Vec<u8>,
}
impl Peer {
    fn recheck(&self, cleanup: &CleanupLog) -> Result<()> {
        if self.service.verify(&self.expected)? != self.pid
            || super::process_creation(self.process.raw).map_err(|_| ())? != self.creation
        {
            return Err(());
        }
        super::alive(self.process.raw).map_err(|_| ())?;
        security::native64(self.process.raw).map_err(|_| ())?;
        let image: Vec<u16> = self.expected.to_str().ok_or(())?.encode_utf16().collect();
        if !super::image_matches(self.process.raw, &image).map_err(|_| ())? {
            return Err(());
        }
        security::service_identity(self.process.raw, self.pid, 0, &self.sid, cleanup)
            .map_err(|_| ())
    }
}

struct Kernel {
    raw: HANDLE,
    close: CloseLog,
}
impl Kernel {
    fn new(raw: HANDLE, close: &CloseLog) -> Result<Self> {
        if raw.is_invalid() {
            return Err(());
        }
        Ok(Self {
            raw,
            close: Rc::clone(close),
        })
    }

    fn invalid() -> Self {
        Self {
            raw: HANDLE::default(),
            close: Rc::new(Cell::new(false)),
        }
    }
}
impl Drop for Kernel {
    fn drop(&mut self) {
        if self.raw.is_invalid() {
            return;
        }
        // SAFETY: uniquely acquired real kernel handle with all sync borrows
        // ended; not a pseudo handle. No broad Send/Sync implementation exists.
        if unsafe { CloseHandle(self.raw) }.is_err() {
            self.close.set(true);
        }
    }
}
struct ScHandle {
    raw: SC_HANDLE,
    close: CloseLog,
}
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: owned SCM/service handle, never CloseHandle, no outstanding
        // query buffer borrows. Cleanup failure prevents accepted output.
        if unsafe { CloseServiceHandle(self.raw) }.is_err() {
            self.close.set(true);
        }
    }
}
struct Scm {
    service: ScHandle,
    _manager: ScHandle,
}
impl Scm {
    fn open(close: &CloseLog) -> Result<Self> {
        // SAFETY: local fixed SCM database; CONNECT only, no create/write rights.
        let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(|_| ())?;
        let manager = ScHandle {
            raw: manager,
            close: Rc::clone(close),
        };
        let name: Vec<u16> = format!("{SERVICE_NAME}\0").encode_utf16().collect();
        // SAFETY: retained SCM and fixed product service name, read-only rights.
        let service = unsafe {
            OpenServiceW(
                manager.raw,
                PCWSTR(name.as_ptr()),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
            )
        }
        .map_err(|_| ())?;
        Ok(Self {
            service: ScHandle {
                raw: service,
                close: Rc::clone(close),
            },
            _manager: manager,
        })
    }
    fn verify(&self, expected: &std::path::Path) -> Result<u32> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        // SAFETY: initialized exact C-layout status storage; synchronous query
        // writes only within this slice and no reference survives the call.
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast::<u8>(),
                mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )
        };
        // SAFETY: live QUERY_STATUS service, fixed info level and bounded output.
        unsafe {
            QueryServiceStatusEx(
                self.service.raw,
                SC_STATUS_PROCESS_INFO,
                Some(buffer),
                &mut needed,
            )
        }
        .map_err(|_| ())?;
        // pcbBytesNeeded is defined for insufficient-buffer failures, not as a
        // success length. Successful fixed-class output has this exact structure.
        if status.dwCurrentState != SERVICE_RUNNING
            || status.dwServiceType != SERVICE_WIN32_OWN_PROCESS
            || status.dwProcessId == 0
        {
            return Err(());
        }
        let mut words = vec![0usize; 8192 / mem::size_of::<usize>()];
        // SAFETY: aligned initialized bounded buffer for the fixed SCM query;
        // internal pointers remain in this stable allocation and are checked below.
        unsafe {
            QueryServiceConfigW(
                self.service.raw,
                Some(words.as_mut_ptr().cast()),
                8192,
                &mut needed,
            )
        }
        .map_err(|_| ())?;
        // SAFETY: successful bounded fixed query filled the complete header.
        let config =
            unsafe { std::ptr::read_unaligned(words.as_ptr().cast::<QUERY_SERVICE_CONFIGW>()) };
        if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS {
            return Err(());
        }
        let account = config_string(&words, 8192, config.lpServiceStartName)?;
        if !account.eq_ignore_ascii_case("LocalSystem") {
            return Err(());
        }
        let command = config_string(&words, 8192, config.lpBinaryPathName)?;
        if !command.eq_ignore_ascii_case(&format!("\"{}\" service", expected.to_str().ok_or(())?)) {
            return Err(());
        }
        Ok(status.dwProcessId)
    }
}
fn config_string(words: &[usize], length: usize, pointer: PWSTR) -> Result<String> {
    let offset = (pointer.0 as usize)
        .checked_sub(words.as_ptr() as usize)
        .ok_or(())?;
    if offset % 2 != 0 || offset >= length {
        return Err(());
    }
    // SAFETY: immutable initialized allocation; offset/length checked, pointer
    // never dereferenced directly. Terminator and UTF16 validated within bounds.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), length) };
    let units: Vec<u16> = bytes[offset..]
        .chunks_exact(2)
        .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
        .collect();
    let end = units.iter().position(|value| *value == 0).ok_or(())?;
    if end == 0 || end > 2048 {
        return Err(());
    }
    String::from_utf16(&units[..end]).map_err(|_| ())
}
fn expected_service() -> Result<PathBuf> {
    // OS current-image resolver, not argv/current-directory/environment. This is
    // a pairing check to the actual SCM service, not a standalone installation
    // ACL proof. The service supervisor holds protected directory/image pins.
    let own = std::env::current_exe().map_err(|_| ())?;
    if own.file_name().and_then(|value| value.to_str()) != Some(PROBE_EXECUTABLE) {
        return Err(());
    }
    let directory = own.parent().ok_or(())?;
    if directory.file_name().and_then(|value| value.to_str()) != Some(INSTALLATION_FOLDER) {
        return Err(());
    }
    Ok(directory.join(SERVICE_EXECUTABLE))
}
fn service_sid() -> Result<Vec<u8>> {
    let name: Vec<u16> = format!("NT SERVICE\\{SERVICE_NAME}\0")
        .encode_utf16()
        .collect();
    // Exact fixed-service SID capacity: successful lookup need not shrink cbSid.
    let mut words = [0u32; 8];
    let mut size = 32;
    let mut domain = [0u16; 128];
    let mut domain_size = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    // SAFETY: fixed local service account, bounded aligned initialized SID/domain
    // outputs. No remote lookup, caller account or privilege/token mutation.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(words.as_mut_ptr().cast())),
            &mut size,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_size,
            &mut kind,
        )
    }
    .map_err(|_| ())?;
    if size != 32 || domain_size as usize > domain.len() || kind != SidTypeWellKnownGroup {
        return Err(());
    }
    let end = domain.iter().position(|value| *value == 0).ok_or(())?;
    if !String::from_utf16(&domain[..end])
        .map_err(|_| ())?
        .eq_ignore_ascii_case("NT SERVICE")
    {
        return Err(());
    }
    // SAFETY: successful SID query returned exactly32 initialized bytes within
    // this owned aligned array. Validate revision/authority/service prefix.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), 32) };
    if bytes[..12] != [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0] {
        return Err(());
    }
    Ok(bytes.to_vec())
}
