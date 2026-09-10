// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-internal Windows peer boundary, NOT a pairing grant or an IPC codec.
//!
//! Only the actual fixed SCM service can create the two first-instance endpoints.
//! The private I/O child owns bounded connect/read/write and native completion.
//! No impersonation, process launch, key access or enrollment occurs here. The
//! future ceremony owner must bind nonce, service epoch, deadline and consent.
//! A zero-buffer Peek observes broken-pipe errors without consuming payload. Its
//! success and retained PID metadata do not guarantee future connection liveness.
//!
//! Primary-token inspection cannot establish that a remote client THREAD has no
//! impersonation token. The trusted GUI/helper entry must reject its own thread
//! token before connecting. Client SQOS and authentication of our server remain
//! required work. No serialized fields, PID, timestamp or boolean can mint a peer.

use std::{
    fmt, mem,
    path::PathBuf,
    ptr,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, LUID, WAIT_TIMEOUT},
        Security::{
            GetTokenInformation, SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS,
            TOKEN_USER, TokenElevation, TokenElevationType, TokenElevationTypeDefault,
            TokenElevationTypeFull, TokenElevationTypeLimited, TokenGroups, TokenIntegrityLevel,
            TokenIsAppContainer, TokenPrimary, TokenSessionId, TokenStatistics, TokenType,
            TokenUIAccess, TokenUser,
        },
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES,
            PIPE_ACCESS_DUPLEX,
        },
        System::{
            Pipes::{
                CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeClientSessionId,
                NAMED_PIPE_MODE, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_MESSAGE, PeekNamedPipe,
            },
            RemoteDesktop::{
                WTSActive, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW, WTSSessionInfoEx,
            },
            Threading::{
                GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_FORMAT,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
                WaitForSingleObject,
            },
        },
    },
    core::{Error as WinError, PWSTR},
};
use windows_service::service::{Service, ServiceState};

use super::{
    Wide,
    filesystem::{ValidatedPairingInstallation, validate_pairing_installation},
    security::{OwnServiceSid, SecurityDescriptor},
};
use crate::{ServiceError, native};

mod io;
pub use io::{PairingPipe, PairingPipeProgress};

const STARTER_PIPE: &str = r"\\.\pipe\UacRemoteController.PairingStarter.v1";
const HELPER_PIPE: &str = r"\\.\pipe\UacRemoteController.PairingHelper.v1";
const PIPE_BUFFER_BYTES: u32 = 4096;
// Concrete data/EA/attribute read+write, READ_CONTROL and SYNCHRONIZE. Crucially
// not FILE_APPEND_DATA == FILE_CREATE_PIPE_INSTANCE (0x4). Future clients must
// request this concrete subset, NOT GENERIC_WRITE/GENERIC_ALL (which include 4).
const STARTER_ACCESS: u32 = 0x0012_019b;
const MAX_TOKEN_BYTES: usize = 65_536;
const MAX_GROUPS: usize = 128;
const GROUP_ENABLED: u32 = 4;
const GROUP_DENY_ONLY: u32 = 16;
const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const INTERACTIVE: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 4, 0, 0, 0];
const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const MEDIUM_IL: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 16, 0, 32, 0, 0];
const HIGH_IL: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 16, 0, 48, 0, 0];
static RESERVED: AtomicBool = AtomicBool::new(false);
static BOUNDARY_HEALTH: BoundaryHealth = BoundaryHealth::new();

/// Shared across the fixed pair: losing one undrained owner invalidates its
/// surviving sibling too. There is deliberately no reset/recovery constructor.
struct BoundaryHealth(AtomicBool);
impl BoundaryHealth {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    fn quarantine(&self) {
        self.0.store(true, Ordering::Release);
    }
    fn check(&self) -> Result<(), PairingPeerError> {
        if self.0.load(Ordering::Acquire) {
            Err(PairingPeerError::CleanupUnconfirmed)
        } else {
            Ok(())
        }
    }
}

/// A fixed endpoint role, not a caller-provided authority claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingPeerRole {
    Starter,
    Helper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingPeerStage {
    CreateEndpoint,
    CreateEvent,
    Connect,
    Read,
    Write,
    PollIo,
    CancelIo,
    QueryPeer,
    QueryProcess,
    QueryToken,
    QuerySession,
}

/// Fixed categories/numeric codes only; native error strings and identity data
/// are deliberately absent from Debug/Display.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairingPeerError {
    #[error("pairing peer boundary is already owned")]
    Busy,
    #[error("pairing peer boundary is closed")]
    Closed,
    #[error("pairing pipe operation is invalid in this phase")]
    InvalidPhase,
    #[error("pairing pipe message is empty, oversized or incomplete")]
    InvalidMessage,
    #[error("pairing pipe original deadline is invalid")]
    InvalidDeadline,
    #[error("pairing pipe original deadline elapsed")]
    DeadlineElapsed,
    #[error("pairing pipe was cancelled")]
    Cancelled,
    #[error("pairing pipe reached end of stream")]
    EndOfStream,
    #[error("pairing peer policy rejected the native observation")]
    Rejected,
    #[error("pairing peer native metadata is malformed or unsupported")]
    Malformed,
    #[error("pairing peer handle cleanup is unconfirmed")]
    CleanupUnconfirmed,
    #[error("pairing peer service context rejected: {0}")]
    Service(ServiceError),
    #[error("pairing peer Windows call failed at {stage:?} ({hresult:#010x})")]
    Native {
        stage: PairingPeerStage,
        hresult: i32,
    },
}

fn native_error(stage: PairingPeerStage, error: WinError) -> PairingPeerError {
    PairingPeerError::Native {
        stage,
        hresult: error.code().0,
    }
}
fn cleanup_state() -> Result<(), PairingPeerError> {
    BOUNDARY_HEALTH.check()
}

struct Handle(Option<HANDLE>);
impl Handle {
    fn new(value: HANDLE, stage: PairingPeerStage) -> Result<Self, PairingPeerError> {
        if value.is_invalid() {
            return Err(native_error(stage, WinError::from_thread()));
        }
        Ok(Self(Some(value)))
    }
    fn raw(&self) -> HANDLE {
        self.0.unwrap_or_default()
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            // SAFETY: unique successful real handle. The I/O child retains the
            // whole owner instead of reaching this Drop while I/O is pending.
            if unsafe { CloseHandle(value) }.is_err() {
                // No retry/double-close or new owner can conceal uncertain release.
                BOUNDARY_HEALTH.quarantine();
            }
        }
    }
}
struct Reservation;
impl Reservation {
    fn acquire() -> Result<Self, PairingPeerError> {
        cleanup_state()?;
        RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PairingPeerError::Busy)?;
        Ok(Self)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        RESERVED.store(false, Ordering::Release);
    }
}

struct ServiceContext {
    service: Service,
    installation: ValidatedPairingInstallation,
    _reservation: Reservation,
}
impl ServiceContext {
    fn observe() -> Result<Rc<Self>, PairingPeerError> {
        let reservation = Reservation::acquire()?;
        windows_identity::verify_service_context()
            .map_err(|e| PairingPeerError::Service(ServiceError::from_identity(e)))?;
        let installation = validate_pairing_installation().map_err(PairingPeerError::Service)?;
        let service = native::running_service_for_probe(installation.service())
            .map_err(PairingPeerError::Service)?;
        let context = Rc::new(Self {
            service,
            installation,
            _reservation: reservation,
        });
        context.recheck()?;
        Ok(context)
    }
    fn recheck(&self) -> Result<(), PairingPeerError> {
        cleanup_state()?;
        windows_identity::verify_service_context()
            .map_err(|e| PairingPeerError::Service(ServiceError::from_identity(e)))?;
        // Retain the original SCM object AND recheck the fixed current service
        // registration. A replacement/name collision cannot stand in for either.
        let status = self
            .service
            .query_status()
            .map_err(|_| PairingPeerError::Rejected)?;
        if status.current_state != ServiceState::Running
            || status.process_id != Some(std::process::id())
        {
            return Err(PairingPeerError::Rejected);
        }
        let _current = native::running_service_for_probe(self.installation.service())
            .map_err(PairingPeerError::Service)?;
        self.installation
            .check_service_image(self.installation.service())
            .map_err(PairingPeerError::Service)?;
        cleanup_state()
    }
}

/// At most two fixed first-instance servers, confined to their service thread
/// by Rc ownership. Creation does not connect or authenticate any caller.
pub struct PairingServerEndpoints {
    starter: PairingServerEndpoint,
    helper: PairingServerEndpoint,
}
impl PairingServerEndpoints {
    pub fn create_for_running_service() -> Result<Self, PairingPeerError> {
        let context = ServiceContext::observe()?;
        let sid = OwnServiceSid::lookup()
            .map_err(PairingPeerError::Service)?
            .bytes();
        let starter = create_server(PairingPeerRole::Starter, &sid, Rc::clone(&context))?;
        let helper = create_server(PairingPeerRole::Helper, &sid, Rc::clone(&context))?;
        context.recheck()?;
        Ok(Self { starter, helper })
    }
    /// Tuple order is fixed: starter, then helper. No endpoint can change roles.
    pub fn into_servers(self) -> (PairingServerEndpoint, PairingServerEndpoint) {
        (self.starter, self.helper)
    }
    pub fn close(self) -> Result<(), PairingPeerError> {
        drop(self);
        cleanup_state()
    }
}

/// Private native I/O operates only on this exact owned server.
/// No public raw-handle import/export, disconnect or reconnect operation exists.
pub struct PairingServerEndpoint {
    pipe: Handle,
    role: PairingPeerRole,
    context: Rc<ServiceContext>,
}
impl PairingServerEndpoint {
    pub fn role(&self) -> PairingPeerRole {
        self.role
    }

    /// Consumes the sole original server after connection completion. An
    /// unconnected/failed observation destroys it instead of recycling a client.
    /// No caller-supplied PID/session/token participates in this operation.
    pub fn authenticate_connected(self) -> Result<PairingPeer, PairingPeerError> {
        self.context.recheck()?;
        let (pid, session) = pipe_identity(self.pipe.raw())?;
        // SAFETY: OS-observed PID only; query/synchronize rights, not injection,
        // termination, duplication or token modification. Handle is retained.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|e| native_error(PairingPeerStage::QueryProcess, e))?;
        let process = Handle::new(process, PairingPeerStage::QueryProcess)?;
        let created = process_identity(process.raw(), pid)?;
        check_image(&self, process.raw())?;
        let token = TokenFacts::observe(process.raw())?;
        token.require(self.role, session)?;
        let interactive = SessionEpoch::observe(session)?;
        let mut peer = PairingPeer {
            process,
            endpoint: self,
            pid,
            created,
            token,
            interactive,
            live: true,
        };
        // Reobserve the same process and pipe before publication. This rejects
        // observed changes; it is not an atomic lease on the client's future use.
        peer.recheck()?;
        Ok(peer)
    }
    pub fn close(self) -> Result<(), PairingPeerError> {
        drop(self);
        cleanup_state()
    }
}

/// Original pipe + process + installation/service pins, never serializable or
/// clonable. Creation time detects PID reuse; it does NOT attest fresh UAC consent.
pub struct PairingPeer {
    process: Handle,
    endpoint: PairingServerEndpoint,
    pid: u32,
    created: u64,
    token: TokenFacts,
    interactive: SessionEpoch,
    live: bool,
}
impl PairingPeer {
    pub fn role(&self) -> PairingPeerRole {
        self.endpoint.role
    }
    /// Informational original session. Call recheck at each protocol transition;
    /// this scalar is neither a grant nor a replacement for the owned connection.
    pub fn session_id(&self) -> u32 {
        self.interactive.id
    }
    pub fn recheck(&mut self) -> Result<(), PairingPeerError> {
        if !self.live {
            return Err(PairingPeerError::Closed);
        }
        let result = self.check_original();
        if result.is_err() {
            self.live = false;
        }
        result
    }
    fn check_original(&self) -> Result<(), PairingPeerError> {
        self.endpoint.context.recheck()?;
        let expected = (self.pid, self.interactive.id);
        if pipe_identity(self.endpoint.pipe.raw())? != expected
            || process_identity(self.process.raw(), self.pid)? != self.created
        {
            return Err(PairingPeerError::Rejected);
        }
        check_image(&self.endpoint, self.process.raw())?;
        let token = TokenFacts::observe(self.process.raw())?;
        token.require(self.role(), self.interactive.id)?;
        if token != self.token || SessionEpoch::observe(self.interactive.id)? != self.interactive {
            return Err(PairingPeerError::Rejected);
        }
        if pipe_identity(self.endpoint.pipe.raw())? != expected
            || process_identity(self.process.raw(), self.pid)? != self.created
        {
            return Err(PairingPeerError::Rejected);
        }
        self.endpoint.context.recheck()
    }
    pub fn close(self) -> Result<(), PairingPeerError> {
        drop(self);
        cleanup_state()
    }
}

macro_rules! redacted_debug {
    ($($kind:ty),+ $(,)?) => { $(impl fmt::Debug for $kind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($kind), "(redacted)"))
        }
    })+ };
}
redacted_debug!(PairingServerEndpoints, PairingServerEndpoint, PairingPeer);

fn pipe_modes() -> (FILE_FLAGS_AND_ATTRIBUTES, NAMED_PIPE_MODE) {
    (
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
    )
}
fn pipe_sddl(role: PairingPeerRole, service_sid: &[u8]) -> Result<String, PairingPeerError> {
    // Fixed NT SERVICE SID: revision 1, authority 5, 80 + five hash subauthorities.
    if service_sid.len() != 32 || service_sid[..12] != [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0] {
        return Err(PairingPeerError::Malformed);
    }
    let mut sid = String::from("S-1-5-80");
    for bytes in service_sid[12..].chunks_exact(4) {
        let number = u32::from_le_bytes(bytes.try_into().map_err(|_| PairingPeerError::Malformed)?);
        sid.push_str(&format!("-{number}"));
    }
    let mut descriptor = format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})");
    if role == PairingPeerRole::Starter {
        descriptor.push_str(&format!("(A;;0x{STARTER_ACCESS:08x};;;AU)"));
    }
    // These NEW objects have explicit role-level mandatory labels. This avoids
    // inheriting the SYSTEM creator's label, while refusing writes below the
    // intended role. It changes no process token or existing object's security.
    descriptor.push_str(match role {
        PairingPeerRole::Starter => "S:(ML;;NW;;;ME)",
        PairingPeerRole::Helper => "S:(ML;;NW;;;HI)",
    });
    Ok(descriptor)
}
fn create_server(
    role: PairingPeerRole,
    sid: &[u8],
    context: Rc<ServiceContext>,
) -> Result<PairingServerEndpoint, PairingPeerError> {
    context.recheck()?;
    let name = Wide::new(match role {
        PairingPeerRole::Starter => STARTER_PIPE,
        PairingPeerRole::Helper => HELPER_PIPE,
    })
    .map_err(PairingPeerError::Service)?;
    let descriptor =
        SecurityDescriptor::from_sddl(&pipe_sddl(role, sid)?).map_err(PairingPeerError::Service)?;
    let security = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.ptr().0,
        bInheritHandle: false.into(),
    };
    let (open, mode) = pipe_modes();
    // SAFETY: fixed local names, bounded buffers, first instance only, no remote
    // clients/inheritance. Private DACL exists AT creation, not patched afterward.
    let pipe = unsafe {
        CreateNamedPipeW(
            name.ptr(),
            open,
            mode,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(ptr::from_ref(&security)),
        )
    };
    let pipe = Handle::new(pipe, PairingPeerStage::CreateEndpoint)?;
    context.recheck()?;
    Ok(PairingServerEndpoint {
        pipe,
        role,
        context,
    })
}
fn pipe_identity(pipe: HANDLE) -> Result<(u32, u32), PairingPeerError> {
    let mut pid = 0;
    let mut session = 0;
    observe_pipe_open(pipe)?;
    // SAFETY: our retained CreateNamedPipe server, exclusive initialized scalars.
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .map_err(|e| native_error(PairingPeerStage::QueryPeer, e))?;
    // SAFETY: same original server, no caller-provided peer metadata.
    unsafe { GetNamedPipeClientSessionId(pipe, &mut session) }
        .map_err(|e| native_error(PairingPeerStage::QueryPeer, e))?;
    if pid == 0 || session == 0 || session == u32::MAX {
        return Err(PairingPeerError::Rejected);
    }
    observe_pipe_open(pipe)?;
    Ok((pid, session))
}
fn observe_pipe_open(pipe: HANDLE) -> Result<(), PairingPeerError> {
    // SAFETY: our fixed DUPLEX|OVERLAPPED server, no buffer and no payload copy or
    // consumption. OVERLAPPED avoids the documented synchronous-handle blocking
    // condition. A successful observation is not a lease on the client's handle;
    // the eventual I/O owner must still detect EOF and fence every transition.
    unsafe { PeekNamedPipe(pipe, None, 0, None, None, None) }
        .map_err(|e| native_error(PairingPeerStage::QueryPeer, e))
}
fn process_identity(process: HANDLE, expected_pid: u32) -> Result<u64, PairingPeerError> {
    // SAFETY: retained process, synchronize/query rights; zero-time nonblocking wait.
    if unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT
        || unsafe { GetProcessId(process) } != expected_pid
    {
        return Err(PairingPeerError::Rejected);
    }
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: same live handle and initialized disjoint fixed-size outputs.
    unsafe { GetProcessTimes(process, &mut created, &mut exit, &mut kernel, &mut user) }
        .map_err(|e| native_error(PairingPeerStage::QueryProcess, e))?;
    let created = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if created == 0 {
        return Err(PairingPeerError::Malformed);
    }
    Ok(created)
}
fn check_image(endpoint: &PairingServerEndpoint, process: HANDLE) -> Result<(), PairingPeerError> {
    let mut buffer = [0u16; 1024];
    let mut length = buffer.len() as u32;
    // SAFETY: retained process, DOS-name mode, initialized bounded output only.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|e| native_error(PairingPeerStage::QueryProcess, e))?;
    let units = buffer
        .get(..length as usize)
        .filter(|v| !v.is_empty() && !v.contains(&0))
        .ok_or(PairingPeerError::Malformed)?;
    let image = PathBuf::from(String::from_utf16(units).map_err(|_| PairingPeerError::Malformed)?);
    match endpoint.role {
        PairingPeerRole::Starter => endpoint.context.installation.check_controller_image(&image),
        PairingPeerRole::Helper => endpoint.context.installation.check_service_image(&image),
    }
    .map_err(PairingPeerError::Service)
}

#[derive(Eq, PartialEq)]
struct SessionEpoch {
    id: u32,
    logon: i64,
    connected: i64,
}
impl SessionEpoch {
    fn observe(id: u32) -> Result<Self, PairingPeerError> {
        if id == 0 || id == u32::MAX {
            return Err(PairingPeerError::Rejected);
        }
        let mut buffer = PWSTR::null();
        let mut bytes = 0;
        // SAFETY: local WTS only, observed session, fixed class; owns returned allocation.
        unsafe { WTSQuerySessionInformationW(None, id, WTSSessionInfoEx, &mut buffer, &mut bytes) }
            .map_err(|e| native_error(PairingPeerStage::QuerySession, e))?;
        struct Allocation(PWSTR);
        impl Drop for Allocation {
            fn drop(&mut self) {
                // SAFETY: exact successful WTS allocation, once, after all reads.
                unsafe { WTSFreeMemory(self.0.0.cast()) };
            }
        }
        if buffer.is_null() {
            return Err(PairingPeerError::Malformed);
        }
        let allocation = Allocation(buffer);
        if bytes as usize != mem::size_of::<WTSINFOEXW>() {
            return Err(PairingPeerError::Malformed);
        }
        // SAFETY: fixed-size WTS class output checked before read; no pointer fields.
        let info = unsafe { ptr::read_unaligned(allocation.0.0.cast::<WTSINFOEXW>()) };
        if info.Level != 1 {
            return Err(PairingPeerError::Malformed);
        }
        // SAFETY: validated Level 1 selects this documented union variant.
        let row = unsafe { info.Data.WTSInfoExLevel1 };
        if row.SessionId != id
            || row.SessionState != WTSActive
            || row.LogonTime <= 0
            || row.ConnectTime <= 0
        {
            return Err(PairingPeerError::Rejected);
        }
        Ok(Self {
            id,
            logon: row.LogonTime,
            connected: row.ConnectTime,
        })
    }
}

struct TokenBuffer {
    words: Vec<usize>,
    length: usize,
}
impl TokenBuffer {
    fn read(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Self, PairingPeerError> {
        // Only these variable-sized outputs use the bounded allocation. Fixed
        // scalar/statistics classes have exact-size initialized ABI storage below.
        if ![TokenUser, TokenIntegrityLevel, TokenGroups].contains(&class) {
            return Err(PairingPeerError::Malformed);
        }
        let mut value = Self {
            words: vec![0; MAX_TOKEN_BYTES / mem::size_of::<usize>()],
            length: 0,
        };
        let mut length = 0;
        // SAFETY: query-only token, fixed classes, initialized aligned bounded
        // storage; embedded pointers stay within this allocation and never escape.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(value.words.as_mut_ptr().cast()),
                MAX_TOKEN_BYTES as u32,
                &mut length,
            )
        }
        .map_err(|e| native_error(PairingPeerStage::QueryToken, e))?;
        if length == 0 || length as usize > MAX_TOKEN_BYTES {
            return Err(PairingPeerError::Malformed);
        }
        value.length = length as usize;
        Ok(value)
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: immutable initialized storage, bounded by actual native length.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
    fn sid(&self, pointer: *mut std::ffi::c_void) -> Result<Vec<u8>, PairingPeerError> {
        let offset = (pointer as usize)
            .checked_sub(self.words.as_ptr() as usize)
            .ok_or(PairingPeerError::Malformed)?;
        bounded_sid(self.bytes(), offset)
    }
}
fn token_scalar(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<u32, PairingPeerError> {
    if ![
        TokenType,
        TokenSessionId,
        TokenElevation,
        TokenElevationType,
        TokenIsAppContainer,
        TokenUIAccess,
    ]
    .contains(&class)
    {
        return Err(PairingPeerError::Malformed);
    }
    let mut value = 0u32;
    let mut returned = 0;
    // SAFETY: query-only retained token, strict fixed-DWORD class allowlist,
    // exact initialized/aligned four-byte output and a disjoint length output.
    // No NULL-size probe or oversized variable-buffer ABI assumption is used.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(ptr::from_mut(&mut value).cast()),
            mem::size_of::<u32>() as u32,
            &mut returned,
        )
    }
    .map_err(|error| native_error(PairingPeerStage::QueryToken, error))?;
    if returned as usize != mem::size_of::<u32>() {
        return Err(PairingPeerError::Malformed);
    }
    Ok(value)
}
fn token_statistics(token: HANDLE) -> Result<TOKEN_STATISTICS, PairingPeerError> {
    let mut value = TOKEN_STATISTICS::default();
    let mut returned = 0;
    // SAFETY: one fixed information class with its exact initialized C-layout
    // output. The successful returned extent and primary type are checked before
    // any statistics participate in retained token identity.
    unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            Some(ptr::from_mut(&mut value).cast()),
            mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    }
    .map_err(|error| native_error(PairingPeerStage::QueryToken, error))?;
    if returned as usize != mem::size_of::<TOKEN_STATISTICS>() {
        return Err(PairingPeerError::Malformed);
    }
    if value.TokenType != TokenPrimary {
        return Err(PairingPeerError::Rejected);
    }
    Ok(value)
}
fn bounded_sid(bytes: &[u8], offset: usize) -> Result<Vec<u8>, PairingPeerError> {
    let sid = bytes.get(offset..).ok_or(PairingPeerError::Malformed)?;
    if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 {
        return Err(PairingPeerError::Malformed);
    }
    Ok(sid
        .get(..8 + usize::from(sid[1]) * 4)
        .ok_or(PairingPeerError::Malformed)?
        .to_vec())
}
fn token_groups(token: HANDLE) -> Result<Vec<(Vec<u8>, u32)>, PairingPeerError> {
    let buffer = TokenBuffer::read(token, TokenGroups)?;
    let count = u32::from_ne_bytes(
        buffer
            .bytes()
            .get(..4)
            .ok_or(PairingPeerError::Malformed)?
            .try_into()
            .map_err(|_| PairingPeerError::Malformed)?,
    ) as usize;
    if count > MAX_GROUPS {
        return Err(PairingPeerError::Malformed);
    }
    let start = mem::offset_of!(TOKEN_GROUPS, Groups);
    let size = mem::size_of::<SID_AND_ATTRIBUTES>();
    let rows = buffer
        .bytes()
        .get(start..start + count * size)
        .ok_or(PairingPeerError::Malformed)?;
    let mut groups = Vec::with_capacity(count);
    for row in rows.chunks_exact(size) {
        // SAFETY: exact bounded initialized row; SID pointer separately bounded.
        let entry = unsafe { ptr::read_unaligned(row.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
        groups.push((buffer.sid(entry.Sid.0)?, entry.Attributes));
    }
    groups.sort();
    Ok(groups)
}
fn enabled(groups: &[(Vec<u8>, u32)], expected: &[u8]) -> bool {
    groups.iter().any(|(sid, flags)| {
        sid == expected && flags & GROUP_ENABLED != 0 && flags & GROUP_DENY_ONLY == 0
    })
}
fn luid(value: LUID) -> u64 {
    (u64::from(value.HighPart as u32) << 32) | u64::from(value.LowPart)
}

#[derive(Eq, PartialEq)]
struct TokenFacts {
    user: Vec<u8>,
    integrity: Vec<u8>,
    groups: Vec<(Vec<u8>, u32)>,
    token_id: u64,
    logon_id: u64,
    session: u32,
    elevation: u32,
    elevation_type: u32,
    app_container: u32,
    ui_access: u32,
}
impl TokenFacts {
    fn observe(process: HANDLE) -> Result<Self, PairingPeerError> {
        let mut token = HANDLE::default();
        // SAFETY: exact retained client process; query primary token, never
        // impersonate/duplicate it or acquire adjustment rights.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|e| native_error(PairingPeerStage::QueryToken, e))?;
        let token = Handle::new(token, PairingPeerStage::QueryToken)?;
        if token_scalar(token.raw(), TokenType)? != TokenPrimary.0 as u32 {
            return Err(PairingPeerError::Rejected);
        }
        let user = TokenBuffer::read(token.raw(), TokenUser)?;
        let integrity = TokenBuffer::read(token.raw(), TokenIntegrityLevel)?;
        let native_stats = token_statistics(token.raw())?;
        if user.length < mem::size_of::<TOKEN_USER>()
            || integrity.length < mem::size_of::<TOKEN_MANDATORY_LABEL>()
        {
            return Err(PairingPeerError::Malformed);
        }
        // SAFETY: fixed C-layout prefixes bounded above; every embedded SID is
        // range-checked against its OWN live allocation before dereference/copy.
        let native_user =
            unsafe { ptr::read_unaligned(user.bytes().as_ptr().cast::<TOKEN_USER>()) };
        // SAFETY: same bounded prefix invariant for the label's own allocation.
        let native_integrity = unsafe {
            ptr::read_unaligned(integrity.bytes().as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
        };
        Ok(Self {
            user: user.sid(native_user.User.Sid.0)?,
            integrity: integrity.sid(native_integrity.Label.Sid.0)?,
            groups: token_groups(token.raw())?,
            token_id: luid(native_stats.TokenId),
            logon_id: luid(native_stats.AuthenticationId),
            session: token_scalar(token.raw(), TokenSessionId)?,
            elevation: token_scalar(token.raw(), TokenElevation)?,
            elevation_type: token_scalar(token.raw(), TokenElevationType)?,
            app_container: token_scalar(token.raw(), TokenIsAppContainer)?,
            ui_access: token_scalar(token.raw(), TokenUIAccess)?,
        })
    }
    fn require(&self, role: PairingPeerRole, pipe_session: u32) -> Result<(), PairingPeerError> {
        if self.session == 0
            || self.session == u32::MAX
            || self.session != pipe_session
            || self.user == SYSTEM
            || self.app_container != 0
            || self.ui_access != 0
            || self.token_id == 0
            || self.logon_id == 0
            || !enabled(&self.groups, INTERACTIVE)
        {
            return Err(PairingPeerError::Rejected);
        }
        let accepted = match role {
            PairingPeerRole::Starter => {
                self.integrity == MEDIUM_IL
                    && self.elevation == 0
                    && (self.elevation_type == TokenElevationTypeDefault.0 as u32
                        || self.elevation_type == TokenElevationTypeLimited.0 as u32)
                    && !enabled(&self.groups, ADMINISTRATORS)
            }
            // Full split token only. Neither Full nor High proves recent consent;
            // the protected ceremony still needs its bound live helper channel.
            PairingPeerRole::Helper => {
                self.integrity == HIGH_IL
                    && self.elevation == 1
                    && self.elevation_type == TokenElevationTypeFull.0 as u32
                    && enabled(&self.groups, ADMINISTRATORS)
            }
        };
        if accepted {
            Ok(())
        } else {
            Err(PairingPeerError::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_READ_DATA, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    };

    #[test]
    fn ordinary_test_executable_cannot_create_service_pairing_endpoints() {
        // Real read-only Windows admission, not synthetic token metadata. This
        // test executable is not the fixed installed SCM service. Admission must
        // fail before either pipe is created; no elevation or SCM mutation is
        // requested. Successful creation here would be a boundary regression.
        assert!(matches!(
            PairingServerEndpoints::create_for_running_service(),
            Err(PairingPeerError::Service(_))
        ));
    }

    #[test]
    fn current_process_primary_token_uses_actual_exact_fixed_query_abi() {
        // Real Windows read-only query of this ordinary CI process, never a role
        // grant. The borrowed pseudo-process handle is NEVER owned or closed;
        // observe owns and closes only its normally opened TOKEN_QUERY handle.
        // SAFETY: borrowing the documented current-process pseudo-handle only.
        let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
        let observed = TokenFacts::observe(process).unwrap();
        // observe required actual TokenPrimary from both exact native queries.
        // No Administrator, session number, username, SID or integrity assumption.
        assert!(observed.elevation <= 1);
        assert!(observed.app_container <= 1);
        assert!(observed.ui_access <= 1);
        assert!(
            [
                TokenElevationTypeDefault.0 as u32,
                TokenElevationTypeFull.0 as u32,
                TokenElevationTypeLimited.0 as u32,
            ]
            .contains(&observed.elevation_type)
        );
    }

    #[test]
    fn token_query_shapes_cannot_cross_fixed_and_variable_allowlists() {
        // Unsupported classes are rejected BEFORE any native call; the null
        // sentinel is not a native token fixture and is never adopted/closed.
        for class in [TokenUser, TokenIntegrityLevel, TokenGroups, TokenStatistics] {
            assert_eq!(
                token_scalar(HANDLE::default(), class),
                Err(PairingPeerError::Malformed)
            );
        }
        for class in [
            TokenType,
            TokenSessionId,
            TokenElevation,
            TokenElevationType,
            TokenIsAppContainer,
            TokenUIAccess,
            TokenStatistics,
        ] {
            assert!(matches!(
                TokenBuffer::read(HANDLE::default(), class),
                Err(PairingPeerError::Malformed)
            ));
        }
    }

    #[test]
    fn uncertain_cleanup_blocks_sibling_checks_without_poisoning_test_process() {
        // Local pure fixture only: never poison production-global admission or
        // call native creation. Both observers refer to one shared pair health.
        let health = BoundaryHealth::new();
        let first = &health;
        let sibling = &health;
        assert_eq!(first.check(), Ok(()));
        assert_eq!(sibling.check(), Ok(()));
        first.quarantine();
        assert_eq!(sibling.check(), Err(PairingPeerError::CleanupUnconfirmed));
        first.quarantine();
        assert_eq!(first.check(), Err(PairingPeerError::CleanupUnconfirmed));
        assert_eq!(sibling.check(), Err(PairingPeerError::CleanupUnconfirmed));
    }

    fn facts(role: PairingPeerRole) -> TokenFacts {
        let mut groups = vec![(INTERACTIVE.to_vec(), GROUP_ENABLED)];
        if role == PairingPeerRole::Helper {
            groups.push((ADMINISTRATORS.to_vec(), GROUP_ENABLED));
        }
        TokenFacts {
            user: vec![1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0],
            integrity: if role == PairingPeerRole::Starter {
                MEDIUM_IL.to_vec()
            } else {
                HIGH_IL.to_vec()
            },
            groups,
            token_id: 7,
            logon_id: 9,
            session: 2,
            elevation: u32::from(role == PairingPeerRole::Helper),
            elevation_type: if role == PairingPeerRole::Starter {
                TokenElevationTypeLimited.0 as u32
            } else {
                TokenElevationTypeFull.0 as u32
            },
            app_container: 0,
            ui_access: 0,
        }
    }
    #[test]
    fn fixed_local_pipe_modes_and_non_generic_starter_rights() {
        let (open, mode) = pipe_modes();
        assert_eq!(
            open,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE
        );
        assert_eq!(
            mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS
        );
        assert_eq!(PIPE_BUFFER_BYTES, 4096);
        assert_ne!(STARTER_PIPE, HELPER_PIPE);
        assert!(STARTER_PIPE.starts_with(r"\\.\pipe\"));
        assert!(HELPER_PIPE.starts_with(r"\\.\pipe\"));
        assert_eq!(
            STARTER_ACCESS & (FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | DELETE).0,
            0
        );
        assert_eq!(STARTER_ACCESS & 0xf000_0000, 0);
        assert_eq!(STARTER_ACCESS & (FILE_READ_DATA | FILE_WRITE_DATA).0, 3);
    }
    #[test]
    fn only_starter_dacl_admits_authenticated_users() {
        let mut sid = vec![1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0];
        sid.extend_from_slice(&[0; 20]);
        let starter = pipe_sddl(PairingPeerRole::Starter, &sid).unwrap();
        let helper = pipe_sddl(PairingPeerRole::Helper, &sid).unwrap();
        assert_eq!(
            starter,
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-80-0-0-0-0-0)(A;;0x0012019b;;;AU)S:(ML;;NW;;;ME)"
        );
        assert_eq!(
            helper,
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-80-0-0-0-0-0)S:(ML;;NW;;;HI)"
        );
        for text in [starter, helper] {
            assert!(text.starts_with("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"));
            assert!(text.contains("(A;;GA;;;S-1-5-80-0-0-0-0-0)"));
        }
        sid[1] = 5;
        assert!(pipe_sddl(PairingPeerRole::Helper, &sid).is_err());
    }
    #[test]
    fn role_token_policies_are_disjoint() {
        let starter = facts(PairingPeerRole::Starter);
        let helper = facts(PairingPeerRole::Helper);
        assert!(starter.require(PairingPeerRole::Starter, 2).is_ok());
        assert!(helper.require(PairingPeerRole::Helper, 2).is_ok());
        assert!(starter.require(PairingPeerRole::Helper, 2).is_err());
        assert!(helper.require(PairingPeerRole::Starter, 2).is_err());
    }
    #[test]
    fn helper_requires_full_and_enabled_non_deny_only_administrator() {
        for elevation_type in [
            TokenElevationTypeDefault.0,
            TokenElevationTypeLimited.0,
            0,
            4,
        ] {
            let mut value = facts(PairingPeerRole::Helper);
            value.elevation_type = elevation_type as u32;
            assert!(value.require(PairingPeerRole::Helper, 2).is_err());
        }
        let mut value = facts(PairingPeerRole::Helper);
        value.groups[1].1 = GROUP_ENABLED | GROUP_DENY_ONLY;
        assert!(value.require(PairingPeerRole::Helper, 2).is_err());
    }
    #[test]
    fn both_roles_reject_system_container_uiaccess_session_and_interactive_changes() {
        for role in [PairingPeerRole::Starter, PairingPeerRole::Helper] {
            for mutation in 0..7 {
                let mut value = facts(role);
                match mutation {
                    0 => value.user = SYSTEM.to_vec(),
                    1 => value.app_container = 1,
                    2 => value.ui_access = 1,
                    3 => value.session = 0,
                    4 => value.session = 3,
                    5 => value.groups[0].1 = GROUP_DENY_ONLY,
                    _ => value.integrity = vec![1, 1, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0],
                }
                assert!(value.require(role, 2).is_err());
            }
        }
    }
    #[test]
    fn bounded_sid_rejects_offsets_headers_and_extent_before_pointer_use() {
        assert_eq!(bounded_sid(SYSTEM, 0).unwrap(), SYSTEM);
        assert!(bounded_sid(SYSTEM, usize::MAX).is_err());
        // Offset 1 happens to start another structurally valid revision/count
        // header (revision 1, count 0); it is not a malformed-header fixture.
        // Offset 2 starts with revision 0 and must reject. Native pointer/role
        // provenance is checked separately from this bounded byte parser.
        assert!(bounded_sid(SYSTEM, 2).is_err());
        let mut prefixed = vec![0; 4];
        prefixed.extend_from_slice(SYSTEM);
        assert_eq!(bounded_sid(&prefixed, 4).unwrap(), SYSTEM);
        assert!(bounded_sid(&SYSTEM[..11], 0).is_err());
        let mut invalid = SYSTEM.to_vec();
        invalid[1] = 16;
        assert!(bounded_sid(&invalid, 0).is_err());
        invalid[0] = 2;
        invalid[1] = 1;
        assert!(bounded_sid(&invalid, 0).is_err());
    }
    #[test]
    fn retained_token_and_session_epoch_identity_detect_replacement() {
        let first = facts(PairingPeerRole::Helper);
        let mut replacement = facts(PairingPeerRole::Helper);
        replacement.token_id += 1;
        assert!(first != replacement);
        replacement = facts(PairingPeerRole::Helper);
        replacement.logon_id += 1;
        assert!(first != replacement);
        assert!(
            SessionEpoch {
                id: 2,
                logon: 8,
                connected: 9
            } != SessionEpoch {
                id: 2,
                logon: 8,
                connected: 10
            }
        );
    }
}
