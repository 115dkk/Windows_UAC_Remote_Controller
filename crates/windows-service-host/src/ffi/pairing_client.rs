// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed local pairing CLIENT boundary only. No UAC launch, caller-nominated
//! path/PID/HANDLE, codec, pairing grant, enrollment, registry or signing API.
//! Every positive operation authenticates the retained SCM/process/pipe and
//! the actual own primary token/thread. Kernel pipe owner/DACL comes from its
//! READ_CONTROL handle; no SYSTEM token or SCM READ_CONTROL query is attempted.

use std::{
    fmt,
    marker::PhantomData,
    mem,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_OPERATION_ABORTED, GENERIC_ALL, HANDLE, HLOCAL, LocalFree,
        },
        Security::{
            ACL_REVISION, ACL_REVISION_DS,
            Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT},
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
            IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR_RELATIVE,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_MODE, FILE_TYPE_PIPE,
            FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, GetFileType, OPEN_EXISTING,
            READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
        },
        System::{
            Pipes::{
                GetNamedPipeServerProcessId, GetNamedPipeServerSessionId, PIPE_READMODE_MESSAGE,
                PeekNamedPipe, SetNamedPipeHandleState,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{
                CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
            },
        },
    },
    core::{Error as WinError, HRESULT, PCWSTR, PWSTR},
};
use windows_service::service::Service;

use super::{
    Wide,
    filesystem::{ValidatedPairingInstallation, validate_pairing_client_installation},
    overlapped_pipe::{BufferLimits, Completed, EventHandle, IoError, Kind, PendingOperation},
    pairing_peer::{
        self, PairingPeerError, PairingPeerRole, SessionEpoch, TokenFacts, process_identity,
    },
    security::{OwnServiceSid, reject_thread_impersonation},
};
use crate::{ServiceError, native};

mod helper_launch;
mod renderer;
pub(crate) use helper_launch::run_pair_helper;
pub use helper_launch::{PairingHelperLaunch, PairingLaunchError, PairingLaunchProgress};
pub(crate) use renderer::run_pair_renderer;

const MAX_MESSAGE: usize = 4096;
const READ_CAPACITY: usize = MAX_MESSAGE + 1;
const MAX_DESCRIPTOR: usize = 65_536;
const MAX_LIFETIME: Duration = Duration::from_secs(5 * 60);
const LIMITS: BufferLimits = BufferLimits {
    max_read: READ_CAPACITY,
    max_write: MAX_MESSAGE,
};
const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
const AUTHENTICATED_USERS: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
static RESERVED: AtomicBool = AtomicBool::new(false);
static UNHEALTHY: AtomicBool = AtomicBool::new(false);
#[derive(Clone, Copy)]
enum ClientEndpoint {
    Starter,
    Helper,
    Renderer,
}
impl ClientEndpoint {
    fn role(self) -> PairingPeerRole {
        match self {
            Self::Starter => PairingPeerRole::Starter,
            _ => PairingPeerRole::Helper,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Starter => pairing_peer::STARTER_PIPE,
            Self::Helper => pairing_peer::HELPER_PIPE,
            Self::Renderer => pairing_peer::RENDERER_PIPE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingClientStage {
    Connect,
    CreateEvent,
    QueryPipe,
    ReadPipeSecurity,
    QueryOwnIdentity,
    QueryServer,
    Read,
    Write,
    PollIo,
    CancelIo,
}

/// Fixed categories only; no endpoint, identity, SID, path or payload is rendered.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairingClientError {
    #[error("the pairing client boundary is already owned")]
    Busy,
    #[error("the pairing client boundary is closed")]
    Closed,
    #[error("the pairing client operation is invalid in this phase")]
    InvalidPhase,
    #[error("the pairing client message is empty, oversized or incomplete")]
    InvalidMessage,
    #[error("the pairing client original deadline is invalid")]
    InvalidDeadline,
    #[error("the pairing client original deadline elapsed")]
    DeadlineElapsed,
    #[error("the pairing client was cancelled")]
    Cancelled,
    #[error("the pairing client reached end of stream")]
    EndOfStream,
    #[error("the native pairing client/server observation was rejected")]
    Rejected,
    #[error("the native pairing metadata is malformed or unsupported")]
    Malformed,
    #[error("the pairing client cleanup is unconfirmed")]
    CleanupUnconfirmed,
    #[error("the pairing client service context rejected: {0}")]
    Service(ServiceError),
    #[error("the pairing client Windows call failed at {stage:?} ({hresult:#010x})")]
    Native {
        stage: PairingClientStage,
        hresult: i32,
    },
}
type Error = PairingClientError;
type Stage = PairingClientStage;

/// Written is a completed pipe write, not a grant or enrollment result.
pub enum PairingClientProgress {
    Pending,
    Read(Vec<u8>),
    Written,
    Idle,
}
impl fmt::Debug for PairingClientProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "PairingClientProgress::Pending",
            Self::Read(_) => "PairingClientProgress::Read(redacted)",
            Self::Written => "PairingClientProgress::Written",
            Self::Idle => "PairingClientProgress::Idle",
        })
    }
}

fn native_error(stage: Stage, error: WinError) -> Error {
    Error::Native {
        stage,
        hresult: error.code().0,
    }
}
fn peer_error_at(stage: Stage, error: PairingPeerError) -> Error {
    match error {
        PairingPeerError::Native { hresult, .. } => Error::Native { stage, hresult },
        PairingPeerError::Service(error) => Error::Service(error),
        PairingPeerError::Malformed => Error::Malformed,
        PairingPeerError::CleanupUnconfirmed => Error::CleanupUnconfirmed,
        _ => Error::Rejected,
    }
}
fn cleanup_state() -> Result<(), Error> {
    if UNHEALTHY.load(Ordering::Acquire) {
        return Err(Error::CleanupUnconfirmed);
    }
    pairing_peer::cleanup_state().map_err(|error| peer_error_at(Stage::QueryOwnIdentity, error))
}
struct Reservation(PhantomData<Rc<()>>);
impl Reservation {
    fn acquire() -> Result<Self, Error> {
        cleanup_state()?;
        RESERVED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Busy)?;
        Ok(Self(PhantomData))
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        RESERVED.store(false, Ordering::Release);
    }
}
struct Handle(HANDLE);
impl Handle {
    fn new(handle: HANDLE) -> Result<Self, Error> {
        if handle.is_invalid() {
            Err(Error::Malformed)
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: uniquely acquired real noninherited handle. A pending operation
        // retains the WHOLE owner instead of allowing this Drop to run.
        if unsafe { CloseHandle(self.0) }.is_err() {
            UNHEALTHY.store(true, Ordering::Release);
        }
    }
}
impl EventHandle for Handle {
    fn raw_event(&self) -> HANDLE {
        self.0
    }
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the exact successful GetSecurityInfo allocation, after all
        // bounded borrowed views end. A failed free is never retried.
        if !unsafe { LocalFree(Some(HLOCAL(self.0.0))) }.0.is_null() {
            UNHEALTHY.store(true, Ordering::Release);
        }
    }
}

struct OwnIdentity {
    pid: u32,
    created: u64,
    thread: u32,
    session: u32,
    token: TokenFacts,
    epoch: SessionEpoch,
}
impl OwnIdentity {
    fn observe(role: PairingPeerRole) -> Result<Self, Error> {
        reject_thread_impersonation().map_err(Error::Service)?;
        // SAFETY: documented current-process/thread observations. The process
        // pseudo-handle is borrowed only and is never adopted/closed.
        let (process, pid, thread) = unsafe {
            (
                GetCurrentProcess(),
                GetCurrentProcessId(),
                GetCurrentThreadId(),
            )
        };
        let mut session = 0;
        // SAFETY: actual current PID only, initialized fixed scalar output.
        unsafe { ProcessIdToSessionId(pid, &mut session) }
            .map_err(|e| native_error(Stage::QueryOwnIdentity, e))?;
        let token = TokenFacts::observe(process)
            .map_err(|error| peer_error_at(Stage::QueryOwnIdentity, error))?;
        token
            .require(role, session)
            .map_err(|error| peer_error_at(Stage::QueryOwnIdentity, error))?;
        let created = process_identity(process, pid)
            .map_err(|error| peer_error_at(Stage::QueryOwnIdentity, error))?;
        let epoch = SessionEpoch::observe(session)
            .map_err(|error| peer_error_at(Stage::QueryOwnIdentity, error))?;
        reject_thread_impersonation().map_err(Error::Service)?;
        cleanup_state()?;
        Ok(Self {
            pid,
            created,
            thread,
            session,
            token,
            epoch,
        })
    }
    fn recheck(&self, role: PairingPeerRole) -> Result<(), Error> {
        let current = Self::observe(role)?;
        if current.pid != self.pid
            || current.created != self.created
            || current.thread != self.thread
            || current.session != self.session
            || current.token != self.token
            || current.epoch != self.epoch
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }
}

fn client_access() -> u32 {
    (FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_READ_EA
        | FILE_WRITE_EA
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE)
        .0
}
fn client_flags() -> FILE_FLAGS_AND_ATTRIBUTES {
    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
}

struct Connection {
    pipe: Handle,
    server: Handle,
    service: Service,
    installation: ValidatedPairingInstallation,
    own: OwnIdentity,
    role: PairingPeerRole,
    pid: u32,
    created: u64,
    service_sid: Vec<u8>,
    reservation: Option<Reservation>,
}
impl Connection {
    fn recheck(&self) -> Result<(), Error> {
        cleanup_state()?;
        self.own.recheck(self.role)?;
        self.installation
            .check_current_client_image(self.role)
            .map_err(Error::Service)?;
        native::recheck_pairing_service_for_client(
            &self.service,
            self.installation.service(),
            self.pid,
        )
        .map_err(Error::Service)?;
        verify_pipe_security(self.pipe.0, self.role, &self.service_sid)?;
        if pipe_identity(self.pipe.0)? != (self.pid, 0)
            || process_identity(self.server.0, self.pid)
                .map_err(|error| peer_error_at(Stage::QueryServer, error))?
                != self.created
        {
            return Err(Error::Rejected);
        }
        self.installation
            .check_service_image(&process_image(self.server.0)?)
            .map_err(Error::Service)?;
        if pipe_identity(self.pipe.0)? != (self.pid, 0)
            || process_identity(self.server.0, self.pid)
                .map_err(|error| peer_error_at(Stage::QueryServer, error))?
                != self.created
        {
            return Err(Error::Rejected);
        }
        native::recheck_pairing_service_for_client(
            &self.service,
            self.installation.service(),
            self.pid,
        )
        .map_err(Error::Service)?;
        reject_thread_impersonation().map_err(Error::Service)?;
        cleanup_state()
    }
}

/// Opaque, noncloneable and !Send/!Sync. One fixed connection and one original
/// deadline (at most five minutes), never a caller-supplied authority assertion.
#[must_use = "retain the client until actual pending I/O is drained"]
pub struct PairingClient {
    inner: Option<Box<Inner>>,
}
impl fmt::Debug for PairingClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingClient(redacted)")
    }
}
impl PairingClient {
    pub fn connect_starter(started_at: Instant, deadline: Instant) -> Result<Self, Error> {
        Self::connect(ClientEndpoint::Starter, started_at, deadline)
    }
    pub fn connect_helper(started_at: Instant, deadline: Instant) -> Result<Self, Error> {
        Self::connect(ClientEndpoint::Helper, started_at, deadline)
    }
    fn connect(
        endpoint: ClientEndpoint,
        started_at: Instant,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let role = endpoint.role();
        let mut budget = OriginalBudget::new(started_at, deadline, Instant::now())?;
        let reservation = Reservation::acquire()?;
        reject_thread_impersonation().map_err(Error::Service)?;
        // Current installed image admission happens BEFORE opening either pipe.
        let installation = validate_pairing_client_installation(role).map_err(Error::Service)?;
        let own = OwnIdentity::observe(role)?;
        let (service, expected_pid) =
            native::pairing_service_for_client(installation.service()).map_err(Error::Service)?;
        let service_sid = OwnServiceSid::lookup().map_err(Error::Service)?.bytes();
        let name = Wide::new(endpoint.name()).map_err(Error::Service)?;
        budget.observe(Instant::now())?;
        own.recheck(role)?;
        budget.observe(Instant::now())?;
        // SAFETY: fixed local endpoint, concrete non-create-instance rights,
        // OPEN_EXISTING, no inherited handle, explicit IDENTIFICATION SQOS.
        // Exactly one attempt; no WaitNamedPipe/reconnect/alternate endpoint.
        let pipe = unsafe {
            CreateFileW(
                name.ptr(),
                client_access(),
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                client_flags(),
                None,
            )
        }
        .map_err(|e| native_error(Stage::Connect, e))?;
        let pipe = Handle::new(pipe)?;
        verify_pipe_security(pipe.0, role, &service_sid)?;
        let (pid, session) = pipe_identity(pipe.0)?;
        if pid != expected_pid || session != 0 {
            return Err(Error::Rejected);
        }
        // SAFETY: actual pipe PID matched to fixed SCM; query/synchronize only,
        // never TOKEN_QUERY, injection, termination or token duplication.
        let server = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .map_err(|e| native_error(Stage::QueryServer, e))?;
        let server = Handle::new(server)?;
        let created = process_identity(server.0, pid)
            .map_err(|error| peer_error_at(Stage::QueryServer, error))?;
        let connection = Connection {
            pipe,
            server,
            service,
            installation,
            own,
            role,
            pid,
            created,
            service_sid,
            reservation: Some(reservation),
        };
        let mut inner = Box::new(Inner {
            operation: None,
            connection: Some(connection),
            budget,
            first_failure: None,
            cleanup_failure: None,
            drained: false,
            protocol_used: false,
        });
        inner.fence()?;
        // SAFETY: our authenticated retained client handle only. This sets its
        // message read mode, not another object/ACL; no protocol bytes are read.
        unsafe { SetNamedPipeHandleState(inner.pipe()?, Some(&PIPE_READMODE_MESSAGE), None, None) }
            .map_err(|e| native_error(Stage::Connect, e))?;
        inner.fence()?;
        Ok(Self { inner: Some(inner) })
    }
    pub fn begin_read(&mut self) -> Result<(), Error> {
        self.inner_mut().begin(Kind::Read(READ_CAPACITY))
    }
    pub fn begin_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.inner_mut().begin(Kind::Write(bytes))
    }
    /// At most one nonblocking native completion query. Identity/deadline loss
    /// after completion discards bytes/success instead of publishing stale data.
    pub fn poll(&mut self) -> Result<PairingClientProgress, Error> {
        self.inner_mut().poll()
    }
    pub fn cancel(&mut self) {
        self.inner_mut().fail(Error::Cancelled);
    }
    /// Cleanup-only. true means I/O quiescent and this operation/connection
    /// released, not ceremony success or proof of every inherited SCM close.
    pub fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
    }
    pub fn is_closed(&self) -> bool {
        self.inner_ref().first_failure.is_some()
    }
    pub fn is_drained(&self) -> bool {
        self.inner_ref().drained
    }
    pub fn first_failure(&self) -> Option<Error> {
        self.inner_ref().first_failure
    }
    pub fn cleanup_failure(&self) -> Option<Error> {
        self.inner_ref().cleanup_failure
    }
    /// Explicit trusted-host launch request only. Consumes the original fresh
    /// Starter client; obtains its ID from that authenticated pipe, not an arg.
    /// Call/poll on the same native worker, never a WebView/UI thread.
    pub fn into_helper_launch(self) -> Result<PairingHelperLaunch, PairingLaunchError> {
        PairingHelperLaunch::from_starter(self)
    }
    fn inner_ref(&self) -> &Inner {
        self.inner
            .as_deref()
            .expect("client owner exists until Drop")
    }
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner
            .as_deref_mut()
            .expect("client owner exists until Drop")
    }
}
impl Drop for PairingClient {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.fail(Error::Cancelled);
            if inner.in_flight() {
                UNHEALTHY.store(true, Ordering::Release);
                // Retain pipe + stable storage/event + server/SCM/installation
                // pins + own identity + original deadline + process reservation.
                // No detached retry/wait/kill and no replacement after quarantine.
                mem::forget(inner);
            }
        }
    }
}

struct OriginalBudget {
    started: Instant,
    deadline: Instant,
    last: Instant,
}
impl OriginalBudget {
    fn new(started: Instant, deadline: Instant, now: Instant) -> Result<Self, Error> {
        let span = deadline
            .checked_duration_since(started)
            .ok_or(Error::InvalidDeadline)?;
        if span.is_zero() || span > MAX_LIFETIME || now < started {
            return Err(Error::InvalidDeadline);
        }
        if now >= deadline {
            return Err(Error::DeadlineElapsed);
        }
        Ok(Self {
            started,
            deadline,
            last: now,
        })
    }
    fn observe(&mut self, now: Instant) -> Result<(), Error> {
        if now < self.started || now < self.last {
            return Err(Error::InvalidDeadline);
        }
        self.last = now;
        if now >= self.deadline {
            Err(Error::DeadlineElapsed)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
    Read,
    Write(usize),
}
impl OperationKind {
    fn from_kind(kind: Kind<'_>) -> Result<Self, Error> {
        match kind {
            Kind::Read(READ_CAPACITY) => Ok(Self::Read),
            Kind::Write(bytes) if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE => {
                Ok(Self::Write(bytes.len()))
            }
            _ => Err(Error::InvalidMessage),
        }
    }
    fn stage(self) -> Stage {
        match self {
            Self::Read => Stage::Read,
            Self::Write(_) => Stage::Write,
        }
    }
}
struct Operation {
    pending: PendingOperation<Handle>,
    kind: OperationKind,
    cancel_requested: bool,
}
struct Inner {
    operation: Option<Operation>,
    connection: Option<Connection>,
    budget: OriginalBudget,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
    drained: bool,
    protocol_used: bool,
}
impl Inner {
    fn in_flight(&self) -> bool {
        self.operation
            .as_ref()
            .is_some_and(|op| op.pending.in_flight())
    }
    fn pipe(&self) -> Result<HANDLE, Error> {
        self.connection
            .as_ref()
            .map(|c| c.pipe.0)
            .ok_or(Error::Closed)
    }
    fn fence(&mut self) -> Result<(), Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let result = (|| {
            self.budget.observe(Instant::now())?;
            self.connection.as_ref().ok_or(Error::Closed)?.recheck()?;
            self.budget.observe(Instant::now())?;
            cleanup_state()
        })();
        result.map_err(|error| self.fail(error))
    }
    fn fail(&mut self, error: Error) -> Error {
        let first = *self.first_failure.get_or_insert(error);
        self.request_cancel_once();
        first
    }
    fn request_cancel_once(&mut self) {
        if !self.in_flight() {
            return;
        }
        let pipe = match self.pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                self.cleanup_failure.get_or_insert(error);
                return;
            }
        };
        if let Some(operation) = self.operation.as_mut() {
            if operation.cancel_requested {
                return;
            }
            operation.cancel_requested = true;
            if let Err(error) = operation.pending.cancel(pipe) {
                self.cleanup_failure
                    .get_or_insert(io_error(Stage::CancelIo, error));
            }
        }
    }
    fn begin(&mut self, kind: Kind<'_>) -> Result<(), Error> {
        self.fence()?;
        self.protocol_used = true;
        if self.operation.is_some() {
            return Err(self.fail(Error::Busy));
        }
        let operation_kind = OperationKind::from_kind(kind).map_err(|error| self.fail(error))?;
        // SAFETY: unnamed noninherited manual-reset event, initially unsignaled.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|e| self.fail(native_error(Stage::CreateEvent, e)))?;
        let event = Handle::new(event).map_err(|error| self.fail(error))?;
        let pending = PendingOperation::prepare(kind, LIMITS, event)
            .map_err(|error| self.fail(io_error(operation_kind.stage(), error)))?;
        self.operation = Some(Operation {
            pending,
            kind: operation_kind,
            cancel_requested: false,
        });
        self.fence()?; // All allocations precede this original-budget fence.
        let pipe = self.pipe().map_err(|error| self.fail(error))?;
        let issued = self
            .operation
            .as_mut()
            .ok_or(Error::InvalidPhase)?
            .pending
            .issue(pipe);
        issued.map_err(|error| self.fail(io_error(operation_kind.stage(), error)))
    }
    fn poll(&mut self) -> Result<PairingClientProgress, Error> {
        self.fence()?;
        let pipe = self.pipe().map_err(|error| self.fail(error))?;
        let Some(operation) = self.operation.as_mut() else {
            return Ok(PairingClientProgress::Idle);
        };
        let kind = operation.kind;
        let completed = match operation.pending.poll(pipe) {
            Ok(None) => {
                self.fence()?;
                return Ok(PairingClientProgress::Pending);
            }
            Ok(Some(value)) => value,
            Err(error) => return Err(self.fail(io_error(kind.stage(), error))),
        };
        if self.in_flight() {
            return Err(self.fail(Error::Malformed));
        }
        drop(self.operation.take()); // Event-close failure is checked before success.
        let progress = classify_completion(kind, completed).map_err(|error| self.fail(error))?;
        self.fence()?;
        Ok(progress)
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        let first = self.fail(Error::Cancelled);
        if self.in_flight() {
            let pipe = self.pipe().map_err(|error| {
                self.cleanup_failure.get_or_insert(error);
                first
            })?;
            let operation = self.operation.as_mut().ok_or(first)?;
            let cancelled = operation.cancel_requested;
            match operation.pending.poll(pipe) {
                Ok(None) => return Ok(false),
                Ok(Some(_)) if self.in_flight() => {
                    self.cleanup_failure.get_or_insert(Error::Malformed);
                    return Err(first);
                }
                Ok(Some(_)) => (),
                Err(error) => {
                    if !expected_cancel_completion(error, cancelled, self.in_flight()) {
                        self.cleanup_failure
                            .get_or_insert(io_error(Stage::PollIo, error));
                    }
                    if self.in_flight() {
                        return Err(first);
                    }
                }
            }
        }
        drop(self.operation.take());
        drop(self.connection.take());
        if let Err(error) = cleanup_state() {
            self.cleanup_failure.get_or_insert(error);
            return Err(first);
        }
        self.drained = true;
        Ok(true)
    }
}
fn io_error(stage: Stage, error: IoError) -> Error {
    match error {
        IoError::Native { hresult } => Error::Native { stage, hresult },
        IoError::InvalidBuffer => Error::InvalidMessage,
        IoError::InvalidPhase => Error::InvalidPhase,
    }
}
fn expected_cancel_completion(error: IoError, cancelled: bool, in_flight: bool) -> bool {
    let aborted = IoError::Native {
        hresult: HRESULT::from_win32(ERROR_OPERATION_ABORTED.0).0,
    };
    cancelled && !in_flight && error == aborted
}
fn classify_completion(
    kind: OperationKind,
    value: Completed,
) -> Result<PairingClientProgress, Error> {
    match (kind, value) {
        (OperationKind::Read, Completed::Bytes(bytes))
            if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE =>
        {
            Ok(PairingClientProgress::Read(bytes))
        }
        (OperationKind::Write(expected), Completed::Count(count))
            if expected != 0 && count == expected =>
        {
            Ok(PairingClientProgress::Written)
        }
        (_, Completed::Eof) => Err(Error::EndOfStream),
        _ => Err(Error::InvalidMessage),
    }
}

fn pipe_identity(pipe: HANDLE) -> Result<(u32, u32), Error> {
    // SAFETY: owned connected OVERLAPPED pipe, fixed metadata queries only.
    if unsafe { GetFileType(pipe) } != FILE_TYPE_PIPE {
        return Err(Error::Rejected);
    }
    unsafe { PeekNamedPipe(pipe, None, 0, None, None, None) }
        .map_err(|e| native_error(Stage::QueryPipe, e))?;
    let (mut pid, mut session) = (0, u32::MAX);
    // SAFETY: initialized exclusive scalar outputs for this exact pipe.
    unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) }
        .map_err(|e| native_error(Stage::QueryPipe, e))?;
    // SAFETY: same retained pipe, no session supplied by a message/caller.
    unsafe { GetNamedPipeServerSessionId(pipe, &mut session) }
        .map_err(|e| native_error(Stage::QueryPipe, e))?;
    if pid == 0 || session != 0 {
        return Err(Error::Rejected);
    }
    Ok((pid, session))
}
pub(super) fn process_image(process: HANDLE) -> Result<PathBuf, Error> {
    let mut buffer = [0u16; 1024];
    let mut length = buffer.len() as u32;
    // SAFETY: retained query-only process, fixed bounded output, DOS path mode.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|e| native_error(Stage::QueryServer, e))?;
    let units = buffer
        .get(..length as usize)
        .filter(|v| !v.is_empty() && !v.contains(&0))
        .ok_or(Error::Malformed)?;
    Ok(PathBuf::from(
        String::from_utf16(units).map_err(|_| Error::Malformed)?,
    ))
}

fn verify_pipe_security(
    pipe: HANDLE,
    role: PairingPeerRole,
    service_sid: &[u8],
) -> Result<(), Error> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: owned pipe with READ_CONTROL; OWNER/DACL only. GetSecurityInfo
    // supports kernel objects/named pipes and returns a LocalAlloc-owned SD.
    let result = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(native_error(
            Stage::ReadPipeSecurity,
            WinError::from(HRESULT::from_win32(result.0)),
        ));
    }
    if descriptor.0.is_null() {
        return Err(Error::Malformed);
    }
    let allocation = Descriptor(descriptor);
    // SAFETY: successful API allocation, not a caller pointer. Query shape before
    // reading its documented contiguous self-relative returned representation.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(Error::Malformed);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: same live descriptor and exclusive initialized fixed outputs.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|e| native_error(Stage::ReadPipeSecurity, e))?;
    if revision != 1 || control & SE_SELF_RELATIVE.0 == 0 {
        return Err(Error::Malformed);
    }
    // SAFETY: validated self-relative descriptor remains owned by allocation.
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if !(mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=MAX_DESCRIPTOR).contains(&length) {
        return Err(Error::Malformed);
    }
    // SAFETY: native-validated contiguous allocation length above, immutable
    // borrowed view ends before LocalFree; pure offsets below stay bounded.
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length) };
    let checked = check_pipe_descriptor(bytes, role, service_sid);
    drop(allocation);
    checked?;
    cleanup_state()
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Malformed)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?,
    ))
}
fn sid_at(bytes: &[u8], offset: usize) -> Result<&[u8], Error> {
    let prefix_end = offset.checked_add(8).ok_or(Error::Malformed)?;
    let header = bytes.get(offset..prefix_end).ok_or(Error::Malformed)?;
    if header[0] != 1 || header[1] > 15 {
        return Err(Error::Malformed);
    }
    let end = prefix_end
        .checked_add(usize::from(header[1]) * 4)
        .ok_or(Error::Malformed)?;
    bytes.get(offset..end).ok_or(Error::Malformed)
}
fn check_pipe_descriptor(
    bytes: &[u8],
    role: PairingPeerRole,
    service_sid: &[u8],
) -> Result<(), Error> {
    let header_size = mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>();
    if bytes.len() < header_size
        || bytes.len() > MAX_DESCRIPTOR
        || bytes[0] != 1
        || bytes[1] != 0
        || !crate::policy::service_sid_matches(service_sid, "NT SERVICE")
    {
        return Err(Error::Malformed);
    }
    let control_offset = mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Control);
    let control = u16::from_le_bytes(
        bytes[control_offset..control_offset + 2]
            .try_into()
            .map_err(|_| Error::Malformed)?,
    );
    let required = (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED).0;
    if control & required != required {
        return Err(Error::Rejected);
    }
    let owner = read_u32(bytes, mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner))? as usize;
    let dacl = read_u32(bytes, mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl))? as usize;
    if owner < header_size
        || dacl < header_size
        || !owner.is_multiple_of(4)
        || !dacl.is_multiple_of(4)
        || sid_at(bytes, owner)? != SYSTEM
    {
        return Err(Error::Rejected);
    }
    let header = bytes.get(dacl..dacl + 8).ok_or(Error::Malformed)?;
    if ![ACL_REVISION.0 as u8, ACL_REVISION_DS.0 as u8].contains(&header[0])
        || header[1] != 0
        || header[6..8] != [0, 0]
    {
        return Err(Error::Malformed);
    }
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let count = u16::from_le_bytes([header[4], header[5]]);
    let expected_count = if role == PairingPeerRole::Starter {
        4
    } else {
        3
    };
    if size < 8 || count != expected_count {
        return Err(Error::Rejected);
    }
    let acl = bytes.get(dacl..dacl + size).ok_or(Error::Malformed)?;
    let mut seen = [false; 4];
    let mut offset = 8;
    for _ in 0..count {
        let header = acl.get(offset..offset + 4).ok_or(Error::Malformed)?;
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        // MS-DTYP ACCESS_ALLOWED_ACE type is 0; no inherited, deny, callback,
        // object or unknown ACE is admitted by this exact product DACL shape.
        if header[0] != 0 || header[1] != 0 || size < 16 || !size.is_multiple_of(4) {
            return Err(Error::Rejected);
        }
        let ace = acl.get(offset..offset + size).ok_or(Error::Malformed)?;
        let mask = read_u32(ace, 4)?;
        let sid = sid_at(ace, 8)?;
        if sid.len() + 8 != size {
            return Err(Error::Malformed);
        }
        let index = if sid == SYSTEM {
            0
        } else if sid == ADMINISTRATORS {
            1
        } else if sid == service_sid {
            2
        } else if role == PairingPeerRole::Starter && sid == AUTHENTICATED_USERS {
            3
        } else {
            return Err(Error::Rejected);
        };
        if seen[index]
            || (index == 3 && mask != client_access())
            || (index != 3 && mask != GENERIC_ALL.0 && mask != FILE_ALL_ACCESS.0)
        {
            return Err(Error::Rejected);
        }
        seen[index] = true;
        offset += size;
    }
    if offset != acl.len()
        || !seen[..usize::from(expected_count)]
            .iter()
            .all(|value| *value)
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::{
        Foundation::{ERROR_IO_INCOMPLETE, ERROR_MORE_DATA, GENERIC_WRITE},
        Storage::FileSystem::FILE_APPEND_DATA,
    };

    fn service_sid() -> Vec<u8> {
        let mut sid = vec![1, 6, 0, 0, 0, 0, 0, 5];
        for part in [80u32, 1, 2, 3, 4, 5] {
            sid.extend_from_slice(&part.to_le_bytes());
        }
        sid
    }
    fn ace(sid: &[u8], mask: u32) -> Vec<u8> {
        let size = u16::try_from(8 + sid.len()).unwrap();
        let mut value = vec![0, 0];
        value.extend_from_slice(&size.to_le_bytes());
        value.extend_from_slice(&mask.to_le_bytes());
        value.extend_from_slice(sid);
        value
    }
    fn descriptor(role: PairingPeerRole, owner: &[u8], entries: &[Vec<u8>]) -> Vec<u8> {
        let _ = role; // Entry list is explicit, allowing adversarial role fixtures.
        let owner_offset = mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>();
        let dacl_offset = owner_offset + owner.len();
        let mut value = vec![0; owner_offset];
        value[0] = 1;
        let control = (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED).0;
        let field = mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Control);
        value[field..field + 2].copy_from_slice(&control.to_le_bytes());
        let field = mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner);
        value[field..field + 4]
            .copy_from_slice(&u32::try_from(owner_offset).unwrap().to_le_bytes());
        let field = mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl);
        value[field..field + 4].copy_from_slice(&u32::try_from(dacl_offset).unwrap().to_le_bytes());
        value.extend_from_slice(owner);
        let size = u16::try_from(8 + entries.iter().map(Vec::len).sum::<usize>()).unwrap();
        value.extend_from_slice(&[ACL_REVISION.0 as u8, 0]);
        value.extend_from_slice(&size.to_le_bytes());
        value.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
        value.extend_from_slice(&[0, 0]);
        for entry in entries {
            value.extend_from_slice(entry);
        }
        value
    }
    fn expected_entries(role: PairingPeerRole, full: u32) -> Vec<Vec<u8>> {
        let mut entries = vec![
            ace(SYSTEM, full),
            ace(ADMINISTRATORS, full),
            ace(&service_sid(), full),
        ];
        if role == PairingPeerRole::Starter {
            entries.push(ace(AUTHENTICATED_USERS, client_access()));
        }
        entries
    }

    #[test]
    fn concrete_client_access_matches_server_grant_without_instance_creation() {
        assert_eq!(client_access(), pairing_peer::STARTER_ACCESS);
        assert_eq!(client_access() & FILE_APPEND_DATA.0, 0);
        assert_eq!(client_access() & (GENERIC_ALL.0 | GENERIC_WRITE.0), 0);
        assert_ne!(client_access() & READ_CONTROL.0, 0);
        assert_ne!(client_access() & SYNCHRONIZE.0, 0);
        assert_eq!(
            client_flags(),
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
        );
    }

    #[test]
    fn exact_system_owned_protected_role_dacl_accepts_documented_generic_mapping() {
        for role in [PairingPeerRole::Starter, PairingPeerRole::Helper] {
            for full in [GENERIC_ALL.0, FILE_ALL_ACCESS.0] {
                let entries = expected_entries(role, full);
                assert_eq!(
                    check_pipe_descriptor(
                        &descriptor(role, SYSTEM, &entries),
                        role,
                        &service_sid()
                    ),
                    Ok(())
                );
                let mut reordered = entries;
                reordered.reverse();
                assert_eq!(
                    check_pipe_descriptor(
                        &descriptor(role, SYSTEM, &reordered),
                        role,
                        &service_sid()
                    ),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn fake_owner_null_or_unprotected_descriptor_never_authenticates_a_pipe() {
        let role = PairingPeerRole::Starter;
        let entries = expected_entries(role, FILE_ALL_ACCESS.0);
        for owner in [AUTHENTICATED_USERS, ADMINISTRATORS] {
            assert!(
                check_pipe_descriptor(&descriptor(role, owner, &entries), role, &service_sid())
                    .is_err()
            );
        }
        for flag in [SE_SELF_RELATIVE, SE_DACL_PRESENT, SE_DACL_PROTECTED] {
            let mut value = descriptor(role, SYSTEM, &entries);
            let at = mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Control);
            let mut control = u16::from_le_bytes(value[at..at + 2].try_into().unwrap());
            control &= !flag.0;
            value[at..at + 2].copy_from_slice(&control.to_le_bytes());
            assert!(check_pipe_descriptor(&value, role, &service_sid()).is_err());
        }
        for field in [
            mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner),
            mem::offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl),
        ] {
            for offset in [0u32, 1, u32::MAX] {
                let mut value = descriptor(role, SYSTEM, &entries);
                value[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                assert!(check_pipe_descriptor(&value, role, &service_sid()).is_err());
            }
        }
    }

    #[test]
    fn extra_unknown_duplicate_inherited_and_create_instance_grants_are_rejected() {
        let role = PairingPeerRole::Starter;
        for mask in [
            client_access() | FILE_APPEND_DATA.0,
            GENERIC_WRITE.0,
            GENERIC_ALL.0,
            FILE_ALL_ACCESS.0,
            0,
        ] {
            let mut entries = expected_entries(role, FILE_ALL_ACCESS.0);
            entries[3] = ace(AUTHENTICATED_USERS, mask);
            assert!(
                check_pipe_descriptor(&descriptor(role, SYSTEM, &entries), role, &service_sid())
                    .is_err()
            );
        }
        for (kind, flags) in [(1, 0), (5, 0), (9, 0), (0, 0x10), (0, 0x08)] {
            let mut entries = expected_entries(role, FILE_ALL_ACCESS.0);
            entries[0][0] = kind;
            entries[0][1] = flags;
            assert!(
                check_pipe_descriptor(&descriptor(role, SYSTEM, &entries), role, &service_sid())
                    .is_err()
            );
        }
        let mut duplicated = expected_entries(role, FILE_ALL_ACCESS.0);
        duplicated[1] = duplicated[0].clone();
        assert!(
            check_pipe_descriptor(&descriptor(role, SYSTEM, &duplicated), role, &service_sid())
                .is_err()
        );
        let mut extra = expected_entries(role, FILE_ALL_ACCESS.0);
        extra.push(ace(AUTHENTICATED_USERS, READ_CONTROL.0));
        assert!(
            check_pipe_descriptor(&descriptor(role, SYSTEM, &extra), role, &service_sid()).is_err()
        );
        let helper_with_starter_grant =
            descriptor(role, SYSTEM, &expected_entries(role, FILE_ALL_ACCESS.0));
        assert!(
            check_pipe_descriptor(
                &helper_with_starter_grant,
                PairingPeerRole::Helper,
                &service_sid()
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_descriptor_lengths_and_sid_offsets_are_bounded() {
        let role = PairingPeerRole::Starter;
        let value = descriptor(role, SYSTEM, &expected_entries(role, FILE_ALL_ACCESS.0));
        for length in 0..value.len() {
            assert!(check_pipe_descriptor(&value[..length], role, &service_sid()).is_err());
        }
        assert!(check_pipe_descriptor(&vec![0; MAX_DESCRIPTOR + 1], role, &service_sid()).is_err());
        assert_eq!(sid_at(&[], usize::MAX), Err(Error::Malformed));
        assert_eq!(read_u32(&[], usize::MAX), Err(Error::Malformed));
        assert!(check_pipe_descriptor(&value, role, SYSTEM).is_err());
    }

    #[test]
    fn original_deadline_is_never_reset_and_rejects_regression() {
        let base = Instant::now();
        let start = base + Duration::from_secs(1);
        assert!(matches!(
            OriginalBudget::new(start, start, start),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(start, start + MAX_LIFETIME + Duration::from_nanos(1), start),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(start, start + MAX_LIFETIME, base),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(start, start + MAX_LIFETIME, start + MAX_LIFETIME),
            Err(Error::DeadlineElapsed)
        ));
        let mut budget = OriginalBudget::new(start, start + MAX_LIFETIME, start).unwrap();
        assert_eq!(budget.observe(start + Duration::from_secs(1)), Ok(()));
        assert_eq!(budget.observe(start), Err(Error::InvalidDeadline));
        assert_eq!(
            budget.observe(start + MAX_LIFETIME),
            Err(Error::DeadlineElapsed)
        );
    }

    #[test]
    fn message_and_completion_shapes_never_accept_truncation_or_eof() {
        assert_eq!(
            OperationKind::from_kind(Kind::Connect),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            OperationKind::from_kind(Kind::Write(&[])),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            OperationKind::from_kind(Kind::Write(&vec![0; MAX_MESSAGE + 1])),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            OperationKind::from_kind(Kind::Read(MAX_MESSAGE)),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            OperationKind::from_kind(Kind::Read(READ_CAPACITY)),
            Ok(OperationKind::Read)
        );
        for value in [
            Completed::Bytes(vec![]),
            Completed::Bytes(vec![0; READ_CAPACITY]),
            Completed::Count(0),
            Completed::Eof,
        ] {
            assert!(classify_completion(OperationKind::Read, value).is_err());
        }
        assert!(classify_completion(OperationKind::Write(4), Completed::Count(3)).is_err());
        assert!(matches!(
            classify_completion(OperationKind::Write(4), Completed::Count(4)),
            Ok(PairingClientProgress::Written)
        ));
        assert_eq!(
            format!(
                "{:?}",
                PairingClientProgress::Read(b"synthetic-private-payload".to_vec())
            ),
            "PairingClientProgress::Read(redacted)"
        );
    }

    #[test]
    fn cancellation_is_not_completion_and_only_terminal_requested_abort_is_expected() {
        let aborted = IoError::Native {
            hresult: HRESULT::from_win32(ERROR_OPERATION_ABORTED.0).0,
        };
        assert!(expected_cancel_completion(aborted, true, false));
        assert!(!expected_cancel_completion(aborted, false, false));
        assert!(!expected_cancel_completion(aborted, true, true));
        for code in [ERROR_IO_INCOMPLETE.0, ERROR_MORE_DATA.0] {
            assert!(!expected_cancel_completion(
                IoError::Native {
                    hresult: HRESULT::from_win32(code).0
                },
                true,
                false
            ));
        }
    }

    #[test]
    fn ordinary_test_image_is_rejected_before_either_native_pipe_is_opened() {
        // Actual read-only installed-path/own-image admission. This test binary
        // is neither fixed installed GUI nor helper; no pipe, elevation, service
        // mutation, provider call or synthetic peer can follow failed admission.
        let start = Instant::now();
        assert!(matches!(
            PairingClient::connect_starter(start, start + Duration::from_secs(5)),
            Err(Error::Service(_))
        ));
        let start = Instant::now();
        assert!(matches!(
            PairingClient::connect_helper(start, start + Duration::from_secs(5)),
            Err(Error::Service(_))
        ));
    }
}
