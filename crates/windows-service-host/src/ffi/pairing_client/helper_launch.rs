// SPDX-License-Identifier: GPL-2.0-or-later
//! One consumed Starter and its actual launched helper. Bound stays live-owned;
//! only authenticated Close -> CloseAck -> original transport EOF ends it.
//! No producer, enrollment, generic launcher, timeout reset or process kill.

use super::{
    Completed, Error as ClientError, Handle, Kind, LIMITS, MAX_LIFETIME, Operation, OperationKind,
    PairingClient, PairingClientProgress, PairingPeerRole, PendingOperation, READ_CAPACITY,
    Reservation, Stage, UNHEALTHY, Wide, cleanup_state, io_error, native_error, peer_error_at,
    process_identity, process_image,
};
use crate::{
    PendingElevationId, ServiceError, ServiceOperation,
    pairing_handoff::{Frame, Handoff, Next},
};
use std::{
    fmt, mem,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use windows::{
    Win32::{
        Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{CreateEventW, GetExitCodeProcess, GetProcessId, WaitForSingleObject},
        },
        UI::Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
    },
    core::{HRESULT, PCWSTR, w},
};

const POLL: Duration = Duration::from_millis(25);
mod renderer_launch;
use renderer_launch::HelperRendererLaunch;
static HELPER_INVOKED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PairingLaunchError {
    #[error("pairing client failed: {0}")]
    Client(#[from] ClientError),
    #[error("the pairing helper handoff frame or phase is invalid")]
    Protocol,
    #[error("the original fresh starter cannot be claimed for launch")]
    InvalidPhase,
    #[error("the pairing helper launch was cancelled by Windows")]
    UserCancelled,
    #[error("the pairing helper launch is unconfirmed; no retry")]
    LaunchUnconfirmed,
    #[error("the pairing helper exited before successful terminal close (code {exit_code})")]
    HelperExited { exit_code: u32 },
    #[error("the pairing helper handoff was cancelled")]
    Cancelled,
    #[error("the pairing helper cleanup remains unconfirmed")]
    CleanupUnconfirmed,
    #[error("Windows helper operation {operation:?} failed ({hresult:#010x})")]
    Native {
        operation: ServiceOperation,
        hresult: i32,
    },
}
impl PairingLaunchError {
    pub(crate) fn service_error(self) -> ServiceError {
        match self {
            Self::Client(ClientError::Service(error)) => error,
            Self::Client(ClientError::Native { stage, hresult }) => {
                ServiceError::PairingClientNative {
                    stage: client_stage_code(stage),
                    hresult,
                }
            }
            Self::Native { operation, hresult } => ServiceError::WindowsCall {
                operation,
                code: hresult as u32,
            },
            Self::Client(ClientError::DeadlineElapsed) => ServiceError::Timeout,
            _ => ServiceError::PairingHandoffUnavailable,
        }
    }
}
type Error = PairingLaunchError;

/// Stable diagnostic IDs, never enum-discriminant casts or recursive wrappers.
fn client_stage_code(stage: Stage) -> u8 {
    match stage {
        Stage::Connect => 1,
        Stage::CreateEvent => 2,
        Stage::QueryPipe => 3,
        Stage::ReadPipeSecurity => 4,
        Stage::QueryOwnIdentity => 5,
        Stage::QueryServer => 6,
        Stage::Read => 7,
        Stage::Write => 8,
        Stage::PollIo => 9,
        Stage::CancelIo => 10,
    }
}

/// Bound is informational while this opaque owner remains live. Closed is ONLY
/// terminal transport close plus helper exit/drain: a rejected attempt may close
/// without EVER binding. Never infer Bound, consent or enrollment from Closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingLaunchProgress {
    Pending,
    BindingWritten,
    Bound,
    Closing,
    CleanupPending,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Read,
    Write,
    TerminalAck(usize),
    TerminalRead,
    PeerClosed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Pending,
    Launch(PendingElevationId),
    Written,
    Bound,
    Closing,
    PeerClosed,
    PrepareRenderer(crate::pairing_handoff::RendererRequest),
    ResumeRenderer(crate::pairing_handoff::RendererRequest),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalCompletion {
    AckWritten,
    PeerClosed,
}

fn terminal_completion(mode: Mode, value: Completed) -> Result<TerminalCompletion, Error> {
    match (mode, value) {
        (Mode::TerminalAck(expected), Completed::Count(count))
            if expected != 0 && count == expected =>
        {
            Ok(TerminalCompletion::AckWritten)
        }
        (Mode::TerminalRead, Completed::Eof) => Ok(TerminalCompletion::PeerClosed),
        _ => Err(Error::Protocol),
    }
}

/// Resource-release predicate only, never authority. Native observations below
/// supply it; the actual original reservation is not reconstructed from flags.
fn release_allowed(
    pipe_drained: bool,
    unknown_launch: bool,
    helper_retained: bool,
    helper_exit: Option<u32>,
) -> bool {
    pipe_drained && !unknown_launch && (!helper_retained || helper_exit.is_some())
}

struct Endpoint {
    client: PairingClient,
    handoff: Handoff,
    mode: Mode,
}
impl Endpoint {
    fn send_renderer_launched(
        &mut self,
        request: crate::pairing_handoff::RendererRequest,
        process: crate::pairing_handoff::RendererProcess,
    ) -> Result<(), Error> {
        let frame = self
            .handoff
            .renderer_launched(request, process)
            .map_err(|_| Error::Protocol)?;
        self.client
            .begin_write(&frame.encode().map_err(|_| Error::Protocol)?)?;
        self.mode = Mode::Write;
        Ok(())
    }
    fn renderer_resumed(&mut self) -> Result<(), Error> {
        self.client.begin_read()?;
        self.mode = Mode::Read;
        Ok(())
    }
    fn starter(mut client: PairingClient) -> Result<Self, Error> {
        client.begin_read()?;
        Ok(Self {
            client,
            handoff: Handoff::starter(),
            mode: Mode::Read,
        })
    }
    fn helper(mut client: PairingClient, id: PendingElevationId) -> Result<Self, Error> {
        let (handoff, hello) = Handoff::helper(id);
        client.begin_write(&hello.encode().map_err(|_| Error::Protocol)?)?;
        Ok(Self {
            client,
            handoff,
            mode: Mode::Write,
        })
    }
    fn send_launched(&mut self, pid: u32, created: u64) -> Result<(), Error> {
        let frame = self
            .handoff
            .launched(pid, created)
            .map_err(|_| Error::Protocol)?;
        self.client
            .begin_write(&frame.encode().map_err(|_| Error::Protocol)?)?;
        self.mode = Mode::Write;
        Ok(())
    }
    fn poll(&mut self) -> Result<Event, Error> {
        if self.mode == Mode::PeerClosed {
            return Ok(Event::PeerClosed);
        }
        if matches!(self.mode, Mode::TerminalAck(_) | Mode::TerminalRead) {
            return self.poll_terminal();
        }
        match self.client.poll()? {
            PairingClientProgress::Pending => Ok(Event::Pending),
            PairingClientProgress::Written if self.mode == Mode::Write => {
                if self.handoff.written().map_err(|_| Error::Protocol)? != Next::Read {
                    return Err(Error::Protocol);
                }
                self.client.begin_read()?;
                self.mode = Mode::Read;
                Ok(Event::Written)
            }
            PairingClientProgress::Read(bytes) if self.mode == Mode::Read => {
                // This is exclusively the original client's NORMAL authenticated
                // completion. No caller can supply a decoded Close/offer here.
                let frame = Frame::decode(&bytes).map_err(|_| Error::Protocol)?;
                match self.handoff.receive(frame).map_err(|_| Error::Protocol)? {
                    Next::Launch(id) => Ok(Event::Launch(id)),
                    Next::BoundLive => {
                        self.client.begin_read()?;
                        Ok(Event::Bound)
                    }
                    Next::CloseAck(id) => {
                        // Logical upward eligibility has ended. The ONLY write
                        // admitted by the terminal path is this internally encoded
                        // Ack. Its issue still uses the normal native fence.
                        let bytes = Frame::CloseAck(id).encode().map_err(|_| Error::Protocol)?;
                        self.client.begin_write(&bytes)?;
                        self.mode = Mode::TerminalAck(bytes.len());
                        Ok(Event::Closing)
                    }
                    Next::PrepareRenderer(request) => Ok(Event::PrepareRenderer(request)),
                    Next::ResumeRenderer(request) => Ok(Event::ResumeRenderer(request)),
                    _ => Err(Error::Protocol),
                }
            }
            _ => Err(Error::Protocol),
        }
    }
    fn budget(&mut self) -> Result<(), Error> {
        self.client.inner_mut().budget.observe(Instant::now())?;
        cleanup_state()?;
        Ok(())
    }
    /// Cleanup-only after a genuine Close. A server can consume Ack and close
    /// immediately; requiring its old SCM/process liveness AFTER that completed
    /// write would reject legitimate termination. No bytes/authority escape.
    fn poll_terminal(&mut self) -> Result<Event, Error> {
        if !self.handoff.closing() {
            return Err(Error::Protocol);
        }
        self.budget()?;
        let inner = self.client.inner_mut();
        if let Some(error) = inner.first_failure {
            return Err(error.into());
        }
        let pipe = inner.pipe()?;
        let operation = inner.operation.as_mut().ok_or(Error::Protocol)?;
        let value = match operation.pending.poll(pipe) {
            Ok(None) => {
                self.budget()?;
                return Ok(Event::Pending);
            }
            Ok(Some(value)) => value,
            Err(error) => return Err(inner.fail(io_error(Stage::PollIo, error)).into()),
        };
        if inner.in_flight() {
            return Err(inner.fail(ClientError::Malformed).into());
        }
        drop(inner.operation.take());
        self.budget()?;
        match terminal_completion(self.mode, value)? {
            TerminalCompletion::AckWritten => {
                self.handoff.ack_written().map_err(|_| Error::Protocol)?;
                self.begin_terminal_read()?;
                self.mode = Mode::TerminalRead;
                Ok(Event::Closing)
            }
            TerminalCompletion::PeerClosed => {
                self.handoff.peer_closed().map_err(|_| Error::Protocol)?;
                self.mode = Mode::PeerClosed;
                Ok(Event::PeerClosed)
            }
        }
    }
    fn begin_terminal_read(&mut self) -> Result<(), Error> {
        self.budget()?;
        let inner = self.client.inner_mut();
        if let Some(error) = inner.first_failure {
            return Err(error.into());
        }
        if inner.operation.is_some() {
            return Err(Error::Protocol);
        }
        // SAFETY: unnamed, noninherited manual-reset event. This private path
        // only observes terminal EOF on the retained original pipe after Ack.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| native_error(Stage::CreateEvent, error))?;
        let event = Handle::new(event)?;
        let pending = PendingOperation::prepare(Kind::Read(READ_CAPACITY), LIMITS, event)
            .map_err(|error| io_error(Stage::Read, error))?;
        inner.operation = Some(Operation {
            pending,
            kind: OperationKind::from_kind(Kind::Read(READ_CAPACITY), false)?,
            cancel_requested: false,
        });
        inner.budget.observe(Instant::now())?;
        cleanup_state()?;
        let pipe = inner.pipe()?;
        inner
            .operation
            .as_mut()
            .ok_or(Error::Protocol)?
            .pending
            .issue(pipe)
            .map_err(|error| inner.fail(io_error(Stage::Read, error)))?;
        Ok(())
    }
    fn cancel(&mut self) {
        self.handoff.cancel();
        self.client.cancel();
    }
}

/// Reuses the exact private Ack/EOF cleanup path. This wrapper is constructed
/// only by the fixed renderer after its genuine normal-authenticated Close;
/// it is stored before the potentially pending Ack write is begun.
pub(super) struct RendererTerminal {
    endpoint: Endpoint,
    id: PendingElevationId,
}
impl RendererTerminal {
    pub(super) fn after_close(client: PairingClient, id: PendingElevationId) -> Self {
        Self {
            endpoint: Endpoint {
                client,
                handoff: Handoff::renderer_close(id),
                mode: Mode::Read,
            },
            id,
        }
    }
    pub(super) fn start(&mut self) -> Result<(), Error> {
        let bytes = Frame::CloseAck(self.id)
            .encode()
            .map_err(|_| Error::Protocol)?;
        self.endpoint.client.begin_write(&bytes)?;
        self.endpoint.mode = Mode::TerminalAck(bytes.len());
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Result<bool, Error> {
        match self.endpoint.poll()? {
            Event::PeerClosed => Ok(true),
            Event::Pending | Event::Closing => Ok(false),
            _ => Err(Error::Protocol),
        }
    }
    pub(super) fn cancel(&mut self) {
        self.endpoint.cancel();
    }
    pub(super) fn drain(&mut self) -> Result<bool, Error> {
        self.endpoint.client.drain().map_err(Into::into)
    }
    pub(super) fn finish(&mut self) -> Result<(), Error> {
        if self.endpoint.mode != Mode::PeerClosed || !self.endpoint.handoff.closed() {
            return Err(Error::Protocol);
        }
        self.endpoint.budget()
    }
}

struct HelperProcess {
    handle: Handle,
    pid: u32,
    created: u64,
}
impl HelperProcess {
    fn recheck(&self, starter: &mut PairingClient) -> Result<(), Error> {
        starter.inner_mut().fence()?;
        if process_identity(self.handle.0, self.pid)
            .map_err(|error| peer_error_at(Stage::QueryServer, error))?
            != self.created
        {
            return Err(Error::LaunchUnconfirmed);
        }
        let connection = starter
            .inner_ref()
            .connection
            .as_ref()
            .ok_or(Error::InvalidPhase)?;
        connection
            .installation
            .check_service_image(&process_image(self.handle.0)?)
            .map_err(ClientError::Service)?;
        let mut session = 0;
        // SAFETY: PID from the retained live process, initialized scalar only.
        unsafe { ProcessIdToSessionId(self.pid, &mut session) }
            .map_err(|error| native_error(Stage::QueryServer, error))?;
        if session != connection.own.session
            || process_identity(self.handle.0, self.pid)
                .map_err(|error| peer_error_at(Stage::QueryServer, error))?
                != self.created
        {
            return Err(Error::LaunchUnconfirmed);
        }
        starter.inner_mut().fence()?;
        Ok(())
    }
    fn exit(&self) -> Result<Option<u32>, Error> {
        // SAFETY: retained actual process; zero-time observation, never wait/kill.
        let state = unsafe { WaitForSingleObject(self.handle.0, 0) };
        if state == WAIT_TIMEOUT {
            return Ok(None);
        }
        if state != WAIT_OBJECT_0 {
            return Err(Error::Native {
                operation: ServiceOperation::WaitElevatedHelper,
                hresult: windows::core::Error::from_thread().code().0,
            });
        }
        let mut code = 0;
        // SAFETY: terminated retained process, initialized fixed output.
        unsafe { GetExitCodeProcess(self.handle.0, &mut code) }.map_err(|error| Error::Native {
            operation: ServiceOperation::WaitElevatedHelper,
            hresult: error.code().0,
        })?;
        Ok(Some(code))
    }
}

#[must_use = "retain the original starter and helper through terminal close/drain"]
pub struct PairingHelperLaunch {
    inner: Option<Box<LaunchInner>>,
}
impl fmt::Debug for PairingHelperLaunch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingHelperLaunch(live_owned, redacted)")
    }
}
struct LaunchInner {
    endpoint: Endpoint,
    helper: Option<HelperProcess>,
    helper_exit: Option<u32>,
    unknown_launch: bool,
    reservation: Option<Reservation>,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
    drained: bool,
}
impl PairingHelperLaunch {
    pub(super) fn from_starter(mut starter: PairingClient) -> Result<Self, Error> {
        let inner = starter.inner_mut();
        inner.fence()?;
        if inner.protocol_used || inner.operation.is_some() {
            return Err(Error::InvalidPhase);
        }
        let connection = inner.connection.as_mut().ok_or(Error::InvalidPhase)?;
        if connection.role != PairingPeerRole::Starter {
            return Err(Error::InvalidPhase);
        }
        let reservation = connection.reservation.take().ok_or(Error::InvalidPhase)?;
        // Once ownership transfers, construction failure poisons the boundary;
        // no detached client Drop may release a replacement launch opportunity.
        let endpoint = match Endpoint::starter(starter) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                UNHEALTHY.store(true, Ordering::Release);
                mem::forget(reservation);
                return Err(error);
            }
        };
        Ok(Self {
            inner: Some(Box::new(LaunchInner {
                endpoint,
                helper: None,
                helper_exit: None,
                unknown_launch: false,
                reservation: Some(reservation),
                first_failure: None,
                cleanup_failure: None,
                drained: false,
            })),
        })
    }
    /// May enter Windows-owned UAC once, on this same native worker. Returning
    /// Bound does not release either original native owner or produce a grant.
    pub fn poll(&mut self) -> Result<PairingLaunchProgress, Error> {
        self.inner_mut().poll()
    }
    pub fn cancel(&mut self) {
        self.inner_mut().fail(Error::Cancelled);
    }
    pub fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
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
    fn inner_ref(&self) -> &LaunchInner {
        self.inner
            .as_deref()
            .expect("launch owner exists until Drop")
    }
    fn inner_mut(&mut self) -> &mut LaunchInner {
        self.inner
            .as_deref_mut()
            .expect("launch owner exists until Drop")
    }
}
impl Drop for PairingHelperLaunch {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && !inner.drained
        {
            inner.fail(Error::Cancelled);
            UNHEALTHY.store(true, Ordering::Release);
            // Keep helper + original client/operation/pins + original
            // reservation together. No wait, kill or replacement on Drop.
            mem::forget(inner);
        }
    }
}
impl LaunchInner {
    fn fail(&mut self, error: Error) -> Error {
        let first = *self.first_failure.get_or_insert(error);
        self.endpoint.cancel();
        first
    }
    fn launch(&mut self, id: PendingElevationId) -> Result<(), Error> {
        // Handoff::receive consumed the one LaunchClaimed transition BEFORE this
        // external call. There is no public identifier/launch or retry method.
        self.endpoint.client.inner_mut().fence()?;
        let connection = self
            .endpoint
            .client
            .inner_ref()
            .connection
            .as_ref()
            .ok_or(Error::InvalidPhase)?;
        let target = connection.installation.service();
        let executable = Wide::new(target).map_err(ClientError::Service)?;
        let arguments =
            Wide::new(format!("pair {}", id.argument())).map_err(ClientError::Service)?;
        let directory =
            Wide::new(target.parent().ok_or(Error::InvalidPhase)?).map_err(ClientError::Service)?;
        let mut info = SHELLEXECUTEINFOW {
            cbSize: mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            lpVerb: w!("runas"),
            lpFile: executable.ptr(),
            lpParameters: arguments.ptr(),
            lpDirectory: directory.ptr(),
            nShow: 0,
            ..Default::default()
        };
        self.endpoint.client.inner_mut().fence()?;
        self.unknown_launch = true;
        // SAFETY: only the original authenticated Starter's pinned fixed helper;
        // all strings remain owned through Windows' synchronous consent call.
        // This is not generally interruptible; the original deadline is checked
        // after return BEFORE identity binding. No wait-for-exit occurs here.
        let launched = unsafe { ShellExecuteExW(&mut info) };
        match launched {
            Err(error) if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => {
                self.unknown_launch = false;
                return Err(Error::UserCancelled);
            }
            Err(error) => {
                return Err(Error::Native {
                    operation: ServiceOperation::LaunchElevatedHelper,
                    hresult: error.code().0,
                });
            }
            Ok(()) => (),
        }
        if info.hProcess.is_invalid() {
            return Err(Error::LaunchUnconfirmed);
        }
        let handle = Handle::new(info.hProcess)?;
        // Adopt before ANY failing post-launch check. Even late/failed metadata
        // must retain the actual process, not silently drop it as never launched.
        self.helper = Some(HelperProcess {
            handle,
            pid: 0,
            created: 0,
        });
        self.unknown_launch = false;
        self.endpoint.client.inner_mut().fence()?;
        let helper = self.helper.as_mut().ok_or(Error::LaunchUnconfirmed)?;
        // SAFETY: retained actual ShellExecuteEx result, not a supplied PID.
        helper.pid = unsafe { GetProcessId(helper.handle.0) };
        helper.created = process_identity(helper.handle.0, helper.pid)
            .map_err(|error| peer_error_at(Stage::QueryServer, error))?;
        helper.recheck(&mut self.endpoint.client)?;
        self.endpoint.send_launched(helper.pid, helper.created)
    }
    fn live_helper(&mut self) -> Result<(), Error> {
        if self.endpoint.handoff.closing() {
            return Ok(());
        }
        if let Some(helper) = self.helper.as_ref() {
            if let Some(code) = helper.exit()? {
                self.helper_exit = Some(code);
                return Err(Error::HelperExited { exit_code: code });
            }
            helper.recheck(&mut self.endpoint.client)?;
        }
        Ok(())
    }
    fn poll(&mut self) -> Result<PairingLaunchProgress, Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let result = (|| match self.endpoint.poll()? {
            Event::Launch(id) => {
                self.launch(id)?;
                Ok(PairingLaunchProgress::Pending)
            }
            Event::Pending => {
                self.live_helper()?;
                Ok(PairingLaunchProgress::Pending)
            }
            Event::Written => {
                self.live_helper()?;
                Ok(PairingLaunchProgress::BindingWritten)
            }
            Event::Bound => {
                self.live_helper()?;
                Ok(PairingLaunchProgress::Bound)
            }
            Event::Closing => Ok(PairingLaunchProgress::Closing),
            Event::PrepareRenderer(_) | Event::ResumeRenderer(_) => Err(Error::Protocol),
            Event::PeerClosed => {
                if !self.drain_resources()? {
                    return Ok(PairingLaunchProgress::CleanupPending);
                }
                self.endpoint.budget()?;
                if let Some(error) = self.first_failure {
                    return Err(error);
                }
                if self.helper_exit != Some(0) {
                    return Err(Error::LaunchUnconfirmed);
                }
                Ok(PairingLaunchProgress::Closed)
            }
        })();
        result.map_err(|error| self.fail(error))
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        if !self.endpoint.handoff.closed() {
            self.fail(Error::Cancelled);
        }
        self.drain_resources()
    }
    fn drain_resources(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        // Closing the drained Starter promptly revokes the service slot. The
        // TRANSFERRED reservation stays here until the helper is actually gone.
        let pipe_drained = self.endpoint.client.drain().map_err(|error| {
            let error = Error::Client(error);
            self.cleanup_failure.get_or_insert(error);
            error
        })?;
        if self.unknown_launch {
            return Err(Error::LaunchUnconfirmed);
        }
        if let Some(helper) = self.helper.as_ref() {
            match helper.exit() {
                Ok(Some(code)) => {
                    self.helper_exit = Some(code);
                    if code != 0 {
                        self.first_failure
                            .get_or_insert(Error::HelperExited { exit_code: code });
                    }
                }
                Ok(None) => return Ok(false),
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    return Err(error);
                }
            }
        }
        if !release_allowed(
            pipe_drained,
            self.unknown_launch,
            self.helper.is_some(),
            self.helper_exit,
        ) {
            return Ok(false);
        }
        drop(self.helper.take());
        cleanup_state().map_err(|error| {
            let error = Error::Client(error);
            self.cleanup_failure.get_or_insert(error);
            error
        })?;
        drop(self.reservation.take());
        self.drained = true;
        Ok(true)
    }
}

struct HelperRunInner {
    endpoint: Endpoint,
    renderer: Option<HelperRendererLaunch>,
    // Same original Helper-client reservation, retained even after pipe drain
    // until its created renderer and desktop owners are actually drained.
    reservation: Option<Reservation>,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
    drained: bool,
}
struct HelperRun {
    inner: Option<Box<HelperRunInner>>,
}
impl HelperRun {
    fn new(mut endpoint: Endpoint) -> Result<Self, Error> {
        let reservation = endpoint
            .client
            .inner_mut()
            .connection
            .as_mut()
            .ok_or(Error::InvalidPhase)?
            .reservation
            .take()
            .ok_or(Error::InvalidPhase)?;
        Ok(Self {
            inner: Some(Box::new(HelperRunInner {
                endpoint,
                renderer: None,
                reservation: Some(reservation),
                first_failure: None,
                cleanup_failure: None,
                drained: false,
            })),
        })
    }
    fn inner_mut(&mut self) -> &mut HelperRunInner {
        self.inner
            .as_deref_mut()
            .expect("helper run exists until Drop")
    }
    fn poll(&mut self) -> Result<bool, Error> {
        let inner = self.inner_mut();
        if let Some(error) = inner.first_failure {
            return Err(error);
        }
        let result = (|| {
            match inner.endpoint.poll()? {
                Event::PrepareRenderer(request) => {
                    if inner.renderer.is_some() {
                        return Err(Error::InvalidPhase);
                    }
                    inner.renderer = Some(HelperRendererLaunch::new());
                    let (request, process) = inner
                        .renderer
                        .as_mut()
                        .ok_or(Error::InvalidPhase)?
                        .begin(&mut inner.endpoint.client, request)?;
                    inner.endpoint.send_renderer_launched(request, process)?;
                }
                Event::ResumeRenderer(request) => {
                    inner
                        .renderer
                        .as_mut()
                        .ok_or(Error::InvalidPhase)?
                        .resume(&mut inner.endpoint.client, request)?;
                    inner.endpoint.renderer_resumed()?;
                }
                Event::Closing => {
                    if let Some(renderer) = inner.renderer.as_mut() {
                        renderer.close_requested();
                    }
                }
                Event::PeerClosed => {
                    if let Some(renderer) = inner.renderer.as_mut() {
                        renderer.close_requested();
                        if !renderer.drain()? {
                            return Ok(false);
                        }
                        if let Some(error) = renderer.failure() {
                            return Err(error);
                        }
                    }
                    if !inner.endpoint.client.drain()? {
                        return Ok(false);
                    }
                    inner.endpoint.budget()?;
                    cleanup_state()?;
                    drop(inner.reservation.take());
                    inner.drained = true;
                    return Ok(true);
                }
                Event::Launch(_) => return Err(Error::Protocol),
                Event::Pending | Event::Written | Event::Bound => {
                    if !inner.endpoint.handoff.closing()
                        && let Some(renderer) = inner.renderer.as_mut()
                    {
                        renderer.recheck(&mut inner.endpoint.client)?;
                    }
                }
            }
            Ok(false)
        })();
        result.map_err(|error| inner.fail(error))
    }
    fn cancel(&mut self) {
        self.inner_mut().fail(Error::Cancelled);
    }
    fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
    }
}
impl HelperRunInner {
    fn fail(&mut self, error: Error) -> Error {
        let first = *self.first_failure.get_or_insert(error);
        self.endpoint.cancel();
        if let Some(renderer) = self.renderer.as_mut() {
            renderer.cancel();
        }
        first
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        let first = self.fail(Error::Cancelled);
        let pipe = self.endpoint.client.drain().map_err(|error| {
            self.cleanup_failure.get_or_insert(Error::Client(error));
            first
        })?;
        let renderer = match self.renderer.as_mut() {
            Some(renderer) => renderer.drain().map_err(|error| {
                self.cleanup_failure.get_or_insert(error);
                first
            })?,
            None => true,
        };
        if !pipe || !renderer {
            return Ok(false);
        }
        cleanup_state()?;
        drop(self.reservation.take());
        self.drained = true;
        Ok(true)
    }
}
impl Drop for HelperRun {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && !inner.drained
        {
            inner.fail(Error::Cancelled);
            UNHEALTHY.store(true, Ordering::Release);
            // No detached replacement or reservation release. Keep the original
            // client/pending storage AND all child/desktop owners together.
            mem::forget(inner);
        }
    }
}
pub(crate) fn run_pair_helper(id: PendingElevationId) -> Result<(), Error> {
    if HELPER_INVOKED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::InvalidPhase);
    }
    let start = Instant::now();
    let deadline = start
        .checked_add(MAX_LIFETIME)
        .ok_or(ClientError::InvalidDeadline)?;
    let client = PairingClient::connect_helper(start, deadline)?;
    let mut owner = HelperRun::new(Endpoint::helper(client, id)?)?;
    let outcome = loop {
        match owner.poll() {
            Ok(true) => break Ok(()),
            Ok(false) => (),
            Err(error) => break Err(error),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(ClientError::DeadlineElapsed.into());
        }
        thread::sleep(POLL.min(remaining));
    };
    if outcome.is_err() {
        owner.cancel();
    }
    loop {
        match owner.drain() {
            Ok(true) => break,
            Ok(false) => (),
            Err(error) => return outcome.and(Err(error)),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return outcome.and(Err(Error::CleanupUnconfirmed));
        }
        thread::sleep(POLL.min(remaining));
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_client_stage_and_hresult_survive_cli_mapping_without_recursive_error() {
        for (stage, code) in [
            (Stage::Connect, 1),
            (Stage::CreateEvent, 2),
            (Stage::QueryPipe, 3),
            (Stage::ReadPipeSecurity, 4),
            (Stage::QueryOwnIdentity, 5),
            (Stage::QueryServer, 6),
            (Stage::Read, 7),
            (Stage::Write, 8),
            (Stage::PollIo, 9),
            (Stage::CancelIo, 10),
        ] {
            let hresult = 0x8007_0005_u32 as i32;
            let actual = Error::Client(ClientError::Native { stage, hresult }).service_error();
            assert_eq!(
                actual,
                ServiceError::PairingClientNative {
                    stage: code,
                    hresult
                }
            );
            assert!(format!("{actual}").contains("80070005"));
        }
    }
    #[test]
    fn fast_server_close_after_ack_uses_actual_completion_then_eof_not_liveness() {
        // Synthetic native completion fixtures only. The production entry gate
        // is a genuine Close from normal authenticated read, not this classifier.
        assert_eq!(
            terminal_completion(Mode::TerminalAck(40), Completed::Count(40)),
            Ok(TerminalCompletion::AckWritten)
        );
        assert_eq!(
            terminal_completion(Mode::TerminalRead, Completed::Eof),
            Ok(TerminalCompletion::PeerClosed)
        );
        assert_eq!(
            terminal_completion(Mode::Read, Completed::Eof),
            Err(Error::Protocol)
        );
        assert_eq!(
            terminal_completion(Mode::TerminalAck(40), Completed::Eof),
            Err(Error::Protocol)
        );
        assert_eq!(
            terminal_completion(Mode::TerminalAck(40), Completed::Count(39)),
            Err(Error::Protocol)
        );
        for bytes in [vec![], vec![1], vec![0; 40]] {
            assert_eq!(
                terminal_completion(Mode::TerminalRead, Completed::Bytes(bytes)),
                Err(Error::Protocol)
            );
        }
    }
    #[test]
    fn draining_starter_does_not_release_the_transferred_slot_while_helper_is_live() {
        assert!(!release_allowed(true, false, true, None));
        assert!(!release_allowed(false, false, true, Some(0)));
        assert!(!release_allowed(true, true, false, None));
        assert!(release_allowed(true, false, true, Some(0)));
        assert!(release_allowed(true, false, true, Some(1))); // Cleanup, not success.
        assert!(release_allowed(true, false, false, None)); // Confirmed no launch.
        // Original reservation release occurs only at this predicate and after
        // actual close/health checks. No new reservation or native fixture exists.
        let mut releases = 0;
        for (drained, exit) in [(false, None), (true, None), (true, Some(0))] {
            if release_allowed(drained, false, true, exit) {
                releases += 1;
            }
        }
        assert_eq!(releases, 1);
    }
    #[test]
    fn debug_metadata_does_not_include_a_public_id_or_grant_claim() {
        assert_eq!(format!("{:?}", PairingLaunchProgress::Closed), "Closed");
        assert!(!format!("{}", Error::LaunchUnconfirmed).contains("approved"));
    }
}
