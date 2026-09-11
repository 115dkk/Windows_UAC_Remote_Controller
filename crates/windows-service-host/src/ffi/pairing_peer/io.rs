// SPDX-License-Identifier: GPL-2.0-or-later
//! One original server/peer and at most one kernel-borrowed operation. This is
//! not a codec, pairing grant, listener thread or client-connection API.

use std::{
    fmt, mem,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{ERROR_OPERATION_ABORTED, HANDLE},
        System::{Pipes::PeekNamedPipe, Threading::CreateEventW},
    },
    core::{HRESULT, PCWSTR},
};

use super::super::overlapped_pipe::{
    BufferLimits, Completed, EventHandle, IoError, Kind, PendingOperation,
};
use super::{
    BOUNDARY_HEALTH, Handle, PairingPeer, PairingPeerError as Error, PairingPeerRole,
    PairingPeerStage as Stage, PairingServerEndpoint, cleanup_state, native_error,
    service_positive,
};

const MAX_MESSAGE: usize = 4096;
const READ_CAPACITY: usize = MAX_MESSAGE + 1;
const MAX_LIFETIME: Duration = Duration::from_secs(5 * 60);
const LIMITS: BufferLimits = BufferLimits {
    max_read: READ_CAPACITY,
    max_write: MAX_MESSAGE,
};

mod listener;
pub(crate) use listener::{
    AttemptWindow, ListenProgress, StarterAdmission, UnboundPairingListener,
};

impl EventHandle for Handle {
    fn raw_event(&self) -> HANDLE {
        self.raw()
    }
}

/// Transport observations only. Written means exactly this pipe write completed,
/// not that a peer accepted it or that a device was enrolled.
pub enum PairingPipeProgress {
    Pending,
    Connected,
    Read(Vec<u8>),
    Written,
    Idle,
}
impl fmt::Debug for PairingPipeProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pending => "PairingPipeProgress::Pending",
            Self::Connected => "PairingPipeProgress::Connected",
            Self::Read(_) => "PairingPipeProgress::Read(redacted)",
            Self::Written => "PairingPipeProgress::Written",
            Self::Idle => "PairingPipeProgress::Idle",
        })
    }
}

/// Thread-confined by the original endpoint's Rc context. No raw handle, native
/// buffer or peer authority can be extracted. The enclosing trusted ceremony
/// supplies ORIGINAL monotonic times; these values alone prove no fresh consent.
pub struct PairingPipe {
    inner: Option<Box<Inner>>,
}
impl fmt::Debug for PairingPipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingPipe(redacted)")
    }
}
impl PairingPipe {
    /// Does not renew an existing ceremony: accepts only a still-live original
    /// interval in (0, 5min]. Connect is an explicit, single-use next operation.
    pub fn new(
        endpoint: PairingServerEndpoint,
        started_at: Instant,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let budget = OriginalBudget::new(started_at, deadline, Instant::now())?;
        let mut inner = Box::new(Inner {
            connection: Some(Connection::Server(endpoint)),
            operation: None,
            phase: Phase::New,
            budget,
            first_failure: None,
            cleanup_failure: None,
            drained: false,
        });
        inner.fence()?;
        Ok(Self { inner: Some(inner) })
    }
    pub fn begin_connect(&mut self) -> Result<(), Error> {
        self.inner_mut().begin(Kind::Connect)
    }
    /// Reads one message into a fixed 4097-byte detection buffer. Zero bytes,
    /// 4097 bytes, EOF or MORE_DATA cannot become a successful application message.
    pub fn begin_read(&mut self) -> Result<(), Error> {
        self.inner_mut().begin(Kind::Read(READ_CAPACITY))
    }
    /// Copies one nonempty message (at most 4096 bytes) before the final native
    /// identity/deadline fence. A caller buffer never becomes kernel-borrowed.
    pub fn begin_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.inner_mut().begin(Kind::Write(bytes))
    }
    /// Nonblocking: at most one native completion query. No success/payload is
    /// returned until a fresh original peer + deadline check AFTER completion.
    pub fn poll(&mut self) -> Result<PairingPipeProgress, Error> {
        self.inner_mut().poll()
    }
    /// Downward logical cancellation only. Even a successful CancelIoEx or
    /// ERROR_NOT_FOUND does not mark the operation or owner drained.
    pub fn cancel(&mut self) {
        self.inner_mut().fail(Error::Cancelled);
    }
    /// Cleanup only; closes logical authority first, then queries completion at
    /// most once. true means native I/O is quiescent and this pipe/operation have
    /// been released. Shared installation/SCM context may remain in the sibling;
    /// this does not assert all underlying SCM close results were confirmed.
    /// It does not clear first_failure or indicate ceremony/transport success.
    pub fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
    }
    pub fn is_closed(&self) -> bool {
        self.inner_ref().phase == Phase::Closed
    }
    pub fn is_drained(&self) -> bool {
        self.inner_ref().drained
    }
    pub fn first_failure(&self) -> Option<Error> {
        self.inner_ref().first_failure
    }
    /// Additional cleanup observation, never a replacement for the first cause.
    pub fn cleanup_failure(&self) -> Option<Error> {
        self.inner_ref().cleanup_failure
    }
    /// Metadata is available only after actual connect + native authentication,
    /// and only after a fresh original-peer check. It is not a grant.
    pub fn role(&mut self) -> Result<PairingPeerRole, Error> {
        let inner = self.inner_mut();
        inner.fence()?;
        match inner.connection.as_ref() {
            Some(Connection::Peer(peer)) => Ok(peer.role()),
            _ => Err(inner.fail(Error::InvalidPhase)),
        }
    }
    pub fn session_id(&mut self) -> Result<u32, Error> {
        let inner = self.inner_mut();
        inner.fence()?;
        match inner.connection.as_ref() {
            Some(Connection::Peer(peer)) => Ok(peer.session_id()),
            _ => Err(inner.fail(Error::InvalidPhase)),
        }
    }
    pub(crate) fn check_live(&mut self) -> Result<(), Error> {
        self.inner_mut().fence()
    }
    /// One private pre-Offer policy capture. All resources are prepared before
    /// the final original deadline/identity fence, then retained before watcharm.
    pub(crate) fn prepare_uac_policy(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            inner.fence()?;
            if inner.phase != Phase::Connected || inner.operation.is_some() {
                return Err(Error::InvalidPhase);
            }
            match inner.connection.as_mut() {
                Some(Connection::Peer(peer)) => peer.prepare_uac_policy_resources()?,
                _ => return Err(Error::InvalidPhase),
            }
            // Even unarmed resources already belong to this exact peer. Late
            // failure cannot leave a watch/key owner detached from its drain.
            inner.fence_before_uac_policy_arm()?;
            match inner.connection.as_mut() {
                Some(Connection::Peer(peer)) => peer.arm_uac_policy()?,
                _ => return Err(Error::InvalidPhase),
            }
            inner.fence()
        })();
        result.map_err(|error| inner.fail(error))
    }
    pub(crate) fn check_uac_policy(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            inner.fence()?;
            match inner.connection.as_mut() {
                Some(Connection::Peer(peer)) => peer.check_uac_policy()?,
                _ => return Err(Error::InvalidPhase),
            }
            inner.fence()
        })();
        result.map_err(|error| inner.fail(error))
    }
    /// The fixed protocol expects no further input after its one matched frame
    /// until Close. Observe queued bytes without arming an unfinishable idle read.
    pub(crate) fn check_input_quiet(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        inner.fence()?;
        let pipe = inner.pipe()?;
        let mut available = 0;
        // SAFETY: retained OVERLAPPED pipe, zero-byte nonconsuming metadata
        // query; one initialized scalar, no payload buffer or caller pointer.
        unsafe { PeekNamedPipe(pipe, None, 0, None, Some(&mut available), None) }
            .map_err(|error| inner.fail(native_error(Stage::QueryPeer, error)))?;
        if available != 0 {
            return Err(inner.fail(Error::InvalidMessage));
        }
        inner.fence()
    }

    /// Corroborates a tuple received on the ORIGINAL Starter pipe against this
    /// actual Helper owner. No raw metadata/grant is returned or reconstructed.
    pub(crate) fn match_launched_helper(
        &mut self,
        starter: &mut Self,
        pid: u32,
        created: u64,
    ) -> Result<(), Error> {
        let result = (|| {
            self.check_live()?;
            starter.check_live()?;
            let helper_inner = self.inner_ref();
            let starter_inner = starter.inner_ref();
            let (Some(Connection::Peer(helper)), Some(Connection::Peer(gui))) = (
                helper_inner.connection.as_ref(),
                starter_inner.connection.as_ref(),
            ) else {
                return Err(Error::InvalidPhase);
            };
            if helper.role() != PairingPeerRole::Helper
                || gui.role() != PairingPeerRole::Starter
                || !std::rc::Rc::ptr_eq(&helper.endpoint.context, &gui.endpoint.context)
                || helper.interactive != gui.interactive
                || helper.pid != pid
                || helper.created != created
                || helper_inner.budget.started_at != starter_inner.budget.started_at
                || helper_inner.budget.deadline != starter_inner.budget.deadline
            {
                return Err(Error::Rejected);
            }
            self.check_live()?;
            starter.check_live()?;
            Ok(())
        })();
        if let Err(error) = result {
            self.inner_mut().fail(error);
            starter.inner_mut().fail(error);
        }
        result
    }
    fn inner_ref(&self) -> &Inner {
        self.inner
            .as_deref()
            .expect("pairing pipe owner exists until Drop")
    }
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner
            .as_deref_mut()
            .expect("pairing pipe owner exists until Drop")
    }
}
impl Drop for PairingPipe {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.fail(Error::Cancelled);
            if inner.in_flight() || inner.drain_uac_policy().is_err() {
                BOUNDARY_HEALTH.quarantine();
                // This is the WHOLE owner, not just OVERLAPPED/storage/event:
                // original pipe, policy key/event, peer process, installation/
                // SCM pins, original deadline and reservation remain together. At most two such
                // owners can exist; the retained pair reservation blocks any
                // replacement; shared health also rejects positive sibling use.
                // No autonomous wait/retry/process kill occurs.
                mem::forget(inner);
            }
            // With no outstanding native borrow, normal member Drop is safe.
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    New,
    Connecting,
    Connected,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationKind {
    Connect,
    Read,
    Write(usize),
}
impl OperationKind {
    fn from_kind(kind: Kind<'_>) -> Result<Self, Error> {
        match kind {
            Kind::Connect => Ok(Self::Connect),
            Kind::Read(READ_CAPACITY) => Ok(Self::Read),
            Kind::Write(bytes) if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE => {
                Ok(Self::Write(bytes.len()))
            }
            Kind::Read(_) | Kind::Write(_) => Err(Error::InvalidMessage),
        }
    }
    fn stage(self) -> Stage {
        match self {
            Self::Connect => Stage::Connect,
            Self::Read => Stage::Read,
            Self::Write(_) => Stage::Write,
        }
    }
}
fn require_start(phase: Phase, kind: OperationKind, operation_present: bool) -> Result<(), Error> {
    if operation_present {
        return Err(Error::Busy);
    }
    match (phase, kind) {
        (Phase::New, OperationKind::Connect)
        | (Phase::Connected, OperationKind::Read | OperationKind::Write(_)) => Ok(()),
        _ => Err(Error::InvalidPhase),
    }
}

struct OriginalBudget {
    started_at: Instant,
    deadline: Instant,
    last_observed: Instant,
}
impl OriginalBudget {
    fn new(started_at: Instant, deadline: Instant, now: Instant) -> Result<Self, Error> {
        let span = deadline
            .checked_duration_since(started_at)
            .ok_or(Error::InvalidDeadline)?;
        if span.is_zero() || span > MAX_LIFETIME || now < started_at {
            return Err(Error::InvalidDeadline);
        }
        if now >= deadline {
            return Err(Error::DeadlineElapsed);
        }
        Ok(Self {
            started_at,
            deadline,
            last_observed: now,
        })
    }
    fn observe(&mut self, now: Instant) -> Result<(), Error> {
        if now < self.started_at || now < self.last_observed {
            return Err(Error::InvalidDeadline);
        }
        self.last_observed = now;
        if now >= self.deadline {
            Err(Error::DeadlineElapsed)
        } else {
            Ok(())
        }
    }
}
enum Connection {
    Server(PairingServerEndpoint),
    Peer(PairingPeer),
}
impl Connection {
    fn raw(&self) -> HANDLE {
        match self {
            Self::Server(endpoint) => endpoint.pipe.raw(),
            Self::Peer(peer) => peer.endpoint.pipe.raw(),
        }
    }
    fn recheck(&mut self) -> Result<(), Error> {
        match self {
            Self::Server(endpoint) => endpoint.context.recheck(),
            Self::Peer(peer) => peer.recheck(),
        }
    }
    fn drain_uac_policy(&mut self) -> Result<(), Error> {
        match self {
            Self::Server(_) => Ok(()),
            Self::Peer(peer) => peer.drain_uac_policy(),
        }
    }
}
struct Operation {
    pending: PendingOperation<Handle>,
    kind: OperationKind,
    cancel_requested: bool,
}
struct Inner {
    // PendingOperation drops before its original connection on a quiescent
    // normal drop. In-flight Drop retains this entire Box instead.
    operation: Option<Operation>,
    connection: Option<Connection>,
    phase: Phase,
    budget: OriginalBudget,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
    drained: bool,
}
impl Inner {
    fn fence_before_uac_policy_arm(&mut self) -> Result<(), Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let result = service_positive(|| {
            self.budget.observe(Instant::now())?;
            match self.connection.as_mut() {
                Some(Connection::Peer(peer)) => peer.check_before_uac_policy_arm()?,
                _ => return Err(Error::InvalidPhase),
            }
            self.budget.observe(Instant::now())?;
            cleanup_state()
        });
        result.map_err(|error| self.fail(error))
    }
    fn drain_uac_policy(&mut self) -> Result<(), Error> {
        if let Some(connection) = self.connection.as_mut() {
            connection.drain_uac_policy().inspect_err(|&error| {
                self.cleanup_failure.get_or_insert(error);
            })?;
        }
        Ok(())
    }
    fn in_flight(&self) -> bool {
        self.operation
            .as_ref()
            .is_some_and(|op| op.pending.in_flight())
    }
    fn pipe(&self) -> Result<HANDLE, Error> {
        self.connection
            .as_ref()
            .map(Connection::raw)
            .ok_or(Error::Closed)
    }
    fn fence(&mut self) -> Result<(), Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let result = service_positive(|| {
            self.budget.observe(Instant::now())?;
            self.connection.as_mut().ok_or(Error::Closed)?.recheck()?;
            // Native metadata checks/allocation do not renew the original budget.
            self.budget.observe(Instant::now())?;
            cleanup_state()
        });
        result.map_err(|error| self.fail(error))
    }
    fn fail(&mut self, error: Error) -> Error {
        let first = *self.first_failure.get_or_insert(error);
        self.phase = Phase::Closed;
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
        let operation_kind = OperationKind::from_kind(kind).map_err(|error| self.fail(error))?;
        require_start(self.phase, operation_kind, self.operation.is_some())
            .map_err(|error| self.fail(error))?;
        // SAFETY: unnamed, noninheritable manual-reset event, initially unsignaled.
        // No existing object/path/security or external process is changed.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| self.fail(native_error(Stage::CreateEvent, error)))?;
        let event = Handle::new(event, Stage::CreateEvent).map_err(|error| self.fail(error))?;
        let pending = PendingOperation::prepare(kind, LIMITS, event)
            .map_err(|error| self.fail(io_error(operation_kind.stage(), error)))?;
        self.operation = Some(Operation {
            pending,
            kind: operation_kind,
            cancel_requested: false,
        });
        // All buffers/owned event exist before this final fresh deadline/cancel/
        // service-or-peer check. Never issue first and then discover expiry.
        self.fence()?;
        let pipe = self.pipe().map_err(|error| self.fail(error))?;
        let issued = service_positive(|| {
            self.operation
                .as_mut()
                .ok_or(Error::InvalidPhase)?
                .pending
                .issue(pipe)
                .map_err(|error| io_error(operation_kind.stage(), error))
        });
        if let Err(error) = issued {
            return Err(self.fail(error));
        }
        if operation_kind == OperationKind::Connect {
            self.phase = Phase::Connecting;
        }
        // Synchronous API success still requires the same completion path.
        Ok(())
    }
    fn poll(&mut self) -> Result<PairingPipeProgress, Error> {
        self.fence()?;
        if self.operation.is_none() {
            return if self.phase == Phase::Connected {
                Ok(PairingPipeProgress::Idle)
            } else {
                Err(self.fail(Error::InvalidPhase))
            };
        }
        let pipe = self.pipe().map_err(|error| self.fail(error))?;
        let operation = match self.operation.as_mut() {
            Some(operation) => operation,
            None => return Err(self.fail(Error::InvalidPhase)),
        };
        let kind = operation.kind;
        let completed = match operation.pending.poll(pipe) {
            Ok(None) => {
                self.fence()?;
                return Ok(PairingPipeProgress::Pending);
            }
            Ok(Some(completed)) => completed,
            Err(error) => return Err(self.fail(io_error(kind.stage(), error))),
        };
        if self.in_flight() {
            return Err(self.fail(Error::Malformed));
        }
        // Actual native completion was observed. Drop the exact operation/event
        // before the final fence so an event close failure cannot hide in success.
        drop(self.operation.take());
        let progress = classify_completion(kind, completed).map_err(|error| self.fail(error))?;
        if kind == OperationKind::Connect {
            self.fence()?;
            let endpoint = match self.connection.take() {
                Some(Connection::Server(endpoint)) => endpoint,
                _ => return Err(self.fail(Error::InvalidPhase)),
            };
            let peer = endpoint
                .authenticate_connected()
                .map_err(|error| self.fail(error))?;
            self.connection = Some(Connection::Peer(peer));
            self.phase = Phase::Connected;
        }
        // Discard a completed read/write/connect on cancel/expiry/identity loss.
        // No payload or success crosses this fence merely because the kernel ran.
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
            let cancel_requested = operation.cancel_requested;
            let result = operation.pending.poll(pipe);
            match result {
                Ok(None) => return Ok(false),
                Ok(Some(_)) if self.in_flight() => {
                    self.cleanup_failure.get_or_insert(Error::Malformed);
                    return Err(first);
                }
                Ok(Some(_)) => (), // Cleanup never publishes bytes or authenticates.
                Err(error) => {
                    if !expected_cancel_completion(error, cancel_requested, self.in_flight()) {
                        self.cleanup_failure
                            .get_or_insert(io_error(Stage::PollIo, error));
                    }
                    if self.in_flight() {
                        return Err(first);
                    }
                }
            }
        }
        // Prepared/unissued or confirmed terminal only; no outstanding borrow.
        drop(self.operation.take());
        // Retain the whole original peer/pipe if the watched key/event release
        // is uncertain. Closing the pipe alone must not free this reservation.
        self.drain_uac_policy().map_err(|_| first)?;
        drop(self.connection.take());
        if let Err(error) = cleanup_state() {
            self.cleanup_failure.get_or_insert(error);
            return Err(first);
        }
        self.drained = true;
        Ok(true)
    }
}
fn expected_cancel_completion(error: IoError, cancel_requested: bool, in_flight: bool) -> bool {
    let aborted = IoError::Native {
        hresult: HRESULT::from_win32(ERROR_OPERATION_ABORTED.0).0,
    };
    cancel_requested && !in_flight && error == aborted
}
fn io_error(stage: Stage, error: IoError) -> Error {
    match error {
        IoError::Native { hresult } => Error::Native { stage, hresult },
        IoError::InvalidBuffer => Error::InvalidMessage,
        IoError::InvalidPhase => Error::InvalidPhase,
    }
}
fn classify_completion(
    kind: OperationKind,
    completed: Completed,
) -> Result<PairingPipeProgress, Error> {
    match (kind, completed) {
        (OperationKind::Connect, Completed::Count(0)) => Ok(PairingPipeProgress::Connected),
        (OperationKind::Read, Completed::Bytes(bytes))
            if !bytes.is_empty() && bytes.len() <= MAX_MESSAGE =>
        {
            Ok(PairingPipeProgress::Read(bytes))
        }
        (OperationKind::Write(expected), Completed::Count(count))
            if expected != 0 && count == expected =>
        {
            Ok(PairingPipeProgress::Written)
        }
        (_, Completed::Eof) => Err(Error::EndOfStream),
        _ => Err(Error::InvalidMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_interval_rejects_invalid_future_and_expired_construction() {
        let start = Instant::now();
        assert!(matches!(
            OriginalBudget::new(start, start, start),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(start, start + MAX_LIFETIME + Duration::from_nanos(1), start),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(
                start + Duration::from_secs(1),
                start + Duration::from_secs(2),
                start
            ),
            Err(Error::InvalidDeadline)
        ));
        assert!(matches!(
            OriginalBudget::new(
                start,
                start + Duration::from_secs(1),
                start + Duration::from_secs(1)
            ),
            Err(Error::DeadlineElapsed)
        ));
        assert!(OriginalBudget::new(start, start + MAX_LIFETIME, start).is_ok());
    }
    #[test]
    fn delayed_wrapper_and_repeated_operations_cannot_refresh_original_budget() {
        let start = Instant::now();
        let deadline = start + MAX_LIFETIME;
        let mut budget =
            OriginalBudget::new(start, deadline, deadline - Duration::from_secs(1)).unwrap();
        for millis in [100, 500, 999] {
            assert!(
                budget
                    .observe(deadline - Duration::from_secs(1) + Duration::from_millis(millis))
                    .is_ok()
            );
            assert_eq!(budget.started_at, start);
            assert_eq!(budget.deadline, deadline);
        }
        assert_eq!(budget.observe(deadline), Err(Error::DeadlineElapsed));
    }
    #[test]
    fn post_allocation_or_post_completion_expiry_and_clock_regression_reject() {
        let start = Instant::now();
        let mut budget = OriginalBudget::new(start, start + Duration::from_secs(1), start).unwrap();
        assert!(budget.observe(start + Duration::from_millis(999)).is_ok());
        assert_eq!(budget.observe(start), Err(Error::InvalidDeadline));
        assert_eq!(
            budget.observe(start + Duration::from_secs(1)),
            Err(Error::DeadlineElapsed)
        );
    }
    #[test]
    fn connect_is_once_and_one_operation_blocks_any_second_issue() {
        assert_eq!(
            require_start(Phase::New, OperationKind::Connect, false),
            Ok(())
        );
        for phase in [Phase::Connecting, Phase::Connected, Phase::Closed] {
            assert_eq!(
                require_start(phase, OperationKind::Connect, false),
                Err(Error::InvalidPhase)
            );
        }
        for kind in [
            OperationKind::Connect,
            OperationKind::Read,
            OperationKind::Write(1),
        ] {
            assert_eq!(
                require_start(Phase::Connected, kind, true),
                Err(Error::Busy)
            );
            assert!(require_start(Phase::Closed, kind, false).is_err());
        }
        assert!(require_start(Phase::New, OperationKind::Read, false).is_err());
        assert!(require_start(Phase::Connected, OperationKind::Read, false).is_ok());
        assert!(require_start(Phase::Connected, OperationKind::Write(1), false).is_ok());
    }
    #[test]
    fn message_limits_include_one_extra_read_byte_but_no_empty_write() {
        assert_eq!(LIMITS.max_read, 4097);
        assert_eq!(LIMITS.max_write, 4096);
        assert!(OperationKind::from_kind(Kind::Write(&[])).is_err());
        assert!(OperationKind::from_kind(Kind::Write(&vec![0; MAX_MESSAGE])).is_ok());
        assert!(OperationKind::from_kind(Kind::Write(&vec![0; READ_CAPACITY])).is_err());
        for size in [0, READ_CAPACITY, READ_CAPACITY + 1] {
            assert!(
                classify_completion(OperationKind::Read, Completed::Bytes(vec![0; size])).is_err()
            );
        }
        assert!(matches!(
            classify_completion(OperationKind::Read, Completed::Bytes(vec![0; MAX_MESSAGE])),
            Ok(PairingPipeProgress::Read(_))
        ));
    }
    #[test]
    fn incomplete_wrong_kind_and_eof_are_not_success() {
        assert!(matches!(
            classify_completion(OperationKind::Connect, Completed::Count(0)),
            Ok(PairingPipeProgress::Connected)
        ));
        assert!(classify_completion(OperationKind::Connect, Completed::Count(1)).is_err());
        assert!(classify_completion(OperationKind::Read, Completed::Count(1)).is_err());
        assert!(classify_completion(OperationKind::Write(2), Completed::Count(1)).is_err());
        assert!(matches!(
            classify_completion(OperationKind::Write(2), Completed::Count(2)),
            Ok(PairingPipeProgress::Written)
        ));
        assert!(matches!(
            classify_completion(OperationKind::Read, Completed::Eof),
            Err(Error::EndOfStream)
        ));
    }
    #[test]
    fn public_progress_debug_never_includes_message_bytes() {
        assert_eq!(
            format!("{:?}", PairingPipeProgress::Read(b"fixture only".to_vec())),
            "PairingPipeProgress::Read(redacted)"
        );
    }
    #[test]
    fn first_failure_survives_cancel_and_distinct_cleanup_failure() {
        // Negative state-only fixture: contains NO endpoint, peer, event or I/O;
        // cannot mint native admission and never calls a native API.
        let now = Instant::now();
        let mut inner = Inner {
            operation: None,
            connection: None,
            phase: Phase::New,
            budget: OriginalBudget::new(now, now + Duration::from_secs(1), now).unwrap(),
            first_failure: None,
            cleanup_failure: None,
            drained: false,
        };
        assert_eq!(inner.fail(Error::Rejected), Error::Rejected);
        assert_eq!(inner.phase, Phase::Closed);
        assert!(!inner.drained);
        let cleanup = Error::Native {
            stage: Stage::PollIo,
            hresult: -1,
        };
        inner.cleanup_failure = Some(cleanup);
        assert_eq!(inner.fail(Error::Cancelled), Error::Rejected);
        assert_eq!(inner.fail(Error::DeadlineElapsed), Error::Rejected);
        assert_eq!(inner.first_failure, Some(Error::Rejected));
        assert_eq!(inner.cleanup_failure, Some(cleanup));
        assert!(!inner.drained);
    }
    #[test]
    fn only_confirmed_abort_after_requested_cancel_is_expected_quiescence() {
        let aborted = IoError::Native {
            hresult: HRESULT::from_win32(ERROR_OPERATION_ABORTED.0).0,
        };
        assert!(expected_cancel_completion(aborted, true, false));
        assert!(!expected_cancel_completion(aborted, true, true));
        assert!(!expected_cancel_completion(aborted, false, false));
        assert!(!expected_cancel_completion(
            IoError::Native {
                hresult: HRESULT::from_win32(5).0
            },
            true,
            true
        ));
        assert!(!expected_cancel_completion(
            IoError::InvalidPhase,
            true,
            false
        ));
    }
}
