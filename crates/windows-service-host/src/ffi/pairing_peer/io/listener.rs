// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed-resource idle Connect ownership. No attempt timer/read/write exists
//! until an actual authenticated Starter is admitted. All transitions take the
//! original inner owner only on success; failure leaves cancellation/drain owned.

use super::super::super::overlapped_pipe::PendingOperation;
use super::super::{PairingPeerRole, ServiceContext};
use super::{
    BOUNDARY_HEALTH, Completed, Connection, Error, Handle, Inner, Kind, LIMITS, MAX_LIFETIME,
    Operation, OperationKind, OriginalBudget, PairingPipe, PairingServerEndpoint, Phase, Stage,
    cleanup_state, expected_cancel_completion, io_error, native_error, service_positive,
};
use std::{fmt, mem, rc::Rc, time::Instant};
use windows::{Win32::System::Threading::CreateEventW, core::PCWSTR};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ListenProgress {
    Pending,
    Connected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenPhase {
    New,
    Connecting,
    Connected,
    Closed,
}

/// Sealed native admission time, not a serialized/request-supplied clock. No
/// Clone, public constructor, reset or later Helper-derived deadline exists.
pub(crate) struct AttemptWindow {
    started: Instant,
    deadline: Instant,
}
impl fmt::Debug for AttemptWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttemptWindow(original)")
    }
}
impl AttemptWindow {
    fn at_admission(started: Instant) -> Result<Self, Error> {
        let deadline = started
            .checked_add(MAX_LIFETIME)
            .ok_or(Error::InvalidDeadline)?;
        Ok(Self { started, deadline })
    }
    pub(crate) fn started(&self) -> Instant {
        self.started
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    fn budget(&self) -> Result<OriginalBudget, Error> {
        OriginalBudget::new(self.started, self.deadline, Instant::now())
    }
    fn check(&self) -> Result<(), Error> {
        self.budget().map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transfer {
    Available,
    Claimed,
    Bound,
}
impl Transfer {
    fn claim(&mut self) -> Result<(), Error> {
        if *self != Self::Available {
            return Err(Error::InvalidPhase);
        }
        *self = Self::Claimed;
        Ok(())
    }
}
pub(crate) struct StarterAdmission {
    starter: Option<PairingPipe>,
    window: Option<AttemptWindow>,
    context: Rc<ServiceContext>,
    helper: Transfer,
    failed: bool,
}
impl fmt::Debug for StarterAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StarterAdmission(native_owned)")
    }
}
impl StarterAdmission {
    fn claim_helper(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidPhase);
        }
        if let Err(error) = self.helper.claim() {
            self.failed = true;
            return Err(error);
        }
        self.check()
    }
    fn check(&mut self) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Cancelled);
        }
        service_positive(|| {
            self.window.as_ref().ok_or(Error::InvalidPhase)?.check()?;
            self.starter
                .as_mut()
                .ok_or(Error::InvalidPhase)?
                .check_live()?;
            self.window.as_ref().ok_or(Error::InvalidPhase)?.check()
        })
    }
    pub(crate) fn take_parts(&mut self) -> Result<(PairingPipe, AttemptWindow), Error> {
        let checked = (|| {
            if self.helper != Transfer::Bound {
                return Err(Error::InvalidPhase);
            }
            self.check()?;
            if self.starter.is_none() || self.window.is_none() {
                return Err(Error::InvalidPhase);
            }
            service_positive(|| Ok(()))
        })();
        if let Err(error) = checked {
            self.failed = true;
            return Err(error);
        }
        // Both values were checked above; no fallible/native operation follows
        // transfer. The caller immediately retains both in its existing session.
        Ok((
            self.starter.take().expect("checked starter owner"),
            self.window.take().expect("checked attempt window"),
        ))
    }
    pub(crate) fn cancel(&mut self) {
        self.failed = true;
        if let Some(starter) = self.starter.as_mut() {
            starter.cancel();
        }
    }
    pub(crate) fn drain(&mut self) -> Result<bool, Error> {
        self.cancel();
        if let Some(starter) = self.starter.as_mut()
            && !starter.drain()?
        {
            return Ok(false);
        }
        drop(self.starter.take());
        self.window = None;
        cleanup_state()?;
        Ok(true)
    }
    pub(crate) fn is_drained(&self) -> bool {
        self.starter.is_none() || self.starter.as_ref().is_some_and(PairingPipe::is_drained)
    }
}

pub(crate) struct UnboundPairingListener {
    inner: Option<Box<ListenerInner>>,
}
impl fmt::Debug for UnboundPairingListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnboundPairingListener(fixed_resource)")
    }
}
impl UnboundPairingListener {
    pub(crate) fn new(endpoint: PairingServerEndpoint) -> Result<Self, Error> {
        let mut inner = Box::new(ListenerInner {
            endpoint: Some(endpoint),
            operation: None,
            phase: ListenPhase::New,
            first_failure: None,
            cleanup_failure: None,
            drained: false,
        });
        inner.fence()?;
        Ok(Self { inner: Some(inner) })
    }
    pub(crate) fn begin_connect(&mut self) -> Result<(), Error> {
        self.inner_mut()?.begin_connect()
    }
    pub(crate) fn poll_connect(&mut self) -> Result<ListenProgress, Error> {
        self.inner_mut()?.poll_connect()
    }
    pub(crate) fn admit_starter(&mut self) -> Result<StarterAdmission, Error> {
        let result = self.admit_checked();
        if let Err(error) = &result
            && let Some(inner) = self.inner.as_mut()
        {
            inner.fail(*error);
        }
        result
    }
    fn admit_checked(&mut self) -> Result<StarterAdmission, Error> {
        let inner = self.inner_mut()?;
        inner.fence()?;
        if inner.phase != ListenPhase::Connected
            || inner.in_flight()
            || inner
                .endpoint
                .as_ref()
                .is_none_or(|endpoint| endpoint.role != PairingPeerRole::Starter)
        {
            return Err(Error::InvalidPhase);
        }
        drop(inner.operation.take()); // Connect completed; event close must be checked.
        cleanup_state()?;
        let endpoint = inner.endpoint.take().ok_or(Error::Closed)?;
        let mut peer = endpoint.authenticate_connected()?;
        peer.recheck()?;
        if crate::entry::stop_requested() {
            return Err(Error::Cancelled);
        }
        // THE only attempt-clock birth, after genuine native authentication.
        let window = AttemptWindow::at_admission(Instant::now())?;
        let context = Rc::clone(&peer.endpoint.context);
        let budget = window.budget()?;
        let mut starter = PairingPipe {
            inner: Some(Box::new(Inner {
                operation: None,
                connection: Some(Connection::Peer(peer)),
                phase: Phase::Connected,
                budget,
                first_failure: None,
                cleanup_failure: None,
                drained: false,
            })),
        };
        starter.check_live()?;
        if crate::entry::stop_requested() {
            return Err(Error::Cancelled);
        }
        // No pending borrow exists on Starter; all failure checks precede take.
        drop(self.inner.take());
        Ok(StarterAdmission {
            starter: Some(starter),
            window: Some(window),
            context,
            helper: Transfer::Available,
            failed: false,
        })
    }
    pub(crate) fn bind_helper(
        &mut self,
        admission: &mut StarterAdmission,
    ) -> Result<PairingPipe, Error> {
        let checked = (|| {
            admission.claim_helper()?;
            let inner = self.inner_mut()?;
            inner.fence()?;
            if !matches!(
                inner.phase,
                ListenPhase::Connecting | ListenPhase::Connected
            ) {
                return Err(Error::InvalidPhase);
            }
            let endpoint = inner.endpoint.as_ref().ok_or(Error::Closed)?;
            if endpoint.role != PairingPeerRole::Helper
                || !Rc::ptr_eq(&endpoint.context, &admission.context)
                || inner.operation.is_none()
            {
                return Err(Error::Rejected);
            }
            let budget = admission
                .window
                .as_ref()
                .ok_or(Error::InvalidPhase)?
                .budget()?;
            admission.check()?;
            inner.fence()?;
            admission.check()?;
            service_positive(|| Ok(()))?;
            Ok(budget)
        })();
        let budget = match checked {
            Ok(budget) => budget,
            Err(error) => {
                admission.failed = true;
                if let Some(inner) = self.inner.as_mut() {
                    inner.fail(error);
                }
                return Err(error);
            }
        };
        // Move the exact PendingOperation, whose storage/event remain stable.
        // No native call, allocation-dependent metadata check or fallible branch
        // follows taking the original box; errors above leave it drainable here.
        let inner = self.inner.take().expect("validated unbound owner");
        let ListenerInner {
            endpoint,
            operation,
            ..
        } = *inner;
        let pipe = PairingPipe {
            inner: Some(Box::new(Inner {
                connection: endpoint.map(Connection::Server),
                operation,
                phase: Phase::Connecting,
                budget,
                first_failure: None,
                cleanup_failure: None,
                drained: false,
            })),
        };
        admission.helper = Transfer::Bound;
        Ok(pipe)
    }
    pub(crate) fn cancel(&mut self) {
        if let Some(inner) = self.inner.as_mut() {
            inner.fail(Error::Cancelled);
        }
    }
    pub(crate) fn drain(&mut self) -> Result<bool, Error> {
        match self.inner.as_mut() {
            Some(inner) => inner.drain(),
            None => Ok(true),
        }
    }
    pub(crate) fn is_drained(&self) -> bool {
        self.inner.as_ref().is_none_or(|inner| inner.drained)
    }
    pub(crate) fn cleanup_failure(&self) -> Option<Error> {
        self.inner.as_ref().and_then(|inner| inner.cleanup_failure)
    }
    fn inner_mut(&mut self) -> Result<&mut ListenerInner, Error> {
        self.inner.as_deref_mut().ok_or(Error::Closed)
    }
}
impl Drop for UnboundPairingListener {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.fail(Error::Cancelled);
            if inner.in_flight() {
                BOUNDARY_HEALTH.quarantine();
                // Whole endpoint/context/reservation plus the original stable
                // operation/event, never only a buffer detached from its pipe.
                mem::forget(inner);
            }
        }
    }
}

struct ListenerInner {
    operation: Option<Operation>,
    endpoint: Option<PairingServerEndpoint>,
    phase: ListenPhase,
    first_failure: Option<Error>,
    cleanup_failure: Option<Error>,
    drained: bool,
}
impl ListenerInner {
    fn in_flight(&self) -> bool {
        self.operation
            .as_ref()
            .is_some_and(|operation| operation.pending.in_flight())
    }
    fn fence(&mut self) -> Result<(), Error> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let result = service_positive(|| {
            self.endpoint
                .as_ref()
                .ok_or(Error::Closed)?
                .context
                .recheck()?;
            cleanup_state()
        });
        result.map_err(|error| self.fail(error))
    }
    fn fail(&mut self, error: Error) -> Error {
        let first = *self.first_failure.get_or_insert(error);
        self.phase = ListenPhase::Closed;
        if let (Some(endpoint), Some(operation)) = (self.endpoint.as_ref(), self.operation.as_mut())
            && operation.pending.in_flight()
            && !operation.cancel_requested
        {
            operation.cancel_requested = true;
            if let Err(error) = operation.pending.cancel(endpoint.pipe.raw()) {
                self.cleanup_failure
                    .get_or_insert(io_error(Stage::CancelIo, error));
            }
        }
        first
    }
    fn begin_connect(&mut self) -> Result<(), Error> {
        self.fence()?;
        if self.phase != ListenPhase::New || self.operation.is_some() {
            return Err(self.fail(Error::InvalidPhase));
        }
        // SAFETY: unnamed noninherited manual-reset event, initialized unsignaled.
        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|error| self.fail(native_error(Stage::CreateEvent, error)))?;
        let event = Handle::new(event, Stage::CreateEvent).map_err(|error| self.fail(error))?;
        let pending = PendingOperation::prepare(Kind::Connect, LIMITS, event)
            .map_err(|error| self.fail(io_error(Stage::Connect, error)))?;
        self.operation = Some(Operation {
            pending,
            kind: OperationKind::Connect,
            cancel_requested: false,
        });
        self.fence()?;
        let pipe = self.endpoint.as_ref().ok_or(Error::Closed)?.pipe.raw();
        let issued = service_positive(|| {
            self.operation
                .as_mut()
                .ok_or(Error::InvalidPhase)?
                .pending
                .issue(pipe)
                .map_err(|error| io_error(Stage::Connect, error))
        });
        issued.map_err(|error| self.fail(error))?;
        self.phase = ListenPhase::Connecting;
        Ok(())
    }
    fn poll_connect(&mut self) -> Result<ListenProgress, Error> {
        self.fence()?;
        if self.phase == ListenPhase::Connected {
            return Ok(ListenProgress::Connected);
        }
        if self.phase != ListenPhase::Connecting {
            return Err(self.fail(Error::InvalidPhase));
        }
        let pipe = self.endpoint.as_ref().ok_or(Error::Closed)?.pipe.raw();
        let result = self
            .operation
            .as_mut()
            .ok_or(Error::InvalidPhase)?
            .pending
            .poll(pipe);
        match result {
            Ok(None) => {
                self.fence()?;
                Ok(ListenProgress::Pending)
            }
            Ok(Some(Completed::Count(0))) if !self.in_flight() => {
                self.phase = ListenPhase::Connected;
                self.fence()?;
                // Keep the completed operation until admission/transfer; helper
                // PairingPipe then performs its normal one-time authentication.
                Ok(ListenProgress::Connected)
            }
            Ok(Some(_)) => Err(self.fail(Error::InvalidMessage)),
            Err(error) => Err(self.fail(io_error(Stage::Connect, error))),
        }
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.drained {
            return Ok(true);
        }
        let first = self.fail(Error::Cancelled);
        if self.in_flight() {
            let pipe = self.endpoint.as_ref().ok_or(first)?.pipe.raw();
            let operation = self.operation.as_mut().ok_or(first)?;
            let cancelled = operation.cancel_requested;
            match operation.pending.poll(pipe) {
                Ok(None) => return Ok(false),
                Ok(Some(_)) if self.in_flight() => return Err(first),
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
        drop(self.endpoint.take());
        cleanup_state().map_err(|error| {
            self.cleanup_failure.get_or_insert(error);
            first
        })?;
        self.drained = true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn idle_age_is_not_part_of_the_single_admitted_window() {
        let idle_start = Instant::now();
        for delay in [Duration::ZERO, Duration::from_secs(86_400)] {
            let admitted = idle_start + delay;
            let window = AttemptWindow::at_admission(admitted).unwrap();
            assert_eq!(window.started(), admitted);
            assert_eq!(window.deadline().duration_since(admitted), MAX_LIFETIME);
            let before_helper = OriginalBudget::new(
                window.started,
                window.deadline,
                admitted + Duration::from_secs(60),
            )
            .unwrap();
            assert_eq!(before_helper.deadline, window.deadline());
            assert!(OriginalBudget::new(window.started, window.deadline, window.deadline).is_err());
        }
    }
    #[test]
    fn failed_unbound_owner_stays_visible_for_drain_and_cannot_admit() {
        // Pure empty-owner fixture: no fake HANDLE, event or native query.
        let mut listener = UnboundPairingListener {
            inner: Some(Box::new(ListenerInner {
                endpoint: None,
                operation: None,
                phase: ListenPhase::Connecting,
                first_failure: Some(Error::Cancelled),
                cleanup_failure: None,
                drained: false,
            })),
        };
        assert!(listener.admit_starter().is_err());
        assert!(listener.inner.is_some());
        assert!(listener.admit_starter().is_err());
        assert!(listener.inner.is_some());
        assert!(!listener.is_drained());
    }
    #[test]
    fn consumed_listener_has_no_second_transition() {
        let mut listener = UnboundPairingListener { inner: None };
        assert!(matches!(listener.admit_starter(), Err(Error::Closed)));
        assert!(matches!(listener.begin_connect(), Err(Error::Closed)));
        assert!(listener.is_drained());
    }
    #[test]
    fn pre_transfer_error_burns_the_single_helper_claim() {
        let mut transfer = Transfer::Available;
        assert_eq!(transfer.claim(), Ok(()));
        // A failed context/deadline check leaves Claimed, never Available.
        assert_eq!(transfer.claim(), Err(Error::InvalidPhase));
        transfer = Transfer::Bound;
        assert_eq!(transfer.claim(), Err(Error::InvalidPhase));
    }
}
