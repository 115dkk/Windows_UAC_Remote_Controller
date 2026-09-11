// SPDX-License-Identifier: GPL-2.0-or-later
//! Private ServiceSession-owned rendezvous producer. Bound matches original
//! native transport owners only: healthy UAC policy/fresh ceremony authority
//! before QR/grants is still REQUIRED future work. No enrollment or signing.
#![forbid(unsafe_code)]

use crate::{
    PairingPeerError, PairingPipe, PairingPipeProgress, PairingServerEndpoints, PendingElevationId,
    ffi::{AttemptWindow, ListenProgress, StarterAdmission, UnboundPairingListener},
    pairing_handoff::{Frame, ServiceHandoff, ServiceSide},
    startup_phase::ScmReadyPermit,
};
use approval_protocol::BootEpoch;
use std::{
    fmt,
    time::{Duration, Instant},
};

const CLOSE_RESERVE: Duration = Duration::from_secs(30);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Dormant,
    Listening,
    Active,
    Draining,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Native(PairingPeerError),
    Protocol,
    Random,
    Epoch,
    Window,
    Cancelled,
    Generation,
}
impl From<PairingPeerError> for Failure {
    fn from(error: PairingPeerError) -> Self {
        Self::Native(error)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Io {
    Connect,
    OfferWrite,
    StarterRead,
    HelperRead,
    BoundWrite,
    CloseWrite,
    AckRead,
    Idle,
}
enum Channel {
    Listener(UnboundPairingListener),
    Pipe {
        pipe: PairingPipe,
        io: Io,
    },
    #[cfg(test)]
    Fixture(FixtureChannel),
}
#[cfg(test)]
struct FixtureChannel {
    polls_left: usize,
    drained: bool,
    cancelled: bool,
    fail: bool,
}
impl Channel {
    fn listener(&mut self) -> Result<&mut UnboundPairingListener, Failure> {
        match self {
            Self::Listener(value) => Ok(value),
            _ => Err(Failure::Protocol),
        }
    }
    fn pipe(&mut self) -> Result<(&mut PairingPipe, &mut Io), Failure> {
        match self {
            Self::Pipe { pipe, io } => Ok((pipe, io)),
            _ => Err(Failure::Protocol),
        }
    }
    fn idle(&self) -> bool {
        matches!(self, Self::Pipe { io: Io::Idle, .. })
    }
    fn cancel(&mut self) {
        match self {
            Self::Listener(value) => value.cancel(),
            Self::Pipe { pipe, .. } => pipe.cancel(),
            #[cfg(test)]
            Self::Fixture(value) => value.cancelled = true,
        }
    }
    fn drain(&mut self) -> Result<bool, PairingPeerError> {
        match self {
            Self::Listener(value) => value.drain(),
            Self::Pipe { pipe, .. } => pipe.drain(),
            #[cfg(test)]
            Self::Fixture(value) => {
                assert!(value.cancelled);
                if value.fail {
                    Err(PairingPeerError::CleanupUnconfirmed)
                } else if value.polls_left != 0 {
                    value.polls_left -= 1;
                    Ok(false)
                } else {
                    value.drained = true;
                    Ok(true)
                }
            }
        }
    }
    fn drained(&self) -> bool {
        match self {
            Self::Listener(value) => value.is_drained(),
            Self::Pipe { pipe, .. } => pipe.is_drained(),
            #[cfg(test)]
            Self::Fixture(value) => value.drained,
        }
    }
    fn cleanup_failed(&self) -> bool {
        match self {
            Self::Listener(value) => value.cleanup_failure().is_some(),
            Self::Pipe { pipe, .. } => pipe.cleanup_failure().is_some(),
            #[cfg(test)]
            Self::Fixture(value) => value.fail,
        }
    }
}

pub(super) struct ServicePairing {
    state: State,
    enabled: bool,
    epoch: Option<BootEpoch>,
    next_generation: Option<u64>,
    generation: Option<u64>,
    starter: Option<Channel>,
    helper: Option<Channel>,
    admission: Option<StarterAdmission>,
    window: Option<AttemptWindow>,
    protocol: Option<ServiceHandoff>,
    next_side: ServiceSide,
    first_failure: Option<Failure>,
    cleanup_failed: bool,
    rearm: bool,
}
impl fmt::Debug for ServicePairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServicePairing")
            .field("state", &self.state)
            .field("first_failure", &self.first_failure)
            .field("cleanup_failed", &self.cleanup_failed)
            .finish_non_exhaustive()
    }
}
impl ServicePairing {
    pub(super) fn dormant() -> Self {
        Self {
            state: State::Dormant,
            enabled: false,
            epoch: None,
            next_generation: Some(1),
            generation: None,
            starter: None,
            helper: None,
            admission: None,
            window: None,
            protocol: None,
            next_side: ServiceSide::Starter,
            first_failure: None,
            cleanup_failed: false,
            rearm: false,
        }
    }
    pub(super) fn activate(
        &mut self,
        _ready: ScmReadyPermit,
        epoch: BootEpoch,
    ) -> Result<(), super::PeerRuntimeError> {
        if self.state != State::Dormant || self.enabled {
            return Err(super::PeerRuntimeError::Protocol);
        }
        self.enabled = true;
        self.epoch = Some(epoch);
        if crate::entry::stop_requested() {
            self.shutdown();
            return Ok(());
        }
        if let Err(error) = self.arm() {
            self.retire(Some(error), false);
        }
        if crate::entry::stop_requested() {
            self.shutdown();
        }
        Ok(())
    }
    fn arm(&mut self) -> Result<(), Failure> {
        self.ensure_running()?;
        if !self.enabled
            || crate::entry::stop_requested()
            || self.remaining_owners() != 0
            || self.cleanup_failed
        {
            return Err(Failure::Cancelled);
        }
        if !matches!(self.state, State::Dormant | State::Draining)
            || self.starter.is_some()
            || self.helper.is_some()
            || self.admission.is_some()
            || self.window.is_some()
            || self.protocol.is_some()
        {
            return Err(Failure::Protocol);
        }
        let pair = PairingServerEndpoints::create_for_running_service()?;
        let (starter, helper) = pair.into_servers();
        self.starter = Some(Channel::Listener(starter.into_unbound_listener()?));
        self.helper = Some(Channel::Listener(helper.into_unbound_listener()?));
        self.ensure_running()?;
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .begin_connect()?;
        self.helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .begin_connect()?;
        self.ensure_running()?;
        self.state = State::Listening;
        self.first_failure = None;
        self.ensure_running()
    }
    pub(super) fn poll(&mut self, epoch: BootEpoch, now: Instant) {
        if matches!(self.state, State::Dormant | State::Unavailable) {
            return;
        }
        if !self.enabled || crate::entry::stop_requested() {
            self.shutdown();
        }
        if self.epoch != Some(epoch) {
            self.retire(Some(Failure::Epoch), false);
        }
        if self.state == State::Draining {
            self.drain_step();
            return;
        }
        let result = match self.state {
            State::Listening => self.listen_step(),
            State::Active => self.active_step(now),
            _ => Ok(()),
        };
        if let Err(error) = result {
            self.retire(Some(error), true);
        }
    }
    fn listen_step(&mut self) -> Result<(), Failure> {
        self.ensure_running()?;
        let starter = self
            .starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .poll_connect()?;
        if starter == ListenProgress::Pending {
            if self
                .helper
                .as_mut()
                .ok_or(Failure::Protocol)?
                .listener()?
                .poll_connect()?
                == ListenProgress::Connected
            {
                return Err(Failure::Protocol);
            }
            return Ok(());
        }
        let admission = self
            .starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .admit_starter()?;
        self.admission = Some(admission); // Retain before any fallible Helper transfer.
        self.ensure_running()?;
        let helper = self
            .helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .listener()?
            .bind_helper(self.admission.as_mut().ok_or(Failure::Protocol)?)?;
        self.helper = Some(Channel::Pipe {
            pipe: helper,
            io: Io::Connect,
        });
        self.ensure_running()?;
        let (starter, window) = self
            .admission
            .as_mut()
            .ok_or(Failure::Protocol)?
            .take_parts()?;
        self.starter = Some(Channel::Pipe {
            pipe: starter,
            io: Io::Idle,
        });
        self.window = Some(window);
        drop(self.admission.take());
        self.ensure_running()?;
        let generation = self.next_generation.take().ok_or(Failure::Generation)?;
        self.next_generation = generation.checked_add(1);
        self.generation = Some(generation);
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| Failure::Random)?;
        self.check_window(Instant::now())?;
        let id = PendingElevationId::from_bytes(bytes).map_err(|_| Failure::Random)?;
        self.protocol = Some(ServiceHandoff::new(id));
        self.state = State::Active;
        self.check_window(Instant::now())?;
        let offer = self
            .protocol
            .as_ref()
            .ok_or(Failure::Protocol)?
            .offer()
            .map_err(|_| Failure::Protocol)?;
        self.write(ServiceSide::Starter, offer, Io::OfferWrite)?;
        Ok(())
    }
    fn channel(&mut self, side: ServiceSide) -> Result<&mut Channel, Failure> {
        match side {
            ServiceSide::Starter => self.starter.as_mut(),
            ServiceSide::Helper => self.helper.as_mut(),
        }
        .ok_or(Failure::Protocol)
    }
    fn write(&mut self, side: ServiceSide, frame: Frame, operation: Io) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        if matches!(frame, Frame::Offer(_) | Frame::Bound(_))
            && Instant::now() >= self.close_at()?
        {
            return Err(Failure::Window);
        }
        let bytes = frame.encode().map_err(|_| Failure::Protocol)?;
        let (pipe, io) = self.channel(side)?.pipe()?;
        if *io != Io::Idle {
            return Err(Failure::Protocol);
        }
        pipe.begin_write(&bytes)?;
        *io = operation;
        self.check_window(Instant::now())
    }
    fn read(&mut self, side: ServiceSide, operation: Io) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        let (pipe, io) = self.channel(side)?.pipe()?;
        if *io != Io::Idle {
            return Err(Failure::Protocol);
        }
        pipe.begin_read()?;
        *io = operation;
        self.check_window(Instant::now())
    }
    fn ensure_running(&self) -> Result<(), Failure> {
        self.ensure_running_with(crate::entry::stop_requested)
    }
    // Private pure observation seam for deterministic fixtures. Production
    // always uses the actual service latch above, never a caller trust flag.
    fn ensure_running_with(&self, stopped: impl FnOnce() -> bool) -> Result<(), Failure> {
        if !self.enabled || stopped() {
            Err(Failure::Cancelled)
        } else {
            Ok(())
        }
    }
    fn check_window(&self, now: Instant) -> Result<(), Failure> {
        self.ensure_running()?;
        if self.generation.is_none_or(|generation| generation == 0) {
            return Err(Failure::Generation);
        }
        let window = self.window.as_ref().ok_or(Failure::Protocol)?;
        if now < window.started() || now >= window.deadline() {
            Err(Failure::Window)
        } else {
            self.ensure_running()
        }
    }
    fn close_at(&self) -> Result<Instant, Failure> {
        self.window
            .as_ref()
            .ok_or(Failure::Protocol)?
            .deadline()
            .checked_sub(CLOSE_RESERVE)
            .ok_or(Failure::Window)
    }
    fn check_pair_live(&mut self) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        self.starter
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .check_live()?;
        self.helper
            .as_mut()
            .ok_or(Failure::Protocol)?
            .pipe()?
            .0
            .check_live()?;
        self.check_window(Instant::now())
    }
    fn match_pair(&mut self) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        let (pid, created) = self
            .protocol
            .as_ref()
            .and_then(ServiceHandoff::candidate)
            .ok_or(Failure::Protocol)?;
        let starter = self.starter.as_mut().ok_or(Failure::Protocol)?.pipe()?.0;
        let helper = self.helper.as_mut().ok_or(Failure::Protocol)?.pipe()?.0;
        helper.match_launched_helper(starter, pid, created)?;
        starter.check_input_quiet()?;
        helper.check_input_quiet()?;
        self.check_window(Instant::now())
    }
    fn active_step(&mut self, now: Instant) -> Result<(), Failure> {
        self.check_window(now)?;
        self.check_pair_live()?;
        if self.protocol.as_ref().is_some_and(ServiceHandoff::is_bound) {
            self.match_pair()?;
        }
        let close_at = self.close_at()?;
        if Instant::now() >= close_at
            && !self
                .protocol
                .as_ref()
                .ok_or(Failure::Protocol)?
                .is_closing()
        {
            if !self.protocol.as_ref().is_some_and(ServiceHandoff::is_bound) || !self.both_idle() {
                return Err(Failure::Window);
            }
            self.match_pair()?;
            self.protocol
                .as_mut()
                .ok_or(Failure::Protocol)?
                .start_close()
                .map_err(|_| Failure::Protocol)?;
        }
        let side = self.next_side;
        self.next_side = match side {
            ServiceSide::Starter => ServiceSide::Helper,
            ServiceSide::Helper => ServiceSide::Starter,
        };
        self.poll_side(side)?;
        self.check_window(Instant::now())?;
        if self
            .protocol
            .as_ref()
            .is_some_and(ServiceHandoff::both_acknowledged)
        {
            // BOTH normal post-read native fences have completed while clients
            // remain live. Only now may either original pipe be closed.
            self.retire(None, true);
            return Ok(());
        }
        if self
            .protocol
            .as_ref()
            .is_some_and(ServiceHandoff::is_closing)
        {
            if self.channel(side)?.idle() {
                if let Ok(close) = self
                    .protocol
                    .as_ref()
                    .ok_or(Failure::Protocol)?
                    .close_frame(side)
                {
                    self.write(side, close, Io::CloseWrite)?;
                }
            }
            return Ok(());
        }
        let ready_to_match = self
            .protocol
            .as_ref()
            .is_some_and(|model| !model.is_matched() && model.candidate().is_some());
        if ready_to_match {
            self.match_pair()?;
            self.protocol
                .as_mut()
                .ok_or(Failure::Protocol)?
                .confirm_match()
                .map_err(|_| Failure::Protocol)?;
            self.check_window(Instant::now())?;
        }
        if self.channel(side)?.idle() {
            if let Ok(bound) = self
                .protocol
                .as_ref()
                .ok_or(Failure::Protocol)?
                .bound_frame(side)
            {
                self.match_pair()?;
                self.write(side, bound, Io::BoundWrite)?;
                self.match_pair()?;
            }
        }
        Ok(())
    }
    fn both_idle(&self) -> bool {
        self.starter.as_ref().is_some_and(Channel::idle)
            && self.helper.as_ref().is_some_and(Channel::idle)
    }
    fn poll_side(&mut self, side: ServiceSide) -> Result<(), Failure> {
        self.check_window(Instant::now())?;
        let (operation, progress) = {
            let (pipe, io) = self.channel(side)?.pipe()?;
            (*io, pipe.poll()?)
        };
        self.check_window(Instant::now())?;
        let outcome = match (operation, progress) {
            (_, PairingPipeProgress::Pending) | (Io::Idle, PairingPipeProgress::Idle) => Ok(()),
            (Io::Connect, PairingPipeProgress::Connected) if side == ServiceSide::Helper => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.read(side, Io::HelperRead)
            }
            (Io::OfferWrite, PairingPipeProgress::Written) if side == ServiceSide::Starter => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .offer_written()
                    .map_err(|_| Failure::Protocol)?;
                self.read(side, Io::StarterRead)
            }
            (Io::StarterRead | Io::HelperRead | Io::AckRead, PairingPipeProgress::Read(bytes)) => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                let frame = Frame::decode(&bytes).map_err(|_| Failure::Protocol)?;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .receive(side, frame)
                    .map_err(|_| Failure::Protocol)
            }
            (Io::BoundWrite, PairingPipeProgress::Written) => {
                self.match_pair()?;
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .bound_written(side)
                    .map_err(|_| Failure::Protocol)?;
                self.match_pair()?; // Includes both-written internal Bound publication.
                Ok(())
            }
            (Io::CloseWrite, PairingPipeProgress::Written) => {
                *self.channel(side)?.pipe()?.1 = Io::Idle;
                self.protocol
                    .as_mut()
                    .ok_or(Failure::Protocol)?
                    .close_written(side)
                    .map_err(|_| Failure::Protocol)?;
                self.read(side, Io::AckRead)
            }
            _ => Err(Failure::Protocol),
        };
        outcome?;
        self.check_window(Instant::now())
    }
    fn retire(&mut self, failure: Option<Failure>, rearm: bool) {
        if let Some(error) = failure {
            self.first_failure.get_or_insert(error);
        }
        if let Some(protocol) = self.protocol.as_mut() {
            protocol.cancel();
        }
        if let Some(starter) = self.starter.as_mut() {
            starter.cancel();
        }
        if let Some(helper) = self.helper.as_mut() {
            helper.cancel();
        }
        if let Some(admission) = self.admission.as_mut() {
            admission.cancel();
        }
        self.state = State::Draining;
        self.rearm = rearm && self.enabled && !crate::entry::stop_requested();
    }
    pub(super) fn shutdown(&mut self) {
        self.enabled = false;
        self.retire(Some(Failure::Cancelled), false);
    }
    fn drain_step(&mut self) {
        for channel in [&mut self.starter, &mut self.helper].into_iter().flatten() {
            if channel.drain().is_err() || channel.cleanup_failed() {
                self.cleanup_failed = true;
            }
        }
        if let Some(admission) = self.admission.as_mut() {
            if admission.drain().is_err() {
                self.cleanup_failed = true;
            }
        }
        if self.remaining_owners() != 0 {
            return;
        }
        drop(self.starter.take());
        drop(self.helper.take());
        drop(self.admission.take());
        self.window = None;
        self.protocol = None;
        self.generation = None;
        if self.rearm
            && !self.cleanup_failed
            && self.enabled
            && !crate::entry::stop_requested()
            && self.next_generation.is_some()
        {
            self.rearm = false;
            if let Err(error) = self.arm() {
                self.retire(Some(error), false);
            }
        } else {
            self.state = State::Unavailable;
        }
    }
    pub(super) fn poll_shutdown(&mut self) {
        self.shutdown();
        self.drain_step();
    }
    pub(super) fn remaining_owners(&self) -> usize {
        usize::from(
            self.starter
                .as_ref()
                .is_some_and(|channel| !channel.drained()),
        ) + usize::from(
            self.helper
                .as_ref()
                .is_some_and(|channel| !channel.drained()),
        ) + usize::from(
            self.admission
                .as_ref()
                .is_some_and(|admission| !admission.is_drained()),
        )
    }
    pub(super) fn cleanup_failed(&self) -> bool {
        self.cleanup_failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(polls_left: usize, fail: bool) -> Channel {
        Channel::Fixture(FixtureChannel {
            polls_left,
            drained: false,
            cancelled: false,
            fail,
        })
    }
    #[test]
    fn late_stop_blocks_producer_eligibility_but_not_mock_cleanup() {
        use std::cell::Cell;
        let mut owner = ServicePairing::dormant();
        owner.enabled = true;
        let stopped = Cell::new(false);
        assert_eq!(owner.ensure_running_with(|| stopped.get()), Ok(()));
        stopped.set(true); // Deterministic fixture: native checks elapsed meanwhile.
        assert_eq!(
            owner.ensure_running_with(|| stopped.get()),
            Err(Failure::Cancelled)
        );
        owner.starter = Some(fixture(1, false));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
        assert!(!owner.enabled);
    }
    #[test]
    fn constructors_are_dormant_and_shutdown_counts_all_mock_owners() {
        let mut owner = ServicePairing::dormant();
        assert_eq!(owner.state, State::Dormant);
        assert!(!owner.enabled);
        assert_eq!(owner.remaining_owners(), 0);
        owner.starter = Some(fixture(0, false));
        owner.helper = Some(fixture(2, false));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
        assert!(owner.starter.is_none() && owner.helper.is_none());
        assert_eq!(owner.state, State::Unavailable);
        assert!(!owner.enabled);
    }
    #[test]
    fn uncertain_mock_drain_retains_owner_and_never_rearms() {
        let mut owner = ServicePairing::dormant();
        owner.helper = Some(fixture(0, true));
        owner.poll_shutdown();
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 1);
        assert!(owner.cleanup_failed());
        assert!(owner.helper.is_some());
        assert!(!owner.rearm);
        // No native handle was constructed; prevent a synthetic failure fixture
        // from being mistaken for the production Session Drop invariant.
    }
    #[test]
    fn active_state_cannot_rearm_or_replace_an_existing_attempt() {
        let mut owner = ServicePairing::dormant();
        owner.state = State::Active;
        owner.enabled = true;
        assert!(owner.arm().is_err()); // Rejects before any native factory.
        assert_eq!(owner.next_generation, Some(1));
    }
    #[test]
    fn ordinary_test_process_cannot_activate_native_pairing_endpoints() {
        // The fake report callbacks test ONLY the native negative factory guard:
        // this executable is not the actual fixed running SCM process. No UAC,
        // provider, endpoint creation or successful activation is expected.
        let began = Instant::now();
        let (request, gate) = crate::startup_phase::ready_handshake();
        request
            .complete_after_report(began, || false, || Ok(()), || ())
            .unwrap();
        let ready = gate.wait(began, || false).unwrap();
        let mut owner = ServicePairing::dormant();
        owner
            .activate(ready, BootEpoch::from_bytes([1; 32]).unwrap())
            .unwrap();
        assert!(!matches!(owner.state, State::Listening | State::Active));
        owner.poll_shutdown();
        assert_eq!(owner.remaining_owners(), 0);
    }
}
