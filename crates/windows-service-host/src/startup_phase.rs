// SPDX-License-Identifier: GPL-2.0-or-later
//! Private two-phase SCM startup policy and one-use, in-process acknowledgement.
//! This is not readiness for a remote request, nor an externally callable gate.
#![forbid(unsafe_code)]

use crate::{ServiceError, contract::remaining_budget};
use std::{
    sync::mpsc::{self, Receiver, SyncSender},
    time::{Duration, Instant},
};

const ACK_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReportPhase {
    Starting,
    PlatformInitializing,
    Ready,
    Stopping,
    Stopped,
}

impl ReportPhase {
    pub(crate) fn platform_initializing(self) -> Result<Self, ServiceError> {
        match self {
            Self::Starting => Ok(Self::PlatformInitializing),
            _ => Err(ServiceError::UnexpectedState),
        }
    }

    pub(crate) fn ready(self) -> Result<Self, ServiceError> {
        match self {
            Self::PlatformInitializing => Ok(Self::Ready),
            _ => Err(ServiceError::UnexpectedState),
        }
    }

    pub(crate) fn progress(self) -> Result<Self, ServiceError> {
        match self {
            Self::Starting | Self::PlatformInitializing | Self::Ready => Ok(self),
            _ => Err(ServiceError::UnexpectedState),
        }
    }

    pub(crate) fn accepts_controls(self) -> bool {
        self == Self::Ready
    }

    pub(crate) fn pending(self) -> bool {
        matches!(self, Self::Starting | Self::Stopping)
    }
}

pub(crate) fn worker_finished_outcome(
    outcome: Result<(), ServiceError>,
    stopping: bool,
) -> Result<(), ServiceError> {
    if !stopping && outcome.is_ok() {
        Err(ServiceError::WorkerFailed)
    } else {
        outcome
    }
}

#[derive(Debug)]
pub(crate) struct RunningRequest {
    acknowledgement: SyncSender<Result<(), ServiceError>>,
}

pub(crate) struct RunningGate {
    acknowledgement: Receiver<Result<(), ServiceError>>,
}

pub(crate) fn running_handshake() -> (RunningRequest, RunningGate) {
    let (acknowledgement, receiver) = mpsc::sync_channel(1);
    (
        RunningRequest { acknowledgement },
        RunningGate {
            acknowledgement: receiver,
        },
    )
}

fn within_startup(elapsed: Duration, cancelled: bool) -> Result<Duration, ServiceError> {
    if cancelled {
        return Err(ServiceError::WorkerFailed);
    }
    remaining_budget(elapsed)
}

impl RunningRequest {
    /// The entry thread supplies its actual synchronous SetServiceStatus call.
    /// No acknowledgement exists until that call succeeds, within the SAME
    /// startup budget and with cancellation checked on both sides of the call.
    /// Consuming self forbids acknowledgement reuse, retries or another worker.
    pub(crate) fn complete_after_report(
        self,
        began: Instant,
        mut cancelled: impl FnMut() -> bool,
        report: impl FnOnce() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        self.complete_with(|| began.elapsed(), &mut cancelled, report)
    }

    fn complete_with(
        self,
        mut elapsed: impl FnMut() -> Duration,
        mut cancelled: impl FnMut() -> bool,
        report: impl FnOnce() -> Result<(), ServiceError>,
    ) -> Result<(), ServiceError> {
        let outcome = within_startup(elapsed(), cancelled())
            .and_then(|_| report())
            .and_then(|()| within_startup(elapsed(), cancelled()).map(|_| ()));
        let delivered = self
            .acknowledgement
            .try_send(outcome)
            .map_err(|_| ServiceError::WorkerFailed);
        outcome.and(delivered)
    }
}

impl RunningGate {
    pub(crate) fn wait(
        self,
        began: Instant,
        cancelled: impl FnMut() -> bool,
    ) -> Result<(), ServiceError> {
        self.wait_with(|| began.elapsed(), cancelled)
    }

    fn wait_with(
        self,
        mut elapsed: impl FnMut() -> Duration,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<(), ServiceError> {
        loop {
            let remaining = within_startup(elapsed(), cancelled())?;
            match self
                .acknowledgement
                .recv_timeout(remaining.min(ACK_POLL_INTERVAL))
            {
                Ok(outcome) => {
                    // A queued success is not permission after cancellation or
                    // deadline expiry. Never reset the budget while polling.
                    within_startup(elapsed(), cancelled())?;
                    return outcome;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ServiceError::WorkerFailed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{LIFECYCLE_TIMEOUT, continuing_pending_start};
    use std::cell::Cell;

    #[test]
    fn platform_work_cannot_follow_an_unacknowledged_request() {
        let (_request, gate) = running_handshake();
        let called = Cell::new(false);
        let elapsed = Cell::new(Duration::ZERO);
        let outcome = gate
            .wait_with(
                || {
                    let previous = elapsed.get();
                    elapsed.set(LIFECYCLE_TIMEOUT);
                    previous
                },
                || false,
            )
            .map(|()| called.set(true));
        assert_eq!(outcome, Err(ServiceError::Timeout));
        assert!(!called.get());
    }

    #[test]
    fn only_successfully_returned_report_releases_platform_work() {
        let (request, gate) = running_handshake();
        let reported = Cell::new(false);
        request
            .complete_after_report(
                Instant::now(),
                || false,
                || {
                    assert!(matches!(
                        gate.acknowledgement.try_recv(),
                        Err(mpsc::TryRecvError::Empty)
                    ));
                    reported.set(true);
                    Ok(())
                },
            )
            .unwrap();
        gate.wait(Instant::now(), || false).unwrap();
        assert!(reported.get());
    }

    #[test]
    fn failed_report_and_closed_sender_never_release_platform_work() {
        let (request, gate) = running_handshake();
        assert_eq!(
            request.complete_after_report(
                Instant::now(),
                || false,
                || { Err(ServiceError::UnexpectedState) }
            ),
            Err(ServiceError::UnexpectedState)
        );
        assert_eq!(
            gate.wait(Instant::now(), || false),
            Err(ServiceError::UnexpectedState)
        );
        let (request, gate) = running_handshake();
        drop(request);
        assert_eq!(
            gate.wait(Instant::now(), || false),
            Err(ServiceError::WorkerFailed)
        );
    }

    #[test]
    fn cancelled_or_expired_entry_does_not_report_or_acknowledge_success() {
        for (elapsed, cancelled, expected) in [
            (Duration::ZERO, true, ServiceError::WorkerFailed),
            (LIFECYCLE_TIMEOUT, false, ServiceError::Timeout),
        ] {
            let (request, gate) = running_handshake();
            let called = Cell::new(false);
            assert_eq!(
                request.complete_with(
                    || elapsed,
                    || cancelled,
                    || {
                        called.set(true);
                        Ok(())
                    }
                ),
                Err(expected)
            );
            assert!(!called.get());
            assert_eq!(gate.wait_with(|| Duration::ZERO, || false), Err(expected));
        }
    }

    #[test]
    fn cancellation_or_expiry_during_report_denies_acknowledgement() {
        for expires in [false, true] {
            let (request, gate) = running_handshake();
            let returned = Cell::new(false);
            let expected = if expires {
                ServiceError::Timeout
            } else {
                ServiceError::WorkerFailed
            };
            assert_eq!(
                request.complete_with(
                    || if expires && returned.get() {
                        LIFECYCLE_TIMEOUT
                    } else {
                        Duration::ZERO
                    },
                    || !expires && returned.get(),
                    || {
                        returned.set(true);
                        Ok(())
                    },
                ),
                Err(expected)
            );
            assert_eq!(gate.wait_with(|| Duration::ZERO, || false), Err(expected));
        }
    }

    #[test]
    fn queued_acknowledgement_cannot_outlive_cancellation_or_budget() {
        for (elapsed, cancelled, expected) in [
            (Duration::ZERO, true, ServiceError::WorkerFailed),
            (LIFECYCLE_TIMEOUT, false, ServiceError::Timeout),
        ] {
            let (request, gate) = running_handshake();
            request
                .complete_after_report(Instant::now(), || false, || Ok(()))
                .unwrap();
            assert_eq!(gate.wait_with(|| elapsed, || cancelled), Err(expected));
        }
        for expires in [false, true] {
            let (request, gate) = running_handshake();
            request
                .complete_after_report(Instant::now(), || false, || Ok(()))
                .unwrap();
            let checked = Cell::new(false);
            let expected = if expires {
                ServiceError::Timeout
            } else {
                ServiceError::WorkerFailed
            };
            assert_eq!(
                gate.wait_with(
                    || if expires && checked.replace(true) {
                        LIFECYCLE_TIMEOUT
                    } else {
                        Duration::ZERO
                    },
                    || !expires && checked.replace(true),
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn closed_worker_rejects_entry_acknowledgement() {
        let (request, gate) = running_handshake();
        drop(gate);
        assert_eq!(
            request.complete_after_report(Instant::now(), || false, || Ok(())),
            Err(ServiceError::WorkerFailed)
        );
    }

    #[test]
    fn progress_never_regresses_running_and_controls_wait_for_real_ready() {
        let starting = ReportPhase::Starting;
        assert_eq!(starting.progress(), Ok(starting));
        assert!(!starting.accepts_controls());
        assert!(starting.pending());
        assert_eq!(starting.ready(), Err(ServiceError::UnexpectedState));
        let platform = starting.platform_initializing().unwrap();
        assert_eq!(platform.progress(), Ok(platform));
        assert!(!platform.accepts_controls());
        assert!(!platform.pending());
        assert_eq!(
            platform.platform_initializing(),
            Err(ServiceError::UnexpectedState)
        );
        let ready = platform.ready().unwrap();
        assert_eq!(ready.progress(), Ok(ready));
        assert!(ready.accepts_controls());
        assert!(!ready.pending());
        assert_eq!(ready.ready(), Err(ServiceError::UnexpectedState));
    }

    #[test]
    fn failed_startup_cleanup_keeps_original_deadline_and_no_controls() {
        let began = Instant::now();
        let nearly_expired = began + LIFECYCLE_TIMEOUT - ACK_POLL_INTERVAL;
        assert_eq!(continuing_pending_start(Some(began), nearly_expired), began);
        assert_eq!(
            continuing_pending_start(None, nearly_expired),
            nearly_expired
        );
        for phase in [ReportPhase::Stopping, ReportPhase::Stopped] {
            assert!(!phase.accepts_controls());
            assert_eq!(phase.progress(), Err(ServiceError::UnexpectedState));
            assert_eq!(phase.ready(), Err(ServiceError::UnexpectedState));
            assert_eq!(
                phase.platform_initializing(),
                Err(ServiceError::UnexpectedState)
            );
        }
    }

    #[test]
    fn actual_worker_failure_is_preserved_and_unsolicited_exit_is_not_success() {
        for stopping in [false, true] {
            assert_eq!(
                worker_finished_outcome(Err(ServiceError::IdentityUnavailable), stopping),
                Err(ServiceError::IdentityUnavailable)
            );
        }
        assert_eq!(worker_finished_outcome(Ok(()), true), Ok(()));
        assert_eq!(
            worker_finished_outcome(Ok(()), false),
            Err(ServiceError::WorkerFailed)
        );
    }
}
