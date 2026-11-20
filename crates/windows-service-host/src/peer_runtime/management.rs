// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-session-owned management listener and one-request connections.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::{
    PairingPeerError, PairingPipeProgress,
    ffi::{ManagementClientClass, ManagementListener, ManagementPipe},
    management_protocol::{ManagementRequest, ManagementResponse, decode_request, encode_response},
};

pub(super) const REARM_INTERVAL: Duration = Duration::from_millis(250);
const REPLY_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) enum ManagementProgress {
    Idle,
    ListenerCreationFailed(PairingPeerError),
    Request {
        class: ManagementClientClass,
        request: ManagementRequest,
    },
    Replied,
}

#[derive(Debug)]
enum State {
    Dormant,
    Listening(ManagementListener),
    Reading(ManagementPipe),
    AwaitingReply(ManagementPipe),
    Writing(ManagementPipe),
    AwaitingEof {
        pipe: ManagementPipe,
        until: Instant,
    },
    Closing(ManagementPipe),
    FailedListener(ManagementListener),
    FailedPipe(ManagementPipe),
    Rearming {
        at: Instant,
    },
    Transition,
    Stopped,
}

#[derive(Debug)]
pub(super) struct ServiceManagement {
    state: State,
    first_failure: Option<PairingPeerError>,
    cleanup_failure: Option<PairingPeerError>,
    listener_failure_reported: bool,
    stopping: bool,
    delay_next_arm: bool,
    #[cfg(test)]
    create_results: Option<std::collections::VecDeque<Result<(), PairingPeerError>>>,
}

impl ServiceManagement {
    pub(super) const fn dormant() -> Self {
        Self {
            state: State::Dormant,
            first_failure: None,
            cleanup_failure: None,
            listener_failure_reported: false,
            stopping: false,
            delay_next_arm: false,
            #[cfg(test)]
            create_results: None,
        }
    }

    pub(super) fn activate(&mut self) -> Result<(), PairingPeerError> {
        if !matches!(self.state, State::Dormant) || self.stopping || self.first_failure.is_some() {
            return Err(PairingPeerError::InvalidPhase);
        }
        let result = self.listen(Instant::now());
        if result.is_err() {
            // Activation returns this failure directly to its owner. Retries in
            // the same outage must not report it again through poll.
            self.listener_failure_reported = true;
        }
        result
    }

    fn create_listener(&mut self) -> Result<ManagementListener, PairingPeerError> {
        // Empty native owners exercise scheduling only, never authentication.
        #[cfg(test)]
        if let Some(results) = &mut self.create_results {
            results.pop_front().expect("unexpected creation attempt")?;
            return Ok(ManagementListener::empty_owner_for_test());
        }
        ManagementListener::create()
    }

    fn begin_connect(&self, listener: &mut ManagementListener) -> Result<(), PairingPeerError> {
        #[cfg(test)]
        if self.create_results.is_some() {
            return Ok(());
        }
        listener.begin_connect()
    }

    fn listen(&mut self, now: Instant) -> Result<(), PairingPeerError> {
        if self.stopping || self.cleanup_failure.is_some() {
            self.state = State::Stopped;
            return Err(PairingPeerError::Cancelled);
        }
        let mut listener = match self.create_listener() {
            Ok(listener) => listener,
            Err(error) => {
                self.record_failure(error);
                if error == PairingPeerError::CleanupUnconfirmed {
                    self.cleanup_failure.get_or_insert(error);
                }
                self.schedule_rearm(now);
                return Err(error);
            }
        };
        if let Err(error) = self.begin_connect(&mut listener) {
            self.delay_next_arm = true;
            listener.cancel();
            self.record_failure(error);
            if error == PairingPeerError::CleanupUnconfirmed {
                self.cleanup_failure.get_or_insert(error);
            }
            self.state = State::FailedListener(listener);
            return Err(error);
        }
        self.state = State::Listening(listener);
        self.delay_next_arm = false;
        self.listener_failure_reported = false;
        Ok(())
    }

    fn record_failure(&mut self, error: PairingPeerError) -> PairingPeerError {
        *self.first_failure.get_or_insert(error)
    }

    fn fail_listener(
        &mut self,
        mut listener: ManagementListener,
        error: PairingPeerError,
    ) -> Result<ManagementProgress, PairingPeerError> {
        listener.cancel();
        self.state = State::FailedListener(listener);
        self.connection_failure(error)
    }

    fn fail_pipe(
        &mut self,
        mut pipe: ManagementPipe,
        error: PairingPeerError,
    ) -> Result<ManagementProgress, PairingPeerError> {
        pipe.cancel();
        self.state = State::FailedPipe(pipe);
        self.connection_failure(error)
    }

    fn connection_failure(
        &mut self,
        error: PairingPeerError,
    ) -> Result<ManagementProgress, PairingPeerError> {
        if error == PairingPeerError::CleanupUnconfirmed {
            self.cleanup_failure.get_or_insert(error);
            Err(error)
        } else {
            // Rejection, disconnect, malformed input and deadlines are local
            // to this connection. Its ORIGINAL owner stays retained for drain.
            Ok(ManagementProgress::Idle)
        }
    }

    fn listener_creation_failure(
        &mut self,
        error: PairingPeerError,
    ) -> Result<ManagementProgress, PairingPeerError> {
        if error == PairingPeerError::CleanupUnconfirmed {
            return self.connection_failure(error);
        }
        if self.listener_failure_reported {
            Ok(ManagementProgress::Idle)
        } else {
            self.listener_failure_reported = true;
            Ok(ManagementProgress::ListenerCreationFailed(error))
        }
    }

    fn rearm_after_drain(&mut self, now: Instant) -> Result<ManagementProgress, PairingPeerError> {
        if self.stopping || self.cleanup_failure.is_some() {
            self.state = State::Stopped;
            return Ok(ManagementProgress::Idle);
        }
        if self.delay_next_arm {
            self.schedule_rearm(now);
            return Ok(ManagementProgress::Idle);
        }
        match self.listen(now) {
            Ok(()) => Ok(ManagementProgress::Idle),
            Err(error) => self.listener_creation_failure(error),
        }
    }

    fn schedule_rearm(&mut self, now: Instant) {
        self.state = if self.stopping || self.cleanup_failure.is_some() {
            State::Stopped
        } else {
            // At most one listener creation attempt per interval. This bounds
            // retry work without letting a few short-lived callers permanently
            // exhaust management availability. No live owner exists here.
            State::Rearming {
                at: now + REARM_INTERVAL,
            }
        };
    }

    pub(super) fn poll(&mut self) -> Result<ManagementProgress, PairingPeerError> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&mut self, now: Instant) -> Result<ManagementProgress, PairingPeerError> {
        let state = std::mem::replace(&mut self.state, State::Transition);
        match state {
            State::Listening(mut listener) => match listener.poll_connect() {
                Ok(None) => {
                    self.state = State::Listening(listener);
                    Ok(ManagementProgress::Idle)
                }
                Ok(Some(mut pipe)) => match pipe.begin_read() {
                    Ok(()) => {
                        self.state = State::Reading(pipe);
                        Ok(ManagementProgress::Idle)
                    }
                    Err(error) => self.fail_pipe(pipe, error),
                },
                Err(error) => self.fail_listener(listener, error),
            },
            State::Reading(mut pipe) => match pipe.poll() {
                Ok(PairingPipeProgress::Pending) => {
                    self.state = State::Reading(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(PairingPipeProgress::Read(bytes)) => {
                    let class = match pipe.class() {
                        Ok(class) => class,
                        Err(error) => return self.fail_pipe(pipe, error),
                    };
                    let request = match decode_request(&bytes) {
                        Ok(request) => request,
                        Err(_) => {
                            return self.fail_pipe(pipe, PairingPeerError::InvalidMessage);
                        }
                    };
                    self.state = State::AwaitingReply(pipe);
                    Ok(ManagementProgress::Request { class, request })
                }
                Ok(_) => self.fail_pipe(pipe, PairingPeerError::InvalidPhase),
                Err(error) => self.fail_pipe(pipe, error),
            },
            State::Writing(mut pipe) => match pipe.poll() {
                Ok(PairingPipeProgress::Pending) => {
                    self.state = State::Writing(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(PairingPipeProgress::Written) => {
                    if let Err(error) = pipe.begin_reply_drain() {
                        return self.fail_pipe(pipe, error);
                    }
                    self.state = State::AwaitingEof {
                        pipe,
                        until: now + REPLY_DRAIN_TIMEOUT,
                    };
                    Ok(ManagementProgress::Replied)
                }
                Ok(_) => self.fail_pipe(pipe, PairingPeerError::InvalidPhase),
                Err(error) => self.fail_pipe(pipe, error),
            },
            State::AwaitingEof { mut pipe, until } => {
                if now >= until {
                    pipe.cancel();
                    self.state = State::Closing(pipe);
                } else {
                    match pipe.poll_reply_drain() {
                        Ok(false) => self.state = State::AwaitingEof { pipe, until },
                        Ok(true) => {
                            drop(pipe);
                            return self.rearm_after_drain(now);
                        }
                        Err(error) => return self.fail_pipe(pipe, error),
                    }
                }
                Ok(ManagementProgress::Idle)
            }
            State::Closing(mut pipe) => match pipe.drain() {
                Ok(false) => {
                    self.state = State::Closing(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(true) => {
                    drop(pipe);
                    self.rearm_after_drain(now)
                }
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    self.state = State::FailedPipe(pipe);
                    Err(error)
                }
            },
            State::FailedListener(mut listener) => match listener.drain() {
                Ok(true) => {
                    drop(listener);
                    self.rearm_after_drain(now)
                }
                Ok(false) => {
                    self.state = State::FailedListener(listener);
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    self.state = State::FailedListener(listener);
                    Err(error)
                }
            },
            State::FailedPipe(mut pipe) => match pipe.drain() {
                Ok(true) => {
                    drop(pipe);
                    self.rearm_after_drain(now)
                }
                Ok(false) => {
                    self.state = State::FailedPipe(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    self.state = State::FailedPipe(pipe);
                    Err(error)
                }
            },
            State::Rearming { at } => {
                if self.stopping || self.cleanup_failure.is_some() {
                    self.state = State::Stopped;
                } else if now < at {
                    self.state = State::Rearming { at };
                } else if let Err(error) = self.listen(now) {
                    // Initial activation reports once to its caller; retries
                    // retain that diagnostic without retiring the core service.
                    // Every attempt repeats the native context/first-instance checks.
                    return self.listener_creation_failure(error);
                }
                Ok(ManagementProgress::Idle)
            }
            State::Dormant => {
                self.state = State::Dormant;
                Ok(ManagementProgress::Idle)
            }
            State::Stopped => {
                self.state = State::Stopped;
                Ok(ManagementProgress::Idle)
            }
            State::AwaitingReply(mut pipe) => match pipe.class() {
                Ok(_) => {
                    self.state = State::AwaitingReply(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => self.fail_pipe(pipe, error),
            },
            State::Transition => {
                self.state = State::Stopped;
                let error = self.record_failure(PairingPeerError::InvalidPhase);
                Err(error)
            }
        }
    }

    pub(super) fn reply(&mut self, response: ManagementResponse) -> Result<(), PairingPeerError> {
        let state = std::mem::replace(&mut self.state, State::Transition);
        let State::AwaitingReply(mut pipe) = state else {
            self.state = state;
            return Err(PairingPeerError::InvalidPhase);
        };
        let wire = match encode_response(&response) {
            Ok(wire) => wire,
            Err(_) => {
                let _ = self.fail_pipe(pipe, PairingPeerError::InvalidMessage);
                return Err(PairingPeerError::InvalidMessage);
            }
        };
        match pipe.begin_write(&wire) {
            Ok(()) => {
                self.state = State::Writing(pipe);
                Ok(())
            }
            Err(error) => self.fail_pipe(pipe, error).map(|_| ()),
        }
    }

    pub(super) fn shutdown(&mut self) {
        self.stopping = true;
        match &mut self.state {
            State::Listening(listener) | State::FailedListener(listener) => listener.cancel(),
            State::AwaitingEof { pipe, .. }
            | State::Reading(pipe)
            | State::AwaitingReply(pipe)
            | State::Writing(pipe)
            | State::Closing(pipe)
            | State::FailedPipe(pipe) => pipe.cancel(),
            State::Dormant | State::Rearming { .. } => self.state = State::Stopped,
            State::Transition | State::Stopped => {}
        }
    }

    pub(super) fn drain(&mut self) -> bool {
        self.shutdown();
        let result = match &mut self.state {
            State::Listening(listener) | State::FailedListener(listener) => listener.drain(),
            State::AwaitingEof { pipe, .. }
            | State::Reading(pipe)
            | State::AwaitingReply(pipe)
            | State::Writing(pipe)
            | State::Closing(pipe)
            | State::FailedPipe(pipe) => pipe.drain(),
            State::Dormant | State::Stopped | State::Rearming { .. } => Ok(true),
            State::Transition => Err(PairingPeerError::InvalidPhase),
        };
        match result {
            Ok(true) => {
                self.state = State::Stopped;
                true
            }
            Ok(false) => false,
            Err(error) => {
                self.cleanup_failure.get_or_insert(error);
                false
            }
        }
    }

    pub(super) fn remaining_owners(&self) -> usize {
        usize::from(matches!(
            self.state,
            State::Listening(_)
                | State::AwaitingEof { .. }
                | State::Reading(_)
                | State::AwaitingReply(_)
                | State::Writing(_)
                | State::Closing(_)
                | State::FailedListener(_)
                | State::FailedPipe(_)
        ))
    }

    pub(super) const fn failed(&self) -> bool {
        // A recovered creation failure is diagnostic history, not failed cleanup.
        self.cleanup_failure.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creation_failure() -> PairingPeerError {
        PairingPeerError::Native {
            stage: crate::PairingPeerStage::CreateEndpoint,
            hresult: 0x8007_0005_u32 as i32,
        }
    }

    fn rearm_at(management: &ServiceManagement) -> Instant {
        let State::Rearming { at } = management.state else {
            panic!("expected rearming, got {:?}", management.state);
        };
        at
    }

    #[test]
    fn initial_creation_failure_retries_without_overwriting_diagnostic_or_spinning() {
        let first = creation_failure();
        let mut results = vec![Err(first)];
        results.extend([Err(PairingPeerError::Busy); 8]);
        results.push(Ok(()));
        let mut management = ServiceManagement::dormant();
        management.create_results = Some(results.into());
        let before = Instant::now();
        assert_eq!(management.activate(), Err(first));
        let mut at = rearm_at(&management);
        assert!(at >= before + REARM_INTERVAL);
        assert!(at <= Instant::now() + REARM_INTERVAL);
        assert_eq!(management.remaining_owners(), 0);
        assert!(!management.failed());

        for _ in 0..8 {
            let remaining = management.create_results.as_ref().unwrap().len();
            for _ in 0..20 {
                assert!(matches!(
                    management.poll_at(at - Duration::from_nanos(1)),
                    Ok(ManagementProgress::Idle)
                ));
            }
            assert_eq!(management.create_results.as_ref().unwrap().len(), remaining);
            assert_eq!(rearm_at(&management), at);
            assert!(matches!(
                management.poll_at(at),
                Ok(ManagementProgress::Idle)
            ));
            assert_eq!(
                management.create_results.as_ref().unwrap().len(),
                remaining - 1
            );
            assert_eq!(rearm_at(&management), at + REARM_INTERVAL);
            assert_eq!(management.first_failure, Some(first));
            management.poll_at(at).unwrap();
            assert_eq!(
                management.create_results.as_ref().unwrap().len(),
                remaining - 1
            );
            at += REARM_INTERVAL;
        }
        management.poll_at(at).unwrap();
        assert!(matches!(management.state, State::Listening(_)));
        assert_eq!(management.first_failure, Some(first));
        assert!(!management.failed());
        assert!(management.drain());
        assert!(!management.failed());
    }

    #[test]
    fn one_listener_outage_records_one_row_at_the_session_seam() {
        let first = creation_failure();
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Err(first), Err(PairingPeerError::Busy)].into());
        management.state = State::Closing(ManagementPipe::empty_owner_for_test());
        let now = Instant::now();
        let mut rows = Vec::new();

        for at in [now, now + REARM_INTERVAL] {
            if let ManagementProgress::ListenerCreationFailed(error) =
                management.poll_at(at).unwrap()
            {
                super::super::observe_management_listener_failure_with(error, |event| {
                    rows.push(event)
                });
            }
        }

        assert_eq!(rows.len(), 1);
        assert_eq!(
            serde_json::to_value(&rows[0]).unwrap(),
            serde_json::json!({
                "kind": "management_listener_creation_failed",
                "error": {
                    "kind": "native",
                    "stage": 1,
                    "code": 0x8007_0005_u32,
                },
            })
        );
        assert!(management.drain());
    }

    #[test]
    fn recreation_failure_reports_once_per_episode_and_again_after_success() {
        let first = creation_failure();
        let repeated = PairingPeerError::Busy;
        let next_episode = PairingPeerError::Native {
            stage: crate::PairingPeerStage::CreateEvent,
            hresult: 0x8007_0008_u32 as i32,
        };
        let mut management = ServiceManagement::dormant();
        management.create_results =
            Some([Err(first), Err(repeated), Ok(()), Err(next_episode)].into());
        management.state = State::Closing(ManagementPipe::empty_owner_for_test());
        let now = Instant::now();

        assert!(matches!(
            management.poll_at(now),
            Ok(ManagementProgress::ListenerCreationFailed(error)) if error == first
        ));
        let retry = rearm_at(&management);
        assert!(matches!(
            management.poll_at(retry),
            Ok(ManagementProgress::Idle)
        ));
        let recovery = rearm_at(&management);
        assert!(matches!(
            management.poll_at(recovery),
            Ok(ManagementProgress::Idle)
        ));
        assert!(matches!(management.state, State::Listening(_)));

        assert!(matches!(
            management.poll_at(recovery),
            Ok(ManagementProgress::Idle)
        ));
        assert!(matches!(management.state, State::FailedListener(_)));
        assert!(matches!(
            management.poll_at(recovery),
            Ok(ManagementProgress::ListenerCreationFailed(error)) if error == next_episode
        ));
        assert!(management.drain());
    }

    #[test]
    fn single_creation_failure_recovers_and_diagnostic_does_not_block_later_rearm() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Err(creation_failure()), Ok(()), Ok(())].into());
        assert_eq!(management.activate(), Err(creation_failure()));
        let at = rearm_at(&management);
        management.poll_at(at).unwrap();
        assert!(matches!(management.state, State::Listening(_)));
        // The synthetic listener has no native endpoint; its next poll returns
        // Closed and must drain/rearm despite the initial diagnostic record.
        management.poll_at(at).unwrap();
        assert!(matches!(management.state, State::FailedListener(_)));
        management.poll_at(at).unwrap();
        assert!(matches!(management.state, State::Listening(_)));
        assert!(management.drain());
    }

    #[test]
    fn shutdown_and_uncertain_creation_cleanup_prevent_retries() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Err(creation_failure()), Ok(())].into());
        assert_eq!(management.activate(), Err(creation_failure()));
        let at = rearm_at(&management);
        management.shutdown();
        management.poll_at(at).unwrap();
        assert!(matches!(management.state, State::Stopped));
        assert_eq!(management.create_results.as_ref().unwrap().len(), 1);

        let mut management = ServiceManagement::dormant();
        management.create_results =
            Some([Err(PairingPeerError::CleanupUnconfirmed), Ok(())].into());
        assert_eq!(
            management.activate(),
            Err(PairingPeerError::CleanupUnconfirmed)
        );
        assert!(matches!(management.state, State::Stopped));
        assert!(management.failed());
        management.poll_at(at + REARM_INTERVAL).unwrap();
        assert_eq!(management.create_results.as_ref().unwrap().len(), 1);
    }

    // These exercise the real state machine with explicitly empty native
    // owners, not authenticated Windows clients. Installed-service native CI
    // separately exercises real read/disconnect/malformed-query lifecycles.
    #[test]
    fn repeated_client_failures_retain_owner_until_drain_without_poisoning_stop() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some(vec![Err(creation_failure()); 6].into());
        for (index, error) in [
            PairingPeerError::EndOfStream,
            PairingPeerError::Cancelled,
            PairingPeerError::InvalidMessage,
            PairingPeerError::DeadlineElapsed,
            PairingPeerError::Rejected,
            PairingPeerError::Closed,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(matches!(
                management.fail_pipe(ManagementPipe::empty_owner_for_test(), error),
                Ok(ManagementProgress::Idle)
            ));
            assert_eq!(management.remaining_owners(), 1);
            assert!(!management.failed());
            let progress = management.poll().unwrap();
            if index == 0 {
                assert!(matches!(
                    progress,
                    ManagementProgress::ListenerCreationFailed(error)
                        if error == creation_failure()
                ));
            } else {
                assert!(matches!(progress, ManagementProgress::Idle));
            }
            assert_eq!(management.remaining_owners(), 0);
            assert!(matches!(management.state, State::Rearming { .. }));
        }
        assert!(management.drain());
        assert!(!management.failed());
        assert!(matches!(management.state, State::Stopped));
    }

    #[test]
    fn reply_to_exited_original_client_is_isolated_and_cannot_retarget() {
        let mut management = ServiceManagement::dormant();
        management.state = State::AwaitingReply(ManagementPipe::empty_owner_for_test());
        assert_eq!(management.reply(ManagementResponse::Done), Ok(()));
        assert!(matches!(management.state, State::FailedPipe(_)));
        assert_eq!(management.remaining_owners(), 1);
        assert_eq!(
            management.reply(ManagementResponse::Done),
            Err(PairingPeerError::InvalidPhase)
        );
        assert!(!management.failed());
        assert!(management.drain());
    }

    #[test]
    fn rejected_listener_drains_before_rearm_and_stop_cancels_retry() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Err(creation_failure())].into());
        management
            .fail_listener(
                ManagementListener::empty_owner_for_test(),
                PairingPeerError::Closed,
            )
            .unwrap();
        assert_eq!(management.remaining_owners(), 1);
        management.poll().unwrap();
        assert_eq!(management.remaining_owners(), 0);
        assert!(matches!(management.state, State::Rearming { .. }));
        management.shutdown();
        management.poll().unwrap();
        assert!(matches!(management.state, State::Stopped));
        assert!(!management.failed());
    }

    #[test]
    fn completed_connection_rearms_without_an_interval() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Ok(())].into());
        management.state = State::Closing(ManagementPipe::empty_owner_for_test());
        management.poll_at(Instant::now()).unwrap();
        assert!(matches!(management.state, State::Listening(_)));
        assert!(management.create_results.as_ref().unwrap().is_empty());
        assert!(management.drain());
    }

    #[test]
    fn reply_drain_deadline_retires_the_original_owner_then_rearms() {
        let mut management = ServiceManagement::dormant();
        management.create_results = Some([Ok(())].into());
        let now = Instant::now();
        let until = now + REPLY_DRAIN_TIMEOUT;
        management.state = State::AwaitingEof {
            pipe: ManagementPipe::empty_owner_for_test(),
            until,
        };
        assert_eq!(management.remaining_owners(), 1);
        management.poll_at(until).unwrap();
        assert!(matches!(management.state, State::Closing(_)));
        assert_eq!(management.create_results.as_ref().unwrap().len(), 1);
        management.poll_at(until).unwrap();
        assert!(matches!(management.state, State::Listening(_)));
        assert!(management.drain());
    }

    #[test]
    fn cleanup_uncertainty_is_sticky_and_never_rearms() {
        let mut management = ServiceManagement::dormant();
        assert!(matches!(
            management.fail_pipe(
                ManagementPipe::empty_owner_for_test(),
                PairingPeerError::CleanupUnconfirmed,
            ),
            Err(PairingPeerError::CleanupUnconfirmed)
        ));
        assert_eq!(management.remaining_owners(), 1);
        assert!(management.failed());
        management.poll().unwrap();
        assert!(matches!(management.state, State::Stopped));
        assert!(management.failed());
    }
}
