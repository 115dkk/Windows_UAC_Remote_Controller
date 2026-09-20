// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-session-owned management listener and one-request connections.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use crate::{
    PairingPeerError, PairingPipeProgress,
    ffi::{ManagementClientClass, ManagementListener, ManagementPipe},
    management_protocol::{ManagementRequest, ManagementResponse, decode_request, encode_response},
};

#[derive(Debug)]
pub(super) enum ManagementProgress {
    Idle,
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
    Closing(ManagementPipe),
    FailedListener(ManagementListener),
    FailedPipe(ManagementPipe),
    Rearming { at: Instant },
    Transition,
    Stopped,
}

#[derive(Debug)]
pub(super) struct ServiceManagement {
    state: State,
    first_failure: Option<PairingPeerError>,
    cleanup_failure: Option<PairingPeerError>,
    stopping: bool,
}

impl ServiceManagement {
    pub(super) const fn dormant() -> Self {
        Self {
            state: State::Dormant,
            first_failure: None,
            cleanup_failure: None,
            stopping: false,
        }
    }

    pub(super) fn activate(&mut self) -> Result<(), PairingPeerError> {
        if !matches!(self.state, State::Dormant) || self.stopping || self.first_failure.is_some() {
            return Err(PairingPeerError::InvalidPhase);
        }
        self.listen()
    }

    fn listen(&mut self) -> Result<(), PairingPeerError> {
        if self.stopping || self.first_failure.is_some() {
            self.state = State::Stopped;
            return Err(PairingPeerError::Cancelled);
        }
        let mut listener = match ManagementListener::create() {
            Ok(listener) => listener,
            Err(error) => {
                self.record_failure(error);
                self.state = State::Stopped;
                return Err(error);
            }
        };
        if let Err(error) = listener.begin_connect() {
            listener.cancel();
            self.record_failure(error);
            self.state = State::FailedListener(listener);
            return Err(error);
        }
        self.state = State::Listening(listener);
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

    fn schedule_rearm(&mut self) {
        self.state = if self.stopping || self.failed() {
            State::Stopped
        } else {
            // At most one listener creation attempt per interval. This bounds
            // retry work without letting a few short-lived callers permanently
            // exhaust management availability. No live owner exists here.
            State::Rearming {
                at: Instant::now() + Duration::from_millis(250),
            }
        };
    }

    pub(super) fn poll(&mut self) -> Result<ManagementProgress, PairingPeerError> {
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
                    pipe.cancel();
                    self.state = State::Closing(pipe);
                    Ok(ManagementProgress::Replied)
                }
                Ok(_) => self.fail_pipe(pipe, PairingPeerError::InvalidPhase),
                Err(error) => self.fail_pipe(pipe, error),
            },
            State::Closing(mut pipe) => match pipe.drain() {
                Ok(false) => {
                    self.state = State::Closing(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(true) => {
                    drop(pipe);
                    self.schedule_rearm();
                    Ok(ManagementProgress::Idle)
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
                    self.schedule_rearm();
                    Ok(ManagementProgress::Idle)
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
                    self.schedule_rearm();
                    Ok(ManagementProgress::Idle)
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
                if self.stopping || self.failed() {
                    self.state = State::Stopped;
                } else if Instant::now() < at {
                    self.state = State::Rearming { at };
                } else {
                    // Unlike initial activation, transient rearm failures do
                    // not retire the core service. Native context/first-instance
                    // checks are still applied on every attempt.
                    match ManagementListener::create() {
                        Ok(mut listener) => {
                            if let Err(error) = listener.begin_connect() {
                                return self.fail_listener(listener, error);
                            }
                            self.state = State::Listening(listener);
                        }
                        Err(error) => {
                            self.schedule_rearm();
                            return self.connection_failure(error);
                        }
                    }
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
            State::Reading(pipe)
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
            State::Reading(pipe)
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
                | State::Reading(_)
                | State::AwaitingReply(_)
                | State::Writing(_)
                | State::Closing(_)
                | State::FailedListener(_)
                | State::FailedPipe(_)
        ))
    }

    pub(super) const fn failed(&self) -> bool {
        self.first_failure.is_some() || self.cleanup_failure.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the real state machine with explicitly empty native
    // owners, not authenticated Windows clients. Installed-service native CI
    // separately exercises real read/disconnect/malformed-query lifecycles.
    #[test]
    fn repeated_client_failures_retain_owner_until_drain_without_poisoning_stop() {
        let mut management = ServiceManagement::dormant();
        for error in [
            PairingPeerError::EndOfStream,
            PairingPeerError::Cancelled,
            PairingPeerError::InvalidMessage,
            PairingPeerError::DeadlineElapsed,
            PairingPeerError::Rejected,
            PairingPeerError::Closed,
        ] {
            assert!(matches!(
                management.fail_pipe(ManagementPipe::empty_owner_for_test(), error),
                Ok(ManagementProgress::Idle)
            ));
            assert_eq!(management.remaining_owners(), 1);
            assert!(!management.failed());
            assert!(matches!(management.poll(), Ok(ManagementProgress::Idle)));
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
