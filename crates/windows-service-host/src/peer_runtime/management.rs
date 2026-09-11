// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-session-owned management listener and one-request connections.
#![forbid(unsafe_code)]

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
    ) -> PairingPeerError {
        listener.cancel();
        let first = self.record_failure(error);
        self.state = State::FailedListener(listener);
        first
    }

    fn fail_pipe(&mut self, mut pipe: ManagementPipe, error: PairingPeerError) -> PairingPeerError {
        pipe.cancel();
        let first = self.record_failure(error);
        self.state = State::FailedPipe(pipe);
        first
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
                    Err(error) => Err(self.fail_pipe(pipe, error)),
                },
                Err(error) => Err(self.fail_listener(listener, error)),
            },
            State::Reading(mut pipe) => match pipe.poll() {
                Ok(PairingPipeProgress::Pending) => {
                    self.state = State::Reading(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(PairingPipeProgress::Read(bytes)) => {
                    let class = match pipe.class() {
                        Ok(class) => class,
                        Err(error) => return Err(self.fail_pipe(pipe, error)),
                    };
                    let request = match decode_request(&bytes) {
                        Ok(request) => request,
                        Err(_) => {
                            return Err(self.fail_pipe(pipe, PairingPeerError::InvalidMessage));
                        }
                    };
                    self.state = State::AwaitingReply(pipe);
                    Ok(ManagementProgress::Request { class, request })
                }
                Ok(_) => Err(self.fail_pipe(pipe, PairingPeerError::InvalidPhase)),
                Err(error) => Err(self.fail_pipe(pipe, error)),
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
                Ok(_) => Err(self.fail_pipe(pipe, PairingPeerError::InvalidPhase)),
                Err(error) => Err(self.fail_pipe(pipe, error)),
            },
            State::Closing(mut pipe) => match pipe.drain() {
                Ok(false) => {
                    self.state = State::Closing(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Ok(true) if self.stopping => {
                    self.state = State::Stopped;
                    Ok(ManagementProgress::Idle)
                }
                Ok(true) => {
                    self.state = State::Stopped;
                    self.listen()?;
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => Err(self.fail_pipe(pipe, error)),
            },
            State::FailedListener(mut listener) => match listener.drain() {
                Ok(true) => {
                    self.state = State::Stopped;
                    Ok(ManagementProgress::Idle)
                }
                Ok(false) => {
                    self.state = State::FailedListener(listener);
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    self.state = State::FailedListener(listener);
                    Ok(ManagementProgress::Idle)
                }
            },
            State::FailedPipe(mut pipe) => match pipe.drain() {
                Ok(true) => {
                    self.state = State::Stopped;
                    Ok(ManagementProgress::Idle)
                }
                Ok(false) => {
                    self.state = State::FailedPipe(pipe);
                    Ok(ManagementProgress::Idle)
                }
                Err(error) => {
                    self.cleanup_failure.get_or_insert(error);
                    self.state = State::FailedPipe(pipe);
                    Ok(ManagementProgress::Idle)
                }
            },
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
                Err(error) => Err(self.fail_pipe(pipe, error)),
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
            Err(_) => return Err(self.fail_pipe(pipe, PairingPeerError::InvalidMessage)),
        };
        match pipe.begin_write(&wire) {
            Ok(()) => {
                self.state = State::Writing(pipe);
                Ok(())
            }
            Err(error) => Err(self.fail_pipe(pipe, error)),
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
            State::Dormant => self.state = State::Stopped,
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
            State::Dormant | State::Stopped => Ok(true),
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
