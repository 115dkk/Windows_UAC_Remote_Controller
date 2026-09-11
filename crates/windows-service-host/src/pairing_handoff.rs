// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed rendezvous/terminal grammar only. None of these frames is a grant.
#![forbid(unsafe_code)]

use crate::PendingElevationId;
use std::fmt;

const HEADER: &[u8; 4] = b"UCPH";
const VERSION: u8 = 1;
const SHORT_FRAME: usize = 40;
const LAUNCH_FRAME: usize = 52;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Frame {
    Offer(PendingElevationId),
    HelperLaunched {
        id: PendingElevationId,
        pid: u32,
        created: u64,
    },
    Hello(PendingElevationId),
    Bound(PendingElevationId),
    Close(PendingElevationId),
    CloseAck(PendingElevationId),
}
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Offer(_) => "Offer(redacted)",
            Self::HelperLaunched { .. } => "HelperLaunched(redacted)",
            Self::Hello(_) => "Hello(redacted)",
            Self::Bound(_) => "Bound(redacted)",
            Self::Close(_) => "Close(redacted)",
            Self::CloseAck(_) => "CloseAck(redacted)",
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffError {
    Frame,
    Phase,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceSide {
    Starter,
    Helper,
}
impl ServiceSide {
    fn index(self) -> usize {
        match self {
            Self::Starter => 0,
            Self::Helper => 1,
        }
    }
}

/// Server FRAME phases only. The ServiceSession's actual native peer comparator
/// must succeed before confirm_match, each Bound write and Bound publication.
/// This pure structure is neither an authorization object nor a second engine.
pub(crate) struct ServiceHandoff {
    id: PendingElevationId,
    offered: bool,
    hello: bool,
    launched: Option<(u32, u64)>,
    matched: bool,
    bound: [bool; 2],
    closing: bool,
    close_written: [bool; 2],
    acknowledgements: [bool; 2],
    failed: bool,
}
impl fmt::Debug for ServiceHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceHandoff(rendezvous_only)")
    }
}
impl ServiceHandoff {
    pub(crate) fn new(id: PendingElevationId) -> Self {
        Self {
            id,
            offered: false,
            hello: false,
            launched: None,
            matched: false,
            bound: [false; 2],
            closing: false,
            close_written: [false; 2],
            acknowledgements: [false; 2],
            failed: false,
        }
    }
    fn reject<T>(&mut self) -> Result<T, HandoffError> {
        self.failed = true;
        Err(HandoffError::Phase)
    }
    pub(crate) fn offer(&self) -> Result<Frame, HandoffError> {
        if self.failed || self.offered || self.closing {
            Err(HandoffError::Phase)
        } else {
            Ok(Frame::Offer(self.id))
        }
    }
    pub(crate) fn offer_written(&mut self) -> Result<(), HandoffError> {
        if self.failed || self.offered || self.closing {
            return self.reject();
        }
        self.offered = true;
        Ok(())
    }
    pub(crate) fn receive(&mut self, side: ServiceSide, frame: Frame) -> Result<(), HandoffError> {
        if self.failed {
            return Err(HandoffError::Phase);
        }
        if self.closing {
            let index = side.index();
            return if frame == Frame::CloseAck(self.id)
                && self.close_written[index]
                && !self.acknowledgements[index]
            {
                self.acknowledgements[index] = true;
                Ok(())
            } else {
                self.reject()
            };
        }
        match (side, frame) {
            (ServiceSide::Starter, Frame::HelperLaunched { id, pid, created })
                if id == self.id
                    && self.offered
                    && self.launched.is_none()
                    && !self.matched
                    && pid != 0
                    && created != 0 =>
            {
                self.launched = Some((pid, created));
                Ok(())
            }
            (ServiceSide::Helper, Frame::Hello(id))
                if id == self.id && !self.hello && !self.matched =>
            {
                self.hello = true;
                Ok(())
            }
            _ => self.reject(),
        }
    }
    pub(crate) fn candidate(&self) -> Option<(u32, u64)> {
        if self.failed || self.closing || !self.offered || !self.hello {
            None
        } else {
            self.launched
        }
    }
    pub(crate) fn confirm_match(&mut self) -> Result<(), HandoffError> {
        if self.matched || self.candidate().is_none() {
            return self.reject();
        }
        self.matched = true;
        Ok(())
    }
    pub(crate) fn is_matched(&self) -> bool {
        self.matched && !self.failed
    }
    pub(crate) fn bound_frame(&self, side: ServiceSide) -> Result<Frame, HandoffError> {
        if self.failed || self.closing || !self.matched || self.bound[side.index()] {
            Err(HandoffError::Phase)
        } else {
            Ok(Frame::Bound(self.id))
        }
    }
    pub(crate) fn bound_written(&mut self, side: ServiceSide) -> Result<(), HandoffError> {
        if self.bound_frame(side).is_err() {
            return self.reject();
        }
        self.bound[side.index()] = true;
        Ok(())
    }
    pub(crate) fn is_bound(&self) -> bool {
        !self.failed && !self.closing && self.bound == [true; 2]
    }
    pub(crate) fn start_close(&mut self) -> Result<(), HandoffError> {
        if !self.is_bound() {
            return self.reject();
        }
        self.closing = true;
        Ok(())
    }
    pub(crate) fn close_frame(&self, side: ServiceSide) -> Result<Frame, HandoffError> {
        if self.failed || !self.closing || self.close_written[side.index()] {
            Err(HandoffError::Phase)
        } else {
            Ok(Frame::Close(self.id))
        }
    }
    pub(crate) fn close_written(&mut self, side: ServiceSide) -> Result<(), HandoffError> {
        if self.close_frame(side).is_err() {
            return self.reject();
        }
        self.close_written[side.index()] = true;
        Ok(())
    }
    pub(crate) fn both_acknowledged(&self) -> bool {
        !self.failed && self.closing && self.acknowledgements == [true; 2]
    }
    pub(crate) fn is_closing(&self) -> bool {
        self.closing
    }
    pub(crate) fn cancel(&mut self) {
        self.failed = true;
    }
}
impl Frame {
    fn kind(self) -> u8 {
        match self {
            Self::Offer(_) => 1,
            Self::HelperLaunched { .. } => 2,
            Self::Hello(_) => 3,
            Self::Bound(_) => 4,
            Self::Close(_) => 5,
            Self::CloseAck(_) => 6,
        }
    }
    fn id(self) -> PendingElevationId {
        match self {
            Self::Offer(id)
            | Self::Hello(id)
            | Self::Bound(id)
            | Self::Close(id)
            | Self::CloseAck(id)
            | Self::HelperLaunched { id, .. } => id,
        }
    }
    pub(crate) fn encode(self) -> Result<Vec<u8>, HandoffError> {
        let mut bytes = Vec::with_capacity(LAUNCH_FRAME);
        bytes.extend_from_slice(HEADER);
        bytes.extend_from_slice(&[VERSION, self.kind(), 0, 0]);
        bytes.extend_from_slice(&self.id().bytes());
        if let Self::HelperLaunched { pid, created, .. } = self {
            if pid == 0 || created == 0 {
                return Err(HandoffError::Frame);
            }
            bytes.extend_from_slice(&pid.to_le_bytes());
            bytes.extend_from_slice(&created.to_le_bytes());
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, HandoffError> {
        if ![SHORT_FRAME, LAUNCH_FRAME].contains(&bytes.len())
            || !bytes.starts_with(HEADER)
            || bytes[4] != VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(HandoffError::Frame);
        }
        let id = PendingElevationId::from_bytes(
            bytes[8..40].try_into().map_err(|_| HandoffError::Frame)?,
        )
        .map_err(|_| HandoffError::Frame)?;
        match (bytes[5], bytes.len()) {
            (1, SHORT_FRAME) => Ok(Self::Offer(id)),
            (3, SHORT_FRAME) => Ok(Self::Hello(id)),
            (4, SHORT_FRAME) => Ok(Self::Bound(id)),
            (5, SHORT_FRAME) => Ok(Self::Close(id)),
            (6, SHORT_FRAME) => Ok(Self::CloseAck(id)),
            (2, LAUNCH_FRAME) => {
                let pid =
                    u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| HandoffError::Frame)?);
                let created =
                    u64::from_le_bytes(bytes[44..52].try_into().map_err(|_| HandoffError::Frame)?);
                if pid == 0 || created == 0 {
                    return Err(HandoffError::Frame);
                }
                Ok(Self::HelperLaunched { id, pid, created })
            }
            _ => Err(HandoffError::Frame),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Offer,
    LaunchClaimed,
    Sending,
    AwaitBound,
    Bound,
    Ack,
    PeerClose,
    Closed,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Next {
    Launch(PendingElevationId),
    Read,
    BoundLive,
    CloseAck(PendingElevationId),
    PeerClosed,
}

/// Private phase state, driven only by the native owner's actual completions.
/// Bound is LIVE information; only authenticated Close -> Ack -> peer EOF closes.
pub(crate) struct Handoff {
    phase: Phase,
    id: Option<PendingElevationId>,
    failure: Option<HandoffError>,
}
impl Handoff {
    pub(crate) fn starter() -> Self {
        Self {
            phase: Phase::Offer,
            id: None,
            failure: None,
        }
    }
    pub(crate) fn helper(id: PendingElevationId) -> (Self, Frame) {
        (
            Self {
                phase: Phase::Sending,
                id: Some(id),
                failure: None,
            },
            Frame::Hello(id),
        )
    }
    fn reject<T>(&mut self, error: HandoffError) -> Result<T, HandoffError> {
        let first = *self.failure.get_or_insert(error);
        self.phase = Phase::Failed;
        Err(first)
    }
    pub(crate) fn receive(&mut self, frame: Frame) -> Result<Next, HandoffError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        match (self.phase, frame) {
            (Phase::Offer, Frame::Offer(id)) => {
                self.id = Some(id);
                self.phase = Phase::LaunchClaimed;
                Ok(Next::Launch(id))
            }
            (Phase::AwaitBound, Frame::Bound(id)) if self.id == Some(id) => {
                self.phase = Phase::Bound;
                Ok(Next::BoundLive)
            }
            (Phase::AwaitBound | Phase::Bound, Frame::Close(id)) if self.id == Some(id) => {
                self.phase = Phase::Ack;
                Ok(Next::CloseAck(id))
            }
            _ => self.reject(HandoffError::Phase),
        }
    }
    pub(crate) fn launched(&mut self, pid: u32, created: u64) -> Result<Frame, HandoffError> {
        if self.phase != Phase::LaunchClaimed || self.failure.is_some() || pid == 0 || created == 0
        {
            return self.reject(HandoffError::Phase);
        }
        let Some(id) = self.id else {
            return self.reject(HandoffError::Phase);
        };
        self.phase = Phase::Sending;
        Ok(Frame::HelperLaunched { id, pid, created })
    }
    pub(crate) fn written(&mut self) -> Result<Next, HandoffError> {
        if self.phase != Phase::Sending || self.failure.is_some() {
            return self.reject(HandoffError::Phase);
        }
        self.phase = Phase::AwaitBound;
        Ok(Next::Read)
    }
    pub(crate) fn ack_written(&mut self) -> Result<(), HandoffError> {
        if self.phase != Phase::Ack || self.failure.is_some() {
            return self.reject(HandoffError::Phase);
        }
        self.phase = Phase::PeerClose;
        Ok(())
    }
    pub(crate) fn peer_closed(&mut self) -> Result<Next, HandoffError> {
        if self.phase != Phase::PeerClose || self.failure.is_some() {
            return self.reject(HandoffError::Phase);
        }
        self.phase = Phase::Closed;
        Ok(Next::PeerClosed)
    }
    pub(crate) fn cancel(&mut self) {
        let _: Result<(), _> = self.reject(HandoffError::Cancelled);
    }
    pub(crate) fn closing(&self) -> bool {
        matches!(self.phase, Phase::Ack | Phase::PeerClose | Phase::Closed)
    }
    pub(crate) fn closed(&self) -> bool {
        self.phase == Phase::Closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(value: u8) -> PendingElevationId {
        PendingElevationId::from_bytes([value; 32]).unwrap()
    }
    #[test]
    fn exact_six_frames_roundtrip_and_reject_all_size_header_mutations() {
        for frame in [
            Frame::Offer(id(1)),
            Frame::HelperLaunched {
                id: id(1),
                pid: 42,
                created: 99,
            },
            Frame::Hello(id(1)),
            Frame::Bound(id(1)),
            Frame::Close(id(1)),
            Frame::CloseAck(id(1)),
        ] {
            let bytes = frame.encode().unwrap();
            assert_eq!(Frame::decode(&bytes), Ok(frame));
            for length in 0..bytes.len() {
                assert!(Frame::decode(&bytes[..length]).is_err());
            }
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(Frame::decode(&extra).is_err());
            for at in [0, 4, 5, 6, 7] {
                let mut changed = bytes.clone();
                changed[at] = 255;
                assert!(Frame::decode(&changed).is_err());
            }
            let mut zero = bytes.clone();
            zero[8..40].fill(0);
            assert!(Frame::decode(&zero).is_err());
            assert!(!format!("{frame:?}").contains(&id(1).argument()));
        }
        assert!(
            Frame::HelperLaunched {
                id: id(1),
                pid: 0,
                created: 1
            }
            .encode()
            .is_err()
        );
    }
    #[test]
    fn launch_is_claimed_once_and_identity_write_precedes_bound() {
        let mut value = Handoff::starter();
        assert_eq!(value.receive(Frame::Offer(id(1))), Ok(Next::Launch(id(1))));
        assert_eq!(
            value.launched(42, 99),
            Ok(Frame::HelperLaunched {
                id: id(1),
                pid: 42,
                created: 99
            })
        );
        assert_eq!(value.written(), Ok(Next::Read));
        assert_eq!(value.receive(Frame::Bound(id(1))), Ok(Next::BoundLive));
        assert!(!value.closed());
        assert!(!value.closing());
        assert!(value.launched(43, 100).is_err());
        assert!(value.receive(Frame::Offer(id(1))).is_err());
    }
    #[test]
    fn helper_remains_live_after_bound_and_ack_until_actual_peer_close() {
        let (mut value, hello) = Handoff::helper(id(1));
        assert_eq!(hello, Frame::Hello(id(1)));
        value.written().unwrap();
        value.receive(Frame::Bound(id(1))).unwrap();
        assert!(!value.closed());
        assert_eq!(
            value.receive(Frame::Close(id(1))),
            Ok(Next::CloseAck(id(1)))
        );
        assert!(value.closing());
        assert!(!value.closed());
        value.ack_written().unwrap();
        assert!(!value.closed());
        assert_eq!(value.peer_closed(), Ok(Next::PeerClosed));
        assert!(value.closed());
    }
    #[test]
    fn eof_without_close_or_before_ack_and_crossed_ids_are_failures() {
        let (mut no_close, _) = Handoff::helper(id(1));
        no_close.written().unwrap();
        assert!(no_close.peer_closed().is_err());
        let (mut early, _) = Handoff::helper(id(1));
        early.written().unwrap();
        early.receive(Frame::Close(id(1))).unwrap();
        assert!(early.peer_closed().is_err());
        let (mut crossed, _) = Handoff::helper(id(1));
        crossed.written().unwrap();
        assert!(crossed.receive(Frame::Bound(id(2))).is_err());
        let (mut wrong_kind, _) = Handoff::helper(id(1));
        wrong_kind.written().unwrap();
        assert!(wrong_kind.receive(Frame::CloseAck(id(1))).is_err());
    }
    #[test]
    fn cancellation_cannot_be_repaired_by_late_offer_bound_or_close() {
        let mut value = Handoff::starter();
        value.cancel();
        for frame in [
            Frame::Offer(id(1)),
            Frame::Bound(id(1)),
            Frame::Close(id(1)),
        ] {
            assert_eq!(value.receive(frame), Err(HandoffError::Cancelled));
        }
        assert!(value.launched(42, 99).is_err());
        assert!(!value.closed());
    }
    #[test]
    fn authenticated_rejection_can_close_without_ever_emitting_bound() {
        let (mut value, _) = Handoff::helper(id(1));
        value.written().unwrap();
        assert_eq!(
            value.receive(Frame::Close(id(1))),
            Ok(Next::CloseAck(id(1)))
        );
        value.ack_written().unwrap();
        assert_eq!(value.peer_closed(), Ok(Next::PeerClosed));
        assert!(value.closed());
        assert!(value.receive(Frame::Bound(id(1))).is_err());
    }
    #[test]
    fn failed_or_cancelled_launch_claim_cannot_retry_with_later_metadata() {
        let mut failed = Handoff::starter();
        failed.receive(Frame::Offer(id(1))).unwrap();
        assert!(failed.launched(0, 99).is_err());
        assert!(failed.launched(42, 99).is_err());
        let mut cancelled = Handoff::starter();
        cancelled.receive(Frame::Offer(id(1))).unwrap();
        cancelled.cancel();
        assert!(cancelled.launched(42, 99).is_err());
        assert!(cancelled.receive(Frame::Offer(id(2))).is_err());
    }
    fn matched_server(hello_first: bool) -> ServiceHandoff {
        let mut server = ServiceHandoff::new(id(1));
        assert_eq!(server.offer(), Ok(Frame::Offer(id(1))));
        if hello_first {
            server
                .receive(ServiceSide::Helper, Frame::Hello(id(1)))
                .unwrap();
        }
        server.offer_written().unwrap();
        server
            .receive(
                ServiceSide::Starter,
                Frame::HelperLaunched {
                    id: id(1),
                    pid: 42,
                    created: 99,
                },
            )
            .unwrap();
        if !hello_first {
            server
                .receive(ServiceSide::Helper, Frame::Hello(id(1)))
                .unwrap();
        }
        assert_eq!(server.candidate(), Some((42, 99)));
        assert!(server.bound_frame(ServiceSide::Starter).is_err());
        // Synthetic native-match success only. Production calls the original
        // peer comparator before this phase transition and every Bound operation.
        server.confirm_match().unwrap();
        server
    }
    #[test]
    fn server_accepts_both_message_orders_but_never_publishes_one_sided_bound() {
        for hello_first in [true, false] {
            let mut server = matched_server(hello_first);
            assert!(server.is_matched());
            assert!(!server.is_bound());
            server.bound_written(ServiceSide::Starter).unwrap();
            assert!(!server.is_bound());
            server.bound_written(ServiceSide::Helper).unwrap();
            assert!(server.is_bound());
            assert!(server.candidate().is_some());
            server.cancel();
            assert!(!server.is_bound());
            assert!(server.bound_frame(ServiceSide::Starter).is_err());
        }
    }
    #[test]
    fn server_cannot_close_either_peer_until_both_exact_acknowledgements() {
        let mut server = matched_server(true);
        server.bound_written(ServiceSide::Starter).unwrap();
        server.bound_written(ServiceSide::Helper).unwrap();
        server.start_close().unwrap();
        assert!(!server.is_bound());
        assert!(server.is_closing());
        server.close_written(ServiceSide::Starter).unwrap();
        server
            .receive(ServiceSide::Starter, Frame::CloseAck(id(1)))
            .unwrap();
        assert!(!server.both_acknowledged());
        server.close_written(ServiceSide::Helper).unwrap();
        assert!(!server.both_acknowledged());
        server
            .receive(ServiceSide::Helper, Frame::CloseAck(id(1)))
            .unwrap();
        assert!(server.both_acknowledged());
    }
    #[test]
    fn server_rejects_crossed_ids_duplicate_hello_and_ack_without_close() {
        let mut server = ServiceHandoff::new(id(1));
        server.offer_written().unwrap();
        assert!(
            server
                .receive(ServiceSide::Helper, Frame::Hello(id(2)))
                .is_err()
        );
        assert!(
            server
                .receive(ServiceSide::Helper, Frame::Hello(id(1)))
                .is_err()
        );
        let mut server = ServiceHandoff::new(id(1));
        server
            .receive(ServiceSide::Helper, Frame::Hello(id(1)))
            .unwrap();
        assert!(
            server
                .receive(ServiceSide::Helper, Frame::Hello(id(1)))
                .is_err()
        );
        let mut server = matched_server(false);
        assert!(
            server
                .receive(ServiceSide::Starter, Frame::CloseAck(id(1)))
                .is_err()
        );
        assert!(!server.both_acknowledged());
        assert!(!server.is_bound());
    }
}
