// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TCP/TLS and host-store delivery; signatures/authentication are synthetic.
use super::*;
use android_controller::{
    ApprovalClock, ApprovalClockError, ApprovalPlan, ApprovalPlanOwner, ApprovalSendOutcome,
    ApprovalSubmission, ApprovalTime, ApprovalTransition, ApprovalWriteProgress, QueuedApproval,
    SendRetry,
};
use approval_protocol::{DecisionPublicKey, DecisionPurpose, SignedDecision};
use notification_policy::{AlertMode, Schedule};

struct NativeTime(Arc<HostClock>);
impl ApprovalClock for NativeTime {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        Ok(ApprovalTime::new(boot(), self.0.inbox()))
    }
}
struct SendFixture {
    pair: Pair,
    approvals: ApprovalPlanOwner,
    owner: DurableInbox,
    clock: Arc<HostClock>,
    reference: PeerAssociationRef,
    binding: RequestBinding,
    _directory: tempfile::TempDir,
}
async fn setup() -> SendFixture {
    let temp = tempfile::tempdir().unwrap();
    let clock = HostClock::new();
    let (mut owner, reference) = owner(&temp, &clock);
    let mut sockets = pair(
        &owner,
        reference,
        clock.clone(),
        CancellationToken::new(),
        Arc::new(ConnectionBudget::new(2).unwrap()),
    )
    .await;
    let message = initial_clock(&mut sockets, &owner, &clock, PC_SIGNING_KEY)
        .await
        .unwrap();
    let sampled = sockets
        .phone
        .apply_event(&mut owner, message, clock.inbox())
        .unwrap();
    assert_clock_update(&sampled, &owner, reference);
    let (event, binding) = opened(89);
    let message = send(&mut sockets, event).await;
    let opened = sockets
        .phone
        .apply_event(&mut owner, message, clock.inbox())
        .unwrap();
    assert!(
        opened
            .committed()
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    let approvals = ApprovalPlanOwner::new(&owner, boot()).unwrap();
    SendFixture {
        pair: sockets,
        approvals,
        owner,
        clock,
        reference,
        binding,
        _directory: temp,
    }
}
fn success<T>(result: ApprovalTransition<T>) -> T {
    let (checks, result) = result.into_parts();
    assert!(
        checks
            .iter()
            .all(|check| check.update().effects().is_empty() && check.update().fault().is_none())
    );
    result.unwrap_or_else(|error| panic!("synthetic approval fixture: {error:?}"))
}
impl SendFixture {
    fn signed(&mut self) -> (ApprovalPlan, ApprovalSubmission) {
        let mut time = NativeTime(self.clock.clone());
        let plan = success(self.approvals.begin(
            &mut self.owner,
            request_key(self.binding),
            &mut time,
        ));
        let attempt = success(self.approvals.claim(&mut self.owner, &plan, &mut time));
        let signature: Signature = SigningKey::from_slice(&[3; 32])
            .unwrap()
            .sign(&attempt.signing_bytes().unwrap());
        let submission = success(self.approvals.finish(
            &mut self.owner,
            &attempt,
            signature.to_der().as_bytes(),
            &mut time,
        ));
        self.approvals.retire_after_native_cleanup(&plan).unwrap();
        (plan, submission)
    }
    fn queue(&mut self, submission: ApprovalSubmission) -> QueuedApproval {
        let sent = self.pair.phone.queue_approval(
            &mut self.owner,
            submission,
            &mut NativeTime(self.clock.clone()),
        );
        assert_eq!(sent.checks().len(), 1);
        assert!(sent.checks()[0].update().effects().is_empty());
        match sent.into_parts().1 {
            ApprovalSendOutcome::Queued(ticket) => ticket,
            other => panic!("unexpected send: {other:?}"),
        }
    }
    async fn drain(&mut self, ticket: &QueuedApproval) {
        let (drained, received) =
            tokio::join!(self.pair.phone.next_event(), self.pair.pc.next_event());
        assert!(matches!(drained.unwrap(), PcSocketEvent::OutboundDrained));
        let bytes = match received.unwrap() {
            SocketEvent::Frame(frame) => frame.into_bytes(),
            other => panic!("unexpected PC event: {other:?}"),
        };
        let signed = SignedDecision::from_wire(&bytes).unwrap();
        let key = DecisionPublicKey::from_sec1_bytes(
            SigningKey::from_slice(&[3; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        signed.verify(&key).unwrap();
        assert_eq!(signed.statement().binding(), self.binding);
        assert_eq!(signed.statement().purpose(), DecisionPurpose::Approve);
        assert_eq!(ticket.progress(), ApprovalWriteProgress::WrittenToSocket);
        assert_eq!(self.owner.counts().unwrap().active(), 1);
        assert!(self.owner.pending_outcomes().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_approval_reaches_actual_peer_frame_without_fabricating_pc_outcome() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, submission) = f.signed();
        let ticket = f.queue(submission);
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Queued);
        assert_eq!(ticket.binding(), f.binding);
        f.drain(&ticket).await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_revocation_after_queue_closes_before_any_complete_peer_frame() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (plan, submission) = f.signed();
        let ticket = f.queue(submission);
        let (receipt, removal) = f
            .owner
            .revoke_peer_association_from_trusted_host(f.reference)
            .unwrap();
        assert!(receipt.changed());
        assert_eq!(removal, PeerAssociationRemoval::Removed);
        assert!(
            !plan.is_cancelled(),
            "the domain lease, not a manual plan cancel, must stop this write"
        );
        let (phone, peer) = tokio::join!(f.pair.phone.next_event(), f.pair.pc.next_event());
        assert!(phone.is_err());
        assert!(!matches!(peer, Ok(SocketEvent::Frame(_))));
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Stopped);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_withdrawal_after_native_retirement_still_invalidates_the_queued_send() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (plan, submission) = f.signed();
        let ticket = f.queue(submission);
        let policy = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
        let changed = f.owner.update_policy(policy, f.clock.inbox()).unwrap();
        assert!(
            changed
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Withdraw { .. }))
        );
        assert!(!plan.is_cancelled());
        let (phone, peer) = tokio::join!(f.pair.phone.next_event(), f.pair.pc.next_event());
        assert!(phone.is_err());
        assert!(!matches!(peer, Ok(SocketEvent::Frame(_))));
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Stopped);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_plan_cancel_is_retained_after_submission_bytes_enter_transport() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (plan, submission) = f.signed();
        let ticket = f.queue(submission);
        plan.cancel();
        assert!(f.pair.phone.next_event().await.is_err());
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Stopped);
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_committed_history_change_does_not_cancel_a_valid_send() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, submission) = f.signed();
        let ticket = f.queue(submission);
        let _ = f.owner.clear_history().unwrap();
        f.drain(&ticket).await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_new_service_epoch_after_queue_stops_the_old_epoch_write() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        f.pair
            .phone
            .queue_clock_probe(&f.owner, f.clock.inbox())
            .unwrap();
        let (sent, got) = tokio::join!(f.pair.phone.next_event(), f.pair.pc.next_event());
        assert!(matches!(sent.unwrap(), PcSocketEvent::OutboundDrained));
        let probe = match got.unwrap() {
            SocketEvent::Frame(frame) => ClockProbeRequest::from_wire(&frame.into_bytes()).unwrap(),
            _ => panic!("refresh clock"),
        };
        let new_epoch = BootEpoch::from_bytes([33; 32]).unwrap();
        let received = send(
            &mut f.pair,
            PcEvent::Clock {
                pc: pc(),
                epoch: new_epoch,
                probe: probe.nonce(),
                sampled_at: ServiceTick::from_nanos_since_epoch(0),
            },
        )
        .await;
        // Received evidence may be queued separately from the durable owner.
        // It is deliberately applied after an approval has entered the queue.
        let (_, submission) = f.signed();
        let ticket = f.queue(submission);
        let committed = f
            .pair
            .phone
            .apply_event(&mut f.owner, received, f.clock.inbox())
            .unwrap();
        assert!(committed.committed().update().fault().is_none());
        assert_eq!(f.owner.counts().unwrap().sources(), 2);
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Stopped);
        assert!(committed.check_current(&f.owner).is_err());
        assert!(f.pair.phone.next_event().await.is_err());
        assert!(!matches!(
            f.pair.pc.next_event().await,
            Ok(SocketEvent::Frame(_))
        ));
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_retry_preserves_original_signature_window_without_new_authentication() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, submission) = f.signed();
        let original = submission.original_window();
        f.pair
            .phone
            .queue_clock_probe(&f.owner, f.clock.inbox())
            .unwrap();
        let blocked =
            f.pair
                .phone
                .queue_approval(&mut f.owner, submission, &mut NativeTime(f.clock.clone()));
        assert!(blocked.checks().is_empty());
        let retained = match blocked.into_parts().1 {
            ApprovalSendOutcome::Retry {
                reason: SendRetry::Busy,
                submission,
            } => submission,
            other => panic!("unexpected busy result: {other:?}"),
        };
        assert_eq!(retained.original_window(), original);
        let (sent, got) = tokio::join!(f.pair.phone.next_event(), f.pair.pc.next_event());
        assert!(matches!(sent.unwrap(), PcSocketEvent::OutboundDrained));
        let probe = match got.unwrap() {
            SocketEvent::Frame(frame) => ClockProbeRequest::from_wire(&frame.into_bytes()).unwrap(),
            _ => panic!("clock request"),
        };
        let reply = send(
            &mut f.pair,
            PcEvent::Clock {
                pc: pc(),
                epoch: epoch(),
                probe: probe.nonce(),
                sampled_at: ServiceTick::from_nanos_since_epoch(0),
            },
        )
        .await;
        let update = f
            .pair
            .phone
            .apply_event(&mut f.owner, reply, f.clock.inbox())
            .unwrap();
        assert!(update.committed().update().fault().is_none());
        let ticket = f.queue(retained);
        f.drain(&ticket).await;
    })
    .await
    .unwrap();
}
