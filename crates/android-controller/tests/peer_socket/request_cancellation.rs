// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TCP/TLS and isolated host-store fixtures, not native auth/quiescence.
use super::*;
use android_controller::{
    ApprovalClock, ApprovalClockError, ApprovalError, ApprovalPlan, ApprovalPlanOwner,
    ApprovalSendOutcome, ApprovalSubmission, ApprovalTime, ApprovalTransition,
    ApprovalWriteProgress, QueuedApproval,
};
use approval_protocol::{DecisionPublicKey, DecisionPurpose, SignedDecision};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};

struct NativeTime(Arc<HostClock>);
impl ApprovalClock for NativeTime {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        Ok(ApprovalTime::new(boot(), self.0.inbox()))
    }
}
struct Fixture {
    pair: Pair,
    approvals: ApprovalPlanOwner,
    owner: DurableInbox,
    clock: Arc<HostClock>,
    a: RequestBinding,
    b: RequestBinding,
    directory: tempfile::TempDir,
}
async fn setup() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let clock = HostClock::new();
    let (mut owner, reference) = owner(&temp, &clock);
    let budget = Arc::new(ConnectionBudget::new(2).unwrap());
    let (phone_socket, pc_socket) = sockets().await;
    let limits = SocketLimits::default().with_io_chunk_bytes(17).unwrap();
    let phone = AssociatedPcSocket::new(
        &owner,
        reference,
        PcSocketInputs {
            socket: phone_socket,
            identity: identity(PHONE_TRANSPORT_KEY, EndpointRole::Client),
            budget: budget.clone(),
            clock: clock.clone(),
            limits,
            stop: CancellationToken::new(),
        },
    )
    .unwrap();
    let transport = PeerTransport::server(
        budget,
        identity(PC_TRANSPORT_KEY, EndpointRole::Server),
        public(PHONE_TRANSPORT_KEY),
        clock.now().unwrap(),
    )
    .unwrap();
    let pc = SocketDriver::new(
        pc_socket,
        transport,
        clock.clone(),
        limits,
        CancellationToken::new(),
    )
    .unwrap();
    let mut pair = Pair { phone, pc };
    let message = initial_clock(&mut pair, &owner, &clock, PC_SIGNING_KEY)
        .await
        .unwrap();
    let sampled = pair
        .phone
        .apply_event(&mut owner, message, clock.inbox())
        .unwrap();
    assert_clock_update(&sampled, &owner, reference);
    let (event, a) = opened(91);
    let received = send(&mut pair, event).await;
    let update = pair
        .phone
        .apply_event(&mut owner, received, clock.inbox())
        .unwrap();
    assert!(
        update
            .committed()
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    let (event, b) = opened(92);
    let received = send(&mut pair, event).await;
    let update = pair
        .phone
        .apply_event(&mut owner, received, clock.inbox())
        .unwrap();
    assert!(
        update
            .committed()
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    let approvals = ApprovalPlanOwner::new(&owner, boot()).unwrap();
    Fixture {
        pair,
        approvals,
        owner,
        clock,
        a,
        b,
        directory: temp,
    }
}
fn success<T>(transition: ApprovalTransition<T>) -> T {
    let (checks, result) = transition.into_parts();
    assert!(
        checks
            .iter()
            .all(|check| check.update().effects().is_empty() && check.update().fault().is_none())
    );
    result.unwrap_or_else(|error| panic!("synthetic approval fixture {error:?}"))
}
impl Fixture {
    fn signed(&mut self, binding: RequestBinding) -> (ApprovalPlan, ApprovalSubmission) {
        let mut clock = NativeTime(self.clock.clone());
        let plan = success(
            self.approvals
                .begin(&mut self.owner, request_key(binding), &mut clock),
        );
        let attempt = success(self.approvals.claim(&mut self.owner, &plan, &mut clock));
        let signature: Signature = SigningKey::from_slice(&[3; 32])
            .unwrap()
            .sign(&attempt.signing_bytes().unwrap());
        let submission = success(self.approvals.finish(
            &mut self.owner,
            &attempt,
            signature.to_der().as_bytes(),
            &mut clock,
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
        match sent.into_parts().1 {
            ApprovalSendOutcome::Queued(ticket) => ticket,
            other => panic!("unexpected approval send {other:?}"),
        }
    }
    async fn receive(&mut self, binding: RequestBinding) {
        let (phone, pc) = tokio::join!(self.pair.phone.next_event(), self.pair.pc.next_event());
        assert!(matches!(phone.unwrap(), PcSocketEvent::OutboundDrained));
        let wire = match pc.unwrap() {
            SocketEvent::Frame(frame) => frame.into_bytes(),
            other => panic!("one complete approval frame {other:?}"),
        };
        let signed = SignedDecision::from_wire(&wire).unwrap();
        let key = DecisionPublicKey::from_sec1_bytes(
            SigningKey::from_slice(&[3; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        signed.verify(&key).unwrap();
        assert_eq!(signed.statement().purpose(), DecisionPurpose::Approve);
        assert_eq!(signed.statement().binding(), binding);
        assert!(self.owner.pending_outcomes().unwrap().is_empty());
        assert!(self.owner.history().unwrap().is_empty());
    }
}
async fn partial_write(phone: &mut AssociatedPcSocket) {
    let mut initial = None;
    for _ in 0..128 {
        let event = {
            let mut future = pin!(phone.next_event());
            poll_fn(|cx| match future.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(None),
                Poll::Ready(value) => Poll::Ready(Some(value)),
            })
            .await
        };
        assert!(event.is_none(), "approval must remain partial: {event:?}");
        let pending = phone.pending_counts();
        if let Some(initial) = initial {
            if pending.socket_write_bytes > 0 && pending.socket_write_bytes < initial {
                assert!(pending.outbound_frame);
                assert!(!pending.transport.outbound_frame);
                return;
            }
        } else if pending.socket_write_bytes > 0 {
            initial = Some(pending.socket_write_bytes);
        }
    }
    panic!("bounded public polls did not expose a partial approval write")
}
async fn assert_stopped(pair: &mut Pair, ticket: &QueuedApproval) {
    let (phone, pc) = tokio::join!(pair.phone.next_event(), pair.pc.next_event());
    assert!(
        matches!(
            phone,
            Err(PeerSocketError::Socket(SocketError::OutboundRevoked))
        ),
        "cancelled write: {phone:?}"
    );
    assert!(
        !matches!(pc, Ok(SocketEvent::Frame(_))),
        "no complete approval frame: {pc:?}"
    );
    assert_eq!(ticket.progress(), ApprovalWriteProgress::Stopped);
    assert!(!pair.phone.pending_counts().outbound_frame);
    assert_eq!(pair.phone.pending_counts().socket_write_bytes, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_cancel_reaches_context_retained_only_by_partial_socket_guard() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (plan, submission) = f.signed(f.a);
        let ticket = f.queue(submission);
        drop(plan); // Slot retired, submission consumed: only the driver guard remains.
        partial_write(&mut f.pair.phone).await;
        let before = witness(&f.directory, &f.owner);
        let receipt = f.approvals.cancel_request(request_key(f.a));
        assert_eq!(receipt.matched_contexts(), 1);
        assert_eq!(
            f.approvals
                .cancel_request(request_key(f.a))
                .matched_contexts(),
            1
        );
        let after = witness(&f.directory, &f.owner);
        assert!(before.snapshot == after.snapshot);
        assert_eq!(before.counts, after.counts);
        assert_eq!(before.history, after.history);
        assert_eq!(before.outcomes, after.outcomes);
        assert_stopped(&mut f.pair, &ticket).await;
        assert_eq!(
            f.approvals
                .cancel_request(request_key(f.a))
                .matched_contexts(),
            0
        );
        assert_eq!(f.owner.counts().unwrap().active(), 2);
        assert!(f.owner.pending_outcomes().unwrap().is_empty());
        assert!(f.owner.history().unwrap().is_empty());
    })
    .await
    .expect("bounded request-scoped partial approval cancellation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_one_request_reaches_active_and_retired_contexts_but_another_request_can_send() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (retired_a, submission_a) = f.signed(f.a);
        let (retired_b, submission_b) = f.signed(f.b);
        let mut clock = NativeTime(f.clock.clone());
        let active_a = success(
            f.approvals
                .begin(&mut f.owner, request_key(f.a), &mut clock),
        );
        let attempt_a = success(f.approvals.claim(&mut f.owner, &active_a, &mut clock));
        let before = witness(&f.directory, &f.owner);
        assert_eq!(
            f.approvals
                .cancel_request(request_key(f.a))
                .matched_contexts(),
            2
        );
        assert!(retired_a.is_cancelled());
        assert!(submission_a.is_cancelled());
        assert!(active_a.is_cancelled());
        assert!(attempt_a.is_cancelled());
        assert!(!retired_b.is_cancelled());
        assert!(!submission_b.is_cancelled());
        let after = witness(&f.directory, &f.owner);
        assert!(before.snapshot == after.snapshot);
        assert_eq!(before.counts, after.counts);
        let busy = f
            .approvals
            .begin(&mut f.owner, request_key(f.b), &mut clock);
        assert_eq!(busy.outcome().unwrap_err(), &ApprovalError::Busy);
        assert!(busy.checks().is_empty());
        f.approvals.retire_after_native_cleanup(&active_a).unwrap(); // No native operation in fixture.
        let ticket = f.queue(submission_b);
        assert_eq!(
            f.approvals
                .cancel_request(request_key(f.a))
                .matched_contexts(),
            2
        );
        assert_eq!(ticket.progress(), ApprovalWriteProgress::Queued);
        f.receive(f.b).await;
        assert_eq!(ticket.progress(), ApprovalWriteProgress::WrittenToSocket);
        assert!(!retired_b.is_cancelled());
        assert_eq!(
            submission_a.into_signed_decision().unwrap_err(),
            ApprovalError::Cancelled
        );
    })
    .await
    .expect("bounded exact-request cancellation isolation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_or_drop_still_invalidates_a_retired_guard_without_a_plan_handle() {
    tokio::time::timeout(TEST_DEADLINE, async {
        for explicit_close in [false, true] {
            let mut f = setup().await;
            let (plan, submission) = f.signed(f.a);
            let ticket = f.queue(submission);
            drop(plan);
            partial_write(&mut f.pair.phone).await;
            if explicit_close {
                f.approvals.close();
            } else {
                drop(f.approvals);
            }
            assert_stopped(&mut f.pair, &ticket).await;
            assert!(f.owner.pending_outcomes().unwrap().is_empty());
            assert!(f.owner.history().unwrap().is_empty());
        }
    })
    .await
    .expect("bounded retired-guard owner close/drop");
}
