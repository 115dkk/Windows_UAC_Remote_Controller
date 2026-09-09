// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual TCP/TLS/host-store path, with software keys and controlled native time.
//! No native denial key operation, authentication, enrollment or Windows proof.
use super::*;
use android_controller::{
    ApprovalClock, ApprovalClockError, ApprovalPlan, ApprovalPlanOwner, ApprovalSendOutcome,
    ApprovalSubmission, ApprovalTime, ApprovalTransition, ApprovalWriteProgress, DenialAttempt,
    DenialOwner, DenialSendOutcome, DenialTransition, DenialWriteProgress, PreparedDenial,
    QueuedDenial, SendIssue, SendRetry,
};
use approval_protocol::{DecisionPublicKey, DecisionPurpose, SignedDecision, UnsignedDecision};
use notification_policy::{AlertMode, Schedule};
use std::{
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::AtomicU64,
    task::Poll,
};

const REQUEST_LIFETIME: u64 = 5_000 * MILLI;

// One synthetic monotonic projection for BOTH socket Instants and phone nanos.
// Advancing it tests exact deadlines without sleeps or a larger outer timeout.
struct ControlledClock {
    origin: Instant,
    nanos: AtomicU64,
}
impl ControlledClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            nanos: AtomicU64::new(0),
        })
    }
    fn set(&self, nanos: u64) {
        let previous = self.nanos.load(Ordering::SeqCst);
        assert!(nanos >= previous);
        self.nanos.store(nanos, Ordering::SeqCst);
    }
    fn inbox(&self) -> InboxClock {
        let nanos = self.nanos.load(Ordering::SeqCst);
        InboxClock::new(
            ClockReading::new(
                MonotonicTime::from_millis(nanos / MILLI),
                LocalTime::new(Weekday::Monday, 600).unwrap(),
            ),
            nanos,
        )
        .unwrap()
    }
}
impl SocketClock for ControlledClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        self.origin
            .checked_add(Duration::from_nanos(self.nanos.load(Ordering::SeqCst)))
            .ok_or(SocketClockUnavailable)
    }
}
struct NativeTime(Arc<ControlledClock>);
impl ApprovalClock for NativeTime {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        Ok(ApprovalTime::new(boot(), self.0.inbox()))
    }
}
struct SendFixture {
    pair: Pair,
    denials: DenialOwner,
    approvals: ApprovalPlanOwner,
    owner: DurableInbox,
    clock: Arc<ControlledClock>,
    reference: PeerAssociationRef,
    binding: RequestBinding,
    _directory: tempfile::TempDir,
}
async fn setup() -> SendFixture {
    let temp = tempfile::tempdir().unwrap();
    let clock = ControlledClock::new();
    let (mut owner, initial) = DurableInbox::create_fresh_host_model(
        directory(&temp),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        boot(),
        clock.inbox(),
    )
    .unwrap();
    assert!(initial.update().effects().is_empty());
    let challenge = LocalAttestationChallenge::from_bytes([65; 32]).unwrap();
    assert!(
        owner
            .begin_local_key_creation(handle(), challenge)
            .unwrap()
            .changed()
    );
    let (recorded, observed) = owner
        .record_local_key_creation(
            LocalKeySetDescriptor::new(
                handle(),
                challenge,
                public(3),
                public(4),
                public(PHONE_TRANSPORT_KEY),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(recorded.changed());
    assert_eq!(observed, LocalKeyObservation::RecordedUnverified);
    let (_, mutation) = owner
        .record_peer_association_from_trusted_host(association())
        .unwrap();
    let reference = reference(mutation);
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
    let pc_transport = PeerTransport::server(
        budget,
        identity(PC_TRANSPORT_KEY, EndpointRole::Server),
        public(PHONE_TRANSPORT_KEY),
        clock.now().unwrap(),
    )
    .unwrap();
    let pc_socket = SocketDriver::new(
        pc_socket,
        pc_transport,
        clock.clone(),
        limits,
        CancellationToken::new(),
    )
    .unwrap();
    let mut sockets = Pair {
        phone,
        pc: pc_socket,
    };
    let phone_flow = async {
        let mut ready = false;
        let mut drained = false;
        let mut message = None;
        for _ in 0..4 {
            match sockets.phone.next_event().await.unwrap() {
                PcSocketEvent::Ready => {
                    assert!(!ready);
                    ready = true;
                    sockets
                        .phone
                        .queue_clock_probe(&owner, clock.inbox())
                        .unwrap();
                }
                PcSocketEvent::OutboundDrained => {
                    assert!(!drained);
                    drained = true;
                }
                PcSocketEvent::Message(event) => {
                    assert!(message.is_none());
                    message = Some(*event);
                }
                other => panic!("unexpected initial phone event {other:?}"),
            }
            if drained && let Some(message) = message.take() {
                assert!(ready);
                return message;
            }
        }
        panic!("bounded initial phone event flow exhausted")
    };
    let (message, _) = tokio::join!(
        phone_flow,
        pc_initial_clock(&mut sockets.pc, PC_SIGNING_KEY)
    );
    let update = sockets
        .phone
        .apply_event(&mut owner, message, clock.inbox())
        .unwrap();
    assert_clock_update(&update, &owner, reference);
    let (event, original) = opened(90);
    let PcEvent::Opened { content, .. } = event else {
        panic!("synthetic opened event")
    };
    let binding = RequestBinding::new(
        original.pc(),
        original.epoch(),
        original.session(),
        original.request_id(),
        original.nonce(),
        original.content_digest(),
        ExpiryTick::from_nanos_since_epoch(REQUEST_LIFETIME).unwrap(),
    );
    let message = send(
        &mut sockets,
        PcEvent::Opened {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            content,
        },
    )
    .await;
    let accepted = sockets
        .phone
        .apply_event(&mut owner, message, clock.inbox())
        .unwrap();
    assert!(
        accepted
            .committed()
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Show(_)))
    );
    let denials = DenialOwner::new(&owner, boot()).unwrap();
    // Simultaneous prepared purposes exist only to test transport arbitration;
    // this fixture is not native user-action/preemption wiring.
    let approvals = ApprovalPlanOwner::new(&owner, boot()).unwrap();
    SendFixture {
        pair: sockets,
        denials,
        approvals,
        owner,
        clock,
        reference,
        binding,
        _directory: temp,
    }
}
fn denial_success<T>(transition: DenialTransition<T>) -> T {
    let (checks, result) = transition.into_parts();
    assert!(
        checks
            .iter()
            .all(|check| check.update().effects().is_empty() && check.update().fault().is_none())
    );
    result.unwrap_or_else(|error| panic!("synthetic denial fixture {error:?}"))
}
fn approval_success<T>(transition: ApprovalTransition<T>) -> T {
    let (checks, result) = transition.into_parts();
    assert!(
        checks
            .iter()
            .all(|check| check.update().effects().is_empty() && check.update().fault().is_none())
    );
    result.unwrap_or_else(|error| panic!("synthetic approval fixture {error:?}"))
}
impl SendFixture {
    fn denial(&mut self) -> (DenialAttempt, PreparedDenial, Vec<u8>) {
        let mut time = NativeTime(self.clock.clone());
        let attempt = denial_success(self.denials.begin(
            &mut self.owner,
            request_key(self.binding),
            &mut time,
        ));
        let signature: Signature = SigningKey::from_slice(&[4; 32])
            .unwrap()
            .sign(&attempt.signing_bytes().unwrap());
        let expected = SignedDecision::from_der(
            UnsignedDecision::new(
                self.binding,
                self.owner
                    .peer_associations()
                    .unwrap()
                    .resolve(self.reference)
                    .unwrap()
                    .descriptor()
                    .recipient_device_id(),
                DecisionPurpose::Deny,
            ),
            signature.to_der().as_bytes(),
        )
        .unwrap()
        .to_wire();
        let prepared = denial_success(self.denials.finish(
            &mut self.owner,
            &attempt,
            signature.to_der().as_bytes(),
            &mut time,
        ));
        assert_eq!(prepared.association().reference(), self.reference);
        assert_eq!(prepared.deadline_nanos(), REQUEST_LIFETIME);
        self.denials.retire_after_native_cleanup(&attempt).unwrap();
        (attempt, prepared, expected)
    }
    fn approval(&mut self) -> (ApprovalPlan, ApprovalSubmission) {
        let mut time = NativeTime(self.clock.clone());
        let plan = approval_success(self.approvals.begin(
            &mut self.owner,
            request_key(self.binding),
            &mut time,
        ));
        let attempt = approval_success(self.approvals.claim(&mut self.owner, &plan, &mut time));
        let signature: Signature = SigningKey::from_slice(&[3; 32])
            .unwrap()
            .sign(&attempt.signing_bytes().unwrap());
        let submission = approval_success(self.approvals.finish(
            &mut self.owner,
            &attempt,
            signature.to_der().as_bytes(),
            &mut time,
        ));
        self.approvals.retire_after_native_cleanup(&plan).unwrap();
        (plan, submission)
    }
    fn queue(&mut self, submission: PreparedDenial) -> QueuedDenial {
        let transition = self.pair.phone.queue_denial(
            &mut self.owner,
            submission,
            &mut NativeTime(self.clock.clone()),
        );
        assert_eq!(transition.checks().len(), 1);
        assert!(transition.checks()[0].update().effects().is_empty());
        match transition.into_parts().1 {
            DenialSendOutcome::Queued(ticket) => ticket,
            other => panic!("unexpected denial send {other:?}"),
        }
    }
    async fn receive(&mut self, purpose: DecisionPurpose) -> Vec<u8> {
        let (sent, got) = tokio::join!(self.pair.phone.next_event(), self.pair.pc.next_event());
        assert!(matches!(sent.unwrap(), PcSocketEvent::OutboundDrained));
        let bytes = match got.unwrap() {
            SocketEvent::Frame(frame) => frame.into_bytes(),
            other => panic!("expected one complete decision {other:?}"),
        };
        let signed = SignedDecision::from_wire(&bytes).unwrap();
        let seed = match purpose {
            DecisionPurpose::Approve => 3,
            DecisionPurpose::Deny => 4,
        };
        let key = DecisionPublicKey::from_sec1_bytes(
            SigningKey::from_slice(&[seed; 32])
                .unwrap()
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        signed.verify(&key).unwrap();
        assert_eq!(signed.statement().purpose(), purpose);
        assert_eq!(signed.statement().binding(), self.binding);
        assert_eq!(
            signed.statement().device_id(),
            self.owner
                .peer_associations()
                .unwrap()
                .resolve(self.reference)
                .unwrap()
                .descriptor()
                .recipient_device_id()
        );
        self.assert_no_outcome();
        bytes
    }
    fn assert_no_outcome(&self) {
        assert_eq!(self.owner.counts().unwrap().active(), 1);
        assert!(self.owner.pending_outcomes().unwrap().is_empty());
        assert!(self.owner.history().unwrap().is_empty());
    }
    async fn assert_stopped(&mut self, ticket: &QueuedDenial, expected: SocketError) {
        let (phone, pc) = tokio::join!(self.pair.phone.next_event(), self.pair.pc.next_event());
        assert!(
            matches!(phone, Err(PeerSocketError::Socket(error)) if error == expected),
            "stopped phone: {phone:?}"
        );
        assert!(
            !matches!(pc, Ok(SocketEvent::Frame(_))),
            "no complete decision: {pc:?}"
        );
        assert_eq!(ticket.progress(), DenialWriteProgress::Stopped);
        assert!(!self.pair.phone.pending_counts().outbound_frame);
        assert_eq!(self.pair.phone.pending_counts().socket_write_bytes, 0);
    }
}

// Only public future polling/pending counts. The 17-byte real socket quantum
// makes a partial ciphertext write observable without sleeping/backdoor hooks.
async fn partial_write(phone: &mut AssociatedPcSocket) {
    let mut initial = None;
    for _ in 0..128 {
        let result = {
            let mut future = pin!(phone.next_event());
            poll_fn(|cx| match future.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(None),
                Poll::Ready(result) => Poll::Ready(Some(result)),
            })
            .await
        };
        assert!(result.is_none(), "decision must remain partial: {result:?}");
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
    panic!("bounded polls did not observe a real partial decision write")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denial_reaches_actual_peer_with_exact_purpose_source_and_signature_without_outcome() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, expected) = f.denial();
        let ticket = f.queue(prepared);
        assert_eq!(ticket.progress(), DenialWriteProgress::Queued);
        assert_eq!(ticket.binding(), f.binding);
        assert_eq!(f.receive(DecisionPurpose::Deny).await, expected);
        assert_eq!(ticket.progress(), DenialWriteProgress::WrittenToSocket);
    })
    .await
    .expect("bounded actual denial delivery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denial_cancel_survives_tls_encryption_partial_write_and_native_slot_retirement() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (attempt, prepared, _) = f.denial();
        let ticket = f.queue(prepared);
        partial_write(&mut f.pair.phone).await;
        attempt.cancel();
        f.assert_stopped(&ticket, SocketError::OutboundRevoked)
            .await;
        f.assert_no_outcome();
    })
    .await
    .expect("bounded partial denial cancellation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_key_reenrollment_after_queue_does_not_rearm_original_denial_guard() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, _) = f.denial();
        let ticket = f.queue(prepared);
        partial_write(&mut f.pair.phone).await;
        let (_, removed) = f
            .owner
            .revoke_peer_association_from_trusted_host(f.reference)
            .unwrap();
        assert_eq!(removed, PeerAssociationRemoval::Removed);
        let (_, added) = f
            .owner
            .record_peer_association_from_trusted_host(association())
            .unwrap();
        assert_ne!(reference(added), f.reference);
        f.assert_stopped(&ticket, SocketError::OutboundRevoked)
            .await;
        f.assert_no_outcome();
    })
    .await
    .expect("bounded queued original-generation revocation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_denial_deadline_stops_partial_write_without_waiting_for_ten_second_frame_limit() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, _) = f.denial();
        let deadline = prepared.deadline_nanos();
        assert!(Duration::from_nanos(deadline) < framed_transport::FRAME_TIMEOUT);
        let ticket = f.queue(prepared);
        partial_write(&mut f.pair.phone).await;
        f.clock.set(deadline); // Equality expires; no sleep or deadline extension.
        f.assert_stopped(&ticket, SocketError::SendDeadline).await;
        // A socket clock is not a hidden domain timer or local outcome writer.
        f.assert_no_outcome();
    })
    .await
    .expect("bounded original denial send deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_withdrawal_after_queue_stops_denial_and_keeps_off_hours_history_empty() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, _) = f.denial();
        let ticket = f.queue(prepared);
        partial_write(&mut f.pair.phone).await;
        let update = f
            .owner
            .update_policy(
                NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
                f.clock.inbox(),
            )
            .unwrap();
        assert!(
            update
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Withdraw { .. }))
        );
        f.assert_stopped(&ticket, SocketError::OutboundRevoked)
            .await;
        assert_eq!(f.owner.counts().unwrap().retained_bodies(), 0);
        assert!(f.owner.pending_outcomes().unwrap().is_empty());
        assert!(f.owner.history().unwrap().is_empty());
    })
    .await
    .expect("bounded queued denial schedule withdrawal");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_purposes_share_one_slot_and_busy_retry_keeps_exact_denial_signature() {
    tokio::time::timeout(TEST_DEADLINE, async {
        for denial_first in [false, true] {
            let mut f = setup().await;
            let (_, denial, expected_denial) = f.denial();
            let original = denial.original_window();
            let deadline = denial.deadline_nanos();
            let (_, approval) = f.approval();
            if denial_first {
                let denial_ticket = f.queue(denial);
                partial_write(&mut f.pair.phone).await;
                let retry = f.pair.phone.queue_approval(
                    &mut f.owner,
                    approval,
                    &mut NativeTime(f.clock.clone()),
                );
                assert!(retry.checks().is_empty());
                let retained = match retry.into_parts().1 {
                    ApprovalSendOutcome::Retry {
                        reason: SendRetry::Busy,
                        submission,
                    } => submission,
                    other => panic!("approval must not overwrite denial: {other:?}"),
                };
                assert_eq!(denial_ticket.progress(), DenialWriteProgress::Queued);
                assert_eq!(f.receive(DecisionPurpose::Deny).await, expected_denial);
                assert_eq!(
                    denial_ticket.progress(),
                    DenialWriteProgress::WrittenToSocket
                );
                let sent = f.pair.phone.queue_approval(
                    &mut f.owner,
                    retained,
                    &mut NativeTime(f.clock.clone()),
                );
                let approval_ticket = match sent.into_parts().1 {
                    ApprovalSendOutcome::Queued(ticket) => ticket,
                    other => panic!("preserved approval retry: {other:?}"),
                };
                let _ = f.receive(DecisionPurpose::Approve).await;
                assert_eq!(
                    approval_ticket.progress(),
                    ApprovalWriteProgress::WrittenToSocket
                );
                assert_eq!(
                    denial_ticket.progress(),
                    DenialWriteProgress::WrittenToSocket
                );
            } else {
                let sent = f.pair.phone.queue_approval(
                    &mut f.owner,
                    approval,
                    &mut NativeTime(f.clock.clone()),
                );
                let approval_ticket = match sent.into_parts().1 {
                    ApprovalSendOutcome::Queued(ticket) => ticket,
                    other => panic!("initial approval: {other:?}"),
                };
                partial_write(&mut f.pair.phone).await;
                let retry = f.pair.phone.queue_denial(
                    &mut f.owner,
                    denial,
                    &mut NativeTime(f.clock.clone()),
                );
                assert!(retry.checks().is_empty());
                let retained = match retry.into_parts().1 {
                    DenialSendOutcome::Retry {
                        reason: SendRetry::Busy,
                        submission,
                    } => submission,
                    other => panic!("denial must not overwrite approval: {other:?}"),
                };
                assert_eq!(retained.original_window(), original);
                assert_eq!(retained.deadline_nanos(), deadline);
                assert_eq!(approval_ticket.progress(), ApprovalWriteProgress::Queued);
                let _ = f.receive(DecisionPurpose::Approve).await;
                assert_eq!(
                    approval_ticket.progress(),
                    ApprovalWriteProgress::WrittenToSocket
                );
                let denial_ticket = f.queue(retained);
                assert_eq!(f.receive(DecisionPurpose::Deny).await, expected_denial);
                assert_eq!(
                    denial_ticket.progress(),
                    DenialWriteProgress::WrittenToSocket
                );
                assert_eq!(
                    approval_ticket.progress(),
                    ApprovalWriteProgress::WrittenToSocket
                );
            }
        }
    })
    .await
    .expect("bounded cross-purpose single-slot arbitration");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clock_probe_busy_retry_returns_same_denial_without_resigning_or_retiming() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, expected) = f.denial();
        let original = prepared.original_window();
        f.pair
            .phone
            .queue_clock_probe(&f.owner, f.clock.inbox())
            .unwrap();
        let retry =
            f.pair
                .phone
                .queue_denial(&mut f.owner, prepared, &mut NativeTime(f.clock.clone()));
        assert!(retry.checks().is_empty());
        let retained = match retry.into_parts().1 {
            DenialSendOutcome::Retry {
                reason: SendRetry::Busy,
                submission,
            } => submission,
            other => panic!("clock probe occupies same slot: {other:?}"),
        };
        assert_eq!(retained.original_window(), original);
        assert_eq!(retained.deadline_nanos(), REQUEST_LIFETIME);
        let (sent, got) = tokio::join!(f.pair.phone.next_event(), f.pair.pc.next_event());
        assert!(matches!(sent.unwrap(), PcSocketEvent::OutboundDrained));
        let probe = match got.unwrap() {
            SocketEvent::Frame(frame) => ClockProbeRequest::from_wire(&frame.into_bytes()).unwrap(),
            other => panic!("fixed probe frame {other:?}"),
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
        assert_eq!(f.receive(DecisionPurpose::Deny).await, expected);
        assert_eq!(ticket.progress(), DenialWriteProgress::WrittenToSocket);
    })
    .await
    .expect("bounded probe-to-denial retry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_owner_instance_cannot_admit_a_prepared_denial_or_start_a_commit() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut first = setup().await;
        let mut second = setup().await;
        let (_, prepared, _) = first.denial();
        let before = witness(&second._directory, &second.owner);
        stage_canary(&second._directory);
        let rejected = second.pair.phone.queue_denial(
            &mut second.owner,
            prepared,
            &mut NativeTime(second.clock.clone()),
        );
        assert!(rejected.checks().is_empty());
        assert!(matches!(
            rejected.outcome(),
            DenialSendOutcome::Rejected(SendIssue::DifferentOrigin)
        ));
        assert_preintent_unchanged(&second._directory, &second.owner, &before);
        remove_own_canary(&second._directory);
        let (_, prepared, expected) = second.denial();
        let ticket = second.queue(prepared);
        assert_eq!(second.receive(DecisionPurpose::Deny).await, expected);
        assert_eq!(ticket.progress(), DenialWriteProgress::WrittenToSocket);
    })
    .await
    .expect("bounded cross-owner denial rejection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_during_queue_commit_returns_withdrawal_without_admitting_signature() {
    struct ExpireAfterCommit {
        clock: Arc<ControlledClock>,
        reads: usize,
    }
    impl ApprovalClock for ExpireAfterCommit {
        fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
            self.reads += 1;
            if self.reads == 2 {
                self.clock.set(REQUEST_LIFETIME);
            }
            Ok(ApprovalTime::new(boot(), self.clock.inbox()))
        }
    }
    tokio::time::timeout(TEST_DEADLINE, async {
        let mut f = setup().await;
        let (_, prepared, _) = f.denial();
        let mut clock = ExpireAfterCommit {
            clock: f.clock.clone(),
            reads: 0,
        };
        let rejected = f
            .pair
            .phone
            .queue_denial(&mut f.owner, prepared, &mut clock);
        assert!(matches!(
            rejected.outcome(),
            DenialSendOutcome::Rejected(SendIssue::ExpiredOrSuppressed)
        ));
        assert_eq!(rejected.checks().len(), 2);
        assert!(
            rejected
                .checks()
                .iter()
                .flat_map(|check| check.update().effects())
                .any(|effect| matches!(effect, Effect::Withdraw { .. }))
        );
        assert!(!f.pair.phone.pending_counts().outbound_frame);
        assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
        assert!(f.owner.history().unwrap().is_empty());
    })
    .await
    .expect("bounded post-commit denial expiry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_new_service_epoch_stops_a_queued_denial_progress_record() {
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
            other => panic!("fixed probe frame {other:?}"),
        };
        let received = send(
            &mut f.pair,
            PcEvent::Clock {
                pc: pc(),
                epoch: BootEpoch::from_bytes([33; 32]).unwrap(),
                probe: probe.nonce(),
                sampled_at: ServiceTick::from_nanos_since_epoch(0),
            },
        )
        .await;
        let (_, prepared, _) = f.denial();
        let ticket = f.queue(prepared);
        let changed = f
            .pair
            .phone
            .apply_event(&mut f.owner, received, f.clock.inbox())
            .unwrap();
        assert!(changed.committed().update().fault().is_none());
        assert!(changed.check_current(&f.owner).is_err());
        assert_eq!(ticket.progress(), DenialWriteProgress::Stopped);
        assert!(f.pair.phone.next_event().await.is_err());
        assert!(!matches!(
            f.pair.pc.next_event().await,
            Ok(SocketEvent::Frame(_))
        ));
        f.assert_no_outcome();
    })
    .await
    .expect("bounded changed-epoch denial withdrawal");
}
