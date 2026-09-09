// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host storage + associated socket ingress, synthetic keys/time only.
//! No native authentication, Keystore, PC grant, Windows action or sender proof.
#![cfg(any(windows, target_os = "linux"))]

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use android_controller::{
    ApprovalAttempt, ApprovalClock, ApprovalClockError, ApprovalError, ApprovalPlan,
    ApprovalPlanOwner, ApprovalTime, ApprovalTransition, AssociatedPcSocket,
    AssociatedRequestIssue, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeySetDescriptor, MAX_LIVE_APPROVAL_CONTEXTS, PcSocketEvent, PcSocketInputs,
    PeerAssociationDescriptor, PeerAssociationMutation, PeerAssociationRef, PeerAssociationRemoval,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DecisionPublicKey, DecisionPurpose, DeviceId, ExpiryTick, OsSession,
    PcIdentity, RequestBinding, RequestContent, RequestId, UnsignedDecision,
};
use framed_transport::{
    CancellationToken, ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable,
    SocketDriver, SocketEvent, SocketLimits,
};
use notification_policy::{
    CapacityLimits, ClockReading, Effect, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId, request_key};
use phone_state_store::NativePrivateDirectory;
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{ClockProbeRequest, PcEvent, ServiceTick, UnsignedPcEvent, encode_frame};
use tokio::net::{TcpListener, TcpStream};

const MILLI: u64 = 1_000_000;
const EXPIRY_MS: u64 = 1_000;
fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(5).unwrap()
}
fn inbox_clock(ms: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        ms * MILLI,
    )
    .unwrap()
}
fn time(ms: u64) -> ApprovalTime {
    ApprovalTime::new(boot(), inbox_clock(ms))
}
struct ScriptClock<'a> {
    values: VecDeque<Result<ApprovalTime, ApprovalClockError>>,
    reads: usize,
    cancel_on: Option<(usize, &'a ApprovalPlan)>,
}
impl ScriptClock<'_> {
    fn at(values: &[u64]) -> Self {
        Self {
            values: values.iter().copied().map(|ms| Ok(time(ms))).collect(),
            reads: 0,
            cancel_on: None,
        }
    }
}
impl ApprovalClock for ScriptClock<'_> {
    fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
        self.reads += 1;
        if let Some((when, plan)) = self.cancel_on
            && when == self.reads
        {
            plan.cancel();
        }
        self.values
            .pop_front()
            .expect("bounded fixture clock script exhausted")
    }
}
struct HostSocketClock;
impl SocketClock for HostSocketClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}
struct SyntheticSigner(SigningKey);
impl PlatformTlsSigner for SyntheticSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        let point =
            PublicKey::from_sec1_bytes(self.0.verifying_key().to_encoded_point(false).as_bytes())
                .unwrap();
        TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes())
            .map_err(|_| SignerError::Unavailable)
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let signature: Signature = self.0.sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}
fn signer(seed: u8) -> Arc<SyntheticSigner> {
    Arc::new(SyntheticSigner(
        SigningKey::from_slice(&[seed; 32]).unwrap(),
    ))
}
fn public(seed: u8) -> TlsPublicKey {
    signer(seed).public_key().unwrap()
}
fn pc() -> PcIdentity {
    PcIdentity::from_bytes([7; 32]).unwrap()
}
fn device() -> DeviceId {
    DeviceId::from_bytes([9; 16]).unwrap()
}
fn handle() -> LocalKeyHandle {
    LocalKeyHandle::from_bytes([1; 32]).unwrap()
}
fn peer() -> PeerAssociationDescriptor {
    PeerAssociationDescriptor::new(pc(), device(), 7, handle(), public(6), public(6)).unwrap()
}
fn frame(event: PcEvent) -> Vec<u8> {
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let signature: Signature = SigningKey::from_slice(&[6; 32])
        .unwrap()
        .sign(&unsigned.signing_bytes());
    encode_frame(
        &unsigned
            .with_der_signature(signature.to_der().as_bytes())
            .unwrap()
            .to_wire(),
    )
    .unwrap()
}

// Owner is declared before the directory so file locks drop before temp cleanup.
struct Fixture {
    owner: DurableInbox,
    temp: tempfile::TempDir,
    binding: RequestBinding,
    reference: PeerAssociationRef,
}
fn fixture() -> Fixture {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let temp = tempfile::tempdir().unwrap();
            let directory = NativePrivateDirectory::from_native_app_data(temp.path()).unwrap();
            let (mut owner, initial) = DurableInbox::create_fresh_host_model(
                directory,
                NotificationPolicy::default(),
                CapacityLimits::default(),
                boot(),
                inbox_clock(0),
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
            let (created, _) = owner
                .record_local_key_creation(
                    LocalKeySetDescriptor::new(
                        handle(),
                        challenge,
                        public(3),
                        public(4),
                        public(5),
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(created.changed());
            let (recorded, mutation) = owner
                .record_peer_association_from_trusted_host(peer())
                .unwrap();
            assert!(recorded.changed());
            let reference = match mutation {
                PeerAssociationMutation::Recorded(value) => value,
                _ => panic!("fresh fixture association"),
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (client, accepted) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let budget = Arc::new(ConnectionBudget::new(2).unwrap());
            let mut phone = AssociatedPcSocket::new(
                &owner,
                reference,
                PcSocketInputs {
                    socket: client.unwrap(),
                    identity: TlsIdentity::from_trusted_host(EndpointRole::Client, signer(5))
                        .unwrap(),
                    budget: budget.clone(),
                    clock: Arc::new(HostSocketClock),
                    limits: SocketLimits::default(),
                    stop: CancellationToken::new(),
                },
            )
            .unwrap();
            let transport = PeerTransport::server(
                budget.clone(),
                TlsIdentity::from_trusted_host(EndpointRole::Server, signer(6)).unwrap(),
                public(5),
                Instant::now(),
            )
            .unwrap();
            let mut server = SocketDriver::new(
                accepted.unwrap().0,
                transport,
                Arc::new(HostSocketClock),
                SocketLimits::default(),
                CancellationToken::new(),
            )
            .unwrap();
            let content = Arc::new(
                RequestContent::new(
                    "Synthetic approval app",
                    "C:\\Synthetic\\approval.exe",
                    "synthetic approval body",
                )
                .unwrap(),
            );
            let binding = RequestBinding::new(
                pc(),
                BootEpoch::from_bytes([2; 32]).unwrap(),
                OsSession::new(1, 3),
                RequestId::from_bytes([1; 32]).unwrap(),
                ChallengeNonce::from_bytes([4; 32]).unwrap(),
                content.digest(),
                ExpiryTick::from_nanos_since_epoch(EXPIRY_MS * MILLI).unwrap(),
            );
            let mut opened = Some(frame(PcEvent::Opened {
                binding,
                issued_at: ServiceTick::from_nanos_since_epoch(0),
                content,
            }));
            let phone_flow = async {
                let mut messages = 0;
                for _ in 0..6 {
                    match phone.next_event().await.unwrap() {
                        PcSocketEvent::Ready => {
                            phone.queue_clock_probe(&owner, inbox_clock(0)).unwrap()
                        }
                        PcSocketEvent::OutboundDrained => (),
                        PcSocketEvent::Message(event) => {
                            messages += 1;
                            let update = phone
                                .apply_event(&mut owner, *event, inbox_clock(messages))
                                .unwrap();
                            update.check_current(&owner).unwrap();
                            assert!(update.committed().update().fault().is_none());
                            if messages == 2 {
                                assert!(
                                    update
                                        .committed()
                                        .update()
                                        .effects()
                                        .iter()
                                        .any(|effect| matches!(effect, Effect::Show(_)))
                                );
                                return;
                            }
                        }
                        other => panic!("unexpected fixture phone event {other:?}"),
                    }
                }
                panic!("bounded fixture phone flow exhausted")
            };
            let server_flow = async {
                let mut replies = 0;
                for _ in 0..6 {
                    match server.next_event().await.unwrap() {
                        SocketEvent::Ready => (), // Keep driving the readiness preface.
                        SocketEvent::Frame(request) => {
                            let request =
                                ClockProbeRequest::from_wire(&request.into_bytes()).unwrap();
                            server
                                .queue_frame(frame(PcEvent::Clock {
                                    pc: request.pc(),
                                    epoch: binding.epoch(),
                                    probe: request.nonce(),
                                    sampled_at: ServiceTick::from_nanos_since_epoch(0),
                                }))
                                .unwrap();
                        }
                        SocketEvent::OutboundDrained => {
                            replies += 1;
                            if replies == 2 {
                                return;
                            }
                            server.queue_frame(opened.take().unwrap()).unwrap();
                        }
                        other => panic!("unexpected fixture server event {other:?}"),
                    }
                }
                panic!("bounded fixture server flow exhausted")
            };
            tokio::join!(phone_flow, server_flow);
            drop(phone);
            drop(server);
            assert_eq!(budget.active(), 0);
            // Source retention survives transport teardown; no test-only production
            // setter installs an associated body. Actual sender readiness is separate.
            Fixture {
                owner,
                temp,
                binding,
                reference,
            }
        })
        .await
        .expect("bounded real associated ingress fixture")
    })
}
fn result<T>(transition: ApprovalTransition<T>) -> T {
    let (checks, result) = transition.into_parts();
    for check in &checks {
        assert!(check.update().fault().is_none());
        assert!(check.update().effects().is_empty());
    }
    result.unwrap_or_else(|error| panic!("unexpected approval transition error: {error:?}"))
}
fn der(attempt: &ApprovalAttempt, seed: u8) -> Vec<u8> {
    let signature: Signature = SigningKey::from_slice(&[seed; 32])
        .unwrap()
        .sign(&attempt.signing_bytes().unwrap());
    signature.to_der().as_bytes().to_vec()
}
fn approval_public() -> DecisionPublicKey {
    DecisionPublicKey::from_sec1_bytes(
        SigningKey::from_slice(&[3; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap()
}

#[test]
fn sealed_plan_claim_and_finish_are_exact_one_shot_data_not_windows_success() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    assert_eq!(plan.binding(), f.binding);
    assert_eq!(plan.deadline_nanos(), EXPIRY_MS * MILLI);
    assert_eq!(plan.association().reference(), f.reference);
    assert_eq!(plan.local_keys().handle(), handle());
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    assert!(attempt.belongs_to(&plan));
    assert!(
        attempt.signing_bytes().unwrap()
            == UnsignedDecision::new(f.binding, device(), DecisionPurpose::Approve).signing_bytes()
    );
    let duplicate = approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[]));
    assert_eq!(
        duplicate.outcome().unwrap_err(),
        &ApprovalError::AlreadyConsumed
    );
    assert!(duplicate.checks().is_empty());
    let signature = der(&attempt, 3);
    let submission = result(approvals.finish(
        &mut f.owner,
        &attempt,
        &signature,
        &mut ScriptClock::at(&[7, 8, 9]),
    ));
    assert!(attempt.is_cancelled());
    assert_eq!(
        approvals
            .finish(
                &mut f.owner,
                &attempt,
                &signature,
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &ApprovalError::AlreadyConsumed
    );
    approvals.retire_after_native_cleanup(&plan).unwrap();
    approvals.retire_after_native_cleanup(&plan).unwrap();
    assert!(!submission.is_cancelled());
    assert!(submission.belongs_to_owner(&f.owner));
    assert_eq!(submission.association().reference(), f.reference);
    let signed = submission.into_signed_decision().unwrap();
    signed.verify(&approval_public()).unwrap();
    assert_eq!(signed.statement().purpose(), DecisionPurpose::Approve);
    assert_eq!(signed.statement().binding(), f.binding);
    assert_eq!(f.owner.counts().unwrap().active(), 1);
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn cancelled_claimed_attempt_stays_inactive_and_slot_waits_for_explicit_native_cleanup() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    plan.cancel();
    assert!(attempt.is_cancelled());
    assert_eq!(
        attempt.signing_bytes().unwrap_err(),
        ApprovalError::Cancelled
    );
    assert_eq!(
        approvals
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &ApprovalError::Busy
    );
    assert_eq!(
        approvals
            .finish(&mut f.owner, &attempt, &[], &mut ScriptClock::at(&[]))
            .outcome()
            .unwrap_err(),
        &ApprovalError::Cancelled
    );
    assert_eq!(
        approvals
            .finish(&mut f.owner, &attempt, &[], &mut ScriptClock::at(&[]))
            .outcome()
            .unwrap_err(),
        &ApprovalError::AlreadyConsumed
    );
    approvals.retire_after_native_cleanup(&plan).unwrap(); // No actual native work exists in this fixture.
    let next = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[7, 8]),
    ));
    assert!(!attempt.belongs_to(&next));
    assert_eq!(
        approvals
            .claim(&mut f.owner, &plan, &mut ScriptClock::at(&[]))
            .outcome()
            .unwrap_err(),
        &ApprovalError::AlreadyConsumed
    );
    assert!(!next.is_cancelled());
    next.cancel();
    approvals.retire_after_native_cleanup(&next).unwrap();
}

#[test]
fn foreign_owner_and_foreign_plan_cannot_claim_an_existing_slot() {
    let mut first = fixture();
    let mut second = fixture();
    let mut a = ApprovalPlanOwner::new(&first.owner, boot()).unwrap();
    let mut b = ApprovalPlanOwner::new(&second.owner, boot()).unwrap();
    let plan = result(a.begin(
        &mut first.owner,
        request_key(first.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let foreign = b.claim(&mut second.owner, &plan, &mut ScriptClock::at(&[]));
    assert_eq!(
        foreign.outcome().unwrap_err(),
        &ApprovalError::ForeignHandle
    );
    assert!(foreign.checks().is_empty());
    assert_eq!(
        a.claim(&mut second.owner, &plan, &mut ScriptClock::at(&[]))
            .outcome()
            .unwrap_err(),
        &ApprovalError::DifferentOwner
    );
    let attempt = result(a.claim(&mut first.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    assert!(attempt.belongs_to(&plan));
    plan.cancel();
    a.retire_after_native_cleanup(&plan).unwrap();
}

#[test]
fn reopened_durable_owner_cannot_finish_an_old_attempt_with_unchanged_saved_keys() {
    let Fixture {
        mut owner,
        temp,
        binding,
        reference,
    } = fixture();
    let mut approvals = ApprovalPlanOwner::new(&owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut owner,
        request_key(binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let attempt = result(approvals.claim(&mut owner, &plan, &mut ScriptClock::at(&[5, 6])));
    let signature = der(&attempt, 3);
    drop(owner);
    let (mut reopened, initial) = DurableInbox::open_existing_host_model(
        NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
        boot(),
        inbox_clock(10),
    )
    .unwrap();
    assert!(initial.update().fault().is_none());
    assert!(
        reopened
            .peer_associations()
            .unwrap()
            .resolve(reference)
            .is_some()
    );
    let finish = approvals.finish(
        &mut reopened,
        &attempt,
        &signature,
        &mut ScriptClock::at(&[]),
    );
    assert_eq!(
        finish.outcome().unwrap_err(),
        &ApprovalError::DifferentOwner
    );
    assert!(finish.checks().is_empty());
    approvals.close();
    assert!(plan.is_cancelled());
    assert!(attempt.is_cancelled());
}

#[test]
fn reenrollment_rejects_original_request_plan_even_when_all_public_keys_are_the_same() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let (_, removed) = f
        .owner
        .revoke_peer_association_from_trusted_host(f.reference)
        .unwrap();
    assert_eq!(removed, PeerAssociationRemoval::Removed);
    let (_, added) = f
        .owner
        .record_peer_association_from_trusted_host(peer())
        .unwrap();
    assert!(matches!(added, PeerAssociationMutation::Recorded(_)));
    let claimed = approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5]));
    assert_eq!(
        claimed.outcome().unwrap_err(),
        &ApprovalError::AssociationIssue(AssociatedRequestIssue::AssociationNoLongerCurrent)
    );
    assert_eq!(claimed.checks().len(), 1);
    assert!(plan.is_cancelled());
}

#[test]
fn expiry_after_begin_commit_is_not_a_sealed_plan_and_preserves_new_downward_effects() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let transition = approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[999, 1_000]),
    );
    assert_eq!(transition.outcome().unwrap_err(), &ApprovalError::Expired);
    assert_eq!(transition.checks().len(), 2);
    assert!(
        transition
            .checks()
            .iter()
            .flat_map(|check| check.update().effects())
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
    assert!(
        transition
            .checks()
            .iter()
            .flat_map(|check| check.update().effects())
            .any(|effect| matches!(effect, Effect::RecordOutcome { .. }))
    );
    assert_eq!(f.owner.counts().unwrap().active(), 0);
    assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
}

#[test]
fn expiry_after_signature_verification_discards_signature_and_keeps_committed_withdrawal() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    let signature = der(&attempt, 3);
    let transition = approvals.finish(
        &mut f.owner,
        &attempt,
        &signature,
        &mut ScriptClock::at(&[998, 999, 1_000]),
    );
    assert_eq!(transition.outcome().unwrap_err(), &ApprovalError::Expired);
    assert_eq!(transition.checks().len(), 2);
    assert!(
        transition
            .checks()
            .iter()
            .flat_map(|check| check.update().effects())
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
    assert!(attempt.is_cancelled());
    assert_eq!(plan.deadline_nanos(), EXPIRY_MS * MILLI);
}

#[test]
fn wrong_role_signatures_and_malformed_der_consume_attempt_without_outcome_or_retry() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    for (index, seed) in [Some(4), Some(5), Some(6), None].into_iter().enumerate() {
        let start = 3 + index as u64 * 10;
        let plan = result(approvals.begin(
            &mut f.owner,
            request_key(f.binding),
            &mut ScriptClock::at(&[start, start + 1]),
        ));
        let attempt = result(approvals.claim(
            &mut f.owner,
            &plan,
            &mut ScriptClock::at(&[start + 2, start + 3]),
        ));
        let signature = seed.map_or_else(Vec::new, |seed| der(&attempt, seed));
        let failed = approvals.finish(
            &mut f.owner,
            &attempt,
            &signature,
            &mut ScriptClock::at(&[start + 4, start + 5]),
        );
        assert_eq!(
            failed.outcome().unwrap_err(),
            &ApprovalError::InvalidSignature
        );
        assert_eq!(failed.checks().len(), 1);
        assert_eq!(
            approvals
                .finish(
                    &mut f.owner,
                    &attempt,
                    &signature,
                    &mut ScriptClock::at(&[])
                )
                .outcome()
                .unwrap_err(),
            &ApprovalError::AlreadyConsumed
        );
        assert!(plan.is_cancelled());
        approvals.retire_after_native_cleanup(&plan).unwrap();
    }
    assert_eq!(f.owner.counts().unwrap().active(), 1);
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn immediate_cancel_during_post_commit_clock_read_invalidates_claim_without_losing_update() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let mut clock = ScriptClock::at(&[5, 6]);
    clock.cancel_on = Some((2, &plan));
    let transition = approvals.claim(&mut f.owner, &plan, &mut clock);
    assert_eq!(transition.outcome().unwrap_err(), &ApprovalError::Cancelled);
    assert_eq!(transition.checks().len(), 1);
    assert!(plan.is_cancelled());
    approvals.retire_after_native_cleanup(&plan).unwrap();
}

#[test]
fn unavailable_regressed_and_changed_boot_post_commit_times_never_create_a_plan() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let scenarios = [
        (
            vec![Ok(time(3)), Err(ApprovalClockError::Unavailable)],
            ApprovalError::ClockUnavailable,
        ),
        (
            vec![
                Ok(time(5)),
                Ok(ApprovalTime::new(
                    PhoneBootId::from_native_boot_count(6).unwrap(),
                    inbox_clock(6),
                )),
            ],
            ApprovalError::BootChanged,
        ),
        (
            vec![Ok(time(9)), Ok(time(8))],
            ApprovalError::ClockRegressed,
        ),
    ];
    for (values, expected) in scenarios {
        let mut clock = ScriptClock {
            values: values.into(),
            reads: 0,
            cancel_on: None,
        };
        let transition = approvals.begin(&mut f.owner, request_key(f.binding), &mut clock);
        assert_eq!(transition.outcome().unwrap_err(), &expected);
        assert_eq!(transition.checks().len(), 1);
    }
}

#[test]
fn unavailable_body_still_returns_maintenance_for_other_expiring_request() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let other = RequestBinding::new(
        f.binding.pc(),
        f.binding.epoch(),
        f.binding.session(),
        RequestId::from_bytes([2; 32]).unwrap(),
        f.binding.nonce(),
        f.binding.content_digest(),
        f.binding.expiry(),
    );
    let transition = approvals.begin(
        &mut f.owner,
        request_key(other),
        &mut ScriptClock::at(&[1_000]),
    );
    assert_eq!(
        transition.outcome().unwrap_err(),
        &ApprovalError::RequestUnavailable
    );
    assert_eq!(transition.checks().len(), 1);
    assert!(
        transition.checks()[0]
            .update()
            .effects()
            .iter()
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
    assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
}

#[test]
fn retirement_preserves_submission_but_explicit_cancel_and_owner_drop_invalidate_it() {
    for close_owner in [false, true] {
        let mut f = fixture();
        let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
        let plan = result(approvals.begin(
            &mut f.owner,
            request_key(f.binding),
            &mut ScriptClock::at(&[3, 4]),
        ));
        let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
        let signature = der(&attempt, 3);
        let submission = result(approvals.finish(
            &mut f.owner,
            &attempt,
            &signature,
            &mut ScriptClock::at(&[7, 8, 9]),
        ));
        approvals.retire_after_native_cleanup(&plan).unwrap();
        assert!(!submission.is_cancelled());
        if close_owner {
            drop(approvals);
        } else {
            plan.cancel();
        }
        assert!(submission.is_cancelled());
        assert_eq!(
            submission.into_signed_decision().unwrap_err(),
            ApprovalError::Cancelled
        );
    }
}

#[test]
fn request_cancellation_reaches_retired_submission_without_a_retained_plan_handle() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    let signature = der(&attempt, 3);
    let submission = result(approvals.finish(
        &mut f.owner,
        &attempt,
        &signature,
        &mut ScriptClock::at(&[7, 8, 9]),
    ));
    approvals.retire_after_native_cleanup(&plan).unwrap();
    drop(attempt);
    drop(plan);
    assert!(!submission.is_cancelled());
    let before = f.owner.counts().unwrap();
    let receipt = approvals.cancel_request(request_key(f.binding));
    assert_eq!(receipt.matched_contexts(), 1);
    assert!(submission.is_cancelled());
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    assert_eq!(f.owner.counts().unwrap(), before);
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
    assert_eq!(
        submission.into_signed_decision().unwrap_err(),
        ApprovalError::Cancelled
    );
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        0
    );
}

#[test]
fn request_cancellation_matches_full_key_does_not_retire_native_slot_or_fence_future_plans() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    for index in 0..3 {
        let b = f.binding;
        let foreign = RequestBinding::new(
            if index == 0 {
                PcIdentity::from_bytes([8; 32]).unwrap()
            } else {
                b.pc()
            },
            if index == 1 {
                BootEpoch::from_bytes([8; 32]).unwrap()
            } else {
                b.epoch()
            },
            b.session(),
            if index == 2 {
                RequestId::from_bytes([8; 32]).unwrap()
            } else {
                b.request_id()
            },
            b.nonce(),
            b.content_digest(),
            b.expiry(),
        );
        assert_eq!(
            approvals
                .cancel_request(request_key(foreign))
                .matched_contexts(),
            0
        );
        assert!(!plan.is_cancelled());
    }
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    assert!(plan.is_cancelled());
    let busy = approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[]),
    );
    assert_eq!(busy.outcome().unwrap_err(), &ApprovalError::Busy);
    assert!(busy.checks().is_empty());
    approvals.retire_after_native_cleanup(&plan).unwrap(); // Synthetic fixture has no native operation.
    // This capability does NOT install the caller's missing same-request fence.
    // A future native denial actor must prevent this begin while its action runs.
    let fresh = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[5, 6]),
    ));
    assert!(!fresh.is_cancelled());
    assert!(plan.is_cancelled());
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        2
    );
    assert!(fresh.is_cancelled());
    approvals.retire_after_native_cleanup(&fresh).unwrap();
}

#[test]
fn live_cancelled_contexts_fill_capacity_and_only_last_reference_drop_recovers_it() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let mut retained = Vec::new();
    for index in 0..MAX_LIVE_APPROVAL_CONTEXTS {
        let start = 3 + u64::try_from(index).unwrap() * 10;
        let plan = result(approvals.begin(
            &mut f.owner,
            request_key(f.binding),
            &mut ScriptClock::at(&[start, start + 1]),
        ));
        if index + 1 == MAX_LIVE_APPROVAL_CONTEXTS {
            let busy = approvals.begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[]),
            );
            assert_eq!(busy.outcome().unwrap_err(), &ApprovalError::Busy);
            assert!(busy.checks().is_empty());
        }
        plan.cancel();
        approvals.retire_after_native_cleanup(&plan).unwrap();
        retained.push(plan);
    }
    let before = f.owner.counts().unwrap();
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        MAX_LIVE_APPROVAL_CONTEXTS
    );
    let full = approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[]),
    );
    assert_eq!(full.outcome().unwrap_err(), &ApprovalError::ContextCapacity);
    assert!(full.checks().is_empty());
    assert_eq!(f.owner.counts().unwrap(), before);
    assert!(retained.iter().all(ApprovalPlan::is_cancelled));
    // Already cancelled and retired is insufficient: release the last handle.
    drop(retained.pop().unwrap());
    let replacement = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[700, 701]),
    ));
    assert!(!replacement.is_cancelled());
    assert!(retained.iter().all(ApprovalPlan::is_cancelled));
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        MAX_LIVE_APPROVAL_CONTEXTS
    );
    approvals.retire_after_native_cleanup(&replacement).unwrap();
    assert_eq!(
        approvals
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &ApprovalError::ContextCapacity
    );
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn closed_owner_cancellation_is_idempotent_and_new_owner_cannot_rearm_old_context() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    plan.cancel();
    approvals.retire_after_native_cleanup(&plan).unwrap();
    approvals.close();
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    assert_eq!(
        approvals
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &ApprovalError::Closed
    );
    drop(approvals);
    let mut replacement = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    assert_eq!(
        replacement
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        0
    );
    let fresh = result(replacement.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[5, 6]),
    ));
    assert!(plan.is_cancelled());
    assert!(!fresh.is_cancelled());
    fresh.cancel();
    replacement.retire_after_native_cleanup(&fresh).unwrap();
}

#[test]
fn failed_begin_does_not_register_or_publish_a_historical_context() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let b = f.binding;
    let unavailable = RequestBinding::new(
        b.pc(),
        b.epoch(),
        b.session(),
        RequestId::from_bytes([8; 32]).unwrap(),
        b.nonce(),
        b.content_digest(),
        b.expiry(),
    );
    let rejected = approvals.begin(
        &mut f.owner,
        request_key(unavailable),
        &mut ScriptClock::at(&[3]),
    );
    assert_eq!(
        rejected.outcome().unwrap_err(),
        &ApprovalError::RequestUnavailable
    );
    assert_eq!(rejected.checks().len(), 1);
    assert_eq!(
        approvals
            .cancel_request(request_key(unavailable))
            .matched_contexts(),
        0
    );
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        0
    );
    let plan = result(approvals.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[4, 5]),
    ));
    assert_eq!(
        approvals
            .cancel_request(request_key(f.binding))
            .matched_contexts(),
        1
    );
    approvals.retire_after_native_cleanup(&plan).unwrap();
}

#[test]
fn native_slot_observation_matches_the_full_key_until_successful_retirement() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let key = request_key(f.binding);
    let different_keys = [
        notification_policy::RequestKey::new([81; 32], key.epoch(), key.request()),
        notification_policy::RequestKey::new(key.pc(), [82; 32], key.request()),
        notification_policy::RequestKey::new(key.pc(), key.epoch(), [83; 32]),
    ];
    assert!(!approvals.has_native_slot_for(key));
    let plan = result(approvals.begin(&mut f.owner, key, &mut ScriptClock::at(&[3, 4])));
    assert!(approvals.has_native_slot_for(key));
    assert!(
        different_keys
            .iter()
            .all(|key| !approvals.has_native_slot_for(*key))
    );
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    assert!(approvals.has_native_slot_for(key));
    let submission = result(approvals.finish(
        &mut f.owner,
        &attempt,
        &der(&attempt, 3),
        &mut ScriptClock::at(&[7, 8, 9]),
    ));
    assert!(approvals.has_native_slot_for(key));
    assert!(
        different_keys
            .iter()
            .all(|key| !approvals.has_native_slot_for(*key))
    );
    // Fixture has no native operation. The accessor cannot prove OS cleanup.
    approvals.retire_after_native_cleanup(&plan).unwrap();
    assert!(!approvals.has_native_slot_for(key));
    assert!(!submission.is_cancelled());
    // Retired signature data still requires request-scoped cancellation.
    assert_eq!(approvals.cancel_request(key).matched_contexts(), 1);
    assert!(submission.is_cancelled());
    assert!(!approvals.has_native_slot_for(key));
}

#[test]
fn failed_finish_and_owner_close_do_not_hide_unretired_native_slots() {
    let mut f = fixture();
    let mut approvals = ApprovalPlanOwner::new(&f.owner, boot()).unwrap();
    let key = request_key(f.binding);
    let plan = result(approvals.begin(&mut f.owner, key, &mut ScriptClock::at(&[3, 4])));
    let attempt = result(approvals.claim(&mut f.owner, &plan, &mut ScriptClock::at(&[5, 6])));
    let failure = approvals.finish(&mut f.owner, &attempt, &[], &mut ScriptClock::at(&[7, 8]));
    assert_eq!(
        failure.outcome().unwrap_err(),
        &ApprovalError::InvalidSignature
    );
    assert!(plan.is_cancelled());
    assert!(approvals.has_native_slot_for(key));
    approvals.close();
    assert!(approvals.has_native_slot_for(key));
    assert_eq!(approvals.cancel_request(key).matched_contexts(), 1);
    assert!(approvals.has_native_slot_for(key));
    approvals.retire_after_native_cleanup(&plan).unwrap();
    assert!(!approvals.has_native_slot_for(key));
    approvals.retire_after_native_cleanup(&plan).unwrap();
    assert!(!approvals.has_native_slot_for(key));
}
