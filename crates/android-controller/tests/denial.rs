// SPDX-License-Identifier: GPL-2.0-or-later
//! Real host storage and associated TCP/TLS ingress with synthetic keys/time.
//! No Android key use, authentication callback, enrollment proof or Windows action.
#![cfg(any(windows, target_os = "linux"))]

use std::{
    collections::VecDeque,
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

use android_controller::{
    ApprovalClock, ApprovalClockError, ApprovalTime, AssociatedPcSocket, AssociatedRequestIssue,
    DenialAttempt, DenialError, DenialOwner, DenialTransition, DurableInbox,
    LocalAttestationChallenge, LocalKeyHandle, LocalKeySetDescriptor, PcSocketEvent,
    PcSocketInputs, PeerAssociationDescriptor, PeerAssociationMutation, PeerAssociationRef,
    PeerAssociationRemoval, PreparedDenial,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, DecisionPublicKey, DecisionPurpose, DeviceId,
    ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent, RequestId, UnsignedDecision,
};
use framed_transport::{
    CancellationToken, ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable,
    SocketDriver, SocketEvent, SocketLimits,
};
use notification_policy::{
    AlertMode, CapacityLimits, ClockReading, DayMask, Effect, LocalTime, MonotonicTime,
    NotificationPolicy, Schedule, TimeWindow, Weekday, WeeklySchedule,
};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId, request_key};
use phone_state_store::{NativePrivateDirectory, STAGING_FILE_NAME};
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
    inbox_clock_at(ms, 600)
}
fn inbox_clock_at(ms: u64, minute: u16) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, minute).unwrap(),
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
    cancel_on: Option<(usize, &'a DenialAttempt)>,
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
        if let Some((when, attempt)) = self.cancel_on
            && when == self.reads
        {
            attempt.cancel();
        }
        self.values
            .pop_front()
            .expect("bounded synthetic native clock script exhausted")
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
fn sign(bytes: &[u8], seed: u8) -> Vec<u8> {
    let signature: Signature = SigningKey::from_slice(&[seed; 32]).unwrap().sign(bytes);
    signature.to_der().as_bytes().to_vec()
}
fn frame(event: PcEvent) -> Vec<u8> {
    let unsigned = UnsignedPcEvent::new(event).unwrap();
    let der = sign(&unsigned.signing_bytes(), 6);
    encode_frame(&unsigned.with_der_signature(&der).unwrap().to_wire()).unwrap()
}

// Keep the real owner before TempDir so its file locks drop before cleanup.
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
            let (mut owner, initial) = DurableInbox::create_fresh_host_model(
                NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
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
            // Explicit trusted-host fixture, not an enrollment ceremony assertion.
            let (_, mutation) = owner
                .record_peer_association_from_trusted_host(peer())
                .unwrap();
            let reference = match mutation {
                PeerAssociationMutation::Recorded(value) => value,
                _ => panic!("fresh synthetic association"),
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
                    "Synthetic denial app",
                    "C:\\Synthetic\\denial.exe",
                    "synthetic denial body",
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
                        SocketEvent::Ready => (),
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
            // Actual associated ingress preserved the original source. No raw
            // production setter inserts an associated body into this fixture.
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
fn success<T>(transition: DenialTransition<T>) -> T {
    let (checks, result) = transition.into_parts();
    for check in &checks {
        assert!(check.update().fault().is_none());
        assert!(check.update().effects().is_empty());
    }
    result.unwrap_or_else(|error| panic!("unexpected denial error {error:?}"))
}
fn begin(f: &mut Fixture, owner: &mut DenialOwner, start: u64) -> DenialAttempt {
    success(owner.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[start, start + 1]),
    ))
}
fn prepare(f: &mut Fixture, owner: &mut DenialOwner) -> (DenialAttempt, PreparedDenial) {
    let attempt = begin(f, owner, 3);
    let der = sign(&attempt.signing_bytes().unwrap(), 4);
    let prepared = success(owner.finish(
        &mut f.owner,
        &attempt,
        &der,
        &mut ScriptClock::at(&[5, 6, 7]),
    ));
    (attempt, prepared)
}
fn denial_public() -> DecisionPublicKey {
    DecisionPublicKey::from_sec1_bytes(
        SigningKey::from_slice(&[4; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    )
    .unwrap()
}
fn assert_withdrawal<T>(transition: &DenialTransition<T>) {
    assert!(
        transition
            .checks()
            .iter()
            .flat_map(|check| check.update().effects())
            .any(|effect| matches!(effect, Effect::Withdraw { .. }))
    );
}

#[test]
fn honest_denial_is_one_shot_without_authentication_or_local_outcome() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let attempt = begin(&mut f, &mut denials, 3);
    assert_eq!(attempt.binding(), f.binding);
    assert_eq!(attempt.deadline_nanos(), EXPIRY_MS * MILLI);
    assert_eq!(attempt.phone_boot(), boot());
    assert_eq!(attempt.association().reference(), f.reference);
    assert_eq!(attempt.local_keys().handle(), handle());
    assert!(attempt.belongs_to_owner(&f.owner));
    let bytes = attempt.signing_bytes().unwrap();
    assert_eq!(
        bytes,
        UnsignedDecision::new(f.binding, device(), DecisionPurpose::Deny).signing_bytes()
    );
    // No auth-event/provider parameter exists in begin/finish; only native time.
    let der = sign(&bytes, 4);
    let prepared = success(denials.finish(
        &mut f.owner,
        &attempt,
        &der,
        &mut ScriptClock::at(&[5, 6, 7]),
    ));
    assert!(attempt.is_cancelled());
    assert_eq!(attempt.signing_bytes().unwrap_err(), DenialError::Cancelled);
    let repeated = denials.finish(&mut f.owner, &attempt, &der, &mut ScriptClock::at(&[]));
    assert_eq!(
        repeated.outcome().unwrap_err(),
        &DenialError::AlreadyConsumed
    );
    assert!(repeated.checks().is_empty());
    denials.retire_after_native_cleanup(&attempt).unwrap();
    denials.retire_after_native_cleanup(&attempt).unwrap();
    assert!(!prepared.is_cancelled());
    assert!(prepared.belongs_to_owner(&f.owner));
    assert_eq!(prepared.original_window(), attempt.original_window());
    assert_eq!(prepared.association().reference(), f.reference);
    assert_eq!(prepared.local_keys().handle(), handle());
    assert_eq!(prepared.phone_boot(), boot());
    assert_eq!(prepared.deadline_nanos(), EXPIRY_MS * MILLI);
    let signed = prepared.into_signed_decision().unwrap();
    signed.verify(&denial_public()).unwrap();
    assert_eq!(signed.statement().purpose(), DecisionPurpose::Deny);
    assert_eq!(signed.statement().device_id(), device());
    assert_eq!(signed.statement().binding(), f.binding);
    assert_eq!(f.owner.counts().unwrap().active(), 1);
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn wrong_role_and_malformed_signatures_consume_attempt_and_never_record_outcome() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    for index in 0..5 {
        let start = 3 + index * 10;
        let attempt = begin(&mut f, &mut denials, start);
        let bytes = attempt.signing_bytes().unwrap();
        let der = match index {
            0 => sign(&bytes, 3), // APPROVAL, not DENIAL.
            1 => sign(&bytes, 5), // TRANSPORT, not DENIAL.
            2 => Vec::new(),
            3 => {
                let mut value = sign(&bytes, 4);
                value.push(0);
                value
            }
            _ => vec![0; 73],
        };
        let rejected = denials.finish(
            &mut f.owner,
            &attempt,
            &der,
            &mut ScriptClock::at(&[start + 2, start + 3]),
        );
        assert_eq!(
            rejected.outcome().unwrap_err(),
            &DenialError::InvalidSignature
        );
        assert_eq!(rejected.checks().len(), 1);
        assert!(attempt.is_cancelled());
        assert_eq!(
            denials
                .finish(&mut f.owner, &attempt, &[], &mut ScriptClock::at(&[]))
                .outcome()
                .unwrap_err(),
            &DenialError::AlreadyConsumed
        );
        assert_eq!(
            denials
                .begin(
                    &mut f.owner,
                    request_key(f.binding),
                    &mut ScriptClock::at(&[])
                )
                .outcome()
                .unwrap_err(),
            &DenialError::Busy
        );
        denials.retire_after_native_cleanup(&attempt).unwrap();
    }
    assert_eq!(f.owner.counts().unwrap().active(), 1);
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn approval_purpose_and_every_changed_binding_component_fail_even_under_denial_key() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let b = f.binding;
    for index in 0..10 {
        let start = 3 + index * 10;
        let attempt = begin(&mut f, &mut denials, start);
        let changed = RequestBinding::new(
            if index == 2 {
                PcIdentity::from_bytes([8; 32]).unwrap()
            } else {
                b.pc()
            },
            if index == 3 {
                BootEpoch::from_bytes([8; 32]).unwrap()
            } else {
                b.epoch()
            },
            match index {
                4 => OsSession::new(42, b.session().logon_id()),
                9 => OsSession::new(b.session().session_id(), 99),
                _ => b.session(),
            },
            if index == 5 {
                RequestId::from_bytes([8; 32]).unwrap()
            } else {
                b.request_id()
            },
            if index == 6 {
                ChallengeNonce::from_bytes([8; 32]).unwrap()
            } else {
                b.nonce()
            },
            if index == 7 {
                ContentDigest::from_bytes([8; 32])
            } else {
                b.content_digest()
            },
            if index == 8 {
                ExpiryTick::from_nanos_since_epoch(999 * MILLI).unwrap()
            } else {
                b.expiry()
            },
        );
        let statement = UnsignedDecision::new(
            changed,
            if index == 1 {
                DeviceId::from_bytes([8; 16]).unwrap()
            } else {
                device()
            },
            if index == 0 {
                DecisionPurpose::Approve
            } else {
                DecisionPurpose::Deny
            },
        );
        let der = sign(&statement.signing_bytes(), 4);
        let rejected = denials.finish(
            &mut f.owner,
            &attempt,
            &der,
            &mut ScriptClock::at(&[start + 2, start + 3]),
        );
        assert_eq!(
            rejected.outcome().unwrap_err(),
            &DenialError::InvalidSignature
        );
        assert_eq!(rejected.checks().len(), 1);
        assert!(attempt.is_cancelled());
        denials.retire_after_native_cleanup(&attempt).unwrap();
    }
    assert!(f.owner.pending_outcomes().unwrap().is_empty());
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn busy_and_foreign_attempts_do_not_consume_the_rightful_slot() {
    let mut first = fixture();
    let mut second = fixture();
    let mut a = DenialOwner::new(&first.owner, boot()).unwrap();
    let mut b = DenialOwner::new(&second.owner, boot()).unwrap();
    let own = begin(&mut first, &mut a, 3);
    let foreign = begin(&mut second, &mut b, 3);
    let wrong = a.finish(&mut first.owner, &foreign, &[], &mut ScriptClock::at(&[]));
    assert_eq!(wrong.outcome().unwrap_err(), &DenialError::ForeignHandle);
    assert!(wrong.checks().is_empty());
    assert_eq!(
        a.retire_after_native_cleanup(&foreign).unwrap_err(),
        DenialError::ForeignHandle
    );
    let busy = a.begin(
        &mut first.owner,
        request_key(first.binding),
        &mut ScriptClock::at(&[]),
    );
    assert_eq!(busy.outcome().unwrap_err(), &DenialError::Busy);
    assert!(busy.checks().is_empty());
    assert!(!own.is_cancelled());
    assert!(!foreign.is_cancelled());
    let der = sign(&own.signing_bytes().unwrap(), 4);
    let prepared = success(a.finish(
        &mut first.owner,
        &own,
        &der,
        &mut ScriptClock::at(&[5, 6, 7]),
    ));
    assert!(!prepared.is_cancelled());
    a.retire_after_native_cleanup(&own).unwrap();
    foreign.cancel();
    b.retire_after_native_cleanup(&foreign).unwrap();
}

#[test]
fn cancellation_and_native_cleanup_are_distinct_and_old_retirement_cannot_free_new_slot() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let attempt = begin(&mut f, &mut denials, 3);
    assert_eq!(
        denials.retire_after_native_cleanup(&attempt).unwrap_err(),
        DenialError::CleanupRequired
    );
    attempt.cancel();
    assert!(attempt.is_cancelled());
    assert_eq!(
        denials
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &DenialError::Busy
    );
    let cancelled = denials.finish(&mut f.owner, &attempt, &[], &mut ScriptClock::at(&[]));
    assert_eq!(cancelled.outcome().unwrap_err(), &DenialError::Cancelled);
    assert!(cancelled.checks().is_empty());
    denials.retire_after_native_cleanup(&attempt).unwrap(); // No actual native work in this fixture.
    let next = begin(&mut f, &mut denials, 5);
    denials.retire_after_native_cleanup(&attempt).unwrap();
    assert_eq!(
        denials
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &DenialError::Busy
    );
    assert!(!next.is_cancelled());
    next.cancel();
    denials.retire_after_native_cleanup(&next).unwrap();
}

#[test]
fn expiry_after_begin_commit_rejects_and_returns_committed_withdrawal() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let rejected = denials.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[999, 1_000]),
    );
    assert_eq!(rejected.outcome().unwrap_err(), &DenialError::Expired);
    assert_eq!(rejected.checks().len(), 2);
    assert_withdrawal(&rejected);
    assert_eq!(f.owner.counts().unwrap().active(), 0);
    assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn expiry_after_signature_verification_rejects_and_preserves_original_deadline() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let attempt = begin(&mut f, &mut denials, 3);
    let der = sign(&attempt.signing_bytes().unwrap(), 4);
    let rejected = denials.finish(
        &mut f.owner,
        &attempt,
        &der,
        &mut ScriptClock::at(&[998, 999, 1_000]),
    );
    assert_eq!(rejected.outcome().unwrap_err(), &DenialError::Expired);
    assert_eq!(rejected.checks().len(), 2);
    assert_withdrawal(&rejected);
    assert!(attempt.is_cancelled());
    assert_eq!(attempt.deadline_nanos(), EXPIRY_MS * MILLI);
    assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
    assert!(f.owner.history().unwrap().is_empty());
}

#[test]
fn schedule_boundary_after_commit_or_signature_withdraws_without_off_hours_history() {
    for after_signature in [false, true] {
        let mut f = fixture();
        let policy = NotificationPolicy::new(
            Some(Schedule::Weekly(
                WeeklySchedule::new([TimeWindow::new(DayMask::ALL, 600, 660).unwrap()]).unwrap(),
            )),
            AlertMode::Sound,
        );
        let policy_update = f.owner.update_policy(policy, inbox_clock(3)).unwrap();
        assert!(policy_update.update().effects().is_empty());
        let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
        let outside = ApprovalTime::new(boot(), inbox_clock_at(8, 660));
        if after_signature {
            let attempt = begin(&mut f, &mut denials, 4);
            let der = sign(&attempt.signing_bytes().unwrap(), 4);
            let mut clock = ScriptClock {
                values: [Ok(time(6)), Ok(time(7)), Ok(outside)].into(),
                reads: 0,
                cancel_on: None,
            };
            let rejected = denials.finish(&mut f.owner, &attempt, &der, &mut clock);
            assert_eq!(rejected.outcome().unwrap_err(), &DenialError::OutsidePolicy);
            assert_eq!(rejected.checks().len(), 2);
            assert_withdrawal(&rejected);
            assert!(attempt.is_cancelled());
        } else {
            let mut clock = ScriptClock {
                values: [Ok(time(4)), Ok(outside)].into(),
                reads: 0,
                cancel_on: None,
            };
            let rejected = denials.begin(&mut f.owner, request_key(f.binding), &mut clock);
            assert_eq!(rejected.outcome().unwrap_err(), &DenialError::OutsidePolicy);
            assert_eq!(rejected.checks().len(), 2);
            assert_withdrawal(&rejected);
        }
        assert_eq!(f.owner.counts().unwrap().retained_bodies(), 0);
        assert!(f.owner.pending_outcomes().unwrap().is_empty());
        assert!(f.owner.history().unwrap().is_empty());
    }
}

#[test]
fn cancellation_during_post_commit_clock_read_keeps_the_committed_check() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let attempt = begin(&mut f, &mut denials, 3);
    let der = sign(&attempt.signing_bytes().unwrap(), 4);
    let mut clock = ScriptClock::at(&[5, 6]);
    clock.cancel_on = Some((2, &attempt));
    let rejected = denials.finish(&mut f.owner, &attempt, &der, &mut clock);
    assert_eq!(rejected.outcome().unwrap_err(), &DenialError::Cancelled);
    assert_eq!(rejected.checks().len(), 1);
    assert!(attempt.is_cancelled());
    denials.retire_after_native_cleanup(&attempt).unwrap();
}

#[test]
fn revocation_and_same_key_reenrollment_never_rearm_retained_attempt_or_prepared_data() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let (attempt, prepared) = prepare(&mut f, &mut denials);
    denials.retire_after_native_cleanup(&attempt).unwrap();
    let next = begin(&mut f, &mut denials, 8);
    let der = sign(&next.signing_bytes().unwrap(), 4);
    let (_, removed) = f
        .owner
        .revoke_peer_association_from_trusted_host(f.reference)
        .unwrap();
    assert_eq!(removed, PeerAssociationRemoval::Removed);
    assert!(next.is_cancelled());
    assert!(prepared.is_cancelled());
    let (_, added) = f
        .owner
        .record_peer_association_from_trusted_host(peer())
        .unwrap();
    let PeerAssociationMutation::Recorded(new_reference) = added else {
        panic!("fresh generation")
    };
    assert_ne!(new_reference, f.reference);
    assert!(next.is_cancelled());
    assert!(prepared.is_cancelled());
    let rejected = denials.finish(&mut f.owner, &next, &der, &mut ScriptClock::at(&[]));
    assert_eq!(rejected.outcome().unwrap_err(), &DenialError::Cancelled);
    assert!(rejected.checks().is_empty());
    denials.retire_after_native_cleanup(&next).unwrap();
    let old_source = denials.begin(
        &mut f.owner,
        request_key(f.binding),
        &mut ScriptClock::at(&[10]),
    );
    assert_eq!(
        old_source.outcome().unwrap_err(),
        &DenialError::AssociationIssue(AssociatedRequestIssue::AssociationNoLongerCurrent)
    );
    assert_eq!(old_source.checks().len(), 1);
    assert_eq!(
        prepared.into_signed_decision().unwrap_err(),
        DenialError::Cancelled
    );
}

#[test]
fn reopening_saved_state_cannot_finish_an_attempt_from_the_old_owner_instance() {
    let Fixture {
        mut owner,
        temp,
        binding,
        reference,
    } = fixture();
    let mut denials = DenialOwner::new(&owner, boot()).unwrap();
    let attempt = success(denials.begin(
        &mut owner,
        request_key(binding),
        &mut ScriptClock::at(&[3, 4]),
    ));
    let der = sign(&attempt.signing_bytes().unwrap(), 4);
    drop(owner);
    assert!(attempt.is_cancelled());
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
    assert!(!attempt.belongs_to_owner(&reopened));
    let rejected = denials.finish(&mut reopened, &attempt, &der, &mut ScriptClock::at(&[]));
    assert_eq!(
        rejected.outcome().unwrap_err(),
        &DenialError::DifferentOwner
    );
    assert!(rejected.checks().is_empty());
    assert_eq!(
        denials
            .finish(&mut reopened, &attempt, &[], &mut ScriptClock::at(&[]))
            .outcome()
            .unwrap_err(),
        &DenialError::AlreadyConsumed
    );
    denials.retire_after_native_cleanup(&attempt).unwrap();
}

#[test]
fn unavailable_regressed_and_changed_boot_observations_close_owner_after_committed_check() {
    for (values, expected) in [
        (
            vec![Ok(time(3)), Err(ApprovalClockError::Unavailable)],
            DenialError::ClockUnavailable,
        ),
        (vec![Ok(time(5)), Ok(time(4))], DenialError::ClockRegressed),
        (
            vec![
                Ok(time(5)),
                Ok(ApprovalTime::new(
                    PhoneBootId::from_native_boot_count(6).unwrap(),
                    inbox_clock(6),
                )),
            ],
            DenialError::BootChanged,
        ),
    ] {
        let mut f = fixture();
        let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
        let mut clock = ScriptClock {
            values: values.into(),
            reads: 0,
            cancel_on: None,
        };
        let rejected = denials.begin(&mut f.owner, request_key(f.binding), &mut clock);
        assert_eq!(rejected.outcome().unwrap_err(), &expected);
        assert_eq!(rejected.checks().len(), 1);
        let closed = denials.begin(
            &mut f.owner,
            request_key(f.binding),
            &mut ScriptClock::at(&[]),
        );
        assert_eq!(closed.outcome().unwrap_err(), &DenialError::Closed);
        assert!(closed.checks().is_empty());
    }
}

#[test]
fn unavailable_requested_body_still_returns_other_requests_expiry_effects() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let other = RequestBinding::new(
        f.binding.pc(),
        f.binding.epoch(),
        f.binding.session(),
        RequestId::from_bytes([8; 32]).unwrap(),
        f.binding.nonce(),
        f.binding.content_digest(),
        f.binding.expiry(),
    );
    let rejected = denials.begin(
        &mut f.owner,
        request_key(other),
        &mut ScriptClock::at(&[1_000]),
    );
    assert_eq!(
        rejected.outcome().unwrap_err(),
        &DenialError::RequestUnavailable
    );
    assert_eq!(rejected.checks().len(), 1);
    assert_withdrawal(&rejected);
    assert_eq!(f.owner.pending_outcomes().unwrap().len(), 1);
}

#[test]
fn cleanup_retirement_preserves_prepared_data_but_explicit_cancel_and_owner_drop_do_not() {
    for drop_denial_owner in [false, true] {
        let mut f = fixture();
        let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
        let (attempt, prepared) = prepare(&mut f, &mut denials);
        denials.retire_after_native_cleanup(&attempt).unwrap();
        assert!(!prepared.is_cancelled());
        if drop_denial_owner {
            drop(denials);
        } else {
            attempt.cancel();
        }
        assert!(prepared.is_cancelled());
        assert_eq!(
            prepared.into_signed_decision().unwrap_err(),
            DenialError::Cancelled
        );
    }
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let (attempt, prepared) = prepare(&mut f, &mut denials);
    denials.retire_after_native_cleanup(&attempt).unwrap();
    drop(f.owner);
    assert!(prepared.is_cancelled());
    assert_eq!(
        prepared.into_signed_decision().unwrap_err(),
        DenialError::Cancelled
    );
}

#[test]
fn storage_failure_immediately_revokes_attempt_and_retired_prepared_data() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let (attempt, prepared) = prepare(&mut f, &mut denials);
    denials.retire_after_native_cleanup(&attempt).unwrap();
    let next = begin(&mut f, &mut denials, 8);
    // Actual isolated store fault injection, not a production recovery shortcut.
    fs::write(
        f.temp.path().join(STAGING_FILE_NAME),
        b"synthetic incomplete stage",
    )
    .unwrap();
    let failure = f.owner.poll(inbox_clock(10)).unwrap_err();
    assert!(f.owner.fault().is_some());
    assert_eq!(
        failure.notification_cleanup(),
        android_controller::NotificationCleanup::ClearAllOwnedRequestNotifications
    );
    assert!(next.is_cancelled());
    assert!(prepared.is_cancelled());
    let rejected = denials.finish(&mut f.owner, &next, &[], &mut ScriptClock::at(&[]));
    assert!(matches!(rejected.outcome(), Err(DenialError::Owner(_))));
    assert!(rejected.checks().is_empty());
    denials.retire_after_native_cleanup(&next).unwrap();
    assert_eq!(
        denials
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &DenialError::Closed
    );
}

#[test]
fn clock_callback_unwind_closes_retired_prepared_data_without_recovery() {
    struct PanickingClock;
    impl ApprovalClock for PanickingClock {
        fn read(&mut self) -> Result<ApprovalTime, ApprovalClockError> {
            panic!("synthetic native time callback failure")
        }
    }
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let (attempt, prepared) = prepare(&mut f, &mut denials);
    denials.retire_after_native_cleanup(&attempt).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = denials.begin(&mut f.owner, request_key(f.binding), &mut PanickingClock);
    }));
    assert!(caught.is_err());
    assert!(prepared.is_cancelled());
    assert_eq!(
        denials
            .begin(
                &mut f.owner,
                request_key(f.binding),
                &mut ScriptClock::at(&[])
            )
            .outcome()
            .unwrap_err(),
        &DenialError::Closed
    );
}

#[test]
fn handle_and_transition_debug_never_include_request_text_or_key_material() {
    let mut f = fixture();
    let mut denials = DenialOwner::new(&f.owner, boot()).unwrap();
    let attempt = begin(&mut f, &mut denials, 3);
    assert_eq!(
        format!("{attempt:?}"),
        "DenialAttempt([redacted], not_native_key_authority)"
    );
    let der = sign(&attempt.signing_bytes().unwrap(), 4);
    let transition = denials.finish(
        &mut f.owner,
        &attempt,
        &der,
        &mut ScriptClock::at(&[5, 6, 7]),
    );
    let debug = format!("{transition:?} {denials:?}");
    assert!(!debug.contains("Synthetic"));
    assert!(!debug.contains("denial.exe"));
    let prepared = success(transition);
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedDenial([redacted], not_windows_result)"
    );
    prepared.cancel();
    assert!(prepared.is_cancelled());
    assert_eq!(
        prepared.into_signed_decision().unwrap_err(),
        DenialError::Cancelled
    );
}
