// SPDX-License-Identifier: GPL-2.0-or-later
//! Test-only real host storage and public association-bound TCP/TLS ingress.
//!
//! Local key/association metadata is an explicit synthetic trusted-host setup,
//! not an enrollment ceremony, native key operation or authentication result.
//! Request provenance comes only from signed frames through AssociatedPcSocket.
//! No receiving-metadata setter or MobileController constructor is used here.
#![cfg(all(test, any(windows, target_os = "linux")))]
#![forbid(unsafe_code)]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use android_controller::{
    AssociatedPcSocket, DurableInbox, LocalAttestationChallenge, LocalKeyHandle,
    LocalKeySetDescriptor, PcSocketEvent, PcSocketInputs, PeerAssociationDescriptor,
    PeerAssociationMutation, PeerAssociationRef,
};
use approval_protocol::{
    BootEpoch, ChallengeNonce, DeviceId, ExpiryTick, OsSession, PcIdentity, RequestBinding,
    RequestContent, RequestId,
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
use phone_request_core::{InboxClock, PhoneBootId};
use phone_state_store::NativePrivateDirectory;
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{ClockProbeRequest, PcEvent, ServiceTick, UnsignedPcEvent, encode_frame};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};

const NANOS_PER_MILLI: u64 = 1_000_000;
const EXPIRY_MS: u64 = 60_000;

pub fn boot() -> PhoneBootId {
    PhoneBootId::from_native_boot_count(5).unwrap()
}

/// Synthetic phone observation; the socket driver separately uses real Instant.
/// This setup is ingress-only, not evidence of native dual-clock send behavior.
pub fn clock(ms: u64) -> InboxClock {
    InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(ms),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        ms.checked_mul(NANOS_PER_MILLI)
            .expect("synthetic clock must fit in nanoseconds"),
    )
    .unwrap()
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

// Field order is intentional: release the locked owner before deleting TempDir.
pub(crate) struct Fixture {
    pub owner: DurableInbox,
    pub temp: TempDir,
    pub binding: RequestBinding,
    pub bindings: Vec<RequestBinding>,
    pub reference: PeerAssociationRef,
    /// Last applied native observation: clock(request count + 1), never clock(3)
    /// unconditionally when this fixture contains multiple requests.
    pub final_clock: InboxClock,
}

/// Synchronous host-test setup; call outside an already-entered Tokio runtime.
/// Returned phone state has processed clock(1) and the original request at clock(2).
pub(crate) fn fixture() -> Fixture {
    fixture_with_requests(1)
}

/// One authenticated connection/probe and 1..=32 separately signed requests.
/// Every request keeps the same original 60-second service deadline; arrival
/// time does not extend it. ABI observations must start at or after final_clock.
pub(crate) fn fixture_with_requests(count: usize) -> Fixture {
    assert!(
        (1..=32).contains(&count),
        "host fixture supports 1..=32 requests"
    );
    fixture_with_deadlines(&vec![EXPIRY_MS; count])
}

/// Distinct original deadlines let one REAL committed withdrawal occur while
/// another request is still live. Never manufacture effects for callback tests.
pub(crate) fn fixture_with_deadlines(deadlines_ms: &[u64]) -> Fixture {
    let count = deadlines_ms.len();
    assert!(
        (1..=32).contains(&count),
        "host fixture supports 1..=32 requests"
    );
    assert!(
        deadlines_ms
            .iter()
            .all(|deadline| *deadline > 100 && *deadline <= 300_000)
    );
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
                // Host-test capacity only; production defaults are unchanged.
                CapacityLimits::new(32, 256).unwrap(),
                boot(),
                clock(0),
            )
            .unwrap();
            assert!(initial.update().effects().is_empty());

            // Same explicit public host-model setup as the core approval tests.
            // Software fixture keys: APPROVAL=3, DENIAL=4, TRANSPORT=5, PC=6.
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
                _ => panic!("fresh synthetic denial ABI association"),
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
                    "Synthetic denial ABI app",
                    "C:\\Synthetic\\denial-fixture.exe",
                    "synthetic denial ABI request body",
                )
                .unwrap(),
            );
            let bindings: Vec<_> = (0..count)
                .map(|index| {
                    RequestBinding::new(
                        pc(),
                        BootEpoch::from_bytes([2; 32]).unwrap(),
                        OsSession::new(1, 3),
                        RequestId::from_bytes([u8::try_from(index + 1).unwrap(); 32]).unwrap(),
                        ChallengeNonce::from_bytes([u8::try_from(index + 4).unwrap(); 32]).unwrap(),
                        content.digest(),
                        ExpiryTick::from_nanos_since_epoch(deadlines_ms[index] * NANOS_PER_MILLI)
                            .unwrap(),
                    )
                })
                .collect();
            let binding = bindings[0];
            // Ready + one probe frame/drain + clock reply + count requests.
            // The extra event allowance is finite and does not add requests.
            let event_limit = count + 4;
            let expected_messages = count + 1;
            let phone_flow = async {
                let mut messages = 0;
                for _ in 0..event_limit {
                    match phone.next_event().await.unwrap() {
                        PcSocketEvent::Ready => phone.queue_clock_probe(&owner, clock(0)).unwrap(),
                        PcSocketEvent::OutboundDrained => (),
                        PcSocketEvent::Message(event) => {
                            messages += 1;
                            let update = phone
                                .apply_event(
                                    &mut owner,
                                    *event,
                                    clock(u64::try_from(messages).unwrap()),
                                )
                                .unwrap();
                            update.check_current(&owner).unwrap();
                            assert!(update.committed().update().fault().is_none());
                            if messages > 1 {
                                assert!(
                                    update
                                        .committed()
                                        .update()
                                        .effects()
                                        .iter()
                                        .any(|effect| matches!(effect, Effect::Show(_)))
                                );
                                assert_eq!(owner.counts().unwrap().active(), messages - 1);
                            }
                            if messages == expected_messages {
                                return;
                            }
                        }
                        other => panic!("unexpected denial fixture phone event {other:?}"),
                    }
                }
                panic!("bounded denial fixture phone flow exhausted")
            };
            let server_flow = async {
                let mut replies = 0;
                for _ in 0..event_limit {
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
                            if replies == expected_messages {
                                return;
                            }
                            let next = bindings
                                .get(replies - 1)
                                .copied()
                                .expect("one signed frame per request");
                            server
                                .queue_frame(frame(PcEvent::Opened {
                                    binding: next,
                                    issued_at: ServiceTick::from_nanos_since_epoch(0),
                                    content: Arc::clone(&content),
                                }))
                                .unwrap();
                        }
                        other => panic!("unexpected denial fixture server event {other:?}"),
                    }
                }
                panic!("bounded denial fixture server flow exhausted")
            };
            tokio::join!(phone_flow, server_flow);
            drop(phone);
            drop(server);
            assert_eq!(budget.active(), 0);
            assert_eq!(owner.counts().unwrap().active(), count);
            // The original source remains in the inbox after transport teardown.
            // This fixture does not claim a still-connected sender or native owner.
            Fixture {
                owner,
                temp,
                binding,
                bindings,
                reference,
                final_clock: clock(u64::try_from(expected_messages).unwrap()),
            }
        })
        .await
        .expect("bounded real associated ingress for denial ABI fixture")
    })
}
