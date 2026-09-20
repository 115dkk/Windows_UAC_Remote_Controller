// SPDX-License-Identifier: GPL-2.0-or-later
//! SOFTWARE TEST KEYS ONLY. No Windows identity, provider, service or UI calls.
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
    pkcs8::EncodePublicKey,
};
use secure_channel::{Channel, MAX_DRAIN_BYTES, TlsIdentity};

use super::*;

pub(crate) trait SyntheticKey {
    fn public_key(&self) -> Result<TlsPublicKey, TlsSigningBridgeError>;
    fn sign(&self, input: &OwnedCertificateVerifyInput) -> Response;
}

struct SoftwareSigner {
    key: SigningKey,
    public: TlsPublicKey,
}

impl SoftwareSigner {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let point = p256::PublicKey::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap();
        let public =
            TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap();
        Self { key, public }
    }

    fn signature(&self, bytes: &[u8]) -> CertificateVerifySignature {
        let signature: Signature = self.key.sign(bytes);
        CertificateVerifySignature::from_der(signature.to_der().as_bytes()).unwrap()
    }
}

impl PlatformTlsSigner for SoftwareSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(self.public.clone())
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        Ok(self.signature(input.as_bytes()))
    }
}

struct Recorder {
    public: TlsPublicKey,
    sender: SyncSender<OwnedCertificateVerifyInput>,
}

impl PlatformTlsSigner for Recorder {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(self.public.clone())
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        self.sender.try_send(input.into_owned()).unwrap();
        Err(SignerError::Rejected)
    }
}

/// Derive every witness through an actual rustls handshake. There is no test
/// byte parser or unchecked witness constructor available outside secure-channel.
fn input_from_tls(role: EndpointRole) -> OwnedCertificateVerifyInput {
    let client_key = Arc::new(SoftwareSigner::new(31));
    let server_key = Arc::new(SoftwareSigner::new(32));
    let client_public = client_key.public.clone();
    let server_public = server_key.public.clone();
    let (sender, received) = mpsc::sync_channel(1);
    let recorder = Arc::new(Recorder {
        public: if role == EndpointRole::Client {
            client_public.clone()
        } else {
            server_public.clone()
        },
        sender,
    });
    let client_signer: Arc<dyn PlatformTlsSigner> = if role == EndpointRole::Client {
        recorder.clone()
    } else {
        client_key
    };
    let server_signer: Arc<dyn PlatformTlsSigner> = if role == EndpointRole::Server {
        recorder
    } else {
        server_key
    };
    let now = Instant::now();
    let mut client = Channel::client(
        TlsIdentity::from_trusted_host(EndpointRole::Client, client_signer).unwrap(),
        server_public,
        now,
    )
    .unwrap();
    let mut server = Channel::server(
        TlsIdentity::from_trusted_host(EndpointRole::Server, server_signer).unwrap(),
        client_public,
        now,
    )
    .unwrap();
    let mut buffer = [0; MAX_DRAIN_BYTES];
    for _ in 0..32 {
        let count = client.drain_tls(&mut buffer, now).unwrap();
        if count > 0 {
            let result = server.feed_tls(&buffer[..count], now);
            if let Ok(input) = received.try_recv() {
                return input;
            }
            assert_eq!(result.unwrap(), count);
        }
        let count = server.drain_tls(&mut buffer, now).unwrap();
        if count > 0 {
            let result = client.feed_tls(&buffer[..count], now);
            if let Ok(input) = received.try_recv() {
                return input;
            }
            assert_eq!(result.unwrap(), count);
        }
    }
    panic!("bounded synthetic TLS fixture did not reach CertificateVerify");
}

struct FixtureKey {
    signer: SoftwareSigner,
    advertised: RefCell<TlsPublicKey>,
    public_calls: Cell<usize>,
    sign_calls: Cell<usize>,
    wrong_signature: bool,
    panic_sign: bool,
    changed_after_sign: Option<TlsPublicKey>,
    clock_after_public: Option<(Rc<Cell<Instant>>, Instant)>,
    clock_after_sign: Option<(Rc<Cell<Instant>>, Instant)>,
}

impl FixtureKey {
    fn new(seed: u8) -> Self {
        let signer = SoftwareSigner::new(seed);
        Self {
            advertised: RefCell::new(signer.public.clone()),
            signer,
            public_calls: Cell::new(0),
            sign_calls: Cell::new(0),
            wrong_signature: false,
            panic_sign: false,
            changed_after_sign: None,
            clock_after_public: None,
            clock_after_sign: None,
        }
    }
}

impl SyntheticKey for FixtureKey {
    fn public_key(&self) -> Result<TlsPublicKey, TlsSigningBridgeError> {
        self.public_calls.set(self.public_calls.get() + 1);
        if let Some((clock, now)) = self
            .clock_after_public
            .as_ref()
            .filter(|_| self.public_calls.get() > 1)
        {
            clock.set(*now);
        }
        Ok(self.advertised.borrow().clone())
    }
    fn sign(&self, input: &OwnedCertificateVerifyInput) -> Response {
        self.sign_calls.set(self.sign_calls.get() + 1);
        assert!(!self.panic_sign, "SYNTHETIC provider unwind");
        let signature = if self.wrong_signature {
            self.signer.signature(b"SYNTHETIC wrong message")
        } else {
            self.signer.signature(input.as_bytes())
        };
        if let Some(public) = &self.changed_after_sign {
            *self.advertised.borrow_mut() = public.clone();
        }
        if let Some((clock, now)) = &self.clock_after_sign {
            clock.set(*now);
        }
        Ok(signature)
    }
}

fn enqueue_elsewhere(
    signer: &Arc<ServiceTlsSigner>,
    input: OwnedCertificateVerifyInput,
    now: Instant,
) -> Result<PendingCall, TlsSigningBridgeError> {
    let signer = Arc::clone(signer);
    thread::spawn(move || signer.enqueue(input, now))
        .join()
        .unwrap()
}

#[test]
fn transfers_actual_server_frame_and_verifies_the_exact_returned_signature() {
    let key = FixtureKey::new(41);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let input = input_from_tls(EndpointRole::Server);
    let message = input.as_bytes().to_vec();
    let call = enqueue_elsewhere(&signer, input, Instant::now()).unwrap();
    assert_eq!(signer.pending_count(), 1);
    assert_eq!(worker.process_one(), Ok(TlsSigningProgress::Signed));
    let signature = call.wait(Instant::now).unwrap();
    let parsed = Signature::from_der(signature.as_der()).unwrap();
    assert!(
        key.signer
            .key
            .verifying_key()
            .verify(&message, &parsed)
            .is_ok()
    );
    assert_eq!(key.sign_calls.get(), 1);
    assert_eq!(key.public_calls.get(), 3); // factory, immediately before, after
    assert_eq!(signer.pending_count(), 0);
    assert_eq!(worker.process_one(), Ok(TlsSigningProgress::Idle));
}

#[test]
fn queue_and_uncollected_responses_share_one_capacity_budget() {
    let key = FixtureKey::new(42);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let mut calls = Vec::new();
    let now = Instant::now();
    for _ in 0..MAX_TLS_SIGNING_REQUESTS {
        calls.push(enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), now).unwrap());
    }
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS);
    assert_eq!(
        enqueue_elsewhere(
            &signer,
            input_from_tls(EndpointRole::Server),
            Instant::now()
        )
        .err(),
        Some(TlsSigningBridgeError::Busy)
    );
    assert_eq!(
        worker.process_with_clock(|| now),
        Ok(TlsSigningProgress::Signed)
    );
    assert_eq!(
        signer.pending_count(),
        MAX_TLS_SIGNING_REQUESTS,
        "a response still owned by its caller retains capacity"
    );
    calls.remove(0).wait(|| now).unwrap();
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS - 1);
    calls.push(
        enqueue_elsewhere(
            &signer,
            input_from_tls(EndpointRole::Server),
            Instant::now(),
        )
        .unwrap(),
    );
    worker.close();
    drop(calls);
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn same_worker_thread_and_client_role_are_rejected_before_queue_or_key_work() {
    let key = FixtureKey::new(43);
    let (signer, _worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    assert_eq!(
        signer
            .enqueue(input_from_tls(EndpointRole::Server), Instant::now())
            .err(),
        Some(TlsSigningBridgeError::SameThread)
    );
    assert_eq!(
        enqueue_elsewhere(
            &signer,
            input_from_tls(EndpointRole::Client),
            Instant::now()
        )
        .err(),
        Some(TlsSigningBridgeError::WrongRole)
    );
    assert_eq!(signer.pending_count(), 0);
    assert_eq!(key.sign_calls.get(), 0);
}

#[test]
fn stale_queued_frame_is_discarded_before_public_lookup_or_sign() {
    let key = FixtureKey::new(44);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let now = Instant::now();
    let before = now.checked_sub(TLS_SIGNING_RESPONSE_TIMEOUT).unwrap();
    let call = enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), before).unwrap();
    assert_eq!(
        worker.process_with_clock(|| now),
        Ok(TlsSigningProgress::Discarded)
    );
    assert_eq!(
        call.wait(|| now).err(),
        Some(TlsSigningBridgeError::TimedOut)
    );
    assert_eq!(key.public_calls.get(), 1);
    assert_eq!(key.sign_calls.get(), 0);
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn dropped_caller_cancels_queued_native_work_but_retains_its_queue_permit() {
    let key = FixtureKey::new(45);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let call = enqueue_elsewhere(
        &signer,
        input_from_tls(EndpointRole::Server),
        Instant::now(),
    )
    .unwrap();
    drop(call);
    assert_eq!(signer.pending_count(), 1);
    assert_eq!(worker.process_one(), Ok(TlsSigningProgress::Discarded));
    assert_eq!(signer.pending_count(), 0);
    assert_eq!(key.sign_calls.get(), 0);
}

#[test]
fn provider_result_at_deadline_is_discarded_and_no_post_deadline_lookup_occurs() {
    let start = Instant::now();
    let clock = Rc::new(Cell::new(start));
    let deadline = start + TLS_SIGNING_RESPONSE_TIMEOUT;
    let mut key = FixtureKey::new(46);
    key.clock_after_sign = Some((Rc::clone(&clock), deadline));
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let call = enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), start).unwrap();
    assert_eq!(
        worker.process_with_clock(|| clock.get()),
        Ok(TlsSigningProgress::Discarded)
    );
    assert_eq!(
        call.wait(|| clock.get()).err(),
        Some(TlsSigningBridgeError::TimedOut)
    );
    assert_eq!(key.sign_calls.get(), 1);
    assert_eq!(key.public_calls.get(), 2);
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn deadline_is_freshly_checked_after_blocking_public_key_inspection() {
    let start = Instant::now();
    let clock = Rc::new(Cell::new(start));
    let mut key = FixtureKey::new(54);
    key.clock_after_public = Some((Rc::clone(&clock), start + TLS_SIGNING_RESPONSE_TIMEOUT));
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let call = enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), start).unwrap();
    assert_eq!(
        worker.process_with_clock(|| clock.get()),
        Ok(TlsSigningProgress::Discarded)
    );
    assert_eq!(
        call.wait(|| clock.get()).err(),
        Some(TlsSigningBridgeError::TimedOut)
    );
    assert_eq!(key.sign_calls.get(), 0);
}

#[test]
fn already_queued_signature_is_not_returned_after_the_caller_deadline() {
    let key = FixtureKey::new(47);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let now = Instant::now();
    let call = enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), now).unwrap();
    assert_eq!(
        worker.process_with_clock(|| now),
        Ok(TlsSigningProgress::Signed)
    );
    assert_eq!(
        call.wait(|| now + TLS_SIGNING_RESPONSE_TIMEOUT).err(),
        Some(TlsSigningBridgeError::TimedOut)
    );
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn proxy_close_rejects_all_uncollected_signatures_and_keeps_live_calls_counted() {
    let key = FixtureKey::new(57);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let now = Instant::now();
    let mut calls = Vec::new();
    for _ in 0..MAX_TLS_SIGNING_REQUESTS {
        calls.push(enqueue_elsewhere(&signer, input_from_tls(EndpointRole::Server), now).unwrap());
        assert_eq!(
            worker.process_with_clock(|| now),
            Ok(TlsSigningProgress::Signed)
        );
    }
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS);
    assert_eq!(key.sign_calls.get(), MAX_TLS_SIGNING_REQUESTS);
    signer.close();
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS);
    for remaining in (0..MAX_TLS_SIGNING_REQUESTS).rev() {
        assert_eq!(
            calls.pop().unwrap().wait(|| now).err(),
            Some(TlsSigningBridgeError::Closed)
        );
        assert_eq!(signer.pending_count(), remaining);
    }
    assert_eq!(worker.process_one(), Err(TlsSigningBridgeError::Closed));
}

#[test]
fn changed_public_key_before_or_after_sign_latches_bridge_closed() {
    for after in [false, true] {
        let mut key = FixtureKey::new(48);
        let wrong = SoftwareSigner::new(49).public;
        if after {
            key.changed_after_sign = Some(wrong.clone());
        }
        let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
        if !after {
            *key.advertised.borrow_mut() = wrong;
        }
        let call = enqueue_elsewhere(
            &signer,
            input_from_tls(EndpointRole::Server),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(
            worker.process_one(),
            Err(TlsSigningBridgeError::PublicKeyMismatch)
        );
        assert!(call.wait(Instant::now).is_err());
        assert!(signer.is_closed());
        assert_eq!(key.sign_calls.get(), usize::from(after));
        assert_eq!(signer.pending_count(), 0);
    }
}

#[test]
fn cryptographically_wrong_signature_is_never_returned() {
    let mut key = FixtureKey::new(50);
    key.wrong_signature = true;
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let call = enqueue_elsewhere(
        &signer,
        input_from_tls(EndpointRole::Server),
        Instant::now(),
    )
    .unwrap();
    assert_eq!(
        worker.process_one(),
        Err(TlsSigningBridgeError::InvalidSignature)
    );
    assert!(call.wait(Instant::now).is_err());
    assert!(signer.is_closed());
}

#[test]
fn worker_close_drop_and_signer_close_are_irreversible_and_do_not_use_key() {
    for close in 0..3 {
        let key = FixtureKey::new(51);
        let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
        let call = enqueue_elsewhere(
            &signer,
            input_from_tls(EndpointRole::Server),
            Instant::now(),
        )
        .unwrap();
        match close {
            0 => {
                worker.close();
                worker.close();
            }
            1 => drop(worker),
            _ => {
                signer.close();
                assert_eq!(worker.process_one(), Err(TlsSigningBridgeError::Closed));
            }
        }
        assert_eq!(
            call.wait(Instant::now).err(),
            Some(TlsSigningBridgeError::Closed)
        );
        assert!(signer.public_key().is_err());
        assert_eq!(
            enqueue_elsewhere(
                &signer,
                input_from_tls(EndpointRole::Server),
                Instant::now()
            )
            .err(),
            Some(TlsSigningBridgeError::Closed)
        );
        assert_eq!(signer.pending_count(), 0);
        assert_eq!(key.sign_calls.get(), 0);
    }
}

#[test]
fn final_proxy_drop_closes_worker_without_native_signing() {
    let key = FixtureKey::new(55);
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    drop(signer);
    assert_eq!(worker.process_one(), Err(TlsSigningBridgeError::Closed));
    assert_eq!(key.sign_calls.get(), 0);
}

#[test]
fn unexpected_provider_unwind_closes_bridge_even_when_host_catches_it() {
    let mut key = FixtureKey::new(56);
    key.panic_sign = true;
    let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    let call = enqueue_elsewhere(
        &signer,
        input_from_tls(EndpointRole::Server),
        Instant::now(),
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.process_one())).is_err()
    );
    assert!(signer.is_closed());
    assert_eq!(
        call.wait(Instant::now).err(),
        Some(TlsSigningBridgeError::Closed)
    );
    assert_eq!(worker.process_one(), Err(TlsSigningBridgeError::Closed));
    assert_eq!(signer.pending_count(), 0);
}

struct BlockingKey {
    signer: SoftwareSigner,
    entered: SyncSender<()>,
    release: Receiver<()>,
}

impl SyntheticKey for BlockingKey {
    fn public_key(&self) -> Result<TlsPublicKey, TlsSigningBridgeError> {
        Ok(self.signer.public.clone())
    }
    fn sign(&self, input: &OwnedCertificateVerifyInput) -> Response {
        self.entered.send(()).unwrap();
        self.release.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(self.signer.signature(input.as_bytes()))
    }
}

#[test]
fn caller_timeout_during_provider_keeps_inflight_capacity_until_actual_return() {
    let (bridge_sender, bridge_receiver) = mpsc::sync_channel(1);
    let (run_sender, run_receiver) = mpsc::sync_channel(1);
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let (done_sender, done_receiver) = mpsc::sync_channel(1);
    let thread = thread::spawn(move || {
        let key = BlockingKey {
            signer: SoftwareSigner::new(52),
            entered: entered_sender,
            release: release_receiver,
        };
        let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
        bridge_sender.send(signer).unwrap();
        run_receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        let result = worker.process_one();
        worker.close();
        done_sender.send(result).unwrap();
    });
    let signer = bridge_receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let now = Instant::now();
    let call = signer
        .enqueue(input_from_tls(EndpointRole::Server), now)
        .unwrap();
    run_sender.send(()).unwrap();
    entered_receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        call.wait(|| now + TLS_SIGNING_RESPONSE_TIMEOUT).err(),
        Some(TlsSigningBridgeError::TimedOut)
    );
    assert_eq!(
        signer.pending_count(),
        1,
        "timeout did not preempt the provider"
    );
    let mut queued = Vec::new();
    for _ in 1..MAX_TLS_SIGNING_REQUESTS {
        queued.push(
            signer
                .enqueue(input_from_tls(EndpointRole::Server), Instant::now())
                .unwrap(),
        );
    }
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS);
    assert_eq!(
        signer
            .enqueue(input_from_tls(EndpointRole::Server), Instant::now())
            .err(),
        Some(TlsSigningBridgeError::Busy)
    );
    release_sender.send(()).unwrap();
    assert_eq!(
        done_receiver.recv_timeout(Duration::from_secs(10)).unwrap(),
        Ok(TlsSigningProgress::Discarded)
    );
    thread.join().unwrap();
    assert_eq!(signer.pending_count(), MAX_TLS_SIGNING_REQUESTS - 1);
    drop(queued);
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn proxy_close_during_provider_retains_inflight_capacity_until_actual_return() {
    let (bridge_sender, bridge_receiver) = mpsc::sync_channel(1);
    let (run_sender, run_receiver) = mpsc::sync_channel(1);
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let (done_sender, done_receiver) = mpsc::sync_channel(1);
    let thread = thread::spawn(move || {
        let key = BlockingKey {
            signer: SoftwareSigner::new(58),
            entered: entered_sender,
            release: release_receiver,
        };
        let (signer, mut worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
        bridge_sender.send(signer).unwrap();
        run_receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        let result = worker.process_one();
        worker.close();
        done_sender.send(result).unwrap();
    });
    let signer = bridge_receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let call = signer
        .enqueue(input_from_tls(EndpointRole::Server), Instant::now())
        .unwrap();
    run_sender.send(()).unwrap();
    entered_receiver
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    signer.close();
    assert!(signer.is_closed());
    assert_eq!(
        call.wait(Instant::now).err(),
        Some(TlsSigningBridgeError::Closed)
    );
    assert_eq!(
        signer.pending_count(),
        1,
        "closure did not preempt the provider"
    );
    assert_eq!(
        signer
            .enqueue(input_from_tls(EndpointRole::Server), Instant::now())
            .err(),
        Some(TlsSigningBridgeError::Closed)
    );
    release_sender.send(()).unwrap();
    assert_eq!(
        done_receiver.recv_timeout(Duration::from_secs(10)).unwrap(),
        Ok(TlsSigningProgress::Discarded)
    );
    thread.join().unwrap();
    assert_eq!(signer.pending_count(), 0);
}

#[test]
fn debug_redacts_key_and_frame_and_only_proxy_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ServiceTlsSigner>();
    let key = FixtureKey::new(53);
    let (signer, worker) = ServiceTlsSigner::with_owner(KeyOwner::Synthetic(&key)).unwrap();
    assert_eq!(
        format!("{signer:?}"),
        "ServiceTlsSigner { closed: false, pending: 0, .. }"
    );
    assert_eq!(
        format!("{worker:?}"),
        "ServiceTlsSigningWorker { closed: false, .. }"
    );
}
