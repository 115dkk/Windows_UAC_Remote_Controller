// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TLS through the production native callback objects, using isolated
//! host-model files and explicitly synthetic software P-256 keys. This does not
//! exercise Kotlin/JNA, Android hardware policy, pairing or user authentication.
#![cfg(any(windows, target_os = "linux"))]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use android_controller::{
    DurableInbox, LocalAttestationChallenge, LocalKeyHandle, LocalKeySetDescriptor,
    PeerAssociationDescriptor, PeerAssociationMutation, PeerAssociationRef,
};
use approval_protocol::{DeviceId, PcIdentity};
use notification_policy::{
    CapacityLimits, ClockReading, LocalTime, MonotonicTime, NotificationPolicy, Weekday,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use phone_request_core::{InboxClock, PhoneBootId};
use phone_state_store::NativePrivateDirectory;
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, Channel, ChannelError, ChannelStatus,
    EndpointRole, PlaintextRead, PlatformTlsSigner, SignerError, TlsIdentity, TlsPublicKey,
};
use uac_android_controller::{
    BridgeError, NativeCertificateVerify, NativeClock, NativeLocalKeySet, NativePlatform,
    NativeRequestSelection, NativeTransportBinding, native_client_transport_identity,
};

const TRANSPORT_SEED: u8 = 5;
const PC_SEED: u8 = 6;
const CHUNK: usize = 251;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn public(seed: u8) -> TlsPublicKey {
    let key = key(seed);
    let point =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(point.to_public_key_der().unwrap().as_bytes()).unwrap()
}
fn owner(temp: &tempfile::TempDir) -> (DurableInbox, PeerAssociationRef) {
    let clock = InboxClock::new(
        ClockReading::new(
            MonotonicTime::from_millis(0),
            LocalTime::new(Weekday::Monday, 600).unwrap(),
        ),
        0,
    )
    .unwrap();
    let (mut owner, initial) = DurableInbox::create_fresh_host_model(
        NativePrivateDirectory::from_native_app_data(temp.path()).unwrap(),
        NotificationPolicy::default(),
        CapacityLimits::default(),
        PhoneBootId::from_native_boot_count(5).unwrap(),
        clock,
    )
    .unwrap();
    assert!(initial.update().effects().is_empty());
    let handle = LocalKeyHandle::from_bytes([1; 32]).unwrap();
    let challenge = LocalAttestationChallenge::from_bytes([2; 32]).unwrap();
    let _ = owner.begin_local_key_creation(handle, challenge).unwrap();
    let _ = owner
        .record_local_key_creation(
            LocalKeySetDescriptor::new(
                handle,
                challenge,
                public(3),
                public(4),
                public(TRANSPORT_SEED),
            )
            .unwrap(),
        )
        .unwrap();
    let (_, mutation) = owner
        .record_peer_association_from_trusted_host(
            PeerAssociationDescriptor::new(
                PcIdentity::from_bytes([7; 32]).unwrap(),
                DeviceId::from_bytes([9; 16]).unwrap(),
                1,
                handle,
                public(PC_SEED),
                public(PC_SEED),
            )
            .unwrap(),
        )
        .unwrap();
    let reference = match mutation {
        PeerAssociationMutation::Recorded(reference)
        | PeerAssociationMutation::AlreadyRecorded(reference) => reference,
    };
    (owner, reference)
}

#[derive(Clone, Copy)]
enum Behavior {
    Valid,
    CancelDuringSign,
    WrongTranscript,
    MalformedDer,
    FailedPrepare,
}

struct SyntheticNativePlatform {
    behavior: Behavior,
    // Simulates this one native platform's retained holder, not an alias lookup
    // from input bytes. Keeping the object for assertions does not keep a signer.
    binding: Mutex<Option<Arc<NativeTransportBinding>>>,
    input: Mutex<Option<Arc<NativeCertificateVerify>>>,
    prepare_calls: AtomicUsize,
    sign_calls: AtomicUsize,
    key_uses: AtomicUsize,
    release_calls: AtomicUsize,
    local_reference_releases: AtomicUsize,
    unexpected_calls: AtomicUsize,
}
impl SyntheticNativePlatform {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            behavior,
            binding: Mutex::new(None),
            input: Mutex::new(None),
            prepare_calls: AtomicUsize::new(0),
            sign_calls: AtomicUsize::new(0),
            key_uses: AtomicUsize::new(0),
            release_calls: AtomicUsize::new(0),
            local_reference_releases: AtomicUsize::new(0),
            unexpected_calls: AtomicUsize::new(0),
        })
    }
    fn binding(&self) -> Arc<NativeTransportBinding> {
        self.binding.lock().unwrap().as_ref().unwrap().clone()
    }
    fn unused<T>(&self) -> Result<T, BridgeError> {
        self.unexpected_calls.fetch_add(1, Ordering::SeqCst);
        Err(BridgeError::NativeUnavailable)
    }
    fn assert_cleaned_once(&self) {
        assert!(self.binding().is_closed());
        assert_eq!(self.release_calls.load(Ordering::SeqCst), 1);
        assert_eq!(self.local_reference_releases.load(Ordering::SeqCst), 0);
        assert_eq!(self.unexpected_calls.load(Ordering::SeqCst), 0);
    }
}
impl NativePlatform for SyntheticNativePlatform {
    fn prepare_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError> {
        assert_eq!(self.prepare_calls.fetch_add(1, Ordering::SeqCst), 0);
        assert!(!binding.is_closed());
        assert_ne!(binding.reference_id(), 0);
        assert!(binding.same_binding(binding.clone()));
        let keys = binding.local_keys()?;
        assert_eq!(keys.handle, vec![1; 32]);
        assert_eq!(keys.approval_spki, public(3).as_spki_der());
        assert_eq!(keys.denial_spki, public(4).as_spki_der());
        assert_eq!(keys.transport_spki, public(TRANSPORT_SEED).as_spki_der());
        *self.binding.lock().unwrap() = Some(binding);
        if matches!(self.behavior, Behavior::FailedPrepare) {
            // An actual failed callback may have published a partial holder.
            return Err(BridgeError::NativeUnavailable);
        }
        Ok(())
    }

    fn sign_client_certificate_verify(
        &self,
        input: Arc<NativeCertificateVerify>,
    ) -> Result<Vec<u8>, BridgeError> {
        assert_eq!(self.sign_calls.fetch_add(1, Ordering::SeqCst), 0);
        let binding = self.binding();
        assert!(!binding.is_closed());
        assert!(input.belongs_to(binding.clone()));
        assert_eq!(input.binding_id(), binding.reference_id());
        assert!(!input.is_cancelled());
        // No raw request constructor exists in the test: this object arrived
        // from the real TLS engine through the production opaque ABI boundary.
        let bytes = input.take_bytes()?;
        assert!(matches!(bytes.len(), 130 | 146));
        let context = b"TLS 1.3, client CertificateVerify";
        assert_eq!(&bytes[..64], &[0x20; 64]);
        assert_eq!(&bytes[64..64 + context.len()], context);
        assert_eq!(bytes[64 + context.len()], 0);
        assert!(matches!(bytes.len() - (65 + context.len()), 32 | 48));
        assert_eq!(input.take_bytes(), Err(BridgeError::NativeUnavailable));
        *self.input.lock().unwrap() = Some(input.clone());
        if matches!(self.behavior, Behavior::MalformedDer) {
            return Ok(vec![0x30, 0]);
        }
        self.key_uses.fetch_add(1, Ordering::SeqCst);
        // The native fixture ONLY uses the transport key, never approval/denial.
        let signing = key(TRANSPORT_SEED);
        let signed_bytes: &[u8] = if matches!(self.behavior, Behavior::WrongTranscript) {
            b"synthetic wrong TLS transcript"
        } else {
            &bytes
        };
        let signature: Signature = signing.sign(signed_bytes);
        if matches!(self.behavior, Behavior::CancelDuringSign) {
            binding.close_binding();
            assert!(input.is_cancelled());
        }
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn release_transport_signer(
        &self,
        binding: Arc<NativeTransportBinding>,
    ) -> Result<(), BridgeError> {
        assert!(
            binding.is_closed(),
            "Rust closes the binding BEFORE native release"
        );
        assert!(binding.same_binding(self.binding()));
        assert_eq!(self.release_calls.fetch_add(1, Ordering::SeqCst), 0);
        assert!(binding.local_keys().is_err());
        Ok(())
    }
    fn state_directory(&self) -> Result<String, BridgeError> {
        self.unused()
    }
    fn clock(&self) -> Result<NativeClock, BridgeError> {
        self.unused()
    }
    fn unix_millis(&self) -> Result<u64, BridgeError> {
        self.unused()
    }
    fn legacy_policy_document(&self) -> Result<Option<String>, BridgeError> {
        self.unused()
    }
    fn has_device_keys(&self) -> Result<bool, BridgeError> {
        self.unused()
    }
    fn reopen_local_key_sets(&self, _keys: Vec<NativeLocalKeySet>) -> Result<(), BridgeError> {
        self.unused()
    }
    fn release_local_key_references(&self) -> Result<(), BridgeError> {
        self.local_reference_releases.fetch_add(1, Ordering::SeqCst);
        Err(BridgeError::NativeUnavailable)
    }
    fn clear_request_notifications(&self) -> Result<(), BridgeError> {
        self.unused()
    }
    fn withdraw_requests(&self, _requests: Vec<NativeRequestSelection>) -> Result<(), BridgeError> {
        self.unused()
    }
}

struct SyntheticPcSigner;
impl PlatformTlsSigner for SyntheticPcSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(public(PC_SEED))
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        assert_eq!(input.role(), EndpointRole::Server);
        let signature: Signature = key(PC_SEED).sign(input.as_bytes());
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}
fn channels(identity: TlsIdentity, pc_pin: TlsPublicKey, now: Instant) -> (Channel, Channel) {
    (
        Channel::client(identity, pc_pin, now).unwrap(),
        Channel::server(
            TlsIdentity::from_trusted_host(EndpointRole::Server, Arc::new(SyntheticPcSigner))
                .unwrap(),
            public(TRANSPORT_SEED),
            now,
        )
        .unwrap(),
    )
}
fn transfer(from: &mut Channel, to: &mut Channel, now: Instant) -> Result<usize, ChannelError> {
    let mut bytes = [0; CHUNK];
    let count = from.drain_tls(&mut bytes, now)?;
    let mut consumed = 0;
    // Each successful step consumes at least one byte, so this suffix loop has
    // at most CHUNK iterations and never drops partially accepted ciphertext.
    while consumed < count {
        let next = to.feed_tls(&bytes[consumed..count], now)?;
        assert!(
            next > 0,
            "bounded handshake unexpectedly stopped accepting its suffix"
        );
        consumed += next;
    }
    Ok(count)
}
fn handshake(client: &mut Channel, server: &mut Channel, now: Instant) -> Result<(), ChannelError> {
    for _ in 0..2048 {
        let sent = transfer(client, server, now)?;
        let received = transfer(server, client, now)?;
        client.tick(now)?;
        server.tick(now)?;
        if client.status() == ChannelStatus::Ready
            && server.status() == ChannelStatus::Ready
            && client.buffered_tls_bytes() == 0
            && server.buffered_tls_bytes() == 0
        {
            return Ok(());
        }
        assert!(
            sent + received > 0,
            "bounded real TLS pump made no progress"
        );
    }
    panic!("real TLS handshake exceeded fixed byte-pump bound");
}

#[test]
fn real_tls_uses_the_opaque_one_shot_client_input_and_transport_key() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, association) = owner(&temp);
    let platform = SyntheticNativePlatform::new(Behavior::Valid);
    let identity =
        native_client_transport_identity(&mut owner, association, platform.clone()).unwrap();
    assert_eq!(identity.role(), EndpointRole::Client);
    assert_eq!(identity.public_key(), &public(TRANSPORT_SEED));
    assert_eq!(
        platform.sign_calls.load(Ordering::SeqCst),
        0,
        "prepare is not signing"
    );
    let now = Instant::now();
    let (mut client, mut server) = channels(identity, public(PC_SEED), now);
    handshake(&mut client, &mut server, now).unwrap();
    assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 1);
    assert_eq!(platform.key_uses.load(Ordering::SeqCst), 1);
    assert_eq!(platform.release_calls.load(Ordering::SeqCst), 0);
    let message = b"synthetic encrypted transport bytes";
    assert_eq!(client.write_plaintext(message, now).unwrap(), message.len());
    assert!(transfer(&mut client, &mut server, now).unwrap() > 0);
    let mut received = [0; 128];
    assert_eq!(
        server.read_plaintext(&mut received, now).unwrap(),
        PlaintextRead::Data(message.len())
    );
    assert_eq!(&received[..message.len()], message);
    client.close(now).unwrap();
    platform.assert_cleaned_once();
    let input = platform.input.lock().unwrap().as_ref().unwrap().clone();
    assert!(input.is_cancelled());
    assert_eq!(input.take_bytes(), Err(BridgeError::NativeUnavailable));
    drop((client, server));
    platform.assert_cleaned_once();
}

#[test]
fn wrong_pc_pin_rejects_before_any_native_client_key_use() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, association) = owner(&temp);
    let platform = SyntheticNativePlatform::new(Behavior::Valid);
    let identity =
        native_client_transport_identity(&mut owner, association, platform.clone()).unwrap();
    let now = Instant::now();
    let (mut client, mut server) = channels(identity, public(8), now);
    assert_eq!(
        handshake(&mut client, &mut server, now),
        Err(ChannelError::TlsRejected)
    );
    assert_ne!(client.status(), ChannelStatus::Ready);
    assert_ne!(server.status(), ChannelStatus::Ready);
    assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 0);
    assert_eq!(platform.key_uses.load(Ordering::SeqCst), 0);
    drop((client, server));
    platform.assert_cleaned_once();
}

#[test]
fn original_association_revocation_after_identity_creation_forbids_key_use() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, association) = owner(&temp);
    let platform = SyntheticNativePlatform::new(Behavior::Valid);
    let identity =
        native_client_transport_identity(&mut owner, association, platform.clone()).unwrap();
    let _ = owner
        .revoke_peer_association_from_trusted_host(association)
        .unwrap();
    assert!(platform.binding().is_closed());
    assert!(matches!(
        native_client_transport_identity(&mut owner, association, platform.clone()),
        Err(BridgeError::LocalKeysUnavailable)
    ));
    assert_eq!(platform.prepare_calls.load(Ordering::SeqCst), 1);
    let now = Instant::now();
    let (mut client, mut server) = channels(identity, public(PC_SEED), now);
    assert_eq!(
        handshake(&mut client, &mut server, now),
        Err(ChannelError::TlsRejected)
    );
    assert_ne!(client.status(), ChannelStatus::Ready);
    assert_ne!(server.status(), ChannelStatus::Ready);
    assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 0);
    assert_eq!(platform.key_uses.load(Ordering::SeqCst), 0);
    drop((client, server));
    platform.assert_cleaned_once();
}

#[test]
fn cancellation_during_callback_and_signature_failures_never_produce_ready() {
    for behavior in [
        Behavior::CancelDuringSign,
        Behavior::WrongTranscript,
        Behavior::MalformedDer,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (mut owner, association) = owner(&temp);
        let platform = SyntheticNativePlatform::new(behavior);
        let identity =
            native_client_transport_identity(&mut owner, association, platform.clone()).unwrap();
        let now = Instant::now();
        let (mut client, mut server) = channels(identity, public(PC_SEED), now);
        assert_eq!(
            handshake(&mut client, &mut server, now),
            Err(ChannelError::TlsRejected)
        );
        assert_ne!(client.status(), ChannelStatus::Ready);
        assert_ne!(server.status(), ChannelStatus::Ready);
        assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 1);
        drop((client, server));
        platform.assert_cleaned_once();
        assert!(
            platform
                .input
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .is_cancelled()
        );
    }
}

#[test]
fn failed_prepare_still_closes_and_releases_its_partially_published_holder_once() {
    let temp = tempfile::tempdir().unwrap();
    let (mut owner, association) = owner(&temp);
    let platform = SyntheticNativePlatform::new(Behavior::FailedPrepare);
    let result = native_client_transport_identity(&mut owner, association, platform.clone());
    assert!(matches!(result, Err(BridgeError::NativeUnavailable)));
    assert_eq!(platform.prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 0);
    assert_eq!(platform.key_uses.load(Ordering::SeqCst), 0);
    platform.assert_cleaned_once();
    drop(result);
    platform.assert_cleaned_once();
}

#[test]
fn dropping_unused_identity_or_channel_releases_only_its_transport_holder_once() {
    for create_channel in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (mut owner, association) = owner(&temp);
        let platform = SyntheticNativePlatform::new(Behavior::Valid);
        let identity =
            native_client_transport_identity(&mut owner, association, platform.clone()).unwrap();
        if create_channel {
            drop(Channel::client(identity, public(PC_SEED), Instant::now()).unwrap());
        } else {
            drop(identity);
        }
        assert_eq!(platform.sign_calls.load(Ordering::SeqCst), 0);
        assert_eq!(platform.key_uses.load(Ordering::SeqCst), 0);
        platform.assert_cleaned_once();
    }
}
