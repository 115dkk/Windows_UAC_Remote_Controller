// SPDX-License-Identifier: GPL-2.0-or-later
//! Real loopback TCP relay + real TLS + signed service event. Synthetic identity
//! keys only: not QR enrollment, TPM/Keystore, Android UI or Windows UAC proof.
use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use framed_transport::{
    ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable, SocketDriver,
    SocketEvent, SocketLimits, TransportStatus,
};
use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use relay_service::{CancellationToken, Registration, RelayLimits, Role, RouteId};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use service_protocol::{
    PcEvent, PcPublicKey, ServiceTick, UnsignedPcEvent, VerifiedPcEvent, encode_frame,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct SyntheticTransportSigner(SigningKey);
impl PlatformTlsSigner for SyntheticTransportSigner {
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

struct RelayFixture {
    stop: CancellationToken,
    task: JoinHandle<Result<relay_service::RelayReport, relay_service::RelayError>>,
}
impl Drop for RelayFixture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

struct SyntheticClock;

impl SocketClock for SyntheticClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}

// Test orchestration only: all socket I/O, buffering and TLS driving belong to
// production SocketDriver. These fixtures still do not prove native identities.
async fn exchange_one(
    socket: TcpStream,
    transport: PeerTransport,
    outbound: Vec<u8>,
) -> (SocketDriver, Vec<u8>) {
    let mut driver = SocketDriver::new(
        socket,
        transport,
        Arc::new(SyntheticClock),
        SocketLimits::default(),
        CancellationToken::new(),
    )
    .unwrap();
    let mut outbound = Some(outbound);
    let mut received = None;
    let mut locally_drained = false;
    for _ in 0..4 {
        match driver.next_event().await.unwrap() {
            SocketEvent::Ready => driver.queue_frame(outbound.take().unwrap()).unwrap(),
            SocketEvent::Frame(frame) => {
                assert!(received.is_none(), "one expected application frame");
                received = Some(frame.into_bytes());
            }
            SocketEvent::OutboundDrained => locally_drained = true,
            SocketEvent::PeerClosed | SocketEvent::LocallyClosed => {
                panic!("connection closed before the expected exchange");
            }
        }
        if locally_drained && let Some(frame) = received.take() {
            return (driver, frame);
        }
    }
    panic!("bounded synthetic exchange event count exhausted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_service_event_crosses_real_rendezvous_and_mutually_pinned_tls() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let mut relay = RelayFixture {
            task: tokio::spawn(relay_service::run(
                listener,
                RelayLimits::new(2, 1).unwrap(),
                stop.clone(),
            )),
            stop,
        };
        let route = RouteId::new([42; 32]).unwrap();
        let (pc_carrier, phone_carrier) = tokio::try_join!(
            relay_service::connect_rendezvous(
                address,
                Registration::new(Role::Pc, route),
                CancellationToken::new()
            ),
            relay_service::connect_rendezvous(
                address,
                Registration::new(Role::Phone, route),
                CancellationToken::new()
            ),
        )
        .unwrap();
        let pc_socket = pc_carrier.into_stream();
        let phone_socket = phone_carrier.into_stream();
        assert!(pc_socket.nodelay().unwrap());
        assert!(phone_socket.nodelay().unwrap());
        // These public routing markers provide no authenticated peer identity.
        let pc_signer = Arc::new(SyntheticTransportSigner(
            SigningKey::from_slice(&[3; 32]).unwrap(),
        ));
        let phone_signer = Arc::new(SyntheticTransportSigner(
            SigningKey::from_slice(&[4; 32]).unwrap(),
        ));
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let pc_channel = PeerTransport::server(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(EndpointRole::Server, pc_signer.clone()).unwrap(),
            phone_signer.public_key().unwrap(),
            Instant::now(),
        )
        .unwrap();
        let phone_channel = PeerTransport::client(
            Arc::clone(&budget),
            TlsIdentity::from_trusted_host(EndpointRole::Client, phone_signer).unwrap(),
            pc_signer.public_key().unwrap(),
            Instant::now(),
        )
        .unwrap();
        assert_eq!(pc_channel.status(), TransportStatus::Handshaking);
        assert_eq!(phone_channel.status(), TransportStatus::Handshaking);
        let pc = PcIdentity::from_bytes([9; 32]).unwrap();
        let content = Arc::new(
            RequestContent::new(
                "Synthetic app",
                "C:\\Synthetic\\app.exe",
                "synthetic-only details",
            )
            .unwrap(),
        );
        let binding = RequestBinding::new(
            pc,
            BootEpoch::from_bytes([1; 32]).unwrap(),
            OsSession::new(1, 7),
            RequestId::from_bytes([2; 32]).unwrap(),
            ChallengeNonce::from_bytes([5; 32]).unwrap(),
            content.digest(),
            ExpiryTick::from_nanos_since_epoch(60_000_000_000).unwrap(),
        );
        let event = PcEvent::Opened {
            binding,
            issued_at: ServiceTick::from_nanos_since_epoch(0),
            content,
        };
        let service_signer = SigningKey::from_slice(&[11; 32]).unwrap();
        let service_key = PcPublicKey::from_sec1_bytes(
            service_signer
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();
        let unsigned = UnsignedPcEvent::new(event.clone()).unwrap();
        let signature: Signature = service_signer.sign(&unsigned.signing_bytes());
        let service_frame = encode_frame(
            &unsigned
                .with_der_signature(signature.to_der().as_bytes())
                .unwrap()
                .to_wire(),
        )
        .unwrap();
        let receipt = encode_frame(b"synthetic transport receipt, NOT approval").unwrap();
        let (pc_result, phone_result) = tokio::join!(
            exchange_one(pc_socket, pc_channel, service_frame),
            exchange_one(phone_socket, phone_channel, receipt)
        );
        assert_eq!(pc_result.1, b"synthetic transport receipt, NOT approval");
        assert_eq!(
            VerifiedPcEvent::from_wire(&phone_result.1, pc, &service_key)
                .unwrap()
                .event(),
            &event
        );
        assert_eq!(budget.active(), 2);
        drop((pc_result, phone_result));
        assert_eq!(budget.active(), 0);
        relay.stop.cancel();
        let report = (&mut relay.task).await.unwrap().unwrap();
        assert_eq!(report.paired, 1);
        assert_eq!(report.remaining_connections, 0);
    })
    .await
    .expect("bounded real TCP/TLS integration deadline");
}
