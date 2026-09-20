// SPDX-License-Identifier: GPL-2.0-or-later
//! Test-only software keys and bounded real TLS byte pumps. No native/device proof.
use std::{sync::Arc, time::Instant};

use p256::{
    PublicKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, Channel, ChannelStatus, EndpointRole,
    MAX_DRAIN_BYTES, PlatformTlsSigner, SignerError, TlsIdentity, TlsPublicKey,
};

use crate::{ConnectionBudget, PeerTransport, TransportError, TransportStatus};

struct SyntheticSigner(SigningKey);

impl PlatformTlsSigner for SyntheticSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        let public =
            PublicKey::from_sec1_bytes(self.0.verifying_key().to_encoded_point(false).as_bytes())
                .map_err(|_| SignerError::Unavailable)?;
        let encoded = public
            .to_public_key_der()
            .map_err(|_| SignerError::Unavailable)?;
        TlsPublicKey::from_spki_der(encoded.as_bytes()).map_err(|_| SignerError::Unavailable)
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

fn signer(seed: u8) -> SyntheticSigner {
    SyntheticSigner(SigningKey::from_slice(&[seed; 32]).expect("synthetic fixture scalar"))
}

pub(crate) fn key(seed: u8) -> TlsPublicKey {
    signer(seed).public_key().unwrap()
}

pub(crate) fn identity(role: EndpointRole, seed: u8) -> TlsIdentity {
    TlsIdentity::from_trusted_host(role, Arc::new(signer(seed))).unwrap()
}

pub(crate) fn pair(now: Instant) -> (PeerTransport, PeerTransport, Arc<ConnectionBudget>) {
    let budget = Arc::new(ConnectionBudget::new(2).unwrap());
    let client = PeerTransport::client(
        Arc::clone(&budget),
        identity(EndpointRole::Client, 1),
        key(2),
        now,
    )
    .unwrap();
    let server = PeerTransport::server(
        Arc::clone(&budget),
        identity(EndpointRole::Server, 2),
        key(1),
        now,
    )
    .unwrap();
    (client, server, budget)
}

struct WireChunk {
    bytes: [u8; MAX_DRAIN_BYTES],
    used: usize,
    end: usize,
}

impl WireChunk {
    fn new() -> Self {
        Self {
            bytes: [0; MAX_DRAIN_BYTES],
            used: 0,
            end: 0,
        }
    }
    fn empty(&self) -> bool {
        self.used == self.end
    }
    fn advance(
        &mut self,
        sender: &mut PeerTransport,
        receiver: &mut PeerTransport,
        chunk_size: usize,
        now: Instant,
    ) -> Result<bool, TransportError> {
        let mut progress = false;
        if self.empty() {
            self.used = 0;
            self.end = sender.drain_tls(&mut self.bytes[..chunk_size], now)?;
            progress |= self.end != 0;
        }
        if !self.empty() {
            let count = receiver.feed_tls(&self.bytes[self.used..self.end], now)?;
            self.used += count;
            progress |= count != 0;
        }
        Ok(progress)
    }
}

/// Test-driver queues are two fixed ciphertext chunks. Completed synthetic
/// frames are collected only for assertions, not as a production receiver model.
type DuplexFrames = (Vec<Vec<u8>>, Vec<Vec<u8>>);

pub(crate) fn pump(
    client: &mut PeerTransport,
    server: &mut PeerTransport,
    now: Instant,
    chunk_size: usize,
) -> Result<DuplexFrames, TransportError> {
    let mut to_server = WireChunk::new();
    let mut to_client = WireChunk::new();
    let mut client_frames = Vec::new();
    let mut server_frames = Vec::new();
    for _ in 0..100_000 {
        let mut progress = to_server.advance(client, server, chunk_size, now)?;
        progress |= to_client.advance(server, client, chunk_size, now)?;
        let before_client = client.pending_counts();
        let before_server = server.pending_counts();
        if let Some(frame) = client.poll_frame(now)? {
            client_frames.push(frame.into_bytes());
            progress = true;
        }
        if let Some(frame) = server.poll_frame(now)? {
            server_frames.push(frame.into_bytes());
            progress = true;
        }
        client.tick(now)?;
        server.tick(now)?;
        let client_counts = client.pending_counts();
        let server_counts = server.pending_counts();
        progress |= client_counts != before_client || server_counts != before_server;
        if to_server.empty()
            && to_client.empty()
            && client.status() == TransportStatus::Ready
            && server.status() == TransportStatus::Ready
            && client_counts == Default::default()
            && server_counts == Default::default()
        {
            return Ok((client_frames, server_frames));
        }
        assert!(progress, "synthetic transport pump made no progress");
    }
    panic!("synthetic transport pump exceeded its fixed iteration bound");
}

/// A separately constructed public Channel is the authenticated adversarial
/// endpoint in these tests; PeerTransport never extracts its inner Channel.
pub(crate) fn raw_pair(now: Instant) -> (Channel, PeerTransport, Arc<ConnectionBudget>) {
    let budget = Arc::new(ConnectionBudget::new(1).unwrap());
    let mut raw = Channel::client(identity(EndpointRole::Client, 1), key(2), now).unwrap();
    let mut peer = PeerTransport::server(
        Arc::clone(&budget),
        identity(EndpointRole::Server, 2),
        key(1),
        now,
    )
    .unwrap();
    for _ in 0..128 {
        let mut bytes = [0; MAX_DRAIN_BYTES];
        let count = raw.drain_tls(&mut bytes, now).unwrap();
        let mut used = 0;
        while used < count {
            let consumed = peer.feed_tls(&bytes[used..count], now).unwrap();
            assert!(consumed > 0);
            used += consumed;
        }
        let count = peer.drain_tls(&mut bytes, now).unwrap();
        let mut used = 0;
        while used < count {
            let consumed = raw.feed_tls(&bytes[used..count], now).unwrap();
            assert!(consumed > 0);
            used += consumed;
        }
        raw.tick(now).unwrap();
        peer.tick(now).unwrap();
        if raw.status() == ChannelStatus::Ready
            && peer.status() == TransportStatus::Ready
            && raw.buffered_tls_bytes() == 0
            && peer.pending_counts().outbound_tls_bytes == 0
        {
            return (raw, peer, budget);
        }
    }
    panic!("raw synthetic handshake exceeded its bound");
}

pub(crate) fn raw_output(raw: &mut Channel, now: Instant) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..8 {
        let mut part = [0; MAX_DRAIN_BYTES];
        let count = raw.drain_tls(&mut part, now).unwrap();
        bytes.extend_from_slice(&part[..count]);
        if raw.buffered_tls_bytes() == 0 {
            return bytes;
        }
    }
    panic!("raw synthetic output exceeded its fixed buffer bound");
}

pub(crate) fn feed_wire(
    peer: &mut PeerTransport,
    bytes: &[u8],
    now: Instant,
) -> Result<(), TransportError> {
    for chunk in bytes.chunks(MAX_DRAIN_BYTES) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let count = peer.feed_tls(rest, now)?;
            assert!(count > 0, "small synthetic raw input must be consumed");
            rest = &rest[count..];
        }
    }
    Ok(())
}

pub(crate) fn send_raw(
    raw: &mut Channel,
    peer: &mut PeerTransport,
    plaintext: &[u8],
    now: Instant,
) -> Result<(), TransportError> {
    assert_eq!(
        raw.write_plaintext(plaintext, now).unwrap(),
        plaintext.len()
    );
    feed_wire(peer, &raw_output(raw, now), now)
}
