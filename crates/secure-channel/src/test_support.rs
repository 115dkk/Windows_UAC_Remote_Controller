// SPDX-License-Identifier: GPL-2.0-or-later
//! EXPLICITLY SYNTHETIC software transport keys. This module is cfg(test) only.
//! These fixtures perform real ECDSA/TLS, not native TPM/Android authentication.
use std::{sync::Arc, time::Instant};

use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};

use crate::{
    CertificateVerifyInput, CertificateVerifySignature, Channel, ChannelError, ChannelStatus,
    EndpointRole, MAX_DRAIN_BYTES, PlatformTlsSigner, SignerError, TlsIdentity, TlsPublicKey,
};

pub(crate) struct SyntheticSigner {
    key: SigningKey,
    public: TlsPublicKey,
    wrong_message: bool,
    high_s: bool,
}

impl SyntheticSigner {
    pub(crate) fn new(seed: u8) -> Self {
        let key = SigningKey::from_slice(&[seed; 32]).expect("valid synthetic fixture scalar");
        let public = p256::PublicKey::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .expect("synthetic public point")
        .to_public_key_der()
        .expect("synthetic public SPKI");
        let public =
            TlsPublicKey::from_spki_der(public.as_bytes()).expect("canonical fixture SPKI");
        Self {
            key,
            public,
            wrong_message: false,
            high_s: false,
        }
    }

    pub(crate) fn with_wrong_message(mut self) -> Self {
        self.wrong_message = true;
        self
    }

    pub(crate) fn with_claimed_public(mut self, public: TlsPublicKey) -> Self {
        self.public = public;
        self
    }

    pub(crate) fn with_high_s(mut self) -> Self {
        self.high_s = true;
        self
    }
}

impl PlatformTlsSigner for SyntheticSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        Ok(self.public.clone())
    }

    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        let mut message = input.as_bytes().to_vec();
        if self.wrong_message {
            // Change client/server context instead of signing the supplied role.
            let other = match input.role() {
                EndpointRole::Client => b"server",
                EndpointRole::Server => b"client",
            };
            message[73..79].copy_from_slice(other);
        }
        let mut signature: Signature = self.key.sign(&message);
        if self.high_s {
            let low = signature.normalize_s().unwrap_or(signature);
            signature = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes())
                .map_err(|_| SignerError::InvalidSignature)?;
        }
        CertificateVerifySignature::from_der(signature.to_der().as_bytes())
            .map_err(|_| SignerError::InvalidSignature)
    }
}

pub(crate) fn key(seed: u8) -> TlsPublicKey {
    SyntheticSigner::new(seed)
        .public_key()
        .expect("synthetic public key")
}

pub(crate) fn identity(role: EndpointRole, seed: u8) -> TlsIdentity {
    TlsIdentity::from_trusted_host(role, Arc::new(SyntheticSigner::new(seed)))
        .expect("synthetic identity")
}

pub(crate) fn pair(now: Instant) -> (Channel, Channel) {
    (
        Channel::client(identity(EndpointRole::Client, 1), key(2), now).expect("client"),
        Channel::server(identity(EndpointRole::Server, 2), key(1), now).expect("server"),
    )
}

pub(crate) fn transfer(
    from: &mut Channel,
    to: &mut Channel,
    now: Instant,
    chunk: usize,
) -> Result<usize, ChannelError> {
    let mut bytes = [0; MAX_DRAIN_BYTES];
    let count = from.drain_tls(&mut bytes[..chunk], now)?;
    let mut consumed = 0;
    while consumed < count {
        let next = to.feed_tls(&bytes[consumed..count], now)?;
        if next == 0 {
            return Err(ChannelError::Backpressure);
        }
        consumed += next;
    }
    Ok(count)
}

pub(crate) fn handshake(
    client: &mut Channel,
    server: &mut Channel,
    now: Instant,
    chunk: usize,
) -> Result<(), ChannelError> {
    for _ in 0..2048 {
        let sent = transfer(client, server, now, chunk)?;
        let received = transfer(server, client, now, chunk)?;
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
            "synthetic handshake did not make bounded progress"
        );
    }
    panic!("synthetic handshake exceeded byte-pump bound");
}

pub(crate) fn drain_all(channel: &mut Channel, now: Instant) -> Vec<u8> {
    let mut result = Vec::new();
    for _ in 0..8 {
        let mut bytes = [0; MAX_DRAIN_BYTES];
        let count = channel.drain_tls(&mut bytes, now).expect("drain TLS");
        result.extend_from_slice(&bytes[..count]);
        if channel.buffered_tls_bytes() == 0 {
            return result;
        }
    }
    panic!("synthetic drain exceeded channel buffer bound");
}

pub(crate) fn frame(role: EndpointRole, hash_size: usize) -> Vec<u8> {
    let mut message = vec![0x20; 64];
    message.extend_from_slice(match role {
        EndpointRole::Client => b"TLS 1.3, client CertificateVerify",
        EndpointRole::Server => b"TLS 1.3, server CertificateVerify",
    });
    message.push(0);
    message.extend(vec![0x42; hash_size]);
    message
}
