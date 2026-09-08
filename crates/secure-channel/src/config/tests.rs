// SPDX-License-Identifier: GPL-2.0-or-later
//! Private adversarial fixtures. Production configuration is never injectable.
use std::{
    io::{Read, Write},
    sync::Arc,
    time::Instant,
};

use rustls::{
    ClientConnection, ServerConnection, SignatureScheme, client::ResolvesClientCert,
    pki_types::ServerName, sign::CertifiedKey,
};

use super::{PinnedPeer, client_config, server_config};
use crate::{
    Channel, ChannelError, ChannelStatus, EndpointRole, MAX_INGRESS_BYTES, PlaintextRead,
    READY_PREFACE,
    identity::BoundSigningKey,
    test_support::{identity, key},
};

#[derive(Debug)]
struct MissingClientKey;
impl ResolvesClientCert for MissingClientKey {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

fn drive_raw_client(
    client: &mut ClientConnection,
    server: &mut Channel,
    now: Instant,
) -> Result<(), ChannelError> {
    for _ in 0..32 {
        let mut bytes = [0; MAX_INGRESS_BYTES];
        let count = client.write_tls(&mut &mut bytes[..]).unwrap();
        if count > 0 {
            assert_eq!(server.feed_tls(&bytes[..count], now)?, count);
        }
        let count = server.drain_tls(&mut bytes, now)?;
        if count > 0 {
            assert_eq!(client.read_tls(&mut &bytes[..count]).unwrap(), count);
            client
                .process_new_packets()
                .map_err(|_| ChannelError::TlsRejected)?;
        }
        server.tick(now)?;
        if !client.is_handshaking() && server.status() == ChannelStatus::Ready {
            return Ok(());
        }
    }
    panic!("raw client fixture exhausted its handshake bound");
}

fn raw_server_pair(now: Instant) -> (Channel, ServerConnection) {
    let mut client = Channel::client(identity(EndpointRole::Client, 1), key(2), now).unwrap();
    let mut server = ServerConnection::new(Arc::new(
        server_config(identity(EndpointRole::Server, 2), key(1)).unwrap(),
    ))
    .unwrap();
    for _ in 0..32 {
        let mut bytes = [0; MAX_INGRESS_BYTES];
        let count = client.drain_tls(&mut bytes, now).unwrap();
        if count > 0 {
            assert_eq!(server.read_tls(&mut &bytes[..count]).unwrap(), count);
            server.process_new_packets().unwrap();
        }
        let count = server.write_tls(&mut &mut bytes[..]).unwrap();
        if count > 0 {
            assert_eq!(client.feed_tls(&bytes[..count], now).unwrap(), count);
        }
        client.tick(now).unwrap();
        if !server.is_handshaking()
            && client.status() == ChannelStatus::AwaitingReadiness
            && !server.wants_write()
            && client.buffered_tls_bytes() == 0
        {
            return (client, server);
        }
    }
    panic!("raw server fixture exhausted its handshake bound");
}

fn send_raw_plaintext(
    server: &mut ServerConnection,
    client: &mut Channel,
    bytes: &[u8],
    now: Instant,
) -> Result<usize, ChannelError> {
    server.writer().write_all(bytes).unwrap();
    let mut ciphertext = [0; MAX_INGRESS_BYTES];
    let count = server.write_tls(&mut &mut ciphertext[..]).unwrap();
    client.feed_tls(&ciphertext[..count], now)
}

#[test]
fn missing_client_key_cannot_make_pc_ready() {
    let now = Instant::now();
    let mut config = client_config(identity(EndpointRole::Client, 1), key(2)).unwrap();
    config.client_auth_cert_resolver = Arc::new(MissingClientKey);
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("wuac.invalid").unwrap(),
    )
    .unwrap();
    let mut server = Channel::server(identity(EndpointRole::Server, 2), key(1), now).unwrap();
    assert!(drive_raw_client(&mut client, &mut server, now).is_err());
    assert_ne!(server.status(), ChannelStatus::Ready);
    assert_eq!(server.buffered_plaintext_bytes(), 0);
}

#[test]
fn absent_or_wrong_alpn_never_releases_application_bytes() {
    for alpn in [Vec::new(), vec![b"unrelated-protocol/1".to_vec()]] {
        let now = Instant::now();
        let mut config = client_config(identity(EndpointRole::Client, 1), key(2)).unwrap();
        config.alpn_protocols = alpn;
        let mut client = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("wuac.invalid").unwrap(),
        )
        .unwrap();
        let mut server = Channel::server(identity(EndpointRole::Server, 2), key(1), now).unwrap();
        assert!(drive_raw_client(&mut client, &mut server, now).is_err());
        assert_ne!(server.status(), ChannelStatus::Ready);
        assert!(server.write_plaintext(b"forbidden", now).is_err());
    }
}

#[test]
fn encrypted_readiness_preface_is_consumed_across_separate_tls_records() {
    let now = Instant::now();
    let (mut client, mut server) = raw_server_pair(now);
    send_raw_plaintext(&mut server, &mut client, &READY_PREFACE[..5], now).unwrap();
    assert_eq!(
        client.read_plaintext(&mut [0; 32], now),
        Err(ChannelError::NotReady)
    );
    send_raw_plaintext(&mut server, &mut client, &READY_PREFACE[5..], now).unwrap();
    client.tick(now).unwrap();
    assert_eq!(client.status(), ChannelStatus::Ready);
    assert_eq!(
        client.read_plaintext(&mut [0; 32], now),
        Ok(PlaintextRead::WouldBlock)
    );
    send_raw_plaintext(&mut server, &mut client, b"actual application bytes", now).unwrap();
    let mut bytes = [0; 64];
    assert_eq!(
        client.read_plaintext(&mut bytes, now),
        Ok(PlaintextRead::Data(24))
    );
    assert_eq!(&bytes[..24], b"actual application bytes");
}

#[test]
fn incorrect_authenticated_readiness_preface_fails_instead_of_becoming_app_data() {
    let now = Instant::now();
    let (mut client, mut server) = raw_server_pair(now);
    assert_eq!(
        send_raw_plaintext(&mut server, &mut client, b"WRONG-PREFACE", now),
        Err(ChannelError::ReadinessRejected)
    );
    assert_eq!(client.status(), ChannelStatus::Failed);
    assert_eq!(client.buffered_plaintext_bytes(), 0);
}

#[test]
fn peer_close_before_readiness_is_not_a_successful_handshake() {
    let now = Instant::now();
    let (mut client, mut server) = raw_server_pair(now);
    server.send_close_notify();
    let mut bytes = [0; MAX_INGRESS_BYTES];
    let count = server.write_tls(&mut &mut bytes[..]).unwrap();
    assert_eq!(
        client.feed_tls(&bytes[..count], now),
        Err(ChannelError::ReadinessRejected)
    );
}

#[test]
fn coalesced_complete_preface_payload_and_close_preserve_authenticated_data() {
    for split in [0, 7, READY_PREFACE.len()] {
        let now = Instant::now();
        let (mut client, mut server) = raw_server_pair(now);
        server.writer().write_all(&READY_PREFACE[..split]).unwrap();
        server.writer().write_all(&READY_PREFACE[split..]).unwrap();
        server.writer().write_all(b"synthetic final reply").unwrap();
        server.send_close_notify();
        let mut coalesced = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut coalesced).unwrap();
        }
        assert!(coalesced.len() <= MAX_INGRESS_BYTES);
        assert_eq!(client.feed_tls(&coalesced, now), Ok(coalesced.len()));
        client.tick(now).unwrap();
        assert_eq!(client.status(), ChannelStatus::PeerClosed);
        let mut out = [0; 128];
        assert_eq!(
            client.read_plaintext(&mut out, now),
            Ok(PlaintextRead::Data(21))
        );
        assert_eq!(&out[..21], b"synthetic final reply");
        assert_eq!(
            client.read_plaintext(&mut out, now),
            Ok(PlaintextRead::PeerClosed)
        );
    }
}

#[test]
fn coalesced_incomplete_preface_and_close_are_rejected() {
    let now = Instant::now();
    let (mut client, mut server) = raw_server_pair(now);
    server.writer().write_all(&READY_PREFACE[..7]).unwrap();
    server.send_close_notify();
    let mut coalesced = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut coalesced).unwrap();
    }
    assert_eq!(
        client.feed_tls(&coalesced, now),
        Err(ChannelError::ReadinessRejected)
    );
    assert_eq!(client.buffered_plaintext_bytes(), 0);
}

#[test]
fn raw_key_flags_signature_scheme_and_resumption_configuration_are_explicit() {
    let client = client_config(identity(EndpointRole::Client, 1), key(2)).unwrap();
    let server = server_config(identity(EndpointRole::Server, 2), key(1)).unwrap();
    assert!(client.client_auth_cert_resolver.only_raw_public_keys());
    assert!(server.cert_resolver.only_raw_public_keys());
    assert!(!client.enable_early_data);
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.send_half_rtt_data);
    assert_eq!(server.send_tls13_tickets, 0);
    assert_eq!(server.max_tls13_tickets, 0);
    assert!(!server.ticketer.enabled());
    assert!(server.ticketer.encrypt(b"test ticket").is_none());
    assert!(server.ticketer.decrypt(b"test ticket").is_none());
    assert!(!client.enable_secret_extraction && !server.enable_secret_extraction);
    assert!(!client.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
    assert!(!server.key_log.will_log("SERVER_TRAFFIC_SECRET_0"));
    let verifier = PinnedPeer(key(1));
    assert!(rustls::server::danger::ClientCertVerifier::client_auth_mandatory(&verifier));
    assert!(rustls::server::danger::ClientCertVerifier::requires_raw_public_keys(&verifier));
    assert!(rustls::client::danger::ServerCertVerifier::requires_raw_public_keys(&verifier));
    assert_eq!(
        rustls::client::danger::ServerCertVerifier::supported_verify_schemes(&verifier),
        [SignatureScheme::ECDSA_NISTP256_SHA256]
    );
    let signer = BoundSigningKey(Arc::new(identity(EndpointRole::Server, 2)));
    assert!(
        rustls::sign::SigningKey::choose_scheme(
            &signer,
            &[
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256
            ]
        )
        .is_none()
    );
}

#[test]
fn raw_key_verifier_rejects_a_chain_even_when_the_first_key_is_pinned() {
    let peer = key(1);
    let verifier = PinnedPeer(peer.clone());
    let cert = rustls::pki_types::CertificateDer::from(peer.as_spki_der());
    assert!(verifier.check_key(&cert, &[]).is_ok());
    assert!(
        verifier
            .check_key(&cert, std::slice::from_ref(&cert))
            .is_err()
    );
}

#[test]
fn tls12_version_downgrade_in_client_hello_is_rejected() {
    let now = Instant::now();
    let mut config = client_config(identity(EndpointRole::Client, 1), key(2)).unwrap();
    config.enable_sni = false;
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("wuac.invalid").unwrap(),
    )
    .unwrap();
    let mut bytes = [0; MAX_INGRESS_BYTES];
    let count = client.write_tls(&mut &mut bytes[..]).unwrap();
    // supported_versions extension: one offered version, TLS 1.3. Preserve all
    // lengths while replacing 0x0304 by TLS 1.2 (0x0303) in the actual ClientHello.
    let pattern = [0, 43, 0, 3, 2, 3, 4];
    let positions: Vec<_> = bytes[..count]
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(position, window)| (window == pattern).then_some(position))
        .collect();
    assert_eq!(positions.len(), 1);
    bytes[positions[0] + pattern.len() - 1] = 3;
    let mut server = Channel::server(identity(EndpointRole::Server, 2), key(1), now).unwrap();
    assert_eq!(
        server.feed_tls(&bytes[..count], now),
        Err(ChannelError::TlsRejected)
    );
    assert_ne!(server.status(), ChannelStatus::Ready);
}

#[test]
fn authenticated_peer_close_allows_already_buffered_plaintext_to_be_drained() {
    let now = Instant::now();
    let (mut client, mut server) = raw_server_pair(now);
    send_raw_plaintext(&mut server, &mut client, READY_PREFACE, now).unwrap();
    client.tick(now).unwrap();
    server
        .writer()
        .write_all(b"last authenticated bytes")
        .unwrap();
    server.send_close_notify();
    let mut ciphertext = [0; MAX_INGRESS_BYTES];
    let count = server.write_tls(&mut &mut ciphertext[..]).unwrap();
    client.feed_tls(&ciphertext[..count], now).unwrap();
    let mut output = [0; 64];
    assert_eq!(
        client.read_plaintext(&mut output, now),
        Ok(PlaintextRead::Data(24))
    );
    assert_eq!(&output[..24], b"last authenticated bytes");
    assert_eq!(
        client.read_plaintext(&mut output, now),
        Ok(PlaintextRead::PeerClosed)
    );
    let mut raw = [0; 1];
    assert!(server.reader().read(&mut raw).is_err());
}
