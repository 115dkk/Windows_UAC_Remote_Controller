// SPDX-License-Identifier: GPL-2.0-or-later
//! Real Rustls byte-pump tests with explicitly synthetic software identities.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};

use crate::{
    CertificateVerifyInput, CertificateVerifySignature, Channel, ChannelError, ChannelStatus,
    EndpointRole, HANDSHAKE_TIMEOUT, MAX_BUFFERED_BYTES, MAX_DRAIN_BYTES, MAX_INGRESS_BYTES,
    MAX_PLAINTEXT_WRITE_BYTES, PlaintextRead, SignerError, TlsIdentity, TlsPublicKey,
    identity::BoundSigningKey, test_support::*,
};

#[test]
fn real_mutual_handshake_and_encrypted_bidirectional_application_bytes() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    let payload = b"synthetic phone application payload";
    assert_eq!(client.write_plaintext(payload, now), Ok(payload.len()));
    let ciphertext = drain_all(&mut client, now);
    assert!(
        !ciphertext
            .windows(payload.len())
            .any(|window| window == payload)
    );
    assert_eq!(server.feed_tls(&ciphertext, now), Ok(ciphertext.len()));
    let mut plaintext = [0; 128];
    assert_eq!(
        server.read_plaintext(&mut plaintext, now),
        Ok(PlaintextRead::Data(payload.len()))
    );
    assert_eq!(&plaintext[..payload.len()], payload);
    let payload = b"synthetic PC application payload";
    assert_eq!(server.write_plaintext(payload, now), Ok(payload.len()));
    let ciphertext = drain_all(&mut server, now);
    assert!(
        !ciphertext
            .windows(payload.len())
            .any(|window| window == payload)
    );
    client.feed_tls(&ciphertext, now).unwrap();
    let mut plaintext = [0; 128];
    assert_eq!(
        client.read_plaintext(&mut plaintext, now),
        Ok(PlaintextRead::Data(payload.len()))
    );
    assert_eq!(&plaintext[..payload.len()], payload);
}

#[test]
fn neither_tls_local_completion_nor_an_unconfirmed_preface_releases_application_bytes() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    assert_eq!(
        client.write_plaintext(b"no early bytes", now),
        Err(ChannelError::NotReady)
    );
    assert_eq!(
        server.write_plaintext(b"no half RTT bytes", now),
        Err(ChannelError::NotReady)
    );
    assert_eq!(
        client.read_plaintext(&mut [0; 16], now),
        Err(ChannelError::NotReady)
    );
    transfer(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    transfer(&mut server, &mut client, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(client.status(), ChannelStatus::AwaitingReadiness);
    assert_eq!(
        client.write_plaintext(b"still too early", now),
        Err(ChannelError::NotReady)
    );
    // PC can authenticate the client's Finished only after this next flight.
    transfer(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(
        client.read_plaintext(&mut [0; 16], now),
        Err(ChannelError::NotReady)
    );
    handshake(&mut client, &mut server, now, 7).unwrap();
    assert_eq!(
        client.read_plaintext(&mut [0; 64], now),
        Ok(PlaintextRead::WouldBlock)
    );
}

#[test]
fn fragmented_records_and_small_output_buffers_complete_without_leaking_preface() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, 3).unwrap();
    client.write_plaintext(b"abcdef", now).unwrap();
    let ciphertext = drain_all(&mut client, now);
    for byte in ciphertext {
        assert_eq!(server.feed_tls(&[byte], now), Ok(1));
    }
    let mut result = Vec::new();
    for _ in 0..6 {
        let mut byte = [0];
        assert_eq!(
            server.read_plaintext(&mut byte, now),
            Ok(PlaintextRead::Data(1))
        );
        result.push(byte[0]);
    }
    assert_eq!(result, b"abcdef");
}

#[test]
fn wrong_server_pin_fails_closed() {
    let now = Instant::now();
    let mut client = Channel::client(identity(EndpointRole::Client, 1), key(3), now).unwrap();
    let mut server = Channel::server(identity(EndpointRole::Server, 2), key(1), now).unwrap();
    assert_eq!(
        handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES),
        Err(ChannelError::TlsRejected)
    );
    assert_eq!(client.status(), ChannelStatus::Failed);
    assert_eq!(
        client.write_plaintext(b"forbidden", now),
        Err(ChannelError::Failed)
    );
}

#[test]
fn wrong_client_pin_produces_no_readiness_ack_and_no_client_application_release() {
    let now = Instant::now();
    let mut client = Channel::client(identity(EndpointRole::Client, 1), key(2), now).unwrap();
    let mut server = Channel::server(identity(EndpointRole::Server, 2), key(3), now).unwrap();
    assert_eq!(
        handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES),
        Err(ChannelError::TlsRejected)
    );
    assert_eq!(server.status(), ChannelStatus::Failed);
    assert_eq!(server.buffered_tls_bytes(), 0);
    assert_eq!(client.status(), ChannelStatus::AwaitingReadiness);
    assert_eq!(
        client.write_plaintext(b"forbidden", now),
        Err(ChannelError::NotReady)
    );
    assert_eq!(
        client.read_plaintext(&mut [0; 32], now),
        Err(ChannelError::NotReady)
    );
}

#[test]
fn malformed_and_noncanonical_public_keys_are_rejected() {
    let valid = key(1);
    assert!(TlsPublicKey::from_spki_der(valid.as_spki_der()).is_ok());
    for length in [0, 1, 90, 92, 2048] {
        assert!(TlsPublicKey::from_spki_der(&vec![0; length]).is_err());
    }
    let mut trailing = valid.as_spki_der().to_vec();
    trailing.push(0);
    assert!(TlsPublicKey::from_spki_der(&trailing).is_err());
    let mut malformed = valid.as_spki_der().to_vec();
    malformed[0] = 0x31;
    assert!(TlsPublicKey::from_spki_der(&malformed).is_err());
    let mut wrong_curve = valid.as_spki_der().to_vec();
    wrong_curve[22] ^= 1;
    assert!(TlsPublicKey::from_spki_der(&wrong_curve).is_err());
    let mut invalid_point = valid.as_spki_der().to_vec();
    invalid_point[26..].fill(0);
    assert!(TlsPublicKey::from_spki_der(&invalid_point).is_err());
    // Compressed SEC1 is mathematically valid, but not the enrolled canonical
    // uncompressed SPKI form accepted by this protocol.
    let software = SigningKey::from_slice(&[1; 32]).unwrap();
    let compressed = software.verifying_key().to_encoded_point(true);
    let mut compressed_spki = valid.as_spki_der()[..26].to_vec();
    compressed_spki[1] = 57;
    compressed_spki[24] = 34;
    compressed_spki.extend_from_slice(compressed.as_bytes());
    assert!(TlsPublicKey::from_spki_der(&compressed_spki).is_err());
}

#[test]
fn malformed_der_signatures_are_rejected_and_real_signature_is_verified() {
    for invalid in [
        vec![],
        vec![0; 64],
        vec![0; 73],
        vec![0x30, 6, 2, 1, 0, 2, 1, 0],
    ] {
        assert!(CertificateVerifySignature::from_der(&invalid).is_err());
    }
    let signing = SigningKey::from_slice(&[1; 32]).unwrap();
    let message = frame(EndpointRole::Client, 32);
    let signature: Signature = signing.sign(&message);
    let mut trailing = signature.to_der().as_bytes().to_vec();
    trailing.push(0);
    assert!(CertificateVerifySignature::from_der(&trailing).is_err());
    let signature = CertificateVerifySignature::from_der(signature.to_der().as_bytes()).unwrap();
    assert!(key(1).verify(&message, &signature));
    assert!(!key(2).verify(&message, &signature));
}

#[test]
fn certificate_verify_input_accepts_only_exact_role_domain_and_supported_hash_lengths() {
    for role in [EndpointRole::Client, EndpointRole::Server] {
        for length in [32, 48] {
            let message = frame(role, length);
            let input = CertificateVerifyInput::parse(role, &message).unwrap();
            assert_eq!(input.as_bytes(), message);
            assert_eq!(input.role(), role);
            let other = if role == EndpointRole::Client {
                EndpointRole::Server
            } else {
                EndpointRole::Client
            };
            assert_eq!(
                CertificateVerifyInput::parse(other, &message).err(),
                Some(SignerError::InvalidMessage)
            );
        }
    }
    for length in [0, 31, 33, 47, 49, 4096] {
        assert!(
            CertificateVerifyInput::parse(
                EndpointRole::Client,
                &frame(EndpointRole::Client, length)
            )
            .is_err()
        );
    }
    let mut malformed = frame(EndpointRole::Client, 32);
    malformed[0] = 0;
    assert!(CertificateVerifyInput::parse(EndpointRole::Client, &malformed).is_err());
    assert!(
        CertificateVerifyInput::parse(EndpointRole::Client, b"arbitrary approval message").is_err()
    );
}

#[test]
fn wrong_role_identity_and_returned_signer_signature_are_rejected() {
    let now = Instant::now();
    assert_eq!(
        Channel::client(identity(EndpointRole::Server, 1), key(2), now).err(),
        Some(ChannelError::WrongIdentityRole)
    );
    assert_eq!(
        Channel::server(identity(EndpointRole::Client, 2), key(1), now).err(),
        Some(ChannelError::WrongIdentityRole)
    );
    assert_eq!(
        Channel::client(identity(EndpointRole::Client, 1), key(1), now).err(),
        Some(ChannelError::KeyReuse)
    );
    for signer in [
        SyntheticSigner::new(1).with_wrong_message(),
        SyntheticSigner::new(4).with_claimed_public(key(1)),
    ] {
        let identity =
            TlsIdentity::from_trusted_host(EndpointRole::Client, Arc::new(signer)).unwrap();
        let signing_key = BoundSigningKey(Arc::new(identity));
        let message = frame(EndpointRole::Client, 32);
        assert!(rustls::sign::Signer::sign(&signing_key, &message).is_err());
        assert!(
            rustls::sign::Signer::sign(&signing_key, &frame(EndpointRole::Server, 32)).is_err()
        );
    }
}

#[test]
fn real_handshake_rejects_platform_signatures_for_the_wrong_key_or_role() {
    for signer in [
        SyntheticSigner::new(1).with_wrong_message(),
        SyntheticSigner::new(4).with_claimed_public(key(1)),
    ] {
        let now = Instant::now();
        let client_identity =
            TlsIdentity::from_trusted_host(EndpointRole::Client, Arc::new(signer)).unwrap();
        let mut client = Channel::client(client_identity, key(2), now).unwrap();
        let mut server = Channel::server(identity(EndpointRole::Server, 2), key(1), now).unwrap();
        assert_eq!(
            handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES),
            Err(ChannelError::TlsRejected)
        );
        assert_eq!(client.status(), ChannelStatus::Failed);
        assert_ne!(server.status(), ChannelStatus::Ready);
    }
}

#[test]
fn legitimate_high_s_native_der_signatures_work_in_both_handshake_directions() {
    let now = Instant::now();
    let signing = SigningKey::from_slice(&[1; 32]).unwrap();
    let message = frame(EndpointRole::Client, 32);
    let signature: Signature = signing.sign(&message);
    let low = signature.normalize_s().unwrap_or(signature);
    let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    assert!(
        high.normalize_s().is_some(),
        "fixture must actually be high-S"
    );
    let der = CertificateVerifySignature::from_der(high.to_der().as_bytes()).unwrap();
    assert!(key(1).verify(&message, &der));
    assert!(!key(2).verify(&message, &der));
    let client_identity = TlsIdentity::from_trusted_host(
        EndpointRole::Client,
        Arc::new(SyntheticSigner::new(1).with_high_s()),
    )
    .unwrap();
    let server_identity = TlsIdentity::from_trusted_host(
        EndpointRole::Server,
        Arc::new(SyntheticSigner::new(2).with_high_s()),
    )
    .unwrap();
    let mut client = Channel::client(client_identity, key(2), now).unwrap();
    let mut server = Channel::server(server_identity, key(1), now).unwrap();
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(client.status(), ChannelStatus::Ready);
    assert_eq!(server.status(), ChannelStatus::Ready);
}

#[test]
fn tampering_and_replayed_ciphertext_fail_and_latch() {
    for replay in [false, true] {
        let now = Instant::now();
        let (mut client, mut server) = pair(now);
        handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
        client
            .write_plaintext(b"synthetic authenticated payload", now)
            .unwrap();
        let mut ciphertext = drain_all(&mut client, now);
        if replay {
            server.feed_tls(&ciphertext, now).unwrap();
            server.read_plaintext(&mut [0; 128], now).unwrap();
        } else {
            let last = ciphertext.last_mut().unwrap();
            *last ^= 0x01;
        }
        assert_eq!(
            server.feed_tls(&ciphertext, now),
            Err(ChannelError::TlsRejected)
        );
        assert_eq!(server.status(), ChannelStatus::Failed);
        assert_eq!(server.buffered_plaintext_bytes(), 0);
        assert_eq!(
            server.read_plaintext(&mut [0; 128], now),
            Err(ChannelError::Failed)
        );
        assert_eq!(server.feed_tls(&[], now), Err(ChannelError::Failed));
        assert_eq!(
            server.drain_tls(&mut [0; 16], now),
            Err(ChannelError::Failed)
        );
        assert_eq!(server.close(now), Err(ChannelError::Failed));
    }
}

#[test]
fn queue_limits_create_backpressure_and_partial_io_without_unbounded_buffers() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(
        client.write_plaintext(&vec![0; MAX_PLAINTEXT_WRITE_BYTES + 1], now),
        Err(ChannelError::PlaintextTooLarge)
    );
    let mut wrote = 0;
    let mut stopped = false;
    for _ in 0..8 {
        let count = client
            .write_plaintext(&[0x55; MAX_PLAINTEXT_WRITE_BYTES], now)
            .unwrap();
        assert!(client.buffered_tls_bytes() <= MAX_BUFFERED_BYTES);
        wrote += count;
        if count == 0 {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    assert!(wrote <= MAX_BUFFERED_BYTES);
    assert_eq!(
        client.close_gracefully(now),
        Err(ChannelError::Backpressure)
    );
    let mut buffer = vec![0; MAX_BUFFERED_BYTES];
    assert!(client.drain_tls(&mut buffer, now).unwrap() <= MAX_DRAIN_BYTES);
    assert_eq!(
        client.feed_tls(&vec![0; MAX_INGRESS_BYTES + 1], now),
        Err(ChannelError::IngressTooLarge)
    );
    assert_eq!(client.status(), ChannelStatus::Failed);
}

#[test]
fn ciphertext_from_an_earlier_session_cannot_be_replayed_after_fresh_handshake() {
    let now = Instant::now();
    let (mut old_client, mut old_server) = pair(now);
    handshake(&mut old_client, &mut old_server, now, MAX_DRAIN_BYTES).unwrap();
    old_client
        .write_plaintext(b"old synthetic session payload", now)
        .unwrap();
    let previous_record = drain_all(&mut old_client, now);
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(
        server.feed_tls(&previous_record, now),
        Err(ChannelError::TlsRejected)
    );
    assert_eq!(server.buffered_plaintext_bytes(), 0);
}

#[test]
fn incoming_plaintext_backpressure_retains_the_callers_unconsumed_ciphertext() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client
        .write_plaintext(&[0x77; MAX_PLAINTEXT_WRITE_BYTES], now)
        .unwrap();
    let encrypted = drain_all(&mut client, now);
    for chunk in encrypted.chunks(MAX_INGRESS_BYTES) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let consumed = server.feed_tls(rest, now).unwrap();
            assert!(consumed > 0);
            rest = &rest[consumed..];
        }
    }
    assert!(server.buffered_plaintext_bytes() <= MAX_BUFFERED_BYTES);
    client.write_plaintext(b"next record", now).unwrap();
    let next = drain_all(&mut client, now);
    // Rustls considers its receive queue full only AFTER exceeding its soft
    // plaintext threshold. Exactly one 16-KiB record is not yet backpressure.
    assert_eq!(server.feed_tls(&next, now), Ok(next.len()));
    client.write_plaintext(b"after backpressure", now).unwrap();
    let retained = drain_all(&mut client, now);
    assert_eq!(server.feed_tls(&retained, now), Ok(0));
    let mut plain = [0; MAX_PLAINTEXT_WRITE_BYTES];
    assert_eq!(
        server.read_plaintext(&mut plain, now),
        Ok(PlaintextRead::Data(MAX_PLAINTEXT_WRITE_BYTES))
    );
    assert!(plain.iter().all(|byte| *byte == 0x77));
    assert_eq!(server.feed_tls(&retained, now), Ok(retained.len()));
    let mut remaining = Vec::new();
    while let PlaintextRead::Data(count) = server.read_plaintext(&mut plain, now).unwrap() {
        remaining.extend_from_slice(&plain[..count]);
    }
    assert_eq!(remaining, b"next recordafter backpressure");
}

#[test]
fn explicit_abort_drops_queued_data_and_clean_peer_close_differs_from_truncation() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client.close_gracefully(now).unwrap();
    let close_notify = drain_all(&mut client, now);
    server.feed_tls(&close_notify, now).unwrap();
    assert_eq!(server.status(), ChannelStatus::PeerClosed);
    assert_eq!(
        server.read_plaintext(&mut [0; 1], now),
        Ok(PlaintextRead::PeerClosed)
    );
    assert_eq!(
        server.write_plaintext(b"no more data", now),
        Err(ChannelError::PeerClosed)
    );
    assert_eq!(
        server.transport_eof(now),
        Ok(crate::EofDisposition::AuthenticatedPeerClose)
    );
    assert_eq!(
        client.write_plaintext(b"closed", now),
        Err(ChannelError::Closed)
    );

    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client
        .write_plaintext(b"must not flush on revocation", now)
        .unwrap();
    client.close(now).unwrap();
    assert_eq!(
        client.transport_eof(now),
        Ok(crate::EofDisposition::LocalAlreadyClosed)
    );
    assert_eq!(client.buffered_tls_bytes(), 0);
    assert_eq!(client.drain_tls(&mut [0; 64], now), Ok(0));
    assert_eq!(server.transport_eof(now), Err(ChannelError::Truncated));
    assert_eq!(server.tick(now), Err(ChannelError::Failed));
}

#[test]
fn trusted_clock_regression_and_inclusive_handshake_deadline_are_fatal() {
    let now = Instant::now();
    let (mut client, _) = pair(now);
    assert_eq!(client.feed_tls(&[], now), Ok(0));
    assert_eq!(
        client.tick(now + HANDSHAKE_TIMEOUT),
        Err(ChannelError::HandshakeExpired)
    );
    assert_eq!(client.tick(now), Err(ChannelError::Failed));
    let (mut client, mut server) = pair(now);
    handshake(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client.tick(now + Duration::from_secs(20)).unwrap();
    assert_eq!(
        client.write_plaintext(b"clock regression", now),
        Err(ChannelError::ClockWentBackwards)
    );
}

#[test]
fn readiness_wait_remains_inside_handshake_deadline() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    transfer(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    transfer(&mut server, &mut client, now, MAX_DRAIN_BYTES).unwrap();
    assert_eq!(client.status(), ChannelStatus::AwaitingReadiness);
    assert_eq!(
        client.tick(now + HANDSHAKE_TIMEOUT),
        Err(ChannelError::HandshakeExpired)
    );
}

#[test]
fn fresh_time_after_handshake_work_is_checked_before_ready_output_or_app_release() {
    let now = Instant::now();
    let (mut client, mut server) = pair(now);
    transfer(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    transfer(&mut server, &mut client, now, MAX_DRAIN_BYTES).unwrap();
    transfer(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    // Server has queued the preface, but must not release it when the trusted
    // time sampled after potentially blocking handshake work is too late.
    assert_eq!(
        server.drain_tls(&mut [0; 64], now + HANDSHAKE_TIMEOUT),
        Err(ChannelError::HandshakeExpired)
    );
    assert_eq!(server.buffered_tls_bytes(), 0);
    assert_eq!(
        client.write_plaintext(b"no unconfirmed release", now),
        Err(ChannelError::NotReady)
    );
}

#[test]
fn debug_output_redacts_transport_keys_and_signing_inputs() {
    let identity = identity(EndpointRole::Client, 1);
    let public = format!("{:?}", identity.public_key());
    assert_eq!(public, "TlsPublicKey([redacted])");
    assert!(!format!("{identity:?}").contains("signer"));
    let message = frame(EndpointRole::Client, 32);
    assert!(
        !format!(
            "{:?}",
            CertificateVerifyInput::parse(EndpointRole::Client, &message).unwrap()
        )
        .contains("66")
    );
    let signing = SigningKey::from_slice(&[1; 32]).unwrap();
    assert_eq!(
        p256::PublicKey::from_sec1_bytes(
            signing.verifying_key().to_encoded_point(false).as_bytes()
        )
        .unwrap()
        .to_public_key_der()
        .unwrap()
        .as_bytes(),
        identity.public_key().as_spki_der()
    );
}
