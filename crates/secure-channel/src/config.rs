// SPDX-License-Identifier: GPL-2.0-or-later
use std::{fmt, sync::Arc};

use rustls::{
    ClientConfig, ClientConnection, Connection, DigitallySignedStruct, DistinguishedName,
    Error as TlsError, NoKeyLog, ServerConfig, ServerConnection, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys, Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::{
        AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage, ProducesTickets,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
};

use crate::{
    ALPN, CertificateVerifySignature, ChannelError, EndpointRole, TlsIdentity, TlsPublicKey,
    identity::{BoundSigningKey, CertificateVerifyInput},
};

#[cfg(test)]
mod tests;

const TRANSPORT_REJECTED: &str = "transport peer authentication rejected";

pub(crate) fn client(
    identity: TlsIdentity,
    peer: TlsPublicKey,
) -> Result<Connection, ChannelError> {
    let config = client_config(identity, peer)?;
    // A syntactic placeholder, never a DNS/PKI trust anchor. SNI is disabled;
    // exact enrolled SPKI bytes are the sole peer identity in this protocol.
    let name = ServerName::try_from("wuac.invalid").map_err(|_| ChannelError::Configuration)?;
    ClientConnection::new(Arc::new(config), name)
        .map(Connection::Client)
        .map_err(|_| ChannelError::Configuration)
}

pub(crate) fn server(
    identity: TlsIdentity,
    peer: TlsPublicKey,
) -> Result<Connection, ChannelError> {
    ServerConnection::new(Arc::new(server_config(identity, peer)?))
        .map(Connection::Server)
        .map_err(|_| ChannelError::Configuration)
}

fn certified_key(identity: TlsIdentity) -> Arc<CertifiedKey> {
    let public_key = CertificateDer::from(identity.public_key.as_spki_der().to_vec());
    Arc::new(CertifiedKey::new(
        vec![public_key],
        Arc::new(BoundSigningKey(Arc::new(identity))),
    ))
}

fn client_config(identity: TlsIdentity, peer: TlsPublicKey) -> Result<ClientConfig, ChannelError> {
    if identity.role != EndpointRole::Client {
        return Err(ChannelError::WrongIdentityRole);
    }
    if identity.public_key == peer {
        return Err(ChannelError::KeyReuse);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ChannelError::Configuration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedPeer(peer)))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
            certified_key(identity),
        )));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.check_selected_alpn = true;
    config.enable_sni = false;
    config.enable_early_data = false;
    config.resumption = Resumption::disabled();
    config.send_ticket_request = None;
    config.key_log = Arc::new(NoKeyLog {});
    config.enable_secret_extraction = false;
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    Ok(config)
}

fn server_config(identity: TlsIdentity, peer: TlsPublicKey) -> Result<ServerConfig, ChannelError> {
    if identity.role != EndpointRole::Server {
        return Err(ChannelError::WrongIdentityRole);
    }
    if identity.public_key == peer {
        return Err(ChannelError::KeyReuse);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ChannelError::Configuration)?
        .with_client_cert_verifier(Arc::new(PinnedPeer(peer)))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
            certified_key(identity),
        )));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = Arc::new(NoTickets);
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.key_log = Arc::new(NoKeyLog {});
    config.enable_secret_extraction = false;
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    config.cert_compression_cache = Arc::new(rustls::compress::CompressionCache::Disabled);
    Ok(config)
}

#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

struct PinnedPeer(TlsPublicKey);

impl fmt::Debug for PinnedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedPeer([redacted])")
    }
}

impl PinnedPeer {
    fn check_key(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), TlsError> {
        if !intermediates.is_empty() || end_entity.as_ref() != self.0.as_spki_der() {
            return Err(TlsError::General(TRANSPORT_REJECTED.into()));
        }
        // The expected bytes were validated strictly at enrollment boundary;
        // exact equality also rejects noncanonical DER, chains and other curves.
        Ok(())
    }

    fn check_signature(
        &self,
        role: EndpointRole,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.check_key(cert, &[])?;
        if signed.scheme != SignatureScheme::ECDSA_NISTP256_SHA256
            || CertificateVerifyInput::parse(role, message).is_err()
        {
            return Err(TlsError::General(TRANSPORT_REJECTED.into()));
        }
        let signature = CertificateVerifySignature::from_der(signed.signature())
            .map_err(|_| TlsError::General(TRANSPORT_REJECTED.into()))?;
        if !self.0.verify(message, &signature) {
            return Err(TlsError::General(TRANSPORT_REJECTED.into()));
        }
        // This marker is returned ONLY after real P-256/SHA-256 verification.
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.check_key(end_entity, intermediates)?;
        if !ocsp.is_empty() {
            return Err(TlsError::General(TRANSPORT_REJECTED.into()));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.check_signature(EndpointRole::Server, message, cert, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinnedPeer {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.check_key(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.check_signature(EndpointRole::Client, message, cert, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
