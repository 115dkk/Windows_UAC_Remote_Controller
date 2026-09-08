// SPDX-License-Identifier: GPL-2.0-or-later
use std::{fmt, sync::Arc};

use rustls::{
    Error as TlsError, SignatureAlgorithm, SignatureScheme,
    pki_types::SubjectPublicKeyInfoDer,
    sign::{Signer, SigningKey},
};
use thiserror::Error;

use crate::{CertificateVerifySignature, TlsPublicKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRole {
    /// The enrolled phone's transport identity.
    Client,
    /// The enrolled PC's transport identity.
    Server,
}

impl EndpointRole {
    const fn context(self) -> &'static [u8] {
        match self {
            Self::Client => b"TLS 1.3, client CertificateVerify",
            Self::Server => b"TLS 1.3, server CertificateVerify",
        }
    }
}

/// A private-constructible, borrowed TLS 1.3 CertificateVerify frame. It cannot
/// represent arbitrary application bytes or a TLS 1.2 signing request. Native
/// owners sign these bytes with ECDSA P-256/SHA-256 (not a prehashed variant).
/// The transcript hash inside the frame is exactly 32 or 48 bytes. This type
/// does not prove hardware provenance, user authentication or approval intent.
pub struct CertificateVerifyInput<'a> {
    role: EndpointRole,
    message: &'a [u8],
}

impl<'a> CertificateVerifyInput<'a> {
    pub fn role(&self) -> EndpointRole {
        self.role
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.message
    }

    pub(crate) fn parse(role: EndpointRole, message: &'a [u8]) -> Result<Self, SignerError> {
        let context = role.context();
        let separator = 64 + context.len();
        let header = separator + 1;
        if ![header + 32, header + 48].contains(&message.len())
            || message.get(..64) != Some(&[0x20; 64])
            || message.get(64..separator) != Some(context)
            || message.get(separator) != Some(&0)
        {
            return Err(SignerError::InvalidMessage);
        }
        Ok(Self { role, message })
    }
}

impl fmt::Debug for CertificateVerifyInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateVerifyInput")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Trusted platform-owner extension point, not an IPC or generic signing API.
/// Implementations must retain the private TRANSPORT key in its native owner;
/// never reuse approval/denial keys or export software fallback keys here.
pub trait PlatformTlsSigner: Send + Sync {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError>;

    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError>;
}

/// Role-bound local identity constructed only by a trusted native host. Not
/// serializable, not a private-key container, and not an enrollment operation.
pub struct TlsIdentity {
    pub(crate) role: EndpointRole,
    pub(crate) public_key: TlsPublicKey,
    pub(crate) signer: Arc<dyn PlatformTlsSigner>,
}

impl TlsIdentity {
    pub fn from_trusted_host(
        role: EndpointRole,
        signer: Arc<dyn PlatformTlsSigner>,
    ) -> Result<Self, SignerError> {
        let public_key = signer.public_key()?;
        Ok(Self {
            role,
            public_key,
            signer,
        })
    }

    pub fn role(&self) -> EndpointRole {
        self.role
    }

    pub fn public_key(&self) -> &TlsPublicKey {
        &self.public_key
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsIdentity")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SignerError {
    #[error("platform transport signer is unavailable")]
    Unavailable,
    #[error("platform transport signer rejected the operation")]
    Rejected,
    #[error("message is not the local role's TLS 1.3 CertificateVerify frame")]
    InvalidMessage,
    #[error("platform transport signature did not verify")]
    InvalidSignature,
}

pub(crate) struct BoundSigningKey(pub(crate) Arc<TlsIdentity>);

impl fmt::Debug for BoundSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundSigningKey")
            .field("role", &self.0.role)
            .finish_non_exhaustive()
    }
}

impl SigningKey for BoundSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(Self(Arc::clone(&self.0))) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.0.public_key.as_spki_der(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for BoundSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        let input = CertificateVerifyInput::parse(self.0.role, message)
            .map_err(|_| TlsError::General("invalid transport signing context".into()))?;
        let signature = self
            .0
            .signer
            .sign_certificate_verify(input)
            .map_err(|_| TlsError::General("platform transport signing failed".into()))?;
        if !self.0.public_key.verify(message, &signature) {
            return Err(TlsError::General(
                "platform transport signature did not verify".into(),
            ));
        }
        Ok(signature.as_der().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}
