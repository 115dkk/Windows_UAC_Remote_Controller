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

    /// Retain this already validated frame for a bounded, trusted in-process
    /// native-owner handoff. This does not parse bytes or confer enrollment,
    /// approval, freshness, or cross-process provenance.
    pub fn into_owned(self) -> OwnedCertificateVerifyInput {
        let mut message = [0; MAX_CERTIFICATE_VERIFY_BYTES];
        message[..self.message.len()].copy_from_slice(self.message);
        OwnedCertificateVerifyInput {
            role: self.role,
            message,
            length: self.message.len(),
        }
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

const MAX_CERTIFICATE_VERIFY_BYTES: usize = 64 + EndpointRole::Server.context().len() + 1 + 48;

/// An owned witness derived only from an actual validated borrowed TLS frame.
/// Fixed storage bounds the complete SHA-256/SHA-384 transcript-hash variants;
/// it is deliberately non-Clone and has no byte parser or serialization API.
/// A receiver must still enforce local role, owner lifetime and its deadline.
/// Copying these bytes through IPC cannot recreate this trusted-process type.
///
/// ```compile_fail
/// use secure_channel::OwnedCertificateVerifyInput;
/// let _ = OwnedCertificateVerifyInput::from_bytes(b"caller-selected message");
/// ```
pub struct OwnedCertificateVerifyInput {
    role: EndpointRole,
    message: [u8; MAX_CERTIFICATE_VERIFY_BYTES],
    length: usize,
}

impl OwnedCertificateVerifyInput {
    pub fn role(&self) -> EndpointRole {
        self.role
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.message[..self.length]
    }

    /// Verify ECDSA P-256/SHA-256 over this exact complete TLS frame. This
    /// verifies signature possession only, not native hardware or enrollment.
    pub fn verify_signature(
        &self,
        public_key: &TlsPublicKey,
        signature: &CertificateVerifySignature,
    ) -> Result<(), SignerError> {
        if public_key.verify(self.as_bytes(), signature) {
            Ok(())
        } else {
            Err(SignerError::InvalidSignature)
        }
    }
}

impl fmt::Debug for OwnedCertificateVerifyInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedCertificateVerifyInput")
            .field("role", &self.role)
            .finish_non_exhaustive()
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

#[cfg(test)]
mod owned_input_tests {
    use super::*;
    use crate::test_support::{SyntheticSigner, frame};

    #[test]
    fn owned_frame_preserves_exact_role_and_both_hash_lengths_after_source_drop() {
        for role in [EndpointRole::Client, EndpointRole::Server] {
            for hash_length in [32, 48] {
                let bytes = frame(role, hash_length);
                let expected = bytes.clone();
                let input = CertificateVerifyInput::parse(role, &bytes)
                    .unwrap()
                    .into_owned();
                drop(bytes);
                assert_eq!(input.role(), role);
                assert_eq!(input.as_bytes(), expected);
                assert_eq!(input.as_bytes().len(), 98 + hash_length);
            }
        }
    }

    #[test]
    fn owned_witness_verifies_only_the_exact_frame_and_key() {
        let signer = SyntheticSigner::new(91);
        let public = signer.public_key().unwrap();
        let bytes = frame(EndpointRole::Server, 32);
        let signature = signer
            .sign_certificate_verify(
                CertificateVerifyInput::parse(EndpointRole::Server, &bytes).unwrap(),
            )
            .unwrap();
        let input = CertificateVerifyInput::parse(EndpointRole::Server, &bytes)
            .unwrap()
            .into_owned();
        assert_eq!(input.verify_signature(&public, &signature), Ok(()));
        let wrong_public = SyntheticSigner::new(92).public_key().unwrap();
        assert_eq!(
            input.verify_signature(&wrong_public, &signature),
            Err(SignerError::InvalidSignature)
        );
        let other_role = frame(EndpointRole::Client, 32);
        let other_input = CertificateVerifyInput::parse(EndpointRole::Client, &other_role)
            .unwrap()
            .into_owned();
        assert_eq!(
            other_input.verify_signature(&public, &signature),
            Err(SignerError::InvalidSignature)
        );
    }

    #[test]
    fn owned_frame_debug_is_redacted_and_type_is_thread_transferable() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OwnedCertificateVerifyInput>();
        let bytes = frame(EndpointRole::Server, 48);
        let input = CertificateVerifyInput::parse(EndpointRole::Server, &bytes)
            .unwrap()
            .into_owned();
        assert_eq!(
            format!("{input:?}"),
            "OwnedCertificateVerifyInput { role: Server, .. }"
        );
    }
}
