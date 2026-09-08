// SPDX-License-Identifier: GPL-2.0-or-later
use std::fmt;

use p256::{
    PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use thiserror::Error;

const SPKI_BYTES: usize = 91;
const MAX_SIGNATURE_BYTES: usize = 72;

/// One valid P-256 point, encoded in the one accepted canonical SPKI form:
/// id-ecPublicKey + prime256v1, with an uncompressed SEC1 point. Public-key
/// validity and canonical encoding do not establish enrollment or attestation.
#[derive(Clone, PartialEq, Eq)]
pub struct TlsPublicKey {
    der: [u8; SPKI_BYTES],
}

impl TlsPublicKey {
    pub fn from_spki_der(bytes: &[u8]) -> Result<Self, KeyError> {
        let der: [u8; SPKI_BYTES] = bytes.try_into().map_err(|_| KeyError::InvalidSpki)?;
        let key = PublicKey::from_public_key_der(bytes).map_err(|_| KeyError::InvalidSpki)?;
        let canonical = key.to_public_key_der().map_err(|_| KeyError::InvalidSpki)?;
        if canonical.as_bytes() != bytes {
            return Err(KeyError::InvalidSpki);
        }
        Ok(Self { der })
    }

    pub fn as_spki_der(&self) -> &[u8] {
        &self.der
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &CertificateVerifySignature) -> bool {
        let Ok(key) = VerifyingKey::from_public_key_der(&self.der) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(signature.as_der()) else {
            return false;
        };
        key.verify(message, &signature).is_ok()
    }
}

impl fmt::Debug for TlsPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsPublicKey([redacted])")
    }
}

/// A bounded, canonical P-256 DER signature. Parsing checks encoding/scalar
/// shape, not who signed it; the channel verifies it against the pinned key.
pub struct CertificateVerifySignature {
    der: [u8; MAX_SIGNATURE_BYTES],
    length: usize,
}

impl CertificateVerifySignature {
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        if bytes.len() > MAX_SIGNATURE_BYTES {
            return Err(SignatureError::InvalidDer);
        }
        let signature = Signature::from_der(bytes).map_err(|_| SignatureError::InvalidDer)?;
        if signature.to_der().as_bytes() != bytes {
            return Err(SignatureError::InvalidDer);
        }
        let mut der = [0; MAX_SIGNATURE_BYTES];
        der[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            der,
            length: bytes.len(),
        })
    }

    pub fn as_der(&self) -> &[u8] {
        &self.der[..self.length]
    }
}

impl fmt::Debug for CertificateVerifySignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateVerifySignature([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("transport public key is not valid canonical P-256 SPKI")]
    InvalidSpki,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("transport signature is not valid canonical P-256 DER")]
    InvalidDer,
}
