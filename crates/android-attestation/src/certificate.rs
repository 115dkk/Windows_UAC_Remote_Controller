// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict bounded certificate data and signature checks, not enrollment trust.

use crate::VerificationError as Error;
use der::{
    Decode, Encode, Reader, SliceReader, Tag,
    asn1::{ObjectIdentifier, UintRef},
};
use ring::signature;
use std::fmt;
use x509_cert::{
    certificate::{CertificateInner, Profile, Version},
    serial_number::SerialNumber,
    time::Time,
};

pub(crate) const KEY_DESCRIPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
pub(crate) const PROVISIONING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.30");
pub(crate) const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
pub(crate) const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Two explicit Android format accommodations, not a generic unchecked profile:
/// positive serial magnitude <=32 bytes and preservation of an encoded Time
/// choice. All DER and subsequent path/signature/policy checks remain required.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AndroidProfile;

impl Profile for AndroidProfile {
    fn check_serial_number(serial: &SerialNumber<Self>) -> der::Result<()> {
        if serial.as_bytes().len() > 33 {
            return Err(Tag::Integer.value_error().into());
        }
        let encoded = serial.to_der()?;
        let positive = UintRef::from_der(&encoded)?;
        if positive.as_bytes().len() > 32
            || positive.as_bytes().is_empty()
            || positive.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(Tag::Integer.value_error().into());
        }
        Ok(())
    }

    fn time_encoding(time: Time) -> der::Result<Time> {
        // Do not rewrite a signed legacy GeneralizedTime as UTCTime.
        Ok(time)
    }
}

pub(crate) struct Certificate<'a> {
    pub(crate) parsed: CertificateInner<AndroidProfile>,
    pub(crate) encoded: &'a [u8],
    tbs: &'a [u8],
    spki: Vec<u8>,
}

impl fmt::Debug for Certificate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Certificate([redacted])")
    }
}

impl<'a> Certificate<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 8192 {
            return Err(Error::Bounds);
        }
        let parsed = CertificateInner::<AndroidProfile>::from_der(bytes).map_err(|_| Error::Der)?;
        let tbs_fields = parsed.tbs_certificate();
        if tbs_fields.version() != Version::V3
            || tbs_fields.issuer_unique_id().is_some()
            || tbs_fields.subject_unique_id().is_some()
        {
            return Err(Error::UnsupportedProfile);
        }
        if parsed.signature_algorithm() != tbs_fields.signature()
            || parsed.signature().as_bytes().is_none()
        {
            return Err(Error::Signature);
        }
        // Check canonical encoding without ever substituting it for signed data.
        if parsed.to_der().map_err(|_| Error::Der)? != bytes {
            return Err(Error::Der);
        }
        let extensions = tbs_fields.extensions().ok_or(Error::UnsupportedProfile)?;
        if extensions.is_empty() || extensions.len() > 24 {
            return Err(Error::Bounds);
        }
        let mut seen = Vec::with_capacity(extensions.len());
        for extension in extensions {
            if seen.contains(&extension.extn_id) {
                return Err(Error::Der);
            }
            seen.push(extension.extn_id);
            if extension.critical
                && ![BASIC_CONSTRAINTS, KEY_USAGE, KEY_DESCRIPTION].contains(&extension.extn_id)
            {
                return Err(Error::UnsupportedProfile);
            }
        }
        let spki = tbs_fields
            .subject_public_key_info()
            .to_der()
            .map_err(|_| Error::Der)?;
        let mut reader = SliceReader::new(bytes).map_err(|_| Error::Der)?;
        let tbs = reader
            .sequence(|nested| -> der::Result<&'a [u8]> {
                let original = nested.tlv_bytes()?;
                nested.tlv_bytes()?;
                nested.tlv_bytes()?;
                Ok(original)
            })
            .map_err(|_| Error::Der)?;
        reader.finish().map_err(|_| Error::Der)?;
        Ok(Self {
            parsed,
            encoded: bytes,
            tbs,
            spki,
        })
    }

    pub(crate) fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub(crate) fn serial(&self) -> &[u8] {
        self.parsed.tbs_certificate().serial_number().as_bytes()
    }

    pub(crate) fn extension(&self, oid: ObjectIdentifier) -> Option<&[u8]> {
        self.parsed
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|extension| extension.extn_id == oid)
            .map(|extension| extension.extn_value.as_bytes())
    }

    pub(crate) fn verify_issued_by(&self, parent: &Self) -> Result<(), Error> {
        if self.parsed.tbs_certificate().issuer() != parent.parsed.tbs_certificate().subject() {
            return Err(Error::Chain);
        }
        let signature = self.parsed.signature().as_bytes().ok_or(Error::Signature)?;
        let algorithm = self.parsed.signature_algorithm();
        let key = parent.parsed.tbs_certificate().subject_public_key_info();
        let public = key.subject_public_key.as_bytes().ok_or(Error::Signature)?;
        if key.algorithm.oid == RSA && algorithm.oid == RSA_SHA256 {
            for parameters in [
                key.algorithm.parameters.as_ref(),
                algorithm.parameters.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                parameters
                    .decode_as::<()>()
                    .map_err(|_| Error::UnsupportedProfile)?;
            }
            return signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public,
            )
            .verify(self.tbs, signature)
            .map_err(|_| Error::Signature);
        }
        if key.algorithm.oid != EC || algorithm.parameters.is_some() {
            return Err(Error::UnsupportedProfile);
        }
        let curve = key
            .algorithm
            .parameters
            .as_ref()
            .ok_or(Error::UnsupportedProfile)?
            .decode_as::<ObjectIdentifier>()
            .map_err(|_| Error::UnsupportedProfile)?;
        let verifier = match (curve, algorithm.oid) {
            (P256, ECDSA_SHA256) => &signature::ECDSA_P256_SHA256_ASN1,
            (P256, ECDSA_SHA384) => &signature::ECDSA_P256_SHA384_ASN1,
            (P384, ECDSA_SHA256) => &signature::ECDSA_P384_SHA256_ASN1,
            (P384, ECDSA_SHA384) => &signature::ECDSA_P384_SHA384_ASN1,
            _ => return Err(Error::UnsupportedProfile),
        };
        signature::UnparsedPublicKey::new(verifier, public)
            .verify(self.tbs, signature)
            .map_err(|_| Error::Signature)
    }
}

#[cfg(test)]
mod tests;
