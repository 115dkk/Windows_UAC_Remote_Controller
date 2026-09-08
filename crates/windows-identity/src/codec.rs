// SPDX-License-Identifier: GPL-2.0-or-later
//! Safe, bounded CNG representation decoding. No private key enters this module.

use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

use crate::{IdentityEncodingError, IdentitySignature, PcPublicKey};

pub(super) const PUBLIC_BLOB_BYTES: usize = 72;
pub(super) const RAW_SIGNATURE_BYTES: usize = 64;
// BCRYPT_ECDSA_PUBLIC_P256_MAGIC, little-endian ASCII "ECS1" (bcrypt.h).
const P256_PUBLIC_MAGIC: u32 = 0x3153_4345;

pub(super) fn public_key_from_blob(blob: &[u8]) -> Result<PcPublicKey, IdentityEncodingError> {
    if blob.len() != PUBLIC_BLOB_BYTES {
        return Err(IdentityEncodingError::PublicBlobLength);
    }
    if blob[..4] != P256_PUBLIC_MAGIC.to_le_bytes() {
        return Err(IdentityEncodingError::PublicBlobMagic);
    }
    if blob[4..8] != 32_u32.to_le_bytes() {
        return Err(IdentityEncodingError::PublicCoordinateSize);
    }
    let mut sec1 = [0_u8; 65];
    sec1[0] = 4;
    sec1[1..].copy_from_slice(&blob[8..]);
    // RustCrypto checks coordinate field bounds, curve membership and infinity;
    // the exact uncompressed shape above has no trailing data or alternate form.
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| IdentityEncodingError::PublicPoint)?;
    Ok(PcPublicKey(sec1))
}

pub(super) fn signature_from_cng(raw: &[u8]) -> Result<IdentitySignature, IdentityEncodingError> {
    if raw.len() != RAW_SIGNATURE_BYTES {
        return Err(IdentityEncodingError::SignatureLength);
    }
    // CNG ECDSA is unsigned, fixed-width big-endian r || s, not ASN.1 DER.
    // RustCrypto rejects zero/out-of-range scalars and performs DER encoding.
    let signature =
        Signature::from_slice(raw).map_err(|_| IdentityEncodingError::SignatureScalar)?;
    let canonical = signature.normalize_s().unwrap_or(signature);
    Ok(IdentitySignature(canonical.to_der().as_bytes().to_vec()))
}

pub(super) fn verify_signature(
    public: &PcPublicKey,
    digest: &[u8; 32],
    signature: &IdentitySignature,
) -> Result<(), IdentityEncodingError> {
    let key = VerifyingKey::from_sec1_bytes(public.as_sec1_bytes())
        .map_err(|_| IdentityEncodingError::PublicPoint)?;
    let parsed = Signature::from_der(signature.as_der_bytes())
        .map_err(|_| IdentityEncodingError::SignatureScalar)?;
    key.verify_prehash(digest, &parsed)
        .map_err(|_| IdentityEncodingError::SignatureVerification)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The standard curve generator is public mathematical data, not a real key.
    fn public_fixture() -> Vec<u8> {
        let generator = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
            0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut blob = Vec::from(P256_PUBLIC_MAGIC.to_le_bytes());
        blob.extend_from_slice(&32_u32.to_le_bytes());
        blob.extend_from_slice(&generator);
        blob
    }

    #[test]
    fn exports_only_exact_uncompressed_public_point() {
        let blob = public_fixture();
        let public = public_key_from_blob(&blob).expect("public mathematical fixture");
        assert_eq!(public.as_sec1_bytes()[0], 4);
        assert_eq!(&public.as_sec1_bytes()[1..], &blob[8..]);
        assert_eq!(format!("{public:?}"), "PcPublicKey([redacted])");
    }

    #[test]
    fn rejects_all_truncations_and_trailing_private_or_other_data() {
        let mut blob = public_fixture();
        for length in 0..PUBLIC_BLOB_BYTES {
            assert_eq!(
                public_key_from_blob(&blob[..length]),
                Err(IdentityEncodingError::PublicBlobLength)
            );
        }
        blob.extend_from_slice(&[0_u8; 32]);
        assert_eq!(
            public_key_from_blob(&blob),
            Err(IdentityEncodingError::PublicBlobLength)
        );
    }

    #[test]
    fn rejects_private_ecdh_other_curve_and_bad_coordinate_size() {
        for magic in [0x3253_4345, 0x314b_4345, 0x3353_4345, 0, u32::MAX] {
            let mut blob = public_fixture();
            blob[..4].copy_from_slice(&magic.to_le_bytes());
            assert_eq!(
                public_key_from_blob(&blob),
                Err(IdentityEncodingError::PublicBlobMagic)
            );
        }
        for size in [0_u32, 31, 33, 48, u32::MAX] {
            let mut blob = public_fixture();
            blob[4..8].copy_from_slice(&size.to_le_bytes());
            assert_eq!(
                public_key_from_blob(&blob),
                Err(IdentityEncodingError::PublicCoordinateSize)
            );
        }
    }

    #[test]
    fn rejects_off_curve_and_out_of_field_points() {
        for coordinates in [[0_u8; 64], [0xff_u8; 64]] {
            let mut blob = public_fixture();
            blob[8..].copy_from_slice(&coordinates);
            assert_eq!(
                public_key_from_blob(&blob),
                Err(IdentityEncodingError::PublicPoint)
            );
        }
    }

    #[test]
    fn signature_conversion_is_strict_der_and_redacted() {
        let mut raw = [0_u8; RAW_SIGNATURE_BYTES];
        raw[31] = 1;
        raw[63] = 2;
        let signature = signature_from_cng(&raw).expect("two valid scalar encodings");
        assert_eq!(signature.as_der_bytes(), &[0x30, 6, 2, 1, 1, 2, 1, 2]);
        assert_eq!(format!("{signature:?}"), "IdentitySignature([redacted])");
        let public = public_key_from_blob(&public_fixture()).expect("public fixture");
        assert_eq!(
            verify_signature(&public, &[0_u8; 32], &signature),
            Err(IdentityEncodingError::SignatureVerification)
        );
    }

    #[test]
    fn signature_requires_exact_length_and_nonzero_bounded_scalars() {
        for length in [0, 1, 32, 63, 65, 72, 128] {
            assert_eq!(
                signature_from_cng(&vec![1_u8; length]),
                Err(IdentityEncodingError::SignatureLength)
            );
        }
        for raw in [[0_u8; RAW_SIGNATURE_BYTES], [0xff_u8; RAW_SIGNATURE_BYTES]] {
            assert_eq!(
                signature_from_cng(&raw),
                Err(IdentityEncodingError::SignatureScalar)
            );
        }
    }

    #[test]
    fn der_integer_sign_padding_comes_from_rustcrypto() {
        let mut raw = [0_u8; RAW_SIGNATURE_BYTES];
        raw[0] = 0x80;
        raw[63] = 1;
        let signature = signature_from_cng(&raw).expect("valid scalar encodings");
        assert_eq!(&signature.as_der_bytes()[2..5], &[2, 33, 0]);
        assert!(Signature::from_der(signature.as_der_bytes()).is_ok());
    }

    #[test]
    fn high_s_is_normalized_by_rustcrypto() {
        // Public curve order minus one, not a private key or a real signature.
        let order_minus_one = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x50,
        ];
        let mut raw = [0_u8; RAW_SIGNATURE_BYTES];
        raw[31] = 1;
        raw[32..].copy_from_slice(&order_minus_one);
        let signature = signature_from_cng(&raw).expect("two valid scalar encodings");
        assert_eq!(signature.as_der_bytes(), &[0x30, 6, 2, 1, 1, 2, 1, 1]);
    }
}
