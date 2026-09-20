// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic INTEGER encodings only; no certificate/native/attestation proof.

use super::AndroidProfile;
use der::{
    Decode, Encode, Tag,
    asn1::{AnyRef, Int, UintRef},
};
use x509_cert::{certificate::Rfc5280, serial_number::SerialNumber};

type AndroidSerial = SerialNumber<AndroidProfile>;

fn positive(magnitude: &[u8]) -> Vec<u8> {
    UintRef::new(magnitude)
        .expect("synthetic unsigned magnitude")
        .to_der()
        .expect("synthetic canonical INTEGER")
}

/// AnyRef encodes the outer TLV; the tested library decoder still interprets
/// and validates the deliberately malformed/signed INTEGER contents.
fn integer_contents(contents: &[u8]) -> Vec<u8> {
    AnyRef::new(Tag::Integer, contents)
        .expect("synthetic INTEGER value")
        .to_der()
        .expect("synthetic INTEGER wrapper")
}

#[test]
fn android_profile_decodes_31_and_32_byte_positive_magnitudes() {
    for length in [31, 32] {
        let magnitude = vec![0x7f; length];
        let encoded = positive(&magnitude);
        let decoded = AndroidSerial::from_der(&encoded).expect("permitted Android magnitude");
        assert_eq!(decoded.to_der().unwrap(), encoded);
        assert_eq!(UintRef::from_der(&encoded).unwrap().as_bytes(), magnitude);
        assert_eq!(AnyRef::from_der(&encoded).unwrap().value().len(), length);
    }
}

#[test]
fn high_bit_31_and_32_byte_magnitudes_keep_the_required_sign_octet() {
    for length in [31, 32] {
        for byte in [0x80, 0xff] {
            let magnitude = vec![byte; length];
            let encoded = positive(&magnitude);
            let value = AnyRef::from_der(&encoded).unwrap();
            assert_eq!(value.value().len(), length + 1);
            assert_eq!(value.value().first(), Some(&0));
            let decoded =
                AndroidSerial::from_der(&encoded).expect("required sign padding is not magnitude");
            assert_eq!(decoded.to_der().unwrap(), encoded);
            assert_eq!(UintRef::from_der(&encoded).unwrap().as_bytes(), magnitude);
        }
    }
}

#[test]
fn from_der_uses_the_selected_profile_not_the_fixed_constructor_limit() {
    // x509-cert0.3 SerialNumber::decode_value calls P::check_serial_number.
    // Its new() constructor instead hardcodes the20-byte construction limit;
    // do not use new() to manufacture these permitted Android test encodings.
    let magnitude = [0x7f; 32];
    let encoded = positive(&magnitude);
    assert!(AndroidSerial::new(&magnitude).is_err());
    assert!(SerialNumber::<Rfc5280>::from_der(&encoded).is_err());
    assert!(AndroidSerial::from_der(&encoded).is_ok());
}

#[test]
fn canonical_33_byte_magnitude_is_rejected_with_or_without_a_sign_octet() {
    for byte in [0x01, 0x7f, 0x80, 0xff] {
        let magnitude = [byte; 33];
        let encoded = positive(&magnitude);
        // It is a valid arbitrary-precision unsigned DER INTEGER. The Android
        // profile, not malformed DER, must reject its33-byte magnitude.
        assert_eq!(UintRef::from_der(&encoded).unwrap().as_bytes(), magnitude);
        assert!(AndroidSerial::from_der(&encoded).is_err());
    }
}

#[test]
fn valid_negative_integer_encodings_are_not_accepted_as_serial_magnitudes() {
    for contents in [vec![0x80], vec![0xff], vec![0x80; 31], vec![0x80; 32]] {
        let encoded = integer_contents(&contents);
        assert!(
            Int::from_der(&encoded).is_ok(),
            "synthetic negative INTEGER is canonical"
        );
        assert!(AndroidSerial::from_der(&encoded).is_err());
    }
}

#[test]
fn zero_is_rejected_even_though_its_integer_der_is_valid() {
    let encoded = 0u8.to_der().unwrap();
    assert!(Int::from_der(&encoded).is_ok());
    assert!(UintRef::from_der(&encoded).is_ok());
    assert!(AndroidSerial::from_der(&encoded).is_err());
    assert!(AndroidSerial::from_der(&integer_contents(&[])).is_err());
}

#[test]
fn redundant_leading_zeroes_are_not_normalized_into_accepted_der() {
    let mut low_boundary = vec![0];
    low_boundary.extend_from_slice(&[0x7f; 31]);
    let mut high_boundary = vec![0, 0];
    high_boundary.extend_from_slice(&[0x80; 32]);
    for contents in [
        vec![0, 1],
        vec![0, 0x7f],
        vec![0, 0, 0x80],
        low_boundary,
        high_boundary,
    ] {
        assert!(AndroidSerial::from_der(&integer_contents(&contents)).is_err());
    }
}

#[test]
fn complete_serial_decoder_rejects_truncation_trailing_data_and_wrong_tag() {
    let encoded = positive(&[0x80; 32]);
    for end in 0..encoded.len() {
        assert!(
            AndroidSerial::from_der(&encoded[..end]).is_err(),
            "truncated synthetic INTEGER at {end}"
        );
    }
    for suffix in [vec![0], 1u8.to_der().unwrap()] {
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&suffix);
        assert!(AndroidSerial::from_der(&trailing).is_err());
    }
    let wrong = AnyRef::new(Tag::OctetString, &[1])
        .unwrap()
        .to_der()
        .unwrap();
    assert!(AndroidSerial::from_der(&wrong).is_err());
}
