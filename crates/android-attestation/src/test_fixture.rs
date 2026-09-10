// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic SOFTWARE certificates for ROOT-run whole-verifier tests only.
//! Names/TEE claims here are deliberately authored test data, not Android or
//! Google evidence. The public verifier must reject this private test anchor.
#![cfg(test)]
#![forbid(unsafe_code)]

use std::{
    fmt,
    str::FromStr,
    time::{Duration, SystemTime},
};

use der::{
    Encode, Tag, TagNumber,
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetString},
};
use ring::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
use secure_channel::TlsPublicKey;
use x509_cert::{
    ext::{
        Extension,
        pkix::{BasicConstraints, KeyUsage, KeyUsages},
    },
    name::Name,
    time::{Time, Validity},
};

use crate::{
    ExpectedKeyBundle, PlatformMinimums, VerificationPolicy, certificate, description::KeyRole,
    roots,
};

const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const CHALLENGE: [u8; 32] = [7; 32];
const SIGNER_DIGEST: [u8; 32] = [8; 32];
const MAX_REPLACEMENT_DESCRIPTION_BYTES: usize = 8192;

/// Three leaf-first5-certificate chains sharing test CAs and a test attester.
/// Private signing material has no getter and never leaves this test object.
pub(crate) struct SyntheticRkp {
    pub(crate) chains: [Vec<Vec<u8>>; 3],
    pub(crate) expected: ExpectedKeyBundle,
    pub(crate) policy: VerificationPolicy,
    pub(crate) anchor: roots::Anchor,
    leaves: [SoftwareTestKey; 3],
    attester: SoftwareTestKey,
    attester_name: Name,
    validity: Validity<certificate::AndroidProfile>,
}

impl fmt::Debug for SyntheticRkp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyntheticRkp([redacted], software_test_fixture_only)")
    }
}

impl SyntheticRkp {
    pub(crate) fn new() -> Self {
        let now = SystemTime::now();
        let hour = Duration::from_secs(3600);
        let before = Time::try_from(
            now.checked_sub(hour)
                .expect("synthetic test clock before epoch"),
        )
        .expect("synthetic validity start");
        let after = Time::try_from(
            now.checked_add(hour)
                .expect("synthetic test clock overflow"),
        )
        .expect("synthetic validity end");
        let validity = Validity::<certificate::AndroidProfile>::new(before, after);

        let root = SoftwareTestKey::p384();
        let ca2 = SoftwareTestKey::p256();
        let ca3 = SoftwareTestKey::p256();
        let attester = SoftwareTestKey::p256();
        let leaves = std::array::from_fn(|_| SoftwareTestKey::p256());
        let root_name = name("CN=Synthetic RKP test root,O=Synthetic fixture");
        let ca2_name = name("CN=Droid CA2,O=Google LLC");
        let ca3_name = name("CN=Droid CA3,O=Google LLC");
        let attester_name = name("CN=synthetic-attester-01,O=TEE");

        let root_der = signed_certificate(
            &root_name,
            &root_name,
            &root,
            &root,
            1,
            &validity,
            ca_extensions(3),
        );
        let ca2_der = signed_certificate(
            &ca2_name,
            &root_name,
            &ca2,
            &root,
            2,
            &validity,
            ca_extensions(2),
        );
        let ca3_der = signed_certificate(
            &ca3_name,
            &ca2_name,
            &ca3,
            &ca2,
            3,
            &validity,
            ca_extensions(1),
        );
        let attester_der = signed_certificate(
            &attester_name,
            &ca3_name,
            &attester,
            &ca3,
            4,
            &validity,
            ca_extensions(0),
        );
        let roles = [KeyRole::Approval, KeyRole::Denial, KeyRole::Transport];
        let chains = std::array::from_fn(|index| {
            let leaf = signed_leaf(
                &leaves[index],
                &attester,
                &attester_name,
                index,
                &validity,
                &Self::default_description(roles[index]),
            );
            vec![
                leaf,
                attester_der.clone(),
                ca3_der.clone(),
                ca2_der.clone(),
                root_der.clone(),
            ]
        });
        let [approval, denial, transport] = leaves.each_ref().map(|key| {
            TlsPublicKey::from_spki_der(&key.spki()).expect("synthetic canonical P256 public key")
        });
        let expected = ExpectedKeyBundle::from_trusted_host(CHALLENGE, approval, denial, transport)
            .expect("synthetic distinct role keys");
        let policy = VerificationPolicy::from_trusted_host(
            vec![SIGNER_DIGEST],
            2,
            PlatformMinimums {
                os_version: 110000,
                os_patch: 202601,
                vendor_patch: Some(20260101),
                boot_patch: Some(20260101),
            },
        )
        .expect("synthetic release policy");
        let anchor = roots::test_anchor(root_der, roots::RootKind::CurrentP384)
            .expect("synthetic self-signed test root");
        Self {
            chains,
            expected,
            policy,
            anchor,
            leaves,
            attester,
            attester_name,
            validity,
        }
    }

    /// Keep the original leaf public key/issuer/time/serial and genuinely resign
    /// the changed description. This tests policy parsing, not signature damage.
    pub(crate) fn replace_leaf_description(&mut self, index: usize, bytes: &[u8]) {
        assert!(
            bytes.len() <= MAX_REPLACEMENT_DESCRIPTION_BYTES,
            "synthetic description bound"
        );
        let leaf = self.leaves.get(index).expect("synthetic role index");
        let encoded = signed_leaf(
            leaf,
            &self.attester,
            &self.attester_name,
            index,
            &self.validity,
            bytes,
        );
        *self
            .chains
            .get_mut(index)
            .and_then(|chain| chain.first_mut())
            .expect("synthetic leaf slot") = encoded;
    }

    pub(crate) fn default_description(role: KeyRole) -> Vec<u8> {
        let package = sequence([octets(b"dev.dkk115.uacremote"), uint(2)]);
        let app = sequence([set([package]), set([octets(&SIGNER_DIGEST)])]);
        let software = sequence([explicit(709, &octets(&app))]);
        let auth = match role {
            KeyRole::Approval => explicit(504, &uint(3)),
            KeyRole::Denial | KeyRole::Transport => explicit(503, &tlv(Tag::Null, &[])),
        };
        let root_of_trust = sequence([
            octets(&[1; 32]),
            true.to_der().expect("synthetic BOOLEAN"),
            enumerated(0),
            octets(&[2; 32]),
        ]);
        let hardware = sequence([
            explicit(1, &set([uint(2)])),
            explicit(2, &uint(3)),
            explicit(3, &uint(256)),
            explicit(5, &set([uint(4)])),
            explicit(10, &uint(1)),
            auth,
            explicit(702, &uint(0)),
            explicit(704, &root_of_trust),
            explicit(705, &uint(160000)),
            explicit(706, &uint(202608)),
            explicit(718, &uint(20260801)),
            explicit(719, &uint(20260801)),
        ]);
        sequence([
            uint(400),
            enumerated(1),
            uint(400),
            enumerated(1),
            octets(&CHALLENGE),
            octets(&[]),
            software,
            hardware,
        ])
    }
}

/// Genuine ring-generated ephemeral SOFTWARE signing keys, test-only by module
/// configuration. No fixed/reused real private material or signing success stub.
struct SoftwareTestKey {
    pair: EcdsaKeyPair,
    curve: ObjectIdentifier,
    signature: ObjectIdentifier,
}

impl SoftwareTestKey {
    fn p256() -> Self {
        Self::new(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            P256,
            ECDSA_SHA256,
        )
    }
    fn p384() -> Self {
        Self::new(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            P384,
            ECDSA_SHA384,
        )
    }

    fn new(
        algorithm: &'static EcdsaSigningAlgorithm,
        curve: ObjectIdentifier,
        signature: ObjectIdentifier,
    ) -> Self {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(algorithm, &rng)
            .expect("synthetic software key generation");
        let pair = EcdsaKeyPair::from_pkcs8(algorithm, document.as_ref(), &rng)
            .expect("synthetic software PKCS8");
        Self {
            pair,
            curve,
            signature,
        }
    }

    fn spki(&self) -> Vec<u8> {
        sequence([
            sequence([oid(EC), oid(self.curve)]),
            BitStringRef::from_bytes(self.pair.public_key().as_ref())
                .expect("synthetic public bit string")
                .to_der()
                .expect("synthetic SPKI bits"),
        ])
    }

    fn algorithm(&self) -> Vec<u8> {
        sequence([oid(self.signature)])
    }
    fn sign_tbs(&self, tbs: &[u8]) -> Vec<u8> {
        self.pair
            .sign(&SystemRandom::new(), tbs)
            .expect("synthetic certificate signature")
            .as_ref()
            .to_vec()
    }
}

fn name(value: &str) -> Name {
    Name::from_str(value).expect("synthetic distinguished name")
}
fn oid(value: ObjectIdentifier) -> Vec<u8> {
    value.to_der().expect("synthetic OID")
}
fn uint(value: u64) -> Vec<u8> {
    value.to_der().expect("synthetic INTEGER")
}
fn octets(value: &[u8]) -> Vec<u8> {
    tlv(Tag::OctetString, value)
}
fn enumerated(value: u8) -> Vec<u8> {
    tlv(Tag::Enumerated, &[value])
}

fn tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    AnyRef::new(tag, value)
        .expect("synthetic DER value")
        .to_der()
        .expect("synthetic DER encoding")
}
fn sequence(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    tlv(
        Tag::Sequence,
        &values.into_iter().flatten().collect::<Vec<_>>(),
    )
}
fn set(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    // The fixture's SETs are all singletons; no sorting/repair of hostile input.
    tlv(Tag::Set, &values.into_iter().flatten().collect::<Vec<_>>())
}
fn explicit(number: u32, value: &[u8]) -> Vec<u8> {
    tlv(
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber(number),
        },
        value,
    )
}

fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Vec<u8> {
    Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value).expect("synthetic extension"),
    }
    .to_der()
    .expect("synthetic Extension encoding")
}
fn ca_extensions(path_length: u8) -> Vec<Vec<u8>> {
    vec![
        extension(
            certificate::BASIC_CONSTRAINTS,
            true,
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(path_length),
            }
            .to_der()
            .expect("synthetic CA constraint"),
        ),
        extension(
            certificate::KEY_USAGE,
            true,
            KeyUsage(KeyUsages::KeyCertSign.into())
                .to_der()
                .expect("synthetic CA key usage"),
        ),
    ]
}

fn signed_leaf(
    leaf: &SoftwareTestKey,
    attester: &SoftwareTestKey,
    issuer: &Name,
    index: usize,
    validity: &Validity<certificate::AndroidProfile>,
    description: &[u8],
) -> Vec<u8> {
    let serial = u64::try_from(index).expect("synthetic role index") + 5;
    signed_certificate(
        &name("CN=Android Keystore Key"),
        issuer,
        leaf,
        attester,
        serial,
        validity,
        vec![
            extension(
                certificate::BASIC_CONSTRAINTS,
                true,
                BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                }
                .to_der()
                .expect("synthetic leaf constraint"),
            ),
            extension(
                certificate::KEY_USAGE,
                true,
                KeyUsage(KeyUsages::DigitalSignature.into())
                    .to_der()
                    .expect("synthetic leaf key usage"),
            ),
            extension(certificate::KEY_DESCRIPTION, false, description.to_vec()),
        ],
    )
}

/// x509-cert0.3 has private TBS fields. Compose the TEST sequence using each
/// field's DER Encode implementation and AnyRef wrappers, never a hand parser.
/// Production Certificate::parse/verify_issued_by still reads/verifies these bytes.
fn signed_certificate(
    subject: &Name,
    issuer: &Name,
    key: &SoftwareTestKey,
    signer: &SoftwareTestKey,
    serial: u64,
    validity: &Validity<certificate::AndroidProfile>,
    extensions: Vec<Vec<u8>>,
) -> Vec<u8> {
    let algorithm = signer.algorithm();
    let tbs = sequence([
        explicit(0, &uint(2)),
        uint(serial),
        algorithm.clone(),
        issuer.to_der().expect("synthetic issuer"),
        validity.to_der().expect("synthetic validity"),
        subject.to_der().expect("synthetic subject"),
        key.spki(),
        explicit(3, &sequence(extensions)),
    ]);
    let signature = signer.sign_tbs(&tbs);
    sequence([
        tbs,
        algorithm,
        BitStringRef::from_bytes(&signature)
            .expect("synthetic signature bits")
            .to_der()
            .expect("synthetic signature encoding"),
    ])
}
