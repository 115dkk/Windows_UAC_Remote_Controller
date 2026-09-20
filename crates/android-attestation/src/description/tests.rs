// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic DER descriptions only: no certificate, attestation-chain, native
//! key, physical-device or authentication proof. ROOT executes these tests.
use super::*;
use der::{Encode, TagNumber};

const CHALLENGE: [u8; 32] = [7; 32];
const SIGNERS: [[u8; 32]; 2] = [[8; 32], [9; 32]];

fn policy() -> DescriptionPolicy<'static> {
    DescriptionPolicy {
        challenge: &CHALLENGE,
        signer_digests: &SIGNERS,
        min_app_version: 2,
        min_os_version: 110000,
        min_os_patch: 202601,
        min_vendor_patch: None,
        min_boot_patch: None,
    }
}
fn tlv(tag: Tag, bytes: &[u8]) -> Vec<u8> {
    AnyRef::new(tag, bytes).unwrap().to_der().unwrap()
}
fn sequence(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    tlv(
        Tag::Sequence,
        &values.into_iter().flatten().collect::<Vec<_>>(),
    )
}
fn set(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    // Do not sort/repair fixtures: tests deliberately supply noncanonical order.
    tlv(Tag::Set, &values.into_iter().flatten().collect::<Vec<_>>())
}
fn uint(value: u64) -> Vec<u8> {
    value.to_der().unwrap()
}
fn enum_value(value: u8) -> Vec<u8> {
    tlv(Tag::Enumerated, &[value])
}
fn blob(bytes: &[u8]) -> Vec<u8> {
    tlv(Tag::OctetString, bytes)
}
fn nil() -> Vec<u8> {
    tlv(Tag::Null, &[])
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
fn app_id(packages: &[(&[u8], u64)], signers: &[[u8; 32]]) -> Vec<u8> {
    sequence([
        set(packages
            .iter()
            .map(|(name, version)| sequence([blob(name), uint(*version)]))),
        set(signers.iter().map(|digest| blob(digest))),
    ])
}
fn root_value(version: u32, locked: bool, state: u8) -> Vec<u8> {
    let mut fields = vec![blob(&[1; 32]), locked.to_der().unwrap(), enum_value(state)];
    if version >= 3 {
        fields.push(blob(&[2; 32]));
    }
    sequence(fields)
}

struct Fixture {
    version: u32,
    keymint: u32,
    attestation_level: u8,
    keymint_level: u8,
    challenge: Vec<u8>,
    unique_id: Vec<u8>,
    software: Vec<(u32, Vec<u8>)>,
    hardware: Vec<(u32, Vec<u8>)>,
}
impl Fixture {
    fn new(role: KeyRole) -> Self {
        let auth = if role == KeyRole::Approval {
            (504, uint(3))
        } else {
            (503, nil())
        };
        Self {
            version: 400,
            keymint: 400,
            attestation_level: 1,
            keymint_level: 1,
            challenge: CHALLENGE.to_vec(),
            unique_id: Vec::new(),
            software: vec![
                (701, uint(123456)),
                (709, blob(&app_id(&[(PACKAGE, 2)], &SIGNERS))),
            ],
            hardware: vec![
                (1, set([uint(2)])),
                (2, uint(3)),
                (3, uint(256)),
                (5, set([uint(4)])),
                (10, uint(1)),
                auth,
                (702, uint(0)),
                (704, root_value(400, true, 0)),
                (705, uint(150000)),
                (706, uint(202609)),
                (718, uint(20260905)),
                (719, uint(20260905)),
            ],
        }
    }
    fn set_hardware(&mut self, tag: u32, value: Vec<u8>) {
        self.hardware.retain(|(old, _)| *old != tag);
        self.hardware.push((tag, value));
        self.hardware.sort_by_key(|(tag, _)| *tag);
    }
    fn set_software(&mut self, tag: u32, value: Vec<u8>) {
        self.software.retain(|(old, _)| *old != tag);
        self.software.push((tag, value));
        self.software.sort_by_key(|(tag, _)| *tag);
    }
    fn fields(&self) -> Vec<Vec<u8>> {
        vec![
            uint(u64::from(self.version)),
            enum_value(self.attestation_level),
            uint(u64::from(self.keymint)),
            enum_value(self.keymint_level),
            blob(&self.challenge),
            blob(&self.unique_id),
            sequence(
                self.software
                    .iter()
                    .map(|(tag, value)| explicit(*tag, value)),
            ),
            sequence(
                self.hardware
                    .iter()
                    .map(|(tag, value)| explicit(*tag, value)),
            ),
        ]
    }
    fn der(&self) -> Vec<u8> {
        sequence(self.fields())
    }
    fn check(&self, role: KeyRole) -> Result<KeyDescription, Error> {
        verify_description(&self.der(), &policy(), role)
    }
}

#[test]
fn all_three_exact_roles_return_only_bounded_platform_metadata() {
    for role in [KeyRole::Approval, KeyRole::Denial, KeyRole::Transport] {
        let value = Fixture::new(role).check(role).unwrap();
        assert_eq!(value.attestation_version, 400);
        assert_eq!(value.keymint_version, 400);
        assert_eq!(value.os_version, 150000);
        assert_eq!(value.os_patch, 202609);
        assert_eq!(value.vendor_patch, Some(20260905));
        assert_eq!(value.app_version, 2);
    }
}

#[test]
fn explicit_version_pairs_include_upgraded_v2_and_sony_v3_but_never_guess_future_versions() {
    for (version, keymint) in [
        (2, 3),
        (3, 4),
        (3, 41),
        (4, 41),
        (100, 100),
        (200, 200),
        (300, 300),
        (400, 400),
        (500, 500),
    ] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.version = version;
        fixture.keymint = keymint;
        fixture.set_hardware(704, root_value(version, true, 0));
        if version == 2 {
            fixture
                .hardware
                .retain(|(tag, _)| !matches!(tag, 718 | 719));
        }
        assert_eq!(
            fixture.check(KeyRole::Approval).unwrap().keymint_version,
            keymint
        );
    }
    for (version, keymint) in [(1, 2), (0, 0), (2, 4), (4, 4), (500, 400), (501, 501)] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.version = version;
        fixture.keymint = keymint;
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::UnsupportedProfile)
        ));
    }
}

#[test]
fn both_security_levels_must_match_the_selected_hardware_profile() {
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.attestation_level = 2;
    fixture.keymint_level = 2;
    let observed = fixture.check(KeyRole::Approval).unwrap();
    assert_eq!(
        observed.attestation_security_level,
        HardwareLevel::StrongBox
    );
    assert_eq!(observed.keymint_security_level, HardwareLevel::StrongBox);
    for (attester, key) in [(1, 2), (2, 1)] {
        let mut mixed = Fixture::new(KeyRole::Approval);
        mixed.attestation_level = attester;
        mixed.keymint_level = key;
        assert!(matches!(
            mixed.check(KeyRole::Approval),
            Err(Error::PlatformPolicy)
        ));
    }
    for bad in [0, 3, 127, 255] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.attestation_level = bad;
        assert!(fixture.check(KeyRole::Approval).is_err());
        fixture.attestation_level = 1;
        fixture.keymint_level = bad;
        assert!(fixture.check(KeyRole::Approval).is_err());
    }
    fixture.version = 2;
    fixture.keymint = 3;
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::PlatformPolicy)
    ));
}

#[test]
fn exact_sign_ec_p256_sha256_and_generated_origin_are_required() {
    for (tag, value) in [
        (2, uint(1)),
        (3, uint(384)),
        (10, uint(2)),
        (702, uint(2)),
        (1, set([uint(7)])),
        (1, set([uint(2), uint(3)])),
        (5, set([uint(5)])),
        (5, set([uint(4), uint(4)])),
    ] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(tag, value);
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
    for missing in [1, 2, 3, 5, 10, 702] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.hardware.retain(|(tag, _)| *tag != missing);
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
}

#[test]
fn approval_and_unauthenticated_roles_cannot_be_swapped() {
    let approval = Fixture::new(KeyRole::Approval);
    assert!(matches!(
        approval.check(KeyRole::Denial),
        Err(Error::KeyPolicy)
    ));
    assert!(matches!(
        approval.check(KeyRole::Transport),
        Err(Error::KeyPolicy)
    ));
    let denial = Fixture::new(KeyRole::Denial);
    assert!(matches!(
        denial.check(KeyRole::Approval),
        Err(Error::KeyPolicy)
    ));
    for auth_type in [0, 1, 2, 4, u64::from(u32::MAX)] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(504, uint(auth_type));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
    for role in [KeyRole::Approval, KeyRole::Denial, KeyRole::Transport] {
        let mut fixture = Fixture::new(role);
        fixture.set_hardware(503, nil());
        fixture.set_hardware(504, uint(3));
        assert!(matches!(fixture.check(role), Err(Error::KeyPolicy)));
    }
}

#[test]
fn auth_timeout_absence_is_not_equivalent_to_explicit_zero() {
    assert!(
        Fixture::new(KeyRole::Approval)
            .check(KeyRole::Approval)
            .is_ok()
    );
    for role in [KeyRole::Approval, KeyRole::Denial, KeyRole::Transport] {
        for timeout in [0, 1, 60] {
            let mut fixture = Fixture::new(role);
            fixture.set_hardware(505, uint(timeout));
            assert!(matches!(fixture.check(role), Err(Error::KeyPolicy)));
            let mut fixture = Fixture::new(role);
            fixture.set_software(505, uint(timeout));
            assert!(matches!(fixture.check(role), Err(Error::KeyPolicy)));
        }
    }
}

#[test]
fn software_only_and_duplicate_security_fields_never_gain_hardware_provenance() {
    for tag in [1, 2, 3, 5, 10, 504, 702] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        let value = fixture
            .hardware
            .iter()
            .find(|(field, _)| *field == tag)
            .unwrap()
            .1
            .clone();
        fixture.set_software(tag, value);
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
        fixture.hardware.retain(|(field, _)| *field != tag);
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_software(704, root_value(400, true, 0));
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::PlatformPolicy)
    ));
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_hardware(709, blob(&app_id(&[(PACKAGE, 2)], &SIGNERS)));
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::AppIdentity)
    ));
}

#[test]
fn unrequested_presence_confirmation_on_body_validity_and_usage_limits_fail() {
    for tag in [305, 506, 507, 508, 509, 600] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(tag, nil());
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
    for tag in [400, 401, 402, 405, 502, 11] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(tag, uint(0));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::KeyPolicy)
        ));
    }
}

#[test]
fn context_tags_are_explicit_canonical_ordered_and_unique() {
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.hardware.swap(0, 1);
    assert!(matches!(fixture.check(KeyRole::Approval), Err(Error::Der)));
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture
        .software
        .push(fixture.software.last().unwrap().clone());
    assert!(matches!(fixture.check(KeyRole::Approval), Err(Error::Der)));
    let mut fields = Fixture::new(KeyRole::Denial).fields();
    fields[7] = sequence([tlv(
        Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(503),
        },
        &nil(),
    )]);
    assert!(matches!(
        verify_description(&sequence(fields), &policy(), KeyRole::Denial),
        Err(Error::Der)
    ));
    let mut fields = Fixture::new(KeyRole::Approval).fields();
    let mut malformed = explicit(709, &blob(&app_id(&[(PACKAGE, 2)], &SIGNERS)));
    malformed.insert(1, 0x80); // Forbidden leading-zero high-tag-number group.
    fields[6] = sequence([malformed]);
    assert!(matches!(
        verify_description(&sequence(fields), &policy(), KeyRole::Approval),
        Err(Error::Der)
    ));
}

#[test]
fn der_rejects_ber_nonminimal_integer_wrong_enum_null_and_explicit_trailing_value() {
    let fixture = Fixture::new(KeyRole::Approval);
    let content: Vec<_> = fixture.fields().into_iter().flatten().collect();
    let mut ber = vec![0x30, 0x80];
    ber.extend(content);
    ber.extend([0, 0]);
    assert!(matches!(
        verify_description(&ber, &policy(), KeyRole::Approval),
        Err(Error::Der)
    ));
    let mut malformed = Fixture::new(KeyRole::Approval);
    malformed.set_hardware(2, tlv(Tag::Integer, &[0, 3]));
    assert!(matches!(
        malformed.check(KeyRole::Approval),
        Err(Error::Der)
    ));
    let mut fields = fixture.fields();
    fields[1] = uint(1);
    assert!(matches!(
        verify_description(&sequence(fields), &policy(), KeyRole::Approval),
        Err(Error::Der)
    ));
    let mut malformed = Fixture::new(KeyRole::Denial);
    malformed.set_hardware(503, tlv(Tag::Null, &[0]));
    assert!(matches!(malformed.check(KeyRole::Denial), Err(Error::Der)));
    malformed.set_hardware(503, [nil(), nil()].concat());
    assert!(matches!(malformed.check(KeyRole::Denial), Err(Error::Der)));
    let bytes = fixture.der();
    assert!(verify_description(&bytes[..bytes.len() - 1], &policy(), KeyRole::Approval).is_err());
    assert!(verify_description(&[bytes, vec![0]].concat(), &policy(), KeyRole::Approval).is_err());
}

#[test]
fn root_of_trust_requires_locked_verified_and_versioned_field_count() {
    for (locked, state) in [(false, 0), (true, 1), (true, 2), (true, 3)] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(704, root_value(400, locked, state));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::PlatformPolicy)
        ));
    }
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_hardware(704, root_value(2, true, 0));
    assert!(matches!(fixture.check(KeyRole::Approval), Err(Error::Der)));
    fixture.set_hardware(
        704,
        sequence([
            blob(&[1; 32]),
            tlv(Tag::Boolean, &[1]),
            enum_value(0),
            blob(&[2; 32]),
        ]),
    );
    assert!(matches!(fixture.check(KeyRole::Approval), Err(Error::Der)));
    for length in [0, 129] {
        fixture.set_hardware(
            704,
            sequence([
                blob(&vec![1; length]),
                true.to_der().unwrap(),
                enum_value(0),
                blob(&[2; 32]),
            ]),
        );
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::PlatformPolicy)
        ));
    }
}

#[test]
fn platform_versions_and_calendar_patch_shapes_are_checked_against_explicit_minima() {
    for (tag, value) in [
        (705, 100000),
        (705, 1000000),
        (706, 202600),
        (706, 202613),
        (706, 202512),
        (718, 20260230),
        (719, 20250229),
    ] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(tag, uint(value));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::PlatformPolicy)
        ));
    }
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_hardware(718, uint(20240229));
    assert!(fixture.check(KeyRole::Approval).is_ok());
    let mut policy = policy();
    policy.min_vendor_patch = Some(20260901);
    assert!(matches!(
        verify_description(&fixture.der(), &policy, KeyRole::Approval),
        Err(Error::PlatformPolicy)
    ));
    fixture.hardware.retain(|(tag, _)| *tag != 718);
    assert!(matches!(
        verify_description(&fixture.der(), &policy, KeyRole::Approval),
        Err(Error::PlatformPolicy)
    ));
}

#[test]
fn application_package_version_and_exact_signer_certificate_digest_set_are_required() {
    for data in [
        app_id(&[(b"other.app", 2)], &SIGNERS),
        app_id(&[(PACKAGE, 1)], &SIGNERS),
        app_id(&[(PACKAGE, 2), (b"other.shared.uid", 2)], &SIGNERS),
        app_id(&[(PACKAGE, 2)], &SIGNERS[..1]),
        app_id(&[(PACKAGE, 2)], &[[10; 32]]),
    ] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_software(709, blob(&data));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::AppIdentity)
        ));
    }
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.software.retain(|(tag, _)| *tag != 709);
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::AppIdentity)
    ));
}

#[test]
fn signer_set_der_order_and_duplicate_rejection_do_not_sort_or_repair_evidence() {
    for signers in [[SIGNERS[1], SIGNERS[0]], [SIGNERS[0], SIGNERS[0]]] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_software(709, blob(&app_id(&[(PACKAGE, 2)], &signers)));
        assert!(matches!(fixture.check(KeyRole::Approval), Err(Error::Der)));
    }
    // Trusted policy ordering is not evidence ordering: it still names a set.
    let reversed = [SIGNERS[1], SIGNERS[0]];
    let mut policy = policy();
    policy.signer_digests = &reversed;
    assert!(
        verify_description(
            &Fixture::new(KeyRole::Approval).der(),
            &policy,
            KeyRole::Approval
        )
        .is_ok()
    );
}

#[test]
fn only_published_non_use_metadata_is_accepted_without_retaining_it() {
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_hardware(303, nil());
    fixture.set_software(724, blob(&[11; 32]));
    assert!(fixture.check(KeyRole::Approval).is_ok());
    fixture.set_hardware(724, blob(&[11; 32]));
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::UnsupportedProfile)
    ));
    fixture.software.retain(|(tag, _)| *tag != 724);
    assert!(fixture.check(KeyRole::Approval).is_ok());
    fixture.set_hardware(724, blob(&[11; 31]));
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::UnsupportedProfile)
    ));
    for tag in [710, 713, 717, 720, 723, 800] {
        let mut fixture = Fixture::new(KeyRole::Approval);
        fixture.set_hardware(tag, blob(b"unrequested identifier"));
        assert!(matches!(
            fixture.check(KeyRole::Approval),
            Err(Error::UnsupportedProfile)
        ));
    }
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.unique_id = vec![1; 16];
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::UnsupportedProfile)
    ));
}

#[test]
fn bounds_and_trusted_policy_errors_fail_without_default_identity_or_clock_policy() {
    assert!(matches!(
        verify_description(&[], &policy(), KeyRole::Approval),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        verify_description(&vec![0; 8193], &policy(), KeyRole::Approval),
        Err(Error::Bounds)
    ));
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.set_software(709, blob(&vec![0; 1025]));
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::Bounds)
    ));
    let data = Fixture::new(KeyRole::Approval).der();
    let mut invalid = policy();
    invalid.challenge = &[0; 32];
    assert!(matches!(
        verify_description(&data, &invalid, KeyRole::Approval),
        Err(Error::InvalidPolicy)
    ));
    invalid = policy();
    invalid.signer_digests = &[];
    assert!(matches!(
        verify_description(&data, &invalid, KeyRole::Approval),
        Err(Error::InvalidPolicy)
    ));
    invalid = policy();
    invalid.signer_digests = &[[8; 32], [8; 32]];
    assert!(matches!(
        verify_description(&data, &invalid, KeyRole::Approval),
        Err(Error::InvalidPolicy)
    ));
    invalid = policy();
    invalid.min_os_patch = 202600;
    assert!(matches!(
        verify_description(&data, &invalid, KeyRole::Approval),
        Err(Error::InvalidPolicy)
    ));
    let mut fixture = Fixture::new(KeyRole::Approval);
    fixture.challenge[0] ^= 1;
    assert!(matches!(
        fixture.check(KeyRole::Approval),
        Err(Error::ChallengeMismatch)
    ));
}

#[test]
fn debug_does_not_render_challenge_signer_or_attested_text() {
    let observed = Fixture::new(KeyRole::Approval)
        .check(KeyRole::Approval)
        .unwrap();
    assert_eq!(format!("{observed:?}"), "KeyDescription(metadata_only)");
    assert_eq!(format!("{:?}", policy()), "DescriptionPolicy([redacted])");
}
