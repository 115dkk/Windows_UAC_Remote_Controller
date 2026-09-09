// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic public-key and byte-store models only. No Windows/TPM/file calls.
use super::{
    RegisteredDeviceKeys, RegistryError,
    journal::{self, AppendSink, Journal},
    model::{Document, MAX_DOCUMENT_BYTES, RegistryChange},
};
use approval_protocol::{DecisionPublicKey, DeviceId};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use secure_channel::TlsPublicKey;

fn point(seed: u8) -> DecisionPublicKey {
    let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
    DecisionPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
        .unwrap()
}
fn tls(seed: u8) -> TlsPublicKey {
    let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
    let public =
        p256::PublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
            .unwrap();
    TlsPublicKey::from_spki_der(public.to_public_key_der().unwrap().as_bytes()).unwrap()
}
pub(super) fn pc() -> DecisionPublicKey {
    point(1)
}
pub(super) fn device(seed: u8) -> DeviceId {
    DeviceId::from_bytes([seed; 16]).unwrap()
}
pub(super) fn keys(first: u8) -> RegisteredDeviceKeys {
    RegisteredDeviceKeys::from_trusted_host(point(first), point(first + 1), tls(first + 2)).unwrap()
}
fn initial() -> (Journal, Vec<u8>) {
    let mut bytes = vec![];
    let state = Journal::initial(pc()).unwrap().append_fixture(&mut bytes);
    (state, bytes)
}

#[test]
fn actual_composite_roundtrip_preserves_roles_revisions_and_empty_highwater() {
    let (mut state, mut bytes) = initial();
    state = state
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    state = state
        .prepare_change(RegistryChange::Replace {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    state = state
        .prepare_change(RegistryChange::Revoke { device: device(1) })
        .unwrap()
        .append_fixture(&mut bytes);
    assert!(state.document.core.entries().is_empty());
    assert_eq!(state.document.core.next_revision(), 3);
    let reopened = Journal::restore(pc(), &bytes).unwrap();
    assert_eq!(reopened.document.core, state.document.core);
    state = reopened
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    let reopened = Journal::restore(pc(), &bytes).unwrap();
    assert_eq!(reopened.document.core.entries()[0].revision(), 3);
    assert_eq!(reopened.document.core.next_revision(), 4);
    assert_eq!(reopened.document.transport(device(1)), Some(&tls(4)));
    assert_eq!(reopened.document.core, state.document.core);
}

#[test]
fn role_separation_includes_pc_transport_and_other_devices() {
    assert!(matches!(
        RegisteredDeviceKeys::from_trusted_host(point(2), point(3), tls(2)),
        Err(RegistryError::KeyReuse)
    ));
    let state = Document::empty(pc())
        .unwrap()
        .changed(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap();
    assert!(matches!(
        state.changed(RegistryChange::Enroll {
            device: device(2),
            keys: keys(4)
        }),
        Err(RegistryError::KeyReuse)
    ));
    assert!(matches!(
        Document::empty(pc())
            .unwrap()
            .changed(RegistryChange::Enroll {
                device: device(1),
                keys: keys(1)
            }),
        Err(RegistryError::KeyReuse)
    ));
    assert!(matches!(
        state.changed(RegistryChange::Enroll {
            device: device(1),
            keys: keys(5)
        }),
        Err(RegistryError::Enrollment(_))
    ));
    assert!(
        state
            .changed(RegistryChange::Replace {
                device: device(2),
                keys: keys(5)
            })
            .is_err()
    );
    assert!(
        state
            .changed(RegistryChange::Revoke { device: device(2) })
            .is_err()
    );
    assert_eq!(state.core.entries().len(), 1);
}

#[test]
fn maximum_composite_is_bounded_and_roundtrips_canonically() {
    let mut state = Document::empty(pc()).unwrap();
    for index in 0..32_u8 {
        state = state
            .changed(RegistryChange::Enroll {
                device: device(index + 1),
                keys: keys(2 + index * 3),
            })
            .unwrap();
    }
    let bytes = state.encode();
    assert_eq!(bytes.len(), 5806);
    assert_eq!(bytes.len(), MAX_DOCUMENT_BYTES);
    assert_eq!(Document::decode(pc(), &bytes).unwrap().encode(), bytes);
    assert!(
        state
            .changed(RegistryChange::Enroll {
                device: device(33),
                keys: keys(100)
            })
            .is_err()
    );
}

#[test]
fn malformed_composite_headers_id_revision_and_points_are_rejected() {
    let state = Document::empty(pc())
        .unwrap()
        .changed(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap();
    let bytes = state.encode();
    let mut candidates = vec![
        vec![],
        bytes[..13].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
    ];
    for range in [0..2, 2..4, 4..12, 14..30, 30..38] {
        let mut bad = bytes.clone();
        bad[range].fill(0);
        candidates.push(bad);
    }
    let mut count = bytes.clone();
    count[12..14].copy_from_slice(&33_u16.to_be_bytes());
    candidates.push(count);
    let mut point = bytes.clone();
    point[38] = 4;
    candidates.push(point);
    let mut cross_role = bytes.clone();
    cross_role[104..195].copy_from_slice(tls(2).as_spki_der());
    candidates.push(cross_role);
    for candidate in candidates {
        assert!(Document::decode(pc(), &candidate).is_err());
    }
}

#[test]
fn corrupted_torn_or_trailing_transactions_never_fall_back_to_old_authority() {
    let (state, mut bytes) = initial();
    let prefix = bytes.len();
    state
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    for length in 0..bytes.len() {
        if length == prefix {
            continue;
        }
        assert!(
            Journal::restore(pc(), &bytes[..length]).is_err(),
            "cut {length}"
        );
    }
    for position in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[position] ^= 0x80;
        assert!(Journal::restore(pc(), &bad).is_err(), "offset {position}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Journal::restore(pc(), &extra).is_err());
    assert!(Journal::restore(point(100), &bytes).is_err());
}

#[test]
fn complete_valid_prefix_rollback_is_explicitly_not_a_hash_chain_guarantee() {
    let (state, mut bytes) = initial();
    let old_prefix = bytes.clone();
    state
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    assert_eq!(
        Journal::restore(pc(), &bytes)
            .unwrap()
            .document
            .core
            .entries()
            .len(),
        1
    );
    // An older COMPLETE journal is still a valid journal. Native ACLs/pins and
    // exclusive ownership, not this format, prevent lower-privilege replacement.
    assert!(
        Journal::restore(pc(), &old_prefix)
            .unwrap()
            .document
            .core
            .entries()
            .is_empty()
    );
}

#[derive(Default)]
struct MemorySink {
    bytes: Vec<u8>,
    calls: usize,
    fail: Option<(usize, Failure)>,
}
#[derive(Clone, Copy)]
enum Failure {
    Before,
    Partial,
    After,
    Length,
    Panic,
}
impl AppendSink for MemorySink {
    fn append_and_flush(&mut self, expected: u64, bytes: &[u8]) -> Result<u64, RegistryError> {
        self.calls += 1;
        assert_eq!(expected, self.bytes.len() as u64);
        if let Some((call, failure)) = self.fail.filter(|(call, _)| *call == self.calls) {
            assert_eq!(call, self.calls);
            match failure {
                Failure::Before => (),
                Failure::Partial => self.bytes.extend_from_slice(&bytes[..bytes.len() / 2]),
                Failure::After => self.bytes.extend_from_slice(bytes),
                Failure::Length => return Ok(expected + bytes.len() as u64 + 1),
                Failure::Panic => panic!("synthetic storage unwind"),
            }
            return Err(RegistryError::Unavailable);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(self.bytes.len() as u64)
    }
}

#[test]
fn failed_intent_commit_flush_or_length_closes_owner_without_success_or_rollback() {
    for step in [1, 2] {
        for failure in [
            Failure::Before,
            Failure::Partial,
            Failure::After,
            Failure::Length,
        ] {
            let (state, bytes) = initial();
            let prepared = state
                .prepare_change(RegistryChange::Enroll {
                    device: device(1),
                    keys: keys(2),
                })
                .unwrap();
            let mut owner = Some(state);
            let mut sink = MemorySink {
                bytes,
                fail: Some((step, failure)),
                ..MemorySink::default()
            };
            assert_eq!(
                journal::publish(&mut owner, &mut sink, prepared),
                Err(RegistryError::Unavailable)
            );
            assert!(owner.is_none());
            assert_eq!(sink.calls, step);
            // Reopening may find old, new or invalid bytes depending on the
            // failed boundary. No blanket durable quarantine/rollback assertion.
        }
    }
}

#[test]
fn unwind_closes_owner_before_storage_is_entered() {
    let (state, bytes) = initial();
    let prepared = state.prepare_change(RegistryChange::Revoke { device: device(1) });
    assert!(prepared.is_err());
    let prepared = state
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap();
    let mut owner = Some(state);
    let mut sink = MemorySink {
        bytes,
        fail: Some((1, Failure::Panic)),
        ..MemorySink::default()
    };
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journal::publish(
            &mut owner, &mut sink, prepared
        )))
        .is_err()
    );
    assert!(owner.is_none());
}

#[test]
fn publication_occurs_after_two_confirmed_appends_and_reopens_exactly() {
    let mut owner = None;
    let mut sink = MemorySink::default();
    journal::publish(&mut owner, &mut sink, Journal::initial(pc()).unwrap()).unwrap();
    assert_eq!(sink.calls, 2);
    let prepared = owner
        .as_ref()
        .unwrap()
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap();
    journal::publish(&mut owner, &mut sink, prepared).unwrap();
    assert_eq!(sink.calls, 4);
    let reopened = Journal::restore(pc(), &sink.bytes).unwrap();
    assert_eq!(
        owner.as_ref().unwrap().document.core,
        reopened.document.core
    );
}

#[test]
fn bounded_journal_requires_maintenance_instead_of_reset_or_unbounded_growth() {
    let (mut state, mut bytes) = initial();
    state = state
        .prepare_change(RegistryChange::Enroll {
            device: device(1),
            keys: keys(2),
        })
        .unwrap()
        .append_fixture(&mut bytes);
    // Only key/public metadata, never real auth or native disk. Each same-key
    // replacement still consumes a revision and transaction slot.
    for _ in 2..511 {
        state = state
            .prepare_change(RegistryChange::Replace {
                device: device(1),
                keys: keys(2),
            })
            .unwrap()
            .append_fixture(&mut bytes);
    }
    let prepared = state
        .prepare_change(RegistryChange::Replace {
            device: device(1),
            keys: keys(2),
        })
        .unwrap();
    let mut owner = Some(state);
    let mut sink = MemorySink {
        bytes,
        ..MemorySink::default()
    };
    assert_eq!(
        journal::publish(&mut owner, &mut sink, prepared),
        Err(RegistryError::MaintenanceRequired)
    );
    assert!(owner.is_none());
    assert_eq!(sink.calls, 2); // Both writes may be committed, but no authority is returned.
    let restored = Journal::restore(pc(), &sink.bytes).unwrap();
    assert_eq!(
        restored.ensure_writable(),
        Err(RegistryError::MaintenanceRequired)
    );
    assert!(
        restored
            .prepare_change(RegistryChange::Revoke { device: device(1) })
            .is_err()
    );
    assert!(sink.bytes.len() < journal::MAX_FILE_BYTES);
    assert!(Journal::restore(pc(), &vec![0; journal::MAX_FILE_BYTES + 1]).is_err());
}
