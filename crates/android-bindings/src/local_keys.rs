// SPDX-License-Identifier: GPL-2.0-or-later
//! Store-locked startup inspection, not key generation or enrollment.
use android_controller::{LocalKeyHandle, LocalKeyLedger, LocalKeySetPhase};
use std::fmt;

use crate::{BridgeError, NativePlatform};

/// Outbound native observation descriptor only. It carries public pins and an
/// opaque local alias handle, never an alias, private key, auth flag or command.
#[derive(uniffi::Record)]
pub struct NativeLocalKeySet {
    pub handle: Vec<u8>,
    pub approval_spki: Vec<u8>,
    pub denial_spki: Vec<u8>,
    pub transport_spki: Vec<u8>,
}
impl NativeLocalKeySet {
    pub(crate) fn from_descriptor(key: &android_controller::LocalKeySetDescriptor) -> Self {
        Self {
            handle: key.handle().as_bytes().to_vec(),
            approval_spki: key.approval_key().as_spki_der().to_vec(),
            denial_spki: key.denial_key().as_spki_der().to_vec(),
            transport_spki: key.transport_key().as_spki_der().to_vec(),
        }
    }
}
impl fmt::Debug for NativeLocalKeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeLocalKeySet([redacted], unverified)")
    }
}

/// Preparations an interrupted creation left behind, in committed handle order.
/// Their native aliases are deleted under this same store lock before the owner
/// commits the ledger without them; the reverse order would strand aliases that
/// no recorded set could ever claim again.
pub(crate) struct AbandonedPreparations(Vec<LocalKeyHandle>);
impl AbandonedPreparations {
    pub(crate) fn handles(&self) -> &[LocalKeyHandle] {
        &self.0
    }
    fn collect(keys: &LocalKeyLedger) -> Self {
        Self(
            keys.entries()
                .filter_map(|phase| match phase {
                    LocalKeySetPhase::Preparing { handle, .. } => Some(*handle),
                    LocalKeySetPhase::CreatedUnverified(_) => None,
                })
                .collect(),
        )
    }
}
impl fmt::Debug for AbandonedPreparations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbandonedPreparations")
            .field("count", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Startup inspection under the store's writer lock.
///
/// A committed Preparing row means this controller asked the native key owner
/// for a set and never learned whether it was created: the ceremony that asked
/// is gone, no enrollment can reference the row, and a phone whose interrupted
/// pairing could never be discarded would stay dead for good. So each such row
/// is reconciled here by deleting exactly its own aliases, and `abandoned` then
/// carries the handles whose rows the caller must commit away. Everything else
/// keeps the original refusals: surviving aliases without metadata never become
/// a new phone, and a recorded set is only ever reopened, never regenerated.
pub(crate) fn preflight(
    keys: &LocalKeyLedger,
    platform: &dyn NativePlatform,
    cleanup_needed: &mut bool,
    abandoned: &mut Option<AbandonedPreparations>,
) -> Result<(), BridgeError> {
    let descriptors = keys
        .entries()
        .filter_map(LocalKeySetPhase::descriptor)
        .map(|key| NativeLocalKeySet {
            handle: key.handle().as_bytes().to_vec(),
            approval_spki: key.approval_key().as_spki_der().to_vec(),
            denial_spki: key.denial_key().as_spki_der().to_vec(),
            transport_spki: key.transport_key().as_spki_der().to_vec(),
        })
        .collect::<Vec<_>>();
    let preparations = AbandonedPreparations::collect(keys);
    if !preparations.handles().is_empty() {
        // The recorded handles travel with the request so the native owner can
        // refuse a deletion this side should never have asked for. Before the
        // call: a failed or partial deletion leaves the rows intact, so the next
        // open repeats this same bounded deletion.
        platform.discard_prepared_key_sets(
            preparations
                .handles()
                .iter()
                .map(|handle| handle.as_bytes().to_vec())
                .collect(),
            descriptors.iter().map(|key| key.handle.clone()).collect(),
        )?;
        *abandoned = Some(preparations);
    }
    if descriptors.is_empty() {
        // Required for BOTH legacy and V2-empty metadata, after store ownership.
        // Presence is not a mapper; surviving aliases never become a new phone.
        return if platform.has_device_keys()? {
            Err(BridgeError::LocalKeysReconciliationRequired)
        } else {
            Ok(())
        };
    }
    // Before the call: an error/throw may follow partial native publication.
    *cleanup_needed = true;
    platform.reopen_local_key_sets(descriptors)
}
