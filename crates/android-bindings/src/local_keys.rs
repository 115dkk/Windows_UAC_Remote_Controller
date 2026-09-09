// SPDX-License-Identifier: GPL-2.0-or-later
//! Store-locked startup inspection, not key generation or enrollment.
use android_controller::{LocalKeyLedger, LocalKeySetPhase};
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

pub(crate) fn preflight(
    keys: &LocalKeyLedger,
    platform: &dyn NativePlatform,
    cleanup_needed: &mut bool,
) -> Result<(), BridgeError> {
    if keys
        .entries()
        .any(|phase| matches!(phase, LocalKeySetPhase::Preparing { .. }))
    {
        return Err(BridgeError::LocalKeysReconciliationRequired);
    }
    if keys.is_empty() {
        // Required for BOTH legacy and V2-empty metadata, after store ownership.
        // Presence is not a mapper; surviving aliases never become a new phone.
        return if platform.has_device_keys()? {
            Err(BridgeError::LocalKeysReconciliationRequired)
        } else {
            Ok(())
        };
    }
    let descriptors = keys
        .entries()
        .map(|phase| {
            let key = phase
                .descriptor()
                .ok_or(BridgeError::LocalKeysReconciliationRequired)?;
            Ok(NativeLocalKeySet {
                handle: key.handle().as_bytes().to_vec(),
                approval_spki: key.approval_key().as_spki_der().to_vec(),
                denial_spki: key.denial_key().as_spki_der().to_vec(),
                transport_spki: key.transport_key().as_spki_der().to_vec(),
            })
        })
        .collect::<Result<Vec<_>, BridgeError>>()?;
    // Before the call: an error/throw may follow partial native publication.
    *cleanup_needed = true;
    platform.reopen_local_key_sets(descriptors)
}
