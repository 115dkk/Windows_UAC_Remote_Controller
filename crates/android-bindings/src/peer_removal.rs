// SPDX-License-Identifier: GPL-2.0-or-later
//! Local downward-only enrollment removal. No PC/network confirmation is needed.
#![forbid(unsafe_code)]

use crate::{BridgeError, MobileController};

#[uniffi::export]
impl MobileController {
    /// Remove the current association for this exact public PC identity. The
    /// durable owner resolves its generation while admitted; UI supplies neither
    /// a path nor a key nor an authorization result. Shared local keys remain.
    pub fn forget_pc(&self, pc_id: String) -> Result<bool, BridgeError> {
        if pc_id.len() != 64
            || !pc_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(false);
        }
        let _admission = self.enter()?;
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(pc_id.as_bytes().chunks_exact(2)) {
            let digit = |value: u8| {
                if value <= b'9' {
                    value - b'0'
                } else {
                    value - b'a' + 10
                }
            };
            *byte = digit(pair[0]) * 16 + digit(pair[1]);
        }
        let removed = self.with_inbox(|owner| {
            let reference = owner
                .peer_associations()
                .map_err(|_| BridgeError::StorageUnavailable)?
                .entries()
                .find(|entry| entry.reference().pc().as_bytes() == &bytes)
                .map(|entry| entry.reference());
            let Some(reference) = reference else {
                return Ok(None);
            };
            let (_committed, removal) = owner
                .revoke_peer_association_from_trusted_host(reference)
                .map_err(|_| BridgeError::StorageUnavailable)?;
            if removal != android_controller::PeerAssociationRemoval::Removed {
                return Err(BridgeError::StorageUnavailable);
            }
            Ok(Some(reference))
        })?;
        let Some(reference) = removed else {
            return Ok(false);
        };
        self.intake.retire_association(reference);
        // The committed removal revoked old leases. Prune presentations and
        // cancel their approval/denial operations before returning success.
        self.dispatch_effects(Vec::new(), false)?;
        self.signal_intake_maintenance();
        Ok(true)
    }
}
