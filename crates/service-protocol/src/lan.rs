// SPDX-License-Identifier: GPL-2.0-or-later
//! The DNS-SD name under which a PC announces its embedded relay on the local
//! network (ADR 0043).
//!
//! A phone whose stored addresses all fail looks for this name to find the PC
//! again after its LAN address changed. The name is a routing hint and nothing
//! else: anyone on the network can announce it, so every address learned from it
//! still needs the pinned TLS connection that every other candidate needs.
//!
//! The label is a digest of the PC identity rather than the identity itself, so
//! the network sees a stable opaque name, and a phone paired with several PCs
//! dials only the one it is looking for.

use approval_protocol::PcIdentity;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"Windows-UAC-Remote-Controller/lan-instance/v1\0";

/// DNS-SD service type, without the `.local` domain.
pub const LAN_SERVICE_TYPE: &str = "_uacremote._tcp";

/// Every instance label starts with this.
pub const LAN_INSTANCE_PREFIX: &str = "uacremote-";

/// Bytes of the digest kept in the label.
const TAG_BYTES: usize = 10;

/// Length of every instance label: the prefix and twice [`TAG_BYTES`] hex digits.
pub const LAN_INSTANCE_LABEL_LEN: usize = LAN_INSTANCE_PREFIX.len() + TAG_BYTES * 2;

/// The instance label this PC announces, for example
/// `uacremote-0123456789abcdef0123`.
pub fn lan_instance_label(pc: &PcIdentity) -> String {
    let digest = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(pc.as_bytes())
        .finalize();
    let mut label = String::with_capacity(LAN_INSTANCE_LABEL_LEN);
    label.push_str(LAN_INSTANCE_PREFIX);
    for byte in &digest[..TAG_BYTES] {
        label.push(char::from(HEX[usize::from(byte >> 4)]));
        label.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    label
}

/// Whether `label` has the shape [`lan_instance_label`] produces. Shape only:
/// it says nothing about which PC, if any, announced it.
pub fn is_lan_instance_label(label: &str) -> bool {
    label.len() == LAN_INSTANCE_LABEL_LEN
        && label.starts_with(LAN_INSTANCE_PREFIX)
        && label[LAN_INSTANCE_PREFIX.len()..]
            .bytes()
            .all(|byte| HEX.contains(&byte))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(seed: u8) -> PcIdentity {
        PcIdentity::from_bytes([seed; 32]).unwrap()
    }

    #[test]
    fn label_is_stable_and_well_formed() {
        let label = lan_instance_label(&pc(7));
        assert_eq!(label, lan_instance_label(&pc(7)));
        assert_eq!(label.len(), LAN_INSTANCE_LABEL_LEN);
        assert!(is_lan_instance_label(&label));
        // A DNS label holds at most 63 bytes.
        assert!(label.len() <= 63);
    }

    #[test]
    fn label_matches_the_domain_separated_digest() {
        let digest = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update([7_u8; 32])
            .finalize();
        let hex: String = digest[..TAG_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(lan_instance_label(&pc(7)), format!("uacremote-{hex}"));
    }

    #[test]
    fn different_pcs_get_different_labels() {
        assert_ne!(lan_instance_label(&pc(7)), lan_instance_label(&pc(8)));
    }

    #[test]
    fn shape_check_rejects_other_names() {
        let label = lan_instance_label(&pc(7));
        assert!(!is_lan_instance_label(""));
        assert!(!is_lan_instance_label("uacremote-"));
        assert!(!is_lan_instance_label(&label.to_uppercase()));
        assert!(!is_lan_instance_label(&format!("{label}0")));
        assert!(!is_lan_instance_label(&label[..label.len() - 1]));
        assert!(!is_lan_instance_label(&label.replacen(
            "uacremote-",
            "uacremotx-",
            1
        )));
        assert!(!is_lan_instance_label(&format!(
            "{}g",
            &label[..label.len() - 1]
        )));
        // Multi-byte text of the right byte length is not hex.
        let multibyte = "uacremote-가나다0123456789a";
        assert_eq!(multibyte.len(), LAN_INSTANCE_LABEL_LEN);
        assert!(!is_lan_instance_label(multibyte));
    }
}
