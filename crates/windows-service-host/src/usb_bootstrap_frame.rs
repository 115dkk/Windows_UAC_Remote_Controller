// SPDX-License-Identifier: GPL-2.0-or-later
//! Public bootstrap bytes only, never a USB authentication/approval protocol.
#![forbid(unsafe_code)]
use service_protocol::{
    MAX_PAIRING_INVITATION_BYTES, MIN_PAIRING_INVITATION_BYTES, PairingInvitation,
};

/// Carries every invitation body the QR carries: v1 (345 or 357 bytes) and v2
/// with up to three alternative endpoints (up to 415). The invitation parser
/// decides the exact length; the frame only bounds it.
const BODY: std::ops::RangeInclusive<usize> =
    MIN_PAIRING_INVITATION_BYTES..=MAX_PAIRING_INVITATION_BYTES;
pub(crate) const MAX_FRAME: usize = 9 + MAX_PAIRING_INVITATION_BYTES;
pub(crate) fn encode(invitation: &PairingInvitation) -> Result<Vec<u8>, ()> {
    let body = invitation.to_wire();
    if !BODY.contains(&body.len()) {
        return Err(());
    }
    let mut frame = Vec::with_capacity(MAX_FRAME);
    frame.extend_from_slice(b"UACUSB\x01");
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}
pub(crate) fn decode(frame: &[u8]) -> Result<PairingInvitation, ()> {
    if frame.len() < 9 || &frame[..7] != b"UACUSB\x01" {
        return Err(());
    }
    let length = u16::from_be_bytes([frame[7], frame[8]]) as usize;
    if !BODY.contains(&length) || frame.len() != length + 9 {
        return Err(());
    }
    PairingInvitation::from_wire(&frame[9..]).map_err(|_| ())
}
