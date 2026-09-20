// SPDX-License-Identifier: GPL-2.0-or-later
//! Public bootstrap bytes only, never a USB authentication/approval protocol.
#![forbid(unsafe_code)]
use service_protocol::PairingInvitation;

pub(crate) const MAX_FRAME: usize = 366;
pub(crate) fn encode(invitation: &PairingInvitation) -> Result<Vec<u8>, ()> {
    let body = invitation.to_wire();
    if ![345, 357].contains(&body.len()) {
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
    if ![345, 357].contains(&length) || frame.len() != length + 9 {
        return Err(());
    }
    PairingInvitation::from_wire(&frame[9..]).map_err(|_| ())
}
