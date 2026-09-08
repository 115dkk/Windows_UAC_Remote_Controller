// SPDX-License-Identifier: GPL-2.0-or-later
//! A bounded, exclusively owned TLS 1.3 channel over caller-owned relay bytes.
//!
//! Both endpoints pin one previously enrolled canonical P-256 raw public key.
//! This authenticates possession of a TRANSPORT key, never phone approval,
//! per-use OS authentication, enrollment consent, hardware provenance or a UAC
//! result. Native owners must keep transport, approval and denial keys distinct.
//! No production key generator, private-key export, PKI root, socket or UI API is
//! provided. Only a trusted host may supply the signer and enrolled peer pin.
//!
//! The PC emits an encrypted fixed readiness preface only after validating the
//! client's CertificateVerify and Finished. The client consumes that preface
//! before application I/O is available. Server readiness does not prove that the
//! client has received the preface. Application framing/decisions are separate.
//!
//! Every mutating operation requires a fresh trusted host Instant. Serialize
//! revocation with channel ownership: close the channel immediately and perform
//! a fresh registry check before constructing a replacement. An established TLS
//! channel cannot discover a later registry revocation on its own.
//! The host clock must include suspend time. On Android, raw std::Instant may
//! exclude deep sleep: the native owner must consistently project its trusted
//! elapsedRealtimeNanos counter onto one Instant origin using checked arithmetic.
//! Mixing that projection with raw Instant::now is forbidden. PC request expiry
//! is an independent control, not replaced by this transport deadline.

#![forbid(unsafe_code)]

mod channel;
mod config;
mod identity;
mod key;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use channel::{Channel, ChannelError, ChannelStatus, EofDisposition, PlaintextRead};
pub use identity::{
    CertificateVerifyInput, EndpointRole, PlatformTlsSigner, SignerError, TlsIdentity,
};
pub use key::{CertificateVerifySignature, KeyError, SignatureError, TlsPublicKey};

pub const ALPN: &[u8] = b"wuac-control/1";
pub const MAX_INGRESS_BYTES: usize = 16 * 1024;
pub const MAX_PLAINTEXT_WRITE_BYTES: usize = 16 * 1024;
pub const MAX_DRAIN_BYTES: usize = 16 * 1024;
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024;
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const READY_PREFACE: &[u8; 18] = b"WUAC-TLS13-READY\0\x01";
