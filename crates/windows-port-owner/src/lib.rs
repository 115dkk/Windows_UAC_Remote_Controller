// SPDX-License-Identifier: GPL-2.0-or-later
//! Read-only TCP listener ownership, not process identity or authorization proof.
//! Observations can race process exit/PID reuse. No elevation, process mutation,
//! command line or full image path is exposed.
#![deny(unsafe_code)]

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;
mod name;

/// Check diagnostic file-name text before publishing or accepting local IPC.
/// Uses the same Cc/Cf exclusions and 64-character bound as the OS observation.
pub fn valid_image_name(value: &str) -> bool {
    name::valid(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerOwner {
    pub pid: u32,
    pub image_name: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PortOwnerError {
    #[error("TCP listener ownership is supported only on Windows")]
    Unsupported,
    #[error("Windows TCP table query failed ({code})")]
    WindowsCall { code: u32 },
    #[error("Windows TCP table exceeds the diagnostic bounds")]
    InvalidTable,
}

/// A process other than this one listening on TCP `port` on any local IPv4 or IPv6 address.
pub fn listener_owner(port: u16) -> Result<Option<ListenerOwner>, PortOwnerError> {
    #[cfg(windows)]
    {
        ffi::listener_owner(port)
    }
    #[cfg(not(windows))]
    {
        let _ = port;
        Err(PortOwnerError::Unsupported)
    }
}

/// Require exclusive address use before binding this Windows listening socket.
/// The caller retains ownership; no socket handle escapes or is closed here.
#[cfg(windows)]
pub fn set_exclusive_address_use(socket: &socket2::Socket) -> std::io::Result<()> {
    ffi::set_exclusive_address_use(socket)
}
