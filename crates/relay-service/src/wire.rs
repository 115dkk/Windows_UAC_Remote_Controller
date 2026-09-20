// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;
use thiserror::Error;

pub const HEADER_MAGIC: &[u8; 8] = b"WUACRLY\0";
pub const HEADER_BYTES: usize = 43;
pub const READY_MARKER: &[u8; 9] = b"WUACPAIR\0";

/// An opaque rendezvous name, not a secret enrollment token or trusted identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteId([u8; 32]);

impl RouteId {
    pub fn new(bytes: [u8; 32]) -> Result<Self, RegistrationError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RegistrationError::ZeroRoute);
        }
        Ok(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RouteId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RouteId([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Pc = 1,
    Phone = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registration {
    role: Role,
    route: RouteId,
}

impl Registration {
    pub const fn new(role: Role, route: RouteId) -> Self {
        Self { role, route }
    }
    pub const fn role(self) -> Role {
        self.role
    }
    pub const fn route(self) -> RouteId {
        self.route
    }

    pub fn to_wire(self) -> [u8; HEADER_BYTES] {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(HEADER_MAGIC);
        header[8..10].copy_from_slice(&1_u16.to_be_bytes());
        header[10] = self.role as u8;
        header[11..].copy_from_slice(self.route.as_bytes());
        header
    }

    pub fn from_wire(header: &[u8]) -> Result<Self, RegistrationError> {
        if header.len() != HEADER_BYTES {
            return Err(RegistrationError::Length);
        }
        if &header[..8] != HEADER_MAGIC {
            return Err(RegistrationError::Magic);
        }
        if header[8..10] != 1_u16.to_be_bytes() {
            return Err(RegistrationError::Version);
        }
        let role = match header[10] {
            1 => Role::Pc,
            2 => Role::Phone,
            _ => return Err(RegistrationError::Role),
        };
        let route = RouteId::new(
            header[11..]
                .try_into()
                .map_err(|_| RegistrationError::Length)?,
        )?;
        Ok(Self { role, route })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("relay registration has the wrong fixed length")]
    Length,
    #[error("relay registration magic is invalid")]
    Magic,
    #[error("relay registration version is unsupported")]
    Version,
    #[error("relay registration role is invalid")]
    Role,
    #[error("relay rendezvous route must not be zero")]
    ZeroRoute,
}
