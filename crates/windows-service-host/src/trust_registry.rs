// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-owned trust persistence; no local/remote enrollment or signing RPC.
#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
mod journal;
mod model;

use approval_core::{EnrollmentError, RegistryCheckpoint};
use approval_protocol::DeviceId;
use secure_channel::TlsPublicKey;
use std::fmt;
use thiserror::Error;

pub use model::RegisteredDeviceKeys;
#[cfg(windows)]
use {
    journal::{Journal, PreparedWrite},
    model::RegistryChange,
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    #[error("device-registry data is invalid")]
    InvalidState,
    #[error("device public keys must be distinct across roles and identities")]
    KeyReuse,
    #[error("device enrollment change was rejected: {0}")]
    Enrollment(EnrollmentError),
    #[error("device-registry maintenance is required before authorization continues")]
    MaintenanceRequired,
    #[error("the device-registry owner is unavailable; no rollback is implied")]
    Unavailable,
    #[error("device-registry operation is unavailable on this platform")]
    UnsupportedPlatform,
}

/// The containing service must invalidate this device's old handshakes/transport
/// and serialize the matching engine mutation before authorizing more requests.
/// This receipt proves only a flushed local registry mutation, not those effects,
/// Android attestation, owner enrollment intent, or actual Windows approval.
#[must_use = "apply the matching engine change and invalidate old peer generations before continuing"]
#[derive(Debug)]
pub struct CommittedRegistryChange {
    device: DeviceId,
}
impl CommittedRegistryChange {
    pub const fn affected_device(&self) -> DeviceId {
        self.device
    }
}

/// An unconstructible-outside-this-crate, non-Clone service-worker resource.
/// Constructors are private to the actual SCM worker, not UI/CLI/network data.
/// Public Rust methods are integration seams, not exported commands. The current
/// host only initializes/restores the store; no enrollment caller is wired yet.
pub struct ServiceRegistry<'identity> {
    #[cfg(windows)]
    file: crate::ffi::ServiceTrustFile,
    #[cfg(windows)]
    state: Option<Journal>,
    #[cfg(windows)]
    _identity: &'identity windows_identity::PcIdentityKey,
    #[cfg(not(windows))]
    _unconstructible: std::convert::Infallible,
    #[cfg(not(windows))]
    _lifetime: std::marker::PhantomData<&'identity ()>,
}
impl fmt::Debug for ServiceRegistry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceRegistry([redacted])")
    }
}

impl ServiceRegistry<'_> {
    pub fn checkpoint_for_engine(&mut self) -> Result<RegistryCheckpoint, RegistryError> {
        #[cfg(windows)]
        {
            Ok(self.healthy()?.document.core.clone())
        }
        #[cfg(not(windows))]
        {
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    pub fn transport_key(
        &mut self,
        device: DeviceId,
    ) -> Result<Option<TlsPublicKey>, RegistryError> {
        #[cfg(windows)]
        {
            Ok(self.healthy()?.document.transport(device).cloned())
        }
        #[cfg(not(windows))]
        {
            let _ = device;
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    /// Caller has already verified the still-live, owner-approved enrollment
    /// ceremony and this exact hardware/auth-policy key bundle. Neither this
    /// method nor its argument constructor establishes that prerequisite.
    pub fn enroll_from_privileged_owner(
        &mut self,
        device: DeviceId,
        keys: RegisteredDeviceKeys,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        #[cfg(windows)]
        {
            self.change(device, RegistryChange::Enroll { device, keys })
        }
        #[cfg(not(windows))]
        {
            let _ = (device, keys);
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    pub fn replace_from_privileged_owner(
        &mut self,
        device: DeviceId,
        keys: RegisteredDeviceKeys,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        #[cfg(windows)]
        {
            self.change(device, RegistryChange::Replace { device, keys })
        }
        #[cfg(not(windows))]
        {
            let _ = (device, keys);
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    pub fn revoke_from_privileged_owner(
        &mut self,
        device: DeviceId,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        #[cfg(windows)]
        {
            self.change(device, RegistryChange::Revoke { device })
        }
        #[cfg(not(windows))]
        {
            let _ = device;
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    pub fn close(self) -> Result<(), RegistryError> {
        #[cfg(windows)]
        {
            self.file.close().map_err(|_| RegistryError::Unavailable)
        }
        #[cfg(not(windows))]
        {
            Err(RegistryError::UnsupportedPlatform)
        }
    }
}

#[cfg(windows)]
impl<'identity> ServiceRegistry<'identity> {
    pub(crate) fn open_existing(
        identity: &'identity windows_identity::PcIdentityKey,
        directory: crate::ffi::TrustDirectory,
    ) -> Result<Self, RegistryError> {
        let pc = Self::pc(identity)?;
        let mut file = directory
            .open_existing()
            .map_err(|_| RegistryError::Unavailable)?;
        let bytes = file
            .read_bounded()
            .map_err(|_| RegistryError::Unavailable)?;
        let state = Journal::restore(pc, &bytes)?;
        state.ensure_writable()?;
        Ok(Self {
            file,
            state: Some(state),
            _identity: identity,
        })
    }

    /// Called only in runtime's actual successful-new-key branch after verifying
    /// the fixed trust directory was empty. Not a first-QR/enrollment grant.
    pub(crate) fn initialize_empty_after_key_creation(
        identity: &'identity windows_identity::PcIdentityKey,
        directory: crate::ffi::TrustDirectory,
    ) -> Result<Self, RegistryError> {
        let prepared = Journal::initial(Self::pc(identity)?)?;
        let file = directory
            .create_new()
            .map_err(|_| RegistryError::Unavailable)?;
        let mut owner = Self {
            file,
            state: None,
            _identity: identity,
        };
        owner.publish(prepared)?;
        Ok(owner)
    }

    fn pc(
        identity: &windows_identity::PcIdentityKey,
    ) -> Result<approval_protocol::DecisionPublicKey, RegistryError> {
        let public = identity
            .public_sec1()
            .map_err(|_| RegistryError::Unavailable)?;
        approval_protocol::DecisionPublicKey::from_sec1_bytes(public.as_sec1_bytes())
            .map_err(|_| RegistryError::InvalidState)
    }

    fn healthy(&mut self) -> Result<&Journal, RegistryError> {
        if windows_identity::verify_service_context().is_err() {
            self.state = None;
            return Err(RegistryError::Unavailable);
        }
        let status = self
            .state
            .as_ref()
            .ok_or(RegistryError::Unavailable)?
            .ensure_writable();
        if let Err(error) = status {
            self.state = None;
            return Err(error);
        }
        self.state.as_ref().ok_or(RegistryError::Unavailable)
    }

    fn change(
        &mut self,
        device: DeviceId,
        change: RegistryChange,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        let prepared = self.healthy()?.prepare_change(change)?;
        self.publish(prepared)?;
        Ok(CommittedRegistryChange { device })
    }

    fn publish(&mut self, prepared: PreparedWrite) -> Result<(), RegistryError> {
        journal::publish(&mut self.state, &mut self.file, prepared)
    }
}

#[cfg(test)]
mod tests;
