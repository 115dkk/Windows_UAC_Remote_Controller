// SPDX-License-Identifier: GPL-2.0-or-later
//! Service-owned trust persistence; no local/remote enrollment or signing RPC.
#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
mod journal;
mod model;

use android_attestation::{TrustedStatusSnapshot, VerificationPolicy, VerifiedKeyBundle};
use approval_core::{EnrollmentError, RegistryCheckpoint};
use approval_protocol::DeviceId;
use relay_service::RouteId;
use secure_channel::TlsPublicKey;
use std::{fmt, net::SocketAddr};
use thiserror::Error;

pub use model::RegisteredDeviceKeys;
#[cfg(windows)]
use {
    journal::{Journal, PreparedWrite},
    model::RegistryChange,
};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    #[error("device attestation evidence is unavailable or no longer current")]
    AttestationUnavailable,
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
    revision: u64,
}
impl CommittedRegistryChange {
    pub const fn affected_device(&self) -> DeviceId {
        self.device
    }

    pub const fn registry_revision(&self) -> u64 {
        self.revision
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

    pub fn device_routes(&mut self) -> Result<Vec<(DeviceId, SocketAddr, RouteId)>, RegistryError> {
        #[cfg(windows)]
        {
            Ok(self.healthy()?.document.device_routes())
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

    /// Caller must still verify the live owner-approved ceremony, possession,
    /// exact challenge/device/PC binding and original deadline. A key-property
    /// proof does not replace those conditions. Current policy/status identity
    /// and proof freshness are checked before this logical registry mutation.
    ///
    /// Shape-only keys cannot enter this service-owned mutation path:
    /// ```compile_fail
    /// use windows_service_host::{ServiceRegistry, RegisteredDeviceKeys};
    /// use approval_protocol::DeviceId;
    /// use android_attestation::{VerificationPolicy, TrustedStatusSnapshot};
    /// fn no_unverified_enrollment(owner: &mut ServiceRegistry<'_>, id: DeviceId, keys: RegisteredDeviceKeys, policy: &VerificationPolicy, status: &TrustedStatusSnapshot) {
    ///     let _ = owner.enroll_from_privileged_owner(id, keys, policy, status);
    /// }
    /// ```
    pub fn enroll_from_privileged_owner(
        &mut self,
        device: DeviceId,
        proof: VerifiedKeyBundle,
        current_policy: &VerificationPolicy,
        current_status: &TrustedStatusSnapshot,
        route: RouteId,
        relay: SocketAddr,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        #[cfg(windows)]
        {
            let keys = attested_keys(proof, current_policy, current_status)?;
            self.change(
                device,
                RegistryChange::Enroll {
                    device,
                    keys,
                    route,
                    relay,
                },
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (device, proof, current_policy, current_status, route, relay);
            Err(RegistryError::UnsupportedPlatform)
        }
    }

    /// Replacement has the same independent live-ceremony requirements as
    /// enrollment and cannot accept only syntactically valid public keys.
    /// ```compile_fail
    /// use windows_service_host::{ServiceRegistry, RegisteredDeviceKeys};
    /// use approval_protocol::DeviceId;
    /// use android_attestation::{VerificationPolicy, TrustedStatusSnapshot};
    /// fn no_unverified_replacement(owner: &mut ServiceRegistry<'_>, id: DeviceId, keys: RegisteredDeviceKeys, policy: &VerificationPolicy, status: &TrustedStatusSnapshot) {
    ///     let _ = owner.replace_from_privileged_owner(id, keys, policy, status);
    /// }
    /// ```
    pub fn replace_from_privileged_owner(
        &mut self,
        device: DeviceId,
        proof: VerifiedKeyBundle,
        current_policy: &VerificationPolicy,
        current_status: &TrustedStatusSnapshot,
        route: RouteId,
        relay: SocketAddr,
    ) -> Result<CommittedRegistryChange, RegistryError> {
        #[cfg(windows)]
        {
            let keys = attested_keys(proof, current_policy, current_status)?;
            self.change(
                device,
                RegistryChange::Replace {
                    device,
                    keys,
                    route,
                    relay,
                },
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (device, proof, current_policy, current_status, route, relay);
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
fn attested_keys(
    proof: VerifiedKeyBundle,
    policy: &VerificationPolicy,
    status: &TrustedStatusSnapshot,
) -> Result<RegisteredDeviceKeys, RegistryError> {
    let [approval, denial, transport] = proof
        .into_current_keys(policy, status)
        .map_err(|_| RegistryError::AttestationUnavailable)?;
    // All three SPKIs were canonical P-256 before certification; conversion only
    // changes their typed representation. It never infers trust from raw bytes.
    let approval =
        approval_protocol::DecisionPublicKey::from_sec1_bytes(&approval.as_spki_der()[26..])
            .map_err(|_| RegistryError::InvalidState)?;
    let denial = approval_protocol::DecisionPublicKey::from_sec1_bytes(&denial.as_spki_der()[26..])
        .map_err(|_| RegistryError::InvalidState)?;
    RegisteredDeviceKeys::from_trusted_host(approval, denial, transport)
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
        let core = &self.healthy()?.document.core;
        let revision = core
            .entries()
            .iter()
            .find(|entry| entry.device_id() == device)
            .map_or(core.next_revision() - 1, |entry| entry.revision());
        Ok(CommittedRegistryChange { device, revision })
    }

    fn publish(&mut self, prepared: PreparedWrite) -> Result<(), RegistryError> {
        journal::publish(&mut self.state, &mut self.file, prepared)
    }
}

#[cfg(test)]
mod tests;
