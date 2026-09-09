// SPDX-License-Identifier: GPL-2.0-or-later
//! One bounded composite: decision revisions and all three public-key roles.
#![forbid(unsafe_code)]

#[cfg(any(windows, test))]
use std::{collections::BTreeMap, fmt};

use approval_core::DeviceKeys;
#[cfg(any(windows, test))]
use approval_core::{PrivilegedDeviceRegistry, RegistryCheckpoint, RegistryCheckpointEntry};
use approval_protocol::DecisionPublicKey;
#[cfg(any(windows, test))]
use approval_protocol::DeviceId;
use secure_channel::TlsPublicKey;

use super::RegistryError;

#[cfg(any(windows, test))]
const VERSION: u16 = 1;
#[cfg(any(windows, test))]
const HEADER_BYTES: usize = 14;
#[cfg(any(windows, test))]
const ENTRY_BYTES: usize = 181;
#[cfg(any(windows, test))]
pub(super) const MAX_DOCUMENT_BYTES: usize = HEADER_BYTES + 32 * ENTRY_BYTES;

/// Public evidence supplied only by the trusted enrollment owner. Shape and
/// role separation do not verify Android attestation or owner enrollment intent.
#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredDeviceKeys {
    decision: DeviceKeys,
    transport: TlsPublicKey,
}

impl RegisteredDeviceKeys {
    pub fn from_trusted_host(
        approval: DecisionPublicKey,
        denial: DecisionPublicKey,
        transport: TlsPublicKey,
    ) -> Result<Self, RegistryError> {
        let decision = DeviceKeys::new(approval, denial).map_err(|_| RegistryError::KeyReuse)?;
        let transport_point = transport_point(&transport)?;
        if decision.approval() == &transport_point || decision.denial() == &transport_point {
            return Err(RegistryError::KeyReuse);
        }
        Ok(Self {
            decision,
            transport,
        })
    }
}

fn transport_point(key: &TlsPublicKey) -> Result<DecisionPublicKey, RegistryError> {
    // TlsPublicKey already validated and round-tripped the ONLY canonical
    // 91-byte P-256 SPKI. Reparse the contained point; never slice raw caller DER.
    DecisionPublicKey::from_sec1_bytes(&key.as_spki_der()[26..])
        .map_err(|_| RegistryError::InvalidState)
}

#[cfg(any(windows, test))]
#[derive(Clone)]
pub(super) struct Document {
    pub(super) pc: DecisionPublicKey,
    pub(super) core: RegistryCheckpoint,
    transport: BTreeMap<DeviceId, TlsPublicKey>,
}

#[cfg(any(windows, test))]
impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistryDocument([redacted])")
    }
}

#[cfg(any(windows, test))]
impl Document {
    pub(super) fn empty(pc: DecisionPublicKey) -> Result<Self, RegistryError> {
        let core = PrivilegedDeviceRegistry::initialize_for_privileged_host(32)
            .map_err(|_| RegistryError::InvalidState)?
            .checkpoint_for_privileged_host();
        Self::new(pc, core, BTreeMap::new())
    }

    fn new(
        pc: DecisionPublicKey,
        core: RegistryCheckpoint,
        transport: BTreeMap<DeviceId, TlsPublicKey>,
    ) -> Result<Self, RegistryError> {
        if core.entries().len() != transport.len() {
            return Err(RegistryError::InvalidState);
        }
        let mut seen = vec![pc.clone()];
        for entry in core.entries() {
            let connection = transport
                .get(&entry.device_id())
                .ok_or(RegistryError::InvalidState)?;
            for key in [
                entry.keys().approval().clone(),
                entry.keys().denial().clone(),
                transport_point(connection)?,
            ] {
                if seen.contains(&key) {
                    return Err(RegistryError::KeyReuse);
                }
                seen.push(key);
            }
        }
        Ok(Self {
            pc,
            core,
            transport,
        })
    }

    pub(super) fn changed(&self, change: RegistryChange) -> Result<Self, RegistryError> {
        let mut core = PrivilegedDeviceRegistry::restore_for_privileged_host(self.core.clone())
            .map_err(|_| RegistryError::InvalidState)?;
        let mut transport = self.transport.clone();
        match change {
            RegistryChange::Enroll { device, keys } => {
                core.enroll_from_privileged_host(device, keys.decision)
                    .map_err(RegistryError::Enrollment)?;
                transport.insert(device, keys.transport);
            }
            RegistryChange::Replace { device, keys } => {
                core.replace_from_privileged_host(device, keys.decision)
                    .map_err(RegistryError::Enrollment)?;
                transport.insert(device, keys.transport);
            }
            RegistryChange::Revoke { device } => {
                core.revoke_from_privileged_host(device)
                    .map_err(RegistryError::Enrollment)?;
                transport
                    .remove(&device)
                    .ok_or(RegistryError::InvalidState)?;
            }
        }
        Self::new(
            self.pc.clone(),
            core.checkpoint_for_privileged_host(),
            transport,
        )
    }

    pub(super) fn transport(&self, device: DeviceId) -> Option<&TlsPublicKey> {
        self.transport.get(&device)
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_BYTES + self.core.entries().len() * ENTRY_BYTES);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&(self.core.capacity() as u16).to_be_bytes());
        out.extend_from_slice(&self.core.next_revision().to_be_bytes());
        out.extend_from_slice(&(self.core.entries().len() as u16).to_be_bytes());
        for entry in self.core.entries() {
            out.extend_from_slice(entry.device_id().as_bytes());
            out.extend_from_slice(&entry.revision().to_be_bytes());
            out.extend_from_slice(entry.keys().approval().compressed_sec1_bytes());
            out.extend_from_slice(entry.keys().denial().compressed_sec1_bytes());
            out.extend_from_slice(self.transport[&entry.device_id()].as_spki_der());
        }
        out
    }

    pub(super) fn decode(pc: DecisionPublicKey, bytes: &[u8]) -> Result<Self, RegistryError> {
        if !(HEADER_BYTES..=MAX_DOCUMENT_BYTES).contains(&bytes.len()) {
            return Err(RegistryError::InvalidState);
        }
        let mut input = Input(bytes);
        if u16::from_be_bytes(input.take()?) != VERSION {
            return Err(RegistryError::InvalidState);
        }
        let capacity = usize::from(u16::from_be_bytes(input.take()?));
        let next_revision = u64::from_be_bytes(input.take()?);
        let count = usize::from(u16::from_be_bytes(input.take()?));
        if count > 32 || bytes.len() != HEADER_BYTES + count * ENTRY_BYTES {
            return Err(RegistryError::InvalidState);
        }
        let mut entries = Vec::with_capacity(count);
        let mut transport = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let device =
                DeviceId::from_bytes(input.take()?).map_err(|_| RegistryError::InvalidState)?;
            if previous.is_some_and(|previous| previous >= device) {
                return Err(RegistryError::InvalidState);
            }
            previous = Some(device);
            let revision = u64::from_be_bytes(input.take()?);
            let approval = DecisionPublicKey::from_sec1_bytes(&input.take::<33>()?)
                .map_err(|_| RegistryError::InvalidState)?;
            let denial = DecisionPublicKey::from_sec1_bytes(&input.take::<33>()?)
                .map_err(|_| RegistryError::InvalidState)?;
            let connection = TlsPublicKey::from_spki_der(&input.take::<91>()?)
                .map_err(|_| RegistryError::InvalidState)?;
            let keys = RegisteredDeviceKeys::from_trusted_host(approval, denial, connection)?;
            entries.push(
                RegistryCheckpointEntry::new(device, revision, keys.decision)
                    .map_err(|_| RegistryError::InvalidState)?,
            );
            transport.insert(device, keys.transport);
        }
        let core = RegistryCheckpoint::new(capacity, next_revision, entries)
            .map_err(|_| RegistryError::InvalidState)?;
        let result = Self::new(pc, core, transport)?;
        if result.encode() != bytes {
            return Err(RegistryError::InvalidState);
        }
        Ok(result)
    }
}

#[cfg(any(windows, test))]
#[derive(Debug)]
pub(super) enum RegistryChange {
    Enroll {
        device: DeviceId,
        keys: RegisteredDeviceKeys,
    },
    Replace {
        device: DeviceId,
        keys: RegisteredDeviceKeys,
    },
    Revoke {
        device: DeviceId,
    },
}

#[cfg(any(windows, test))]
pub(super) struct Input<'a>(pub(super) &'a [u8]);
#[cfg(any(windows, test))]
impl Input<'_> {
    pub(super) fn take<const N: usize>(&mut self) -> Result<[u8; N], RegistryError> {
        let value = self.0.get(..N).ok_or(RegistryError::InvalidState)?;
        let value = value.try_into().map_err(|_| RegistryError::InvalidState)?;
        self.0 = &self.0[N..];
        Ok(value)
    }
}
