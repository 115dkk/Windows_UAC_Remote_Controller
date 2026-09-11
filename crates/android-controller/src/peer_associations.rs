// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded phone peer-association relationships for the SAME durable owner.
//!
//! This module validates STRUCTURE, not enrollment authority. Only a trusted
//! native enrollment owner may record a descriptor after actually validating
//! the PC grant/receipt, endpoint/key ownership, current revision and required
//! attestation/policy. No renderer or foreign-callback enrollment API is supplied.
//! CreatedUnverified local metadata never creates an association by itself.
//!
//! Local generations invalidate stale request/approval references after removal
//! and re-enrollment. They do not prove freshness of a restored file or a remote
//! PC revision. Persist this ledger with its LocalKeyLedger in one protected
//! controller transaction; publish no association/pin/action before that commit.
//! Loading an older well-formed snapshot cannot be detected by this codec alone.
//! Revalidate global local-key relationships after every local-key mutation too.
//!
//! No signing, networking, native key generation, pairing UI, bulk replacement,
//! key deletion, hidden ban list, authentication boolean or automatic recovery.

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::{DeviceId, PcIdentity};
use secure_channel::TlsPublicKey;
use thiserror::Error;

use crate::{LocalKeyHandle, LocalKeyLedger};

pub const MAX_PEER_ASSOCIATIONS: usize = 32;
const MAGIC: &[u8; 8] = b"UACPEER\0";
const VERSION: u16 = 2;
const LEGACY_VERSION: u16 = 1;
const HEADER_BYTES: usize = 24;
const LEGACY_RECORD_BYTES: usize = 32 + 16 + 8 + 32 + 91 + 91 + 8;
const RELAY_RECORD_BYTES: usize = 1 + 1 + 2 + 16 + 32;
const RECORD_BYTES: usize = LEGACY_RECORD_BYTES + RELAY_RECORD_BYTES;
/// Exact v2 maximum: header24 + 32 fixed330-byte active association records.
pub const MAX_PEER_ASSOCIATION_LEDGER_BYTES: usize =
    HEADER_BYTES + MAX_PEER_ASSOCIATIONS * RECORD_BYTES;

/// Numeric public rendezvous coordinates retained from the original invitation.
/// They identify a relay meeting point but grant no authority and contain no secret.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RelayEndpoint {
    pub address: SocketAddr,
    pub route: [u8; 32],
}
impl RelayEndpoint {
    pub fn new(address: SocketAddr, route: [u8; 32]) -> Result<Self, PeerAssociationError> {
        validate_relay(address, &route)?;
        Ok(Self { address, route })
    }
}
impl fmt::Debug for RelayEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RelayEndpoint([redacted], public_rendezvous_only)")
    }
}

/// Immutable host-supplied relationship, not a verified PC receipt. TlsPublicKey
/// is reused as the canonical 91-byte P-256 SPKI representation for BOTH PC roles;
/// a valid curve point does not establish its role, enrollment or ownership.
#[derive(Clone, PartialEq)]
pub struct PeerAssociationDescriptor {
    pc: PcIdentity,
    recipient_device_id: DeviceId,
    pc_registry_revision: u64,
    local_key_handle: LocalKeyHandle,
    pc_signing_key: TlsPublicKey,
    pc_transport_key: TlsPublicKey,
    relay: Option<RelayEndpoint>,
}

impl PeerAssociationDescriptor {
    pub fn new(
        pc: PcIdentity,
        recipient_device_id: DeviceId,
        pc_registry_revision: u64,
        local_key_handle: LocalKeyHandle,
        pc_signing_key: TlsPublicKey,
        pc_transport_key: TlsPublicKey,
    ) -> Result<Self, PeerAssociationError> {
        if pc_registry_revision == 0 {
            return Err(PeerAssociationError::InvalidPcRegistryRevision);
        }
        // The same PC may deliberately use one domain-separated key for both
        // roles. Cross-PC and global local-role isolation are ledger checks.
        Ok(Self {
            pc,
            recipient_device_id,
            pc_registry_revision,
            local_key_handle,
            pc_signing_key,
            pc_transport_key,
            relay: None,
        })
    }
    pub fn with_relay(
        mut self,
        address: SocketAddr,
        route: [u8; 32],
    ) -> Result<Self, PeerAssociationError> {
        self.relay = Some(RelayEndpoint::new(address, route)?);
        Ok(self)
    }
    pub const fn pc(&self) -> PcIdentity {
        self.pc
    }
    pub const fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }
    pub const fn pc_registry_revision(&self) -> u64 {
        self.pc_registry_revision
    }
    pub const fn local_key_handle(&self) -> LocalKeyHandle {
        self.local_key_handle
    }
    pub const fn pc_signing_key(&self) -> &TlsPublicKey {
        &self.pc_signing_key
    }
    pub const fn pc_transport_key(&self) -> &TlsPublicKey {
        &self.pc_transport_key
    }
    pub const fn relay(&self) -> Option<(SocketAddr, [u8; 32])> {
        match self.relay {
            Some(relay) => Some((relay.address, relay.route)),
            None => None,
        }
    }
    fn pc_keys(&self) -> [&TlsPublicKey; 2] {
        [&self.pc_signing_key, &self.pc_transport_key]
    }
    fn shares_pc_key(&self, other: &Self) -> bool {
        self.pc_keys()
            .into_iter()
            .any(|key| other.pc_keys().contains(&key))
    }
}
impl fmt::Debug for PeerAssociationDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("PeerAssociationDescriptor([redacted], host_supplied_not_authentication)")
    }
}

/// Current-reference identity only. No public constructor and no authority claim:
/// the future receiving/approval owner must resolve it against current state.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PeerAssociationRef {
    pc: PcIdentity,
    generation: u64,
}
impl PeerAssociationRef {
    pub const fn pc(self) -> PcIdentity {
        self.pc
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
impl fmt::Debug for PeerAssociationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerAssociationRef([redacted], current_lookup_required)")
    }
}

#[derive(Clone, PartialEq)]
pub struct PeerAssociation {
    descriptor: PeerAssociationDescriptor,
    generation: u64,
}
impl PeerAssociation {
    pub const fn descriptor(&self) -> &PeerAssociationDescriptor {
        &self.descriptor
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn reference(&self) -> PeerAssociationRef {
        PeerAssociationRef {
            pc: self.descriptor.pc,
            generation: self.generation,
        }
    }
}
impl fmt::Debug for PeerAssociation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAssociation")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Pure transaction candidate. Bounded Clone is metadata, never a second native
/// owner or a committed grant. Removal preserves the next-generation highwater.
#[derive(Clone, PartialEq)]
pub struct PeerAssociationLedger {
    entries: BTreeMap<PcIdentity, PeerAssociation>,
    next_generation: u64,
}
impl Default for PeerAssociationLedger {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_generation: 1,
        }
    }
}
impl fmt::Debug for PeerAssociationLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerAssociationLedger")
            .field("active_count", &self.entries.len())
            .field("next_generation", &self.next_generation)
            .finish_non_exhaustive()
    }
}

impl PeerAssociationLedger {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub const fn next_generation(&self) -> u64 {
        self.next_generation
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &PeerAssociation> + DoubleEndedIterator {
        self.entries.values()
    }
    pub fn lookup_current(&self, pc: PcIdentity) -> Option<&PeerAssociation> {
        self.entries.get(&pc)
    }
    /// Local membership/generation lookup only. The composite must already have
    /// validated local-key relationships; current native/peer authority is a
    /// separate receiving-owner check, never inferred from Some(entry).
    pub fn resolve(&self, reference: PeerAssociationRef) -> Option<&PeerAssociation> {
        self.entries
            .get(&reference.pc)
            .filter(|entry| entry.generation == reference.generation)
    }

    /// Trusted-native enrollment boundary, not caller authentication. A native
    /// host must already possess the real current enrollment authority; neither
    /// this name, a parsed descriptor nor local key observation supplies it.
    /// Exact active repeats are idempotent. Any conflicting PC tuple requires
    /// explicit removal and new trusted enrollment, never implicit overwrite.
    /// Every rejection leaves BOTH active state and highwater unchanged.
    pub fn record_from_trusted_host(
        &mut self,
        descriptor: PeerAssociationDescriptor,
        local_keys: &LocalKeyLedger,
    ) -> Result<PeerAssociationMutation, PeerAssociationError> {
        self.validate_relationships(local_keys)?;
        validate_local_relationship(&descriptor, local_keys)?;
        if let Some(existing) = self.entries.get(&descriptor.pc) {
            return if existing.descriptor == descriptor {
                Ok(PeerAssociationMutation::AlreadyRecorded(
                    existing.reference(),
                ))
            } else {
                Err(PeerAssociationError::ConflictRequiresRemoval)
            };
        }
        if self.entries.len() == MAX_PEER_ASSOCIATIONS {
            return Err(PeerAssociationError::CapacityReached);
        }
        for existing in self.entries.values() {
            validate_pair(&existing.descriptor, &descriptor)?;
        }
        let following = self
            .next_generation
            .checked_add(1)
            .ok_or(PeerAssociationError::GenerationExhausted)?;
        let reference = PeerAssociationRef {
            pc: descriptor.pc,
            generation: self.next_generation,
        };
        self.entries.insert(
            descriptor.pc,
            PeerAssociation {
                descriptor,
                generation: reference.generation,
            },
        );
        self.next_generation = following;
        Ok(PeerAssociationMutation::Recorded(reference))
    }

    /// Downward-only exact-generation removal, including when local keys are
    /// unavailable. A delayed stale remove cannot remove a replacement. No key
    /// deletion occurs; NotCurrent does not assert that another state was removed.
    pub fn remove_from_trusted_host(
        &mut self,
        reference: PeerAssociationRef,
    ) -> PeerAssociationRemoval {
        if self.resolve(reference).is_none() {
            return PeerAssociationRemoval::NotCurrent;
        }
        self.entries.remove(&reference.pc);
        PeerAssociationRemoval::Removed
    }

    /// Mandatory composite check on load and after EVERY local-key mutation.
    /// Referenced handles must be CreatedUnverified, and neither PC key may
    /// equal ANY Created local set's approval/denial/transport key. This never
    /// upgrades those local keys or proves the PC's receipt/registry revision.
    pub fn validate_relationships(
        &self,
        local_keys: &LocalKeyLedger,
    ) -> Result<(), PeerAssociationError> {
        self.validate_shape()?;
        for entry in self.entries.values() {
            validate_local_relationship(&entry.descriptor, local_keys)?;
        }
        Ok(())
    }

    /// Own-shape codec only. The containing controller MUST separately validate
    /// relationships with its local ledger before accepting the combined state.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PeerAssociationError> {
        self.validate_shape()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(HEADER_BYTES + self.entries.len() * RECORD_BYTES)
            .map_err(|_| PeerAssociationError::AllocationFailed)?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.next_generation.to_be_bytes());
        bytes.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        for entry in self.entries.values() {
            let descriptor = &entry.descriptor;
            bytes.extend_from_slice(descriptor.pc.as_bytes());
            bytes.extend_from_slice(descriptor.recipient_device_id.as_bytes());
            bytes.extend_from_slice(&descriptor.pc_registry_revision.to_be_bytes());
            bytes.extend_from_slice(descriptor.local_key_handle.as_bytes());
            bytes.extend_from_slice(descriptor.pc_signing_key.as_spki_der());
            bytes.extend_from_slice(descriptor.pc_transport_key.as_spki_der());
            bytes.extend_from_slice(&entry.generation.to_be_bytes());
            write_relay(&mut bytes, descriptor.relay);
        }
        Ok(bytes)
    }

    /// Strict fixed-record v1/v2 restore; no truncation/default/reordering on error.
    /// V1 rows receive no relay endpoint. All newly written rows use v2.
    /// Preserves even an empty ledger's highwater, including u64::MAX exhaustion.
    /// Decoding proves neither current disk provenance nor native enrollment.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerAssociationError> {
        if bytes.len() > MAX_PEER_ASSOCIATION_LEDGER_BYTES {
            return Err(PeerAssociationError::TooLarge);
        }
        let mut input = Input { bytes, offset: 0 };
        if input.take::<8>()? != *MAGIC {
            return Err(PeerAssociationError::InvalidEncoding);
        }
        let version = u16::from_be_bytes(input.take()?);
        let record_bytes = match version {
            LEGACY_VERSION => LEGACY_RECORD_BYTES,
            VERSION => RECORD_BYTES,
            _ => return Err(PeerAssociationError::UnsupportedVersion),
        };
        if input.take::<2>()? != [0; 2] {
            return Err(PeerAssociationError::InvalidEncoding);
        }
        let next_generation = u64::from_be_bytes(input.take()?);
        if next_generation == 0 {
            return Err(PeerAssociationError::InvalidGeneration);
        }
        let count = usize::from(u16::from_be_bytes(input.take()?));
        if count > MAX_PEER_ASSOCIATIONS {
            return Err(PeerAssociationError::CapacityReached);
        }
        if input.take::<2>()? != [0; 2] || bytes.len() != HEADER_BYTES + count * record_bytes {
            return Err(PeerAssociationError::InvalidEncoding);
        }
        let mut entries = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let pc = PcIdentity::from_bytes(input.take()?)
                .map_err(|_| PeerAssociationError::InvalidIdentity)?;
            if let Some(prior) = previous {
                if pc == prior {
                    return Err(PeerAssociationError::DuplicatePcIdentity);
                }
                if pc < prior {
                    return Err(PeerAssociationError::NonCanonicalOrder);
                }
            }
            previous = Some(pc);
            let recipient = DeviceId::from_bytes(input.take()?)
                .map_err(|_| PeerAssociationError::InvalidIdentity)?;
            let revision = u64::from_be_bytes(input.take()?);
            let handle = LocalKeyHandle::from_bytes(input.take()?)
                .map_err(|_| PeerAssociationError::InvalidIdentity)?;
            let signing = read_key(&mut input)?;
            let transport = read_key(&mut input)?;
            let generation = u64::from_be_bytes(input.take()?);
            let relay = if version == VERSION {
                read_relay(&mut input)?
            } else {
                None
            };
            let mut descriptor = PeerAssociationDescriptor::new(
                pc, recipient, revision, handle, signing, transport,
            )?;
            if let Some(relay) = relay {
                descriptor = descriptor.with_relay(relay.address, relay.route)?;
            }
            entries.insert(
                pc,
                PeerAssociation {
                    descriptor,
                    generation,
                },
            );
        }
        let ledger = Self {
            entries,
            next_generation,
        };
        ledger.validate_shape()?;
        Ok(ledger)
    }

    fn validate_shape(&self) -> Result<(), PeerAssociationError> {
        if self.entries.len() > MAX_PEER_ASSOCIATIONS {
            return Err(PeerAssociationError::CapacityReached);
        }
        if self.next_generation == 0 {
            return Err(PeerAssociationError::InvalidGeneration);
        }
        for (index, (pc, entry)) in self.entries.iter().enumerate() {
            if *pc != entry.descriptor.pc {
                return Err(PeerAssociationError::InvalidIdentity);
            }
            if entry.generation == 0 || entry.generation >= self.next_generation {
                return Err(PeerAssociationError::InvalidGeneration);
            }
            if entry.descriptor.pc_registry_revision == 0 {
                return Err(PeerAssociationError::InvalidPcRegistryRevision);
            }
            if let Some(relay) = entry.descriptor.relay {
                validate_relay(relay.address, &relay.route)?;
            }
            for previous in self.entries.values().take(index) {
                if previous.generation == entry.generation {
                    return Err(PeerAssociationError::DuplicateGeneration);
                }
                validate_pair(&previous.descriptor, &entry.descriptor)?;
            }
        }
        Ok(())
    }
}

fn validate_relay(address: SocketAddr, route: &[u8; 32]) -> Result<(), PeerAssociationError> {
    if address.port() == 0 {
        return Err(PeerAssociationError::InvalidRelayPort);
    }
    if route.iter().all(|byte| *byte == 0) {
        return Err(PeerAssociationError::InvalidRelayRoute);
    }
    Ok(())
}

fn write_relay(bytes: &mut Vec<u8>, relay: Option<RelayEndpoint>) {
    let Some(relay) = relay else {
        bytes.extend_from_slice(&[0; RELAY_RECORD_BYTES]);
        return;
    };
    bytes.push(1);
    match relay.address.ip() {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&relay.address.port().to_be_bytes());
            bytes.extend_from_slice(&address.octets());
            bytes.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&relay.address.port().to_be_bytes());
            bytes.extend_from_slice(&address.octets());
        }
    }
    bytes.extend_from_slice(&relay.route);
}

fn read_relay(input: &mut Input<'_>) -> Result<Option<RelayEndpoint>, PeerAssociationError> {
    let present = input.take::<1>()?[0];
    let family = input.take::<1>()?[0];
    let port = u16::from_be_bytes(input.take()?);
    let address = input.take::<16>()?;
    let route = input.take::<32>()?;
    match present {
        0 if family == 0 && port == 0 && address == [0; 16] && route == [0; 32] => Ok(None),
        0 => Err(PeerAssociationError::InvalidRelayEncoding),
        1 => {
            if port == 0 {
                return Err(PeerAssociationError::InvalidRelayPort);
            }
            if route.iter().all(|byte| *byte == 0) {
                return Err(PeerAssociationError::InvalidRelayRoute);
            }
            let ip = match family {
                4 if address[4..] == [0; 12] => IpAddr::V4(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                )),
                4 => return Err(PeerAssociationError::InvalidRelayEncoding),
                6 => IpAddr::V6(Ipv6Addr::from(address)),
                _ => return Err(PeerAssociationError::InvalidRelayFamily),
            };
            RelayEndpoint::new(SocketAddr::new(ip, port), route).map(Some)
        }
        _ => Err(PeerAssociationError::InvalidRelayEncoding),
    }
}

fn validate_pair(
    first: &PeerAssociationDescriptor,
    second: &PeerAssociationDescriptor,
) -> Result<(), PeerAssociationError> {
    if first.local_key_handle == second.local_key_handle {
        return Err(PeerAssociationError::LocalHandleAlreadyAssociated);
    }
    if first.recipient_device_id == second.recipient_device_id {
        return Err(PeerAssociationError::DeviceAlreadyAssociated);
    }
    if first.shares_pc_key(second) {
        return Err(PeerAssociationError::PcKeyReuse);
    }
    Ok(())
}

fn validate_local_relationship(
    descriptor: &PeerAssociationDescriptor,
    local_keys: &LocalKeyLedger,
) -> Result<(), PeerAssociationError> {
    if local_keys
        .get(descriptor.local_key_handle)
        .and_then(|phase| phase.descriptor())
        .is_none()
    {
        return Err(PeerAssociationError::LocalKeyUnavailable);
    }
    for local in local_keys.entries().filter_map(|phase| phase.descriptor()) {
        let local_roles = [
            local.approval_key(),
            local.denial_key(),
            local.transport_key(),
        ];
        if descriptor
            .pc_keys()
            .into_iter()
            .any(|key| local_roles.contains(&key))
        {
            return Err(PeerAssociationError::PcKeyMatchesLocalKey);
        }
    }
    Ok(())
}

/// In-memory relationship result only, not an enrollment/commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAssociationMutation {
    Recorded(PeerAssociationRef),
    AlreadyRecorded(PeerAssociationRef),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAssociationRemoval {
    Removed,
    NotCurrent,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PeerAssociationError {
    #[error("peer association PC registry revision must be nonzero")]
    InvalidPcRegistryRevision,
    #[error("peer association conflicts with current membership; explicit removal is required")]
    ConflictRequiresRemoval,
    #[error("peer association contains a duplicate PC identity")]
    DuplicatePcIdentity,
    #[error("peer association local handle is already assigned to another PC")]
    LocalHandleAlreadyAssociated,
    #[error("peer association recipient device is already assigned to another PC")]
    DeviceAlreadyAssociated,
    #[error("peer association PC public key is reused across PCs")]
    PcKeyReuse,
    #[error("peer association references no created local key set")]
    LocalKeyUnavailable,
    #[error("peer association PC key matches a local role key")]
    PcKeyMatchesLocalKey,
    #[error("peer association capacity reached")]
    CapacityReached,
    #[error("peer association generation allocation is exhausted")]
    GenerationExhausted,
    #[error("peer association generation or highwater is invalid")]
    InvalidGeneration,
    #[error("peer association generation is reused")]
    DuplicateGeneration,
    #[error("peer association identity is invalid")]
    InvalidIdentity,
    #[error("peer association key is not canonical P-256 SPKI")]
    InvalidPublicKey,
    #[error("peer association encoding is invalid")]
    InvalidEncoding,
    #[error("peer association relay endpoint encoding is invalid")]
    InvalidRelayEncoding,
    #[error("peer association relay address family is invalid")]
    InvalidRelayFamily,
    #[error("peer association relay port must be nonzero")]
    InvalidRelayPort,
    #[error("peer association relay route must be nonzero")]
    InvalidRelayRoute,
    #[error("peer association version is unsupported")]
    UnsupportedVersion,
    #[error("peer association encoding exceeds its byte limit")]
    TooLarge,
    #[error("peer association PC records are not in canonical order")]
    NonCanonicalOrder,
    #[error("bounded peer association encoding allocation failed")]
    AllocationFailed,
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Input<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PeerAssociationError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PeerAssociationError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PeerAssociationError::InvalidEncoding)?
            .try_into()
            .map_err(|_| PeerAssociationError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
}
fn read_key(input: &mut Input<'_>) -> Result<TlsPublicKey, PeerAssociationError> {
    TlsPublicKey::from_spki_der(&input.take::<91>()?)
        .map_err(|_| PeerAssociationError::InvalidPublicKey)
}
