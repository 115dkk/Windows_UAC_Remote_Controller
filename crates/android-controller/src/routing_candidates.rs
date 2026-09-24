// SPDX-License-Identifier: GPL-2.0-or-later
//! Durable routing coordinates only. No freshness, clock, authority or key state.
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use approval_protocol::PcIdentity;

use crate::{PeerAssociationLedger, PeerAssociationRef};

pub(crate) const MAX_CANDIDATE_BYTES: usize = 2 + 32 * (41 + 4 * 19);

#[derive(Clone, Default, PartialEq)]
pub(crate) struct RoutingCandidates(BTreeMap<PcIdentity, (u64, Vec<SocketAddr>)>);

impl RoutingCandidates {
    pub(crate) fn get(&self, reference: PeerAssociationRef) -> &[SocketAddr] {
        self.0
            .get(&reference.pc())
            .filter(|(generation, _)| *generation == reference.generation())
            .map_or(&[], |(_, addresses)| addresses.as_slice())
    }

    pub(crate) fn replace(
        &mut self,
        reference: PeerAssociationRef,
        endpoints: Vec<SocketAddr>,
    ) -> Result<(), ()> {
        if endpoints.len() > 4
            || endpoints.iter().enumerate().any(|(index, endpoint)| {
                !valid_endpoint(*endpoint) || endpoints[..index].contains(endpoint)
            })
        {
            return Err(());
        }
        if endpoints.is_empty() {
            self.0.remove(&reference.pc());
        } else {
            self.0
                .insert(reference.pc(), (reference.generation(), endpoints));
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, pc: PcIdentity) {
        self.0.remove(&pc);
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for (pc, (generation, addresses)) in &self.0 {
            bytes.extend_from_slice(pc.as_bytes());
            bytes.extend_from_slice(&generation.to_be_bytes());
            bytes.push(addresses.len() as u8);
            for address in addresses {
                match address.ip() {
                    IpAddr::V4(ip) => {
                        bytes.push(4);
                        bytes.extend_from_slice(&ip.octets());
                        bytes.extend_from_slice(&[0; 12]);
                    }
                    IpAddr::V6(ip) => {
                        bytes.push(6);
                        bytes.extend_from_slice(&ip.octets());
                    }
                }
                bytes.extend_from_slice(&address.port().to_be_bytes());
            }
        }
        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8], ledger: &PeerAssociationLedger) -> Result<Self, ()> {
        if bytes.len() < 2 || bytes.len() > MAX_CANDIDATE_BYTES {
            return Err(());
        }
        let count = usize::from(u16::from_be_bytes(bytes[..2].try_into().map_err(|_| ())?));
        if count > 32 {
            return Err(());
        }
        let mut remaining = &bytes[2..];
        let mut result = Self::default();
        let mut previous = None;
        for _ in 0..count {
            let header = remaining.get(..41).ok_or(())?;
            let pc =
                PcIdentity::from_bytes(header[..32].try_into().map_err(|_| ())?).map_err(|_| ())?;
            if previous.is_some_and(|prior| prior >= pc) {
                return Err(());
            }
            previous = Some(pc);
            let generation = u64::from_be_bytes(header[32..40].try_into().map_err(|_| ())?);
            let reference = ledger
                .lookup_current(pc)
                .filter(|entry| entry.generation() == generation)
                .ok_or(())?
                .reference();
            let address_count = usize::from(header[40]);
            if !(1..=4).contains(&address_count) {
                return Err(());
            }
            remaining = &remaining[41..];
            let mut endpoints = Vec::new();
            for _ in 0..address_count {
                let value = remaining.get(..19).ok_or(())?;
                let ip = match value[0] {
                    4 if value[5..17] == [0; 12] => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(&value[1..5]).map_err(|_| ())?,
                    )),
                    6 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&value[1..17]).map_err(|_| ())?,
                    )),
                    _ => return Err(()),
                };
                endpoints.push(SocketAddr::new(
                    ip,
                    u16::from_be_bytes(value[17..19].try_into().map_err(|_| ())?),
                ));
                remaining = &remaining[19..];
            }
            result.replace(reference, endpoints)?;
        }
        if !remaining.is_empty() {
            return Err(());
        }
        Ok(result)
    }
}

fn valid_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0
        || endpoint.ip().is_unspecified()
        || endpoint.ip().is_loopback()
        || endpoint.ip().is_multicast()
    {
        return false;
    }
    match endpoint {
        SocketAddr::V4(value) => {
            !value.ip().is_broadcast()
                && value.ip().octets()[0] != 0
                && value.ip().octets()[0] < 240
        }
        SocketAddr::V6(value) => {
            value.flowinfo() == 0
                && value.scope_id() == 0
                && value.ip().to_ipv4_mapped().is_none()
                && !value.ip().is_unicast_link_local()
        }
    }
}
