// SPDX-License-Identifier: GPL-2.0-or-later
use crate::message::{ClockProbeNonce, PcEvent, PcEventError, RequestResolution, ServiceTick};
use approval_protocol::{
    BootEpoch, ChallengeNonce, ContentDigest, ExpiryTick, MAX_DETAILS_BYTES, MAX_PATH_BYTES,
    MAX_PROGRAM_NAME_BYTES, OsSession, PcIdentity, RequestBinding, RequestContent, RequestId,
};
use std::sync::Arc;

pub(crate) fn encode(event: &PcEvent) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    match event {
        PcEvent::Opened {
            binding,
            issued_at,
            content,
        } => {
            bytes.push(1);
            put_binding(&mut bytes, *binding);
            bytes.extend_from_slice(&issued_at.as_nanos_since_epoch().to_be_bytes());
            for text in [content.program_name(), content.path(), content.details()] {
                bytes.extend_from_slice(&(text.len() as u32).to_be_bytes());
                bytes.extend_from_slice(text.as_bytes());
            }
        }
        PcEvent::Resolved {
            binding,
            issued_at,
            outcome,
        } => {
            bytes.push(2);
            put_binding(&mut bytes, *binding);
            bytes.extend_from_slice(&issued_at.as_nanos_since_epoch().to_be_bytes());
            bytes.push(match outcome {
                RequestResolution::Approved => 1,
                RequestResolution::Denied => 2,
                RequestResolution::Cancelled => 3,
                RequestResolution::Expired => 4,
                RequestResolution::Failed => 5,
            });
        }
        PcEvent::Clock {
            pc,
            epoch,
            probe,
            sampled_at,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(pc.as_bytes());
            bytes.extend_from_slice(epoch.as_bytes());
            bytes.extend_from_slice(probe.as_bytes());
            bytes.extend_from_slice(&sampled_at.as_nanos_since_epoch().to_be_bytes());
        }
    }
    bytes
}

fn put_binding(bytes: &mut Vec<u8>, binding: RequestBinding) {
    bytes.extend_from_slice(binding.pc().as_bytes());
    bytes.extend_from_slice(binding.epoch().as_bytes());
    bytes.extend_from_slice(&binding.session().session_id().to_be_bytes());
    bytes.extend_from_slice(&binding.session().logon_id().to_be_bytes());
    bytes.extend_from_slice(binding.request_id().as_bytes());
    bytes.extend_from_slice(binding.nonce().as_bytes());
    bytes.extend_from_slice(binding.content_digest().as_bytes());
    bytes.extend_from_slice(&binding.expiry().as_nanos_since_epoch().to_be_bytes());
}

pub(crate) fn decode(bytes: &[u8]) -> Result<PcEvent, PcEventError> {
    let mut reader = Reader::new(bytes);
    if reader.u16()? != 1 {
        return Err(PcEventError::UnsupportedVersion);
    }
    let event = match reader.u8()? {
        1 => {
            let binding = reader.binding()?;
            let issued_at = ServiceTick::from_nanos_since_epoch(reader.u64()?);
            let name = reader.text(MAX_PROGRAM_NAME_BYTES)?;
            let path = reader.text(MAX_PATH_BYTES)?;
            let details = reader.text(MAX_DETAILS_BYTES)?;
            let content = Arc::new(
                RequestContent::new(name, path, details)
                    .map_err(|_| PcEventError::InvalidFields)?,
            );
            PcEvent::Opened {
                binding,
                issued_at,
                content,
            }
        }
        2 => {
            let binding = reader.binding()?;
            let issued_at = ServiceTick::from_nanos_since_epoch(reader.u64()?);
            let outcome = match reader.u8()? {
                1 => RequestResolution::Approved,
                2 => RequestResolution::Denied,
                3 => RequestResolution::Cancelled,
                4 => RequestResolution::Expired,
                5 => RequestResolution::Failed,
                _ => return Err(PcEventError::UnsupportedKind),
            };
            PcEvent::Resolved {
                binding,
                issued_at,
                outcome,
            }
        }
        3 => PcEvent::Clock {
            pc: PcIdentity::from_bytes(reader.array()?).map_err(|_| PcEventError::InvalidFields)?,
            epoch: BootEpoch::from_bytes(reader.array()?)
                .map_err(|_| PcEventError::InvalidFields)?,
            probe: ClockProbeNonce::from_bytes(reader.array()?)?,
            sampled_at: ServiceTick::from_nanos_since_epoch(reader.u64()?),
        },
        _ => return Err(PcEventError::UnsupportedKind),
    };
    reader.finish()?;
    Ok(event)
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], PcEventError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PcEventError::InvalidLength)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PcEventError::InvalidLength)?;
        self.offset = end;
        Ok(bytes)
    }
    pub(crate) fn finish(self) -> Result<(), PcEventError> {
        if self.offset != self.bytes.len() {
            return Err(PcEventError::InvalidLength);
        }
        Ok(())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], PcEventError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PcEventError::InvalidLength)
    }
    fn u8(&mut self) -> Result<u8, PcEventError> {
        Ok(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, PcEventError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, PcEventError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, PcEventError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn tick(&mut self) -> Result<ExpiryTick, PcEventError> {
        ExpiryTick::from_nanos_since_epoch(self.u64()?).map_err(|_| PcEventError::InvalidFields)
    }
    fn text(&mut self, limit: usize) -> Result<&'a str, PcEventError> {
        let size = self.u32()? as usize;
        if size > limit {
            return Err(PcEventError::InvalidLength);
        }
        std::str::from_utf8(self.take(size)?).map_err(|_| PcEventError::InvalidText)
    }
    fn binding(&mut self) -> Result<RequestBinding, PcEventError> {
        Ok(RequestBinding::new(
            PcIdentity::from_bytes(self.array()?).map_err(|_| PcEventError::InvalidFields)?,
            BootEpoch::from_bytes(self.array()?).map_err(|_| PcEventError::InvalidFields)?,
            OsSession::new(self.u32()?, self.u64()?),
            RequestId::from_bytes(self.array()?).map_err(|_| PcEventError::InvalidFields)?,
            ChallengeNonce::from_bytes(self.array()?).map_err(|_| PcEventError::InvalidFields)?,
            ContentDigest::from_bytes(self.array()?),
            self.tick()?,
        ))
    }
}
