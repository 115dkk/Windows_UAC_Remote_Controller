// SPDX-License-Identifier: GPL-2.0-or-later
//! Closed, service-authenticated pairing object inspection protocol. No visual,
//! authorization, signing, arbitrary path or input operation exists here.
use std::fmt;

const MAGIC: &[u8; 4] = b"UPI1";
pub const MAX_BYTES: usize = 128;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Binding {
    pub process: u32,
    pub created: u64,
    pub thread: u32,
    pub thread_created: u64,
    pub desktop: u64,
    pub station: u64,
    pub pending: [u8; 32],
    pub display: [u8; 32],
    pub cutoff: u64,
}
impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingInspectionBinding(redacted)")
    }
}
impl Binding {
    fn valid(&self) -> bool {
        self.process != 0
            && self.thread != 0
            && self.created != 0
            && self.thread_created != 0
            && self.desktop != 0
            && self.station != 0
            && self.desktop != u64::MAX
            && self.station != u64::MAX
            && self.pending != [0; 32]
            && self.display != [0; 32]
            && self.pending != self.display
            && self.cutoff != 0
            && self.cutoff <= i64::MAX as u64
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Bind(Binding),
    Check(u64),
    Close(u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub stage: u8,
    pub hresult: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply {
    pub sequence: u64,
    pub failure: Option<Failure>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidFrame;

impl Request {
    pub fn encode(self) -> Result<Vec<u8>, InvalidFrame> {
        let mut bytes = MAGIC.to_vec();
        match self {
            Self::Bind(value) if value.valid() => {
                bytes.push(1);
                bytes.extend(value.process.to_be_bytes());
                bytes.extend(value.created.to_be_bytes());
                bytes.extend(value.thread.to_be_bytes());
                bytes.extend(value.thread_created.to_be_bytes());
                bytes.extend(value.desktop.to_be_bytes());
                bytes.extend(value.station.to_be_bytes());
                bytes.extend(value.pending);
                bytes.extend(value.display);
                bytes.extend(value.cutoff.to_be_bytes());
            }
            Self::Check(sequence) | Self::Close(sequence) if sequence != 0 => {
                bytes.push(if matches!(self, Self::Check(_)) { 2 } else { 3 });
                bytes.extend(sequence.to_be_bytes());
            }
            _ => return Err(InvalidFrame),
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidFrame> {
        if bytes.get(..4) != Some(MAGIC) {
            return Err(InvalidFrame);
        }
        let u64_at = |at: usize| -> Result<u64, InvalidFrame> {
            Ok(u64::from_be_bytes(
                bytes
                    .get(at..at + 8)
                    .ok_or(InvalidFrame)?
                    .try_into()
                    .map_err(|_| InvalidFrame)?,
            ))
        };
        let value = match (bytes.get(4), bytes.len()) {
            (Some(1), 117) => Self::Bind(Binding {
                process: u32::from_be_bytes(bytes[5..9].try_into().map_err(|_| InvalidFrame)?),
                created: u64_at(9)?,
                thread: u32::from_be_bytes(bytes[17..21].try_into().map_err(|_| InvalidFrame)?),
                thread_created: u64_at(21)?,
                desktop: u64_at(29)?,
                station: u64_at(37)?,
                pending: bytes[45..77].try_into().map_err(|_| InvalidFrame)?,
                display: bytes[77..109].try_into().map_err(|_| InvalidFrame)?,
                cutoff: u64_at(109)?,
            }),
            (Some(2), 13) => Self::Check(u64_at(5)?),
            (Some(3), 13) => Self::Close(u64_at(5)?),
            _ => return Err(InvalidFrame),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(InvalidFrame);
        }
        Ok(value)
    }
}
impl Reply {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.push(4);
        bytes.extend(self.sequence.to_be_bytes());
        bytes.push(u8::from(self.failure.is_some()));
        let failure = self.failure.unwrap_or(Failure {
            stage: 0,
            hresult: 0,
        });
        bytes.push(failure.stage);
        bytes.extend(failure.hresult.to_be_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidFrame> {
        if bytes.len() != 19 || bytes[..4] != *MAGIC || bytes[4] != 4 || bytes[13] > 1 {
            return Err(InvalidFrame);
        }
        let sequence = u64::from_be_bytes(bytes[5..13].try_into().map_err(|_| InvalidFrame)?);
        let failure = Failure {
            stage: bytes[14],
            hresult: i32::from_be_bytes(bytes[15..19].try_into().map_err(|_| InvalidFrame)?),
        };
        if bytes[13] == 0
            && failure
                != (Failure {
                    stage: 0,
                    hresult: 0,
                })
        {
            return Err(InvalidFrame);
        }
        Ok(Self {
            sequence,
            failure: (bytes[13] == 1).then_some(failure),
        })
    }
}

/// Implemented by the fixed installed service binary's nonvisual child mode.
/// Calls occur only after native SYSTEM/service/SCM/pipe authentication.
pub trait Inspector {
    fn bind(&mut self, binding: Binding) -> Result<(), Failure>;
    fn check(&mut self) -> Result<(), Failure>;
    fn close(&mut self) -> Result<(), Failure>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_frames_reject_truncation_trailing_bytes_and_crossed_roles() {
        let binding = Binding {
            process: 1,
            created: 2,
            thread: 3,
            thread_created: 4,
            desktop: 5,
            station: 6,
            pending: [1; 32],
            display: [2; 32],
            cutoff: 7,
        };
        for request in [Request::Bind(binding), Request::Check(1), Request::Close(2)] {
            let bytes = request.encode().unwrap();
            assert!(bytes.len() <= MAX_BYTES);
            assert_eq!(Request::decode(&bytes), Ok(request));
            assert!(Reply::decode(&bytes).is_err());
            for length in 0..bytes.len() {
                assert!(Request::decode(&bytes[..length]).is_err());
            }
            let mut extra = bytes;
            extra.push(0);
            assert!(Request::decode(&extra).is_err());
        }
        assert!(Request::Check(0).encode().is_err());
        assert!(
            Request::Bind(Binding {
                display: binding.pending,
                ..binding
            })
            .encode()
            .is_err()
        );
        for reply in [
            Reply {
                sequence: 0,
                failure: None,
            },
            Reply {
                sequence: 2,
                failure: Some(Failure {
                    stage: 5,
                    hresult: -1,
                }),
            },
        ] {
            assert_eq!(Reply::decode(&reply.encode()), Ok(reply));
            assert!(Request::decode(&reply.encode()).is_err());
        }
    }
}
