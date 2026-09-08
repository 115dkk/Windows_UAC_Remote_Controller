// SPDX-License-Identifier: GPL-2.0-or-later
use crate::MAX_PC_EVENT_BYTES;
use std::fmt;
use thiserror::Error;

pub const MAX_STREAM_CHUNK_BYTES: usize = 16 * 1024;

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() || payload.len() > MAX_PC_EVENT_BYTES {
        return Err(FrameError::InvalidLength);
    }
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// One incremental frame only. A caller must cap simultaneously retained frames
/// and invoke this ONLY for authenticated/decrypted application bytes.
#[derive(Default)]
pub struct FrameDecoder {
    header: [u8; 4],
    header_used: usize,
    payload: Vec<u8>,
    wanted: Option<usize>,
    closed: bool,
}

impl fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

pub struct FrameFeed {
    pub consumed: usize,
    pub frame: Option<Vec<u8>>,
}
impl fmt::Debug for FrameFeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameFeed")
            .field("consumed", &self.consumed)
            .field("frame_complete", &self.frame.is_some())
            .finish_non_exhaustive()
    }
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    /// Returns after at most one complete frame; process that frame before
    /// supplying unconsumed input. Invalid length or oversized chunks poison it.
    pub fn feed(&mut self, input: &[u8]) -> Result<FrameFeed, FrameError> {
        if self.closed {
            return Err(FrameError::Closed);
        }
        if input.len() > MAX_STREAM_CHUNK_BYTES {
            return self.fail(FrameError::ChunkTooLarge);
        }
        let mut consumed = 0;
        if self.wanted.is_none() {
            let amount = (4 - self.header_used).min(input.len());
            self.header[self.header_used..self.header_used + amount]
                .copy_from_slice(&input[..amount]);
            self.header_used += amount;
            consumed += amount;
            if self.header_used < 4 {
                return Ok(FrameFeed {
                    consumed,
                    frame: None,
                });
            }
            let wanted = u32::from_be_bytes(self.header) as usize;
            if wanted == 0 || wanted > MAX_PC_EVENT_BYTES {
                return self.fail(FrameError::InvalidLength);
            }
            self.wanted = Some(wanted);
            self.payload = Vec::with_capacity(wanted);
        }
        let wanted = self.wanted.ok_or(FrameError::InvalidLength)?;
        let amount = (wanted - self.payload.len()).min(input.len() - consumed);
        self.payload
            .extend_from_slice(&input[consumed..consumed + amount]);
        consumed += amount;
        let frame = if self.payload.len() == wanted {
            self.header = [0; 4];
            self.header_used = 0;
            self.wanted = None;
            Some(std::mem::take(&mut self.payload))
        } else {
            None
        };
        Ok(FrameFeed { consumed, frame })
    }
    /// Call only after authenticated transport EOF/close. Partial frames are a
    /// truncation error, never accepted as complete messages; either closes it.
    pub fn finish(&mut self) -> Result<(), FrameError> {
        if self.closed {
            return Err(FrameError::Closed);
        }
        let incomplete = self.header_used != 0 || self.wanted.is_some();
        self.closed = true;
        self.payload = Vec::new();
        if incomplete {
            Err(FrameError::Truncated)
        } else {
            Ok(())
        }
    }
    fn fail<T>(&mut self, error: FrameError) -> Result<T, FrameError> {
        self.closed = true;
        self.payload = Vec::new();
        Err(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FrameError {
    #[error("stream frame length is invalid")]
    InvalidLength,
    #[error("stream input chunk exceeds its limit")]
    ChunkTooLarge,
    #[error("stream ended inside a frame")]
    Truncated,
    #[error("stream decoder is closed")]
    Closed,
}
