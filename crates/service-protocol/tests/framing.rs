// SPDX-License-Identifier: GPL-2.0-or-later
use service_protocol::{
    FrameDecoder, FrameError, MAX_PC_EVENT_BYTES, MAX_STREAM_CHUNK_BYTES, encode_frame,
};

#[test]
fn fragmented_headers_payloads_and_multiple_frames_are_lossless() {
    for size in [1, 2, 3, 4, 7, 17, 128] {
        let first = encode_frame(b"synthetic-one").unwrap();
        let second = encode_frame(b"synthetic-two").unwrap();
        let bytes = [first, second].concat();
        let mut decoder = FrameDecoder::new();
        let mut output = Vec::new();
        for chunk in bytes.chunks(size) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let result = decoder.feed(rest).unwrap();
                assert!(result.consumed > 0);
                rest = &rest[result.consumed..];
                if let Some(frame) = result.frame {
                    output.push(frame);
                }
            }
        }
        assert_eq!(
            output,
            vec![b"synthetic-one".to_vec(), b"synthetic-two".to_vec()]
        );
        assert_eq!(decoder.finish(), Ok(()));
        assert_eq!(decoder.feed(b"x").unwrap_err(), FrameError::Closed);
    }
}

#[test]
fn maximum_frame_is_one_bounded_allocation_and_not_truncated() {
    let payload = vec![0x53; MAX_PC_EVENT_BYTES];
    let wire = encode_frame(&payload).unwrap();
    let mut decoder = FrameDecoder::new();
    let mut frame = None;
    for chunk in wire.chunks(MAX_STREAM_CHUNK_BYTES) {
        let fed = decoder.feed(chunk).unwrap();
        assert_eq!(fed.consumed, chunk.len());
        if fed.frame.is_some() {
            assert!(frame.is_none());
            frame = fed.frame;
        }
    }
    assert_eq!(frame, Some(payload));
    assert_eq!(decoder.finish(), Ok(()));
}

#[test]
fn invalid_bounds_and_oversized_chunks_poison_the_decoder() {
    for size in [0, MAX_PC_EVENT_BYTES as u32 + 1, u32::MAX] {
        let mut decoder = FrameDecoder::new();
        assert_eq!(
            decoder.feed(&size.to_be_bytes()).unwrap_err(),
            FrameError::InvalidLength
        );
        assert_eq!(
            decoder.feed(&encode_frame(b"x").unwrap()).unwrap_err(),
            FrameError::Closed
        );
    }
    let mut decoder = FrameDecoder::new();
    assert_eq!(
        decoder
            .feed(&vec![0; MAX_STREAM_CHUNK_BYTES + 1])
            .unwrap_err(),
        FrameError::ChunkTooLarge
    );
    assert_eq!(decoder.finish(), Err(FrameError::Closed));
    assert_eq!(encode_frame(&[]), Err(FrameError::InvalidLength));
    assert_eq!(
        encode_frame(&vec![0; MAX_PC_EVENT_BYTES + 1]),
        Err(FrameError::InvalidLength)
    );
}

#[test]
fn eof_at_every_partial_boundary_is_never_a_complete_frame() {
    let bytes = encode_frame(b"synthetic").unwrap();
    for end in 1..bytes.len() {
        let mut decoder = FrameDecoder::new();
        assert!(decoder.feed(&bytes[..end]).unwrap().frame.is_none());
        assert_eq!(decoder.finish(), Err(FrameError::Truncated));
        assert_eq!(decoder.feed(&bytes[end..]).unwrap_err(), FrameError::Closed);
    }
    assert_eq!(FrameDecoder::new().finish(), Ok(()));
}
