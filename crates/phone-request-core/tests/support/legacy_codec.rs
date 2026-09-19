// SPDX-License-Identifier: GPL-2.0-or-later
//! Test-fixture downconversion only. Strips schema4 provenance without inventing
//! it; production never writes legacy checkpoints.
pub fn as_v3(bytes: &[u8]) -> Vec<u8> {
    assert_eq!(&bytes[8..10], &4_u16.to_be_bytes());
    let mut at = 22 + u32::from_be_bytes(bytes[18..22].try_into().unwrap()) as usize;
    fn optional(bytes: &[u8], at: &mut usize) {
        let present = bytes[*at];
        *at += 1;
        assert!(present <= 1);
        if present != 0 {
            *at += 8;
        }
    }
    optional(bytes, &mut at);
    let local = bytes[at];
    at += 1 + if local == 1 { 3 } else { 0 };
    optional(bytes, &mut at);
    at += 1; // fault
    let engine = bytes[at];
    at += 1;
    if engine != 0 {
        optional(bytes, &mut at);
        optional(bytes, &mut at);
        at += 1;
    }
    let sources = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
    at += 2;
    let mut omitted = Vec::new();
    for _ in 0..sources {
        at += 32 + 32 + 8;
        optional(bytes, &mut at);
        assert_eq!(
            bytes[at], 0,
            "legacy fixture cannot represent source quarantine/retirement"
        );
        omitted.push(at);
        at += 1;
    }
    let rows = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
    at += 2;
    for _ in 0..rows {
        at += 180 + 8;
        let window = bytes[at];
        at += 1 + if window != 0 { 16 } else { 0 };
        at += 1 + 8 + 1;
        optional(bytes, &mut at);
        at += 1;
        optional(bytes, &mut at);
        assert!(bytes[at] <= 1);
        omitted.push(at);
        at += 1;
    }
    let mut legacy = bytes.to_vec();
    for index in omitted.into_iter().rev() {
        legacy.remove(index);
    }
    legacy[8..10].copy_from_slice(&3_u16.to_be_bytes());
    legacy
}
