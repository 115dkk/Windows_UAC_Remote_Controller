// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic clock requests only; no enrollment or native clock assertion.
use approval_protocol::PcIdentity;
use service_protocol::{CLOCK_REQUEST_BYTES, ClockProbe, ClockProbeRequest};

#[test]
fn request_is_exactly_the_probe_pc_and_nonce() {
    let pc = PcIdentity::from_bytes([1; 32]).unwrap();
    let probe = ClockProbe::start(pc, 0).unwrap();
    let request = probe.request();
    let wire = request.to_wire();
    assert_eq!(wire.len(), CLOCK_REQUEST_BYTES);
    assert_eq!(ClockProbeRequest::from_wire(&wire).unwrap(), request);
    assert_eq!(request.pc(), pc);
    assert_eq!(request.nonce(), probe.nonce());
    assert_eq!(
        format!("{request:?}"),
        "ClockProbeRequest([redacted], transport_required)"
    );
}

#[test]
fn short_long_unknown_version_reserved_and_zero_identity_are_rejected() {
    let probe = ClockProbe::start(PcIdentity::from_bytes([1; 32]).unwrap(), 0).unwrap();
    let wire = probe.request().to_wire();
    for end in 0..wire.len() {
        assert!(ClockProbeRequest::from_wire(&wire[..end]).is_err());
    }
    let mut longer = wire.to_vec();
    longer.push(0);
    assert!(ClockProbeRequest::from_wire(&longer).is_err());
    for offset in [0, 7, 8, 9, 10, 11, 76, 77, 78, 79] {
        let mut bad = wire;
        bad[offset] ^= 0x80;
        assert!(ClockProbeRequest::from_wire(&bad).is_err());
    }
    for range in [12..44, 44..76] {
        let mut bad = wire;
        bad[range].fill(0);
        assert!(ClockProbeRequest::from_wire(&bad).is_err());
    }
}
