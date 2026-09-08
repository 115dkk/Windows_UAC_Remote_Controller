// SPDX-License-Identifier: GPL-2.0-or-later
//! Public fixed-wire and configuration contracts; synthetic route only.

use std::time::Duration;

use relay_service::{
    COPY_BUFFER_BYTES, HEADER_BYTES, HEADER_MAGIC, READY_MARKER, Registration, RelayLimits, Role,
    RouteId,
};

#[test]
fn registration_and_ready_marker_have_exact_bounded_v1_encodings() {
    assert_eq!(HEADER_BYTES, 43);
    assert_eq!(HEADER_MAGIC, b"WUACRLY\0");
    assert_eq!(READY_MARKER, b"WUACPAIR\0");
    assert_eq!(COPY_BUFFER_BYTES, 16 * 1024);
    let route = RouteId::new([17; 32]).expect("synthetic route");
    for (role, byte) in [(Role::Pc, 1), (Role::Phone, 2)] {
        let registration = Registration::new(role, route);
        let header = registration.to_wire();
        assert_eq!(&header[..8], HEADER_MAGIC);
        assert_eq!(&header[8..10], &1_u16.to_be_bytes());
        assert_eq!(header[10], byte);
        assert_eq!(&header[11..], &[17; 32]);
        assert_eq!(Registration::from_wire(&header), Ok(registration));
        for length in 0..HEADER_BYTES {
            assert!(Registration::from_wire(&header[..length]).is_err());
        }
        let mut extra = header.to_vec();
        extra.push(0);
        assert!(Registration::from_wire(&extra).is_err());
    }
    assert!(RouteId::new([0; 32]).is_err());
    assert_eq!(format!("{route:?}"), "RouteId([redacted])");
    let diagnostic = format!("{:?}", Registration::new(Role::Pc, route));
    assert!(!diagnostic.contains("[17, 17"));
}

#[test]
fn limits_cannot_disable_timeouts_or_exceed_resource_and_deadline_ceilings() {
    let limits = RelayLimits::default();
    assert_eq!(limits.max_connections(), 64);
    assert_eq!(limits.max_waiting_rooms(), 32);
    assert_eq!(limits.header_timeout(), Duration::from_secs(5));
    assert_eq!(limits.waiting_timeout(), Duration::from_secs(30));
    assert_eq!(limits.inactivity_timeout(), Duration::from_secs(300));
    assert_eq!(limits.absolute_timeout(), Duration::from_secs(3_600));
    assert_eq!(limits.shutdown_timeout(), Duration::from_secs(5));
    for (connections, rooms) in [(0, 1), (1, 1), (65, 1), (64, 0), (64, 33), (2, 3)] {
        assert!(RelayLimits::new(connections, rooms).is_err());
    }
    assert!(RelayLimits::new(2, 1).is_ok());
    let valid = [
        limits.header_timeout(),
        limits.waiting_timeout(),
        limits.inactivity_timeout(),
        limits.absolute_timeout(),
        limits.shutdown_timeout(),
    ];
    for index in 0..valid.len() {
        for invalid in [Duration::ZERO, valid[index] + Duration::from_nanos(1)] {
            let mut durations = valid;
            durations[index] = invalid;
            assert!(
                limits
                    .with_timeouts(
                        durations[0],
                        durations[1],
                        durations[2],
                        durations[3],
                        durations[4]
                    )
                    .is_err()
            );
        }
    }
}
