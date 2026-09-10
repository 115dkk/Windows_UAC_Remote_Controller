// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic release settings/status bytes and injected process-local clocks.
//! Constructor success does not prove HTTPS provenance, a native key or enrollment.
use super::*;

const EMPTY_STATUS: &[u8] = br#"{"entries":{}}"#;
const REVOKED_STATUS: &[u8] = br#"{"entries":{"10":{"status":"REVOKED"}}}"#;

fn minimums() -> PlatformMinimums {
    PlatformMinimums {
        os_version: 110000,
        os_patch: 202601,
        vendor_patch: None,
        boot_patch: None,
    }
}
fn release() -> VerificationPolicy {
    VerificationPolicy::from_trusted_host(vec![[1; 32], [2; 32]], 1, minimums()).unwrap()
}
fn synthetic_start(monotonic: Instant) -> StatusFetchStarted {
    // This fake UTC floor is for a parser/TTL test only. No authenticated fetch
    // took place and this must never be a production freshness construction.
    StatusFetchStarted {
        clock: Clock {
            utc: Duration::ZERO,
            monotonic,
        },
    }
}
fn synthetic_snapshot(monotonic: Instant, utc: Duration, ttl: Duration) -> TrustedStatusSnapshot {
    TrustedStatusSnapshot {
        entries: RevocationList::parse(EMPTY_STATUS).unwrap(),
        received_clock: Clock { utc, monotonic },
        deadline: monotonic.checked_add(ttl).unwrap(),
        identity: Arc::new(()),
    }
}

#[test]
fn explicit_release_policy_rejects_empty_duplicate_zero_or_excess_signer_configuration() {
    assert!(VerificationPolicy::from_trusted_host(vec![[1; 32]], 1, minimums()).is_ok());
    for signers in [
        vec![],
        vec![[0; 32]],
        vec![[1; 32], [1; 32]],
        (1u8..=17).map(|value| [value; 32]).collect(),
    ] {
        assert!(matches!(
            VerificationPolicy::from_trusted_host(signers, 1, minimums()),
            Err(Error::InvalidPolicy)
        ));
    }
    for version in [0, u64::MAX] {
        assert!(matches!(
            VerificationPolicy::from_trusted_host(vec![[1; 32]], version, minimums()),
            Err(Error::InvalidPolicy)
        ));
    }
}

#[test]
fn platform_minima_validate_android_floor_and_real_calendar_dates() {
    for version in [0, 109999, 1_000_000] {
        let mut invalid = minimums();
        invalid.os_version = version;
        assert!(matches!(
            VerificationPolicy::from_trusted_host(vec![[1; 32]], 1, invalid),
            Err(Error::InvalidPolicy)
        ));
    }
    for patch in [0, 202600, 202613] {
        let mut invalid = minimums();
        invalid.os_patch = patch;
        assert!(matches!(
            VerificationPolicy::from_trusted_host(vec![[1; 32]], 1, invalid),
            Err(Error::InvalidPolicy)
        ));
    }
    for patch in [20260229, 20260431, 20260001, 20261301] {
        for vendor in [true, false] {
            let mut invalid = minimums();
            if vendor {
                invalid.vendor_patch = Some(patch);
            } else {
                invalid.boot_patch = Some(patch);
            }
            assert!(matches!(
                VerificationPolicy::from_trusted_host(vec![[1; 32]], 1, invalid),
                Err(Error::InvalidPolicy)
            ));
        }
    }
    let valid = PlatformMinimums {
        vendor_patch: Some(20240229),
        boot_patch: Some(20000229),
        ..minimums()
    };
    assert!(VerificationPolicy::from_trusted_host(vec![[1; 32]], 1, valid).is_ok());
}

#[test]
fn fingerprint_is_signer_order_independent_but_binds_each_policy_field() {
    let original = release();
    let reversed =
        VerificationPolicy::from_trusted_host(vec![[2; 32], [1; 32]], 1, minimums()).unwrap();
    assert_eq!(original.fingerprint(), reversed.fingerprint());
    assert_eq!(original.signers, reversed.signers);
    for other in [
        VerificationPolicy::from_trusted_host(vec![[1; 32], [3; 32]], 1, minimums()).unwrap(),
        VerificationPolicy::from_trusted_host(vec![[1; 32], [2; 32]], 2, minimums()).unwrap(),
        VerificationPolicy::from_trusted_host(
            vec![[1; 32], [2; 32]],
            1,
            PlatformMinimums {
                os_version: 120000,
                ..minimums()
            },
        )
        .unwrap(),
        VerificationPolicy::from_trusted_host(
            vec![[1; 32], [2; 32]],
            1,
            PlatformMinimums {
                os_patch: 202602,
                ..minimums()
            },
        )
        .unwrap(),
        VerificationPolicy::from_trusted_host(
            vec![[1; 32], [2; 32]],
            1,
            PlatformMinimums {
                vendor_patch: Some(20260901),
                ..minimums()
            },
        )
        .unwrap(),
        VerificationPolicy::from_trusted_host(
            vec![[1; 32], [2; 32]],
            1,
            PlatformMinimums {
                boot_patch: Some(20260901),
                ..minimums()
            },
        )
        .unwrap(),
    ] {
        assert_ne!(original.fingerprint(), other.fingerprint());
    }
}

#[test]
fn description_view_keeps_exact_supplied_challenge_and_explicit_release_values() {
    let policy = VerificationPolicy::from_trusted_host(
        vec![[2; 32], [1; 32]],
        17,
        PlatformMinimums {
            vendor_patch: Some(20260901),
            boot_patch: Some(20260902),
            ..minimums()
        },
    )
    .unwrap();
    let challenge = [55; 32];
    let view = policy.description(&challenge);
    assert_eq!(view.challenge, &challenge);
    assert_eq!(view.signer_digests, &[[1; 32], [2; 32]]);
    assert_eq!(view.min_app_version, 17);
    assert_eq!(view.min_os_version, 110000);
    assert_eq!(view.min_os_patch, 202601);
    assert_eq!(view.min_vendor_patch, Some(20260901));
    assert_eq!(view.min_boot_patch, Some(20260902));
}

#[test]
fn zero_http_freshness_rejects_and_large_ttls_cap_at_the_original_start_plus_24_hours() {
    let start = Instant::now();
    assert!(matches!(
        TrustedStatusSnapshot::from_authenticated_google_response(
            synthetic_start(start),
            EMPTY_STATUS,
            Duration::ZERO
        ),
        Err(Error::StaleStatus)
    ));
    for ttl in [
        Duration::from_secs(86_400),
        Duration::from_secs(86_401),
        Duration::MAX,
    ] {
        let snapshot = TrustedStatusSnapshot::from_authenticated_google_response(
            synthetic_start(start),
            EMPTY_STATUS,
            ttl,
        )
        .unwrap();
        assert_eq!(snapshot.received_clock.monotonic, start);
        assert_eq!(
            snapshot.deadline,
            start.checked_add(Duration::from_secs(86_400)).unwrap()
        );
    }
    let shorter = TrustedStatusSnapshot::from_authenticated_google_response(
        synthetic_start(start),
        EMPTY_STATUS,
        Duration::from_secs(3600),
    )
    .unwrap();
    assert_eq!(
        shorter.deadline,
        start.checked_add(Duration::from_secs(3600)).unwrap()
    );
}

#[test]
fn malformed_status_body_never_becomes_an_empty_fresh_snapshot() {
    let start = Instant::now();
    for body in [
        b"".as_slice(),
        b"{}",
        br#"{"entries":[]}"#,
        br#"{"entries":{"10":{"status":"GOOD"}}}"#,
        br#"{"entries":{},"entries":{}}"#,
        br#"{"entries":{}}false"#,
    ] {
        assert!(matches!(
            TrustedStatusSnapshot::from_authenticated_google_response(
                synthetic_start(start),
                body,
                Duration::from_secs(3600)
            ),
            Err(Error::Der)
        ));
    }
    assert!(matches!(
        TrustedStatusSnapshot::from_authenticated_google_response(
            synthetic_start(start),
            &vec![b' '; 2 * 1024 * 1024 + 1],
            Duration::from_secs(3600)
        ),
        Err(Error::Bounds)
    ));
}

#[test]
fn exact_original_deadline_expires_without_reset_on_use_or_another_snapshot() {
    let start = Instant::now().checked_add(Duration::from_secs(60)).unwrap();
    let utc = Duration::from_secs(1000);
    let snapshot = synthetic_snapshot(start, utc, Duration::from_secs(60));
    let before = Clock {
        monotonic: snapshot
            .deadline
            .checked_sub(Duration::from_nanos(1))
            .unwrap(),
        utc: utc + Duration::from_secs(59),
    };
    assert_eq!(snapshot.require_current(&before), Ok(()));
    assert_eq!(snapshot.require_current(&before), Ok(()));
    let at = Clock {
        monotonic: snapshot.deadline,
        utc: utc + Duration::from_secs(60),
    };
    assert_eq!(snapshot.require_current(&at), Err(Error::StaleStatus));
    let newer = synthetic_snapshot(
        start + Duration::from_secs(59),
        utc + Duration::from_secs(59),
        Duration::from_secs(60),
    );
    assert_eq!(newer.require_current(&at), Ok(()));
    assert_eq!(snapshot.require_current(&at), Err(Error::StaleStatus));
    assert_eq!(snapshot.deadline, start + Duration::from_secs(60));
}

#[test]
fn before_start_monotonic_or_utc_rollback_reject_even_before_expiry() {
    let start = Instant::now().checked_add(Duration::from_secs(60)).unwrap();
    let utc = Duration::from_secs(1000);
    let snapshot = synthetic_snapshot(start, utc, Duration::from_secs(60));
    assert_eq!(
        snapshot.require_current(&Clock {
            monotonic: start,
            utc
        }),
        Ok(())
    );
    assert_eq!(
        snapshot.require_current(&Clock {
            monotonic: start - Duration::from_nanos(1),
            utc
        }),
        Err(Error::StaleStatus)
    );
    assert_eq!(
        snapshot.require_current(&Clock {
            monotonic: start + Duration::from_secs(1),
            utc: utc - Duration::from_nanos(1)
        }),
        Err(Error::StaleStatus)
    );
    assert_eq!(
        snapshot.require_current(&Clock {
            monotonic: snapshot.deadline + Duration::from_nanos(1),
            utc: utc + Duration::from_secs(60)
        }),
        Err(Error::StaleStatus)
    );
}

#[test]
fn caller_supplied_status_parsing_and_arc_identity_are_not_https_provenance() {
    // No HTTP client or authentication happened. The constructor's documented
    // trusted-fetch premise is a caller responsibility, not proved by parsing.
    let start = Instant::now();
    let first = TrustedStatusSnapshot::from_authenticated_google_response(
        synthetic_start(start),
        REVOKED_STATUS,
        Duration::from_secs(3600),
    )
    .unwrap();
    let second = TrustedStatusSnapshot::from_authenticated_google_response(
        synthetic_start(start),
        REVOKED_STATUS,
        Duration::from_secs(3600),
    )
    .unwrap();
    assert!(first.entries.contains_serial(&[0x10]).unwrap());
    assert!(second.entries.contains_serial(&[0x10]).unwrap());
    assert_eq!(first.deadline, second.deadline);
    // Private process-local identity only, not independent freshness/authority.
    assert!(!Arc::ptr_eq(&first.identity, &second.identity));
}

#[test]
fn debug_keeps_release_signers_and_status_contents_redacted() {
    assert_eq!(format!("{:?}", release()), "VerificationPolicy([redacted])");
    let start = Instant::now();
    assert_eq!(
        format!("{:?}", synthetic_start(start)),
        "StatusFetchStarted([redacted])"
    );
    assert_eq!(
        format!(
            "{:?}",
            synthetic_snapshot(start, Duration::from_secs(1000), Duration::from_secs(60))
        ),
        "TrustedStatusSnapshot([redacted])"
    );
}
