// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure signed fixtures and synthetic ticks, not Android/Windows clock QA.

use std::sync::Arc;

use approval_protocol::{
    BootEpoch, ChallengeNonce, ExpiryTick, OsSession, PcIdentity, RequestBinding, RequestContent,
    RequestId,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use service_protocol::{
    ClockCorrelation, ClockError, ClockProbe, ClockProbeNonce, MAX_CLOCK_CORRELATION_AGE_NANOS,
    MAX_CLOCK_PROBE_RTT_NANOS, PcEvent, PcEventError, PcPublicKey, RequestResolution, ServiceTick,
    SignedPcEvent, UnsignedPcEvent, VerifiedPcEvent,
};

const SECOND: u64 = 1_000_000_000;

fn pc() -> PcIdentity {
    PcIdentity::from_bytes([1; 32]).expect("synthetic PC")
}

fn epoch() -> BootEpoch {
    BootEpoch::from_bytes([2; 32]).expect("synthetic service epoch")
}

fn fixture_key() -> SigningKey {
    SigningKey::from_slice(&[3; 32]).expect("synthetic signing fixture, never an enrolled key")
}

fn public(key: &SigningKey) -> PcPublicKey {
    PcPublicKey::from_sec1_bytes(key.verifying_key().to_encoded_point(false).as_bytes())
        .expect("synthetic public key")
}

fn signed(event: PcEvent) -> SignedPcEvent {
    let unsigned = UnsignedPcEvent::new(event).expect("valid synthetic event");
    let signature: Signature = fixture_key().sign(&unsigned.signing_bytes());
    unsigned
        .with_der_signature(signature.to_der().as_bytes())
        .expect("synthetic DER")
}

fn verified(event: PcEvent) -> VerifiedPcEvent {
    let expected_pc = event.pc();
    signed(event)
        .verify(expected_pc, &public(&fixture_key()))
        .expect("verified synthetic fixture")
}

fn clock_event(
    expected_pc: PcIdentity,
    service_epoch: BootEpoch,
    nonce: ClockProbeNonce,
    sample: u64,
) -> PcEvent {
    PcEvent::Clock {
        pc: expected_pc,
        epoch: service_epoch,
        probe: nonce,
        sampled_at: ServiceTick::from_nanos_since_epoch(sample),
    }
}

fn correlation(sent: u64, received: u64, sample: u64) -> ClockCorrelation {
    let probe = ClockProbe::start(pc(), sent).expect("fresh test probe from CSPRNG");
    let response = verified(clock_event(pc(), epoch(), probe.nonce(), sample));
    probe
        .complete(&response, received)
        .expect("synthetic bounded clock response")
}

fn opened_with_identity(
    expected_pc: PcIdentity,
    service_epoch: BootEpoch,
    issued: u64,
    expiry: u64,
) -> PcEvent {
    let content = Arc::new(
        RequestContent::new(
            "합성 시계 테스트 앱",
            "C:\\Synthetic\\clock-fixture.exe",
            "synthetic timing fixture",
        )
        .expect("synthetic inert content"),
    );
    let binding = RequestBinding::new(
        expected_pc,
        service_epoch,
        OsSession::new(1, 7),
        RequestId::from_bytes([4; 32]).expect("synthetic request ID"),
        ChallengeNonce::from_bytes([5; 32]).expect("synthetic request nonce"),
        content.digest(),
        ExpiryTick::from_nanos_since_epoch(expiry).expect("positive synthetic expiry"),
    );
    PcEvent::Opened {
        binding,
        issued_at: ServiceTick::from_nanos_since_epoch(issued),
        content,
    }
}

fn opened(issued: u64, expiry: u64) -> VerifiedPcEvent {
    verified(opened_with_identity(pc(), epoch(), issued, expiry))
}

#[test]
fn probe_nonce_is_nonzero_fresh_and_not_exposed_by_debug() {
    let first = ClockProbe::start(pc(), 0).expect("fresh first probe");
    let second = ClockProbe::start(pc(), 0).expect("fresh second probe");
    assert!(first.nonce().as_bytes().iter().any(|byte| *byte != 0));
    assert!(second.nonce().as_bytes().iter().any(|byte| *byte != 0));
    // This checks accidental fixed/reused challenges, not RNG statistical quality.
    assert_ne!(first.nonce(), second.nonce());
    assert_eq!(format!("{first:?}"), "ClockProbe([redacted])");
}

#[test]
fn original_window_maps_from_send_anchor_not_response_or_request_receipt() {
    let sent = 1_000 * SECOND;
    let probe_received = sent + 2 * SECOND;
    let mut correlation = correlation(sent, probe_received, 100 * SECOND);
    assert_eq!(correlation.pc(), pc());
    assert_eq!(correlation.epoch(), epoch());
    assert_eq!(
        correlation.service_sample().as_nanos_since_epoch(),
        100 * SECOND
    );
    assert_eq!(correlation.phone_anchor_nanos(), sent);
    assert_eq!(correlation.phone_probe_received_nanos(), probe_received);

    let event = opened(99 * SECOND, 110 * SECOND);
    let first = correlation
        .map_request(&event, sent + 3 * SECOND)
        .expect("live request");
    assert_eq!(first.phone_issued_nanos(), sent - SECOND);
    assert_eq!(first.phone_expiry_nanos(), sent + 10 * SECOND);
    assert_eq!(
        first.service_issued_at().as_nanos_since_epoch(),
        99 * SECOND
    );
    let PcEvent::Opened { binding, .. } = event.event() else {
        unreachable!()
    };
    assert_eq!(first.binding(), *binding);

    let duplicate = correlation
        .map_request(&event, sent + 7 * SECOND)
        .expect("later duplicate mapping");
    assert_eq!(duplicate, first);
    assert!(first.phone_expiry_nanos() < probe_received + 10 * SECOND);
    assert!(first.phone_expiry_nanos() < sent + 3 * SECOND + 11 * SECOND);
    assert!(!correlation.is_faulted());
}

#[test]
fn resolved_uses_the_same_original_window_as_opened() {
    let sent = 100 * SECOND;
    let mut correlation = correlation(sent, sent + SECOND, 50 * SECOND);
    let event = opened(49 * SECOND, 60 * SECOND);
    let window = correlation
        .map_request(&event, sent + SECOND)
        .expect("opened mapping");
    let PcEvent::Opened {
        binding, issued_at, ..
    } = event.event()
    else {
        unreachable!()
    };
    for outcome in [
        RequestResolution::Approved,
        RequestResolution::Denied,
        RequestResolution::Cancelled,
        RequestResolution::Expired,
        RequestResolution::Failed,
    ] {
        let resolution = verified(PcEvent::Resolved {
            binding: *binding,
            issued_at: *issued_at,
            outcome,
        });
        assert_eq!(
            correlation
                .map_request(&resolution, sent + 2 * SECOND)
                .expect("original resolution mapping"),
            window
        );
    }
}

#[test]
fn complete_rejects_wrong_pc_nonce_and_non_clock_event() {
    let other_pc = PcIdentity::from_bytes([9; 32]).expect("other synthetic PC");
    let probe = ClockProbe::start(pc(), 100).expect("probe");
    let response = verified(clock_event(other_pc, epoch(), probe.nonce(), 1_000));
    assert_eq!(
        probe.complete(&response, 110).expect_err("wrong PC"),
        ClockError::WrongPc
    );

    let probe = ClockProbe::start(pc(), 100).expect("probe");
    let mut changed = *probe.nonce().as_bytes();
    // Change one byte while retaining a nonzero nonce, without a probabilistic fixture collision.
    changed[0] ^= 1;
    if changed.iter().all(|byte| *byte == 0) {
        changed[1] = 1;
    }
    let response = verified(clock_event(
        pc(),
        epoch(),
        ClockProbeNonce::from_bytes(changed).expect("different nonce"),
        1_000,
    ));
    assert_eq!(
        probe.complete(&response, 110).expect_err("wrong nonce"),
        ClockError::WrongProbe
    );

    let probe = ClockProbe::start(pc(), 100).expect("probe");
    assert_eq!(
        probe
            .complete(&opened(0, 100), 110)
            .expect_err("request is not a clock response"),
        ClockError::WrongEventKind
    );
}

#[test]
fn clock_response_requires_the_enrolled_signing_key_before_completion() {
    let probe = ClockProbe::start(pc(), 100).expect("probe");
    let response = signed(clock_event(pc(), epoch(), probe.nonce(), 1_000));
    let wrong_key = SigningKey::from_slice(&[8; 32]).expect("other synthetic key");
    assert_eq!(
        response.verify(pc(), &public(&wrong_key)),
        Err(PcEventError::InvalidSignature)
    );
    assert_eq!(
        VerifiedPcEvent::from_wire(&response.to_wire(), pc(), &public(&wrong_key)),
        Err(PcEventError::InvalidSignature)
    );
    let authenticated = response
        .verify(pc(), &public(&fixture_key()))
        .expect("proper fixture key");
    assert!(probe.complete(&authenticated, 110).is_ok());
}

#[test]
fn replayed_clock_reply_cannot_complete_a_new_probe() {
    let probe = ClockProbe::start(pc(), 100).expect("first probe");
    let response = verified(clock_event(pc(), epoch(), probe.nonce(), 1_000));
    let _correlation = probe
        .complete(&response, 110)
        .expect("first response consumed");
    // The original probe cannot be reused (covered by the API's compile-fail
    // example); a newly generated challenge must reject the old signed reply.
    let new_probe = ClockProbe::start(pc(), 120).expect("fresh new probe");
    assert_eq!(
        new_probe.complete(&response, 130).expect_err("old reply"),
        ClockError::WrongProbe
    );
}

#[test]
fn ten_second_round_trip_boundary_is_inclusive() {
    let sent = 100;
    let probe = ClockProbe::start(pc(), sent).expect("probe");
    let response = verified(clock_event(pc(), epoch(), probe.nonce(), 1_000));
    assert!(
        probe
            .complete(&response, sent + MAX_CLOCK_PROBE_RTT_NANOS)
            .is_ok()
    );

    let probe = ClockProbe::start(pc(), sent).expect("probe");
    let response = verified(clock_event(pc(), epoch(), probe.nonce(), 1_000));
    assert_eq!(
        probe
            .complete(&response, sent + MAX_CLOCK_PROBE_RTT_NANOS + 1)
            .expect_err("delayed response"),
        ClockError::ProbeTooSlow
    );
}

#[test]
fn probe_completion_rejects_local_clock_regression_without_wrapping() {
    let probe = ClockProbe::start(pc(), 100).expect("probe");
    let response = verified(clock_event(pc(), epoch(), probe.nonce(), 1_000));
    assert_eq!(
        probe
            .complete(&response, 99)
            .expect_err("native clock regression"),
        ClockError::LocalClockRegressed
    );
}

#[test]
fn five_minute_correlation_age_boundary_is_inclusive_and_measured_from_send() {
    let sent = 100;
    let sample = 1_000;
    let mut correlation = correlation(sent, sent + MAX_CLOCK_PROBE_RTT_NANOS, sample);
    let event = opened(
        sample + MAX_CLOCK_CORRELATION_AGE_NANOS,
        sample + MAX_CLOCK_CORRELATION_AGE_NANOS + SECOND,
    );
    let boundary = sent + MAX_CLOCK_CORRELATION_AGE_NANOS;
    assert!(correlation.map_request(&event, boundary).is_ok());
    assert_eq!(
        correlation
            .map_request(&event, boundary + 1)
            .expect_err("too old"),
        ClockError::CorrelationTooOld
    );
    // The authentic matching event supplied a fresh local observation even
    // though its correlation was too old. It cannot later be made young again.
    assert_eq!(
        correlation
            .map_request(&event, boundary)
            .expect_err("clock cannot move back into validity"),
        ClockError::LocalClockRegressed
    );
    assert!(correlation.is_faulted());
}

#[test]
fn wrong_event_pc_or_epoch_does_not_advance_or_fault_the_native_watermark() {
    let mut correlation = correlation(1_000, 1_010, 100);
    let other_pc = PcIdentity::from_bytes([9; 32]).expect("other synthetic PC");
    let other_epoch = BootEpoch::from_bytes([9; 32]).expect("other synthetic epoch");
    let wrong_pc = verified(opened_with_identity(other_pc, epoch(), 100, 200));
    let wrong_epoch = verified(opened_with_identity(pc(), other_epoch, 100, 200));
    let clock = verified(clock_event(
        pc(),
        epoch(),
        ClockProbeNonce::from_bytes([6; 32]).expect("synthetic nonce"),
        100,
    ));
    for observed_at in [0, u64::MAX] {
        assert_eq!(
            correlation
                .map_request(&wrong_pc, observed_at)
                .expect_err("other PC"),
            ClockError::WrongPc
        );
        assert_eq!(
            correlation
                .map_request(&wrong_epoch, observed_at)
                .expect_err("other epoch"),
            ClockError::WrongEpoch
        );
        assert_eq!(
            correlation
                .map_request(&clock, observed_at)
                .expect_err("not a request"),
            ClockError::WrongEventKind
        );
        assert!(!correlation.is_faulted());
    }
    assert!(correlation.map_request(&opened(100, 200), 1_020).is_ok());
}

#[test]
fn regression_after_a_mapping_latches_and_cannot_be_cleared_with_a_later_time() {
    let mut correlation = correlation(1_000, 1_010, 100);
    let event = opened(100, 300);
    correlation
        .map_request(&event, 1_020)
        .expect("first mapping");
    assert_eq!(
        correlation
            .map_request(&event, 1_019)
            .expect_err("fresh native regression"),
        ClockError::LocalClockRegressed
    );
    assert!(correlation.is_faulted());
    assert_eq!(
        correlation
            .map_request(&event, 1_021)
            .expect_err("latched correlation"),
        ClockError::CorrelationFaulted
    );
}

#[test]
fn mapping_before_probe_completion_is_a_latched_regression() {
    let mut correlation = correlation(1_000, 1_010, 100);
    assert_eq!(
        correlation
            .map_request(&opened(100, 300), 1_009)
            .expect_err("queued stale timestamp"),
        ClockError::LocalClockRegressed
    );
    assert!(correlation.is_faulted());
}

#[test]
fn source_expiry_at_or_before_sample_and_mapped_expiry_at_receipt_are_expired() {
    for expiry in [99, 100] {
        let mut correlation = correlation(1_000, 1_000, 100);
        assert_eq!(
            correlation
                .map_request(&opened(0, expiry), 1_000)
                .expect_err("not after sample"),
            ClockError::RequestExpired
        );
    }
    let mut correlation = correlation(1_000, 1_010, 100);
    let event = opened(100, 200);
    assert_eq!(
        correlation
            .map_request(&event, 1_100)
            .expect_err("exclusive expiry at receipt"),
        ClockError::RequestExpired
    );
    assert_eq!(
        correlation
            .map_request(&event, 1_101)
            .expect_err("past expiry"),
        ClockError::RequestExpired
    );
}

#[test]
fn authentic_expired_event_still_records_the_fresh_native_observation() {
    let mut correlation = correlation(1_000, 1_010, 100);
    assert_eq!(
        correlation
            .map_request(&opened(100, 150), 1_100)
            .expect_err("expired event"),
        ClockError::RequestExpired
    );
    assert_eq!(
        correlation
            .map_request(&opened(100, 300), 1_099)
            .expect_err("not a fresh processing timestamp"),
        ClockError::LocalClockRegressed
    );
    assert!(correlation.is_faulted());
}

#[test]
fn zero_samples_and_zero_phone_origin_are_supported() {
    let mut correlation = correlation(0, 0, 0);
    let window = correlation
        .map_request(&opened(0, 1), 0)
        .expect("zero origin, positive lifetime");
    assert_eq!(window.phone_issued_nanos(), 0);
    assert_eq!(window.phone_expiry_nanos(), 1);
}

#[test]
fn earlier_original_issuance_saturates_at_zero_without_inventing_lifetime() {
    let mut correlation = correlation(50, 60, 1_000);
    let window = correlation
        .map_request(&opened(0, 2_000), 60)
        .expect("pre-phone-origin issuance");
    assert_eq!(window.phone_issued_nanos(), 0);
    assert_eq!(window.phone_expiry_nanos(), 1_050);
    assert!(window.phone_expiry_nanos() - window.phone_issued_nanos() <= 2_000);
}

#[test]
fn future_issuance_is_rejected_but_equal_to_current_observation_is_valid() {
    let mut correlation = correlation(1_000, 1_010, 100);
    let event = opened(200, 300);
    assert_eq!(
        correlation
            .map_request(&event, 1_099)
            .expect_err("issuance lower bound is still future"),
        ClockError::IssuedInFuture
    );
    let window = correlation
        .map_request(&event, 1_100)
        .expect("issuance exactly now");
    assert_eq!(window.phone_issued_nanos(), 1_100);
}

#[test]
fn expiry_mapping_overflow_is_rejected_instead_of_wrapping_or_saturating() {
    let mut correlation = correlation(u64::MAX - 10, u64::MAX - 5, 0);
    assert_eq!(
        correlation
            .map_request(&opened(0, 20), u64::MAX - 5)
            .expect_err("overflow"),
        ClockError::ArithmeticOverflow
    );
    assert!(!correlation.is_faulted());
}

#[test]
fn near_maximum_service_ticks_use_checked_differences_without_overflow() {
    let mut correlation = correlation(1_000, 1_000, u64::MAX - 100);
    let window = correlation
        .map_request(&opened(u64::MAX - 200, u64::MAX), 1_000)
        .expect("bounded service-tick difference");
    assert_eq!(window.phone_issued_nanos(), 900);
    assert_eq!(window.phone_expiry_nanos(), 1_100);
}

#[test]
fn network_delay_can_only_shorten_remaining_life_for_one_fixed_mapping() {
    let event = opened(1_000, 1_100);
    for round_trip in [0, 10, 50, 99] {
        let mut correlation = correlation(10_000, 10_000 + round_trip, 1_000);
        let received_at = 10_000 + round_trip;
        let window = correlation
            .map_request(&event, received_at)
            .expect("remaining positive life");
        assert_eq!(window.phone_expiry_nanos(), 10_100);
        assert_eq!(window.phone_expiry_nanos() - received_at, 100 - round_trip);
    }
    let mut correlation = correlation(10_000, 10_100, 1_000);
    assert_eq!(
        correlation
            .map_request(&event, 10_100)
            .expect_err("delay consumed all life"),
        ClockError::RequestExpired
    );
}

#[test]
fn window_and_correlation_debug_never_include_binding_or_request_body() {
    let mut correlation = correlation(1_000, 1_010, 100);
    let window = correlation
        .map_request(&opened(100, 200), 1_020)
        .expect("window");
    assert_eq!(format!("{window:?}"), "MappedRequestWindow([redacted])");
    let diagnostic = format!("{correlation:?}");
    assert!(!diagnostic.contains("clock-fixture"));
    assert!(!diagnostic.contains("synthetic"));
    assert!(!diagnostic.contains("PcIdentity"));
    assert!(!diagnostic.contains("1000"));
}
