// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure trusted-metadata seam, not signed or native authorization evidence.
use notification_policy::{
    AlertMode, AuthenticatedRequestMetadata, CapacityLimits, ClockReading, Effect, LocalTime,
    MonotonicTime, NotificationEngine, NotificationPolicy, RequestKey, Schedule, Weekday,
};

fn clock(ms: u64) -> ClockReading {
    ClockReading::new(
        MonotonicTime::from_millis(ms),
        LocalTime::new(Weekday::Monday, 600).unwrap(),
    )
}
fn metadata(issued: u64, expiry: u64) -> AuthenticatedRequestMetadata {
    AuthenticatedRequestMetadata::new(
        RequestKey::new([1; 32], [2; 32], [3; 32]),
        MonotonicTime::from_millis(issued),
        MonotonicTime::from_millis(expiry),
    )
    .unwrap()
}
#[test]
fn replacement_refreshes_active_without_fresh_alert_or_terminal_history() {
    let mut engine =
        NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default());
    let previous = metadata(0, 1000);
    engine.receive(previous, clock(0));
    let effects = engine.renew(Some(previous), metadata(900, 1900), clock(900));
    assert!(
        matches!(effects.as_slice(), [Effect::Restore(row)] if row.expires_at.as_millis() == 1900)
    );
    assert_eq!(engine.active_count(), 1);
}
#[test]
fn policy_suppression_and_absent_expired_state_never_revive() {
    let previous = metadata(0, 1000);
    let mut engine = NotificationEngine::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::default(),
    );
    engine.receive(previous, clock(0));
    engine.update_policy(NotificationPolicy::default(), clock(10));
    let effects = engine.renew(Some(previous), metadata(900, 1900), clock(900));
    assert!(effects.iter().all(|effect| !matches!(
        effect,
        Effect::Show(_) | Effect::Restore(_) | Effect::RecordOutcome { .. }
    )));
    assert_eq!(engine.active_count(), 0);
    engine.poll(clock(2000));
    let effects = engine.renew(Some(metadata(900, 1900)), metadata(2000, 3000), clock(2000));
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Effect::Show(_) | Effect::Restore(_)))
    );
    assert_eq!(engine.active_count(), 0);
}
