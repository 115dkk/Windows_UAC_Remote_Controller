// SPDX-License-Identifier: GPL-2.0-or-later

use notification_policy::{
    AlertMode, AuthenticatedPcOutcome, AuthenticatedRequestMetadata, CapacityError, CapacityLimits,
    ClockReading, DayMask, DropReason, Effect, EngineFault, MAX_ACTIVE_REQUESTS,
    MAX_REQUEST_LIFETIME_MILLIS, MAX_RETAINED_REQUESTS, MetadataError, MonotonicTime,
    NotificationEngine, NotificationPolicy, RequestKey, RequestOutcome, Schedule, TimeWindow,
    Weekday, WeeklySchedule, WithdrawalReason,
};

fn time(milliseconds: u64) -> MonotonicTime {
    MonotonicTime::from_millis(milliseconds)
}

fn clock(milliseconds: u64, minute: u16) -> ClockReading {
    ClockReading::new(
        time(milliseconds),
        notification_policy::LocalTime::new(Weekday::Monday, minute).unwrap(),
    )
}

fn key(request: u8) -> RequestKey {
    // Fixed nonsecret fixture identifiers, not authentication keys.
    RequestKey::new([1; 32], [2; 32], [request; 32])
}

fn metadata(request: u8, issued_at: u64, expires_at: u64) -> AuthenticatedRequestMetadata {
    AuthenticatedRequestMetadata::new(key(request), time(issued_at), time(expires_at)).unwrap()
}

fn engine() -> NotificationEngine {
    NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default())
}

fn weekly_policy(start: u16, end: u16) -> NotificationPolicy {
    NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new([TimeWindow::new(DayMask::ALL, start, end).unwrap()]).unwrap(),
        )),
        AlertMode::Silent,
    )
}

fn dropped(request: u8, reason: DropReason) -> Effect {
    Effect::Drop {
        key: key(request),
        reason,
    }
}

fn assert_no_history_or_show(effects: &[Effect]) {
    assert!(
        effects
            .iter()
            .all(|effect| !matches!(effect, Effect::RecordOutcome { .. } | Effect::Show(_)))
    );
}

#[test]
fn metadata_bounds_lifetime_without_overflow() {
    assert_eq!(
        AuthenticatedRequestMetadata::new(key(1), time(10), time(10)),
        Err(MetadataError::EmptyOrReversedLifetime)
    );
    assert_eq!(
        AuthenticatedRequestMetadata::new(key(1), time(11), time(10)),
        Err(MetadataError::EmptyOrReversedLifetime)
    );
    assert_eq!(
        AuthenticatedRequestMetadata::new(key(1), time(0), time(MAX_REQUEST_LIFETIME_MILLIS + 1)),
        Err(MetadataError::LifetimeTooLong)
    );
    let maximum = metadata(1, 0, MAX_REQUEST_LIFETIME_MILLIS);
    assert_eq!(maximum.issued_at().as_millis(), 0);
    assert_eq!(
        maximum.expires_at().as_millis(),
        MAX_REQUEST_LIFETIME_MILLIS
    );
    let at_limit = metadata(1, u64::MAX - 1, u64::MAX);
    let mut state = engine();
    assert!(matches!(
        state.receive(at_limit, clock(u64::MAX - 1, 600)).as_slice(),
        [Effect::Show(_)]
    ));
    assert_eq!(state.poll(clock(u64::MAX, 600)).len(), 2);
}

#[test]
fn capacities_are_validated_and_defaults_are_bounded() {
    assert_eq!(
        CapacityLimits::new(0, 1),
        Err(CapacityError::ActiveOutOfRange)
    );
    assert_eq!(
        CapacityLimits::new(MAX_ACTIVE_REQUESTS + 1, MAX_RETAINED_REQUESTS),
        Err(CapacityError::ActiveOutOfRange)
    );
    assert_eq!(
        CapacityLimits::new(2, 1),
        Err(CapacityError::RetainedOutOfRange)
    );
    assert_eq!(
        CapacityLimits::new(1, MAX_RETAINED_REQUESTS + 1),
        Err(CapacityError::RetainedOutOfRange)
    );
    let defaults = CapacityLimits::default();
    assert!(defaults.max_active() <= MAX_ACTIVE_REQUESTS);
    assert!(defaults.max_retained() <= MAX_RETAINED_REQUESTS);
}

#[test]
fn default_shows_but_explicit_disabled_drops_without_history() {
    let request = metadata(1, 0, 1000);
    let mut enabled = engine();
    assert!(matches!(
        enabled.receive(request, clock(1, 600)).as_slice(),
        [Effect::Show(_)]
    ));
    let mut disabled = NotificationEngine::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        CapacityLimits::default(),
    );
    assert_eq!(
        disabled.receive(request, clock(1, 600)),
        [dropped(1, DropReason::NotificationsDisabled)]
    );
    assert!(disabled.poll(clock(1000, 600)).is_empty());
    assert_eq!(disabled.retained_count(), 0);
}

#[test]
fn every_alert_preference_reaches_the_show_effect_explicitly() {
    for alert in [AlertMode::Sound, AlertMode::VibrateOnly, AlertMode::Silent] {
        let mut state = NotificationEngine::new(
            NotificationPolicy::new(None, alert),
            CapacityLimits::default(),
        );
        let effects = state.receive(metadata(1, 0, 1000), clock(1, 600));
        let [Effect::Show(pending)] = effects.as_slice() else {
            panic!("expected exactly one Show");
        };
        assert_eq!(pending.alert, alert);
        assert_eq!(pending.key, key(1));
        assert_eq!(pending.expires_at, time(1000));
    }
}

#[test]
fn duplicate_does_not_renotify_or_extend_original_deadline() {
    let mut state = engine();
    let request = metadata(1, 0, 1000);
    state.receive(request, clock(1, 600));
    assert_eq!(
        state.receive(request, clock(2, 600)),
        [dropped(1, DropReason::DuplicateActive)]
    );
    assert_eq!(
        state.receive(metadata(1, 0, 2000), clock(3, 600)),
        [dropped(1, DropReason::ConflictingDeadline)]
    );
    assert_eq!(state.next_deadline(), Some(time(1000)));
    assert!(
        state
            .check_pending(key(1), clock(999, 600))
            .pending
            .is_some()
    );
    let checked = state.check_pending(key(1), clock(1000, 600));
    assert!(checked.pending.is_none());
    assert_eq!(checked.effects.len(), 2);
    assert_eq!(
        state.receive(request, clock(1001, 600)),
        [dropped(1, DropReason::Expired)]
    );
}

#[test]
fn expired_on_arrival_never_shows_or_creates_history() {
    let mut state = engine();
    assert_eq!(
        state.receive(metadata(1, 0, 10), clock(10, 600)),
        [dropped(1, DropReason::Expired)]
    );
    assert_eq!(state.retained_count(), 0);
    assert_eq!(state.active_count(), 0);
    assert_eq!(state.next_deadline(), None);
}

#[test]
fn offline_deadline_withdraws_and_records_exactly_one_active_time_expiry() {
    let mut state = engine();
    state.receive(metadata(1, 0, 1000), clock(1, 600));
    assert!(state.poll(clock(999, 600)).is_empty());
    assert_eq!(
        state.poll(clock(1000, 600)),
        [
            Effect::Withdraw {
                key: key(1),
                reason: WithdrawalReason::ExpiredLocally,
            },
            Effect::RecordOutcome {
                key: key(1),
                outcome: RequestOutcome::ExpiredLocally,
            },
        ]
    );
    assert!(state.poll(clock(1000, 600)).is_empty());
    assert!(state.poll(clock(1001, 600)).is_empty());
    assert!(
        state
            .check_pending(key(1), clock(1001, 600))
            .pending
            .is_none()
    );
}

#[test]
fn authenticated_pc_outcomes_withdraw_once_and_suppress_replays() {
    for (pc_outcome, withdrawal, history) in [
        (
            AuthenticatedPcOutcome::Cancelled,
            WithdrawalReason::CancelledByPc,
            RequestOutcome::CancelledByPc,
        ),
        (
            AuthenticatedPcOutcome::Expired,
            WithdrawalReason::ExpiredByPc,
            RequestOutcome::ExpiredByPc,
        ),
        (
            AuthenticatedPcOutcome::Completed,
            WithdrawalReason::CompletedByPc,
            RequestOutcome::CompletedByPc,
        ),
    ] {
        let mut state = engine();
        let request = metadata(1, 0, 1000);
        state.receive(request, clock(1, 600));
        assert_eq!(
            state.resolve_from_pc(request, pc_outcome, clock(2, 600)),
            [
                Effect::Withdraw {
                    key: key(1),
                    reason: withdrawal,
                },
                Effect::RecordOutcome {
                    key: key(1),
                    outcome: history,
                },
            ]
        );
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.retained_count(), 1);
        assert_eq!(
            state.resolve_from_pc(request, pc_outcome, clock(3, 600)),
            [dropped(1, DropReason::PreviouslySuppressed)]
        );
        assert_eq!(
            state.receive(request, clock(4, 600)),
            [dropped(1, DropReason::PreviouslySuppressed)]
        );
        assert!(state.check_pending(key(1), clock(5, 600)).pending.is_none());
        assert!(state.poll(clock(1000, 600)).is_empty());
    }
}

#[test]
fn cancel_before_delivery_creates_only_a_minimal_suppression_marker() {
    let mut state = engine();
    let request = metadata(1, 0, 1000);
    assert_eq!(
        state.resolve_from_pc(request, AuthenticatedPcOutcome::Cancelled, clock(1, 600)),
        [dropped(1, DropReason::ResolutionBeforeDelivery)]
    );
    assert_eq!(
        state.receive(request, clock(2, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    assert_eq!(state.active_count(), 0);
    assert_eq!(state.retained_count(), 1);
    assert!(state.poll(clock(1000, 600)).is_empty());
}

#[test]
fn cancellation_targets_the_exact_pc_session_and_request() {
    let original = metadata(1, 0, 1000);
    for other_key in [
        RequestKey::new([9; 32], [2; 32], [1; 32]),
        RequestKey::new([1; 32], [9; 32], [1; 32]),
        RequestKey::new([1; 32], [2; 32], [9; 32]),
    ] {
        let mut state = engine();
        state.receive(original, clock(1, 600));
        let other = AuthenticatedRequestMetadata::new(other_key, time(0), time(1000)).unwrap();
        let effects =
            state.resolve_from_pc(other, AuthenticatedPcOutcome::Cancelled, clock(2, 600));
        assert_no_history_or_show(&effects);
        assert!(state.check_pending(key(1), clock(3, 600)).pending.is_some());
    }
}

#[test]
fn cancellation_cannot_retime_or_withdraw_another_lifetime() {
    let mut state = engine();
    state.receive(metadata(1, 0, 1000), clock(1, 600));
    assert_eq!(
        state.resolve_from_pc(
            metadata(1, 0, 2000),
            AuthenticatedPcOutcome::Cancelled,
            clock(2, 600),
        ),
        [dropped(1, DropReason::ConflictingDeadline)]
    );
    assert!(state.check_pending(key(1), clock(3, 600)).pending.is_some());
    assert_eq!(state.next_deadline(), Some(time(1000)));
}

#[test]
fn changed_issue_time_cannot_resolve_or_replace_a_retained_request() {
    let mut state = engine();
    let original = metadata(1, 0, 1000);
    let retimed = metadata(1, 1, 1000);
    state.receive(original, clock(1, 600));
    assert_eq!(
        state.receive(retimed, clock(2, 600)),
        [dropped(1, DropReason::ConflictingIssueTime)]
    );
    for outcome in [
        AuthenticatedPcOutcome::Cancelled,
        AuthenticatedPcOutcome::Expired,
        AuthenticatedPcOutcome::Completed,
    ] {
        assert_eq!(
            state.resolve_from_pc(retimed, outcome, clock(3, 600)),
            [dropped(1, DropReason::ConflictingIssueTime)]
        );
        assert!(state.check_pending(key(1), clock(3, 600)).pending.is_some());
    }
    assert_eq!(state.next_deadline(), Some(time(1000)));
    let resolved =
        state.resolve_from_pc(original, AuthenticatedPcOutcome::Cancelled, clock(4, 600));
    assert!(matches!(
        resolved.as_slice(),
        [Effect::Withdraw { .. }, Effect::RecordOutcome { .. }]
    ));
    assert_eq!(
        state.receive(retimed, clock(5, 600)),
        [dropped(1, DropReason::ConflictingIssueTime)]
    );
}

#[test]
fn off_hours_suppression_keeps_the_original_issue_time_without_history() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    let original = metadata(1, 0, 180_000);
    state.receive(original, clock(1, 599));
    let effects = state.receive(metadata(1, 1, 180_000), clock(60_000, 600));
    assert_eq!(effects, [dropped(1, DropReason::ConflictingIssueTime)]);
    assert_no_history_or_show(&effects);
    assert_eq!(
        state.receive(original, clock(60_001, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    assert_eq!(state.active_count(), 0);
    assert_eq!(state.retained_count(), 1);
}

#[test]
fn notification_debug_does_not_publish_protocol_identifiers() {
    let request = metadata(171, 0, 1000);
    assert_eq!(format!("{:?}", request.key()), "RequestKey([redacted])");
    let mut state = engine();
    let effects = state.receive(request, clock(1, 600));
    for debug in [
        format!("{request:?}"),
        format!("{effects:?}"),
        format!("{state:?}"),
    ] {
        assert!(debug.contains("RequestKey([redacted])"));
        assert!(!debug.contains("[171, 171"));
        assert!(!debug.contains("[1, 1"));
        assert!(!debug.contains("[2, 2"));
    }
}

#[test]
fn off_hours_request_is_not_queued_for_the_next_allowed_minute() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    let request = metadata(1, 0, 180_000);
    assert_eq!(
        state.receive(request, clock(1, 599)),
        [dropped(1, DropReason::OutsideAllowedTime)]
    );
    assert_eq!(
        state.receive(request, clock(60_001, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    assert!(state.poll(clock(120_000, 601)).is_empty());
    assert!(
        state
            .check_pending(key(1), clock(120_001, 601))
            .pending
            .is_none()
    );
    assert!(state.poll(clock(180_000, 602)).is_empty());
    assert_eq!(state.retained_count(), 0);
}

#[test]
fn off_hours_cancel_and_expiry_never_become_body_history() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    let request = metadata(1, 0, 1000);
    let mut effects = state.receive(request, clock(1, 599));
    effects.extend(state.resolve_from_pc(
        request,
        AuthenticatedPcOutcome::Cancelled,
        clock(2, 599),
    ));
    effects.extend(state.poll(clock(1000, 600)));
    assert_no_history_or_show(&effects);
}

#[test]
fn retained_off_hours_deadline_cannot_be_extended_or_shortened_by_retry() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    state.receive(metadata(1, 0, 120_000), clock(1, 599));
    for deadline in [90_000, 180_000] {
        assert_eq!(
            state.receive(metadata(1, 0, deadline), clock(60_000, 600)),
            [dropped(1, DropReason::ConflictingDeadline)]
        );
    }
    assert_eq!(
        state.receive(metadata(1, 0, 120_000), clock(90_000, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    assert_eq!(state.retained_count(), 1);
    assert!(state.poll(clock(120_000, 601)).is_empty());
    assert_eq!(state.retained_count(), 0);
}

#[test]
fn active_capacity_drop_gets_a_marker_and_never_fills_a_later_free_slot() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 3).unwrap(),
    );
    let first = metadata(1, 0, 1000);
    let second = metadata(2, 0, 2000);
    state.receive(first, clock(1, 600));
    assert_eq!(
        state.receive(second, clock(2, 600)),
        [dropped(2, DropReason::ActiveCapacity)]
    );
    state.resolve_from_pc(first, AuthenticatedPcOutcome::Cancelled, clock(3, 600));
    assert_eq!(
        state.receive(second, clock(4, 600)),
        [dropped(2, DropReason::PreviouslySuppressed)]
    );
    assert!(matches!(
        state
            .receive(metadata(3, 0, 2000), clock(5, 600))
            .as_slice(),
        [Effect::Show(_)]
    ));
    assert_eq!(state.active_count(), 1);
    assert_eq!(state.retained_count(), 3);
}

#[test]
fn retained_capacity_quarantine_closes_the_untracked_drop_replay_hole() {
    let mut state =
        NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::new(1, 1).unwrap());
    state.receive(metadata(1, 0, 60_000), clock(1, 599));
    let untracked = metadata(2, 0, 120_000);
    assert_eq!(
        state.receive(untracked, clock(2, 599)),
        [dropped(2, DropReason::RetainedCapacity)]
    );
    assert_eq!(state.retained_count(), 1);
    assert_eq!(state.quarantine_until(), Some(time(120_000)));
    assert!(state.poll(clock(60_000, 600)).is_empty());
    assert_eq!(state.retained_count(), 0);
    assert_eq!(
        state.receive(untracked, clock(60_001, 600)),
        [dropped(2, DropReason::CapacityQuarantine)]
    );
    assert_eq!(state.retained_count(), 0);
    assert_eq!(
        state.receive(untracked, clock(120_000, 601)),
        [dropped(2, DropReason::Expired)]
    );
    assert_eq!(state.quarantine_until(), None);
    assert!(matches!(
        state
            .receive(metadata(3, 120_000, 121_000), clock(120_000, 601))
            .as_slice(),
        [Effect::Show(_)]
    ));
}

#[test]
fn quarantine_tracks_largest_untracked_deadline_without_unbounded_storage() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        CapacityLimits::new(1, 1).unwrap(),
    );
    state.receive(metadata(1, 0, 100), clock(1, 600));
    state.receive(metadata(2, 0, 200), clock(2, 600));
    for request in 3..=250 {
        let effects = state.receive(metadata(request, 0, 500), clock(3, 600));
        assert_eq!(effects, [dropped(request, DropReason::CapacityQuarantine)]);
        assert_eq!(state.retained_count(), 1);
    }
    assert_eq!(state.quarantine_until(), Some(time(500)));
    assert!(state.poll(clock(100, 600)).is_empty());
    assert_eq!(state.retained_count(), 0);
    assert_eq!(state.quarantine_until(), Some(time(500)));
    assert!(state.poll(clock(500, 600)).is_empty());
    assert_eq!(state.quarantine_until(), None);
}

#[test]
fn saturation_preserves_existing_active_request_and_its_cancel_marker() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).unwrap(),
    );
    let original = metadata(1, 0, 1000);
    state.receive(original, clock(1, 600));
    state.receive(metadata(2, 0, 2000), clock(2, 600));
    assert!(state.check_pending(key(1), clock(3, 600)).pending.is_some());
    let cancelled =
        state.resolve_from_pc(original, AuthenticatedPcOutcome::Cancelled, clock(4, 600));
    assert_eq!(cancelled.len(), 2);
    assert_eq!(state.retained_count(), 1);
    assert_eq!(
        state.receive(original, clock(5, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
}

#[test]
fn unknown_cancellation_at_capacity_is_covered_by_quarantine() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).unwrap(),
    );
    state.receive(metadata(1, 0, 100), clock(1, 600));
    let cancelled = metadata(2, 0, 200);
    assert_eq!(
        state.resolve_from_pc(cancelled, AuthenticatedPcOutcome::Cancelled, clock(2, 600)),
        [dropped(2, DropReason::RetainedCapacity)]
    );
    state.poll(clock(100, 600));
    assert_eq!(
        state.receive(cancelled, clock(101, 600)),
        [dropped(2, DropReason::CapacityQuarantine)]
    );
}

#[test]
fn policy_restriction_withdraws_without_history_and_expansion_cannot_resurrect() {
    let mut state = engine();
    let request = metadata(1, 0, 1000);
    state.receive(request, clock(1, 600));
    let effects = state.update_policy(weekly_policy(660, 720), clock(2, 600));
    assert_eq!(
        effects,
        [Effect::Withdraw {
            key: key(1),
            reason: WithdrawalReason::ScheduleBlocked,
        }]
    );
    assert_no_history_or_show(&effects);
    assert!(state.check_pending(key(1), clock(3, 600)).pending.is_none());
    assert!(
        state
            .update_policy(NotificationPolicy::default(), clock(4, 600))
            .is_empty()
    );
    assert_eq!(
        state.receive(request, clock(5, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    assert!(state.poll(clock(1000, 600)).is_empty());
}

#[test]
fn explicit_disable_suppresses_pending_and_does_not_replay_when_reenabled() {
    let mut state = engine();
    let request = metadata(1, 0, 1000);
    state.receive(request, clock(1, 600));
    let effects = state.update_policy(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Sound),
        clock(2, 600),
    );
    assert_eq!(effects.len(), 1);
    assert!(matches!(effects[0], Effect::Withdraw { .. }));
    assert!(
        state
            .update_policy(NotificationPolicy::default(), clock(3, 600))
            .is_empty()
    );
    assert_eq!(
        state.receive(request, clock(4, 600)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
}

#[test]
fn reaching_end_exclusive_boundary_withdraws_even_without_network_activity() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    let request = metadata(1, 0, 180_000);
    state.receive(request, clock(1, 659));
    assert_eq!(
        state.poll(clock(60_000, 660)),
        [Effect::Withdraw {
            key: key(1),
            reason: WithdrawalReason::ScheduleBlocked,
        }]
    );
    assert!(
        state
            .check_pending(key(1), clock(60_001, 660))
            .pending
            .is_none()
    );
    assert!(state.poll(clock(180_000, 662)).is_empty());
}

#[test]
fn alert_change_updates_existing_notification_without_another_show() {
    let mut state = engine();
    state.receive(metadata(1, 0, 1000), clock(1, 600));
    for (observation, mode) in [
        (2, AlertMode::VibrateOnly),
        (3, AlertMode::Silent),
        (4, AlertMode::Sound),
    ] {
        assert_eq!(
            state.update_policy(NotificationPolicy::new(None, mode), clock(observation, 600)),
            [Effect::UpdateAlert {
                key: key(1),
                alert: mode
            }]
        );
        assert_eq!(
            state
                .check_pending(key(1), clock(observation, 600))
                .pending
                .unwrap()
                .alert,
            mode
        );
    }
}

#[test]
fn unchanged_alert_does_not_renotify_or_update() {
    let mut state = engine();
    state.receive(metadata(1, 0, 1000), clock(1, 600));
    assert!(
        state
            .update_policy(NotificationPolicy::default(), clock(2, 600))
            .is_empty()
    );
}

#[test]
fn full_256_bit_identities_are_distinct_even_with_identical_first_half() {
    let first = RequestKey::new([1; 32], [2; 32], [3; 32]);
    for field in 0..3 {
        let mut values = [[1; 32], [2; 32], [3; 32]];
        values[field][31] = 99;
        let different = RequestKey::new(values[0], values[1], values[2]);
        assert_ne!(first, different);
        let mut state = engine();
        let original = AuthenticatedRequestMetadata::new(first, time(0), time(1000)).unwrap();
        let other = AuthenticatedRequestMetadata::new(different, time(0), time(1000)).unwrap();
        state.receive(original, clock(1, 600));
        state.resolve_from_pc(other, AuthenticatedPcOutcome::Cancelled, clock(2, 600));
        assert!(state.check_pending(first, clock(3, 600)).pending.is_some());
    }
}

#[test]
fn queued_show_is_not_actionable_after_cancellation_or_expiry() {
    for cancel in [false, true] {
        let mut state = engine();
        let request = metadata(1, 0, 1000);
        let initial_show = state.receive(request, clock(1, 600));
        assert!(matches!(initial_show.as_slice(), [Effect::Show(_)]));
        if cancel {
            state.resolve_from_pc(request, AuthenticatedPcOutcome::Cancelled, clock(2, 600));
        }
        let checked = state.check_pending(key(1), clock(1000, 600));
        assert!(checked.pending.is_none());
    }
}

#[test]
fn backward_monotonic_time_latches_a_fault_and_withdraws_without_authorization() {
    let mut state = engine();
    let request = metadata(1, 0, 1000);
    state.receive(request, clock(100, 600));
    assert_eq!(
        state.poll(clock(99, 600)),
        [
            Effect::Withdraw {
                key: key(1),
                reason: WithdrawalReason::EngineFault
            },
            Effect::Fault(EngineFault::ClockMovedBackwards),
        ]
    );
    assert_eq!(state.fault(), Some(EngineFault::ClockMovedBackwards));
    assert!(
        state
            .check_pending(key(1), clock(101, 600))
            .pending
            .is_none()
    );
    assert_eq!(
        state.receive(request, clock(102, 600)),
        [dropped(1, DropReason::EngineFault)]
    );
    assert!(state.poll(clock(103, 600)).is_empty());
}

#[test]
fn future_issued_metadata_cannot_install_an_unbounded_quarantine_or_later_reappear() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).unwrap(),
    );
    state.receive(metadata(1, 0, 1000), clock(1, 600));
    let future = metadata(2, u64::MAX - 1, u64::MAX);
    let effects = state.receive(future, clock(2, 600));
    assert!(effects.contains(&Effect::Fault(EngineFault::FutureIssueTime)));
    assert!(effects.contains(&dropped(2, DropReason::InvalidRequestTime)));
    assert!(effects.contains(&Effect::Withdraw {
        key: key(1),
        reason: WithdrawalReason::EngineFault
    }));
    assert_no_history_or_show(&effects);
    assert_eq!(state.quarantine_until(), None);
    assert_eq!(state.retained_count(), 1);
    assert_eq!(
        state.receive(future, clock(u64::MAX - 1, 600)),
        [dropped(2, DropReason::EngineFault)]
    );
}

#[test]
fn repeated_local_minutes_are_not_monotonic_faults_or_replay_opportunities() {
    let mut state = NotificationEngine::new(weekly_policy(60, 180), CapacityLimits::default());
    let request = metadata(1, 0, 180_000);
    state.receive(request, clock(1, 119));
    assert!(state.poll(clock(60_000, 60)).is_empty());
    assert_eq!(state.fault(), None);
    assert_eq!(
        state.receive(request, clock(60_001, 60)),
        [dropped(1, DropReason::DuplicateActive)]
    );
    assert_eq!(state.poll(clock(180_000, 62)).len(), 2);
}

#[test]
fn skipped_local_window_does_not_queue_and_timezone_change_can_withdraw() {
    let mut state = NotificationEngine::new(weekly_policy(120, 180), CapacityLimits::default());
    let request = metadata(1, 0, 180_000);
    state.receive(request, clock(1, 119));
    assert!(state.poll(clock(60_000, 180)).is_empty());
    assert_eq!(
        state.receive(request, clock(60_001, 180)),
        [dropped(1, DropReason::PreviouslySuppressed)]
    );
    // A trusted timezone correction now reports an allowed local minute; only a
    // genuinely different authenticated request may be admitted.
    let shown = state.receive(metadata(2, 60_002, 180_000), clock(60_002, 150));
    assert!(matches!(shown.as_slice(), [Effect::Show(_)]));
    assert_eq!(
        state.poll(clock(60_003, 300)),
        [Effect::Withdraw {
            key: key(2),
            reason: WithdrawalReason::ScheduleBlocked
        }]
    );
    assert_eq!(state.fault(), None);
}

#[test]
fn active_expiry_history_and_off_hours_marker_cleanup_are_distinct() {
    let mut state = NotificationEngine::new(weekly_policy(600, 660), CapacityLimits::default());
    state.receive(metadata(1, 0, 1000), clock(1, 599));
    state.receive(metadata(2, 0, 1000), clock(2, 600));
    let effects = state.poll(clock(1000, 600));
    assert_eq!(effects.len(), 2);
    assert_eq!(
        effects[1],
        Effect::RecordOutcome {
            key: key(2),
            outcome: RequestOutcome::ExpiredLocally
        }
    );
    assert_eq!(state.retained_count(), 0);
}

#[test]
fn expired_or_suppressed_resolution_is_idempotent_without_new_history() {
    let mut state = engine();
    let request = metadata(1, 0, 10);
    state.receive(request, clock(1, 600));
    let at_expiry = state.resolve_from_pc(request, AuthenticatedPcOutcome::Expired, clock(10, 600));
    assert_eq!(at_expiry.len(), 3);
    assert_eq!(at_expiry[2], dropped(1, DropReason::Expired));
    assert_eq!(
        state.resolve_from_pc(request, AuthenticatedPcOutcome::Expired, clock(11, 600)),
        [dropped(1, DropReason::Expired)]
    );
}

#[test]
fn one_transition_has_a_bounded_number_of_effects() {
    let limits = CapacityLimits::new(MAX_ACTIVE_REQUESTS, MAX_RETAINED_REQUESTS).unwrap();
    let mut state = NotificationEngine::new(NotificationPolicy::default(), limits);
    for identifier in 0..MAX_RETAINED_REQUESTS {
        let mut id = [0; 32];
        id[..std::mem::size_of::<usize>()].copy_from_slice(&identifier.to_le_bytes());
        let exact_key = RequestKey::new([1; 32], [2; 32], id);
        let request = AuthenticatedRequestMetadata::new(exact_key, time(0), time(1000)).unwrap();
        let effects = state.receive(request, clock(1, 600));
        assert!(effects.len() <= 2 * limits.max_retained() + 2);
        assert!(state.active_count() <= limits.max_active());
        assert!(state.retained_count() <= limits.max_retained());
    }
    assert_eq!(state.retained_count(), limits.max_retained());
    let expiry = state.poll(clock(1000, 600));
    assert_eq!(expiry.len(), 2 * limits.max_active());
    assert_eq!(state.retained_count(), 0);
}
