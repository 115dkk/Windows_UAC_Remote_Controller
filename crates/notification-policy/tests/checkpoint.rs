// SPDX-License-Identifier: GPL-2.0-or-later

use notification_policy::{
    AlertMode, AuthenticatedRequestMetadata, CapacityLimits, CheckpointError, ClockReading,
    DropReason, Effect, EngineFault, LifecycleCheckpoint, LifecycleRecord, LocalTime,
    MAX_ACTIVE_REQUESTS, MAX_REQUEST_LIFETIME_MILLIS, MAX_RETAINED_REQUESTS, MonotonicTime,
    NotificationEngine, NotificationPolicy, RequestKey, RequestOutcome, Schedule, Weekday,
    WithdrawalReason,
};

fn time(milliseconds: u64) -> MonotonicTime {
    MonotonicTime::from_millis(milliseconds)
}

fn clock(milliseconds: u64) -> ClockReading {
    ClockReading::new(
        time(milliseconds),
        LocalTime::new(Weekday::Monday, 600).unwrap(),
    )
}

fn key(request: u8) -> RequestKey {
    // Synthetic nonsecret identifiers, not proof of an authenticated PC request.
    RequestKey::new([1; 32], [2; 32], [request; 32])
}

fn metadata(request: u8, issued_at: u64, expires_at: u64) -> AuthenticatedRequestMetadata {
    AuthenticatedRequestMetadata::new(key(request), time(issued_at), time(expires_at)).unwrap()
}

fn owner_round_trip(checkpoint: &LifecycleCheckpoint) -> LifecycleCheckpoint {
    // Synthetic, already-owned metadata only. This does not model private files,
    // PC signature verification, native boot identity, or lease continuity.
    LifecycleCheckpoint::from_trusted_storage(
        checkpoint.policy().clone(),
        checkpoint.limits(),
        checkpoint.records().to_vec(),
        checkpoint.quarantine_until(),
        checkpoint.last_observed(),
        checkpoint.fault(),
    )
    .unwrap()
}

fn stored_records(
    records: Vec<LifecycleRecord>,
    last_observed: u64,
) -> Result<LifecycleCheckpoint, CheckpointError> {
    LifecycleCheckpoint::from_trusted_storage(
        NotificationPolicy::default(),
        CapacityLimits::default(),
        records,
        None,
        Some(time(last_observed)),
        None,
    )
}

#[test]
fn checkpoint_restore_preserves_expiry_without_emitting_another_show() {
    let mut original =
        NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default());
    let request = metadata(1, 0, 1_000);
    assert!(matches!(
        original.receive(request, clock(100)).as_slice(),
        [Effect::Show(_)]
    ));

    let checkpoint = original.checkpoint();
    assert_eq!(checkpoint.records().len(), 1);
    assert_eq!(checkpoint.records()[0].metadata(), request);
    assert!(checkpoint.records()[0].is_active());
    assert_eq!(checkpoint.last_observed(), Some(time(100)));
    let mut restored = NotificationEngine::restore(checkpoint);

    assert_eq!(restored.next_deadline(), Some(time(1_000)));
    assert!(restored.poll(clock(999)).is_empty());
    assert_eq!(
        restored.poll(clock(1_000)),
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
    assert_eq!(restored.retained_count(), 0);
    assert!(restored.poll(clock(1_001)).is_empty());
}

#[test]
fn recovery_rejection_suppresses_only_the_selected_request_without_history() {
    let mut state =
        NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default());
    let rejected = metadata(1, 0, 1_000);
    let still_valid = metadata(2, 0, 1_000);
    state.receive(rejected, clock(100));
    state.receive(still_valid, clock(101));

    assert_eq!(
        state.suppress_for_recovery(key(1), clock(110)),
        [Effect::Withdraw {
            key: key(1),
            reason: WithdrawalReason::RecoveryRejected,
        }]
    );
    assert_eq!(state.active_count(), 1);
    assert_eq!(state.retained_count(), 2);
    assert!(state.check_pending(key(1), clock(110)).pending.is_none());
    assert!(state.check_pending(key(2), clock(110)).pending.is_some());
    assert!(state.suppress_for_recovery(key(1), clock(111)).is_empty());
    assert_eq!(
        state.receive(rejected, clock(112)),
        [Effect::Drop {
            key: key(1),
            reason: DropReason::PreviouslySuppressed,
        }]
    );
    assert_eq!(state.fault(), None);
}

#[test]
fn storage_round_trip_preserves_policy_limits_suppression_and_quarantine() {
    let policy = NotificationPolicy::new(None, AlertMode::VibrateOnly);
    let limits = CapacityLimits::new(1, 2).unwrap();
    let mut original = NotificationEngine::new(policy.clone(), limits);
    original.receive(metadata(1, 0, 1_000), clock(100));
    original.receive(metadata(2, 0, 2_000), clock(200));
    original.receive(metadata(3, 0, 3_000), clock(300));

    let checkpoint = original.checkpoint();
    assert_eq!(checkpoint.policy(), &policy);
    assert_eq!(checkpoint.limits(), limits);
    assert_eq!(checkpoint.last_observed(), Some(time(300)));
    assert_eq!(checkpoint.quarantine_until(), Some(time(3_000)));
    assert_eq!(checkpoint.fault(), None);
    assert_eq!(
        checkpoint.records(),
        &[
            LifecycleRecord::new(metadata(1, 0, 1_000), true),
            LifecycleRecord::new(metadata(2, 0, 2_000), false),
        ]
    );
    assert_eq!(owner_round_trip(&checkpoint), checkpoint);

    // Capturing a checkpoint never ties it to subsequent source-engine changes.
    original.update_policy(
        NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
        clock(301),
    );
    let mut restored = NotificationEngine::restore(checkpoint.clone());
    assert_eq!(restored.checkpoint(), checkpoint);
    assert_eq!(restored.active_count(), 1);
    assert!(restored.poll(clock(300)).is_empty());
    assert_eq!(
        restored.receive(metadata(2, 0, 2_000), clock(301)),
        [Effect::Drop {
            key: key(2),
            reason: DropReason::PreviouslySuppressed,
        }]
    );
    assert_eq!(
        restored.receive(metadata(4, 0, 2_000), clock(302)),
        [Effect::Drop {
            key: key(4),
            reason: DropReason::CapacityQuarantine,
        }]
    );
    assert_eq!(restored.quarantine_until(), Some(time(3_000)));
}

#[test]
fn fresh_empty_checkpoint_remains_unobserved_until_the_owner_polls() {
    let policy = NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent);
    let state = NotificationEngine::new(policy.clone(), CapacityLimits::default());
    let checkpoint = state.checkpoint();
    assert!(checkpoint.records().is_empty());
    assert_eq!(checkpoint.last_observed(), None);
    assert_eq!(checkpoint.quarantine_until(), None);
    assert_eq!(checkpoint.fault(), None);
    assert_eq!(owner_round_trip(&checkpoint), checkpoint);

    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(restored.policy(), &policy);
    assert_eq!(restored.checkpoint().last_observed(), None);
    assert!(restored.poll(clock(50)).is_empty());
    assert_eq!(restored.checkpoint().last_observed(), Some(time(50)));
}

#[test]
fn storage_requires_observation_for_any_record_quarantine_or_fault() {
    for (records, quarantine, fault) in [
        (
            vec![LifecycleRecord::new(metadata(1, 0, 1_000), false)],
            None,
            None,
        ),
        (vec![], Some(time(1)), None),
        (vec![], None, Some(EngineFault::ClockMovedBackwards)),
        (vec![], None, Some(EngineFault::FutureIssueTime)),
    ] {
        assert_eq!(
            LifecycleCheckpoint::from_trusted_storage(
                NotificationPolicy::default(),
                CapacityLimits::default(),
                records,
                quarantine,
                None,
                fault,
            ),
            Err(CheckpointError::MissingObservation)
        );
    }
}

#[test]
fn storage_enforces_inclusive_issue_and_exclusive_expiry_for_every_record_state() {
    for active in [false, true] {
        assert_eq!(
            stored_records(
                vec![LifecycleRecord::new(metadata(1, 101, 200), active)],
                100
            ),
            Err(CheckpointError::FutureIssueTime)
        );
        for expires_at in [99, 100] {
            assert_eq!(
                stored_records(
                    vec![LifecycleRecord::new(metadata(1, 0, expires_at), active)],
                    100,
                ),
                Err(CheckpointError::ExpiredRecord)
            );
        }
        let valid = stored_records(
            vec![LifecycleRecord::new(metadata(1, 100, 101), active)],
            100,
        )
        .unwrap();
        assert_eq!(valid.records()[0].is_active(), active);
        assert_eq!(valid.records()[0].metadata().issued_at(), time(100));
    }
}

#[test]
fn storage_enforces_configured_retained_and_active_capacity_before_restore() {
    let limits = CapacityLimits::new(1, 2).unwrap();
    let make = |records| {
        LifecycleCheckpoint::from_trusted_storage(
            NotificationPolicy::default(),
            limits,
            records,
            None,
            Some(time(100)),
            None,
        )
    };
    assert_eq!(
        make(vec![
            LifecycleRecord::new(metadata(1, 0, 1_000), false),
            LifecycleRecord::new(metadata(2, 0, 1_000), false),
            LifecycleRecord::new(metadata(3, 0, 1_000), false),
        ]),
        Err(CheckpointError::RetainedCapacityExceeded)
    );
    assert_eq!(
        make(vec![
            LifecycleRecord::new(metadata(1, 0, 1_000), true),
            LifecycleRecord::new(metadata(2, 0, 1_000), true),
        ]),
        Err(CheckpointError::ActiveCapacityExceeded)
    );
    let boundary = make(vec![
        LifecycleRecord::new(metadata(2, 0, 1_000), false),
        LifecycleRecord::new(metadata(1, 0, 1_000), true),
    ])
    .unwrap();
    let restored = NotificationEngine::restore(boundary);
    assert_eq!(restored.active_count(), 1);
    assert_eq!(restored.retained_count(), 2);
}

#[test]
fn storage_round_trips_the_global_capacity_boundary_and_rejects_one_more_record() {
    let limits = CapacityLimits::new(MAX_ACTIVE_REQUESTS, MAX_RETAINED_REQUESTS).unwrap();
    let mut records: Vec<_> = (0..MAX_RETAINED_REQUESTS)
        .map(|index| {
            let mut request_id = [0; 32];
            request_id[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            LifecycleRecord::new(
                AuthenticatedRequestMetadata::new(
                    RequestKey::new([1; 32], [2; 32], request_id),
                    time(0),
                    time(1_000),
                )
                .unwrap(),
                index < MAX_ACTIVE_REQUESTS,
            )
        })
        .collect();
    let make = |records| {
        LifecycleCheckpoint::from_trusted_storage(
            NotificationPolicy::default(),
            limits,
            records,
            None,
            Some(time(100)),
            None,
        )
    };
    let checkpoint = make(records.clone()).unwrap();
    let restored = NotificationEngine::restore(owner_round_trip(&checkpoint));
    assert_eq!(restored.active_count(), MAX_ACTIVE_REQUESTS);
    assert_eq!(restored.retained_count(), MAX_RETAINED_REQUESTS);

    records.push(LifecycleRecord::new(metadata(0xff, 0, 1_000), false));
    assert_eq!(
        make(records),
        Err(CheckpointError::RetainedCapacityExceeded)
    );
}

#[test]
fn storage_rejects_duplicate_keys_even_when_lifetime_or_state_differs() {
    for duplicate in [
        LifecycleRecord::new(metadata(1, 0, 1_000), false),
        LifecycleRecord::new(metadata(1, 0, 1_000), true),
        LifecycleRecord::new(metadata(1, 1, 1_000), false),
        LifecycleRecord::new(metadata(1, 0, 1_001), false),
    ] {
        assert_eq!(
            stored_records(
                vec![
                    LifecycleRecord::new(metadata(2, 0, 1_000), false),
                    duplicate,
                    LifecycleRecord::new(metadata(1, 0, 1_000), false),
                ],
                100,
            ),
            Err(CheckpointError::DuplicateRequestKey)
        );
    }
}

#[test]
fn storage_uses_every_byte_of_all_three_key_parts_without_truncation() {
    let base_parts = ([17; 32], [23; 32], [29; 32]);
    let mut different_pc = base_parts.0;
    different_pc[31] ^= 1;
    let mut different_epoch = base_parts.1;
    different_epoch[31] ^= 1;
    let mut different_request = base_parts.2;
    different_request[31] ^= 1;
    let parts = [
        base_parts,
        (different_pc, base_parts.1, base_parts.2),
        (base_parts.0, different_epoch, base_parts.2),
        (base_parts.0, base_parts.1, different_request),
    ];
    let records = parts
        .into_iter()
        .map(|(pc, epoch, request)| {
            let full_key = RequestKey::new(pc, epoch, request);
            assert_eq!(full_key.pc(), pc);
            assert_eq!(full_key.epoch(), epoch);
            assert_eq!(full_key.request(), request);
            LifecycleRecord::new(
                AuthenticatedRequestMetadata::new(full_key, time(0), time(1_000)).unwrap(),
                false,
            )
        })
        .collect();
    let checkpoint = stored_records(records, 100).unwrap();
    assert_eq!(checkpoint.records().len(), 4);
    assert_eq!(
        NotificationEngine::restore(checkpoint.clone()).checkpoint(),
        checkpoint
    );
}

#[test]
fn storage_rejects_expired_or_overlong_quarantine_without_overflow() {
    let make = |previous, deadline| {
        LifecycleCheckpoint::from_trusted_storage(
            NotificationPolicy::default(),
            CapacityLimits::default(),
            vec![],
            Some(time(deadline)),
            Some(time(previous)),
            None,
        )
    };
    for deadline in [99, 100] {
        assert_eq!(make(100, deadline), Err(CheckpointError::ExpiredQuarantine));
    }
    assert_eq!(
        make(100, 100 + MAX_REQUEST_LIFETIME_MILLIS + 1),
        Err(CheckpointError::QuarantineTooLong)
    );
    assert_eq!(make(0, u64::MAX), Err(CheckpointError::QuarantineTooLong));
    assert_eq!(
        make(100, 100 + MAX_REQUEST_LIFETIME_MILLIS)
            .unwrap()
            .quarantine_until(),
        Some(time(100 + MAX_REQUEST_LIFETIME_MILLIS))
    );
    assert_eq!(
        make(u64::MAX - 1, u64::MAX).unwrap().quarantine_until(),
        Some(time(u64::MAX))
    );
}

#[test]
fn reachable_quarantine_near_clock_limit_round_trips_and_expires_once() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).unwrap(),
    );
    state.receive(metadata(1, u64::MAX - 2, u64::MAX), clock(u64::MAX - 2));
    state.receive(metadata(2, u64::MAX - 2, u64::MAX), clock(u64::MAX - 1));
    let checkpoint = owner_round_trip(&state.checkpoint());
    assert_eq!(checkpoint.quarantine_until(), Some(time(u64::MAX)));
    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(restored.poll(clock(u64::MAX)).len(), 2);
    assert_eq!(restored.retained_count(), 0);
    assert_eq!(restored.quarantine_until(), None);
    assert!(restored.poll(clock(u64::MAX)).is_empty());
}

#[test]
fn empty_quarantined_engine_restores_without_reopening_admission() {
    let mut state = NotificationEngine::new(
        NotificationPolicy::default(),
        CapacityLimits::new(1, 1).unwrap(),
    );
    state.receive(metadata(1, 0, 110), clock(100));
    state.receive(metadata(2, 0, 1_000), clock(101));
    state.poll(clock(110));
    let checkpoint = owner_round_trip(&state.checkpoint());
    assert!(checkpoint.records().is_empty());
    assert_eq!(checkpoint.quarantine_until(), Some(time(1_000)));
    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(
        restored.receive(metadata(3, 0, 1_000), clock(111)),
        [Effect::Drop {
            key: key(3),
            reason: DropReason::CapacityQuarantine,
        }]
    );
    assert!(restored.poll(clock(1_000)).is_empty());
    assert_eq!(restored.quarantine_until(), None);
    assert!(matches!(
        restored
            .receive(metadata(4, 1_000, 2_000), clock(1_000))
            .as_slice(),
        [Effect::Show(_)]
    ));
}

#[test]
fn storage_rejects_active_records_in_faulted_or_disabled_state() {
    for fault in [
        EngineFault::ClockMovedBackwards,
        EngineFault::FutureIssueTime,
    ] {
        assert_eq!(
            LifecycleCheckpoint::from_trusted_storage(
                NotificationPolicy::default(),
                CapacityLimits::default(),
                vec![LifecycleRecord::new(metadata(1, 0, 1_000), true)],
                None,
                Some(time(100)),
                Some(fault),
            ),
            Err(CheckpointError::FaultWithActiveRecords)
        );
    }
    for active in [false, true] {
        let result = LifecycleCheckpoint::from_trusted_storage(
            NotificationPolicy::new(Some(Schedule::Never), AlertMode::Silent),
            CapacityLimits::default(),
            vec![LifecycleRecord::new(metadata(1, 0, 1_000), active)],
            None,
            Some(time(100)),
            None,
        );
        if active {
            assert_eq!(
                result,
                Err(CheckpointError::DisabledPolicyWithActiveRecords)
            );
        } else {
            assert!(!result.unwrap().records()[0].is_active());
        }
    }
}

#[test]
fn faulted_engine_round_trip_never_clears_the_fault_or_advances_its_clock() {
    for fault in [
        EngineFault::ClockMovedBackwards,
        EngineFault::FutureIssueTime,
    ] {
        let mut state =
            NotificationEngine::new(NotificationPolicy::default(), CapacityLimits::default());
        state.receive(metadata(1, 0, 1_000), clock(100));
        let effects = match fault {
            EngineFault::ClockMovedBackwards => state.poll(clock(99)),
            EngineFault::FutureIssueTime => state.receive(metadata(2, 101, 1_000), clock(100)),
        };
        assert!(effects.contains(&Effect::Fault(fault)));
        let checkpoint = owner_round_trip(&state.checkpoint());
        assert_eq!(checkpoint.fault(), Some(fault));
        assert_eq!(checkpoint.last_observed(), Some(time(100)));
        assert!(!checkpoint.records()[0].is_active());

        let mut restored = NotificationEngine::restore(checkpoint.clone());
        assert!(restored.poll(clock(5_000)).is_empty());
        assert_eq!(restored.checkpoint(), checkpoint);
        assert!(
            restored
                .check_pending(key(1), clock(5_000))
                .pending
                .is_none()
        );
        assert_eq!(
            restored.receive(metadata(3, 4_000, 6_000), clock(5_000)),
            [Effect::Drop {
                key: key(3),
                reason: DropReason::EngineFault,
            }]
        );
        assert_eq!(owner_round_trip(&restored.checkpoint()), checkpoint);
    }
}

#[test]
fn restored_engine_rejects_a_clock_before_the_saved_observation() {
    let checkpoint =
        stored_records(vec![LifecycleRecord::new(metadata(1, 0, 1_000), true)], 100).unwrap();
    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(
        restored.poll(clock(99)),
        [
            Effect::Withdraw {
                key: key(1),
                reason: WithdrawalReason::EngineFault,
            },
            Effect::Fault(EngineFault::ClockMovedBackwards),
        ]
    );
    assert_eq!(restored.active_count(), 0);
    assert_eq!(restored.checkpoint().last_observed(), Some(time(100)));
}

#[test]
fn recovery_rejection_runs_expiry_before_attempting_retirement() {
    let checkpoint =
        stored_records(vec![LifecycleRecord::new(metadata(1, 0, 1_000), true)], 100).unwrap();
    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(
        restored.suppress_for_recovery(key(1), clock(1_000)),
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
    assert!(
        restored
            .suppress_for_recovery(key(1), clock(1_001))
            .is_empty()
    );
}

#[test]
fn recovery_rejection_does_not_add_effects_for_unknown_or_faulted_requests() {
    let checkpoint =
        stored_records(vec![LifecycleRecord::new(metadata(1, 0, 1_000), true)], 100).unwrap();
    let mut restored = NotificationEngine::restore(checkpoint);
    assert!(
        restored
            .suppress_for_recovery(key(2), clock(100))
            .is_empty()
    );
    assert_eq!(restored.active_count(), 1);
    assert_eq!(
        restored.suppress_for_recovery(key(1), clock(99)),
        [
            Effect::Withdraw {
                key: key(1),
                reason: WithdrawalReason::EngineFault,
            },
            Effect::Fault(EngineFault::ClockMovedBackwards),
        ]
    );
    assert!(
        restored
            .suppress_for_recovery(key(1), clock(101))
            .is_empty()
    );
    assert_eq!(restored.fault(), Some(EngineFault::ClockMovedBackwards));
}

#[test]
fn recovery_rejection_tombstone_survives_storage_without_history_or_resurrection() {
    let checkpoint =
        stored_records(vec![LifecycleRecord::new(metadata(1, 0, 1_000), true)], 100).unwrap();
    let mut state = NotificationEngine::restore(checkpoint);
    state.suppress_for_recovery(key(1), clock(101));
    let checkpoint = owner_round_trip(&state.checkpoint());
    assert!(!checkpoint.records()[0].is_active());
    let mut restored = NotificationEngine::restore(checkpoint);
    assert_eq!(
        restored.receive(metadata(1, 0, 1_000), clock(102)),
        [Effect::Drop {
            key: key(1),
            reason: DropReason::PreviouslySuppressed,
        }]
    );
    assert!(restored.poll(clock(1_000)).is_empty());
    assert_eq!(restored.retained_count(), 0);
}

#[test]
fn checkpoint_and_record_debug_do_not_print_identifiers() {
    let record = LifecycleRecord::new(metadata(0xa5, 0, 1_000), true);
    let checkpoint = stored_records(vec![record], 100).unwrap();
    let checkpoint_debug = format!("{checkpoint:?}");
    assert!(checkpoint_debug.contains("record_count: 1"));
    assert!(!checkpoint_debug.contains("AuthenticatedRequestMetadata"));
    assert!(!checkpoint_debug.contains("RequestKey"));
    let record_debug = format!("{record:?}");
    assert!(record_debug.contains("RequestKey([redacted])"));
    assert!(!record_debug.contains("165, 165"));
}
