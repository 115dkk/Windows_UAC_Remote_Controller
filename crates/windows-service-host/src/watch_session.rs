// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure bounded state for the supervised prompt watcher.
#![forbid(unsafe_code)]
// Only the 64-bit Windows watch owner drives this machine; other targets compile
// it for the shared WatchSession type without ever constructing it.
#![cfg_attr(not(all(windows, target_pointer_width = "64")), allow(dead_code))]

use crate::{
    ProbeSupervisorError, WatchEvent,
    management_protocol::{WatcherHealth, WatcherRefusal},
    probe_supervisor::{WatchLifecycle, WatchObservation},
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use windows_prompt_probe::supervision::{
    ApplyOutcome, HelperMessage, MAX_PARKED_PROMPTS, TargetIdentity,
};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OBSERVATIONS: usize = 64;
const MAX_POLL_OBSERVATIONS: usize = 16;
const MAX_CONSECUTIVE_FAILURES: u32 = 8;
const FIRST_START_DELAYS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageError {
    Protocol,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrackedTarget {
    identity: TargetIdentity,
    applied: bool,
    replied: bool,
}

pub(crate) struct WatchMachine {
    observations: VecDeque<WatchObservation>,
    tracked: Option<TrackedTarget>,
    last_sequence: u32,
    last_message: Instant,
    failures: u32,
    first_start_failures: usize,
    retry_at: Option<Instant>,
    cleanup_pending: bool,
    running: bool,
    unavailable: bool,
    shutting_down: bool,
    ever_started: bool,
    run_has_heartbeat: bool,
    alive_recorded: bool,
    health: Option<WatcherHealth>,
    reported_start_error: Option<ProbeSupervisorError>,
    initial_unavailable_recorded: bool,
}

impl WatchMachine {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            observations: VecDeque::new(),
            tracked: None,
            last_sequence: 0,
            last_message: now,
            failures: 0,
            first_start_failures: 0,
            retry_at: Some(now),
            cleanup_pending: false,
            running: false,
            unavailable: false,
            shutting_down: false,
            ever_started: false,
            run_has_heartbeat: false,
            alive_recorded: false,
            health: None,
            reported_start_error: None,
            initial_unavailable_recorded: false,
        }
    }

    pub(crate) fn launched(&mut self, now: Instant) -> Result<(), MessageError> {
        if self.unavailable || self.shutting_down || self.running || self.retry_at.is_none() {
            return Err(MessageError::Protocol);
        }
        self.running = true;
        self.cleanup_pending = false;
        self.retry_at = None;
        self.last_message = now;
        self.run_has_heartbeat = false;
        self.observe_health(WatcherHealth::Starting)?;
        if self.ever_started {
            self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Restarted))?;
            self.enqueue(WatchObservation::Event(WatchEvent::HelperRestarted {
                attempt: self.failures,
            }))?;
        } else {
            self.ever_started = true;
            self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Started))?;
        }
        Ok(())
    }

    pub(crate) fn launch_refused(
        &mut self,
        error: ProbeSupervisorError,
        retained: bool,
        now: Instant,
    ) -> Result<(), MessageError> {
        self.running = false;
        self.clear_run_state();
        self.cleanup_pending = retained;
        if !self.ever_started && !retained {
            let delay =
                FIRST_START_DELAYS[self.first_start_failures.min(FIRST_START_DELAYS.len() - 1)];
            self.first_start_failures = self.first_start_failures.saturating_add(1);
            self.retry_at = Some(now.checked_add(delay).unwrap_or(now));
            self.observe_health(WatcherHealth::Unavailable(classify(error)))?;
            self.record_initial_refusal(error)?;
            return Ok(());
        }

        let exhausted = if error == ProbeSupervisorError::NoInteractiveSession && !retained {
            self.retry_at = Some(now.checked_add(Duration::from_secs(60)).unwrap_or(now));
            false
        } else {
            self.schedule_failure(now)
        };
        self.observe_health(WatcherHealth::Unavailable(classify(error)))?;
        if !self.ever_started {
            self.record_initial_refusal(error)?;
        }
        if exhausted {
            self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Unavailable))?;
            self.enqueue(WatchObservation::Event(WatchEvent::HelperUnavailable))?;
        }
        Ok(())
    }

    pub(crate) fn ingest(
        &mut self,
        message: HelperMessage,
        session: u32,
        now: Instant,
    ) -> Result<(), MessageError> {
        if !self.running || self.unavailable || self.shutting_down || session == 0 {
            return Err(MessageError::Protocol);
        }
        let heartbeat = matches!(message, HelperMessage::Heartbeat { .. });
        match message {
            HelperMessage::Appeared { target, report } => {
                if self.tracked.is_some()
                    || !valid_target(target)
                    || target.sequence <= self.last_sequence
                {
                    return Err(MessageError::Protocol);
                }
                self.last_sequence = target.sequence;
                self.tracked = Some(TrackedTarget {
                    identity: target,
                    applied: false,
                    replied: false,
                });
                self.enqueue(WatchObservation::Event(WatchEvent::Appeared {
                    target,
                    report,
                    session,
                }))
            }
            HelperMessage::Gone { target, reason } => {
                if self.tracked.map(|tracked| tracked.identity) != Some(target) {
                    return Err(MessageError::Protocol);
                }
                self.tracked = None;
                self.enqueue(WatchObservation::Event(WatchEvent::Gone { target, reason }))
            }
            HelperMessage::Applied { target, outcome } => {
                if !matches!(
                    self.tracked,
                    Some(TrackedTarget {
                        identity,
                        applied: true,
                        replied: false,
                    }) if identity == target
                ) {
                    return Err(MessageError::Protocol);
                }
                if matches!(outcome, ApplyOutcome::Gone) {
                    self.tracked = None;
                } else if let Some(tracked) = &mut self.tracked {
                    tracked.replied = true;
                }
                self.enqueue(WatchObservation::Event(WatchEvent::Applied {
                    target,
                    outcome,
                }))
            }
            HelperMessage::Heartbeat { sequence } => {
                let expected = self
                    .tracked
                    .map_or(self.last_sequence, |tracked| tracked.identity.sequence);
                if sequence != expected {
                    return Err(MessageError::Protocol);
                }
                // The helper emits this only after a fresh, double-captured
                // same-content census. Never renew a consumed/applying target.
                if let Some(tracked) = self.tracked.filter(|tracked| !tracked.applied) {
                    self.enqueue(WatchObservation::Event(WatchEvent::StillPresent {
                        target: tracked.identity,
                    }))
                } else {
                    Ok(())
                }
            }
            HelperMessage::Parked { count } => {
                if count > MAX_PARKED_PROMPTS {
                    return Err(MessageError::Protocol);
                }
                self.enqueue(WatchObservation::Event(WatchEvent::ParkedChanged { count }))
            }
        }?;
        self.last_message = now;
        self.failures = 0;
        if heartbeat && !self.run_has_heartbeat {
            self.run_has_heartbeat = true;
            self.observe_health(WatcherHealth::Running)?;
            if !self.alive_recorded {
                self.alive_recorded = true;
                self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Alive))?;
            }
        }
        Ok(())
    }

    pub(crate) fn reserve_apply(
        &mut self,
        target: TargetIdentity,
    ) -> Result<(), ProbeSupervisorError> {
        if !self.running || self.unavailable || self.shutting_down {
            return Err(ProbeSupervisorError::ApplyRefused);
        }
        match &mut self.tracked {
            Some(tracked) if tracked.identity == target && !tracked.applied => {
                tracked.applied = true;
                Ok(())
            }
            _ => Err(ProbeSupervisorError::ApplyRefused),
        }
    }

    pub(crate) fn heartbeat_expired(&self, now: Instant) -> bool {
        self.running
            && !self.shutting_down
            && now.saturating_duration_since(self.last_message) >= HEARTBEAT_TIMEOUT
    }

    pub(crate) fn failed(&mut self, now: Instant, cleanup_pending: bool) {
        if self.unavailable || self.shutting_down {
            return;
        }
        self.running = false;
        self.clear_run_state();
        self.cleanup_pending = cleanup_pending;
        let exhausted = self.schedule_failure(now);
        let _ = self.observe_health(WatcherHealth::Unavailable(WatcherRefusal::HelperFailed));
        if exhausted {
            let _ = self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Unavailable));
            let _ = self.enqueue(WatchObservation::Event(WatchEvent::HelperUnavailable));
        }
    }

    pub(crate) fn defer_cleanup(&mut self, now: Instant) {
        let delay = failure_delay(self.failures.max(1));
        self.retry_at = Some(now.checked_add(delay).unwrap_or(now));
        self.cleanup_pending = true;
    }

    pub(crate) fn cleanup_confirmed(&mut self) {
        self.cleanup_pending = false;
    }

    pub(crate) fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }

    pub(crate) fn retry_due(&self, now: Instant) -> bool {
        !self.unavailable
            && !self.shutting_down
            && self.retry_at.is_some_and(|deadline| now >= deadline)
    }

    pub(crate) fn drain(&mut self) -> Vec<WatchObservation> {
        let count = self.observations.len().min(MAX_POLL_OBSERVATIONS);
        self.observations.drain(..count).collect()
    }

    pub(crate) fn begin_shutdown(&mut self) -> bool {
        if self.shutting_down {
            return false;
        }
        self.shutting_down = true;
        self.running = false;
        self.clear_run_state();
        self.retry_at = None;
        true
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    pub(crate) fn is_running(&self) -> bool {
        self.running
    }

    pub(crate) fn is_unavailable(&self) -> bool {
        self.unavailable
    }

    fn schedule_failure(&mut self, now: Instant) -> bool {
        self.failures = self.failures.saturating_add(1);
        let delay = failure_delay(self.failures);
        self.retry_at = Some(now.checked_add(delay).unwrap_or(now));
        self.failures == MAX_CONSECUTIVE_FAILURES.saturating_add(1)
    }

    fn record_initial_refusal(&mut self, error: ProbeSupervisorError) -> Result<(), MessageError> {
        if self.reported_start_error.replace(error) != Some(error) {
            self.enqueue(WatchObservation::StartFailed(error))?;
        }
        if !self.initial_unavailable_recorded {
            self.initial_unavailable_recorded = true;
            self.enqueue(WatchObservation::Lifecycle(WatchLifecycle::Unavailable))?;
        }
        Ok(())
    }

    fn observe_health(&mut self, health: WatcherHealth) -> Result<(), MessageError> {
        if self.health == Some(health) {
            return Ok(());
        }
        self.health = Some(health);
        self.enqueue(WatchObservation::Health(health))
    }

    fn clear_run_state(&mut self) {
        self.tracked = None;
        self.last_sequence = 0;
        self.run_has_heartbeat = false;
    }

    fn enqueue(&mut self, observation: WatchObservation) -> Result<(), MessageError> {
        if self.observations.len() >= MAX_OBSERVATIONS {
            self.make_unavailable();
            return Err(MessageError::Overflow);
        }
        self.observations.push_back(observation);
        Ok(())
    }

    fn make_unavailable(&mut self) {
        self.running = false;
        self.unavailable = true;
        self.cleanup_pending = true;
        self.clear_run_state();
        self.retry_at = None;
        self.health = Some(WatcherHealth::Unavailable(WatcherRefusal::HelperFailed));
        self.observations.clear();
        self.observations
            .push_back(WatchObservation::Health(WatcherHealth::Unavailable(
                WatcherRefusal::HelperFailed,
            )));
        self.observations
            .push_back(WatchObservation::Lifecycle(WatchLifecycle::Unavailable));
        self.observations
            .push_back(WatchObservation::Event(WatchEvent::HelperUnavailable));
    }
}

fn failure_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(4);
    Duration::from_secs(5_u64.checked_shl(shift).unwrap_or(60).min(60))
}

fn classify(error: ProbeSupervisorError) -> WatcherRefusal {
    match error {
        ProbeSupervisorError::NoInteractiveSession
        | ProbeSupervisorError::SessionChanged
        | ProbeSupervisorError::AmbiguousSessions => WatcherRefusal::NoSignedInUser,
        ProbeSupervisorError::HelperDamaged => WatcherRefusal::HelperDamaged,
        _ => WatcherRefusal::HelperFailed,
    }
}

fn valid_target(target: TargetIdentity) -> bool {
    target.hwnd != 0 && target.pid != 0 && target.created != 0 && target.sequence != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_prompt_probe::{
        LabelKind, ProbeCounts, ProbeReport, PromptContentObservation, PromptLabel,
        supervision::{GoneReason, RefusalReason},
    };

    fn target(sequence: u32) -> TargetIdentity {
        TargetIdentity {
            hwnd: u64::from(sequence),
            pid: 2,
            created: 3,
            sequence,
        }
    }

    fn report() -> ProbeReport {
        let content = PromptContentObservation::from_parts(
            vec![1],
            "synthetic".into(),
            vec![PromptLabel::new(0, 1, LabelKind::Text, true, "label".into()).unwrap()],
        )
        .unwrap();
        ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 1,
                enabled_elements: 1,
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            content,
        )
        .unwrap()
    }

    fn running_machine(now: Instant) -> WatchMachine {
        let mut machine = WatchMachine::new(now);
        machine.launched(now).unwrap();
        machine.drain();
        machine
    }

    fn drain_events(machine: &mut WatchMachine) -> Vec<WatchEvent> {
        machine
            .drain()
            .into_iter()
            .filter_map(|observation| match observation {
                WatchObservation::Event(event) => Some(event),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn fresh_heartbeat_only_renews_an_unconsumed_tracked_target() {
        let now = Instant::now();
        let mut machine = running_machine(now);
        machine
            .ingest(HelperMessage::Heartbeat { sequence: 0 }, 4, now)
            .unwrap();
        assert!(drain_events(&mut machine).is_empty());
        machine
            .ingest(
                HelperMessage::Appeared {
                    target: target(1),
                    report: report(),
                },
                4,
                now,
            )
            .unwrap();
        drain_events(&mut machine);
        machine
            .ingest(HelperMessage::Heartbeat { sequence: 1 }, 4, now)
            .unwrap();
        assert_eq!(
            drain_events(&mut machine),
            vec![WatchEvent::StillPresent { target: target(1) }]
        );
        machine.reserve_apply(target(1)).unwrap();
        machine
            .ingest(HelperMessage::Heartbeat { sequence: 1 }, 4, now)
            .unwrap();
        assert!(drain_events(&mut machine).is_empty());
    }

    #[test]
    fn parked_changes_enqueue_without_touching_prompt_tracking_and_refresh_liveness() {
        let began = Instant::now();
        let now = began + Duration::from_secs(14);
        let mut machine = running_machine(began);
        machine
            .ingest(HelperMessage::Parked { count: 3 }, 4, now)
            .unwrap();
        assert_eq!(
            drain_events(&mut machine),
            vec![WatchEvent::ParkedChanged { count: 3 }]
        );
        assert!(!machine.heartbeat_expired(now + Duration::from_secs(14)));
        assert_eq!(
            machine.ingest(
                HelperMessage::Parked {
                    count: MAX_PARKED_PROMPTS + 1,
                },
                4,
                now + Duration::from_secs(14),
            ),
            Err(MessageError::Protocol)
        );
        assert!(machine.heartbeat_expired(now + Duration::from_secs(15)));
        assert_eq!(machine.last_sequence, 0);
        assert!(machine.tracked.is_none());
    }

    #[test]
    fn appeared_rejects_an_empty_native_identity() {
        let now = Instant::now();
        let mut machine = running_machine(now);
        assert_eq!(
            machine.ingest(
                HelperMessage::Appeared {
                    target: TargetIdentity {
                        hwnd: 0,
                        ..target(1)
                    },
                    report: report(),
                },
                4,
                now,
            ),
            Err(MessageError::Protocol)
        );
        assert!(drain_events(&mut machine).is_empty());
    }

    #[test]
    fn sequence_must_advance_and_heartbeat_must_match() {
        let now = Instant::now();
        let current = target(1);
        let mut machine = running_machine(now);
        machine
            .ingest(
                HelperMessage::Appeared {
                    target: current,
                    report: report(),
                },
                4,
                now,
            )
            .unwrap();
        assert_eq!(
            machine.ingest(HelperMessage::Heartbeat { sequence: 0 }, 4, now),
            Err(MessageError::Protocol)
        );
        assert_eq!(
            machine.ingest(HelperMessage::Heartbeat { sequence: 1 }, 4, now),
            Ok(())
        );
        machine
            .ingest(
                HelperMessage::Gone {
                    target: current,
                    reason: GoneReason::Closed,
                },
                4,
                now,
            )
            .unwrap();
        assert_eq!(
            machine.ingest(
                HelperMessage::Appeared {
                    target: current,
                    report: report(),
                },
                4,
                now,
            ),
            Err(MessageError::Protocol)
        );
    }

    #[test]
    fn malformed_message_does_not_refresh_heartbeat_or_reset_failures() {
        let began = Instant::now();
        let mut machine = running_machine(began);
        machine.failures = 3;
        machine.running = true;
        assert_eq!(
            machine.ingest(
                HelperMessage::Gone {
                    target: target(1),
                    reason: GoneReason::Closed,
                },
                4,
                began + Duration::from_secs(14),
            ),
            Err(MessageError::Protocol)
        );
        assert_eq!(machine.failures, 3);
        assert!(machine.heartbeat_expired(began + Duration::from_secs(15)));
    }

    #[test]
    fn queue_returns_oldest_sixteen_observations_per_poll() {
        let now = Instant::now();
        let mut machine = running_machine(now);
        for attempt in 1..=20 {
            machine
                .enqueue(WatchObservation::Event(WatchEvent::HelperRestarted {
                    attempt,
                }))
                .unwrap();
        }
        let first = machine.drain();
        assert_eq!(first.len(), 16);
        assert!(matches!(
            first.first(),
            Some(WatchObservation::Event(WatchEvent::HelperRestarted {
                attempt: 1
            }))
        ));
        assert!(matches!(
            first.last(),
            Some(WatchObservation::Event(WatchEvent::HelperRestarted {
                attempt: 16
            }))
        ));
        let second = machine.drain();
        assert_eq!(second.len(), 4);
        assert!(matches!(
            second.first(),
            Some(WatchObservation::Event(WatchEvent::HelperRestarted {
                attempt: 17
            }))
        ));
    }

    #[test]
    fn queue_overflow_replaces_stale_observations_with_unavailable() {
        let now = Instant::now();
        let mut machine = running_machine(now);
        for attempt in 1..=64 {
            machine
                .enqueue(WatchObservation::Event(WatchEvent::HelperRestarted {
                    attempt,
                }))
                .unwrap();
        }
        assert_eq!(
            machine.enqueue(WatchObservation::Event(WatchEvent::HelperRestarted {
                attempt: 65,
            })),
            Err(MessageError::Overflow)
        );
        assert_eq!(
            machine.drain(),
            vec![
                WatchObservation::Health(WatcherHealth::Unavailable(WatcherRefusal::HelperFailed,)),
                WatchObservation::Lifecycle(WatchLifecycle::Unavailable),
                WatchObservation::Event(WatchEvent::HelperUnavailable),
            ]
        );
    }

    #[test]
    fn apply_is_reserved_once_for_only_the_current_target() {
        let now = Instant::now();
        let current = target(1);
        let mut machine = running_machine(now);
        machine
            .ingest(
                HelperMessage::Appeared {
                    target: current,
                    report: report(),
                },
                4,
                now,
            )
            .unwrap();
        assert_eq!(
            machine.reserve_apply(target(2)),
            Err(ProbeSupervisorError::ApplyRefused)
        );
        assert_eq!(machine.reserve_apply(current), Ok(()));
        assert_eq!(
            machine.reserve_apply(current),
            Err(ProbeSupervisorError::ApplyRefused)
        );
        assert_eq!(
            machine.ingest(
                HelperMessage::Applied {
                    target: current,
                    outcome: ApplyOutcome::StillPresent,
                },
                4,
                now,
            ),
            Ok(())
        );
    }

    #[test]
    fn applied_gone_forgets_target_and_allows_the_next_prompt() {
        let now = Instant::now();
        let first = target(1);
        let next = target(2);
        let mut machine = running_machine(now);
        machine
            .ingest(
                HelperMessage::Appeared {
                    target: first,
                    report: report(),
                },
                4,
                now,
            )
            .unwrap();
        machine.reserve_apply(first).unwrap();
        machine
            .ingest(
                HelperMessage::Applied {
                    target: first,
                    outcome: ApplyOutcome::Gone,
                },
                4,
                now,
            )
            .unwrap();
        assert_eq!(
            machine.ingest(
                HelperMessage::Appeared {
                    target: next,
                    report: report(),
                },
                4,
                now,
            ),
            Ok(())
        );
        assert_eq!(machine.reserve_apply(next), Ok(()));
    }

    #[test]
    fn non_gone_apply_reply_keeps_target_consumed_until_gone() {
        for outcome in [
            ApplyOutcome::StillPresent,
            ApplyOutcome::Refused(RefusalReason::ContentChanged),
        ] {
            let now = Instant::now();
            let current = target(1);
            let mut machine = running_machine(now);
            machine
                .ingest(
                    HelperMessage::Appeared {
                        target: current,
                        report: report(),
                    },
                    4,
                    now,
                )
                .unwrap();
            machine.reserve_apply(current).unwrap();
            machine
                .ingest(
                    HelperMessage::Applied {
                        target: current,
                        outcome,
                    },
                    4,
                    now,
                )
                .unwrap();
            assert_eq!(
                machine.reserve_apply(current),
                Err(ProbeSupervisorError::ApplyRefused)
            );
            assert_eq!(
                machine.ingest(
                    HelperMessage::Gone {
                        target: current,
                        reason: GoneReason::Closed,
                    },
                    4,
                    now,
                ),
                Ok(())
            );
        }
    }
}
