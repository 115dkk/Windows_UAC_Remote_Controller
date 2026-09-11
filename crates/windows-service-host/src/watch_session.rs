// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure bounded state for the supervised prompt watcher.
#![forbid(unsafe_code)]

use crate::{ProbeSupervisorError, WatchEvent};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use windows_prompt_probe::supervision::{ApplyOutcome, HelperMessage, TargetIdentity};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_EVENTS: usize = 64;
const MAX_POLL_EVENTS: usize = 16;
const MAX_CONSECUTIVE_FAILURES: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureDisposition {
    Retry { at: Instant },
    Unavailable,
}

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
    events: VecDeque<WatchEvent>,
    tracked: Option<TrackedTarget>,
    last_sequence: u32,
    last_message: Instant,
    failures: u32,
    retry_at: Option<Instant>,
    running: bool,
    unavailable: bool,
    shutting_down: bool,
}

impl WatchMachine {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            events: VecDeque::new(),
            tracked: None,
            last_sequence: 0,
            last_message: now,
            failures: 0,
            retry_at: None,
            running: true,
            unavailable: false,
            shutting_down: false,
        }
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
                self.enqueue(WatchEvent::Appeared {
                    target,
                    report,
                    session,
                })
            }
            HelperMessage::Gone { target, reason } => {
                if self.tracked.map(|tracked| tracked.identity) != Some(target) {
                    return Err(MessageError::Protocol);
                }
                self.tracked = None;
                self.enqueue(WatchEvent::Gone { target, reason })
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
                self.enqueue(WatchEvent::Applied { target, outcome })
            }
            HelperMessage::Heartbeat { sequence } => {
                let expected = self
                    .tracked
                    .map_or(self.last_sequence, |tracked| tracked.identity.sequence);
                if sequence != expected {
                    return Err(MessageError::Protocol);
                }
                Ok(())
            }
        }?;
        self.last_message = now;
        self.failures = 0;
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

    pub(crate) fn failed(&mut self, now: Instant) -> FailureDisposition {
        self.running = false;
        self.tracked = None;
        self.last_sequence = 0;
        self.retry_at = None;
        if self.unavailable || self.shutting_down {
            return FailureDisposition::Unavailable;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures > MAX_CONSECUTIVE_FAILURES {
            self.make_unavailable();
            return FailureDisposition::Unavailable;
        }
        let shift = self.failures.saturating_sub(1).min(4);
        let seconds = 5_u64.checked_shl(shift).unwrap_or(60).min(60);
        let at = now.checked_add(Duration::from_secs(seconds)).unwrap_or(now);
        self.retry_at = Some(at);
        FailureDisposition::Retry { at }
    }

    pub(crate) fn retry_due(&self, now: Instant) -> bool {
        !self.unavailable
            && !self.shutting_down
            && self.retry_at.is_some_and(|deadline| now >= deadline)
    }

    pub(crate) fn relaunched(&mut self, now: Instant) -> Result<(), MessageError> {
        if self.unavailable || self.shutting_down || self.running || self.retry_at.is_none() {
            return Err(MessageError::Protocol);
        }
        let attempt = self.failures;
        self.running = true;
        self.retry_at = None;
        self.last_message = now;
        self.enqueue(WatchEvent::HelperRestarted { attempt })
    }

    pub(crate) fn drain(&mut self) -> Vec<WatchEvent> {
        let count = self.events.len().min(MAX_POLL_EVENTS);
        self.events.drain(..count).collect()
    }

    pub(crate) fn make_unavailable(&mut self) {
        self.running = false;
        self.unavailable = true;
        self.tracked = None;
        self.last_sequence = 0;
        self.retry_at = None;
        self.events.clear();
        self.events.push_back(WatchEvent::HelperUnavailable);
    }

    pub(crate) fn begin_shutdown(&mut self) {
        self.shutting_down = true;
        self.running = false;
        self.tracked = None;
        self.last_sequence = 0;
        self.retry_at = None;
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

    fn enqueue(&mut self, event: WatchEvent) -> Result<(), MessageError> {
        if self.events.len() >= MAX_EVENTS {
            self.make_unavailable();
            return Err(MessageError::Overflow);
        }
        self.events.push_back(event);
        Ok(())
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

    #[test]
    fn appeared_rejects_an_empty_native_identity() {
        let now = Instant::now();
        let mut machine = WatchMachine::new(now);
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
        assert!(machine.drain().is_empty());
    }

    #[test]
    fn sequence_must_advance_and_heartbeat_must_match() {
        let now = Instant::now();
        let current = target(1);
        let mut machine = WatchMachine::new(now);
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
        let mut machine = WatchMachine::new(began);
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
    fn heartbeat_expires_at_the_exact_fifteen_second_boundary() {
        let began = Instant::now();
        let machine = WatchMachine::new(began);
        assert!(machine.is_running());
        assert!(!machine.heartbeat_expired(began + Duration::from_millis(14_999)));
        assert!(machine.heartbeat_expired(began + Duration::from_secs(15)));
    }

    #[test]
    fn backoff_doubles_then_stays_at_sixty_seconds() {
        let began = Instant::now();
        let mut machine = WatchMachine::new(began);
        for (index, seconds) in [5, 10, 20, 40, 60, 60, 60, 60].into_iter().enumerate() {
            let failed = began + Duration::from_secs(index as u64 * 100);
            assert_eq!(
                machine.failed(failed),
                FailureDisposition::Retry {
                    at: failed + Duration::from_secs(seconds),
                }
            );
            machine.running = true;
        }
        assert_eq!(
            machine.failed(began + Duration::from_secs(900)),
            FailureDisposition::Unavailable
        );
        assert!(matches!(
            machine.drain().as_slice(),
            [WatchEvent::HelperUnavailable]
        ));
    }

    #[test]
    fn valid_message_resets_the_consecutive_failure_count() {
        let now = Instant::now();
        let mut machine = WatchMachine::new(now);
        machine.failures = 3;
        machine
            .ingest(HelperMessage::Heartbeat { sequence: 0 }, 4, now)
            .unwrap();
        assert_eq!(machine.failures, 0);
        assert_eq!(
            machine.failed(now),
            FailureDisposition::Retry {
                at: now + Duration::from_secs(5),
            }
        );
    }

    #[test]
    fn queue_returns_oldest_sixteen_events_per_poll() {
        let now = Instant::now();
        let mut machine = WatchMachine::new(now);
        for attempt in 1..=20 {
            machine
                .enqueue(WatchEvent::HelperRestarted { attempt })
                .unwrap();
        }
        let first = machine.drain();
        assert_eq!(first.len(), 16);
        assert!(matches!(
            first.first(),
            Some(WatchEvent::HelperRestarted { attempt: 1 })
        ));
        assert!(matches!(
            first.last(),
            Some(WatchEvent::HelperRestarted { attempt: 16 })
        ));
        let second = machine.drain();
        assert_eq!(second.len(), 4);
        assert!(matches!(
            second.first(),
            Some(WatchEvent::HelperRestarted { attempt: 17 })
        ));
    }

    #[test]
    fn queue_overflow_replaces_stale_events_with_unavailable() {
        let now = Instant::now();
        let mut machine = WatchMachine::new(now);
        for attempt in 1..=64 {
            machine
                .enqueue(WatchEvent::HelperRestarted { attempt })
                .unwrap();
        }
        assert_eq!(
            machine.enqueue(WatchEvent::HelperRestarted { attempt: 65 }),
            Err(MessageError::Overflow)
        );
        assert!(matches!(
            machine.drain().as_slice(),
            [WatchEvent::HelperUnavailable]
        ));
    }

    #[test]
    fn apply_is_reserved_once_for_only_the_current_target() {
        let now = Instant::now();
        let current = target(1);
        let mut machine = WatchMachine::new(now);
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
        let mut machine = WatchMachine::new(now);
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
            let mut machine = WatchMachine::new(now);
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

    #[test]
    fn restart_forgets_target_and_reports_attempt_after_relaunch() {
        let now = Instant::now();
        let current = target(1);
        let mut machine = WatchMachine::new(now);
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
        let retry = now + Duration::from_secs(5);
        assert_eq!(machine.failed(now), FailureDisposition::Retry { at: retry });
        assert_eq!(
            machine.reserve_apply(current),
            Err(ProbeSupervisorError::ApplyRefused)
        );
        assert!(machine.retry_due(retry));
        machine.relaunched(retry).unwrap();
        assert_eq!(
            machine.ingest(HelperMessage::Heartbeat { sequence: 0 }, 4, retry),
            Ok(())
        );
        assert_eq!(
            machine.ingest(
                HelperMessage::Appeared {
                    target: current,
                    report: report(),
                },
                4,
                retry,
            ),
            Ok(())
        );
        let events = machine.drain();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            events.get(1),
            Some(WatchEvent::HelperRestarted { attempt: 1 })
        ));
        assert!(matches!(
            events.last(),
            Some(WatchEvent::Appeared { target, .. }) if *target == current
        ));
    }

    #[test]
    fn shutdown_is_idempotent_and_disables_heartbeat_and_retry() {
        let now = Instant::now();
        let mut machine = WatchMachine::new(now);
        machine.begin_shutdown();
        machine.begin_shutdown();
        assert!(machine.is_shutting_down());
        assert!(!machine.heartbeat_expired(now + Duration::from_secs(30)));
        assert!(!machine.retry_due(now + Duration::from_secs(30)));
    }
}
