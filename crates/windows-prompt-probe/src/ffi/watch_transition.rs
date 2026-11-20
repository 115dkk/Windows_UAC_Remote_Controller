// SPDX-License-Identifier: GPL-2.0-or-later
//! Watch publication decisions over value observations; no native operations.
#![forbid(unsafe_code)]

use crate::{
    ProbeFailure, ProbeReport,
    settle::{SettleGate, Settled},
    supervision::{ApplyOutcome, GoneReason, HelperMessage, RefusalReason, TargetIdentity},
};
use std::time::{Duration, Instant};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const PARKED_CENSUS_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CycleFault {
    InputDesktopUnavailable,
    InputDesktopNameUnavailable,
    InputDesktopVerification(ProbeFailure),
    CandidateQuery,
    PostCaptureRecheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CycleAction {
    DesktopChanged,
    SkipWindow,
    VerificationFailed,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OutcomeObservation {
    Gone,
    StillPresent,
    Unobservable,
}

pub(super) fn fold_outcome_observations(
    observations: impl IntoIterator<Item = OutcomeObservation>,
) -> ApplyOutcome {
    if observations
        .into_iter()
        .any(|observation| observation == OutcomeObservation::Gone)
    {
        ApplyOutcome::Gone
    } else {
        ApplyOutcome::StillPresent
    }
}

pub(super) const fn cycle_action(fault: CycleFault) -> CycleAction {
    match fault {
        CycleFault::InputDesktopUnavailable | CycleFault::InputDesktopNameUnavailable => {
            CycleAction::DesktopChanged
        }
        CycleFault::InputDesktopVerification(ProbeFailure::SecureInputDesktopProfileRequired) => {
            CycleAction::DesktopChanged
        }
        CycleFault::InputDesktopVerification(_) => CycleAction::Fatal,
        CycleFault::CandidateQuery => CycleAction::SkipWindow,
        CycleFault::PostCaptureRecheck => CycleAction::VerificationFailed,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct WindowIdentity {
    pub hwnd: u64,
    pub pid: u32,
    pub created: u64,
}

impl WindowIdentity {
    fn target(self, sequence: u32) -> TargetIdentity {
        TargetIdentity {
            hwnd: self.hwnd,
            pid: self.pid,
            created: self.created,
            sequence,
        }
    }
}

pub(super) struct Tracked {
    pub identity: TargetIdentity,
    pub report: ProbeReport,
}

impl Tracked {
    fn window(&self) -> WindowIdentity {
        WindowIdentity {
            hwnd: self.identity.hwnd,
            pid: self.identity.pid,
            created: self.identity.created,
        }
    }
}

pub(super) enum Census {
    None,
    DesktopChanged,
    VerificationFailed,
    One {
        window: WindowIdentity,
        report: Option<ProbeReport>,
    },
    Ambiguous,
}

pub(super) enum Observation {
    // A fault before the secure census does not consume the apply recheck request.
    DesktopChanged,
    DesktopFault(CycleFault),
    Census(Census),
    Parked {
        attempted_at: Instant,
        count: Option<u8>,
    },
    Applied {
        target: TargetIdentity,
        outcome: ApplyOutcome,
    },
    FinishCycle {
        heartbeat_due: bool,
    },
}

#[derive(Clone, Copy)]
pub(super) struct CyclePlan {
    pub heartbeat_due: bool,
    verify_content: bool,
    tracked_window: Option<WindowIdentity>,
}

impl CyclePlan {
    pub fn capture(self, window: WindowIdentity) -> bool {
        self.tracked_window != Some(window) || self.verify_content
    }
}

pub(super) struct WatchState {
    tracked: Option<Tracked>,
    settling: SettleGate<WindowIdentity, ProbeReport>,
    recheck_content: bool,
    sequence: u32,
    last_output: Instant,
    last_parked: u8,
    last_parked_census: Option<Instant>,
    content_verified: bool,
    settle_after_write: Option<(WindowIdentity, ProbeReport)>,
}

/// The adapter installs `next` only after every message has been written. A failed
/// write ends the helper and drops this pending state, including any new target.
pub(super) struct Transition {
    pub next: WatchState,
    pub messages: Vec<HelperMessage>,
}

impl WatchState {
    pub fn new(now: Instant) -> Self {
        Self {
            tracked: None,
            settling: SettleGate::new(),
            recheck_content: false,
            sequence: 0,
            last_output: now,
            last_parked: 0,
            last_parked_census: None,
            content_verified: false,
            settle_after_write: None,
        }
    }

    pub fn tracked(&self) -> Option<&Tracked> {
        self.tracked.as_ref()
    }

    pub fn cycle_plan(&self, now: Instant) -> CyclePlan {
        let heartbeat_due = now.saturating_duration_since(self.last_output) >= HEARTBEAT_INTERVAL;
        CyclePlan {
            heartbeat_due,
            verify_content: heartbeat_due || self.recheck_content,
            tracked_window: self.tracked.as_ref().map(Tracked::window),
        }
    }

    pub fn check_census_sequence(&self) -> Result<(), ()> {
        self.sequence.checked_add(1).map(|_| ()).ok_or(())
    }

    pub fn parked_census_due(&self, now: Instant) -> bool {
        self.last_parked_census
            .is_none_or(|at| now.saturating_duration_since(at) >= PARKED_CENSUS_INTERVAL)
    }

    pub fn output_written(&mut self, now: Instant) {
        self.last_output = now;
        if let Some((window, report)) = self.settle_after_write.take() {
            // Replacement settling starts after Gone is written, not before a
            // possibly blocking pipe write (the original watch-loop ordering).
            self.settling.observe(now, window, report, same_report);
        }
    }

    pub fn transition(mut self, now: Instant, observation: Observation) -> Result<Transition, ()> {
        let mut messages = Vec::new();
        match observation {
            Observation::DesktopChanged => self.withdraw(GoneReason::DesktopChanged, &mut messages),
            Observation::DesktopFault(fault) => {
                if cycle_action(fault) != CycleAction::DesktopChanged {
                    return Err(());
                }
                self.withdraw(GoneReason::DesktopChanged, &mut messages);
            }
            Observation::Census(census) => {
                self.recheck_content = false;
                self.content_verified = false;
                match census {
                    Census::None => self.withdraw(GoneReason::Closed, &mut messages),
                    Census::DesktopChanged => {
                        self.withdraw(GoneReason::DesktopChanged, &mut messages)
                    }
                    Census::Ambiguous => self.withdraw(GoneReason::Ambiguous, &mut messages),
                    Census::VerificationFailed => {
                        self.withdraw(GoneReason::VerificationFailed, &mut messages)
                    }
                    Census::One { window, report } => {
                        let same_window = self
                            .tracked
                            .as_ref()
                            .is_some_and(|prior| prior.window() == window);
                        match report {
                            None => {
                                if !same_window {
                                    self.replace(&mut messages);
                                }
                            }
                            Some(report) => {
                                let same_content = same_window
                                    && self
                                        .tracked
                                        .as_ref()
                                        .is_some_and(|prior| same_report(&prior.report, &report));
                                if same_content {
                                    self.content_verified = true;
                                } else if self.tracked.is_some() {
                                    self.replace(&mut messages);
                                    self.settle_after_write = Some((window, report));
                                } else {
                                    if let Settled::Publish(report) =
                                        self.settling.observe(now, window, report, same_report)
                                    {
                                        let identity =
                                            window.target(self.sequence.checked_add(1).ok_or(())?);
                                        let message = HelperMessage::Appeared {
                                            target: identity,
                                            report: report.clone(),
                                        };
                                        if message.fits_watch_frame() {
                                            messages.push(message);
                                            self.sequence = identity.sequence;
                                            self.tracked = Some(Tracked { identity, report });
                                            self.content_verified = true;
                                        } else {
                                            self.settling.clear();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Observation::Parked {
                attempted_at,
                count,
            } => {
                self.last_parked_census = Some(attempted_at);
                if let Some(count) = count.filter(|count| *count != self.last_parked) {
                    messages.push(HelperMessage::Parked { count });
                    self.last_parked = count;
                }
            }
            Observation::Applied { target, outcome } => {
                messages.push(HelperMessage::Applied { target, outcome });
                if matches!(
                    outcome,
                    ApplyOutcome::Refused(RefusalReason::ContentChanged)
                ) {
                    self.recheck_content = true;
                }
                if outcome == ApplyOutcome::Gone
                    && self.tracked.as_ref().map(|current| current.identity) == Some(target)
                {
                    self.tracked = None;
                }
            }
            Observation::FinishCycle { heartbeat_due } => {
                // Liveness may retain the last sequence after Gone, but a live
                // target can be renewed only by this cycle's content capture.
                if heartbeat_due
                    && now.saturating_duration_since(self.last_output) >= HEARTBEAT_INTERVAL
                    && (self.tracked.is_none() || self.content_verified)
                {
                    messages.push(HelperMessage::Heartbeat {
                        sequence: self.sequence,
                    });
                }
                self.content_verified = false;
            }
        }
        Ok(Transition {
            next: self,
            messages,
        })
    }

    fn replace(&mut self, messages: &mut Vec<HelperMessage>) {
        if let Some(current) = self.tracked.take() {
            messages.push(HelperMessage::Gone {
                target: current.identity,
                reason: GoneReason::Replaced,
            });
        }
    }

    fn withdraw(&mut self, reason: GoneReason, messages: &mut Vec<HelperMessage>) {
        self.settling.clear();
        self.content_verified = false;
        if let Some(current) = self.tracked.take() {
            messages.push(HelperMessage::Gone {
                target: current.identity,
                reason,
            });
        }
    }
}

fn same_report(held: &ProbeReport, fresh: &ProbeReport) -> bool {
    fresh.content() == held.content() && fresh.counts().describes_the_same_prompt(held.counts())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LabelKind, ProbeCounts, PromptContentObservation, PromptLabel};

    fn window() -> WindowIdentity {
        WindowIdentity {
            hwnd: 1,
            pid: 2,
            created: 3,
        }
    }

    fn target(sequence: u32) -> TargetIdentity {
        TargetIdentity {
            hwnd: 1,
            pid: 2,
            created: 3,
            sequence,
        }
    }

    fn report(text: &str) -> ProbeReport {
        ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 2,
                enabled_elements: 2,
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            PromptContentObservation::from_parts(
                vec![1],
                String::new(),
                vec![PromptLabel::new(1, 1, LabelKind::Text, true, text.into()).unwrap()],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn observed(text: &str) -> Observation {
        Observation::Census(Census::One {
            window: window(),
            report: Some(report(text)),
        })
    }

    fn step(
        state: WatchState,
        now: Instant,
        observation: Observation,
    ) -> (WatchState, Vec<HelperMessage>) {
        let Transition { mut next, messages } = state.transition(now, observation).unwrap();
        // These tests acknowledge each output at a supplied time, not a wall clock.
        for _ in &messages {
            next.output_written(now);
        }
        (next, messages)
    }

    fn published(start: Instant) -> WatchState {
        let (state, messages) = step(WatchState::new(start), start, observed("original"));
        assert!(messages.is_empty());
        let (state, messages) = step(state, start + Duration::from_secs(1), observed("original"));
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: target(1),
                report: report("original")
            }]
        );
        state
    }

    #[test]
    fn desktop_faults_withdraw_and_unexpected_verification_failures_remain_fatal() {
        let start = Instant::now();
        for fault in [
            CycleFault::InputDesktopUnavailable,
            CycleFault::InputDesktopNameUnavailable,
            CycleFault::InputDesktopVerification(ProbeFailure::SecureInputDesktopProfileRequired),
        ] {
            let (state, messages) = step(
                published(start),
                start + Duration::from_secs(6),
                Observation::DesktopFault(fault),
            );
            assert_eq!(
                messages,
                [HelperMessage::Gone {
                    target: target(1),
                    reason: GoneReason::DesktopChanged
                }]
            );
            assert!(state.tracked().is_none());
            let (_, messages) = step(
                state,
                start + Duration::from_secs(6),
                Observation::FinishCycle {
                    heartbeat_due: true,
                },
            );
            assert!(messages.is_empty());
        }
        for failure in [
            ProbeFailure::ThreadImpersonationPresent,
            ProbeFailure::MalformedNativeData(crate::NativeOperation::DesktopInput),
            ProbeFailure::NativeCall {
                operation: crate::NativeOperation::DesktopInput,
                hresult: -1,
            },
        ] {
            assert!(
                published(start)
                    .transition(
                        start + Duration::from_secs(6),
                        Observation::DesktopFault(CycleFault::InputDesktopVerification(failure))
                    )
                    .is_err()
            );
        }
        assert_eq!(
            cycle_action(CycleFault::CandidateQuery),
            CycleAction::SkipWindow
        );
        assert_eq!(
            cycle_action(CycleFault::PostCaptureRecheck),
            CycleAction::VerificationFailed
        );
    }

    #[test]
    fn replacement_settling_starts_only_after_the_withdrawal_write_completes() {
        let start = Instant::now();
        let Transition { mut next, messages } = published(start)
            .transition(start + Duration::from_secs(6), observed("changed"))
            .unwrap();
        assert_eq!(
            messages,
            [HelperMessage::Gone {
                target: target(1),
                reason: GoneReason::Replaced
            }]
        );
        next.output_written(start + Duration::from_secs(8));
        let (state, messages) = step(
            next,
            start + Duration::from_millis(8999),
            observed("changed"),
        );
        assert!(messages.is_empty());
        let (_, messages) = step(state, start + Duration::from_secs(9), observed("changed"));
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: target(2),
                report: report("changed")
            }]
        );
    }

    #[test]
    fn heartbeat_cannot_renew_without_a_content_observation_even_when_due() {
        let start = Instant::now();
        let (state, _) = step(
            published(start),
            start + Duration::from_secs(6),
            Observation::Census(Census::One {
                window: window(),
                report: None,
            }),
        );
        let (_, messages) = step(
            state,
            start + Duration::from_secs(6),
            Observation::FinishCycle {
                heartbeat_due: true,
            },
        );
        assert!(messages.is_empty());
    }

    #[test]
    fn same_prompt_is_not_republished_and_only_a_due_content_capture_renews() {
        let start = Instant::now();
        let state = published(start);
        let plan = state.cycle_plan(start + Duration::from_secs(2));
        assert!(!plan.capture(window()));
        assert!(!plan.heartbeat_due);
        let (state, messages) = step(
            state,
            start + Duration::from_secs(2),
            Observation::Census(Census::One {
                window: window(),
                report: None,
            }),
        );
        assert!(messages.is_empty());
        let plan = state.cycle_plan(start + Duration::from_secs(6));
        assert!(plan.capture(window()));
        assert!(plan.heartbeat_due);
        let (state, messages) = step(state, start + Duration::from_secs(6), observed("original"));
        assert!(messages.is_empty());
        let (_, messages) = step(
            state,
            start + Duration::from_secs(6),
            Observation::FinishCycle {
                heartbeat_due: plan.heartbeat_due,
            },
        );
        assert_eq!(messages, [HelperMessage::Heartbeat { sequence: 1 }]);
    }

    #[test]
    fn census_window_count_is_not_prompt_content_but_prompt_counts_are() {
        let start = Instant::now();
        let original = report("original");
        let recounted = ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 2,
                ..original.counts()
            },
            original.content().clone(),
        )
        .unwrap();
        let (state, messages) = step(
            published(start),
            start + Duration::from_secs(6),
            Observation::Census(Census::One {
                window: window(),
                report: Some(recounted),
            }),
        );
        assert!(messages.is_empty());
        assert_eq!(state.tracked().unwrap().report, original);
        let changed = ProbeReport::from_observation(
            ProbeCounts {
                elements: 3,
                ..original.counts()
            },
            original.content().clone(),
        )
        .unwrap();
        let (state, messages) = step(
            state,
            start + Duration::from_secs(6),
            Observation::Census(Census::One {
                window: window(),
                report: Some(changed.clone()),
            }),
        );
        assert_eq!(
            messages,
            [HelperMessage::Gone {
                target: target(1),
                reason: GoneReason::Replaced
            }]
        );
        let (_, messages) = step(
            state,
            start + Duration::from_secs(7),
            Observation::Census(Census::One {
                window: window(),
                report: Some(changed.clone()),
            }),
        );
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: target(2),
                report: changed
            }]
        );
    }

    #[test]
    fn a_reused_window_with_a_different_process_creation_is_a_replacement() {
        let start = Instant::now();
        let window = WindowIdentity {
            created: 4,
            ..window()
        };
        let state = published(start);
        assert!(
            state
                .cycle_plan(start + Duration::from_secs(2))
                .capture(window)
        );
        let (state, messages) = step(
            state,
            start + Duration::from_secs(2),
            Observation::Census(Census::One {
                window,
                report: Some(report("original")),
            }),
        );
        assert_eq!(
            messages,
            [HelperMessage::Gone {
                target: target(1),
                reason: GoneReason::Replaced
            }]
        );
        let (_, messages) = step(
            state,
            start + Duration::from_secs(3),
            Observation::Census(Census::One {
                window,
                report: Some(report("original")),
            }),
        );
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: TargetIdentity {
                    created: 4,
                    ..target(2)
                },
                report: report("original")
            }]
        );
    }

    #[test]
    fn changed_content_withdraws_then_settles_before_a_new_sequence() {
        let start = Instant::now();
        let state = published(start);
        let (state, messages) = step(state, start + Duration::from_secs(6), observed("changed"));
        assert_eq!(
            messages,
            [HelperMessage::Gone {
                target: target(1),
                reason: GoneReason::Replaced
            }]
        );
        assert!(state.tracked().is_none());
        let (state, messages) = step(
            state,
            start + Duration::from_millis(6999),
            observed("changed"),
        );
        assert!(messages.is_empty());
        let (_, messages) = step(state, start + Duration::from_secs(7), observed("changed"));
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: target(2),
                report: report("changed")
            }]
        );
    }

    #[test]
    fn prompt_gone_and_ambiguous_census_withdraw_the_tracked_target() {
        let start = Instant::now();
        for (census, reason) in [
            (Census::None, GoneReason::Closed),
            (Census::Ambiguous, GoneReason::Ambiguous),
        ] {
            let (state, messages) = step(
                published(start),
                start + Duration::from_secs(6),
                Observation::Census(census),
            );
            assert_eq!(
                messages,
                [HelperMessage::Gone {
                    target: target(1),
                    reason
                }]
            );
            assert!(state.tracked().is_none());
            let (_, messages) = step(
                state,
                start + Duration::from_secs(6),
                Observation::FinishCycle {
                    heartbeat_due: true,
                },
            );
            assert!(messages.is_empty());
        }
    }

    #[test]
    fn desktop_change_withdraws_and_clears_a_settling_prompt() {
        let start = Instant::now();
        let (state, messages) = step(
            published(start),
            start + Duration::from_secs(6),
            Observation::Census(Census::DesktopChanged),
        );
        assert_eq!(
            messages,
            [HelperMessage::Gone {
                target: target(1),
                reason: GoneReason::DesktopChanged
            }]
        );
        let (state, _) = step(state, start + Duration::from_secs(7), observed("original"));
        let (state, messages) = step(
            state,
            start + Duration::from_secs(8),
            Observation::Census(Census::DesktopChanged),
        );
        assert!(messages.is_empty());
        let (_, messages) = step(state, start + Duration::from_secs(9), observed("original"));
        assert!(messages.is_empty());
    }

    #[test]
    fn unobservable_cycle_withdraws_before_any_later_liveness_heartbeat() {
        let start = Instant::now();
        for census in [Census::DesktopChanged, Census::VerificationFailed] {
            let (state, messages) = step(
                published(start),
                start + Duration::from_secs(6),
                Observation::Census(census),
            );
            assert!(matches!(messages.as_slice(), [HelperMessage::Gone { .. }]));
            assert!(state.tracked().is_none());
            let (state, messages) = step(
                state,
                start + Duration::from_secs(6),
                Observation::FinishCycle {
                    heartbeat_due: true,
                },
            );
            assert!(messages.is_empty());
            let (_, messages) = step(
                state,
                start + Duration::from_secs(11),
                Observation::FinishCycle {
                    heartbeat_due: true,
                },
            );
            // The last sequence remains on the wire, but Gone has already withdrawn it.
            assert_eq!(messages, [HelperMessage::Heartbeat { sequence: 1 }]);
        }
    }

    #[test]
    fn crossing_heartbeat_time_during_an_identity_only_census_does_not_renew() {
        let start = Instant::now();
        let state = published(start);
        let plan = state.cycle_plan(start + Duration::from_millis(5999));
        assert!(!plan.capture(window()));
        let (state, _) = step(
            state,
            start + Duration::from_secs(7),
            Observation::Census(Census::One {
                window: window(),
                report: None,
            }),
        );
        let (_, messages) = step(
            state,
            start + Duration::from_secs(7),
            Observation::FinishCycle {
                heartbeat_due: plan.heartbeat_due,
            },
        );
        assert!(messages.is_empty());
    }

    #[test]
    fn oversized_appeared_is_not_published_or_assigned_a_sequence() {
        let start = Instant::now();
        let oversized = "界".repeat(22_000);
        let (state, _) = step(WatchState::new(start), start, observed(&oversized));
        let (state, messages) = step(state, start + Duration::from_secs(1), observed(&oversized));
        assert!(messages.is_empty());
        assert!(state.tracked().is_none());
        let (state, _) = step(state, start + Duration::from_secs(2), observed("fits"));
        let (_, messages) = step(state, start + Duration::from_secs(3), observed("fits"));
        assert_eq!(
            messages,
            [HelperMessage::Appeared {
                target: target(1),
                report: report("fits")
            }]
        );
    }

    #[test]
    fn parked_count_changes_publish_once_and_failed_counts_keep_the_last_value() {
        let start = Instant::now();
        let state = WatchState::new(start);
        assert!(state.parked_census_due(start));
        let (state, messages) = step(
            state,
            start,
            Observation::Parked {
                attempted_at: start,
                count: Some(2),
            },
        );
        assert_eq!(messages, [HelperMessage::Parked { count: 2 }]);
        assert!(!state.parked_census_due(start + Duration::from_millis(999)));
        let now = start + Duration::from_secs(1);
        assert!(state.parked_census_due(now));
        let (state, messages) = step(
            state,
            now,
            Observation::Parked {
                attempted_at: now,
                count: None,
            },
        );
        assert!(messages.is_empty());
        let (state, messages) = step(
            state,
            now,
            Observation::Parked {
                attempted_at: now,
                count: Some(2),
            },
        );
        assert!(messages.is_empty());
        let (_, messages) = step(
            state,
            now,
            Observation::Parked {
                attempted_at: now,
                count: Some(0),
            },
        );
        assert_eq!(messages, [HelperMessage::Parked { count: 0 }]);
    }

    #[test]
    fn apply_content_refusal_forces_the_next_capture_and_applied_gone_forgets_target() {
        let start = Instant::now();
        let now = start + Duration::from_secs(2);
        let (state, messages) = step(
            published(start),
            now,
            Observation::Applied {
                target: target(1),
                outcome: ApplyOutcome::Refused(RefusalReason::ContentChanged),
            },
        );
        assert_eq!(
            messages,
            [HelperMessage::Applied {
                target: target(1),
                outcome: ApplyOutcome::Refused(RefusalReason::ContentChanged)
            }]
        );
        assert!(state.cycle_plan(now).capture(window()));
        let (state, _) = step(state, now, observed("original"));
        assert!(!state.cycle_plan(now).capture(window()));
        let (state, messages) = step(
            state,
            now,
            Observation::Applied {
                target: target(1),
                outcome: ApplyOutcome::Gone,
            },
        );
        assert_eq!(
            messages,
            [HelperMessage::Applied {
                target: target(1),
                outcome: ApplyOutcome::Gone
            }]
        );
        assert!(state.tracked().is_none());
    }
    #[test]
    fn any_gone_observation_establishes_gone() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::StillPresent,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Gone,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::Gone
        );
    }

    #[test]
    fn all_unobservable_observations_do_not_establish_disappearance() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::StillPresent
        );
    }

    #[test]
    fn still_present_then_unobservable_does_not_establish_disappearance() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::StillPresent,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::StillPresent
        );
    }

    #[test]
    fn unobservable_then_gone_establishes_disappearance() {
        assert_eq!(
            fold_outcome_observations(
                [OutcomeObservation::Unobservable, OutcomeObservation::Gone,]
            ),
            ApplyOutcome::Gone
        );
    }
}
