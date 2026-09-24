// SPDX-License-Identifier: GPL-2.0-or-later
//! Holding a newly seen prompt until it stops changing.
//!
//! The consent dialog is still being assembled when it first appears: on a real
//! PC (2026-09-24) one uncaptured node joined the top of its tree after the
//! first capture, every label ordinal moved by one, and the phone's approval of
//! that first capture was refused as `ContentChanged` because the dialog it
//! described no longer existed. Apply stays that strict. What changes is when
//! the phone is asked: only once the same content has been read for
//! [`STABLE_FOR`]. A dialog that never settles is still published after
//! [`MAX_HOLD`], so a request is late by at most that long, never withheld.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

/// How long the same content must keep being read before the phone is asked.
pub(crate) const STABLE_FOR: Duration = Duration::from_secs(1);
/// The longest a prompt waits for its content to stop changing.
pub(crate) const MAX_HOLD: Duration = Duration::from_secs(5);

pub(crate) enum Settled<R> {
    Hold,
    Publish(R),
}

struct Held<K, R> {
    key: K,
    report: R,
    first_seen: Instant,
    unchanged_since: Instant,
}

/// One held prompt at most, keyed by its native window identity. A different
/// window starts over; the same window with different content restarts only
/// the stability clock.
pub(crate) struct SettleGate<K, R> {
    held: Option<Held<K, R>>,
}

impl<K: PartialEq, R> SettleGate<K, R> {
    pub(crate) const fn new() -> Self {
        Self { held: None }
    }

    pub(crate) fn observe(
        &mut self,
        now: Instant,
        key: K,
        report: R,
        same: impl FnOnce(&R, &R) -> bool,
    ) -> Settled<R> {
        let Some(held) = self.held.as_mut().filter(|held| held.key == key) else {
            self.held = Some(Held {
                key,
                report,
                first_seen: now,
                unchanged_since: now,
            });
            return Settled::Hold;
        };
        // Keep the newest read either way: it is what apply will compare with.
        if !same(&held.report, &report) {
            held.unchanged_since = now;
        }
        held.report = report;
        let stable = now.saturating_duration_since(held.unchanged_since) >= STABLE_FOR;
        let overdue = now.saturating_duration_since(held.first_seen) >= MAX_HOLD;
        if stable || overdue {
            return self
                .held
                .take()
                .map_or(Settled::Hold, |held| Settled::Publish(held.report));
        }
        Settled::Hold
    }

    /// The window closed, became ambiguous or could not be verified: whatever
    /// was held describes nothing on screen any more.
    pub(crate) fn clear(&mut self) {
        self.held = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(left: &&str, right: &&str) -> bool {
        left == right
    }

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn a_new_prompt_is_held_until_its_content_is_read_unchanged_for_the_stable_window() {
        let start = Instant::now();
        let mut gate = SettleGate::new();
        assert!(matches!(gate.observe(start, 1, "a", same), Settled::Hold));
        assert!(matches!(
            gate.observe(at(start, 200), 1, "a", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 999), 1, "a", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 1_000), 1, "a", same),
            Settled::Publish("a")
        ));
        // Publishing empties the gate: the next read starts a new hold.
        assert!(matches!(
            gate.observe(at(start, 1_200), 1, "a", same),
            Settled::Hold
        ));
    }

    #[test]
    fn a_late_change_restarts_the_clock_and_publishes_the_settled_content() {
        // The measured case: the dialog gained a node after its first capture.
        let start = Instant::now();
        let mut gate = SettleGate::new();
        assert!(matches!(
            gate.observe(start, 1, "early", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 600), 1, "settled", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 1_200), 1, "settled", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 1_600), 1, "settled", same),
            Settled::Publish("settled")
        ));
    }

    #[test]
    fn a_prompt_that_never_settles_is_published_after_the_maximum_hold() {
        let start = Instant::now();
        let mut gate = SettleGate::new();
        let mut published = None;
        let texts = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"];
        for (millis, text) in (0..).step_by(500).zip(texts) {
            if let Settled::Publish(report) = gate.observe(at(start, millis), 1, text, same) {
                published = Some((millis, report));
                break;
            }
        }
        assert_eq!(published, Some((5_000, "k")));
    }

    #[test]
    fn a_different_window_starts_over_and_clear_forgets_the_held_prompt() {
        let start = Instant::now();
        let mut gate = SettleGate::new();
        assert!(matches!(gate.observe(start, 1, "a", same), Settled::Hold));
        assert!(matches!(
            gate.observe(at(start, 900), 2, "a", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 1_500), 2, "a", same),
            Settled::Hold
        ));
        assert!(matches!(
            gate.observe(at(start, 1_900), 2, "a", same),
            Settled::Publish("a")
        ));
        assert!(matches!(
            gate.observe(at(start, 2_000), 2, "a", same),
            Settled::Hold
        ));
        gate.clear();
        assert!(matches!(
            gate.observe(at(start, 3_500), 2, "a", same),
            Settled::Hold
        ));
    }
}
