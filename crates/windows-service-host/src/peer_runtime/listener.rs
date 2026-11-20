// SPDX-License-Identifier: GPL-2.0-or-later
//! Diagnostic-only listener state. No owner is stopped or granted authority.

use super::ServiceSession;
use crate::management_protocol::ListenerFault;
use std::{
    io,
    time::{Duration, Instant},
};
use windows_port_owner::ListenerOwner;

const OWNER_LOOKUP_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_ABUSE_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const PEER_WORKER_EXIT_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the embedded relay's counters are due for a diagnostics row: they
/// moved since the last row, and that row is at least a minute old.
pub(super) fn relay_abuse_due(
    current: relay_service::RelayAbuseCounters,
    reported: Option<(Instant, relay_service::RelayAbuseCounters)>,
    now: Instant,
) -> bool {
    match reported {
        None => current != relay_service::RelayAbuseCounters::default(),
        Some((at, last)) => {
            current != last && now.saturating_duration_since(at) >= RELAY_ABUSE_REPORT_INTERVAL
        }
    }
}

fn observe_peer_worker_exits_with(
    exits: [(super::PeerExitCause, u64); 8],
    pending: &mut [u64; 8],
    reported: &mut [Option<Instant>; 8],
    now: Instant,
    flush: bool,
    mut record: impl FnMut(crate::public_diagnostics::Event),
) {
    for (cause, count) in exits {
        let pending = &mut pending[cause as usize];
        *pending = pending.saturating_add(count);
    }
    for cause in [
        super::PeerExitCause::LocallyClosed,
        super::PeerExitCause::PeerClosed,
        super::PeerExitCause::TlsFailure,
        super::PeerExitCause::Timeout,
        super::PeerExitCause::ProtocolViolation,
        super::PeerExitCause::ClockFailure,
        super::PeerExitCause::IoFailure,
        super::PeerExitCause::Panic,
    ] {
        let index = cause as usize;
        if pending[index] == 0
            || (!flush
                && reported[index].is_some_and(|at| {
                    now.saturating_duration_since(at) < PEER_WORKER_EXIT_REPORT_INTERVAL
                }))
        {
            continue;
        }
        let count = std::mem::take(&mut pending[index]);
        reported[index] = Some(now);
        record(crate::public_diagnostics::Event::PeerWorkerExited { cause, count });
    }
}

pub(super) fn fault_for_failure(
    error: &io::Error,
    now: Instant,
    cache: &mut Option<(Instant, Option<ListenerOwner>)>,
    lookup: impl FnOnce() -> Option<ListenerOwner>,
) -> Option<ListenerFault> {
    let in_use = error.kind() == io::ErrorKind::AddrInUse || error.raw_os_error() == Some(10048);
    let reserved = error.raw_os_error() == Some(10013);
    if !in_use && !reserved {
        return None;
    }
    if cache
        .as_ref()
        .is_none_or(|(at, _)| now.saturating_duration_since(*at) >= OWNER_LOOKUP_INTERVAL)
    {
        *cache = Some((now, lookup()));
    }
    match cache.as_ref().and_then(|(_, owner)| owner.as_ref()) {
        Some(owner) => Some(ListenerFault::InUse {
            pid: owner.pid,
            program: owner.image_name.clone(),
        }),
        None if in_use => Some(ListenerFault::InUse {
            pid: 0,
            program: None,
        }),
        None => Some(ListenerFault::Reserved),
    }
}

impl ServiceSession<'_> {
    pub(super) fn observe_peer_worker_exits(&mut self, now: Instant, flush: bool) {
        let exits = self.take_peer_worker_exits();
        #[cfg(test)]
        let recorded = self.peer_worker_exit_fixture.clone();
        observe_peer_worker_exits_with(
            exits,
            &mut self.peer_worker_exit_pending,
            &mut self.peer_worker_exit_reported_at,
            now,
            flush,
            |event| {
                #[cfg(test)]
                if let Some(recorded) = &recorded {
                    recorded.borrow_mut().push(event);
                    return;
                }
                crate::public_diagnostics::record(event);
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_worker_exit_rows_accumulate_until_due_and_flush_at_shutdown() {
        use crate::peer_runtime::PeerExitCause;

        fn exits(values: &[(PeerExitCause, u64)]) -> [(PeerExitCause, u64); 8] {
            let mut counts = [0_u64; 8];
            for (cause, count) in values {
                counts[*cause as usize] = *count;
            }
            [
                PeerExitCause::LocallyClosed,
                PeerExitCause::PeerClosed,
                PeerExitCause::TlsFailure,
                PeerExitCause::Timeout,
                PeerExitCause::ProtocolViolation,
                PeerExitCause::ClockFailure,
                PeerExitCause::IoFailure,
                PeerExitCause::Panic,
            ]
            .map(|cause| (cause, counts[cause as usize]))
        }

        let start = Instant::now();
        let mut pending = [0_u64; 8];
        let mut reported = [None; 8];
        let mut rows = Vec::new();
        observe_peer_worker_exits_with(
            exits(&[(PeerExitCause::Timeout, 2)]),
            &mut pending,
            &mut reported,
            start,
            false,
            |event| rows.push(event),
        );
        observe_peer_worker_exits_with(
            exits(&[(PeerExitCause::Timeout, 3), (PeerExitCause::PeerClosed, 1)]),
            &mut pending,
            &mut reported,
            start + Duration::from_secs(10),
            false,
            |event| rows.push(event),
        );
        observe_peer_worker_exits_with(
            exits(&[]),
            &mut pending,
            &mut reported,
            start + Duration::from_secs(59),
            false,
            |event| rows.push(event),
        );
        observe_peer_worker_exits_with(
            exits(&[(PeerExitCause::Timeout, 4)]),
            &mut pending,
            &mut reported,
            start + Duration::from_secs(60),
            false,
            |event| rows.push(event),
        );
        observe_peer_worker_exits_with(
            exits(&[(PeerExitCause::Timeout, 5)]),
            &mut pending,
            &mut reported,
            start + Duration::from_secs(61),
            true,
            |event| rows.push(event),
        );

        let values: Vec<_> = rows
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect();
        assert_eq!(
            values,
            [
                ("timeout", 2),
                ("peer_closed", 1),
                ("timeout", 7),
                ("timeout", 5),
            ]
            .map(|(cause, count)| {
                serde_json::json!({
                    "kind": "peer_worker_exited",
                    "cause": cause,
                    "count": count,
                })
            })
        );
        assert!(pending.iter().all(|count| *count == 0));
    }

    #[test]
    fn relay_abuse_is_reported_on_change_and_at_most_once_a_minute() {
        let now = Instant::now();
        let none = relay_service::RelayAbuseCounters::default();
        let one = relay_service::RelayAbuseCounters {
            evicted_pairs: 1,
            ..none
        };
        let two = relay_service::RelayAbuseCounters {
            evicted_pairs: 2,
            ..none
        };
        assert!(!relay_abuse_due(none, None, now));
        assert!(relay_abuse_due(one, None, now));
        assert!(!relay_abuse_due(
            one,
            Some((now, one)),
            now + Duration::from_secs(600)
        ));
        assert!(!relay_abuse_due(
            two,
            Some((now, one)),
            now + Duration::from_secs(59)
        ));
        assert!(relay_abuse_due(
            two,
            Some((now, one)),
            now + Duration::from_secs(60)
        ));
    }

    #[test]
    fn owner_lookup_is_shared_across_retries_and_error_codes_for_five_seconds() {
        let now = Instant::now();
        let mut cache = None;
        let owner = ListenerOwner {
            pid: 123,
            image_name: Some("veraport.exe".into()),
        };
        let expected = Some(ListenerFault::InUse {
            pid: 123,
            program: owner.image_name.clone(),
        });
        assert_eq!(
            fault_for_failure(
                &io::Error::from_raw_os_error(10048),
                now,
                &mut cache,
                || Some(owner)
            ),
            expected
        );
        for seconds in 1..5 {
            assert_eq!(
                fault_for_failure(
                    &io::Error::from_raw_os_error(10013),
                    now + Duration::from_secs(seconds),
                    &mut cache,
                    || panic!("cached lookup must not repeat")
                ),
                expected
            );
        }
        assert_eq!(
            fault_for_failure(
                &io::Error::from_raw_os_error(10013),
                now + Duration::from_secs(5),
                &mut cache,
                || None
            ),
            Some(ListenerFault::Reserved)
        );
    }

    #[test]
    fn unknown_owner_reserved_and_unrelated_errors_stay_distinct() {
        let now = Instant::now();
        let mut cache = None;
        assert_eq!(
            fault_for_failure(&io::ErrorKind::AddrInUse.into(), now, &mut cache, || None),
            Some(ListenerFault::InUse {
                pid: 0,
                program: None
            })
        );
        assert_eq!(
            fault_for_failure(
                &io::Error::from_raw_os_error(10013),
                now,
                &mut cache,
                || panic!("cached absence")
            ),
            Some(ListenerFault::Reserved)
        );
        assert_eq!(
            fault_for_failure(&io::ErrorKind::Other.into(), now, &mut cache, || panic!(
                "unrelated error"
            )),
            None
        );
    }
}
