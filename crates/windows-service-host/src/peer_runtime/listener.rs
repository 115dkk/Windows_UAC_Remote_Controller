// SPDX-License-Identifier: GPL-2.0-or-later
//! Diagnostic-only listener state. No owner is stopped or granted authority.

use super::ServiceSession;
use crate::management_protocol::{ListenerFault, ManagementResponse};
use std::{
    io,
    time::{Duration, Instant},
};
use windows_port_owner::ListenerOwner;

const OWNER_LOOKUP_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_ABUSE_REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the embedded relay's counters are due for a diagnostics row: they
/// moved since the last row, and that row is at least a minute old.
fn relay_abuse_due(
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

fn fault_for_failure(
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
    pub(super) fn observe_listener_failure(&mut self, error: &io::Error, now: Instant) {
        let fault = fault_for_failure(error, now, &mut self.relay_owner_lookup, || {
            windows_port_owner::listener_owner(relay_service::EMBEDDED_RELAY_PORT)
                .ok()
                .flatten()
        });
        self.set_listener_fault(fault);
    }

    fn set_listener_fault(&mut self, fault: Option<ListenerFault>) {
        if self.relay_listener_fault != fault {
            crate::public_diagnostics::record(
                crate::public_diagnostics::Event::RelayListenerChanged {
                    fault: fault.clone(),
                },
            );
            self.relay_listener_fault = fault;
        }
    }

    /// Makes route abuse at the embedded relay visible in public diagnostics.
    /// A restarted relay counts from zero again, which also reads as a change.
    pub(super) fn observe_relay_abuse(&mut self, now: Instant) {
        let Some(current) = self
            .embedded_relay
            .as_ref()
            .map(relay_service::HostedRelay::abuse_counters)
        else {
            return;
        };
        if !relay_abuse_due(current, self.relay_abuse_reported, now) {
            return;
        }
        crate::public_diagnostics::record(crate::public_diagnostics::Event::RelayAbuse {
            evicted_pairs: current.evicted_pairs,
            rejected_duplicates: current.rejected_duplicates,
            rejected_pc_sources: current.rejected_pc_sources,
            rejected_evictions: current.rejected_evictions,
        });
        self.relay_abuse_reported = Some((now, current));
    }

    pub(super) fn clear_listener_fault(&mut self) {
        self.set_listener_fault(None);
        self.relay_owner_lookup = None;
    }

    pub(super) fn listener_status(&self) -> ManagementResponse {
        ManagementResponse::ListenerStatus {
            port: relay_service::EMBEDDED_RELAY_PORT,
            fault: if self.embedded_mode && !self.closing && self.pending_relay.is_none() {
                self.relay_listener_fault.clone()
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
