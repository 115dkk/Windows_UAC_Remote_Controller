// SPDX-License-Identifier: GPL-2.0-or-later
//! Display-only projection of the service-owned journal. Verification and
//! delivery events are not Windows outcomes and must never become approvals.
use crate::{ActivityKind, ActivityView};
use activity_journal::{
    ActivityEvent, ActivityRecord, ConnectionOutcome, Decision, RequestOutcome, ServiceOutcome,
};

pub(crate) fn project(records: Vec<ActivityRecord>) -> Vec<ActivityView> {
    records
        .into_iter()
        .enumerate()
        .filter_map(|(index, record)| {
            let kind = match record.event() {
                ActivityEvent::Connection(ConnectionOutcome::PairedDeviceConnected) => {
                    ActivityKind::Connected
                }
                ActivityEvent::Connection(ConnectionOutcome::PairedDeviceDisconnected) => {
                    ActivityKind::Disconnected
                }
                ActivityEvent::Service(ServiceOutcome::Started) => ActivityKind::ServiceStarted,
                ActivityEvent::Failure(_) => ActivityKind::Failure,
                ActivityEvent::Request(RequestOutcome::WindowsApplied {
                    decision: Decision::Approve,
                }) => ActivityKind::Approved,
                ActivityEvent::Request(RequestOutcome::WindowsApplied {
                    decision: Decision::Deny,
                }) => ActivityKind::Denied,
                ActivityEvent::Request(
                    RequestOutcome::WindowsRejected | RequestOutcome::WindowsOutcomeUnknown,
                ) => ActivityKind::Failure,
                ActivityEvent::Request(RequestOutcome::Expired) => ActivityKind::Expired,
                ActivityEvent::Request(RequestOutcome::Cancelled) => ActivityKind::Cancelled,
                _ => return None,
            };
            Some(ActivityView {
                id: format!("pc-{}-{index}", record.timestamp().get()),
                timestamp_millis: record.timestamp().get(),
                kind,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(event: ActivityEvent) -> ActivityRecord {
        serde_json::from_value(serde_json::json!({"timestamp_unix_ms": 1000, "event": event}))
            .unwrap()
    }

    #[test]
    fn only_observed_windows_application_is_an_approval() {
        let events = vec![
            record(ActivityEvent::Request(
                RequestOutcome::PhoneDecisionVerified {
                    decision: Decision::Approve,
                },
            )),
            record(ActivityEvent::Request(
                RequestOutcome::DecisionSentToWindows {
                    decision: Decision::Approve,
                },
            )),
            record(ActivityEvent::Request(
                RequestOutcome::WindowsOutcomeUnknown,
            )),
            record(ActivityEvent::Request(RequestOutcome::WindowsApplied {
                decision: Decision::Approve,
            })),
            record(ActivityEvent::Request(RequestOutcome::WindowsApplied {
                decision: Decision::Deny,
            })),
        ];
        let rows = project(events);
        assert_eq!(
            rows.iter().map(|row| row.kind).collect::<Vec<_>>(),
            vec![
                ActivityKind::Failure,
                ActivityKind::Approved,
                ActivityKind::Denied
            ]
        );
        assert!(rows.windows(2).all(|pair| pair[0].id != pair[1].id));
    }
}
