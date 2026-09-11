//! Scripted boundary fixtures, not actual Android lifecycle execution.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use controller_runtime::{PhoneServiceState, Schedule};

use super::*;

fn stopped() -> PhoneServiceView {
    PhoneServiceView {
        state: PhoneServiceState::Stopped,
        boot_enabled: Some(false),
        can_start: true,
        can_stop: false,
        policy_owner_ready: false,
    }
}

fn ready() -> PhoneServiceView {
    PhoneServiceView {
        state: PhoneServiceState::LocalSettingsReady,
        boot_enabled: Some(true),
        can_start: false,
        can_stop: true,
        policy_owner_ready: true,
    }
}

struct Port {
    observations: RefCell<VecDeque<PhoneServiceView>>,
    last: Cell<PhoneServiceView>,
    calls: RefCell<Vec<&'static str>>,
    policy_failed: Cell<bool>,
    history_failed: Cell<bool>,
    control_failed: Cell<bool>,
}

impl Port {
    fn new(observations: &[PhoneServiceView]) -> Self {
        Self {
            observations: RefCell::new(observations.iter().copied().collect()),
            last: Cell::new(stopped()),
            calls: RefCell::new(Vec::new()),
            policy_failed: Cell::new(false),
            history_failed: Cell::new(false),
            control_failed: Cell::new(false),
        }
    }
    fn count(&self, name: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|value| **value == name)
            .count()
    }
}

impl OwnerPort for Port {
    fn requests(&self) -> Result<RequestsReply, AppIssue> {
        self.calls.borrow_mut().push("requests");
        Ok(RequestsReply::Ok { requests_json: r#"{"version":1,"status":"unavailable","revision":"0","peerCount":0,"connectedPeerCount":0,"requests":[]}"#.into() })
    }
    fn review(&self) -> Result<RequestReviewReply, AppIssue> {
        Ok(RequestReviewReply::Ok {
            locator: None,
            revision: "0".into(),
        })
    }
    fn decide(
        &self,
        _locator: String,
        _decision: controller_runtime::DecisionIntent,
    ) -> Result<RequestActionReply, AppIssue> {
        self.calls.borrow_mut().push("decision");
        Ok(RequestActionReply::Queued {})
    }
    fn service(&self) -> Result<PhoneServiceView, AppIssue> {
        self.calls.borrow_mut().push("service");
        if let Some(next) = self.observations.borrow_mut().pop_front() {
            self.last.set(next);
        }
        Ok(self.last.get())
    }
    fn readiness(&self) -> Result<MobileReadiness, AppIssue> {
        Ok(MobileReadiness::UNAVAILABLE)
    }
    fn policy(&self) -> Result<PolicyReply, AppIssue> {
        self.calls.borrow_mut().push("policy");
        if self.policy_failed.get() {
            return Err(mobile_issue());
        }
        Ok(PolicyReply::Ok {
            policy_json: r#"{"schedule":{"mode":"never"},"alert":"silent"}"#.into(),
        })
    }
    fn save_policy(&self, policy: String) -> Result<PolicyReply, AppIssue> {
        self.calls.borrow_mut().push("save");
        Ok(PolicyReply::Ok {
            policy_json: policy,
        })
    }
    fn history(&self) -> Result<HistoryReply, AppIssue> {
        self.calls.borrow_mut().push("history");
        if self.history_failed.get() {
            return Err(controller_runtime::phone_history_issue());
        }
        Ok(HistoryReply::Ok {
            history_json: r#"{"schemaVersion":1,"records":[]}"#.into(),
        })
    }
    fn clear_history(&self) -> Result<HistoryReply, AppIssue> {
        self.calls.borrow_mut().push("clear");
        Ok(HistoryReply::Ok {
            history_json: r#"{"schemaVersion":1,"records":[]}"#.into(),
        })
    }
    fn control(&self, action: ServiceAction) -> Result<ServiceControlReply, AppIssue> {
        self.calls.borrow_mut().push(match action {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            _ => panic!("unsupported control reached native port"),
        });
        Ok(if self.control_failed.get() {
            ServiceControlReply::Unavailable {}
        } else {
            ServiceControlReply::Requested {}
        })
    }
}

#[test]
fn stopped_owner_still_has_recovery_surface_without_policy_or_history_calls() {
    let port = Port::new(&[stopped()]);
    let view = snapshot(&port, OwnerOperation::Read).unwrap();
    assert_eq!(view.schema_version, 4);
    assert_eq!(view.phone_service, Some(stopped()));
    assert!(view.policy.is_none() && view.issue.is_none());
    assert_eq!(
        view.data_availability,
        controller_runtime::DataAvailability::UNAVAILABLE
    );
    assert_eq!(port.count("policy") + port.count("history"), 0);
}

#[test]
fn queued_phone_decision_is_not_an_optimistic_windows_result() {
    let port = Port::new(&[ready()]);
    let view = snapshot(
        &port,
        OwnerOperation::Decide("a".repeat(32), controller_runtime::DecisionIntent::Approve),
    )
    .unwrap();
    assert_eq!(port.count("decision"), 1);
    assert!(view.requests.is_empty());
    assert_eq!(view.data_availability.requests, Availability::Unavailable);
    assert!(view.activity.is_empty());
    assert!(view.request_review.is_none());
}

#[test]
fn stopped_or_invalid_locator_never_reaches_phone_decision() {
    let port = Port::new(&[stopped()]);
    let view = snapshot(
        &port,
        OwnerOperation::Decide("a".repeat(32), controller_runtime::DecisionIntent::Deny),
    )
    .unwrap();
    assert!(view.issue.is_some());
    assert_eq!(port.count("decision"), 0);
    let port = Port::new(&[ready()]);
    assert!(
        snapshot(
            &port,
            OwnerOperation::Decide(
                "../../invalid".into(),
                controller_runtime::DecisionIntent::Approve
            )
        )
        .is_err()
    );
    assert_eq!(port.count("decision"), 0);
}

#[test]
fn accepted_start_is_preparing_not_optimistic_ready_or_retry() {
    let pending = PhoneServiceView {
        state: PhoneServiceState::Preparing,
        policy_owner_ready: false,
        ..ready()
    };
    let port = Port::new(&[stopped(), pending]);
    let view = snapshot(&port, OwnerOperation::ControlService(ServiceAction::Start)).unwrap();
    assert_eq!(view.phone_service, Some(pending));
    assert!(view.policy.is_none() && view.issue.is_none());
    assert_eq!(port.count("start"), 1);
    assert_eq!(port.count("policy"), 0);
}

#[test]
fn stop_acknowledgement_keeps_cleanup_visible_and_hides_unavailable_policy() {
    let cleanup = PhoneServiceView {
        state: PhoneServiceState::CleanupPending,
        boot_enabled: Some(false),
        can_start: false,
        can_stop: true,
        policy_owner_ready: false,
    };
    let port = Port::new(&[ready(), cleanup]);
    let view = snapshot(&port, OwnerOperation::ControlService(ServiceAction::Stop)).unwrap();
    assert_eq!(view.phone_service, Some(cleanup));
    assert!(view.policy.is_none());
    assert_eq!(port.count("stop"), 1);
}

#[test]
fn unknown_contradictory_and_unexposed_actions_never_reach_control() {
    for observation in [
        PhoneServiceView::UNAVAILABLE,
        PhoneServiceView {
            boot_enabled: None,
            ..stopped()
        },
        ready(),
    ] {
        let port = Port::new(&[observation]);
        assert!(
            snapshot(&port, OwnerOperation::ControlService(ServiceAction::Start))
                .unwrap()
                .issue
                .is_some()
        );
        assert_eq!(port.count("start"), 0);
    }
    for action in [
        ServiceAction::Install,
        ServiceAction::Restart,
        ServiceAction::Uninstall,
    ] {
        let port = Port::new(&[stopped()]);
        assert!(snapshot(&port, OwnerOperation::ControlService(action)).is_err());
        assert!(port.calls.borrow().is_empty());
    }
}

#[test]
fn failed_control_preserves_current_state_without_success_or_automatic_retry() {
    let port = Port::new(&[stopped()]);
    port.control_failed.set(true);
    let view = snapshot(&port, OwnerOperation::ControlService(ServiceAction::Start)).unwrap();
    assert_eq!(view.phone_service, Some(stopped()));
    assert_eq!(view.issue.unwrap().code, "phone_service_change_unconfirmed");
    assert_eq!(port.count("start"), 1);
}

#[test]
fn failed_policy_read_does_not_strand_service_controls_or_invent_defaults() {
    let port = Port::new(&[ready()]);
    port.policy_failed.set(true);
    let view = snapshot(&port, OwnerOperation::Read).unwrap();
    assert!(view.phone_service.unwrap().can_stop);
    assert!(view.policy.is_none() && view.issue.is_some());
    assert_eq!(port.count("history"), 0);
}

#[test]
fn failed_policy_read_still_refreshes_a_now_stopped_owners_recovery_controls() {
    let port = Port::new(&[ready(), ready(), stopped()]);
    port.policy_failed.set(true);
    let view = snapshot(&port, OwnerOperation::Read).unwrap();
    assert_eq!(view.phone_service, Some(stopped()));
    assert!(view.phone_service.unwrap().can_start);
    assert!(view.policy.is_none());
    assert_eq!(view.issue.unwrap().code, "mobile_state_unavailable");
    assert_eq!(view.data_availability.activity, Availability::Unavailable);
    assert_eq!(port.count("service"), 3);
    assert_eq!(port.count("history"), 0);
}

#[test]
fn failed_control_can_still_have_changed_native_state_without_claiming_rollback() {
    let port = Port::new(&[ready(), stopped()]);
    port.control_failed.set(true);
    let view = snapshot(&port, OwnerOperation::ControlService(ServiceAction::Stop)).unwrap();
    assert_eq!(view.phone_service, Some(stopped()));
    let issue = view.issue.unwrap();
    assert_eq!(issue.code, "phone_service_change_unconfirmed");
    assert_eq!(
        issue.message,
        "휴대폰 승인을 켜거나 끈 결과를 확인하지 못했어요."
    );
    assert_eq!(port.count("stop"), 1);
    assert_eq!(port.count("policy") + port.count("history"), 0);
}

#[test]
fn unavailable_history_keeps_the_observed_policy_and_its_own_unavailable_status() {
    let port = Port::new(&[ready()]);
    port.history_failed.set(true);
    let view = snapshot(&port, OwnerOperation::Read).unwrap();
    assert_eq!(view.policy.unwrap().schedule(), &Schedule::Never);
    assert_eq!(view.data_availability.activity, Availability::Unavailable);
    assert!(view.issue.is_some());
}

#[test]
fn a_stop_during_policy_history_reads_withdraws_their_current_availability() {
    let port = Port::new(&[ready(), ready(), stopped()]);
    let view = snapshot(&port, OwnerOperation::Read).unwrap();
    assert_eq!(view.phone_service, Some(stopped()));
    assert!(view.policy.is_none());
    assert_eq!(view.data_availability.activity, Availability::Unavailable);
    assert!(!view.can_clear_activity);
}

#[test]
fn stopped_owner_rejects_mutations_but_ready_owner_returns_committed_policy() {
    let policy = r#"{"schedule":{"mode":"never"},"alert":"silent"}"#;
    let port = Port::new(&[stopped()]);
    assert!(
        snapshot(&port, OwnerOperation::SavePolicy(policy.into()))
            .unwrap()
            .issue
            .is_some()
    );
    assert!(
        snapshot(&port, OwnerOperation::ClearHistory)
            .unwrap()
            .issue
            .is_some()
    );
    assert_eq!(port.count("save") + port.count("clear"), 0);
    let port = Port::new(&[ready()]);
    let saved = snapshot(&port, OwnerOperation::SavePolicy(policy.into())).unwrap();
    assert_eq!(saved.policy.unwrap().schedule(), &Schedule::Never);
    assert_eq!(port.count("save"), 1);
    assert_eq!(port.count("policy"), 0);
    let cleared = snapshot(&port, OwnerOperation::ClearHistory).unwrap();
    assert_eq!(cleared.data_availability.activity, Availability::Available);
    assert_eq!(port.count("clear"), 1);
}
