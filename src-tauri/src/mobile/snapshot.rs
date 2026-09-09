//! Independent service recovery surface; never create an owner just to read it.
use controller_runtime::{
    AppIssue, AppSnapshot, Availability, MobileReadiness, NotificationPolicy, PhoneServiceView,
    ServiceAction,
};

use super::{
    HistoryReply, OwnerOperation, PolicyReply, RequestActionReply, RequestReviewReply,
    RequestsReply, ServiceControlReply, mobile_issue,
};

pub(super) trait OwnerPort {
    fn service(&self) -> Result<PhoneServiceView, AppIssue>;
    fn readiness(&self) -> Result<MobileReadiness, AppIssue>;
    fn policy(&self) -> Result<PolicyReply, AppIssue>;
    fn save_policy(&self, policy: String) -> Result<PolicyReply, AppIssue>;
    fn history(&self) -> Result<HistoryReply, AppIssue>;
    fn clear_history(&self) -> Result<HistoryReply, AppIssue>;
    fn control(&self, action: ServiceAction) -> Result<ServiceControlReply, AppIssue>;
    fn requests(&self) -> Result<RequestsReply, AppIssue>;
    fn review(&self) -> Result<RequestReviewReply, AppIssue>;
    fn decide(
        &self,
        locator: String,
        decision: controller_runtime::DecisionIntent,
    ) -> Result<RequestActionReply, AppIssue>;
}

pub(super) const fn service_issue() -> AppIssue {
    AppIssue {
        code: "phone_service_unavailable",
        message: "휴대폰 서비스 상태를 확인하지 못했어요.",
        next_action: Some("현재 상태를 새로 확인해 주세요."),
    }
}

const fn control_issue() -> AppIssue {
    AppIssue {
        code: "phone_service_change_unconfirmed",
        message: "휴대폰 서비스 변경 결과를 확인하지 못했어요.",
        next_action: Some("현재 상태와 자동 시작 설정을 확인한 뒤 다시 시도해 주세요."),
    }
}

fn observed_service(port: &impl OwnerPort) -> Result<PhoneServiceView, AppIssue> {
    port.service()?.checked().ok_or_else(service_issue)
}

pub(super) fn snapshot(
    port: &impl OwnerPort,
    operation: OwnerOperation,
) -> Result<AppSnapshot, AppIssue> {
    if matches!(
        operation,
        OwnerOperation::ControlService(
            ServiceAction::Install | ServiceAction::Restart | ServiceAction::Uninstall
        )
    ) {
        return Err(controller_runtime::PlatformError::Unsupported.into());
    }
    let before = observed_service(port);
    let mut operation_issue = None;
    let mut saved_policy: Option<NotificationPolicy> = None;
    let mut cleared_history = None;
    match operation {
        OwnerOperation::Read => {}
        OwnerOperation::Decide(locator, decision) => {
            controller_runtime::check_request_locator(&locator)?;
            if before.as_ref().is_ok_and(|view| view.policy_owner_ready) {
                // Native acceptance is only queue admission. Snapshot below is
                // observed again; never publish an optimistic approval/result.
                if let Err(issue) = port
                    .decide(locator, decision)
                    .and_then(RequestActionReply::accepted)
                {
                    operation_issue = Some(issue);
                }
            } else {
                operation_issue = Some(controller_runtime::phone_request_issue());
            }
        }
        OwnerOperation::ControlService(action) => {
            if before.as_ref().is_ok_and(|view| view.allows(action)) {
                if !matches!(port.control(action), Ok(ServiceControlReply::Requested {})) {
                    operation_issue = Some(control_issue());
                }
            } else {
                operation_issue = Some(control_issue());
            }
        }
        OwnerOperation::SavePolicy(policy) => {
            if before.as_ref().is_ok_and(|view| view.policy_owner_ready) {
                match port.save_policy(policy).and_then(PolicyReply::policy) {
                    Ok(value) => saved_policy = Some(value),
                    Err(issue) => operation_issue = Some(issue),
                }
            } else {
                operation_issue = Some(mobile_issue());
            }
        }
        OwnerOperation::ClearHistory => {
            if before.as_ref().is_ok_and(|view| view.policy_owner_ready) {
                match port.clear_history().and_then(HistoryReply::history) {
                    Ok(Some(history)) => cleared_history = Some(history),
                    Ok(None) => operation_issue = Some(controller_runtime::phone_history_issue()),
                    Err(issue) => operation_issue = Some(issue),
                }
            } else {
                operation_issue = Some(controller_runtime::phone_history_issue());
            }
        }
    }
    // A fresh observation after a command. A native request acknowledgement is
    // not an optimistic state transition; it may still be preparing/cleaning.
    let service = observed_service(port);
    let mut value = AppSnapshot::from_android_service(
        service.unwrap_or(PhoneServiceView::UNAVAILABLE),
        port.readiness().unwrap_or(MobileReadiness::UNAVAILABLE),
    );
    value.issue = operation_issue.or(service.err());
    if !value
        .phone_service
        .is_some_and(|view| view.policy_owner_ready)
    {
        return Ok(value);
    }
    let policy = saved_policy.map_or_else(|| port.policy().and_then(PolicyReply::policy), Ok);
    match policy {
        Ok(policy) => {
            value.policy = Some(policy);
            let history = cleared_history.map_or_else(
                || port.history().and_then(HistoryReply::history),
                |history| Ok(Some(history)),
            );
            match history {
                Ok(Some(history)) => {
                    value.can_clear_activity = !history.is_empty();
                    value.activity = history;
                    value.data_availability.activity = Availability::Available;
                }
                Ok(None) => {}
                Err(issue) => value.issue = value.issue.or(Some(issue)),
            }
        }
        Err(issue) => value.issue = value.issue.or(Some(issue)),
    }
    // Catalogue availability is independent of history. Unknown and partial
    // inventory remain distinct from a known empty ready catalogue.
    match port.requests().and_then(RequestsReply::requests) {
        Ok(requests) => {
            if requests.catalog.status == controller_runtime::RequestCatalogState::Ready {
                value.data_availability.requests = Availability::Available;
                value.requests = requests.requests;
            }
            value.request_catalog = Some(requests.catalog);
        }
        Err(issue) => value.issue = value.issue.or(Some(issue)),
    }
    value.request_review = port
        .review()
        .and_then(RequestReviewReply::review)
        .ok()
        .flatten()
        .filter(|review| {
            value
                .requests
                .iter()
                .any(|request| request.id == review.locator)
        });
    // Read callbacks may cross a stop/failure. Do not display their data as a
    // current available owner once that owner is no longer ready.
    let after = observed_service(port);
    let current = after.unwrap_or(PhoneServiceView::UNAVAILABLE);
    value.phone_service = Some(current);
    if !current.policy_owner_ready {
        value.policy = None;
        value.activity.clear();
        value.can_clear_activity = false;
        value.data_availability.activity = Availability::Unavailable;
        value.requests.clear();
        value.request_catalog = None;
        value.request_review = None;
        value.data_availability.requests = Availability::Unavailable;
    }
    value.issue = value.issue.or(after.err());
    Ok(value)
}

#[cfg(test)]
mod tests;
