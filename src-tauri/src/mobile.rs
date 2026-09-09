//! Android shell bridge to the Application owner; no second store or authority.
use controller_runtime::AppIssue;
use tauri::plugin::{Builder, TauriPlugin};

#[cfg(any(target_os = "android", test))]
mod snapshot;

#[cfg(target_os = "android")]
struct DeviceState(tauri::plugin::PluginHandle<tauri::Wry>);

pub(crate) fn init() -> TauriPlugin<tauri::Wry> {
    Builder::new("device-state")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                use tauri::Manager;
                let plugin =
                    _api.register_android_plugin("dev.dkk115.uacremote", "DeviceStatePlugin")?;
                _app.manage(DeviceState(plugin));
            }
            Ok(())
        })
        .build()
}

pub(crate) fn open_lock_settings(app: &tauri::AppHandle) -> Result<(), AppIssue> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let _: serde_json::Value = app
            .state::<DeviceState>()
            .0
            .run_mobile_plugin("openLockSettings", ())
            .map_err(|_| mobile_issue())?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err(mobile_issue())
    }
}

const fn mobile_issue() -> AppIssue {
    AppIssue {
        code: "mobile_state_unavailable",
        message: "휴대폰 상태를 확인하지 못했어요.",
        next_action: Some("휴대폰에서 앱을 다시 열어 주세요."),
    }
}

pub(crate) fn open_notification_settings(app: &tauri::AppHandle) -> Result<(), AppIssue> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let _: serde_json::Value = app
            .state::<DeviceState>()
            .0
            .run_mobile_plugin("openNotificationSettings", ())
            .map_err(|_| mobile_issue())?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err(mobile_issue())
    }
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum PolicyReply {
    Ok {
        #[serde(rename = "policyJson")]
        policy_json: String,
    },
    Busy {},
    Unavailable {},
    InvalidPolicy {},
    StorageUnavailable {},
}

#[cfg(any(target_os = "android", test))]
impl PolicyReply {
    fn policy(self) -> Result<controller_runtime::NotificationPolicy, AppIssue> {
        match self {
            Self::Ok { policy_json } => {
                controller_runtime::decode_notification_policy_json(policy_json.as_bytes())
            }
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::Unavailable {} => Err(mobile_issue()),
            Self::InvalidPolicy {} => {
                Err(controller_runtime::PreferenceError::InvalidPolicy.into())
            }
            Self::StorageUnavailable {} => Err(crate::commands::storage_issue()),
        }
    }
}

#[cfg(any(target_os = "android", test))]
pub(crate) enum OwnerOperation {
    Read,
    SavePolicy(String),
    ClearHistory,
    ControlService(controller_runtime::ServiceAction),
    Decide(String, controller_runtime::DecisionIntent),
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RequestsReply {
    Ok {
        #[serde(rename = "requestsJson")]
        requests_json: String,
    },
    Busy {},
    Unavailable {},
}

#[cfg(any(target_os = "android", test))]
impl RequestsReply {
    fn requests(self) -> Result<controller_runtime::PhoneRequestCatalog, AppIssue> {
        match self {
            Self::Ok { requests_json } => {
                controller_runtime::decode_phone_requests_json(requests_json.as_bytes())
            }
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::Unavailable {} => Err(controller_runtime::phone_request_issue()),
        }
    }
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RequestActionReply {
    Queued {},
    Busy {},
    Unavailable {},
    Stale {},
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RequestReviewReply {
    Ok {
        #[serde(deserialize_with = "required_review_locator")]
        locator: Option<String>,
        revision: String,
    },
    Busy {},
    Unavailable {},
}

#[cfg(any(target_os = "android", test))]
fn required_review_locator<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    serde::Deserialize::deserialize(deserializer)
}

#[cfg(any(target_os = "android", test))]
impl RequestReviewReply {
    fn review(self) -> Result<Option<controller_runtime::RequestReviewView>, AppIssue> {
        match self {
            Self::Ok { locator, revision } => {
                let parsed = revision
                    .parse::<u64>()
                    .map_err(|_| controller_runtime::phone_request_issue())?;
                if parsed.to_string() != revision {
                    return Err(controller_runtime::phone_request_issue());
                }
                locator
                    .map(|locator| {
                        controller_runtime::check_request_locator(&locator)?;
                        Ok(controller_runtime::RequestReviewView { locator, revision })
                    })
                    .transpose()
            }
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::Unavailable {} => Err(controller_runtime::phone_request_issue()),
        }
    }
}

#[cfg(any(target_os = "android", test))]
impl RequestActionReply {
    fn accepted(self) -> Result<(), AppIssue> {
        match self {
            Self::Queued {} => Ok(()),
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::Unavailable {} | Self::Stale {} => Err(controller_runtime::phone_request_issue()),
        }
    }
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum RequestDetailsReply {
    Ok {
        #[serde(rename = "detailsJson")]
        details_json: String,
    },
    Busy {},
    Unavailable {},
    Stale {},
}

#[cfg(any(target_os = "android", test))]
impl RequestDetailsReply {
    fn details(self, locator: &str) -> Result<controller_runtime::RequestDetailsView, AppIssue> {
        match self {
            Self::Ok { details_json } => controller_runtime::decode_phone_request_details_json(
                details_json.as_bytes(),
                locator,
            ),
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::Unavailable {} | Self::Stale {} => Err(controller_runtime::phone_request_issue()),
        }
    }
}

#[cfg(target_os = "android")]
pub(crate) fn request_details(
    app: &tauri::AppHandle,
    locator: String,
) -> Result<controller_runtime::RequestDetailsView, AppIssue> {
    use tauri::Manager;
    controller_runtime::check_request_locator(&locator)?;
    #[derive(serde::Serialize)]
    struct Selection<'a> {
        locator: &'a str,
    }
    let reply: RequestDetailsReply = app
        .state::<DeviceState>()
        .0
        .run_mobile_plugin("controllerRequestDetails", Selection { locator: &locator })
        .map_err(|_| controller_runtime::phone_request_issue())?;
    reply.details(&locator)
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ServiceControlReply {
    Requested {},
    Unavailable {},
    NotAllowed {},
}

#[cfg(any(target_os = "android", test))]
#[derive(serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum HistoryReply {
    Ok {
        #[serde(rename = "historyJson")]
        history_json: String,
    },
    Busy {},
    Unavailable {},
    InvalidPolicy {},
    StorageUnavailable {},
    HistoryUnavailable {},
}

#[cfg(any(target_os = "android", test))]
impl HistoryReply {
    fn history(self) -> Result<Option<Vec<controller_runtime::ActivityView>>, AppIssue> {
        match self {
            Self::Ok { history_json } => {
                controller_runtime::decode_phone_history_json(history_json.as_bytes()).map(Some)
            }
            Self::HistoryUnavailable {} => Ok(None),
            Self::Busy {} => Err(crate::commands::busy_issue()),
            Self::StorageUnavailable {} => Err(crate::commands::storage_issue()),
            Self::Unavailable {} | Self::InvalidPolicy {} => {
                Err(controller_runtime::phone_history_issue())
            }
        }
    }
}

#[cfg(target_os = "android")]
pub(crate) fn policy_snapshot(
    app: &tauri::AppHandle,
    operation: OwnerOperation,
) -> Result<controller_runtime::AppSnapshot, AppIssue> {
    use tauri::Manager;
    snapshot::snapshot(&NativeOwnerPort(&app.state::<DeviceState>().0), operation)
}

#[cfg(target_os = "android")]
struct NativeOwnerPort<'a>(&'a tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(target_os = "android")]
impl snapshot::OwnerPort for NativeOwnerPort<'_> {
    fn review(&self) -> Result<RequestReviewReply, AppIssue> {
        self.0
            .run_mobile_plugin("controllerRequestReview", ())
            .map_err(|_| controller_runtime::phone_request_issue())
    }
    fn requests(&self) -> Result<RequestsReply, AppIssue> {
        self.0
            .run_mobile_plugin("controllerRequests", ())
            .map_err(|_| controller_runtime::phone_request_issue())
    }

    fn decide(
        &self,
        locator: String,
        decision: controller_runtime::DecisionIntent,
    ) -> Result<RequestActionReply, AppIssue> {
        #[derive(serde::Serialize)]
        struct Action {
            locator: String,
            action: controller_runtime::DecisionIntent,
        }
        self.0
            .run_mobile_plugin(
                "controllerRequestAction",
                Action {
                    locator,
                    action: decision,
                },
            )
            .map_err(|_| controller_runtime::phone_request_issue())
    }
    fn service(&self) -> Result<controller_runtime::PhoneServiceView, AppIssue> {
        self.0
            .run_mobile_plugin("controllerService", ())
            .map_err(|_| snapshot::service_issue())
    }

    fn readiness(&self) -> Result<controller_runtime::MobileReadiness, AppIssue> {
        self.0
            .run_mobile_plugin("readiness", ())
            .map_err(|_| mobile_issue())
    }

    fn policy(&self) -> Result<PolicyReply, AppIssue> {
        self.0
            .run_mobile_plugin("controllerPolicy", ())
            .map_err(|_| mobile_issue())
    }

    fn save_policy(&self, policy_json: String) -> Result<PolicyReply, AppIssue> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SavePolicy {
            policy_json: String,
        }
        self.0
            .run_mobile_plugin("saveControllerPolicy", SavePolicy { policy_json })
            .map_err(|_| mobile_issue())
    }

    fn history(&self) -> Result<HistoryReply, AppIssue> {
        self.0
            .run_mobile_plugin("controllerHistory", ())
            .map_err(|_| controller_runtime::phone_history_issue())
    }

    fn clear_history(&self) -> Result<HistoryReply, AppIssue> {
        self.0
            .run_mobile_plugin("clearControllerHistory", ())
            .map_err(|_| controller_runtime::phone_history_issue())
    }

    fn control(
        &self,
        action: controller_runtime::ServiceAction,
    ) -> Result<ServiceControlReply, AppIssue> {
        let command = match action {
            controller_runtime::ServiceAction::Start => "startControllerService",
            controller_runtime::ServiceAction::Stop => "stopControllerService",
            _ => return Err(controller_runtime::PlatformError::Unsupported.into()),
        };
        self.0
            .run_mobile_plugin(command, ())
            .map_err(|_| snapshot::service_issue())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HistoryReply, PolicyReply, RequestActionReply, RequestDetailsReply, RequestReviewReply,
        RequestsReply, ServiceControlReply,
    };

    #[test]
    fn request_reply_boundaries_have_no_success_or_authority_fallback() {
        for document in [
            serde_json::json!({}),
            serde_json::json!({"status":"approved"}),
            serde_json::json!({"status":"queued","authenticated":true}),
        ] {
            assert!(serde_json::from_value::<RequestActionReply>(document).is_err());
        }
        for status in ["queued", "busy", "unavailable", "stale"] {
            let reply: RequestActionReply =
                serde_json::from_value(serde_json::json!({"status":status})).unwrap();
            assert_eq!(reply.accepted().is_ok(), status == "queued");
        }
        for status in ["busy", "unavailable"] {
            let reply: RequestsReply =
                serde_json::from_value(serde_json::json!({"status":status})).unwrap();
            assert!(reply.requests().is_err());
        }
        let malformed = RequestsReply::Ok {
            requests_json: "{}".into(),
        };
        assert!(malformed.requests().is_err());
    }

    #[test]
    fn on_demand_reply_is_bound_to_exact_locator_and_keeps_details_out_of_errors() {
        let locator = "a".repeat(32);
        for status in ["busy", "unavailable", "stale"] {
            let reply: RequestDetailsReply =
                serde_json::from_value(serde_json::json!({"status":status})).unwrap();
            assert!(reply.details(&locator).is_err());
        }
        let reply = RequestDetailsReply::Ok { details_json: serde_json::json!({"version":1,"id":locator,
            "programName":"original-program","executablePath":"original-path","details":"synthetic-original-body",
            "remainingSeconds":12,"refreshAfterMillis":1000}).to_string() };
        assert_eq!(
            reply.details(&locator).unwrap().details,
            "synthetic-original-body"
        );
        assert!(
            serde_json::from_value::<RequestDetailsReply>(
                serde_json::json!({"status":"ok","detailsJson":"{}","approved":true})
            )
            .is_err()
        );
    }

    #[test]
    fn sticky_review_is_navigation_only_and_revision_is_not_a_lossy_number() {
        for document in [
            serde_json::json!({"status":"ok","revision":"0"}),
            serde_json::json!({"status":"ok","revision":1,"locator":null}),
            serde_json::json!({"status":"ok","revision":"1","locator":null,"approve":true}),
        ] {
            assert!(serde_json::from_value::<RequestReviewReply>(document).is_err());
        }
        for status in ["busy", "unavailable"] {
            let reply: RequestReviewReply =
                serde_json::from_value(serde_json::json!({"status":status})).unwrap();
            assert!(reply.review().is_err());
        }
        assert!(
            RequestReviewReply::Ok {
                locator: None,
                revision: "0".into()
            }
            .review()
            .unwrap()
            .is_none()
        );
        assert!(
            RequestReviewReply::Ok {
                locator: None,
                revision: "00".into()
            }
            .review()
            .is_err()
        );
        let locator = "b".repeat(32);
        let review = RequestReviewReply::Ok {
            locator: Some(locator.clone()),
            revision: u64::MAX.to_string(),
        }
        .review()
        .unwrap()
        .unwrap();
        assert_eq!(review.locator, locator);
        assert!(!format!("{review:?}").contains(&locator));
    }

    #[test]
    fn control_acknowledgement_has_no_running_or_authorization_fallback() {
        for status in ["requested", "not_allowed", "unavailable"] {
            assert!(
                serde_json::from_value::<ServiceControlReply>(serde_json::json!({"status":status}))
                    .is_ok()
            );
        }
        for input in [
            serde_json::json!({}),
            serde_json::json!({"status":"running"}),
            serde_json::json!({"status":"requested", "authenticated":true}),
            serde_json::json!({"status":"requested", "bootEnabled":true}),
        ] {
            assert!(serde_json::from_value::<ServiceControlReply>(input).is_err());
        }
    }

    #[test]
    fn history_reply_never_turns_native_failure_or_malformed_content_into_empty_data() {
        for input in [
            r#"{}"#,
            r#"{"status":"ok"}"#,
            r#"{"status":"history_unavailable","historyJson":"{}"}"#,
        ] {
            assert!(serde_json::from_str::<HistoryReply>(input).is_err());
        }
        for status in ["busy", "unavailable", "storage_unavailable"] {
            let reply: HistoryReply =
                serde_json::from_value(serde_json::json!({"status":status})).unwrap();
            assert!(reply.history().is_err());
        }
        let reply: HistoryReply =
            serde_json::from_value(serde_json::json!({"status":"ok", "historyJson":"{}"})).unwrap();
        assert!(reply.history().is_err());
        let reply: HistoryReply = serde_json::from_value(
            serde_json::json!({"status":"ok", "historyJson":r#"{"schemaVersion":1,"records":[]}"#}),
        )
        .unwrap();
        assert!(reply.history().unwrap().unwrap().is_empty());
        let partial: HistoryReply =
            serde_json::from_value(serde_json::json!({"status":"history_unavailable"})).unwrap();
        assert!(partial.history().unwrap().is_none());
    }

    #[test]
    fn native_policy_reply_has_no_default_or_raw_error_fallback() {
        for input in [
            r#"{}"#,
            r#"{"status":"ok"}"#,
            r#"{"status":"future"}"#,
            r#"{"status":"storage_unavailable","policyJson":"{}"}"#,
        ] {
            assert!(
                serde_json::from_str::<PolicyReply>(input).is_err(),
                "unexpectedly accepted {input}"
            );
        }
        assert!(
            serde_json::from_str::<PolicyReply>(r#"{"status":"ok","policyJson":"{}"}"#)
                .unwrap()
                .policy()
                .is_err()
        );
        for status in [
            "busy",
            "unavailable",
            "invalid_policy",
            "storage_unavailable",
        ] {
            let reply: PolicyReply =
                serde_json::from_str(&format!("{{\"status\":\"{status}\"}}")).unwrap();
            assert!(reply.policy().is_err());
        }
        let policy = r#"{"schedule":{"mode":"never"},"alert":"silent"}"#;
        let reply: PolicyReply =
            serde_json::from_value(serde_json::json!({"status":"ok", "policyJson":policy}))
                .unwrap();
        assert_eq!(
            serde_json::to_string(&reply.policy().unwrap()).unwrap(),
            policy
        );
    }
}
