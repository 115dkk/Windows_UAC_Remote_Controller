//! Android shell bridge to the Application owner; no second store or authority.
use controller_runtime::AppIssue;
use tauri::plugin::{Builder, TauriPlugin};

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

#[cfg(target_os = "android")]
pub(crate) fn readiness(
    app: &tauri::AppHandle,
) -> Result<controller_runtime::MobileReadiness, AppIssue> {
    use tauri::Manager;
    app.state::<DeviceState>()
        .0
        .run_mobile_plugin("readiness", ())
        .map_err(|_| mobile_issue())
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

#[cfg(target_os = "android")]
pub(crate) enum OwnerOperation {
    Read,
    SavePolicy(String),
    ClearHistory,
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
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SavePolicy {
        policy_json: String,
    }
    let plugin = &app.state::<DeviceState>().0;
    let cleared = if matches!(&operation, OwnerOperation::ClearHistory) {
        let reply: HistoryReply = plugin
            .run_mobile_plugin("clearControllerHistory", ())
            .map_err(|_| controller_runtime::phone_history_issue())?;
        Some(
            reply
                .history()?
                .ok_or_else(controller_runtime::phone_history_issue)?,
        )
    } else {
        None
    };
    let reply: PolicyReply = match operation {
        OwnerOperation::SavePolicy(policy_json) => {
            plugin.run_mobile_plugin("saveControllerPolicy", SavePolicy { policy_json })
        }
        OwnerOperation::Read | OwnerOperation::ClearHistory => {
            plugin.run_mobile_plugin("controllerPolicy", ())
        }
    }
    .map_err(|_| mobile_issue())?;
    let policy = reply.policy()?;
    let history = match cleared {
        Some(history) => Some(history),
        None => plugin
            .run_mobile_plugin::<HistoryReply>("controllerHistory", ())
            .map_err(|_| controller_runtime::phone_history_issue())?
            .history()?,
    };
    let readiness = readiness(app).unwrap_or(controller_runtime::MobileReadiness::UNAVAILABLE);
    Ok(
        controller_runtime::AppSnapshot::from_android_policy_and_history(
            policy, readiness, history,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{HistoryReply, PolicyReply};

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
