//! Android shell bridge to the Application owner; no second store or authority.
use controller_runtime::AppIssue;
use tauri::plugin::{Builder, TauriPlugin};

/// Injected native invocation context, not a renderer argument. The Android
/// origin was captured at physical WebView IPC entry, before command queues.
pub(crate) struct CommandOrigin {
    #[cfg(target_os = "android")]
    native: tauri::ipc::AndroidInvokeOrigin,
}

impl<'de, R: tauri::Runtime> tauri::ipc::CommandArg<'de, R> for CommandOrigin {
    fn from_command(
        command: tauri::ipc::CommandItem<'de, R>,
    ) -> Result<Self, tauri::ipc::InvokeError> {
        #[cfg(target_os = "android")]
        {
            Ok(Self { native: <tauri::ipc::AndroidInvokeOrigin as tauri::ipc::CommandArg<'de, R>>::from_command(command)? })
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = command;
            Ok(Self {})
        }
    }
}

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

pub(crate) fn open_lock_settings(
    app: &tauri::AppHandle,
    origin: &CommandOrigin,
) -> Result<(), AppIssue> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let _: serde_json::Value = app
            .state::<DeviceState>()
            .0
            .run_mobile_plugin_from_origin(&origin.native, "openLockSettings", ())
            .map_err(|_| mobile_issue())?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
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

pub(crate) fn open_notification_settings(
    app: &tauri::AppHandle,
    origin: &CommandOrigin,
) -> Result<(), AppIssue> {
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        let _: serde_json::Value = app
            .state::<DeviceState>()
            .0
            .run_mobile_plugin_from_origin(&origin.native, "openNotificationSettings", ())
            .map_err(|_| mobile_issue())?;
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
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
    origin: &CommandOrigin,
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
        .run_mobile_plugin_from_origin(
            &origin.native,
            "controllerRequestDetails",
            Selection { locator: &locator },
        )
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
    origin: &CommandOrigin,
    operation: OwnerOperation,
) -> Result<controller_runtime::AppSnapshot, AppIssue> {
    use tauri::Manager;
    snapshot::snapshot(
        &NativeOwnerPort(&app.state::<DeviceState>().0, origin),
        operation,
    )
}

#[cfg(target_os = "android")]
struct NativeOwnerPort<'a>(
    &'a tauri::plugin::PluginHandle<tauri::Wry>,
    &'a CommandOrigin,
);

#[cfg(target_os = "android")]
impl snapshot::OwnerPort for NativeOwnerPort<'_> {
    fn review(&self) -> Result<RequestReviewReply, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "controllerRequestReview", ())
            .map_err(|_| controller_runtime::phone_request_issue())
    }
    fn requests(&self) -> Result<RequestsReply, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "controllerRequests", ())
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
            .run_mobile_plugin_from_origin(
                &self.1.native,
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
            .run_mobile_plugin_from_origin(&self.1.native, "controllerService", ())
            .map_err(|_| snapshot::service_issue())
    }

    fn readiness(&self) -> Result<controller_runtime::MobileReadiness, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "readiness", ())
            .map_err(|_| mobile_issue())
    }

    fn policy(&self) -> Result<PolicyReply, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "controllerPolicy", ())
            .map_err(|_| mobile_issue())
    }

    fn save_policy(&self, policy_json: String) -> Result<PolicyReply, AppIssue> {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SavePolicy {
            policy_json: String,
        }
        self.0
            .run_mobile_plugin_from_origin(
                &self.1.native,
                "saveControllerPolicy",
                SavePolicy { policy_json },
            )
            .map_err(|_| mobile_issue())
    }

    fn history(&self) -> Result<HistoryReply, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "controllerHistory", ())
            .map_err(|_| controller_runtime::phone_history_issue())
    }

    fn clear_history(&self) -> Result<HistoryReply, AppIssue> {
        self.0
            .run_mobile_plugin_from_origin(&self.1.native, "clearControllerHistory", ())
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
            .run_mobile_plugin_from_origin(&self.1.native, command, ())
            .map_err(|_| snapshot::service_issue())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ipc_diagnostics_do_not_log_keys_payloads_or_responses() {
        let webview = include_str!("../../vendor/tauri-2.11.5/src/webview/mod.rs");
        assert!(!webview.contains("__TAURI_INVOKE_KEY__ expected"));
        assert!(webview.contains("IPC invoke key rejected"));
        let ipc = include_str!("../../vendor/tauri-2.11.5/src/ipc/protocol.rs");
        for forbidden in [
            "request = request.body()",
            "response = format!",
            "response = v,",
            "ipc.request.error {e}",
        ] {
            assert!(!ipc.contains(forbidden));
        }
        assert!(ipc.contains("IPC request rejected during parsing"));
    }

    use super::{
        HistoryReply, PolicyReply, RequestActionReply, RequestDetailsReply, RequestReviewReply,
        RequestsReply, ServiceControlReply,
    };

    #[test]
    fn physical_origin_is_carried_at_both_native_ipc_entries_not_from_json() {
        // Source-contract regression only; real old/current physical JNI entry
        // rejection is exercised separately by Android instrumentation.
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let binding = compact(include_str!("../../vendor/wry/src/android/binding.rs"));
        assert!(binding.contains("capture_webview_origin(env,&webview)"));
        assert!(binding.contains("capture_webview_origin(&mutenv,&webview)"));
        assert_eq!(binding.matches(".extension(origin)").count(), 2);
        let post = compact(include_str!("../../vendor/wry/src/android/kotlin/Ipc.kt"));
        assert!(post.contains("Rust.ipc(webView,webView.id,webViewClient.currentUrl,m)"));
        let request = compact(include_str!(
            "../../vendor/wry/src/android/kotlin/RustWebViewClient.kt"
        ));
        assert!(request.contains(
            "Rust.handleRequest(view,view.id,request,view.isDocumentStartScriptEnabled)"
        ));
        let protocol = compact(include_str!(
            "../../vendor/tauri-2.11.5/src/ipc/protocol.rs"
        ));
        assert_eq!(
            protocol
                .matches("AndroidInvokeOrigin::from_extensions(request.extensions())")
                .count(),
            2
        );
        let origin = compact(include_str!(
            "../../vendor/tauri-2.11.5/src/ipc/android_origin.rs"
        ));
        assert!(origin.contains("command.message.android_origin.as_ref()"));
        assert!(!origin.contains("DeserializeforAndroidInvokeOrigin"));
        assert!(!origin.contains("SerializeforAndroidInvokeOrigin"));
        assert!(!origin.contains("getRawArgs"));
    }

    #[test]
    fn facade_snapshots_the_native_original_view_and_adapter_fields_stay_immutable() {
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let facade = compact(include_str!(
            "../gen/android/app/src/main/java/dev/dkk115/uacremote/DeviceStatePlugin.kt"
        ));
        assert!(facade.contains("valorigin=invoke.originatingWebView"));
        assert!(facade.contains("commands?.takeIf{it.matches(origin)}"));
        assert!(facade.contains("action(captured,invoke)"));
        assert!(facade.contains("webView.context!==activity"));
        assert!(facade.contains("Looper.myLooper()!=Looper.getMainLooper()"));
        let adapter = compact(include_str!(
            "../gen/android/app/src/main/java/dev/dkk115/uacremote/DeviceStateActivityCommands.kt"
        ));
        assert!(adapter.contains("privatevalactivity:MainActivity"));
        assert!(adapter.contains("privatevalwebView:WebView"));
        assert!(adapter.contains("privatevalbinding:DeviceStateViewBinding<MainActivity,WebView>"));
        assert!(!adapter.contains("privatevaractivity"));
        assert!(!adapter.contains("privatevarhost"));
        assert!(adapter.contains("binding.matches(activity,webView)"));
        assert!(adapter.contains("isCurrentForegroundControllerHost(activity)"));
        let main = compact(include_str!(
            "../gen/android/app/src/main/java/dev/dkk115/uacremote/MainActivity.kt"
        ));
        assert!(main.contains(
            "super.onWebViewCreate(webView)DeviceStatePlugin.actualWebViewCreated(this,webView)"
        ));
    }

    #[test]
    fn project_mobile_calls_have_no_unbound_current_view_dispatch_fallback() {
        let source = include_str!("mobile.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains(".run_mobile_plugin("));
        assert!(production.contains("run_mobile_plugin_from_origin"));
        let production = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(production.contains("tauri::ipc::CommandArg<'de,R>forCommandOrigin"));
        let commands = include_str!("commands.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            .replace(",)", ")");
        assert!(commands.contains("origin:crate::mobile::CommandOrigin"));
        assert!(commands.contains("policy_snapshot(&app,&origin,operation)"));
        assert!(commands.contains("request_details(&app,&origin,request_id)"));
    }

    #[test]
    fn generic_wry_work_is_generation_fenced_and_missing_context_completes_without_retargeting() {
        let pipe = include_str!("../../vendor/wry/src/android/main_pipe.rs")
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert!(pipe.contains("Option<AndroidActivityOrigin>"));
        assert!(pipe.contains("activity_origin_current(&origin)"));
        assert!(pipe.contains("callback(&mutself.env,&JObject::null(),&JObject::null())"));
        assert!(pipe.contains("sender.send(Err(Error::ActivityNotFound))"));
        assert!(pipe.contains("WebViewMessage::GetUrl(sender)=>drop(sender)"));
        assert!(pipe.contains("WebViewMessage::GetCookies(sender,_)=>drop(sender)"));
        let android = include_str!("../../vendor/wry/src/android/mod.rs");
        assert!(android.contains("MainPipe::send_without_activity"));
        assert!(!android.contains("first_activity_id().expect"));
        assert!(!android.contains("let activity_id = loop"));
    }

    #[test]
    fn eval_callbacks_retain_physical_origin_and_cancel_without_a_substitute_result() {
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let pipe = compact(include_str!("../../vendor/wry/src/android/main_pipe.rs"));
        assert!(pipe.contains("PendingEval{origin,callback}"));
        assert!(pipe.contains("pending.len()>=64"));
        let binding = compact(include_str!("../../vendor/wry/src/android/binding.rs"));
        assert!(binding.contains("cancel_evals_for_activity(&origin)"));
        assert!(binding.contains("entry.origin.same(&origin)"));
        assert!(binding.contains("callbacks.remove(&id)"));
        let view = compact(include_str!(
            "../../vendor/wry/src/android/kotlin/RustWebView.kt"
        ));
        assert!(view.contains("Rust.onEval(this,this.id,id,result)"));
        let android = compact(include_str!("../../vendor/wry/src/android/mod.rs"));
        assert!(android.contains("entry.origin.activity_origin().same(origin)"));
        assert!(android.contains("drop(cancelled)"));
        assert!(android.contains("id.checked_add(1)"));
    }

    #[test]
    fn wry_handler_publication_and_retirement_share_exact_registration_ownership() {
        // Passive source contracts, not JNI/concurrency execution evidence.
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let handlers = compact(include_str!("../../vendor/wry/src/android/handlers.rs"));
        assert!(handlers.contains("structHandlerRegistration(Arc<RegistrationInner>)"));
        assert!(handlers.contains("entries:HashMap<WebviewId,RegisteredHandlers>"));
        assert!(handlers.contains("definitions:HashMap<ActivityId,CreateWebViewAttributes>"));
        assert!(handlers.contains("entry.registration.same(registration)"));
        assert!(handlers.contains("entry.activity_origin.same(origin)"));
        assert!(handlers.contains("registry.remove_owned(&definition.registration)"));
        assert!(handlers.contains("old.registration.is_live()"));
        assert!(handlers.contains("Arc::clone(&old_handlers.handlers)"));
        assert!(handlers.contains("registration.retire()"));
        assert!(handlers.contains("drop(replaced)"));
        assert!(handlers.contains("drop(removed)"));
        let binding = compact(include_str!("../../vendor/wry/src/android/binding.rs"));
        let destroy = binding
            .split("pubunsafefnonWebviewDestroy")
            .nth(1)
            .unwrap()
            .split("#[allow(non_snake_case)]")
            .next()
            .unwrap();
        assert!(destroy.contains("handlers::retire_activity(&origin,is_changing_configurations)"));
        assert!(destroy.contains("remove_activity_proxy(&origin)"));
        assert!(!destroy.contains("MainPipe::send"));
        assert!(!binding.contains("REQUEST_HANDLER.lock()"));
        assert!(!binding.contains("IPC.lock()"));
        let origin = compact(include_str!("../../vendor/wry/src/android/origin.rs"));
        assert!(origin.contains("registration:HandlerRegistration"));
        assert!(origin.contains("handlers::current(&self.0.registration)"));
    }

    #[test]
    fn wry_erased_callbacks_remain_serialized_but_http_response_wait_does_not_hold_guard() {
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let handlers = compact(include_str!("../../vendor/wry/src/android/handlers.rs"));
        for cell in [
            "request:Mutex<UnsafeRequestHandler>",
            "ipc:Option<Mutex<UnsafeIpc>>",
            "title:Option<Mutex<UnsafeTitleHandler>>",
            "navigation:Option<Mutex<UnsafeUrlLoadingOverride>>",
            "load:Option<Mutex<UnsafeOnPageLoadHandler>>",
        ] {
            assert!(handlers.contains(cell));
        }
        let android = compact(include_str!("../../vendor/wry/src/android/mod.rs"));
        assert!(!android.contains("unsafeimplSyncfor$type_name"));
        assert!(android.contains("returnSome(rx)"));
        let binding = compact(include_str!("../../vendor/wry/src/android/binding.rs"));
        let call = binding.find("letresponse_receiver={").unwrap();
        let guard = binding[call..]
            .find("registered.handlers.request.lock()")
            .unwrap()
            + call;
        let guard_end = binding[guard..].find("};").unwrap() + guard;
        let wait = binding
            .find("letresponse=response_receiver.and_then")
            .unwrap();
        assert!(call < guard && guard < guard_end && guard_end < wait);
        assert!(binding[guard_end..wait].contains("Noownership-registryorcallback-celllock"));
        assert!(binding[wait..].contains("if!handlers::current(&registered.registration)"));
        let bridge = compact(include_str!("../../vendor/wry/src/android/kotlin/Rust.kt"));
        for entry in [
            "shouldOverride",
            "withAssetLoader",
            "assetLoaderDomain",
            "handleReceivedTitle",
            "onPageLoading",
            "onPageLoaded",
            "isCurrentWebView",
        ] {
            assert!(bridge.contains(&format!("fun{entry}(webView:WebView,")));
        }
        let view = compact(include_str!(
            "../../vendor/wry/src/android/kotlin/RustWebView.kt"
        ));
        assert!(view.contains("if(Rust.isCurrentWebView(this,id)){super.loadData"));
    }

    #[test]
    fn wry_queue_rejection_cancels_exact_work_and_preserves_dormant_configuration() {
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let pipe = compact(include_str!("../../vendor/wry/src/android/main_pipe.rs"));
        assert!(pipe.contains("constQUEUE_CAPACITY:usize=8"));
        assert!(pipe.contains("VecDeque::with_capacity(QUEUE_CAPACITY)"));
        assert!(pipe.contains("QUEUE.lock()"));
        assert!(!pipe.contains("QUEUE.try_lock()"));
        let enqueue = pipe.split("fnenqueue(").nth(1).unwrap();
        assert!(
            enqueue
                .find("letwake_fd=MAIN_PIPE[1].as_raw_fd();")
                .unwrap()
                < enqueue.find("letmutqueue=matchQUEUE.lock()").unwrap()
        );
        assert!(enqueue.contains("queue.len()>=QUEUE_CAPACITY{drop(queue);returnErr("));
        assert!(pipe.contains("libc::O_NONBLOCK|libc::O_CLOEXEC"));
        assert!(pipe.contains("letrejected=queue.pop_back();drop(queue);drop(rejected);"));
        assert!(pipe.contains("letnext=QUEUE.lock().unwrap().pop_front();ifletSome("));
        assert!(pipe.contains("QUEUE_CLOSED.store(true,Ordering::Release)"));
        assert!(pipe.contains("handlers::rollback(&attributes.registration)"));
        assert!(!pipe.contains("CHANNEL.0.send"));
        assert!(!pipe.contains("WebViewMessage::OnDestroy"));
        let android = compact(include_str!("../../vendor/wry/src/android/mod.rs"));
        assert!(android.contains("handlers::prepare_configuration(&origin)"));
        assert!(android.contains("handlers::rollback_configuration(rollback)"));
        assert!(android.contains("handlers::rollback(&registration)"));
        assert!(!android.contains("WEBVIEW_ATTRIBUTES.lock()"));
        let handlers = compact(include_str!("../../vendor/wry/src/android/handlers.rs"));
        assert!(handlers.contains("rollback.candidate.retire()"));
        assert!(handlers.contains("!registry.entries.contains_key(rollback.candidate.label())"));
        assert!(
            handlers.contains(
                "!registry.definitions.contains_key(&rollback.candidate.activity().id())"
            )
        );
        let origin = compact(include_str!("../../vendor/wry/src/android/origin.rs"));
        let exec = origin
            .split("pubfnexec<F>")
            .nth(1)
            .unwrap()
            .split("pubfneval")
            .next()
            .unwrap();
        assert!(exec.contains("MainPipe::send("));
        assert!(!exec.contains("Ok(())"));
    }

    #[test]
    fn wry_initial_bootstrap_wait_is_original_bounded_and_never_used_for_later_gaps() {
        fn compact(source: &str) -> String {
            source
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .replace(",)", ")")
        }
        let activity = compact(include_str!(
            "../../vendor/wry/src/android/kotlin/WryActivity.kt"
        ));
        assert!(
            activity.find("Rust.wryCreate()").unwrap() < activity.find("Rust.create()").unwrap()
        );
        let android = compact(include_str!("../../vendor/wry/src/android/mod.rs"));
        assert!(
            android
                .find("register_activity_proxy(activity_id,")
                .unwrap()
                < android.find("publish_initial_activity(&origin)").unwrap()
        );
        let pipe = compact(include_str!("../../vendor/wry/src/android/main_pipe.rs"));
        assert!(
            pipe.contains("Bootstrap::Registered(WeakActivityOrigin)")
                || pipe.contains("Registered(WeakActivityOrigin)")
        );
        assert!(pipe.contains("if*main_thread==std::thread::current().id(){returnNone;}"));
        assert!(
            pipe.contains("wait_timeout_while(bootstrap,super::MAIN_PIPE_TIMEOUT,|state|matches!(state,Bootstrap::Waiting))")
                || pipe.contains("wait_timeout_while(bootstrap,super::MAIN_PIPE_TIMEOUT,|state|{matches!(state,Bootstrap::Waiting)})")
        );
        assert!(pipe.contains(
            "Bootstrap::Registered(original)=>original.upgrade().filter(activity_origin_current)"
        ));
        assert!(pipe.contains("*bootstrap=Bootstrap::Failed"));
        assert!(
            pipe.contains("Bootstrap::Registered(_)=>{drop(bootstrap);first_activity_origin()")
        );
        assert!(pipe.contains("Self::enqueue(origin.id(),Some(origin),message)"));
    }

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
