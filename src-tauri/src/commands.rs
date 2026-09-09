#[cfg(not(target_os = "android"))]
use controller_runtime::AppRuntime;
#[cfg(not(target_os = "android"))]
use std::sync::{Arc, Mutex};

use controller_runtime::{
    AppIssue, AppSnapshot, DecisionIntent, ServiceAction, decode_notification_policy_json,
};

#[derive(Clone)]
pub(crate) struct ControllerState {
    #[cfg(not(target_os = "android"))]
    runtime: Arc<Mutex<Result<AppRuntime, AppIssue>>>,
    admission: crate::admission::CommandAdmission,
}

impl ControllerState {
    #[cfg(not(target_os = "android"))]
    pub(crate) fn new(runtime: Result<AppRuntime, AppIssue>) -> Self {
        Self {
            runtime: Arc::new(Mutex::new(runtime)),
            admission: Default::default(),
        }
    }
    #[cfg(target_os = "android")]
    pub(crate) fn android() -> Self {
        Self {
            admission: Default::default(),
        }
    }
}

pub(crate) const fn storage_issue() -> AppIssue {
    AppIssue {
        code: "app_storage_unavailable",
        message: "앱 설정을 열지 못했어요.",
        next_action: Some("앱을 닫고 다시 열어 주세요."),
    }
}

const fn worker_issue() -> AppIssue {
    AppIssue {
        code: "app_worker_unavailable",
        message: "요청한 작업을 마치지 못했어요.",
        next_action: Some("현재 상태를 새로 확인해 주세요."),
    }
}

pub(crate) const fn busy_issue() -> AppIssue {
    AppIssue {
        code: "app_busy",
        message: "앞서 요청한 작업이 아직 끝나지 않았어요.",
        next_action: Some("작업이 끝난 뒤 다시 시도해 주세요."),
    }
}

fn check_identifier(identifier: &str) -> Result<(), AppIssue> {
    if identifier.is_empty() || identifier.len() > 128 {
        return Err(AppIssue {
            code: "invalid_request_identifier",
            message: "요청 정보를 읽지 못했어요.",
            next_action: Some("현재 상태를 새로 확인해 주세요."),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
async fn with_runtime<T: Send + 'static>(
    state: &ControllerState,
    operation: impl FnOnce(&mut AppRuntime) -> Result<T, AppIssue> + Send + 'static,
) -> Result<T, AppIssue> {
    // Reject before spawning: there is no unbounded waiting work/string queue.
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    let runtime = Arc::clone(&state.runtime);
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        let mut guard = runtime.lock().map_err(|_| worker_issue())?;
        match &mut *guard {
            Ok(runtime) => operation(runtime),
            Err(issue) => Err(*issue),
        }
    })
    .await
    .map_err(|_| worker_issue())?
}

#[cfg(target_os = "android")]
async fn with_android_owner(
    app: tauri::AppHandle,
    state: &ControllerState,
    operation: crate::mobile::OwnerOperation,
) -> Result<AppSnapshot, AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::policy_snapshot(&app, operation)
    })
    .await
    .map_err(|_| worker_issue())?
}

#[tauri::command]
pub(crate) async fn app_snapshot(
    app: tauri::AppHandle,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(target_os = "android")]
    {
        with_android_owner(app, &state, crate::mobile::OwnerOperation::Read).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        with_runtime(&state, |runtime| Ok(runtime.snapshot())).await
    }
}

#[tauri::command]
pub(crate) async fn save_notification_policy(
    app: tauri::AppHandle,
    policy_json: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    let policy = decode_notification_policy_json(policy_json.as_bytes())?;
    #[cfg(target_os = "android")]
    {
        let canonical = serde_json::to_string(&policy).map_err(|_| worker_issue())?;
        with_android_owner(
            app,
            &state,
            crate::mobile::OwnerOperation::SavePolicy(canonical),
        )
        .await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        with_runtime(&state, move |runtime| runtime.save_policy(policy)).await
    }
}

#[tauri::command]
pub(crate) async fn control_service(
    action: ServiceAction,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, move |runtime| runtime.control_service(action)).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = (state, action);
        Err(controller_runtime::PlatformError::Unsupported.into())
    }
}

#[tauri::command]
pub(crate) async fn begin_pairing(
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, |runtime| runtime.begin_pairing()).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        Err(controller_runtime::UnwiredCapability::Pairing.issue())
    }
}

#[tauri::command]
pub(crate) async fn remove_device(
    device_id: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    check_identifier(&device_id)?;
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, move |runtime| runtime.remove_device(&device_id)).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        Err(controller_runtime::UnwiredCapability::Unpairing.issue())
    }
}

#[tauri::command]
pub(crate) async fn decide_request(
    request_id: String,
    decision: DecisionIntent,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    check_identifier(&request_id)?;
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, move |runtime| runtime.decide(&request_id, decision)).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = (state, decision);
        Err(controller_runtime::UnwiredCapability::Decisions.issue())
    }
}

#[tauri::command]
pub(crate) async fn clear_activity(
    app: tauri::AppHandle,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        with_runtime(&state, |runtime| runtime.clear_activity()).await
    }
    #[cfg(target_os = "android")]
    {
        with_android_owner(app, &state, crate::mobile::OwnerOperation::ClearHistory).await
    }
}

#[tauri::command]
pub(crate) async fn open_lock_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::open_lock_settings(&app)
    })
    .await
    .map_err(|_| worker_issue())?
}

#[tauri::command]
pub(crate) async fn open_notification_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::open_notification_settings(&app)
    })
    .await
    .map_err(|_| worker_issue())?
}
