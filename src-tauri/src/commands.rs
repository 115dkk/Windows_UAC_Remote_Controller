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
    origin: crate::mobile::CommandOrigin,
    state: &ControllerState,
    operation: crate::mobile::OwnerOperation,
) -> Result<AppSnapshot, AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::policy_snapshot(&app, &origin, operation)
    })
    .await
    .map_err(|_| worker_issue())?
}

#[tauri::command]
pub(crate) async fn app_snapshot(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(target_os = "android")]
    {
        with_android_owner(app, origin, &state, crate::mobile::OwnerOperation::Read).await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, |runtime| Ok(runtime.snapshot())).await
    }
}

#[tauri::command]
pub(crate) async fn save_notification_policy(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    policy_json: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    let policy = decode_notification_policy_json(policy_json.as_bytes())?;
    #[cfg(target_os = "android")]
    {
        let canonical = serde_json::to_string(&policy).map_err(|_| worker_issue())?;
        with_android_owner(
            app,
            origin,
            &state,
            crate::mobile::OwnerOperation::SavePolicy(canonical),
        )
        .await
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, move |runtime| runtime.save_policy(policy)).await
    }
}

#[tauri::command]
pub(crate) async fn control_service(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    action: ServiceAction,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, move |runtime| runtime.control_service(action)).await
    }
    #[cfg(target_os = "android")]
    {
        with_android_owner(
            app,
            origin,
            &state,
            crate::mobile::OwnerOperation::ControlService(action),
        )
        .await
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
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    check_identifier(&device_id)?;
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, move |runtime| runtime.remove_device(&device_id)).await
    }
    #[cfg(target_os = "android")]
    {
        with_android_owner(
            app,
            origin,
            &state,
            crate::mobile::OwnerOperation::RemovePeer(device_id),
        )
        .await
    }
}

#[tauri::command]
pub(crate) async fn begin_pairing_usb(
    _arguments: crate::mobile::ScannerArguments,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, |runtime| runtime.begin_pairing_usb()).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        Err(controller_runtime::UnwiredCapability::Pairing.issue())
    }
}

#[tauri::command]
pub(crate) async fn set_relay(
    address: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    if address.is_empty() || address.len() > 80 {
        return Err(AppIssue {
            code: "invalid_relay_address",
            message: "중계 서버 주소를 숫자 IP 주소와 포트로 입력해 주세요.",
            next_action: Some("예: 192.0.2.10:443 또는 [2001:db8::10]:443"),
        });
    }
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, move |runtime| runtime.set_relay(&address)).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = state;
        Err(controller_runtime::PlatformError::Unsupported.into())
    }
}

/// One of three strict JSON shapes, validated with the service's rules before
/// any elevation; the elevated CLI and the service validate it again.
#[tauri::command]
pub(crate) async fn set_external_access(
    access_json: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    let access = controller_runtime::decode_external_access_json(access_json.as_bytes())?;
    #[cfg(not(target_os = "android"))]
    {
        with_runtime(&state, move |runtime| runtime.set_external_access(access)).await
    }
    #[cfg(target_os = "android")]
    {
        let _ = (state, access);
        Err(controller_runtime::PlatformError::Unsupported.into())
    }
}

#[tauri::command]
pub(crate) async fn decide_request(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    request_id: String,
    decision: DecisionIntent,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    check_identifier(&request_id)?;
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, move |runtime| runtime.decide(&request_id, decision)).await
    }
    #[cfg(target_os = "android")]
    {
        controller_runtime::check_request_locator(&request_id)?;
        with_android_owner(
            app,
            origin,
            &state,
            crate::mobile::OwnerOperation::Decide(request_id, decision),
        )
        .await
    }
}

#[tauri::command]
pub(crate) async fn request_details(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    request_id: String,
    state: tauri::State<'_, ControllerState>,
) -> Result<controller_runtime::RequestDetailsView, AppIssue> {
    controller_runtime::check_request_locator(&request_id)?;
    #[cfg(target_os = "android")]
    {
        let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
        tauri::async_runtime::spawn_blocking(move || {
            let _lease = lease;
            crate::mobile::request_details(&app, &origin, request_id)
        })
        .await
        .map_err(|_| worker_issue())?
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, state, origin);
        Err(controller_runtime::phone_request_issue())
    }
}

#[tauri::command]
pub(crate) async fn clear_activity(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    state: tauri::State<'_, ControllerState>,
) -> Result<AppSnapshot, AppIssue> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, origin);
        with_runtime(&state, |runtime| runtime.clear_activity()).await
    }
    #[cfg(target_os = "android")]
    {
        with_android_owner(
            app,
            origin,
            &state,
            crate::mobile::OwnerOperation::ClearHistory,
        )
        .await
    }
}

#[tauri::command]
pub(crate) async fn open_diagnostics_folder(
    state: tauri::State<'_, ControllerState>,
) -> Result<(), DiagnosticFolderIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        #[cfg(windows)]
        let (opened, native_stage, native_code) =
            match windows_service_host::open_diagnostics_folder() {
                Ok(()) => (true, None, None),
                Err(windows_service_host::ServiceError::DiagnosticsFolderFailure {
                    stage,
                    detail,
                }) => (false, Some(stage), Some(detail)),
                Err(_) => (false, None, None),
            };
        #[cfg(not(windows))]
        let (opened, native_stage, native_code) = (false, None, None);
        if opened {
            return Ok(());
        }
        Err(DiagnosticFolderIssue {
            issue: AppIssue {
                code: "diagnostics_folder_unavailable",
                message: "로그 폴더를 열지 못했습니다. 설치 상태와 폴더 접근 권한을 확인하십시오.",
                next_action: None,
            },
            native_stage,
            native_code,
        })
    })
    .await
    .map_err(|_| DiagnosticFolderIssue::from(worker_issue()))?
}

/// Closed operation stage and numeric OS code only; never native text or paths.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticFolderIssue {
    #[serde(flatten)]
    issue: AppIssue,
    native_stage: Option<u8>,
    native_code: Option<u32>,
}
impl From<AppIssue> for DiagnosticFolderIssue {
    fn from(issue: AppIssue) -> Self {
        Self {
            issue,
            native_stage: None,
            native_code: None,
        }
    }
}

#[tauri::command]
pub(crate) async fn open_lock_settings(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::open_lock_settings(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}

#[tauri::command]
pub(crate) async fn open_notification_settings(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::open_notification_settings(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}

/// Saves only the app's bounded closed Android diagnostics to user-visible
/// Downloads and opens the system Sharesheet. No path or log payload comes from JS.
#[tauri::command]
pub(crate) async fn export_android_diagnostics(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    _arguments: crate::mobile::EmptyArguments,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::export_android_diagnostics(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}

/// Opens Android's document picker and saves closed diagnostics to its result.
/// No renderer-selected path, URI, contents or service authority is accepted.
#[tauri::command]
pub(crate) async fn save_android_diagnostics(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    _arguments: crate::mobile::EmptyArguments,
    state: tauri::State<'_, ControllerState>,
) -> Result<crate::mobile::DiagnosticSaveOutcome, AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::save_android_diagnostics(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}

#[tauri::command]
pub(crate) async fn open_pairing_scanner(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    _arguments: crate::mobile::ScannerArguments,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        // Released on the native Dialog's opened/busy/unavailable reply, not on
        // camera completion. No QR, key, expected tuple or result body returns.
        crate::mobile::open_pairing_scanner(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}

/// Fixed native USB input surface; accepts no invitation, path or peer from JS.
#[tauri::command]
pub(crate) async fn open_pairing_usb(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    _arguments: crate::mobile::ScannerArguments,
    state: tauri::State<'_, ControllerState>,
) -> Result<(), AppIssue> {
    let lease = state.admission.try_enter().ok_or_else(busy_issue)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _lease = lease;
        crate::mobile::open_pairing_usb(&app, &origin)
    })
    .await
    .map_err(|_| worker_issue())?
}
