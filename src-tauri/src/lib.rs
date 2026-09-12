//! Thin native shell. Persistence and command semantics live in controller-runtime.
#![forbid(unsafe_code)]

mod admission;
#[cfg(target_os = "android")]
mod android_window;
mod commands;
mod language;
mod lifecycle_policy;
mod mobile;
mod taskbar;

#[cfg(not(target_os = "android"))]
use controller_runtime::{AppIssue, AppPrivateDirectory, AppRuntime, Platform, PlatformAdapter};
use tauri::Manager;

#[cfg(not(target_os = "android"))]
fn native_platform() -> Platform {
    if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Unsupported
    }
}

#[cfg(not(target_os = "android"))]
fn initialize_runtime(app: &tauri::AppHandle) -> Result<AppRuntime, AppIssue> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| commands::storage_issue())?;
    // The native shell chooses this package-specific path, never an IPC argument.
    std::fs::create_dir_all(&directory).map_err(|_| commands::storage_issue())?;
    let directory = AppPrivateDirectory::from_native_app_data(directory).map_err(AppIssue::from)?;
    #[cfg(windows)]
    let adapter: Box<dyn PlatformAdapter> = Box::new(controller_runtime::WindowsPlatformAdapter);
    #[cfg(not(windows))]
    let adapter: Box<dyn PlatformAdapter> =
        Box::new(controller_runtime::UnavailablePlatformAdapter);
    // No environment-supplied machine identity. Until the native device owner
    // supplies a verified display name, the UI uses its neutral "this PC" label.
    AppRuntime::open(directory, native_platform(), None, adapter)
}

fn local_navigation(url: &tauri::Url) -> bool {
    match (url.scheme(), url.host_str()) {
        ("tauri", Some("localhost")) => {
            url.port().is_none() && url.username().is_empty() && url.password().is_none()
        }
        ("http" | "https", Some("tauri.localhost")) => {
            url.port().is_none() && url.username().is_empty() && url.password().is_none()
        }
        ("http", Some("127.0.0.1")) if cfg!(debug_assertions) => url.port() == Some(1420),
        _ => false,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(mobile::init())
        .setup(|app| {
            // Shell integration is optional. A failure disables the taskbar
            // request, not the approval app; this is never called by the service.
            #[cfg(windows)]
            let _ = windows_service_host::initialize_desktop_shell_identity();
            // A failed runtime is kept as an explicit error, not replaced by
            // successful default state. The UI can render the real failure.
            #[cfg(not(target_os = "android"))]
            app.manage(commands::ControllerState::new(initialize_runtime(
                app.handle(),
            )));
            // Android's Application owns the only durable Rust policy store.
            // Never open the old AppRuntime/policy writer from an Activity.
            #[cfg(target_os = "android")]
            {
                app.manage(commands::ControllerState::android());
                android_window::install(app.handle())?;
            }
            #[cfg(not(target_os = "android"))]
            {
                let config = app
                    .config()
                    .app
                    .windows
                    .first()
                    .ok_or("missing main window configuration")?;
                tauri::WebviewWindowBuilder::from_config(app, config)?
                    .on_navigation(local_navigation)
                    .build()?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_snapshot,
            language::get_language,
            language::set_language,
            commands::save_notification_policy,
            commands::control_service,
            commands::begin_pairing,
            commands::open_pairing_scanner,
            commands::remove_device,
            commands::set_relay,
            taskbar::taskbar_offer,
            taskbar::request_taskbar_pin,
            commands::decide_request,
            commands::request_details,
            commands::clear_activity,
            commands::open_lock_settings,
            commands::open_notification_settings,
        ])
        .build(tauri::generate_context!())
        .expect("native application host could not run");

    app.run(|_app, event| {
        #[cfg(windows)]
        if matches!(&event, tauri::RunEvent::Exit) {
            windows_service_host::shutdown_desktop_shell();
        }
        #[cfg(target_os = "android")]
        android_window::on_event(_app, &event);
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event
            && lifecycle_policy::prevent_implicit_exit(cfg!(target_os = "android"), code)
        {
            // Finishing the last Android Activity must not call process::exit
            // on the Application-owned foreground service/Rust policy owner.
            // Android retains process-lifetime authority; explicit Tauri exit
            // and restart still follow their original path on every platform.
            api.prevent_exit();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::local_navigation;
    #[test]
    fn only_local_application_origins_may_navigate() {
        for allowed in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
        ] {
            assert!(local_navigation(&allowed.parse().unwrap()));
        }
        for denied in [
            "https://example.com/",
            "file:///C:/Windows/",
            "https://tauri.localhost.example.com/",
            "http://127.0.0.1:9000/",
            "http://tauri.localhost:9000/",
            "tauri://localhost:1234/",
            "https://user@tauri.localhost/",
        ] {
            assert!(!local_navigation(&denied.parse().unwrap()));
        }
    }
}
