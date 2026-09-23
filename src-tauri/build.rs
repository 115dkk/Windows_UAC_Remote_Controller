#![forbid(unsafe_code)]

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "app_snapshot",
        "get_language",
        "set_language",
        "save_notification_policy",
        "control_service",
        "begin_pairing",
        "begin_pairing_usb",
        "remove_device",
        "decide_request",
        "clear_activity",
        "open_diagnostics_folder",
        "open_lock_settings",
        "open_notification_settings",
        "export_android_diagnostics",
        "save_android_diagnostics",
        "open_pairing_scanner",
        "open_pairing_usb",
        "request_details",
        "set_relay",
        "set_external_access",
        "taskbar_offer",
        "request_taskbar_pin",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("Tauri application build configuration must be valid");
}
