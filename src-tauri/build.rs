#![forbid(unsafe_code)]

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(&[
        "app_snapshot",
        "save_notification_policy",
        "control_service",
        "begin_pairing",
        "remove_device",
        "decide_request",
        "clear_activity",
        "open_lock_settings",
        "open_notification_settings",
        "open_pairing_scanner",
        "request_details",
        "set_relay",
        "taskbar_offer",
        "request_taskbar_pin",
    ]);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("Tauri application build configuration must be valid");
}
