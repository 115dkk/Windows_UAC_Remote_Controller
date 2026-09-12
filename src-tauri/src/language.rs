// SPDX-License-Identifier: GPL-2.0-or-later
//! Presentation-only language preference. No path, registry key, command or
//! authorization value is accepted from a caller.
use controller_runtime::AppIssue;
use presentation_i18n::LanguageSettings;

fn issue() -> AppIssue {
    AppIssue {
        code: "language_unavailable",
        message: "언어 설정을 저장하지 못했어요. 다시 시도해 주세요.",
        next_action: None,
    }
}

fn update_title(app: &tauri::AppHandle, settings: &LanguageSettings) {
    #[cfg(not(target_os = "android"))]
    {
        use tauri::Manager;
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_title(presentation_i18n::tr(
                settings.effective_locale(),
                "UAC 원격 승인",
            ));
        }
    }
    #[cfg(target_os = "android")]
    let _ = (app, settings);
}

#[tauri::command]
pub(crate) async fn get_language(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
) -> Result<LanguageSettings, AppIssue> {
    let owner = app.clone();
    let settings = tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "android")]
        {
            crate::mobile::language_settings(&owner, &origin, None)
        }
        #[cfg(windows)]
        {
            let _ = (owner, origin);
            windows_service_host::get_language_settings().map_err(|_| issue())
        }
        #[cfg(not(any(windows, target_os = "android")))]
        {
            let _ = (owner, origin);
            Err(issue())
        }
    })
    .await
    .map_err(|_| issue())??;
    update_title(&app, &settings);
    Ok(settings)
}

#[tauri::command]
pub(crate) async fn set_language(
    app: tauri::AppHandle,
    origin: crate::mobile::CommandOrigin,
    language: String,
) -> Result<LanguageSettings, AppIssue> {
    if !presentation_i18n::valid_preference(&language) {
        return Err(issue());
    }
    let owner = app.clone();
    let settings = tauri::async_runtime::spawn_blocking(move || {
        #[cfg(target_os = "android")]
        {
            crate::mobile::language_settings(&owner, &origin, Some(language))
        }
        #[cfg(windows)]
        {
            let _ = (owner, origin);
            windows_service_host::set_language_preference(&language).map_err(|_| issue())
        }
        #[cfg(not(any(windows, target_os = "android")))]
        {
            let _ = (owner, origin, language);
            Err(issue())
        }
    })
    .await
    .map_err(|_| issue())??;
    update_title(&app, &settings);
    Ok(settings)
}
