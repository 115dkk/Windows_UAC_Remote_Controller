// SPDX-License-Identifier: GPL-2.0-or-later
//! Presentation-only Windows integration. These commands cannot select another
//! app, write a registry value, invoke an installer, or request elevation.

#[derive(serde::Serialize)]
pub(crate) struct TaskbarOffer {
    version: Option<String>,
    status: &'static str,
}

#[cfg(windows)]
mod desktop {
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tauri::Manager;

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    pub(super) struct Lease;
    impl Lease {
        pub(super) fn enter() -> Result<Self, &'static str> {
            ACTIVE
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| Self)
                .map_err(|_| "taskbar_busy")
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            ACTIVE.store(false, Ordering::Release);
        }
    }

    pub(super) fn status(value: windows_service_host::TaskbarStatus) -> &'static str {
        use windows_service_host::TaskbarStatus;
        match value {
            TaskbarStatus::Hidden => "hidden",
            TaskbarStatus::Available => "available",
            TaskbarStatus::Pinned => "pinned",
            TaskbarStatus::Unavailable => "unavailable",
            TaskbarStatus::Declined => "declined",
        }
    }

    pub(super) async fn on_ui_thread<T: Send + 'static>(
        app: tauri::AppHandle,
        operation: fn() -> Pin<Box<dyn Future<Output = T> + Send>>,
    ) -> Result<T, &'static str> {
        let (sender, mut receiver) = tauri::async_runtime::channel(1);
        let owner = app.clone();
        app.run_on_main_thread(move || {
            let focused = owner
                .get_webview_window("main")
                .and_then(|window| window.is_focused().ok())
                .unwrap_or(false);
            let result = if focused {
                Ok(operation())
            } else {
                Err("taskbar_foreground_required")
            };
            let _ = sender.try_send(result);
        })
        .map_err(|_| "taskbar_unavailable")?;
        let future = receiver.recv().await.ok_or("taskbar_unavailable")??;
        Ok(future.await)
    }
}

#[tauri::command]
pub(crate) async fn taskbar_offer(app: tauri::AppHandle) -> Result<TaskbarOffer, &'static str> {
    #[cfg(windows)]
    {
        let _lease = desktop::Lease::enter()?;
        let offer = desktop::on_ui_thread(app, windows_service_host::begin_taskbar_offer).await?;
        Ok(TaskbarOffer {
            version: offer.version,
            status: desktop::status(offer.status),
        })
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Ok(TaskbarOffer {
            version: None,
            status: "hidden",
        })
    }
}

#[tauri::command]
pub(crate) async fn request_taskbar_pin(
    app: tauri::AppHandle,
) -> Result<&'static str, &'static str> {
    #[cfg(windows)]
    {
        let _lease = desktop::Lease::enter()?;
        desktop::on_ui_thread(app, windows_service_host::begin_taskbar_pin)
            .await
            .map(desktop::status)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        Ok("unavailable")
    }
}
