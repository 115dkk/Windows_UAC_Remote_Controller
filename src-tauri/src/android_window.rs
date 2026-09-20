// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed main-window attachment, not a command/plugin/service authority surface.
use crate::lifecycle_policy::{AttachmentAction, attachment_action};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tauri::{
    AppHandle, Manager, RunEvent, WindowEvent,
    tao::platform::android::{
        ExistingActivity, ExistingActivityEvent, ExistingActivityObserver,
        observe_existing_activities,
    },
};

#[derive(Default)]
struct WindowLifecycle {
    pending: Mutex<Option<ExistingActivity>>,
    observer: Mutex<Option<ExistingActivityObserver>>,
    queued: AtomicBool,
    dirty: AtomicBool,
    stopped: AtomicBool,
}

pub(crate) fn install(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(WindowLifecycle::default());
    if !app.manage(Arc::clone(&state)) {
        return Err("Android window lifecycle already installed".into());
    }
    let weak = Arc::downgrade(&state);
    let handle = app.clone();
    let observer = observe_existing_activities(move |event| {
        let Some(state) = weak.upgrade() else {
            return;
        };
        if state.stopped.load(Ordering::Acquire) {
            return;
        }
        match event {
            ExistingActivityEvent::Created(activity) => {
                if activity.activity_name() != "MainActivity" || !activity.needs_window() {
                    return;
                }
                let Ok(mut pending) = state.pending.lock() else {
                    return;
                };
                if state.stopped.load(Ordering::Acquire) {
                    return;
                }
                if pending
                    .as_ref()
                    .is_some_and(|old| old.same_instance(&activity))
                {
                    return;
                }
                // Never choose arbitrarily between two live pending Activities.
                if pending
                    .as_ref()
                    .is_some_and(|old| old.is_live() && old.needs_window())
                {
                    return;
                }
                *pending = Some(activity);
            }
            ExistingActivityEvent::Destroyed { activity, .. } => {
                let Ok(mut pending) = state.pending.lock() else {
                    return;
                };
                if pending
                    .as_ref()
                    .is_some_and(|old| old.same_instance(&activity))
                {
                    pending.take();
                }
            }
        }
        state.dirty.store(true, Ordering::Release);
        state.schedule(&handle);
    })?;
    *state
        .observer
        .lock()
        .map_err(|_| "Android window observer unavailable")? = Some(observer);
    Ok(())
}

impl WindowLifecycle {
    fn schedule(self: &Arc<Self>, app: &AppHandle) {
        if self.stopped.load(Ordering::Acquire) || self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        let state = Arc::clone(self);
        let handle = app.clone();
        if app
            .run_on_main_thread(move || {
                state.queued.store(false, Ordering::Release);
                state.advance(&handle);
            })
            .is_err()
        {
            self.queued.store(false, Ordering::Release);
            // Keep the exact pending lease. Only a later actual lifecycle event
            // can progress it; there is no polling, fallback or new Activity.
        }
    }

    fn advance(&self, app: &AppHandle) {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return;
        }
        let activity = {
            let Ok(mut pending) = self.pending.lock() else {
                return;
            };
            let Some(activity) = pending.as_ref() else {
                return;
            };
            match attachment_action(
                self.stopped.load(Ordering::Acquire),
                activity.is_live(),
                activity.needs_window(),
                app.get_webview_window("main").is_some(),
            ) {
                AttachmentAction::Discard => {
                    pending.take();
                    return;
                }
                AttachmentAction::WaitForWindowDestruction => return,
                AttachmentAction::Attach => pending.take().expect("checked pending lease"),
            }
        };
        // This closure executes on the existing Tauri runtime thread. Only the
        // checked main config/local navigation policy is used; no caller input.
        let result = (|| {
            let config = app
                .config()
                .app
                .windows
                .iter()
                .find(|config| config.label == "main")
                .ok_or("fixed main window configuration missing")?;
            tauri::WebviewWindowBuilder::from_config(app, config)?
                .with_existing_android_activity(activity)
                .on_navigation(crate::local_navigation)
                .build()?;
            Ok::<(), Box<dyn std::error::Error>>(())
        })();
        if result.is_err() {
            // A consumed/partially constructed physical generation is never
            // retried or rebound. A later genuine new Activity is a new lease.
            eprintln!("Android exact main-window attachment unavailable");
        }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Ok(mut pending) = self.pending.lock() {
            pending.take();
        }
        if let Ok(mut observer) = self.observer.lock() {
            observer.take();
        }
        self.dirty.store(false, Ordering::Release);
    }
}

pub(crate) fn on_event(app: &AppHandle, event: &RunEvent) {
    let Some(state) = app.try_state::<Arc<WindowLifecycle>>() else {
        return;
    };
    match event {
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::Destroyed,
            ..
        } if label == "main" => {
            // Tauri manager already removed the old logical window. Defer until
            // the runtime finishes its own Destroyed dispatch; no nested build.
            state.dirty.store(true, Ordering::Release);
        }
        RunEvent::MainEventsCleared => {
            // This consumes only a bit set by an actual create/destroy event,
            // not a polling retry or a source of additional attachment permits.
            state.advance(app);
        }
        RunEvent::ExitRequested { code: Some(_), .. } | RunEvent::Exit => state.stop(),
        _ => {}
    }
}
