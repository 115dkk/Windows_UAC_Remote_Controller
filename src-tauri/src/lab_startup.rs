// SPDX-License-Identifier: GPL-2.0-or-later
//! Compiled only for the disposable Windows lab. Fixed startup milestones, no
//! request data or authority. The launcher owns a fresh private WebView folder.
use std::{fs::OpenOptions, io::Write, path::PathBuf};

mod pairing_offer;
pub(crate) use pairing_offer::run as probe_pairing_offer;

pub(crate) fn note(stage: &'static str) {
    let Some(directory) = std::env::var_os("WEBVIEW2_USER_DATA_FOLDER") else {
        return;
    };
    let path = PathBuf::from(directory).join("controller-startup.txt");
    // Never create the caller-selected directory, truncate an existing file,
    // or recover/reset application storage. Missing evidence stays unknown.
    let file = if stage == "run_enter" {
        OpenOptions::new().write(true).create_new(true).open(path)
    } else {
        OpenOptions::new().append(true).open(path)
    };
    if let Ok(mut file) = file {
        if stage == "run_enter" {
            let _ = writeln!(file, "uac-ci-startup-notes-do-not-ship");
        }
        let _ = writeln!(file, "{stage}");
    }
}
