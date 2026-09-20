// SPDX-License-Identifier: GPL-2.0-or-later
//! Disposable CI pre-authorization probe. Read one genuine Starter Offer, then
//! cancel/drain the original owner. Never launch a helper or return Offer bytes.
use crate::{PairingClient, PairingClientError, PairingClientProgress, pairing_handoff::Frame};
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

pub fn run() {
    if std::env::var_os("UAC_LAB_PAIRING_OFFER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let Some(directory) = std::env::var_os("WEBVIEW2_USER_DATA_FOLDER") else {
        return;
    };
    let Ok(mut output) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PathBuf::from(directory).join("pairing-offer.txt"))
    else {
        return;
    };
    let _ = writeln!(output, "uac-ci-startup-notes-do-not-ship");
    let result = probe(&mut output);
    match result {
        Ok(()) => {
            let _ = writeln!(output, "offer_received_and_drained");
        }
        Err(PairingClientError::Native { stage, hresult }) => {
            let _ = writeln!(output, "native {stage:?} {hresult}");
        }
        Err(error) => {
            let _ = writeln!(output, "failure {error:?}");
        }
    }
}

fn probe(output: &mut impl Write) -> Result<(), PairingClientError> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    let mut client = PairingClient::connect_starter(started, deadline)?;
    let _ = writeln!(output, "starter_connected");
    let result = (|| {
        client.begin_read()?;
        while Instant::now() < deadline {
            match client.poll()? {
                PairingClientProgress::Pending => thread::sleep(Duration::from_millis(25)),
                PairingClientProgress::Read(bytes) => {
                    return if matches!(Frame::decode(&bytes), Ok(Frame::Offer(_))) {
                        Ok(())
                    } else {
                        Err(PairingClientError::InvalidMessage)
                    };
                }
                _ => return Err(PairingClientError::InvalidPhase),
            }
        }
        Err(PairingClientError::DeadlineElapsed)
    })();
    client.cancel();
    while !client.drain()? {
        if Instant::now() >= deadline {
            return Err(PairingClientError::CleanupUnconfirmed);
        }
        thread::sleep(Duration::from_millis(25));
    }
    result
}

/// Fixed, payload-free native error graph; one new leaf per disposable process.
pub(crate) fn launch_failure(error: crate::PairingLaunchError) {
    if std::env::var_os("UAC_LAB_PAIRING_OFFER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let Some(directory) = std::env::var_os("WEBVIEW2_USER_DATA_FOLDER") else {
        return;
    };
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PathBuf::from(directory).join("pairing-launch-failure.txt"))
    {
        let _ = writeln!(file, "uac-ci-startup-notes-do-not-ship\n{error:?}");
    }
}
