// SPDX-License-Identifier: GPL-2.0-or-later
//! Compile-only, Windows x64 management-client diagnostics. No authorization
//! decisions depend on this best-effort sink. It never writes product state.
#![forbid(unsafe_code)]

use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::Write,
    os::windows::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use crate::{PairingClientError, PairingPeerError, ServiceError};

const MARKER: &str = "uac-ci-startup-notes-do-not-ship";
const MAX_BYTES: usize = 8192;
// Including the marker, at most 64 lines are emitted per process lifetime.
const MAX_ENTRIES: usize = 63;

macro_rules! stages {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug)]
        pub(crate) enum Stage { $($variant),+ }
        impl Stage {
            const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
        }
    };
}

stages! {
    ExchangeStart => "exchange_start",
    StarterIdentity => "starter_identity",
    HelperIdentity => "helper_identity",
    OwnImpersonation => "own_impersonation",
    OwnSessionId => "own_session_id",
    OwnToken => "own_token",
    OwnTokenRequirement => "own_token_requirement",
    OwnProcessIdentity => "own_process_identity",
    OwnSessionEpoch => "own_session_epoch",
    OwnCleanup => "own_cleanup",
    OwnRecheck => "own_recheck",
    ConnectBudget => "connect_budget",
    ConnectReservation => "connect_reservation",
    ConnectInstallation => "connect_installation",
    ConnectOwnIdentity => "connect_own_identity",
    ConnectScm => "connect_scm",
    ConnectServiceSid => "connect_service_sid",
    ConnectPipeOpen => "connect_pipe_open",
    ConnectPipeSecurity => "connect_pipe_security",
    ConnectPipeIdentity => "connect_pipe_identity",
    ConnectServerOpen => "connect_server_open",
    ConnectServerIdentity => "connect_server_identity",
    ConnectFirstFence => "connect_first_fence",
    ConnectReadMode => "connect_read_mode",
    ConnectFinalFence => "connect_final_fence",
    FenceOwnIdentity => "fence_own_identity",
    FenceClientImage => "fence_client_image",
    FenceScm => "fence_scm",
    FencePipeSecurity => "fence_pipe_security",
    FenceServerIdentity => "fence_server_identity",
    FenceServerImage => "fence_server_image",
    ExchangeConnect => "exchange_connect",
    ExchangeBeginWrite => "exchange_begin_write",
    ExchangePollWrite => "exchange_poll_write",
    ExchangeBeginRead => "exchange_begin_read",
    ExchangePollRead => "exchange_poll_read",
    ExchangeDecode => "exchange_decode",
    ExchangeCleanup => "exchange_cleanup",
    DenyVmRead => "deny_vm_read",
    DenyVmWrite => "deny_vm_write",
    DenyVmOperation => "deny_vm_operation",
    DenyDuplicate => "deny_duplicate",
    DenyTerminate => "deny_terminate",
    DenyCreateThread => "deny_create_thread",
    DenyCreateProcess => "deny_create_process",
    DenySuspend => "deny_suspend",
    DenySetInformation => "deny_set_information",
    DenySetQuota => "deny_set_quota",
    DenyWriteDacl => "deny_write_dacl",
    DenyWriteOwner => "deny_write_owner",
    DenyReadControl => "deny_read_control",
    DenyQueryInformation => "deny_query_information",
    DenyComposite => "deny_composite",
    DenyTokenQuery => "deny_token_query",
    DenyTokenDuplicate => "deny_token_duplicate",
    DenyTokenImpersonate => "deny_token_impersonate",
    DenyTokenAssign => "deny_token_assign",
}

thread_local! { static ACTIVE: Cell<bool> = const { Cell::new(false) }; }

#[derive(Debug)]
pub(crate) struct Scope(bool);
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.set(self.0);
    }
}

pub(crate) fn begin() -> Scope {
    let scope = Scope(ACTIVE.replace(true));
    record(Stage::ExchangeStart, "ok", 0);
    scope
}

pub(crate) fn success(stage: Stage) {
    record(stage, "ok", 0);
}

pub(crate) fn denied_access(stage: Stage) {
    record(stage, "access_denied", 5);
}

pub(crate) fn unexpected_access(stage: Stage) {
    record(stage, "unexpected_grant", 0);
}

struct Sink {
    file: File,
    bytes: usize,
    entries: usize,
    failed: bool,
}

impl Sink {
    fn create() -> Option<Self> {
        let directory = PathBuf::from(std::env::var_os("WEBVIEW2_USER_DATA_FOLDER")?);
        if !directory.is_dir() {
            return None;
        }
        // Exact new leaf only, no mkdir/truncation/append to an existing file.
        // Deny write/delete sharing while retaining the original file owner.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(1)
            .custom_flags(0x0020_0000) // FILE_FLAG_OPEN_REPARSE_POINT.
            .open(directory.join("management-client.txt"))
            .ok()?;
        writeln!(file, "{MARKER}").ok()?;
        Some(Self {
            file,
            bytes: MARKER.len() + 1,
            entries: 0,
            failed: false,
        })
    }
}

fn record(stage: Stage, category: &'static str, code: i64) {
    if !ACTIVE.get() {
        return;
    }
    static SINK: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();
    let Ok(mut guard) = SINK.get_or_init(|| Mutex::new(Sink::create())).try_lock() else {
        return;
    };
    let Some(sink) = guard.as_mut() else {
        return;
    };
    if sink.failed || sink.entries >= MAX_ENTRIES {
        return;
    }
    let line = format!("{} {category} {code}\n", stage.name());
    if sink.bytes + line.len() > MAX_BYTES {
        return;
    }
    if sink.file.write_all(line.as_bytes()).is_err() {
        sink.failed = true;
        return;
    }
    sink.bytes += line.len();
    sink.entries += 1;
}

fn service(error: ServiceError) -> (&'static str, i64) {
    match error {
        ServiceError::WindowsCall { code, .. } => ("service_windows", i64::from(code)),
        ServiceError::ConfigurationConflict => ("service_configuration", 0),
        ServiceError::UntrustedInstallation => ("service_untrusted_installation", 0),
        ServiceError::UnsafePath => ("service_unsafe_path", 0),
        ServiceError::UnsafePermissions => ("service_unsafe_permissions", 0),
        ServiceError::ElevationRequired => ("service_elevation_required", 0),
        ServiceError::NotInstalled => ("service_not_installed", 0),
        ServiceError::UnexpectedState => ("service_unexpected_state", 0),
        _ => ("service_other", i64::from(error.service_diagnostic_code())),
    }
}

pub(crate) fn client<T>(stage: Stage, result: &Result<T, PairingClientError>, success: bool) {
    use PairingClientError as E;
    let (category, code) = match result {
        Ok(_) if success => ("ok", 0),
        Ok(_) => return,
        Err(error) => match *error {
            E::Busy => ("busy", 0),
            E::Closed => ("closed", 0),
            E::InvalidPhase => ("invalid_phase", 0),
            E::InvalidMessage => ("invalid_message", 0),
            E::InvalidDeadline => ("invalid_deadline", 0),
            E::DeadlineElapsed => ("deadline_elapsed", 0),
            E::Cancelled => ("cancelled", 0),
            E::EndOfStream => ("end_of_stream", 0),
            E::Rejected => ("rejected", 0),
            E::Malformed => ("malformed", 0),
            E::CleanupUnconfirmed => ("cleanup_unconfirmed", 0),
            E::Service(error) => service(error),
            E::Native { hresult, .. } => ("native", i64::from(hresult)),
        },
    };
    record(stage, category, code);
}

pub(crate) fn peer<T>(stage: Stage, result: &Result<T, PairingPeerError>) {
    use PairingPeerError as E;
    let Err(error) = result else {
        return;
    };
    let (category, code) = match *error {
        E::Busy => ("busy", 0),
        E::Closed => ("closed", 0),
        E::InvalidPhase => ("invalid_phase", 0),
        E::InvalidMessage => ("invalid_message", 0),
        E::InvalidDeadline => ("invalid_deadline", 0),
        E::DeadlineElapsed => ("deadline_elapsed", 0),
        E::Cancelled => ("cancelled", 0),
        E::EndOfStream => ("end_of_stream", 0),
        E::Rejected => ("rejected", 0),
        E::Malformed => ("malformed", 0),
        E::CleanupUnconfirmed => ("cleanup_unconfirmed", 0),
        E::Service(error) => service(error),
        E::Native { hresult, .. } => ("native", i64::from(hresult)),
    };
    record(stage, category, code);
}
