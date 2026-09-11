// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed Windows pairing owner. Native clients and helper launch stay on one thread.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use windows_service_host::{
    PairingClient, PairingClientError, PairingHelperLaunch, PairingLaunchError,
    PairingLaunchProgress, ServiceError, ServiceOperation,
};

use crate::{PairingAttemptHandle, PairingFailure, PairingStarter, PairingUiPhase, PairingUiState};

const ATTEMPT_LIFETIME: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsPairingStarter;

impl PairingStarter for WindowsPairingStarter {
    fn available(&self) -> bool {
        true
    }

    fn start(&self) -> Result<Box<dyn PairingAttemptHandle>, PairingFailure> {
        let started_at = Instant::now();
        let state = Arc::new(Mutex::new(PairingUiState::connecting(started_at)));
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_state = Arc::clone(&state);
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("ui-pairing-starter".to_owned())
            .spawn(move || run_attempt(worker_state, worker_cancelled, started_at))
            .map_err(|_| PairingFailure::Unavailable)?;
        Ok(Box::new(WindowsPairingAttempt {
            state,
            cancelled,
            worker: Some(worker),
        }))
    }
}

struct WindowsPairingAttempt {
    state: Arc<Mutex<PairingUiState>>,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for WindowsPairingAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsPairingAttempt")
            .finish_non_exhaustive()
    }
}

impl PairingAttemptHandle for WindowsPairingAttempt {
    fn state(&self) -> PairingUiState {
        self.state.lock().map(|state| *state).unwrap_or_else(|_| {
            let now = Instant::now();
            PairingUiState::failure(PairingFailure::Unavailable, now, now)
        })
    }

    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn join_until(&mut self, deadline: Instant) -> bool {
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                publish_failure(&self.state, PairingFailure::Unavailable);
                return false;
            }
            thread::sleep(POLL_INTERVAL.min(remaining));
        }
        match self.worker.take() {
            Some(worker) => worker.join().is_ok(),
            None => true,
        }
    }
}

fn run_attempt(state: Arc<Mutex<PairingUiState>>, cancelled: Arc<AtomicBool>, started_at: Instant) {
    let Some(deadline) = started_at.checked_add(ATTEMPT_LIFETIME) else {
        publish_failure(&state, PairingFailure::Unavailable);
        return;
    };
    let client = match PairingClient::connect_starter(started_at, deadline) {
        Ok(client) => client,
        Err(error) => {
            publish_failure(&state, map_client_error(error));
            return;
        }
    };
    // PairingHelperLaunch::from_starter owns the Offer read. Reading it through
    // PairingClient first marks the protocol used and makes this transfer invalid.
    // The UI owner therefore never decodes or copies Offer bytes.
    let mut launch = match client.into_helper_launch() {
        Ok(launch) => launch,
        Err(error) => {
            publish_failure(&state, map_launch_error(error));
            return;
        }
    };
    let mut outcome: Option<Result<(), PairingFailure>> = None;
    let mut helper_running = false;
    while outcome.is_none() && Instant::now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            launch.cancel();
            outcome = Some(Err(PairingFailure::Unavailable));
            break;
        }
        if !helper_running {
            // poll may synchronously enter ShellExecuteExW after its internal Offer
            // read. There is no native progress event immediately before that call.
            // Publish before the first poll that can enter it. This may replace the
            // connecting message one poll before the Offer actually completes.
            publish_phase(&state, PairingUiPhase::WaitingForAdmin);
        }
        match launch.poll() {
            Ok(PairingLaunchProgress::Pending) => {}
            Ok(
                PairingLaunchProgress::BindingWritten
                | PairingLaunchProgress::Bound
                | PairingLaunchProgress::Closing
                | PairingLaunchProgress::CleanupPending,
            ) => {
                helper_running = true;
                publish_phase(&state, PairingUiPhase::HelperRunning);
            }
            Ok(PairingLaunchProgress::Closed) => outcome = Some(Ok(())),
            Err(error) => {
                outcome = Some(Err(map_launch_error(error)));
                launch.cancel();
            }
        }
        if outcome.is_none() {
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
    let mut outcome = outcome.unwrap_or(Err(PairingFailure::Timeout));
    if Instant::now() >= deadline {
        launch.cancel();
        outcome = Err(PairingFailure::Timeout);
    }
    if !drain_until(&mut launch, deadline) || launch.cleanup_failure().is_some() {
        outcome = Err(if Instant::now() >= deadline {
            PairingFailure::Timeout
        } else {
            PairingFailure::Unavailable
        });
    } else if outcome.is_ok()
        && (launch.first_failure().is_some()
            || !launch.is_drained()
            || launch.cleanup_failure().is_some())
    {
        outcome = Err(PairingFailure::Unavailable);
    }
    match outcome {
        Ok(()) => publish_finished(&state),
        Err(failure) => publish_failure(&state, failure),
    }
}

fn drain_until(launch: &mut PairingHelperLaunch, deadline: Instant) -> bool {
    loop {
        match launch.drain() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => return false,
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn map_launch_error(error: PairingLaunchError) -> PairingFailure {
    match error {
        PairingLaunchError::Client(PairingClientError::DeadlineElapsed) => PairingFailure::Timeout,
        PairingLaunchError::Client(error) => map_client_error(error),
        PairingLaunchError::UserCancelled => PairingFailure::UserCancelled,
        PairingLaunchError::HelperExited { .. } => PairingFailure::HelperFailed,
        PairingLaunchError::Native {
            operation: ServiceOperation::LaunchElevatedHelper,
            ..
        } => PairingFailure::HelperFailed,
        PairingLaunchError::Protocol
        | PairingLaunchError::InvalidPhase
        | PairingLaunchError::LaunchUnconfirmed
        | PairingLaunchError::Cancelled
        | PairingLaunchError::CleanupUnconfirmed
        | PairingLaunchError::Native { .. } => PairingFailure::Unavailable,
    }
}

fn map_client_error(error: PairingClientError) -> PairingFailure {
    match error {
        PairingClientError::DeadlineElapsed => PairingFailure::Timeout,
        PairingClientError::Service(error) => map_service_error(error),
        PairingClientError::Native {
            stage: windows_service_host::PairingClientStage::Connect,
            ..
        } => PairingFailure::ServiceNotReady,
        PairingClientError::Busy
        | PairingClientError::Closed
        | PairingClientError::InvalidPhase
        | PairingClientError::InvalidMessage
        | PairingClientError::InvalidDeadline
        | PairingClientError::Cancelled
        | PairingClientError::EndOfStream
        | PairingClientError::Rejected
        | PairingClientError::Malformed
        | PairingClientError::CleanupUnconfirmed
        | PairingClientError::Native { .. } => PairingFailure::Unavailable,
    }
}

#[allow(clippy::too_many_lines)]
fn map_service_error(error: ServiceError) -> PairingFailure {
    match error {
        ServiceError::NotInstalled
        | ServiceError::ServiceStopped
        | ServiceError::UnexpectedState
        | ServiceError::PairingHandoffUnavailable => PairingFailure::ServiceNotReady,
        ServiceError::Timeout => PairingFailure::Timeout,
        ServiceError::UnsupportedPlatform
        | ServiceError::InvalidArguments
        | ServiceError::ElevationRequired
        | ServiceError::WindowsCall { .. }
        | ServiceError::UnsupportedResult(_)
        | ServiceError::ConfigurationConflict
        | ServiceError::UntrustedInstallation
        | ServiceError::UnsafePath
        | ServiceError::UnsafePermissions
        | ServiceError::InstallationIncomplete { .. }
        | ServiceError::JournalProvisioningRequired
        | ServiceError::JournalUnavailable
        | ServiceError::RegistryProvisioningRequired
        | ServiceError::RegistryUnavailable
        | ServiceError::RegistryMaintenanceRequired
        | ServiceError::IdentityUnavailable
        | ServiceError::IdentityPolicy(_)
        | ServiceError::IdentityWindows { .. }
        | ServiceError::IdentityMalformed(_)
        | ServiceError::IdentityEncoding { .. }
        | ServiceError::IdentityKeyAlreadyExists
        | ServiceError::IdentityKeyNotFound
        | ServiceError::IdentityCreationUncertain { .. }
        | ServiceError::IdentityCleanupFailed { .. }
        | ServiceError::IdentityHandleAlreadyReleased
        | ServiceError::StartupFailure { .. }
        | ServiceError::InvalidClock
        | ServiceError::WorkerFailed
        | ServiceError::AlreadyDispatched
        | ServiceError::OutputUnavailable
        | ServiceError::ProbeBusy
        | ServiceError::ProbeSlotsFull
        | ServiceError::ProbeUnavailable
        | ServiceError::ManagementRefused
        | ServiceError::PairingClientNative { .. }
        | ServiceError::RendererNative { .. } => PairingFailure::Unavailable,
    }
}

fn publish_phase(state: &Mutex<PairingUiState>, phase: PairingUiPhase) {
    if let Ok(mut state) = state.lock()
        && state.terminal_at.is_none()
    {
        let started_at = state.started_at;
        *state = PairingUiState::running(phase, started_at);
    }
}

fn publish_finished(state: &Mutex<PairingUiState>) {
    if let Ok(mut state) = state.lock() {
        let started_at = state.started_at;
        *state = PairingUiState::finished(started_at, Instant::now());
    }
}

fn publish_failure(state: &Mutex<PairingUiState>, failure: PairingFailure) {
    if let Ok(mut state) = state.lock() {
        let started_at = state.started_at;
        *state = PairingUiState::failure(failure, started_at, Instant::now());
    }
}
