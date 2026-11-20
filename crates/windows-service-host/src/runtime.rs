// SPDX-License-Identifier: GPL-2.0-or-later
//! Trusted service worker: lifecycle, protected identity and bounded journal.
//! Pairing and the protected prompt watcher activate only after actual full SCM Ready.
//! Phone authorization remains distinct from the watcher's observed Windows outcome.
#![forbid(unsafe_code)]

use crate::peer_runtime::{PeerRuntimeError, ServiceSession, SessionCleanup, SessionProgress};
use crate::probe_supervisor::{WatchLifecycle, WatchObservation};
use crate::startup_phase::{
    ReadyRequest, RunningRequest, ready_handshake, run_platform_step, running_handshake,
};
use crate::{
    ProbeSupervisorError, ServiceProbeSupervisor, WatchSession,
    diagnostic::{
        CleanupObservation, HelperExitObservation, ProbeAdmission, ProbeDiagnosticRecord,
        ProbeObservation,
    },
};
use crate::{ServiceError, ServiceRegistry, ffi};
use activity_journal::{
    ActivityEvent, ActivityRecord, Decision, FailureKind, Journal, JournalError, Limits,
    PurgeReport, RequestOutcome, ServiceOutcome, UnixMillis,
};
use approval_core::DecisionError;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_identity::{IdentityError, PcIdentityKey};

pub(crate) static PROBE_REQUESTS: ProbeAdmission = ProbeAdmission::new();

#[derive(Debug)]
pub(crate) enum WorkerEvent {
    Progress,
    ScmRunningRequired(RunningRequest),
    Ready(ReadyRequest),
    Finished(Result<(), ServiceError>),
}

/// The service-entry thread owns this handle; worker resources are constructed
/// on the worker thread and remain there. Only fixed lifecycle messages cross.
pub(crate) struct Worker {
    stop: Sender<()>,
    events: Receiver<WorkerEvent>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn spawn(startup_began: Instant) -> Result<Self, ServiceError> {
        let (stop, requests) = mpsc::channel();
        let (sender, events) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("service-lifecycle".into())
            .spawn(move || {
                // No unwind reaches SCM or disappears as a falsely successful stop.
                let outcome = std::panic::catch_unwind(|| run(&requests, &sender, startup_began))
                    .unwrap_or(Err(ServiceError::WorkerFailed));
                let _ = sender.send(WorkerEvent::Finished(outcome));
            })
            .map_err(|_| ServiceError::WorkerFailed)?;
        Ok(Self {
            stop,
            events,
            thread: Some(thread),
        })
    }

    pub(crate) fn request_stop(&self) {
        PROBE_REQUESTS.close();
        let _ = self.stop.send(());
    }

    pub(crate) fn next_event(&self) -> Result<Option<WorkerEvent>, ServiceError> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(ServiceError::WorkerFailed),
        }
    }

    pub(crate) fn join_finished(&mut self) -> Result<(), ServiceError> {
        // Only called after Finished was received. No unbounded join on a live
        // worker is permitted: a tiny final return is verified with is_finished.
        let Some(thread) = self.thread.take() else {
            return Err(ServiceError::WorkerFailed);
        };
        if !thread.is_finished() {
            self.thread = Some(thread);
            return Err(ServiceError::UnexpectedState);
        }
        thread.join().map_err(|_| ServiceError::WorkerFailed)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
    }
}

fn now() -> Result<UnixMillis, ServiceError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ServiceError::InvalidClock)?
        .as_millis();
    UnixMillis::new(u64::try_from(millis).map_err(|_| ServiceError::InvalidClock)?)
        .map_err(|_| ServiceError::InvalidClock)
}

const JOURNAL_FAILURE_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const DECISION_REJECTION_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const JOURNAL_COMMAND_CAPACITY: usize = 64;
const JOURNAL_APPEND_DROPPED: u8 = 1;
const JOURNAL_PURGE_DROPPED: u8 = 2;

trait JournalStore: Send + 'static {
    fn limits(&self) -> Limits;
    fn append(
        &mut self,
        now: UnixMillis,
        event: ActivityEvent,
    ) -> Result<PurgeReport, JournalError>;
    fn recent(
        &mut self,
        now: UnixMillis,
        limit: usize,
    ) -> Result<Vec<ActivityRecord>, JournalError>;
    fn purge(&mut self, now: UnixMillis) -> Result<PurgeReport, JournalError>;
}

impl JournalStore for Journal {
    fn limits(&self) -> Limits {
        self.limits()
    }

    fn append(
        &mut self,
        now: UnixMillis,
        event: ActivityEvent,
    ) -> Result<PurgeReport, JournalError> {
        self.append(now, event)
    }

    fn recent(
        &mut self,
        now: UnixMillis,
        limit: usize,
    ) -> Result<Vec<ActivityRecord>, JournalError> {
        self.recent(now, limit)
    }

    fn purge(&mut self, now: UnixMillis) -> Result<PurgeReport, JournalError> {
        self.purge(now)
    }
}

#[derive(Clone, Copy, Debug)]
enum JournalCommand {
    Append {
        now: UnixMillis,
        event: ActivityEvent,
    },
    Purge {
        now: UnixMillis,
    },
    Shutdown,
}

#[derive(Debug, Default)]
struct PublishedActivity {
    generation: u64,
    records: Option<Vec<ActivityRecord>>,
}

struct RuntimeJournal {
    commands: SyncSender<JournalCommand>,
    queue_faults: Arc<AtomicU8>,
    published: Arc<Mutex<PublishedActivity>>,
    observed_generation: u64,
    cached: Option<Vec<ActivityRecord>>,
    limits: Limits,
    clock_floor: UnixMillis,
    thread: Option<JoinHandle<()>>,
}

impl RuntimeJournal {
    fn spawn(journal: Journal, opened_at: UnixMillis) -> Result<Self, ServiceError> {
        Self::spawn_store(journal, opened_at)
    }

    fn spawn_store<S: JournalStore>(
        journal: S,
        opened_at: UnixMillis,
    ) -> Result<Self, ServiceError> {
        let limits = journal.limits();
        let (commands, receiver) = mpsc::sync_channel(JOURNAL_COMMAND_CAPACITY);
        let queue_faults = Arc::new(AtomicU8::new(0));
        let published = Arc::new(Mutex::new(PublishedActivity::default()));
        let worker_faults = queue_faults.clone();
        let worker_published = published.clone();
        let (initialized, initialized_rx) = mpsc::sync_channel(0);
        let thread = thread::Builder::new()
            .name("activity-journal".into())
            .spawn(move || {
                run_journal_worker(
                    journal,
                    receiver,
                    worker_faults,
                    worker_published,
                    opened_at,
                    initialized,
                );
            })
            .map_err(|_| ServiceError::WorkerFailed)?;
        if initialized_rx.recv().is_err() {
            let _ = thread.join();
            return Err(ServiceError::WorkerFailed);
        }
        Ok(Self {
            commands,
            queue_faults,
            published,
            observed_generation: 0,
            cached: None,
            limits,
            clock_floor: opened_at,
            thread: Some(thread),
        })
    }

    fn append_at(&self, now: UnixMillis, event: ActivityEvent) {
        self.try_send(
            JournalCommand::Append { now, event },
            JOURNAL_APPEND_DROPPED,
        );
    }

    fn purge_at(&self, now: UnixMillis) {
        self.try_send(JournalCommand::Purge { now }, JOURNAL_PURGE_DROPPED);
    }

    fn try_send(&self, command: JournalCommand, fault: u8) {
        match self.commands.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.queue_faults.fetch_or(fault, Ordering::Release);
            }
        }
    }

    fn cached_recent(&mut self, now: UnixMillis, limit: usize) -> Option<Vec<ActivityRecord>> {
        self.clock_floor = self.clock_floor.max(now);
        if let Ok(published) = self.published.try_lock()
            && published.generation != self.observed_generation
        {
            self.observed_generation = published.generation;
            self.cached.clone_from(&published.records);
        }
        let cutoff = self
            .clock_floor
            .get()
            .saturating_sub(self.limits.max_age_ms());
        self.cached.as_ref().map(|records| {
            records
                .iter()
                .copied()
                .filter(|record| record.timestamp().get() >= cutoff)
                .take(limit.min(self.limits.max_records()))
                .collect()
        })
    }

    fn finish(mut self) -> Result<(), ServiceError> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), ServiceError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let sent = self.commands.send(JournalCommand::Shutdown).is_ok();
        let joined = thread.join().is_ok();
        if sent && joined {
            Ok(())
        } else {
            Err(ServiceError::WorkerFailed)
        }
    }
}

impl Drop for RuntimeJournal {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_journal_worker<S: JournalStore>(
    mut journal: S,
    commands: Receiver<JournalCommand>,
    queue_faults: Arc<AtomicU8>,
    published: Arc<Mutex<PublishedActivity>>,
    opened_at: UnixMillis,
    initialized: SyncSender<()>,
) {
    let mut failures = JournalFailureReports::default();
    publish_recent(&mut journal, opened_at, &published);
    let _ = initialized.send(());
    loop {
        report_journal_queue_faults(&mut failures, &queue_faults);
        match commands.recv() {
            Ok(JournalCommand::Append { now, event }) => match journal.append(now, event) {
                Ok(_) => {
                    crate::public_diagnostics::record(crate::public_diagnostics::Event::Activity {
                        event,
                    });
                    publish_recent(&mut journal, now, &published);
                }
                Err(error) => failures.record(JournalOperation::Append, &error, Instant::now()),
            },
            Ok(JournalCommand::Purge { now }) => match journal.purge(now) {
                Ok(_) => publish_recent(&mut journal, now, &published),
                Err(error) => failures.record(JournalOperation::Purge, &error, Instant::now()),
            },
            Ok(JournalCommand::Shutdown) => {
                report_journal_queue_faults(&mut failures, &queue_faults);
                break;
            }
            Err(_) => {
                report_journal_queue_faults(&mut failures, &queue_faults);
                break;
            }
        }
    }
}

fn publish_recent<S: JournalStore>(
    journal: &mut S,
    now: UnixMillis,
    published: &Mutex<PublishedActivity>,
) {
    let records = journal
        .recent(now, crate::management_protocol::MAX_ACTIVITY_RECORDS)
        .ok();
    if let Ok(mut published) = published.lock() {
        published.generation = published.generation.wrapping_add(1);
        published.records = records;
    }
}

fn report_journal_queue_faults(failures: &mut JournalFailureReports, queue_faults: &AtomicU8) {
    let faults = queue_faults.swap(0, Ordering::AcqRel);
    let at = Instant::now();
    if faults & JOURNAL_APPEND_DROPPED != 0 {
        failures.record_fault(
            JournalOperation::Append,
            crate::public_diagnostics::JournalFault::QueueFull,
            at,
        );
    }
    if faults & JOURNAL_PURGE_DROPPED != 0 {
        failures.record_fault(
            JournalOperation::Purge,
            crate::public_diagnostics::JournalFault::QueueFull,
            at,
        );
    }
}

#[derive(Clone, Copy, Debug)]
struct DecisionRejectionReport {
    reason: crate::public_diagnostics::DecisionRejectionReason,
    at: Instant,
}

#[derive(Debug, Default)]
struct DecisionRejectionReports {
    rows: Vec<DecisionRejectionReport>,
}

impl DecisionRejectionReports {
    fn should_record(
        &mut self,
        reason: crate::public_diagnostics::DecisionRejectionReason,
        at: Instant,
    ) -> bool {
        if let Some(previous) = self.rows.iter_mut().find(|row| row.reason == reason) {
            if at.saturating_duration_since(previous.at) < DECISION_REJECTION_REPORT_INTERVAL {
                return false;
            }
            previous.at = at;
        } else {
            self.rows.push(DecisionRejectionReport { reason, at });
        }
        true
    }

    fn record(&mut self, error: DecisionError, at: Instant) {
        let reason = decision_rejection_reason(error);
        if self.should_record(reason, at) {
            crate::public_diagnostics::record(crate::public_diagnostics::Event::DecisionRejected {
                reason,
            });
        }
    }
}

fn decision_rejection_reason(
    error: DecisionError,
) -> crate::public_diagnostics::DecisionRejectionReason {
    use crate::public_diagnostics::DecisionRejectionReason as Reason;
    match error {
        DecisionError::Clock(_) => Reason::Clock,
        DecisionError::WrongPc => Reason::WrongPc,
        DecisionError::WrongEpoch => Reason::WrongEpoch,
        DecisionError::UnknownOrCompleted => Reason::UnknownOrCompleted,
        DecisionError::Expired => Reason::Expired,
        DecisionError::BindingMismatch => Reason::BindingMismatch,
        DecisionError::NotEligible => Reason::NotEligible,
        DecisionError::EnrollmentChanged => Reason::EnrollmentChanged,
        DecisionError::InvalidSignature => Reason::InvalidSignature,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalOperation {
    Append,
    Purge,
}

#[derive(Clone, Copy, Debug)]
struct JournalFailureReport {
    operation: JournalOperation,
    fault: crate::public_diagnostics::JournalFault,
    at: Instant,
}

#[derive(Debug, Default)]
struct JournalFailureReports {
    rows: Vec<JournalFailureReport>,
}

impl JournalFailureReports {
    fn record(&mut self, operation: JournalOperation, error: &JournalError, at: Instant) {
        self.record_fault(
            operation,
            crate::public_diagnostics::JournalFault::from(error),
            at,
        );
    }

    fn record_fault(
        &mut self,
        operation: JournalOperation,
        fault: crate::public_diagnostics::JournalFault,
        at: Instant,
    ) {
        if let Some(previous) = self
            .rows
            .iter_mut()
            .find(|row| row.operation == operation && row.fault == fault)
        {
            if at.saturating_duration_since(previous.at) < JOURNAL_FAILURE_REPORT_INTERVAL {
                return;
            }
            previous.at = at;
        } else {
            self.rows.push(JournalFailureReport {
                operation,
                fault,
                at,
            });
        }
        let event = match operation {
            JournalOperation::Append => {
                crate::public_diagnostics::Event::JournalAppendFailed { fault }
            }
            JournalOperation::Purge => {
                crate::public_diagnostics::Event::JournalPurgeFailed { fault }
            }
        };
        crate::public_diagnostics::record(event);
    }
}

fn append(journal: &RuntimeJournal, event: ActivityEvent) -> Result<(), ServiceError> {
    journal.append_at(now()?, event);
    Ok(())
}

fn purge_journal(journal: &RuntimeJournal) -> Result<(), ServiceError> {
    journal.purge_at(now()?);
    Ok(())
}

fn cancellation_requested(stop: &Receiver<()>) -> bool {
    crate::entry::stop_requested()
        || matches!(stop.try_recv(), Ok(()) | Err(TryRecvError::Disconnected))
}

fn run(
    stop: &Receiver<()>,
    events: &Sender<WorkerEvent>,
    startup_began: Instant,
) -> Result<(), ServiceError> {
    // Identity and future transport/prompt workers belong at this trusted Rust seam.
    // They must initialize genuinely before claiming any additional readiness,
    // obey cancellation, and never expose their credentials through presentation.
    if cancellation_requested(stop) {
        return Ok(());
    }
    let _installation = ffi::validate_installation(true).map_err(|error| error.at_startup(1))?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    let directory = ffi::open_activity_directory().map_err(|error| error.at_startup(2))?;
    let opened_at = now().map_err(|error| error.at_startup(3))?;
    let journal = crate::journal_recovery::open(
        directory.path(),
        Limits::default(),
        opened_at,
        crate::public_diagnostics::record,
    )
    .map_err(|_| ServiceError::JournalUnavailable.at_startup(3))?;
    events
        .send(WorkerEvent::Progress)
        .map_err(|_| ServiceError::WorkerFailed)?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    let mut journal =
        RuntimeJournal::spawn(journal, opened_at).map_err(|error| error.at_startup(3))?;
    // Key work stays on the service worker, never the SCM entry callback or
    // a WebView/IPC thread. Only genuine absence permits initial creation.
    // Capture the fixed identity-context cause before the trust-store adapter's
    // intentionally coarse error mapping. This adds no privilege/key mutation.
    windows_identity::verify_service_context().map_err(ServiceError::from_identity)?;
    let mut trust_directory =
        ffi::TrustDirectory::open_for_service().map_err(|error| error.at_startup(4))?;
    let registry_absent = trust_directory
        .is_empty_registry_absent()
        .map_err(|error| error.at_startup(5))?;
    let bootstrap_authorized = trust_directory
        .take_missing_registry_bootstrap()
        .map_err(|error| error.at_startup(5))?;
    // Keep every protected preflight before SCM Running, but defer the first
    // platform-provider/key call until this exact entry thread has successfully
    // reported Running with NO accepted controls. This one-use in-process gate
    // retains the original startup deadline and does not advertise real Ready.
    let (request, gate) = running_handshake();
    events
        .send(WorkerEvent::ScmRunningRequired(request))
        .map_err(|_| ServiceError::WorkerFailed)?;
    gate.wait(startup_began, || cancellation_requested(stop))?;
    if cancellation_requested(stop) {
        return Ok(());
    }
    // Establish this service-owned process's narrow observation contract only
    // after original SCM Running/no-controls, before key opening and Ready.
    ffi::provision_current_process_observer(startup_began).map_err(|error| error.at_startup(7))?;
    // This private disposition is produced only here by the actual key API,
    // never supplied by a renderer, file, phone or caller freshness boolean.
    enum IdentityOrigin {
        Existing,
        CreatedNow,
        ResumedInitial,
    }
    let opened = run_platform_step(
        startup_began,
        || cancellation_requested(stop),
        PcIdentityKey::open_existing_for_service,
    )?;
    let (identity, origin) = match opened {
        Ok(identity) => {
            if registry_absent {
                if !bootstrap_authorized {
                    return Err(ServiceError::RegistryUnavailable);
                }
                (identity, IdentityOrigin::ResumedInitial)
            } else {
                (identity, IdentityOrigin::Existing)
            }
        }
        Err(IdentityError::KeyNotFound) => {
            // Do not create a replacement key beside older trust data. Missing
            // either half of a previously initialized identity requires recovery.
            if !registry_absent {
                return Err(ServiceError::RegistryUnavailable);
            }
            // Opening may have blocked through Stop or the original deadline.
            // Absence is not permission to start a late creation attempt.
            let created = run_platform_step(
                startup_began,
                || cancellation_requested(stop),
                PcIdentityKey::create_for_service,
            )?
            .map_err(ServiceError::from_identity)?;
            (created, IdentityOrigin::CreatedNow)
        }
        Err(error) => return Err(ServiceError::from_identity(error)),
    };
    let relay = trust_directory
        .read_relay_endpoint()
        .map_err(|error| error.at_startup(6))?;
    // Storage/ACL failures stop startup like the relay file. Unusable content
    // does not: the service runs Automatic and says so in public diagnostics.
    let external_access = startup_external_access(
        trust_directory
            .read_external_access()
            .map_err(|error| error.at_startup(EXTERNAL_ACCESS_STAGE))?,
    );
    let registry = match origin {
        IdentityOrigin::Existing => ServiceRegistry::open_existing(&identity, trust_directory),
        IdentityOrigin::CreatedNow | IdentityOrigin::ResumedInitial => {
            ServiceRegistry::initialize_empty_for_bootstrap(&identity, trust_directory)
        }
    }
    .map_err(registry_error)?;
    // Retain the actual registry, restored engine, original epoch coordinate and
    // borrowed native key in ONE worker-owned session. No carrier/listener is
    // activated and SCM readiness still does not mean remote approval readiness.
    let mut session =
        ServiceSession::for_service(registry, &identity, Instant::now()).map_err(session_error)?;
    session.use_external_access(external_access);
    let mut supervisor = None;
    let mut supervisor_initialization_failed = None;
    let mut watch = None;
    let mut decision_rejections = DecisionRejectionReports::default();
    // The fixed step a failure after Ready came from, for public diagnostics.
    let mut step = RuntimeStep::Ready;
    // Keep session OUTSIDE this unwind boundary: every returned error or unwind
    // takes the same staged drain before registry/key release or Finished.
    let runtime_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), RuntimeFailure> {
            if cancellation_requested(stop) {
                return Ok(());
            }
            events
                .send(WorkerEvent::Progress)
                .map_err(|_| ServiceError::WorkerFailed)?;
            // Passive fixed-slot inspection only, never a startup probe. Failure/full
            // storage disables this diagnostic without bypassing identity/registry init.
            PROBE_REQUESTS.prepare(
                crate::native::probe_control_registration_ready(_installation.executable())
                    .and_then(|()| directory.probe_slot_available()),
            );
            let (ready_request, ready_gate) = ready_handshake();
            events
                .send(WorkerEvent::Ready(ready_request))
                .map_err(|_| ServiceError::WorkerFailed)?;
            let ready = ready_gate.wait(startup_began, || cancellation_requested(stop))?;
            if cancellation_requested(stop) {
                return Ok(());
            }
            append(&journal, ActivityEvent::Service(ServiceOutcome::Started))?;
            step = RuntimeStep::Pairing;
            if let Some(reason) = session
                .activate_pairing(ready)
                .map_err(runtime_session_failure)?
            {
                // Fixed kind only; the reason itself stays out of the journal.
                append(
                    &journal,
                    ActivityEvent::Service(ServiceOutcome::ManagementUnavailable),
                )?;
                #[cfg(feature = "lab-software-identity")]
                crate::lab::record_note(&format!("management listener unavailable: {reason}"));
                #[cfg(not(feature = "lab-software-identity"))]
                drop(reason);
            }
            step = RuntimeStep::Relay;
            session
                .configure_relay_after_ready(relay)
                .map_err(runtime_session_failure)?;
            step = RuntimeStep::Watcher;
            // The watcher owner keeps first creation, restart cleanup and health
            // together. A refusal is observed and retried without ending service.
            let watcher_now = Instant::now();
            watch =
                Some(WatchSession::for_running_service().map_err(|_| RuntimeFailure::watcher())?);
            let observations = watch
                .as_mut()
                .ok_or(RuntimeFailure::watcher())?
                .poll(watcher_now)
                .map_err(|_| RuntimeFailure::watcher())?;
            process_watch_observations(&journal, &mut session, observations, watcher_now)?;
            if cancellation_requested(stop) {
                return Ok(());
            }
            step = RuntimeStep::Loop;
            let mut last_purge = Instant::now();
            let mut last_activity_read: Option<Instant> = None;
            loop {
                if cancellation_requested(stop) {
                    break;
                }
                let iteration_now = Instant::now();
                if last_activity_read
                    .is_none_or(|at| iteration_now.duration_since(at) >= Duration::from_secs(1))
                {
                    let records = diagnostic_time()
                        .and_then(|now| UnixMillis::new(now).ok())
                        .and_then(|now| {
                            journal.cached_recent(
                                now,
                                crate::management_protocol::MAX_ACTIVITY_RECORDS,
                            )
                        });
                    session.observe_activity(records);
                    last_activity_read = Some(Instant::now());
                }
                let observations = match watch.as_mut() {
                    Some(watcher) => watcher
                        .poll(iteration_now)
                        .map_err(|_| RuntimeFailure::watcher())?,
                    None => Vec::new(),
                };
                process_watch_observations(&journal, &mut session, observations, iteration_now)?;
                if let Some(progress) = session
                    .prompt_deadline_step(iteration_now)
                    .map_err(runtime_session_failure)?
                {
                    journal_prompt_progress(&journal, progress)?;
                }
                let processed = if watch
                    .as_ref()
                    .is_some_and(WatchSession::blocks_diagnostic_probe)
                {
                    session.process_one_with_watch(watch.as_mut().ok_or(RuntimeFailure::watcher())?)
                } else {
                    session.process_one()
                };
                match processed.map_err(runtime_session_failure)? {
                    SessionProgress::DecisionRejected(error) => {
                        decision_rejections.record(error, iteration_now);
                    }
                    SessionProgress::AuthorizedButNotApplied(reason) => {
                        let failure = match reason {
                            crate::peer_runtime::NotAppliedReason::PlatformUnavailable => {
                                FailureKind::PlatformUnavailable
                            }
                            crate::peer_runtime::NotAppliedReason::NoLiveTarget
                            | crate::peer_runtime::NotAppliedReason::ExpiredAfterVerification
                            | crate::peer_runtime::NotAppliedReason::PeerChangedAfterVerification => {
                                FailureKind::RequestValidationFailed
                            }
                        };
                        append(&journal, ActivityEvent::Failure(failure))?;
                    }
                    SessionProgress::ApplyRequested { purpose, .. } => {
                        let decision = journal_decision(purpose);
                        append(
                            &journal,
                            ActivityEvent::Request(RequestOutcome::PhoneDecisionVerified {
                                decision,
                            }),
                        )?;
                        append(
                            &journal,
                            ActivityEvent::Request(RequestOutcome::DecisionSentToWindows {
                                decision,
                            }),
                        )?;
                    }
                    SessionProgress::Prompt(progress) => {
                        journal_prompt_progress(&journal, progress)?;
                    }
                    SessionProgress::PairingFailed => append(
                        &journal,
                        ActivityEvent::Failure(FailureKind::TransportUnavailable),
                    )?,
                    SessionProgress::Enrolled(_device) => {
                        // The fixed journal schema has no enrollment-device event.
                    }
                    _ => {}
                }
                match stop.recv_timeout(Duration::from_millis(25)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                }
                if let Some(request) = PROBE_REQUESTS.take() {
                    // The native watcher adapter names whether it holds the shared
                    // process lease; a refused first start does not reserve it.
                    let result = if watch
                        .as_ref()
                        .is_some_and(WatchSession::blocks_diagnostic_probe)
                    {
                        run_busy_probe(&directory, &request)
                    } else {
                        run_requested_probe(
                            &directory,
                            &mut supervisor,
                            &mut supervisor_initialization_failed,
                            &request,
                        )
                    };
                    // A watcher that has not started yet is retried under the same
                    // lease: release it unless the probe owner is quarantined (then the
                    // lease stays held by design).
                    if matches!(result, Ok(false)) {
                        supervisor = None;
                        supervisor_initialization_failed = None;
                    }
                    match result {
                        Ok(quarantined) => {
                            request.finish(directory.probe_slot_available(), quarantined)
                        }
                        Err(ServiceError::ProbeSlotsFull) => request.finish(Ok(false), false),
                        Err(_) => request.finish(Err(ServiceError::ProbeUnavailable), true),
                    }
                }
                if last_purge.elapsed() >= Duration::from_secs(3_600) {
                    purge_journal(&journal)?;
                    last_purge = Instant::now();
                }
            }
            append(&journal, ActivityEvent::Service(ServiceOutcome::Stopping))?;
            Ok(())
        },
    ));
    let outcome = match runtime_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(failure)) => {
            record_runtime_failure(step, failure);
            Err(failure.error)
        }
        Err(_) => {
            let failure = RuntimeFailure::panicked();
            record_runtime_failure(step, failure);
            Err(failure.error)
        }
    };
    PROBE_REQUESTS.close();
    if let Some(watch) = watch.as_mut() {
        watch.begin_shutdown();
    }
    session.begin_shutdown();
    let io_failed = loop {
        let watch_done = watch.as_mut().is_none_or(WatchSession::poll_shutdown);
        match session.poll_shutdown() {
            SessionCleanup::CleanupPending { .. } => {
                // Retain ownership even beyond an expected cleanup interval.
                // No timeout is a quiescence receipt and no live join blocks
                // this key worker. Existing SCM timeout reporting is unchanged.
                thread::park_timeout(Duration::from_millis(25));
            }
            SessionCleanup::Quiescent { io_failed } if watch_done => break io_failed,
            SessionCleanup::Quiescent { .. } => thread::park_timeout(Duration::from_millis(25)),
        }
    };
    drop(watch);
    drop(supervisor);
    let closed = session.finish_shutdown().map_err(session_error);
    drop(session);
    let identity_closed = identity.close().map_err(ServiceError::from_identity);
    // The journal worker drains before the directory/installation pins, never the reverse.
    let journal_closed = journal.finish();
    drop(directory);
    outcome
        .and(closed)
        .and(identity_closed)
        .and(journal_closed)
        .and(if io_failed {
            Err(ServiceError::WorkerFailed)
        } else {
            Ok(())
        })
}

/// Fixed public-diagnostics stage of the optional external-access read.
const EXTERNAL_ACCESS_STAGE: u8 = 8;

fn startup_external_access(
    stored: crate::external_access::StoredExternalAccess,
) -> crate::external_access::ExternalAccessSetting {
    if stored == crate::external_access::StoredExternalAccess::Invalid {
        crate::public_diagnostics::record(crate::public_diagnostics::Event::ConfigurationIgnored {
            stage: EXTERNAL_ACCESS_STAGE,
        });
        #[cfg(feature = "lab-software-identity")]
        crate::lab::record_note("external access configuration ignored; using automatic");
    }
    stored.effective_setting()
}

fn session_error(error: PeerRuntimeError) -> ServiceError {
    match error {
        PeerRuntimeError::Clock => ServiceError::InvalidClock,
        PeerRuntimeError::Registry => ServiceError::RegistryUnavailable,
        _ => ServiceError::WorkerFailed,
    }
}

fn runtime_session_failure(error: PeerRuntimeError) -> RuntimeFailure {
    use crate::public_diagnostics::RuntimeFailureCause as Cause;
    let cause = match error {
        PeerRuntimeError::Closed => Cause::SessionClosed,
        PeerRuntimeError::Registry => Cause::Registry,
        PeerRuntimeError::PeerChanged => Cause::PeerChanged,
        PeerRuntimeError::Identity => Cause::Identity,
        PeerRuntimeError::Clock => Cause::Clock,
        PeerRuntimeError::Capacity => Cause::Capacity,
        PeerRuntimeError::Protocol => Cause::Protocol,
        PeerRuntimeError::Io => Cause::Io,
        PeerRuntimeError::Unwind => Cause::Panicked,
        PeerRuntimeError::CleanupPending => Cause::CleanupPending,
        PeerRuntimeError::Signing(_) => Cause::Signing,
    };
    RuntimeFailure {
        error: session_error(error),
        cause,
        panicked: error == PeerRuntimeError::Unwind,
    }
}

fn journal_decision(purpose: approval_protocol::DecisionPurpose) -> Decision {
    match purpose {
        approval_protocol::DecisionPurpose::Approve => Decision::Approve,
        approval_protocol::DecisionPurpose::Deny => Decision::Deny,
    }
}

fn journal_prompt_progress(
    journal: &RuntimeJournal,
    progress: crate::peer_runtime::prompt::PromptProgress,
) -> Result<(), ServiceError> {
    if let Some(result) = progress.result() {
        let outcome = match result {
            crate::peer_runtime::prompt::PromptResult::Approved => RequestOutcome::WindowsApplied {
                decision: Decision::Approve,
            },
            crate::peer_runtime::prompt::PromptResult::Denied => RequestOutcome::WindowsApplied {
                decision: Decision::Deny,
            },
            crate::peer_runtime::prompt::PromptResult::Cancelled => RequestOutcome::Cancelled,
            crate::peer_runtime::prompt::PromptResult::Expired => RequestOutcome::Expired,
            crate::peer_runtime::prompt::PromptResult::FailedRejected => {
                RequestOutcome::WindowsRejected
            }
            crate::peer_runtime::prompt::PromptResult::FailedUnknown => {
                RequestOutcome::WindowsOutcomeUnknown
            }
        };
        append(journal, ActivityEvent::Request(outcome))?;
    }
    if progress.observed() {
        append(journal, ActivityEvent::Request(RequestOutcome::Observed))?;
        if progress.delivery_failed() {
            // This specific observed request reached no eligible connected
            // phone. Do not emit this on periodic clocks/renewals/idle polls.
            append(journal, ActivityEvent::Failure(FailureKind::DeliveryFailed))?;
        }
    }
    if progress.queued_opened() != 0 {
        append(
            journal,
            ActivityEvent::Request(RequestOutcome::NotificationSent),
        )?;
    }
    Ok(())
}

fn process_watch_observations(
    journal: &RuntimeJournal,
    session: &mut ServiceSession<'_>,
    observations: Vec<WatchObservation>,
    at: Instant,
) -> Result<(), RuntimeFailure> {
    for observation in observations {
        match observation {
            WatchObservation::Health(health) => session.set_watcher_health(health),
            WatchObservation::StartFailed(error) => {
                crate::public_diagnostics::record(
                    crate::public_diagnostics::Event::WatcherStartFailed { error },
                );
            }
            WatchObservation::Lifecycle(lifecycle) => {
                let outcome = match lifecycle {
                    WatchLifecycle::Started => ServiceOutcome::WatcherStarted,
                    WatchLifecycle::Alive => ServiceOutcome::WatcherAlive,
                    WatchLifecycle::Restarted => ServiceOutcome::WatcherRestarted,
                    WatchLifecycle::Unavailable => ServiceOutcome::WatcherUnavailable,
                };
                append(journal, ActivityEvent::Service(outcome))?;
            }
            WatchObservation::Event(crate::WatchEvent::ParkedChanged { count }) => {
                append(
                    journal,
                    ActivityEvent::Request(if count > 0 {
                        RequestOutcome::ParkedOnTaskbar { count }
                    } else {
                        RequestOutcome::ParkedCleared
                    }),
                )?;
                session
                    .set_parked_prompts(count, at)
                    .map_err(runtime_session_failure)?;
            }
            WatchObservation::Event(event) => {
                let progress = session
                    .handle_watch_event(event, at)
                    .map_err(runtime_session_failure)?;
                journal_prompt_progress(journal, progress)?;
            }
        }
    }
    Ok(())
}

fn diagnostic_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
}

fn run_busy_probe(
    directory: &ffi::ActivityDirectory,
    request: &crate::diagnostic::ProbeRun<'_>,
) -> Result<bool, ServiceError> {
    let file = directory.reserve_probe_slot()?;
    let record = ProbeDiagnosticRecord::new(
        file.slot(),
        std::process::id(),
        diagnostic_time(),
        diagnostic_time(),
        if request.cancelled() {
            ProbeObservation::CancelledBeforeProbe
        } else {
            ProbeObservation::SupervisorFailure {
                failure: ProbeSupervisorError::Busy,
            }
        },
        CleanupObservation::NoRetainedRun,
        HelperExitObservation::NotStarted,
    );
    file.write_record(record)?;
    Ok(false)
}

fn run_requested_probe(
    directory: &ffi::ActivityDirectory,
    supervisor: &mut Option<ServiceProbeSupervisor>,
    initialization_failure: &mut Option<ProbeSupervisorError>,
    request: &crate::diagnostic::ProbeRun<'_>,
) -> Result<bool, ServiceError> {
    let file = directory.reserve_probe_slot()?;
    let started = diagnostic_time();
    let (outcome, cleanup, helper_exit, quarantined) = if request.cancelled() {
        (
            ProbeObservation::CancelledBeforeProbe,
            CleanupObservation::NoRetainedRun,
            HelperExitObservation::NotStarted,
            false,
        )
    } else {
        if supervisor.is_none() && initialization_failure.is_none() {
            match ServiceProbeSupervisor::for_running_service() {
                Ok(owner) => *supervisor = Some(owner),
                Err(error) => *initialization_failure = Some(error),
            }
        }
        match supervisor {
            Some(owner) if !request.cancelled() => match owner.probe_once() {
                Ok(report) => {
                    let (outcome, helper_exit) = ProbeObservation::from_report(report);
                    (
                        outcome,
                        CleanupObservation::ReportAndExitConfirmed,
                        helper_exit,
                        false,
                    )
                }
                Err(error) => {
                    let quarantined = owner.is_quarantined();
                    (
                        ProbeObservation::SupervisorFailure { failure: error },
                        if quarantined {
                            CleanupObservation::Quarantined
                        } else {
                            CleanupObservation::NoRetainedRun
                        },
                        HelperExitObservation::Unknown,
                        quarantined,
                    )
                }
            },
            Some(_) => (
                ProbeObservation::CancelledBeforeProbe,
                CleanupObservation::NoRetainedRun,
                HelperExitObservation::NotStarted,
                false,
            ),
            None => (
                ProbeObservation::SupervisorFailure {
                    failure: initialization_failure
                        .unwrap_or(ProbeSupervisorError::NotRunningService),
                },
                CleanupObservation::Unknown,
                HelperExitObservation::NotStarted,
                true,
            ),
        }
    };
    let record = ProbeDiagnosticRecord::new(
        file.slot(),
        std::process::id(),
        started,
        diagnostic_time(),
        outcome,
        cleanup,
        helper_exit,
    );
    file.write_record(record)?;
    Ok(quarantined)
}

/// Where the worker was when it failed after SCM Ready. Fixed numbers only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeStep {
    Ready = 1,
    Pairing = 2,
    Relay = 3,
    Watcher = 4,
    Loop = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeFailure {
    error: ServiceError,
    cause: crate::public_diagnostics::RuntimeFailureCause,
    panicked: bool,
}

impl RuntimeFailure {
    fn watcher() -> Self {
        Self {
            error: ServiceError::WorkerFailed,
            cause: crate::public_diagnostics::RuntimeFailureCause::Watcher,
            panicked: false,
        }
    }

    fn panicked() -> Self {
        Self {
            error: ServiceError::WorkerFailed,
            cause: crate::public_diagnostics::RuntimeFailureCause::Panicked,
            panicked: true,
        }
    }
}

impl From<ServiceError> for RuntimeFailure {
    fn from(error: ServiceError) -> Self {
        Self {
            error,
            cause: crate::public_diagnostics::RuntimeFailureCause::Service,
            panicked: false,
        }
    }
}

fn record_runtime_failure(step: RuntimeStep, failure: RuntimeFailure) {
    crate::public_diagnostics::record(crate::public_diagnostics::Event::RuntimeFailure {
        step: step as u8,
        cause: failure.cause,
        panicked: failure.panicked,
        code: if failure.panicked {
            0
        } else {
            failure.error.service_diagnostic_code()
        },
    });
}

fn registry_error(error: crate::RegistryError) -> ServiceError {
    if error == crate::RegistryError::MaintenanceRequired {
        ServiceError::RegistryMaintenanceRequired
    } else {
        ServiceError::RegistryUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use activity_journal::{ActivityRecord, PurgeReport};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct JournalIoCounts {
        appends: AtomicUsize,
        reads: AtomicUsize,
        purges: AtomicUsize,
    }

    struct JournalDouble {
        counts: Arc<JournalIoCounts>,
        initialized: Option<mpsc::SyncSender<()>>,
        append_started: Option<mpsc::SyncSender<()>>,
        append_release: Option<mpsc::Receiver<()>>,
    }

    impl JournalStore for JournalDouble {
        fn limits(&self) -> Limits {
            Limits::default()
        }

        fn append(
            &mut self,
            _now: UnixMillis,
            _event: ActivityEvent,
        ) -> Result<PurgeReport, JournalError> {
            self.counts.appends.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = &self.append_started {
                let _ = started.try_send(());
            }
            if let Some(release) = self.append_release.take() {
                let _ = release.recv();
            }
            Ok(PurgeReport::default())
        }

        fn recent(
            &mut self,
            _now: UnixMillis,
            _limit: usize,
        ) -> Result<Vec<ActivityRecord>, JournalError> {
            self.counts.reads.fetch_add(1, Ordering::SeqCst);
            if let Some(initialized) = self.initialized.take() {
                let _ = initialized.send(());
            }
            Ok(Vec::new())
        }

        fn purge(&mut self, _now: UnixMillis) -> Result<PurgeReport, JournalError> {
            self.counts.purges.fetch_add(1, Ordering::SeqCst);
            Ok(PurgeReport::default())
        }
    }

    #[test]
    fn idle_activity_ticks_use_cached_records_without_journal_io() {
        let counts = Arc::new(JournalIoCounts::default());
        let (initialized, initialized_rx) = mpsc::sync_channel(1);
        let store = JournalDouble {
            counts: counts.clone(),
            initialized: Some(initialized),
            append_started: None,
            append_release: None,
        };
        let opened_at = UnixMillis::new(1_000).unwrap();
        let mut journal = RuntimeJournal::spawn_store(store, opened_at).unwrap();
        initialized_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let before = (
            counts.appends.load(Ordering::SeqCst),
            counts.reads.load(Ordering::SeqCst),
            counts.purges.load(Ordering::SeqCst),
        );

        for tick in 1..=10 {
            assert_eq!(
                journal.cached_recent(
                    UnixMillis::new(1_000 + tick).unwrap(),
                    crate::management_protocol::MAX_ACTIVITY_RECORDS,
                ),
                Some(Vec::new())
            );
        }

        assert_eq!(
            (
                counts.appends.load(Ordering::SeqCst),
                counts.reads.load(Ordering::SeqCst),
                counts.purges.load(Ordering::SeqCst),
            ),
            before
        );
        assert_eq!(journal.finish(), Ok(()));
    }

    #[test]
    fn approval_thread_never_waits_for_delayed_or_saturated_journal_io() {
        let counts = Arc::new(JournalIoCounts::default());
        let (initialized, initialized_rx) = mpsc::sync_channel(1);
        let (append_started, append_started_rx) = mpsc::sync_channel(1);
        let (append_release, append_release_rx) = mpsc::sync_channel(1);
        let store = JournalDouble {
            counts: counts.clone(),
            initialized: Some(initialized),
            append_started: Some(append_started),
            append_release: Some(append_release_rx),
        };
        let now = UnixMillis::new(1_000).unwrap();
        let journal = RuntimeJournal::spawn_store(store, now).unwrap();
        initialized_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        journal.append_at(now, ActivityEvent::Service(ServiceOutcome::Started));
        append_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        for _ in 0..JOURNAL_COMMAND_CAPACITY {
            journal.append_at(now, ActivityEvent::Service(ServiceOutcome::Started));
        }

        let (returned, returned_rx) = mpsc::sync_channel(1);
        thread::scope(|scope| {
            scope.spawn(|| {
                journal.append_at(now, ActivityEvent::Service(ServiceOutcome::Started));
                returned.send(()).unwrap();
            });
            let result = returned_rx.recv_timeout(Duration::from_millis(250));
            append_release.send(()).unwrap();
            assert_eq!(result, Ok(()));
        });

        assert_eq!(journal.finish(), Ok(()));
        assert_eq!(
            counts.appends.load(Ordering::SeqCst),
            JOURNAL_COMMAND_CAPACITY + 1
        );
    }

    #[test]
    fn startup_cancellation_detects_stop_and_owner_disconnection() {
        let (sender, receiver) = mpsc::channel();
        assert!(!cancellation_requested(&receiver));
        sender.send(()).unwrap();
        assert!(cancellation_requested(&receiver));
        drop(sender);
        assert!(cancellation_requested(&receiver));
    }

    #[test]
    fn journal_failure_rows_are_limited_by_operation_and_fault_for_sixty_seconds() {
        let began = Instant::now();
        let mut reports = JournalFailureReports::default();
        reports.record(
            JournalOperation::Append,
            &JournalError::MissingStorage,
            began,
        );
        reports.record(
            JournalOperation::Append,
            &JournalError::MissingStorage,
            began + Duration::from_secs(59),
        );
        assert_eq!(reports.rows.len(), 1);
        assert_eq!(reports.rows[0].at, began);

        reports.record(
            JournalOperation::Append,
            &JournalError::CorruptStorage,
            began + Duration::from_secs(59),
        );
        reports.record(
            JournalOperation::Purge,
            &JournalError::MissingStorage,
            began + Duration::from_secs(59),
        );
        assert_eq!(reports.rows.len(), 3);

        reports.record(
            JournalOperation::Append,
            &JournalError::MissingStorage,
            began + Duration::from_secs(60),
        );
        assert_eq!(reports.rows.len(), 3);
        assert_eq!(reports.rows[0].at, began + Duration::from_secs(60));
    }

    #[test]
    fn runtime_failure_mapping_preserves_session_causes_and_caught_panics() {
        use crate::public_diagnostics::RuntimeFailureCause;
        use crate::tls_signer::TlsSigningBridgeError;

        let cases = [
            (
                PeerRuntimeError::Closed,
                RuntimeFailureCause::SessionClosed,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Registry,
                RuntimeFailureCause::Registry,
                false,
                ServiceError::RegistryUnavailable,
            ),
            (
                PeerRuntimeError::PeerChanged,
                RuntimeFailureCause::PeerChanged,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Identity,
                RuntimeFailureCause::Identity,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Clock,
                RuntimeFailureCause::Clock,
                false,
                ServiceError::InvalidClock,
            ),
            (
                PeerRuntimeError::Capacity,
                RuntimeFailureCause::Capacity,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Protocol,
                RuntimeFailureCause::Protocol,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Io,
                RuntimeFailureCause::Io,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Unwind,
                RuntimeFailureCause::Panicked,
                true,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::CleanupPending,
                RuntimeFailureCause::CleanupPending,
                false,
                ServiceError::WorkerFailed,
            ),
            (
                PeerRuntimeError::Signing(TlsSigningBridgeError::InvalidSignature),
                RuntimeFailureCause::Signing,
                false,
                ServiceError::WorkerFailed,
            ),
        ];

        for (error, cause, panicked, service_error) in cases {
            let failure = runtime_session_failure(error);
            assert_eq!(failure.error, service_error);
            assert_eq!(failure.cause, cause);
            assert_eq!(failure.panicked, panicked);
        }
    }

    #[test]
    fn decision_rejection_mapping_is_complete_and_rows_are_rate_limited_by_reason() {
        use crate::public_diagnostics::DecisionRejectionReason;
        use approval_core::{ClockError, DecisionError};

        let cases = [
            (
                DecisionError::Clock(ClockError::WentBackwards),
                DecisionRejectionReason::Clock,
            ),
            (DecisionError::WrongPc, DecisionRejectionReason::WrongPc),
            (
                DecisionError::WrongEpoch,
                DecisionRejectionReason::WrongEpoch,
            ),
            (
                DecisionError::UnknownOrCompleted,
                DecisionRejectionReason::UnknownOrCompleted,
            ),
            (DecisionError::Expired, DecisionRejectionReason::Expired),
            (
                DecisionError::BindingMismatch,
                DecisionRejectionReason::BindingMismatch,
            ),
            (
                DecisionError::NotEligible,
                DecisionRejectionReason::NotEligible,
            ),
            (
                DecisionError::EnrollmentChanged,
                DecisionRejectionReason::EnrollmentChanged,
            ),
            (
                DecisionError::InvalidSignature,
                DecisionRejectionReason::InvalidSignature,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(decision_rejection_reason(error), expected);
        }

        let began = Instant::now();
        let mut reports = DecisionRejectionReports::default();
        assert!(reports.should_record(DecisionRejectionReason::Expired, began));
        assert!(!reports.should_record(
            DecisionRejectionReason::Expired,
            began + Duration::from_secs(59)
        ));
        assert!(reports.should_record(
            DecisionRejectionReason::BindingMismatch,
            began + Duration::from_secs(59)
        ));
        assert!(reports.should_record(
            DecisionRejectionReason::Expired,
            began + Duration::from_secs(60)
        ));
    }

    #[test]
    fn append_and_purge_storage_errors_do_not_escape_the_journal_worker() {
        let directory = tempfile::tempdir().unwrap();
        let opened_at = now().unwrap();
        let journal = Journal::open(directory.path(), Limits::default(), opened_at).unwrap();
        std::fs::remove_file(directory.path().join("activity.jsonl")).unwrap();
        let journal = RuntimeJournal::spawn_store(journal, opened_at).unwrap();

        journal.append_at(opened_at, ActivityEvent::Service(ServiceOutcome::Started));
        journal.purge_at(opened_at);
        assert_eq!(journal.finish(), Ok(()));
    }
}
