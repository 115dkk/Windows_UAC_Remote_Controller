// SPDX-License-Identifier: GPL-2.0-or-later
//! One phone-owned enrollment ceremony from an already accepted native scan.
//! Status exposes only bounded progress, a comparison code and terminal reason.

use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use framed_transport::{
    ConnectionBudget, PeerTransport, SocketDriver, SocketError, SocketEvent, SocketLimits,
};
use relay_service::{Registration, Role, RouteId};
use service_protocol::{
    CandidateSubmission, CandidateSubmissionFields, CeremonyMessageKind, PairingChallenge,
    PairingConfirmation, PairingConfirmationFields, candidate_digest, ceremony_message_kind,
    frame_plaintext_submission,
};
use tokio_util::sync::CancellationToken;

use super::{CreatedPairingCommitError, CreatedPairingKeys, NativePairingScan};
use crate::{BridgeError, MobileController};

const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(120);
const ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeCeremonyPhase {
    CreatingKeys,
    Connecting,
    Submitting,
    AwaitingCandidate,
    Compare,
    AwaitingAcceptance,
    Enrolled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum NativeCeremonyFailure {
    Cancelled,
    Expired,
    Network,
    Rejected,
    Mismatch,
    Storage,
    Unavailable,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeCeremonyStatus {
    pub phase: NativeCeremonyPhase,
    pub comparison_code: Option<String>,
    pub failure: Option<NativeCeremonyFailure>,
    pub deadline_nanos: u64,
}

#[derive(uniffi::Object)]
pub struct NativePairingCeremony {
    status: Arc<Mutex<NativeCeremonyStatus>>,
    confirmed: Arc<AtomicBool>,
    confirmation: Arc<tokio::sync::Notify>,
    stop: CancellationToken,
    settled: Arc<AtomicBool>,
    scan: Arc<Mutex<Option<Arc<NativePairingScan>>>>,
}
impl std::fmt::Debug for NativePairingCeremony {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativePairingCeremony([redacted])")
    }
}
impl Drop for NativePairingCeremony {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(scan) = self
            .scan
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            scan.cancel();
        }
    }
}

#[uniffi::export]
impl NativePairingCeremony {
    pub fn status(&self) -> NativeCeremonyStatus {
        self.status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub fn confirm(&self) -> Result<(), BridgeError> {
        let phase = self.status.lock().map_err(|_| BridgeError::Closed)?.phase;
        if phase != NativeCeremonyPhase::Compare
            || self
                .confirmed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(BridgeError::InvalidObservation);
        }
        self.confirmation.notify_waiters();
        Ok(())
    }

    pub fn cancel(&self) {
        self.stop.cancel();
        if let Some(scan) = self
            .scan
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            scan.cancel();
        }
        self.confirmation.notify_waiters();
    }

    pub fn is_settled(&self) -> bool {
        self.settled.load(Ordering::Acquire)
    }
}

#[uniffi::export]
impl MobileController {
    pub fn begin_pairing_ceremony(
        self: &Arc<Self>,
        scan: Arc<NativePairingScan>,
    ) -> Result<Arc<NativePairingCeremony>, BridgeError> {
        let deadline = scan.ceremony_deadline();
        let deadline_nanos = scan.ceremony_deadline_nanos();

        // This is the only consumption point. The original scan remains retained
        // by both the exported object and worker until all ceremony resources drop.
        let (invitation, intent) = self.take_pairing_scan(&scan)?;
        let status = Arc::new(Mutex::new(NativeCeremonyStatus {
            phase: NativeCeremonyPhase::CreatingKeys,
            comparison_code: None,
            failure: None,
            deadline_nanos,
        }));
        let confirmed = Arc::new(AtomicBool::new(false));
        let confirmation = Arc::new(tokio::sync::Notify::new());
        let stop = CancellationToken::new();
        let settled = Arc::new(AtomicBool::new(false));
        let retained_scan = Arc::new(Mutex::new(Some(Arc::clone(&scan))));
        let ceremony = Arc::new(NativePairingCeremony {
            status: Arc::clone(&status),
            confirmed: Arc::clone(&confirmed),
            confirmation: Arc::clone(&confirmation),
            stop: stop.clone(),
            settled: Arc::clone(&settled),
            scan: Arc::clone(&retained_scan),
        });
        let controller = Arc::clone(self);
        let platform = Arc::clone(&self.platform);
        let clock = scan.ceremony_clock();
        let worker_status = Arc::clone(&status);
        let worker_settled = Arc::clone(&settled);
        let worker_retained_scan = Arc::clone(&retained_scan);
        let worker_intent = Arc::new(Mutex::new(Some(intent)));
        let worker_intent_slot = Arc::clone(&worker_intent);
        let spawn = std::thread::Builder::new()
            .name("uac-pairing-ceremony".into())
            .spawn(move || {
                let mut intent = worker_intent_slot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| NativeCeremonyFailure::Unavailable)?;
                    runtime.block_on(run_ceremony(
                        controller,
                        scan,
                        invitation,
                        intent.take().expect("ceremony worker owns one intent"),
                        platform,
                        clock,
                        Arc::clone(&worker_status),
                        confirmed,
                        confirmation,
                        stop,
                        deadline,
                    ))
                }));
                if let Some(intent) = intent.take() {
                    intent.cancel();
                }
                let (phase, failure) = match result {
                    Ok(Ok(warning)) => (NativeCeremonyPhase::Enrolled, warning),
                    Ok(Err(failure)) => (NativeCeremonyPhase::Failed, Some(failure)),
                    Err(_) => (
                        NativeCeremonyPhase::Failed,
                        Some(NativeCeremonyFailure::Unavailable),
                    ),
                };
                worker_retained_scan
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take();
                let mut current = worker_status
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                current.phase = phase;
                current.comparison_code = None;
                current.failure = failure;
                drop(current);
                worker_settled.store(true, Ordering::Release);
            });
        if spawn.is_err() {
            if let Some(intent) = worker_intent
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                intent.cancel();
            }
            ceremony.cancel();
            let mut current = status.lock().unwrap_or_else(|error| error.into_inner());
            current.phase = NativeCeremonyPhase::Failed;
            current.comparison_code = None;
            current.failure = Some(NativeCeremonyFailure::Unavailable);
            drop(current);
            settled.store(true, Ordering::Release);
            return Err(BridgeError::NativeUnavailable);
        }
        Ok(ceremony)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_ceremony(
    controller: Arc<MobileController>,
    scan: Arc<NativePairingScan>,
    invitation: service_protocol::PairingInvitation,
    intent: super::KeyCreationIntent,
    platform: Arc<dyn crate::NativePlatform>,
    clock: Arc<dyn framed_transport::SocketClock>,
    status: Arc<Mutex<NativeCeremonyStatus>>,
    confirmed: Arc<AtomicBool>,
    confirmation: Arc<tokio::sync::Notify>,
    stop: CancellationToken,
    deadline: Instant,
) -> Result<Option<NativeCeremonyFailure>, NativeCeremonyFailure> {
    ensure_live(&stop, deadline)?;
    scan.check_current().map_err(map_bridge)?;
    let created = controller.create_pairing_keys(intent).map_err(map_bridge)?;
    let _created_guard = CreatedCancellationGuard(created.cancellation_state());
    ensure_live_or_cancel(&created, &stop, deadline)?;
    set_phase(&status, NativeCeremonyPhase::Connecting, None);

    let fields = invitation.fields();
    let route = RouteId::new(fields.route).map_err(|_| {
        created.cancel();
        NativeCeremonyFailure::Rejected
    })?;
    let carrier = await_bounded(
        &stop,
        deadline,
        Duration::from_secs(30),
        relay_service::connect_rendezvous(
            fields.relay_address,
            Registration::new(Role::Phone, route),
            stop.child_token(),
        ),
    )
    .await
    .inspect_err(|_| created.cancel())?
    .map_err(|error| {
        created.cancel();
        if matches!(error, relay_service::RendezvousError::Cancelled) {
            NativeCeremonyFailure::Cancelled
        } else {
            NativeCeremonyFailure::Network
        }
    })?;

    set_phase(&status, NativeCeremonyPhase::Submitting, None);
    let submission = make_submission(&invitation, &created).inspect_err(|_| created.cancel())?;
    let stream = carrier.into_stream();
    write_plaintext_submission(
        &stream,
        &frame_plaintext_submission(&submission),
        &stop,
        deadline,
    )
    .await
    .inspect_err(|_| created.cancel())?;

    let local_keys = created.local_keys().clone();
    let pc_transport_key = fields.pc_transport_key.clone();
    let (stream, identity) = crate::transport::created_identity_with_socket(
        stream, local_keys, platform,
    )
    .map_err(|error| {
        created.cancel();
        map_bridge(error)
    })?;
    let now = clock.now().map_err(|_| {
        created.cancel();
        NativeCeremonyFailure::Unavailable
    })?;
    let budget = Arc::new(ConnectionBudget::new(1).map_err(|_| {
        created.cancel();
        NativeCeremonyFailure::Unavailable
    })?);
    let transport =
        PeerTransport::client(budget, identity, pc_transport_key, now).map_err(|_| {
            created.cancel();
            NativeCeremonyFailure::Rejected
        })?;
    let mut driver = SocketDriver::new(
        stream,
        transport,
        Arc::clone(&clock),
        SocketLimits::default(),
        stop.child_token(),
    )
    .map_err(|error| {
        created.cancel();
        map_socket(error)
    })?;

    set_phase(&status, NativeCeremonyPhase::AwaitingCandidate, None);
    let frozen_wire = next_frame(&mut driver, &stop, deadline, CANDIDATE_TIMEOUT)
        .await
        .inspect_err(|_| created.cancel())?;
    if ceremony_message_kind(&frozen_wire) != Some(CeremonyMessageKind::FrozenCandidate) {
        let _ = driver.reject_protocol_message();
        created.cancel();
        return Err(NativeCeremonyFailure::Rejected);
    }
    let digest = candidate_digest(&frozen_wire);
    let frozen = controller
        .match_frozen_candidate(created, &frozen_wire)
        .map_err(|_| NativeCeremonyFailure::Mismatch)?;
    let comparison_code = frozen
        .comparison_code()
        .map_err(|_| {
            frozen.cancel();
            NativeCeremonyFailure::Mismatch
        })?
        .as_str()
        .to_owned();
    set_phase(&status, NativeCeremonyPhase::Compare, Some(comparison_code));
    wait_for_confirmation(&confirmed, &confirmation, &stop, deadline)
        .await
        .inspect_err(|_| frozen.cancel())?;

    let comparison_code = status
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .comparison_code
        .clone();
    set_phase(
        &status,
        NativeCeremonyPhase::AwaitingAcceptance,
        comparison_code,
    );
    let confirmation = PairingConfirmation::new(PairingConfirmationFields {
        ceremony_nonce: fields.ceremony_nonce,
        phone_keys: submission.phone_keys(),
        candidate_digest: digest,
        confirmed: true,
    })
    .map_err(|_| {
        frozen.cancel();
        NativeCeremonyFailure::Rejected
    })?;
    let confirmation_frame =
        service_protocol::encode_frame(&confirmation.to_wire()).map_err(|_| {
            frozen.cancel();
            NativeCeremonyFailure::Rejected
        })?;
    driver.queue_frame(confirmation_frame).map_err(|error| {
        frozen.cancel();
        map_socket(error)
    })?;
    let acceptance = next_frame(&mut driver, &stop, deadline, ACCEPTANCE_TIMEOUT)
        .await
        .inspect_err(|_| frozen.cancel())?;
    if ceremony_message_kind(&acceptance) != Some(CeremonyMessageKind::EnrollmentAcceptance) {
        let _ = driver.reject_protocol_message();
        frozen.cancel();
        return Err(NativeCeremonyFailure::Rejected);
    }
    let warning = match controller.commit_created_pairing(frozen, &acceptance) {
        Ok(_) => None,
        Err(CreatedPairingCommitError::CommittedButNotLive { .. }) => {
            Some(NativeCeremonyFailure::Unavailable)
        }
        Err(CreatedPairingCommitError::Rejected(error)) => return Err(map_bridge(error)),
    };
    close_driver(&mut driver, &stop, deadline).await;
    Ok(warning)
}

struct CreatedCancellationGuard(Arc<super::CreationState>);

impl Drop for CreatedCancellationGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn make_submission(
    invitation: &service_protocol::PairingInvitation,
    created: &CreatedPairingKeys,
) -> Result<CandidateSubmission, NativeCeremonyFailure> {
    let fields = invitation.fields();
    let keys = created.local_keys();
    let evidence = created.unverified_evidence();
    CandidateSubmission::new(
        CandidateSubmissionFields {
            ceremony_nonce: fields.ceremony_nonce,
            attestation_challenge: PairingChallenge::from_bytes(*keys.challenge().as_bytes())
                .map_err(|_| NativeCeremonyFailure::Rejected)?,
            pc: fields.pc,
            recipient_device: fields.recipient_device,
            invitation_context: invitation.context_digest(),
            approval_key: keys.approval_key().clone(),
            denial_key: keys.denial_key().clone(),
            transport_key: keys.transport_key().clone(),
        },
        evidence.approval.certificates.clone(),
        evidence.denial.certificates.clone(),
        evidence.transport.certificates.clone(),
    )
    .map_err(|_| NativeCeremonyFailure::Rejected)
}

async fn next_frame(
    driver: &mut SocketDriver,
    stop: &CancellationToken,
    deadline: Instant,
    limit: Duration,
) -> Result<Vec<u8>, NativeCeremonyFailure> {
    let operation_deadline = bounded_deadline(deadline, limit);
    loop {
        let event = await_until(stop, deadline, operation_deadline, driver.next_event())
            .await?
            .map_err(map_socket)?;
        match event {
            SocketEvent::Ready | SocketEvent::OutboundDrained => continue,
            SocketEvent::Frame(frame) => return Ok(frame.into_bytes()),
            SocketEvent::PeerClosed | SocketEvent::LocallyClosed => {
                return Err(NativeCeremonyFailure::Network);
            }
        }
    }
}

async fn wait_for_confirmation(
    confirmed: &AtomicBool,
    notification: &tokio::sync::Notify,
    stop: &CancellationToken,
    deadline: Instant,
) -> Result<(), NativeCeremonyFailure> {
    loop {
        let notified = notification.notified();
        if confirmed.load(Ordering::Acquire) {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(NativeCeremonyFailure::Cancelled),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                return Err(NativeCeremonyFailure::Expired);
            }
            _ = notified => {}
        }
    }
}

async fn close_driver(driver: &mut SocketDriver, stop: &CancellationToken, deadline: Instant) {
    if driver.begin_close().is_err() {
        driver.abort();
        return;
    }
    let close_deadline = bounded_deadline(deadline, CLOSE_TIMEOUT);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => {
                driver.abort();
                return;
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(close_deadline)) => {
                driver.abort();
                return;
            }
            event = driver.next_event() => match event {
                Ok(SocketEvent::LocallyClosed) => return,
                Ok(_) => continue,
                Err(_) => {
                    driver.abort();
                    return;
                }
            }
        }
    }
}

async fn write_plaintext_submission(
    stream: &tokio::net::TcpStream,
    bytes: &[u8],
    stop: &CancellationToken,
    deadline: Instant,
) -> Result<(), NativeCeremonyFailure> {
    let operation_deadline = bounded_deadline(deadline, SUBMISSION_TIMEOUT);
    let mut written = 0;
    while written < bytes.len() {
        await_until(stop, deadline, operation_deadline, stream.writable())
            .await?
            .map_err(|_| NativeCeremonyFailure::Network)?;
        match stream.try_write(&bytes[written..]) {
            Ok(0) => return Err(NativeCeremonyFailure::Network),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(NativeCeremonyFailure::Network),
        }
    }
    Ok(())
}

fn bounded_deadline(deadline: Instant, limit: Duration) -> Instant {
    Instant::now()
        .checked_add(limit)
        .map_or(deadline, |value| value.min(deadline))
}

async fn await_until<T, F>(
    stop: &CancellationToken,
    deadline: Instant,
    operation_deadline: Instant,
    future: F,
) -> Result<T, NativeCeremonyFailure>
where
    F: Future<Output = T>,
{
    ensure_live(stop, deadline)?;
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(NativeCeremonyFailure::Cancelled),
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(operation_deadline)) => {
            if operation_deadline == deadline {
                Err(NativeCeremonyFailure::Expired)
            } else {
                Err(NativeCeremonyFailure::Network)
            }
        }
        value = future => Ok(value),
    }
}

async fn await_bounded<T, F>(
    stop: &CancellationToken,
    deadline: Instant,
    limit: Duration,
    future: F,
) -> Result<T, NativeCeremonyFailure>
where
    F: Future<Output = T>,
{
    await_until(stop, deadline, bounded_deadline(deadline, limit), future).await
}

fn ensure_live(stop: &CancellationToken, deadline: Instant) -> Result<(), NativeCeremonyFailure> {
    if stop.is_cancelled() {
        Err(NativeCeremonyFailure::Cancelled)
    } else if Instant::now() >= deadline {
        Err(NativeCeremonyFailure::Expired)
    } else {
        Ok(())
    }
}

fn ensure_live_or_cancel(
    created: &CreatedPairingKeys,
    stop: &CancellationToken,
    deadline: Instant,
) -> Result<(), NativeCeremonyFailure> {
    ensure_live(stop, deadline).inspect_err(|_| created.cancel())
}

fn set_phase(
    status: &Mutex<NativeCeremonyStatus>,
    phase: NativeCeremonyPhase,
    comparison_code: Option<String>,
) {
    let mut status = status.lock().unwrap_or_else(|error| error.into_inner());
    status.phase = phase;
    status.comparison_code = comparison_code;
    status.failure = None;
}

fn map_bridge(error: BridgeError) -> NativeCeremonyFailure {
    match error {
        BridgeError::StorageUnavailable
        | BridgeError::OwnerFaulted
        | BridgeError::LocalKeysReconciliationRequired => NativeCeremonyFailure::Storage,
        BridgeError::Closed => NativeCeremonyFailure::Cancelled,
        BridgeError::InvalidObservation => NativeCeremonyFailure::Mismatch,
        _ => NativeCeremonyFailure::Unavailable,
    }
}

fn map_socket(error: SocketError) -> NativeCeremonyFailure {
    match error {
        SocketError::Cancelled => NativeCeremonyFailure::Cancelled,
        SocketError::ClockUnavailable | SocketError::ClockRegressed | SocketError::ClockRange => {
            NativeCeremonyFailure::Unavailable
        }
        SocketError::Transport(
            framed_transport::TransportError::ProtocolRejected
            | framed_transport::TransportError::InvalidOutboundFrame,
        ) => NativeCeremonyFailure::Rejected,
        _ => NativeCeremonyFailure::Network,
    }
}
