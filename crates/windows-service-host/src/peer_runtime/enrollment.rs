// SPDX-License-Identifier: GPL-2.0-or-later
//! One bounded outbound enrollment carrier. The relay remains untrusted; exact
//! original-field checks, Android evidence and mutually pinned TLS precede use.
#![forbid(unsafe_code)]

use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use android_attestation::{
    CandidateEvidence, ExpectedKeyBundle, TrustedStatusSnapshot, VerificationError,
    VerificationPolicy, VerifiedKeyBundle, fetch_google_status, verify_key_bundle,
};
#[cfg(test)]
use android_attestation::{TestAttestationAnchor, verify_key_bundle_with_test_anchors};
use approval_protocol::{DeviceId, PcIdentity};
use framed_transport::{
    CancellationToken, ConnectionBudget, PeerTransport, SocketDriver, SocketEvent, SocketLimits,
};
use relay_service::{Registration, Role, RouteId, connect_rendezvous};
use secure_channel::{EndpointRole, TlsIdentity, TlsPublicKey};
use service_protocol::{
    CandidateSubmission, FrozenCandidateContext, FrozenCandidateFields, InvitationContextDigest,
    MatchedFrozenCandidate, PairingChallenge, PairingComparisonCode, PairingConfirmation,
    PairingInvitation, PairingNonce, SignedEnrollmentAcceptance, SignedFrozenCandidate,
    UnsignedFrozenCandidate, candidate_digest, ceremony_message_kind, encode_frame,
    plaintext_submission_length,
};
use tokio::{io::AsyncReadExt, sync::mpsc as async_mpsc};

use super::ServiceClock;
use crate::{RegistryError, tls_signer::ServiceTlsSigner};

const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(120);
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(150);
const ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(25);

pub(super) type VerifiedMaterial = (VerifiedKeyBundle, TrustedStatusSnapshot);

#[derive(Clone)]
pub(super) struct ExpectedOriginal {
    pub(super) nonce: PairingNonce,
    pub(super) challenge: PairingChallenge,
    pub(super) pc: PcIdentity,
    pub(super) recipient: DeviceId,
    pub(super) invitation_context: InvitationContextDigest,
    pub(super) intended_revision: u64,
    pub(super) policy: VerificationPolicy,
}
impl fmt::Debug for ExpectedOriginal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedOriginal([redacted], shape_only)")
    }
}

pub(super) struct EnrollmentInputs {
    pub(super) relay: SocketAddr,
    pub(super) route: RouteId,
    pub(super) invitation: PairingInvitation,
    pub(super) expected: ExpectedOriginal,
    pub(super) deadline: Instant,
    pub(super) signer: Arc<ServiceTlsSigner>,
    pub(super) pc_signing_key: TlsPublicKey,
    pub(super) pc_transport_key: TlsPublicKey,
    #[cfg(test)]
    pub(super) verification: Option<TestVerification>,
}

#[cfg(test)]
pub(super) struct TestVerification {
    pub(super) status: TrustedStatusSnapshot,
    pub(super) anchors: Vec<TestAttestationAnchor>,
}
impl fmt::Debug for EnrollmentInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrollmentInputs([redacted])")
    }
}

pub(super) enum EnrollmentProgress {
    Connecting,
    AwaitingSubmission,
    Verifying,
    CandidateSent { code: PairingComparisonCode },
    PhoneConfirmed,
    AwaitingPcDecision,
    Accepted,
    Closed,
}
impl Clone for EnrollmentProgress {
    fn clone(&self) -> Self {
        match self {
            Self::Connecting => Self::Connecting,
            Self::AwaitingSubmission => Self::AwaitingSubmission,
            Self::Verifying => Self::Verifying,
            Self::CandidateSent { code } => Self::CandidateSent { code: code.clone() },
            Self::PhoneConfirmed => Self::PhoneConfirmed,
            Self::AwaitingPcDecision => Self::AwaitingPcDecision,
            Self::Accepted => Self::Accepted,
            Self::Closed => Self::Closed,
        }
    }
}
impl fmt::Debug for EnrollmentProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => f.write_str("Connecting"),
            Self::AwaitingSubmission => f.write_str("AwaitingSubmission"),
            Self::Verifying => f.write_str("Verifying"),
            Self::CandidateSent { .. } => f.write_str("CandidateSent([redacted])"),
            Self::PhoneConfirmed => f.write_str("PhoneConfirmed"),
            Self::AwaitingPcDecision => f.write_str("AwaitingPcDecision"),
            Self::Accepted => f.write_str("Accepted"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum EnrollmentError {
    #[error("the relay is unavailable")]
    RelayUnavailable,
    #[error("the enrollment deadline expired")]
    Timeout,
    #[error("the enrollment protocol was rejected")]
    Protocol,
    #[error("Android key evidence was rejected")]
    Attestation(VerificationError),
    #[error("trusted Android status is unavailable")]
    StatusUnavailable,
    #[error("the registry rejected enrollment")]
    #[allow(dead_code)]
    Registry(RegistryError),
    #[error("PC signing failed")]
    Signing,
    #[error("the phone declined enrollment")]
    PhoneDeclined,
    #[error("the PC declined enrollment")]
    PcDeclined,
    #[error("enrollment was cancelled")]
    Cancelled,
}

#[derive(Clone)]
pub(super) struct CandidateSummary {
    pub(super) device: DeviceId,
    pub(super) phone_keys: service_protocol::PhoneKeyDigest,
    pub(super) approval_key: TlsPublicKey,
    pub(super) denial_key: TlsPublicKey,
    pub(super) transport_key: TlsPublicKey,
}
impl fmt::Debug for CandidateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CandidateSummary([redacted])")
    }
}

enum Command {
    Frozen(SignedFrozenCandidate),
    Decision(bool),
    Acceptance(SignedEnrollmentAcceptance),
    Cancel,
}
enum Event {
    AwaitingSubmission,
    Verifying,
    Verified {
        material: Box<VerifiedMaterial>,
        summary: Box<CandidateSummary>,
    },
    FrozenDrained,
    PhoneConfirmed,
    AwaitingPcDecision,
    Accepted,
    Closed,
    Failed(EnrollmentError),
}

pub(super) struct EnrollmentCarrier {
    commands: async_mpsc::Sender<Command>,
    events: mpsc::Receiver<Event>,
    thread: Option<JoinHandle<()>>,
    stop: CancellationToken,
    expected_context: FrozenCandidateContext,
    intended_revision: u64,
    verified: Option<VerifiedMaterial>,
    summary: Option<CandidateSummary>,
    candidate_device: Option<DeviceId>,
    progress: EnrollmentProgress,
    deadline: Instant,
    decision: Option<bool>,
    frozen_sent: bool,
}
impl fmt::Debug for EnrollmentCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentCarrier")
            .field("progress", &self.progress)
            .field(
                "thread_finished",
                &self.thread.as_ref().is_none_or(JoinHandle::is_finished),
            )
            .finish_non_exhaustive()
    }
}

impl EnrollmentCarrier {
    pub(super) fn start(inputs: EnrollmentInputs) -> Result<Self, EnrollmentError> {
        if Instant::now() >= inputs.deadline
            || inputs.invitation.fields().relay_address != inputs.relay
            || inputs.invitation.fields().route != *inputs.route.as_bytes()
            || inputs.invitation.context_digest() != inputs.expected.invitation_context
        {
            return Err(EnrollmentError::Protocol);
        }
        let expected_context = FrozenCandidateContext {
            ceremony_nonce: inputs.expected.nonce,
            attestation_challenge: inputs.expected.challenge,
            pc: inputs.expected.pc,
            recipient_device: inputs.expected.recipient,
            phone_keys: service_protocol::PhoneKeyDigest::from_bytes([0; 32]),
            pc_signing_key: inputs.pc_signing_key.clone(),
            pc_transport_key: inputs.pc_transport_key.clone(),
            invitation_context: inputs.expected.invitation_context,
        };
        let intended_revision = inputs.expected.intended_revision;
        let inputs_deadline = inputs.deadline;
        let stop = CancellationToken::new();
        let thread_stop = stop.clone();
        let (command_sender, commands) = async_mpsc::channel(3);
        let (event_sender, events) = mpsc::sync_channel(8);
        let (startup_sender, startup) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("service-enrollment-io".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let result = match runtime {
                    Ok(runtime) => {
                        if startup_sender.send(true).is_err() {
                            return;
                        }
                        runtime.block_on(run(inputs, commands, event_sender.clone(), thread_stop))
                    }
                    Err(_) => {
                        let _ = startup_sender.send(false);
                        return;
                    }
                };
                if let Err(error) = result {
                    let _ = event_sender.try_send(Event::Failed(error));
                }
            })
            .map_err(|_| EnrollmentError::RelayUnavailable)?;
        if startup.recv() != Ok(true) {
            stop.cancel();
            let _ = thread.join();
            return Err(EnrollmentError::RelayUnavailable);
        }
        Ok(Self {
            commands: command_sender,
            events,
            thread: Some(thread),
            stop,
            expected_context,
            intended_revision,
            verified: None,
            summary: None,
            candidate_device: None,
            progress: EnrollmentProgress::Connecting,
            deadline: inputs_deadline,
            decision: None,
            frozen_sent: false,
        })
    }

    pub(super) fn poll(&mut self, now: Instant) -> Result<EnrollmentProgress, EnrollmentError> {
        let next = match self.events.try_recv() {
            Ok(Event::AwaitingSubmission) => EnrollmentProgress::AwaitingSubmission,
            Ok(Event::Verifying) => EnrollmentProgress::Verifying,
            Ok(Event::Verified { material, summary }) => {
                let mut context = self.expected_context.clone();
                context.phone_keys = summary.phone_keys;
                self.expected_context = context;
                self.candidate_device = Some(summary.device);
                self.verified = Some(*material);
                self.summary = Some(*summary);
                EnrollmentProgress::Verifying
            }
            Ok(Event::FrozenDrained) => self.progress.clone(),
            Ok(Event::PhoneConfirmed) => EnrollmentProgress::PhoneConfirmed,
            Ok(Event::AwaitingPcDecision) => EnrollmentProgress::AwaitingPcDecision,
            Ok(Event::Accepted) => EnrollmentProgress::Accepted,
            Ok(Event::Closed) => EnrollmentProgress::Closed,
            Ok(Event::Failed(error)) => return Err(error),
            Err(mpsc::TryRecvError::Empty) => {
                if now >= self.deadline && !matches!(self.progress, EnrollmentProgress::Closed) {
                    self.cancel();
                    return Err(EnrollmentError::Timeout);
                }
                return Ok(self.progress.clone());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                    Err(EnrollmentError::Protocol)
                } else {
                    Ok(self.progress.clone())
                };
            }
        };
        self.progress = next;
        if now >= self.deadline && !matches!(self.progress, EnrollmentProgress::Closed) {
            self.cancel();
            return Err(EnrollmentError::Timeout);
        }
        Ok(self.progress.clone())
    }

    pub(super) fn ready_for_frozen(&self) -> bool {
        !self.frozen_sent
            && self.verified.is_some()
            && self.summary.is_some()
            && matches!(self.progress, EnrollmentProgress::Verifying)
    }

    pub(super) fn ready_to_commit(&self) -> bool {
        self.decision == Some(true)
            && self.verified.is_some()
            && self.summary.is_some()
            && matches!(self.progress, EnrollmentProgress::AwaitingPcDecision)
    }

    pub(super) fn candidate_device(&self) -> Option<DeviceId> {
        self.candidate_device
    }

    pub(super) fn unsigned_frozen(&self) -> Result<UnsignedFrozenCandidate, EnrollmentError> {
        if !self.ready_for_frozen() {
            return Err(EnrollmentError::Protocol);
        }
        UnsignedFrozenCandidate::new(FrozenCandidateFields {
            context: self.expected_context.clone(),
            intended_registry_revision: self.intended_revision,
        })
        .map_err(|_| EnrollmentError::Protocol)
    }

    pub(super) fn send_frozen(
        &mut self,
        frozen: SignedFrozenCandidate,
    ) -> Result<PairingComparisonCode, EnrollmentError> {
        if !self.ready_for_frozen() {
            return Err(EnrollmentError::Protocol);
        }
        let matched: MatchedFrozenCandidate = frozen
            .verify(&self.expected_context.pc_signing_key)
            .and_then(|value| value.match_original(&self.expected_context))
            .map_err(|_| EnrollmentError::Signing)?;
        if matched.fields().intended_registry_revision != self.intended_revision {
            return Err(EnrollmentError::Protocol);
        }
        let code = matched.comparison_code();
        self.commands
            .try_send(Command::Frozen(frozen))
            .map_err(|_| EnrollmentError::Protocol)?;
        self.verified.as_ref().ok_or(EnrollmentError::Protocol)?;
        self.frozen_sent = true;
        self.progress = EnrollmentProgress::CandidateSent { code: code.clone() };
        Ok(code)
    }

    pub(super) fn pc_decision(&mut self, confirmed: bool) -> Result<(), EnrollmentError> {
        if !matches!(
            self.progress,
            EnrollmentProgress::PhoneConfirmed | EnrollmentProgress::AwaitingPcDecision
        ) || self.decision.is_some()
        {
            return Err(EnrollmentError::Protocol);
        }
        self.commands
            .try_send(Command::Decision(confirmed))
            .map_err(|_| EnrollmentError::Protocol)?;
        self.decision = Some(confirmed);
        Ok(())
    }

    pub(super) fn take_verified(
        &mut self,
    ) -> Result<(VerifiedMaterial, CandidateSummary), EnrollmentError> {
        if !self.ready_to_commit() {
            return Err(EnrollmentError::Protocol);
        }
        Ok((
            self.verified.take().ok_or(EnrollmentError::Protocol)?,
            self.summary.take().ok_or(EnrollmentError::Protocol)?,
        ))
    }

    pub(super) fn send_acceptance(
        &mut self,
        acceptance: SignedEnrollmentAcceptance,
    ) -> Result<(), EnrollmentError> {
        if self.decision != Some(true)
            || !matches!(self.progress, EnrollmentProgress::AwaitingPcDecision)
        {
            return Err(EnrollmentError::Protocol);
        }
        let verified = acceptance
            .verify(&self.expected_context.pc_signing_key)
            .map_err(|_| EnrollmentError::Signing)?;
        let fields = verified.fields();
        if fields.ceremony_nonce != self.expected_context.ceremony_nonce
            || fields.attestation_challenge != self.expected_context.attestation_challenge
            || fields.pc != self.expected_context.pc
            || fields.recipient_device != self.expected_context.recipient_device
            || fields.registry_revision != self.intended_revision
            || fields.phone_keys != self.expected_context.phone_keys
            || fields.pc_signing_key != self.expected_context.pc_signing_key
            || fields.pc_transport_key != self.expected_context.pc_transport_key
        {
            return Err(EnrollmentError::Protocol);
        }
        self.commands
            .try_send(Command::Acceptance(acceptance))
            .map_err(|_| EnrollmentError::Protocol)
    }

    pub(super) fn cancel(&mut self) {
        self.stop.cancel();
        let _ = self.commands.try_send(Command::Cancel);
    }

    pub(super) fn drain(&mut self) -> bool {
        self.cancel();
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.thread.take().map(JoinHandle::join);
        }
        self.thread.is_none()
    }

    pub(super) fn remaining_owners(&self) -> usize {
        usize::from(self.thread.is_some())
    }
}
impl Drop for EnrollmentCarrier {
    fn drop(&mut self) {
        self.cancel();
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            let _ = self.thread.take().map(JoinHandle::join);
        }
    }
}

async fn run(
    inputs: EnrollmentInputs,
    mut commands: async_mpsc::Receiver<Command>,
    events: mpsc::SyncSender<Event>,
    stop: CancellationToken,
) -> Result<(), EnrollmentError> {
    let carrier = connect_rendezvous(
        inputs.relay,
        Registration::new(Role::Pc, inputs.route),
        stop.clone(),
    )
    .await
    .map_err(|error| {
        if stop.is_cancelled() {
            EnrollmentError::Cancelled
        } else {
            let _ = error;
            EnrollmentError::RelayUnavailable
        }
    })?;
    send_event(&events, Event::AwaitingSubmission)?;
    let mut socket = carrier.into_stream();
    let submission_deadline = step_deadline(inputs.deadline, SUBMISSION_TIMEOUT)?;
    let mut prefix = [0; 4];
    read_exact(&mut socket, &mut prefix, submission_deadline, &stop).await?;
    let length = plaintext_submission_length(prefix).map_err(|_| EnrollmentError::Protocol)?;
    let mut body = vec![0; length];
    read_exact(&mut socket, &mut body, submission_deadline, &stop).await?;
    let submission =
        CandidateSubmission::from_wire(&body).map_err(|_| EnrollmentError::Protocol)?;
    let fields = submission.fields().clone();
    if fields.ceremony_nonce != inputs.expected.nonce
        || fields.attestation_challenge != inputs.expected.challenge
        || fields.pc != inputs.expected.pc
        || fields.recipient_device != inputs.expected.recipient
        || fields.invitation_context != inputs.expected.invitation_context
    {
        return Err(EnrollmentError::Protocol);
    }
    send_event(&events, Event::Verifying)?;
    let verification_started = Instant::now();
    let expected = ExpectedKeyBundle::from_trusted_host(
        *inputs.expected.challenge.as_bytes(),
        fields.approval_key.clone(),
        fields.denial_key.clone(),
        fields.transport_key.clone(),
    )
    .map_err(EnrollmentError::Attestation)?;
    let approval: Vec<_> = submission
        .approval_chain()
        .iter()
        .map(Vec::as_slice)
        .collect();
    let denial: Vec<_> = submission
        .denial_chain()
        .iter()
        .map(Vec::as_slice)
        .collect();
    let transport: Vec<_> = submission
        .transport_chain()
        .iter()
        .map(Vec::as_slice)
        .collect();
    let evidence = CandidateEvidence::new(&approval, &denial, &transport)
        .map_err(EnrollmentError::Attestation)?;
    #[cfg(not(test))]
    let status = fetch_google_status().map_err(|error| match error {
        VerificationError::StatusUnavailable | VerificationError::StaleStatus => {
            EnrollmentError::StatusUnavailable
        }
        other => EnrollmentError::Attestation(other),
    })?;
    #[cfg(not(test))]
    let verified = verify_key_bundle(&evidence, &expected, &inputs.expected.policy, &status)
        .map_err(EnrollmentError::Attestation)?;
    #[cfg(test)]
    let (verified, status) = if let Some(test) = inputs.verification {
        let verified = verify_key_bundle_with_test_anchors(
            &evidence,
            &expected,
            &inputs.expected.policy,
            &test.status,
            &test.anchors,
        )
        .map_err(EnrollmentError::Attestation)?;
        (verified, test.status)
    } else {
        let status = fetch_google_status().map_err(|error| match error {
            VerificationError::StatusUnavailable | VerificationError::StaleStatus => {
                EnrollmentError::StatusUnavailable
            }
            other => EnrollmentError::Attestation(other),
        })?;
        let verified = verify_key_bundle(&evidence, &expected, &inputs.expected.policy, &status)
            .map_err(EnrollmentError::Attestation)?;
        (verified, status)
    };
    if verification_started.elapsed() >= VERIFICATION_TIMEOUT || Instant::now() >= inputs.deadline {
        return Err(EnrollmentError::Timeout);
    }
    let summary = CandidateSummary {
        device: fields.recipient_device,
        phone_keys: submission.phone_keys(),
        approval_key: fields.approval_key.clone(),
        denial_key: fields.denial_key.clone(),
        transport_key: fields.transport_key.clone(),
    };
    let identity = TlsIdentity::from_trusted_host(EndpointRole::Server, inputs.signer)
        .map_err(|_| EnrollmentError::Signing)?;
    if identity.public_key() != &inputs.pc_transport_key {
        return Err(EnrollmentError::Signing);
    }
    let transport_owner = PeerTransport::server(
        Arc::new(ConnectionBudget::new(1).map_err(|_| EnrollmentError::Protocol)?),
        identity,
        summary.transport_key.clone(),
        Instant::now(),
    )
    .map_err(|_| EnrollmentError::Protocol)?;
    let mut driver = SocketDriver::new(
        socket,
        transport_owner,
        Arc::new(ServiceClock),
        SocketLimits::default(),
        stop.clone(),
    )
    .map_err(|_| EnrollmentError::Protocol)?;
    await_ready(&mut driver, inputs.deadline, &stop).await?;
    send_event(
        &events,
        Event::Verified {
            material: Box::new((verified, status)),
            summary: Box::new(summary.clone()),
        },
    )?;
    let frozen = await_frozen(&mut driver, &mut commands, inputs.deadline, &stop).await?;
    let frozen_wire = frozen.to_wire();
    driver
        .queue_frame(encode_frame(&frozen_wire).map_err(|_| EnrollmentError::Protocol)?)
        .map_err(|_| EnrollmentError::Protocol)?;
    await_drain(
        &mut driver,
        step_deadline(inputs.deadline, ACCEPTANCE_TIMEOUT)?,
        &stop,
    )
    .await?;
    send_event(&events, Event::FrozenDrained)?;
    let confirmation_deadline = step_deadline(inputs.deadline, CONFIRMATION_TIMEOUT)?;
    let confirmation = await_confirmation(&mut driver, confirmation_deadline, &stop).await?;
    let fields = confirmation.fields();
    if fields.ceremony_nonce != inputs.expected.nonce
        || fields.phone_keys != summary.phone_keys
        || fields.candidate_digest != candidate_digest(&frozen_wire)
    {
        driver.abort();
        return Err(EnrollmentError::Protocol);
    }
    if !fields.confirmed {
        driver.abort();
        return Err(EnrollmentError::PhoneDeclined);
    }
    send_event(&events, Event::PhoneConfirmed)?;
    send_event(&events, Event::AwaitingPcDecision)?;
    let decision = await_decision(&mut driver, &mut commands, inputs.deadline, &stop).await?;
    if !decision {
        driver.abort();
        return Err(EnrollmentError::PcDeclined);
    }
    let acceptance = await_acceptance(&mut driver, &mut commands, inputs.deadline, &stop).await?;
    driver
        .queue_frame(encode_frame(&acceptance.to_wire()).map_err(|_| EnrollmentError::Protocol)?)
        .map_err(|_| EnrollmentError::Protocol)?;
    await_drain(
        &mut driver,
        step_deadline(inputs.deadline, ACCEPTANCE_TIMEOUT)?,
        &stop,
    )
    .await?;
    send_event(&events, Event::Accepted)?;
    driver
        .begin_close()
        .map_err(|_| EnrollmentError::Protocol)?;
    let close_deadline = step_deadline(inputs.deadline, CLOSE_TIMEOUT)?;
    loop {
        match next_socket_event(&mut driver, close_deadline, &stop).await? {
            SocketEvent::PeerClosed | SocketEvent::LocallyClosed => break,
            SocketEvent::Ready | SocketEvent::OutboundDrained => (),
            SocketEvent::Frame(_) => {
                driver.abort();
                return Err(EnrollmentError::Protocol);
            }
        }
    }
    send_event(&events, Event::Closed)
}

fn send_event(events: &mpsc::SyncSender<Event>, event: Event) -> Result<(), EnrollmentError> {
    events.try_send(event).map_err(|error| match error {
        mpsc::TrySendError::Full(_) => EnrollmentError::Protocol,
        mpsc::TrySendError::Disconnected(_) => EnrollmentError::Cancelled,
    })
}

fn step_deadline(whole: Instant, duration: Duration) -> Result<Instant, EnrollmentError> {
    let step = Instant::now()
        .checked_add(duration)
        .ok_or(EnrollmentError::Timeout)?;
    let deadline = step.min(whole);
    if Instant::now() >= deadline {
        Err(EnrollmentError::Timeout)
    } else {
        Ok(deadline)
    }
}
async fn read_exact(
    socket: &mut tokio::net::TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<(), EnrollmentError> {
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(EnrollmentError::Cancelled),
        result = tokio::time::timeout_at(deadline.into(), socket.read_exact(bytes)) => {
            result.map_err(|_| EnrollmentError::Timeout)?.map(|_| ()).map_err(|_| EnrollmentError::Protocol)
        }
    }
}
async fn next_socket_event(
    driver: &mut SocketDriver,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<SocketEvent, EnrollmentError> {
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(EnrollmentError::Cancelled),
        result = tokio::time::timeout_at(deadline.into(), driver.next_event()) => {
            result.map_err(|_| EnrollmentError::Timeout)?.map_err(|_| EnrollmentError::Protocol)
        }
    }
}
async fn await_ready(
    driver: &mut SocketDriver,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<(), EnrollmentError> {
    match next_socket_event(driver, deadline, stop).await? {
        SocketEvent::Ready => Ok(()),
        SocketEvent::Frame(_) | SocketEvent::OutboundDrained => {
            driver.abort();
            Err(EnrollmentError::Protocol)
        }
        SocketEvent::PeerClosed | SocketEvent::LocallyClosed => Err(EnrollmentError::Protocol),
    }
}
async fn await_drain(
    driver: &mut SocketDriver,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<(), EnrollmentError> {
    match next_socket_event(driver, deadline, stop).await? {
        SocketEvent::OutboundDrained => Ok(()),
        SocketEvent::Ready | SocketEvent::Frame(_) => {
            driver.abort();
            Err(EnrollmentError::Protocol)
        }
        SocketEvent::PeerClosed | SocketEvent::LocallyClosed => Err(EnrollmentError::Protocol),
    }
}
async fn await_confirmation(
    driver: &mut SocketDriver,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<PairingConfirmation, EnrollmentError> {
    match next_socket_event(driver, deadline, stop).await? {
        SocketEvent::Frame(frame) => {
            let bytes = frame.into_bytes();
            if ceremony_message_kind(&bytes)
                != Some(service_protocol::CeremonyMessageKind::Confirmation)
            {
                driver.abort();
                return Err(EnrollmentError::Protocol);
            }
            PairingConfirmation::from_wire(&bytes).map_err(|_| EnrollmentError::Protocol)
        }
        SocketEvent::Ready | SocketEvent::OutboundDrained => {
            driver.abort();
            Err(EnrollmentError::Protocol)
        }
        SocketEvent::PeerClosed | SocketEvent::LocallyClosed => Err(EnrollmentError::Protocol),
    }
}
async fn await_frozen(
    driver: &mut SocketDriver,
    commands: &mut async_mpsc::Receiver<Command>,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<SignedFrozenCandidate, EnrollmentError> {
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return Err(EnrollmentError::Cancelled),
            command = commands.recv() => match command {
                Some(Command::Frozen(value)) => return Ok(value),
                Some(Command::Cancel) | None => return Err(EnrollmentError::Cancelled),
                Some(Command::Decision(_) | Command::Acceptance(_)) => return Err(EnrollmentError::Protocol),
            },
            result = tokio::time::timeout_at(deadline.into(), driver.next_event()) => match result {
                Err(_) => return Err(EnrollmentError::Timeout),
                Ok(Ok(SocketEvent::PeerClosed | SocketEvent::LocallyClosed)) | Ok(Err(_)) => return Err(EnrollmentError::Protocol),
                Ok(Ok(_)) => { driver.abort(); return Err(EnrollmentError::Protocol); }
            },
            _ = tokio::time::sleep(POLL) => driver.observe_liveness().map_err(|_| EnrollmentError::Protocol)?,
        }
    }
}
async fn await_decision(
    driver: &mut SocketDriver,
    commands: &mut async_mpsc::Receiver<Command>,
    deadline: Instant,
    stop: &CancellationToken,
) -> Result<bool, EnrollmentError> {
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(EnrollmentError::Cancelled),
        command = commands.recv() => match command {
            Some(Command::Decision(value)) => Ok(value),
            Some(Command::Cancel) | None => Err(EnrollmentError::Cancelled),
            Some(_) => Err(EnrollmentError::Protocol),
        },
        result = tokio::time::timeout_at(deadline.into(), driver.next_event()) => match result {
            Err(_) => Err(EnrollmentError::Timeout),
            Ok(Ok(SocketEvent::PeerClosed | SocketEvent::LocallyClosed)) | Ok(Err(_)) => Err(EnrollmentError::Protocol),
            Ok(Ok(_)) => { driver.abort(); Err(EnrollmentError::Protocol) }
        },
    }
}
async fn await_acceptance(
    driver: &mut SocketDriver,
    commands: &mut async_mpsc::Receiver<Command>,
    whole: Instant,
    stop: &CancellationToken,
) -> Result<SignedEnrollmentAcceptance, EnrollmentError> {
    let deadline = step_deadline(whole, ACCEPTANCE_TIMEOUT)?;
    tokio::select! {
        biased;
        _ = stop.cancelled() => Err(EnrollmentError::Cancelled),
        command = commands.recv() => match command {
            Some(Command::Acceptance(value)) => Ok(value),
            Some(Command::Cancel) | None => Err(EnrollmentError::Cancelled),
            Some(_) => Err(EnrollmentError::Protocol),
        },
        result = tokio::time::timeout_at(deadline.into(), driver.next_event()) => match result {
            Err(_) => Err(EnrollmentError::Timeout),
            Ok(Ok(SocketEvent::PeerClosed | SocketEvent::LocallyClosed)) | Ok(Err(_)) => Err(EnrollmentError::Protocol),
            Ok(Ok(_)) => { driver.abort(); Err(EnrollmentError::Protocol) }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_runtime::tests::Identity;
    use approval_core::{DeviceKeys, PrivilegedDeviceRegistry, RegistryCheckpoint};
    use approval_protocol::DecisionPublicKey;
    use service_protocol::{
        CandidateSubmissionFields, EnrollmentAcceptanceFields, PairingConfirmationFields,
        PairingInvitationFields, PairingNonce, UnsignedEnrollmentAcceptance,
        frame_plaintext_submission,
    };
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::Barrier,
    };

    /// Loopback relay fixtures bind and drop ephemeral ports; running them one at
    /// a time keeps a freed port from being handed to a neighbouring test's PC.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Fixture {
        inputs: EnrollmentInputs,
        worker: crate::tls_signer::ServiceTlsSigningWorker<'static>,
        identity: &'static Identity,
        candidate: android_attestation::SyntheticRkp,
    }

    fn fixture(relay: SocketAddr, deadline: Instant) -> Fixture {
        let identity = Box::leak(Box::new(Identity::new()));
        let (signer, worker) = ServiceTlsSigner::for_test_key(identity).unwrap();
        let pc = PcIdentity::from_bytes([1; 32]).unwrap();
        let recipient = DeviceId::from_bytes([2; 16]).unwrap();
        let nonce = PairingNonce::from_bytes([3; 32]).unwrap();
        let challenge = PairingChallenge::from_bytes([7; 32]).unwrap();
        let route = RouteId::new([4; 32]).unwrap();
        let invitation = PairingInvitation::new(PairingInvitationFields {
            ceremony_nonce: nonce,
            attestation_challenge: challenge,
            pc,
            recipient_device: recipient,
            pc_signing_key: identity.public.clone(),
            pc_transport_key: identity.public.clone(),
            relay_address: relay,
            route: *route.as_bytes(),
        })
        .unwrap();
        let verification = android_attestation::SyntheticRkp::new();
        let status = TrustedStatusSnapshot::from_test_response(br#"{"entries":{}}"#).unwrap();
        let expected = ExpectedOriginal {
            nonce,
            challenge,
            pc,
            recipient,
            invitation_context: invitation.context_digest(),
            intended_revision: 41,
            policy: verification.policy.clone(),
        };
        Fixture {
            inputs: EnrollmentInputs {
                relay,
                route,
                invitation,
                expected,
                deadline,
                signer,
                pc_signing_key: identity.public.clone(),
                pc_transport_key: identity.public.clone(),
                verification: Some(TestVerification {
                    status,
                    anchors: vec![verification.anchor.clone()],
                }),
            },
            worker,
            identity,
            candidate: verification,
        }
    }

    fn drain(carrier: &mut EnrollmentCarrier) {
        carrier.cancel();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !carrier.drain() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
    }

    fn decision_key(key: &TlsPublicKey) -> DecisionPublicKey {
        DecisionPublicKey::from_sec1_bytes(&key.as_spki_der()[26..]).unwrap()
    }

    fn read_registration(stream: &mut TcpStream, expected: Registration) {
        let expected = expected.to_wire();
        let mut actual = vec![0; expected.len()];
        stream.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        stream.write_all(relay_service::READY_MARKER).unwrap();
    }

    fn pump_worker(worker: &mut crate::tls_signer::ServiceTlsSigningWorker<'_>) {
        // Once the carrier's I/O thread has released its signer the request
        // channel is closed; that is the normal end of a ceremony, not a failure.
        match worker.process_one() {
            Ok(_) | Err(crate::tls_signer::TlsSigningBridgeError::Closed) => (),
            Err(error) => panic!("signing worker failed: {error:?}"),
        }
    }

    fn wait_progress(
        carrier: &mut EnrollmentCarrier,
        worker: &mut crate::tls_signer::ServiceTlsSigningWorker<'_>,
        accepts: impl Fn(&EnrollmentProgress, &EnrollmentCarrier) -> bool,
    ) -> EnrollmentProgress {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            pump_worker(worker);
            match carrier.poll(Instant::now()) {
                Ok(progress) if accepts(&progress, carrier) => return progress,
                Ok(_) => assert!(Instant::now() < deadline),
                Err(error) => panic!("unexpected enrollment error: {error}"),
            }
            thread::yield_now();
        }
    }

    struct PhoneResult {
        frozen_wire: Vec<u8>,
        acceptance: Option<SignedEnrollmentAcceptance>,
    }

    fn submission(
        invitation: &PairingInvitation,
        candidate: &android_attestation::SyntheticRkp,
    ) -> CandidateSubmission {
        let [approval_key, denial_key, transport_key] = candidate.public_keys();
        CandidateSubmission::new(
            CandidateSubmissionFields {
                ceremony_nonce: invitation.fields().ceremony_nonce,
                attestation_challenge: invitation.fields().attestation_challenge,
                pc: invitation.fields().pc,
                recipient_device: invitation.fields().recipient_device,
                invitation_context: invitation.context_digest(),
                approval_key,
                denial_key,
                transport_key,
            },
            candidate.chains[0].clone(),
            candidate.chains[1].clone(),
            candidate.chains[2].clone(),
        )
        .unwrap()
    }

    fn wait_any_error(
        carrier: &mut EnrollmentCarrier,
        worker: &mut crate::tls_signer::ServiceTlsSigningWorker<'_>,
    ) -> EnrollmentError {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            pump_worker(worker);
            match carrier.poll(Instant::now()) {
                Err(error) => return error,
                Ok(_) => assert!(Instant::now() < deadline),
            }
            thread::yield_now();
        }
    }

    fn wait_error(
        carrier: &mut EnrollmentCarrier,
        worker: &mut crate::tls_signer::ServiceTlsSigningWorker<'_>,
        accepts: impl Fn(&EnrollmentError) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            pump_worker(worker);
            match carrier.poll(Instant::now()) {
                Err(error) if accepts(&error) => return,
                Err(error) => panic!("unexpected enrollment error: {error}"),
                Ok(_) => assert!(Instant::now() < deadline),
            }
            thread::yield_now();
        }
    }

    fn spawn_phone(
        listener: TcpListener,
        invitation: PairingInvitation,
        route: RouteId,
        candidate: android_attestation::SyntheticRkp,
        confirmed: bool,
        release_close: Arc<Barrier>,
    ) -> JoinHandle<PhoneResult> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_registration(&mut stream, Registration::new(Role::Pc, route));
            let submission = submission(&invitation, &candidate);
            stream
                .write_all(&frame_plaintext_submission(&submission))
                .unwrap();
            stream.set_nonblocking(true).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let identity = TlsIdentity::from_trusted_host(
                    EndpointRole::Client,
                    Arc::new(candidate.transport_signer()),
                )
                .unwrap();
                let transport = PeerTransport::client(
                    Arc::new(ConnectionBudget::new(1).unwrap()),
                    identity,
                    invitation.fields().pc_transport_key.clone(),
                    Instant::now(),
                )
                .unwrap();
                let mut driver = SocketDriver::new(
                    tokio::net::TcpStream::from_std(stream).unwrap(),
                    transport,
                    Arc::new(ServiceClock),
                    SocketLimits::default(),
                    CancellationToken::new(),
                )
                .unwrap();
                let frozen_wire = loop {
                    match driver.next_event().await.unwrap() {
                        SocketEvent::Frame(frame) => break frame.into_bytes(),
                        SocketEvent::Ready | SocketEvent::OutboundDrained => (),
                        SocketEvent::PeerClosed | SocketEvent::LocallyClosed => {
                            panic!("PC closed before frozen candidate")
                        }
                    }
                };
                let _verified_frozen = SignedFrozenCandidate::from_wire(&frozen_wire)
                    .unwrap()
                    .verify(&invitation.fields().pc_signing_key)
                    .unwrap();
                let confirmation = PairingConfirmation::new(PairingConfirmationFields {
                    ceremony_nonce: invitation.fields().ceremony_nonce,
                    phone_keys: submission.phone_keys(),
                    candidate_digest: candidate_digest(&frozen_wire),
                    confirmed,
                })
                .unwrap();
                driver
                    .queue_frame(encode_frame(&confirmation.to_wire()).unwrap())
                    .unwrap();
                while !matches!(driver.next_event().await, Ok(SocketEvent::OutboundDrained)) {}
                if !confirmed {
                    return PhoneResult {
                        frozen_wire,
                        acceptance: None,
                    };
                }
                let acceptance = loop {
                    match driver.next_event().await {
                        Ok(SocketEvent::Frame(frame)) => {
                            break SignedEnrollmentAcceptance::from_wire(&frame.into_bytes()).ok();
                        }
                        Ok(SocketEvent::PeerClosed | SocketEvent::LocallyClosed) | Err(_) => {
                            break None;
                        }
                        Ok(SocketEvent::Ready | SocketEvent::OutboundDrained) => (),
                    }
                };
                if acceptance.is_some() {
                    release_close.wait();
                    // The PC may already have closed after the acceptance; a
                    // close on a closing transport is not a phone-side failure.
                    let _ = driver.begin_close();
                    while !matches!(
                        driver.next_event().await,
                        Ok(SocketEvent::LocallyClosed | SocketEvent::PeerClosed) | Err(_)
                    ) {}
                }
                PhoneResult {
                    frozen_wire,
                    acceptance,
                }
            })
        })
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn loopback_enrollment_uses_exact_frozen_wire_and_committed_revision() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = listener.local_addr().unwrap();
        let fixture = fixture(relay, Instant::now() + Duration::from_secs(15));
        let invitation = fixture.inputs.invitation.clone();
        let route = fixture.inputs.route;
        let close = Arc::new(Barrier::new(2));
        let phone = spawn_phone(
            listener,
            invitation.clone(),
            route,
            fixture.candidate,
            true,
            Arc::clone(&close),
        );
        let mut worker = fixture.worker;
        let identity = fixture.identity;
        let checkpoint = RegistryCheckpoint::new(32, 41, Vec::new()).unwrap();
        let mut registry =
            PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint).unwrap();
        let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, carrier| {
            matches!(progress, EnrollmentProgress::Verifying) && carrier.ready_for_frozen()
        });
        let unsigned = carrier.unsigned_frozen().unwrap();
        let signature = identity.sign_protocol(&unsigned.signing_bytes());
        let frozen = unsigned.with_der_signature(&signature).unwrap();
        let expected_wire = frozen.to_wire();
        let expected_code = frozen
            .verify(&identity.public)
            .unwrap()
            .match_original(&carrier.expected_context)
            .unwrap()
            .comparison_code();
        assert_eq!(carrier.send_frozen(frozen).unwrap(), expected_code);
        wait_progress(&mut carrier, &mut worker, |progress, _carrier| {
            matches!(progress, EnrollmentProgress::PhoneConfirmed)
        });
        carrier.pc_decision(true).unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, carrier| {
            matches!(progress, EnrollmentProgress::AwaitingPcDecision) && carrier.ready_to_commit()
        });
        let (_, summary) = carrier.take_verified().unwrap();
        let keys = DeviceKeys::new(
            decision_key(&summary.approval_key),
            decision_key(&summary.denial_key),
        )
        .unwrap();
        registry
            .enroll_from_privileged_host(summary.device, keys)
            .unwrap();
        let committed = registry.checkpoint_for_privileged_host();
        let committed_revision = committed
            .entries()
            .iter()
            .find(|entry| entry.device_id() == summary.device)
            .unwrap()
            .revision();
        let unsigned = UnsignedEnrollmentAcceptance::new(EnrollmentAcceptanceFields {
            ceremony_nonce: invitation.fields().ceremony_nonce,
            attestation_challenge: invitation.fields().attestation_challenge,
            pc: invitation.fields().pc,
            recipient_device: summary.device,
            registry_revision: committed_revision,
            phone_keys: summary.phone_keys,
            pc_signing_key: identity.public.clone(),
            pc_transport_key: identity.public.clone(),
        })
        .unwrap();
        let signature = identity.sign_protocol(&unsigned.signing_bytes());
        carrier
            .send_acceptance(unsigned.with_der_signature(&signature).unwrap())
            .unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, _carrier| {
            matches!(progress, EnrollmentProgress::Accepted)
        });
        close.wait();
        wait_progress(&mut carrier, &mut worker, |progress, _carrier| {
            matches!(progress, EnrollmentProgress::Closed)
        });
        let result = phone.join().unwrap();
        assert_eq!(result.frozen_wire, expected_wire);
        let acceptance = result.acceptance.unwrap();
        assert_eq!(
            acceptance
                .verify(&identity.public)
                .unwrap()
                .fields()
                .registry_revision,
            committed_revision
        );
        drain(&mut carrier);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn every_original_submission_field_mismatch_is_rejected_before_tls() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        for changed in 0..5 {
            // A Windows loopback peer can reset the connection before the READY
            // marker is read, which the carrier reports as RelayUnavailable. That
            // case is retried; anything but a pre-TLS Protocol rejection fails.
            let mut attempts = 0;
            loop {
                attempts += 1;
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let relay = listener.local_addr().unwrap();
                let fixture = fixture(relay, Instant::now() + Duration::from_secs(10));
                let invitation = fixture.inputs.invitation.clone();
                let route = fixture.inputs.route;
                let candidate = fixture.candidate;
                let phone = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    read_registration(&mut stream, Registration::new(Role::Pc, route));
                    let original = submission(&invitation, &candidate);
                    let mut fields = original.fields().clone();
                    match changed {
                        0 => fields.ceremony_nonce = PairingNonce::from_bytes([9; 32]).unwrap(),
                        1 => {
                            fields.attestation_challenge =
                                PairingChallenge::from_bytes([9; 32]).unwrap()
                        }
                        2 => fields.pc = PcIdentity::from_bytes([9; 32]).unwrap(),
                        3 => fields.recipient_device = DeviceId::from_bytes([9; 16]).unwrap(),
                        4 => {
                            fields.invitation_context = InvitationContextDigest::from_bytes([9; 32])
                        }
                        _ => unreachable!(),
                    }
                    let changed = CandidateSubmission::new(
                        fields,
                        candidate.chains[0].clone(),
                        candidate.chains[1].clone(),
                        candidate.chains[2].clone(),
                    )
                    .unwrap();
                    stream
                        .write_all(&frame_plaintext_submission(&changed))
                        .unwrap();
                    // Keep the phone side open until the PC has read and rejected the
                    // submission: dropping a Windows socket early can reset the
                    // connection and discard the READY marker still in flight.
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut sink = [0u8; 64];
                    while matches!(stream.read(&mut sink), Ok(count) if count > 0) {}
                });
                let mut worker = fixture.worker;
                let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
                let outcome = wait_any_error(&mut carrier, &mut worker);
                phone.join().unwrap();
                drain(&mut carrier);
                match outcome {
                    EnrollmentError::Protocol => break,
                    EnrollmentError::RelayUnavailable if attempts < 3 => continue,
                    other => panic!("case {changed}: unexpected enrollment error: {other}"),
                }
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn phone_decline_stops_before_pc_decision_or_acceptance() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = listener.local_addr().unwrap();
        let fixture = fixture(relay, Instant::now() + Duration::from_secs(15));
        let invitation = fixture.inputs.invitation.clone();
        let route = fixture.inputs.route;
        let close = Arc::new(Barrier::new(1));
        let phone = spawn_phone(listener, invitation, route, fixture.candidate, false, close);
        let mut worker = fixture.worker;
        let identity = fixture.identity;
        let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, carrier| {
            matches!(progress, EnrollmentProgress::Verifying) && carrier.ready_for_frozen()
        });
        let unsigned = carrier.unsigned_frozen().unwrap();
        let signature = identity.sign_protocol(&unsigned.signing_bytes());
        carrier
            .send_frozen(unsigned.with_der_signature(&signature).unwrap())
            .unwrap();
        wait_error(&mut carrier, &mut worker, |error| {
            matches!(error, EnrollmentError::PhoneDeclined)
        });
        let result = phone.join().unwrap();
        assert!(result.acceptance.is_none());
        assert!(!carrier.ready_to_commit());
        drain(&mut carrier);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pc_decline_stops_before_verified_material_can_be_committed() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = listener.local_addr().unwrap();
        let fixture = fixture(relay, Instant::now() + Duration::from_secs(15));
        let invitation = fixture.inputs.invitation.clone();
        let route = fixture.inputs.route;
        let phone = spawn_phone(
            listener,
            invitation,
            route,
            fixture.candidate,
            true,
            Arc::new(Barrier::new(1)),
        );
        let mut worker = fixture.worker;
        let identity = fixture.identity;
        let checkpoint = RegistryCheckpoint::new(32, 41, Vec::new()).unwrap();
        let registry = PrivilegedDeviceRegistry::restore_for_privileged_host(checkpoint).unwrap();
        let before = registry.checkpoint_for_privileged_host();
        let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, carrier| {
            matches!(progress, EnrollmentProgress::Verifying) && carrier.ready_for_frozen()
        });
        let unsigned = carrier.unsigned_frozen().unwrap();
        let signature = identity.sign_protocol(&unsigned.signing_bytes());
        carrier
            .send_frozen(unsigned.with_der_signature(&signature).unwrap())
            .unwrap();
        wait_progress(&mut carrier, &mut worker, |progress, _carrier| {
            matches!(progress, EnrollmentProgress::PhoneConfirmed)
        });
        carrier.pc_decision(false).unwrap();
        wait_error(&mut carrier, &mut worker, |error| {
            matches!(error, EnrollmentError::PcDeclined)
        });
        assert!(!carrier.ready_to_commit());
        assert!(matches!(
            carrier.take_verified(),
            Err(EnrollmentError::Protocol)
        ));
        assert!(registry.checkpoint_for_privileged_host() == before);
        let result = phone.join().unwrap();
        assert!(result.acceptance.is_none());
        drain(&mut carrier);
    }

    #[test]
    fn relay_connection_failure_is_reported_and_thread_is_reclaimed() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = listener.local_addr().unwrap();
        drop(listener);
        let fixture = fixture(relay, Instant::now() + Duration::from_secs(5));
        let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match carrier.poll(Instant::now()) {
                Err(EnrollmentError::RelayUnavailable) => break,
                Err(error) => panic!("unexpected enrollment error: {error}"),
                Ok(_) => assert!(Instant::now() < deadline),
            }
            thread::yield_now();
        }
        drain(&mut carrier);
    }

    #[test]
    fn whole_deadline_cancels_a_phone_that_never_connects() {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = listener.local_addr().unwrap();
        let fixture = fixture(relay, Instant::now() + Duration::from_millis(50));
        let mut carrier = EnrollmentCarrier::start(fixture.inputs).unwrap();
        thread::park_timeout(Duration::from_millis(75));
        assert!(matches!(
            carrier.poll(Instant::now()),
            Err(EnrollmentError::Timeout)
        ));
        drain(&mut carrier);
        drop(listener);
    }
}
