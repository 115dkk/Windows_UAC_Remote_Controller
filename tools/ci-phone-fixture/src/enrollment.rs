// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact original-invitation checks, pinned TLS, native-screen SAS comparison,
//! phone confirmation and independently verified signed acceptance.

use android_attestation::SyntheticRkp;
use serde_json::json;
use service_protocol::{
    CandidateSubmission, CandidateSubmissionFields, EnrollmentAcceptanceFields,
    FrozenCandidateContext, PairingConfirmation, PairingConfirmationFields, PairingInvitation,
    SignedEnrollmentAcceptance, SignedFrozenCandidate, candidate_digest,
    frame_plaintext_submission,
};
use tokio::io::{AsyncBufRead, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{
    Command, Result, STEP_LIMIT, close, command, connect, driver, emit, hex, next_frame, queue,
};

pub(super) async fn enroll(
    input: &mut (impl AsyncBufRead + Unpin),
    invitation: &PairingInvitation,
    candidate: &SyntheticRkp,
) -> Result<()> {
    let fields = invitation.fields();
    let [approval_key, denial_key, transport_key] = candidate.public_keys();
    let submission = CandidateSubmission::new(
        CandidateSubmissionFields {
            ceremony_nonce: fields.ceremony_nonce,
            attestation_challenge: fields.attestation_challenge,
            pc: fields.pc,
            recipient_device: fields.recipient_device,
            invitation_context: invitation.context_digest(),
            approval_key,
            denial_key,
            transport_key,
        },
        candidate.chains[0].clone(),
        candidate.chains[1].clone(),
        candidate.chains[2].clone(),
    )
    .map_err(|_| "submission_rejected")?;
    let context = FrozenCandidateContext {
        ceremony_nonce: fields.ceremony_nonce,
        attestation_challenge: fields.attestation_challenge,
        pc: fields.pc,
        recipient_device: fields.recipient_device,
        phone_keys: submission.phone_keys(),
        pc_signing_key: fields.pc_signing_key.clone(),
        pc_transport_key: fields.pc_transport_key.clone(),
        invitation_context: invitation.context_digest(),
    };
    let mut stream = connect(invitation).await?;
    tokio::time::timeout(
        STEP_LIMIT,
        stream.write_all(&frame_plaintext_submission(&submission)),
    )
    .await
    .map_err(|_| "submission_timeout")?
    .map_err(|_| "submission_failed")?;
    let mut socket = driver(stream, invitation, candidate)?;
    let wire = next_frame(&mut socket).await?;
    let matched = SignedFrozenCandidate::from_wire(&wire)
        .and_then(|value| value.verify(&fields.pc_signing_key))
        .and_then(|value| value.match_original(&context))
        .map_err(|_| "frozen_candidate_mismatch")?;
    let revision = matched.fields().intended_registry_revision;
    emit(json!({"state":"awaiting_comparison","identity":"software_ci_fixture"}))?;
    let Command::ConfirmComparison { code } = command(input).await? else {
        return Err("expected_comparison");
    };
    let code = Zeroizing::new(code);
    if code.len() != 6
        || !code.bytes().all(|byte| byte.is_ascii_digit())
        || code.as_str() != matched.comparison_code().as_str()
    {
        return Err("comparison_mismatch");
    }
    drop(code);
    let confirmation = PairingConfirmation::new(PairingConfirmationFields {
        ceremony_nonce: fields.ceremony_nonce,
        phone_keys: submission.phone_keys(),
        candidate_digest: candidate_digest(&wire),
        confirmed: true,
    })
    .map_err(|_| "confirmation_rejected")?;
    queue(&mut socket, &confirmation.to_wire())?;
    // This state records local intent only. Acceptance below is separate proof.
    emit(json!({"state":"phone_confirmation_queued","identity":"software_ci_fixture"}))?;
    let acceptance = SignedEnrollmentAcceptance::from_wire(&next_frame(&mut socket).await?)
        .and_then(|value| value.verify(&fields.pc_signing_key))
        .map_err(|_| "acceptance_signature_rejected")?;
    let expected = EnrollmentAcceptanceFields {
        ceremony_nonce: fields.ceremony_nonce,
        attestation_challenge: fields.attestation_challenge,
        pc: fields.pc,
        recipient_device: fields.recipient_device,
        registry_revision: revision,
        phone_keys: submission.phone_keys(),
        pc_signing_key: fields.pc_signing_key.clone(),
        pc_transport_key: fields.pc_transport_key.clone(),
    };
    if acceptance.fields() != &expected {
        return Err("acceptance_context_mismatch");
    }
    close(&mut socket).await?;
    emit(json!({
        "state":"enrollment_accepted",
        "identity":"software_ci_fixture",
        "device_id":hex(fields.recipient_device.as_bytes()),
        "registry_revision":revision
    }))
}
