// SPDX-License-Identifier: GPL-2.0-or-later
//! One clock-correlated, CI-marker-bound, enrolled-key DENIAL roundtrip.

use std::time::Instant;

use android_attestation::SyntheticRkp;
use approval_protocol::{RequestBinding, RequestContent};
use framed_transport::SocketEvent;
use serde_json::json;
use service_protocol::{
    ClockProbe, PairingInvitation, PcEvent, PcPublicKey, RequestResolution, VerifiedPcEvent,
};
use sha2::{Digest, Sha256};

use crate::{Result, STEP_LIMIT, close, connect, driver, emit, hex, next_frame, queue};

const CI_PROGRAM_MARKER: &str = "UacCiHarmlessRequest";

pub(super) async fn deny_next(
    invitation: &PairingInvitation,
    candidate: &SyntheticRkp,
    expected_program_name: &str,
    expected_path: &str,
    expected_details_sha256: Option<&str>,
) -> Result<()> {
    validate_expectation(
        expected_program_name,
        expected_path,
        expected_details_sha256,
    )?;
    let fields = invitation.fields();
    let mut socket = driver(connect(invitation).await?, invitation, candidate)?;
    tokio::time::timeout(STEP_LIMIT, async {
        loop {
            match socket
                .next_event()
                .await
                .map_err(|_| "session_tls_failed")?
            {
                SocketEvent::Ready => return Ok(()),
                SocketEvent::OutboundDrained => (),
                _ => return Err("session_not_ready"),
            }
        }
    })
    .await
    .map_err(|_| "session_tls_timeout")??;
    let base = Instant::now();
    let probe = ClockProbe::start(fields.pc, nanos(base)?).map_err(|_| "clock_probe_failed")?;
    queue(&mut socket, &probe.request().to_wire())?;
    let key = PcPublicKey::from_spki_der(fields.pc_signing_key.as_spki_der())
        .map_err(|_| "pc_signing_key_rejected")?;
    let clock_wire = next_frame(&mut socket).await?;
    let clock = VerifiedPcEvent::from_wire(&clock_wire, fields.pc, &key)
        .map_err(|_| "clock_signature_rejected")?;
    let mut correlation = probe
        .complete(&clock, nanos(base)?)
        .map_err(|_| "clock_mismatch")?;
    emit(json!({"state":"session_ready","identity":"software_ci_fixture"}))?;

    let opened_wire = next_frame(&mut socket).await?;
    let opened = VerifiedPcEvent::from_wire(&opened_wire, fields.pc, &key)
        .map_err(|_| "request_signature_rejected")?;
    let PcEvent::Opened {
        binding,
        issued_at,
        content,
    } = opened.event()
    else {
        return Err("expected_opened_request");
    };
    correlation
        .map_request(&opened, nanos(base)?)
        .map_err(|_| "request_not_fresh")?;
    match_metadata(
        content,
        *binding,
        expected_program_name,
        expected_path,
        expected_details_sha256,
    )?;
    emit(json!({
        "state":"request_verified",
        "identity":"software_ci_fixture",
        "request_id":hex(binding.request_id().as_bytes()),
        "content_digest":hex(binding.content_digest().as_bytes())
    }))?;
    // The statement comes ONLY from the verified matching Opened event. There
    // is no command that supplies a binding, key selector or arbitrary bytes.
    let denial = candidate
        .sign_denial(*binding, fields.recipient_device)
        .map_err(|_| "denial_signing_failed")?;
    correlation
        .map_request(&opened, nanos(base)?)
        .map_err(|_| "request_expired_before_send")?;
    queue(&mut socket, &denial.to_wire())?;
    emit(json!({"state":"denial_queued","identity":"software_ci_fixture"}))?;
    let resolved_wire = next_frame(&mut socket).await?;
    let resolved = VerifiedPcEvent::from_wire(&resolved_wire, fields.pc, &key)
        .map_err(|_| "resolution_signature_rejected")?;
    let PcEvent::Resolved {
        binding: resolved_binding,
        issued_at: resolved_issued,
        outcome,
    } = resolved.event()
    else {
        return Err("expected_resolution");
    };
    if resolved_binding != binding || resolved_issued != issued_at {
        return Err("resolution_binding_mismatch");
    }
    let outcome_name = match outcome {
        RequestResolution::Denied => "denied",
        RequestResolution::Approved => "approved",
        RequestResolution::Cancelled => "cancelled",
        RequestResolution::Expired => "expired",
        RequestResolution::Failed => "failed",
    };
    emit(json!({
        "state":"pc_resolution",
        "identity":"software_ci_fixture",
        "request_id":hex(binding.request_id().as_bytes()),
        "content_digest":hex(binding.content_digest().as_bytes()),
        "outcome":outcome_name
    }))?;
    if *outcome != RequestResolution::Denied {
        return Err("pc_did_not_report_denied");
    }
    close(&mut socket).await?;
    emit(
        json!({"state":"completed","identity":"software_ci_fixture","native_android_verified":false}),
    )
}

fn nanos(base: Instant) -> Result<u64> {
    u64::try_from(base.elapsed().as_nanos()).map_err(|_| "clock_range")
}

fn validate_expectation(marker: &str, path: &str, details_hash: Option<&str>) -> Result<()> {
    if marker != CI_PROGRAM_MARKER
        || path.is_empty()
        || details_hash.is_some_and(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return Err("invalid_request_expectation");
    }
    Ok(())
}

pub(super) fn match_metadata(
    content: &RequestContent,
    binding: RequestBinding,
    marker: &str,
    expected_path: &str,
    expected_details_sha256: Option<&str>,
) -> Result<()> {
    validate_expectation(marker, expected_path, expected_details_sha256)?;
    // VerifiedPcEvent::from_wire already verifies the signature before parsing
    // and calls PcEvent::validate, which recomputes this exact content digest.
    // Keep the explicit local guard so metadata matching cannot accidentally
    // become a substitute for request-binding verification during refactoring.
    if content.digest() != binding.content_digest() {
        return Err("request_content_digest_mismatch");
    }
    let marker_in_details = content.details().contains(marker);
    let path_matches = if content.path().is_empty() {
        // A collapsed native UAC view may omit the path. A program caption
        // alone is then insufficient: the actual details must retain our marker.
        marker_in_details
    } else {
        content.path() == expected_path
    };
    if !(content.program_name().contains(marker) || marker_in_details)
        || !path_matches
        || expected_details_sha256
            .is_some_and(|hash| hex(&Sha256::digest(content.details().as_bytes())) != hash)
    {
        return Err("request_metadata_mismatch");
    }
    Ok(())
}
