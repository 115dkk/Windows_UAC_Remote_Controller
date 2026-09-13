// SPDX-License-Identifier: GPL-2.0-or-later
//! CI-only SOFTWARE phone, never Android hardware or biometric evidence.
//! No listening socket, approval operation, generic signer, file persistence,
//! key export or raw-input logging. One invitation, one denial, then exit.
#![forbid(unsafe_code)]

mod enrollment;
mod pixels;
mod session;
#[cfg(test)]
mod tests;

use std::{
    io::Write,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use android_attestation::SyntheticRkp;
use base64::{Engine, engine::general_purpose::STANDARD};
use framed_transport::{
    CancellationToken, ConnectionBudget, PeerTransport, SocketClock, SocketClockUnavailable,
    SocketDriver, SocketEvent, SocketLimits,
};
use relay_service::{Registration, Role, RouteId};
use secure_channel::{EndpointRole, TlsIdentity};
use serde::Deserialize;
use serde_json::json;
use service_protocol::PairingInvitation;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const MAX_COMMAND_BYTES: usize = 16 * 1024;
const MAX_PIXEL_COMMAND_BYTES: usize = 12 * 1024 * 1024;
const STEP_LIMIT: Duration = Duration::from_secs(120);

// Deliberately no Debug: these variants may contain a bootstrap invitation or
// a native-screen comparison code. Neither is suitable for logs/artifacts.
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Prepare {
        expected_relay_ip: Option<IpAddr>,
    },
    Enroll {
        qr: String,
    },
    EnrollPixels {
        png_base64: String,
    },
    ConfirmComparison {
        code: String,
    },
    DenyNext {
        expected_program_name: String,
        expected_path: String,
        expected_details_sha256: Option<String>,
    },
}

#[derive(Debug)]
struct CiClock;

impl SocketClock for CiClock {
    fn now(&self) -> std::result::Result<Instant, SocketClockUnavailable> {
        Ok(Instant::now())
    }
}

fn main() {
    // Third-party panic messages never reach CI logs with live request data.
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| -> Result<()> {
        require_ci()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "runtime_unavailable")?;
        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(300), run())
                .await
                .map_err(|_| "whole_run_timeout")?
        });
        // Tokio stdin uses a blocking reader. A harness that closes no pipe
        // must not keep this bounded CI process alive after the whole timeout.
        runtime.shutdown_timeout(Duration::from_secs(1));
        result
    });
    match result {
        Ok(Ok(())) => (),
        Ok(Err(reason)) => {
            let _ =
                emit(json!({"state":"failed","reason":reason,"identity":"software_ci_fixture"}));
            std::process::exit(1);
        }
        Err(_) => {
            let _ = emit(
                json!({"state":"failed","reason":"fixture_panic","identity":"software_ci_fixture"}),
            );
            std::process::exit(1);
        }
    }
}

fn require_ci() -> Result<()> {
    if !cfg!(target_os = "windows")
        || std::env::args_os().len() != 1
        || std::env::var("CI").as_deref() != Ok("true")
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_OS").as_deref() != Ok("Windows")
        || std::env::var("WUAC_CI_PHONE_FIXTURE").as_deref() != Ok("1")
        || !std::env::var("GITHUB_RUN_ID")
            .is_ok_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err("ci_only");
    }
    Ok(())
}

async fn run() -> Result<()> {
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let Command::Prepare { expected_relay_ip } = command(&mut input).await? else {
        return Err("expected_prepare");
    };
    // ROOT's runner harness may select an address it has verified belongs to
    // this runner's interface (the embedded relay advertises the LAN address).
    // That trusted local control input is independent of the scanned QR.
    let expected_relay_ip = expected_relay_ip.unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if expected_relay_ip.is_unspecified() || expected_relay_ip.is_multicast() {
        return Err("invalid_expected_relay_ip");
    }
    let mut candidate = SyntheticRkp::new();
    let root = candidate.chains[0].last().ok_or("synthetic_root_missing")?;
    emit(json!({
        "state":"prepared",
        "identity":"software_ci_fixture",
        "root_der_base64":STANDARD.encode(root),
        "app_signer_sha256":hex(&[8;32]),
        "package_name":"dev.dkk115.uacremote",
        "hardware_attestation_verified":false,
        "biometrics_verified":false
    }))?;
    let qr = match command(&mut input).await? {
        Command::Enroll { qr } => Zeroizing::new(qr),
        Command::EnrollPixels { png_base64 } => pixels::decode(Zeroizing::new(png_base64))?,
        _ => return Err("expected_enroll"),
    };
    let invitation = PairingInvitation::from_qr_text(&qr).map_err(|_| "invalid_invitation")?;
    drop(qr);
    if invitation.fields().relay_address.ip() != expected_relay_ip
        || invitation.fields().relay_address.port() != 7443
    {
        return Err("relay_endpoint_mismatch");
    }
    candidate
        .reissue_for_challenge(*invitation.fields().attestation_challenge.as_bytes())
        .map_err(|_| "synthetic_challenge_rejected")?;
    enrollment::enroll(&mut input, &invitation, &candidate).await?;
    let Command::DenyNext {
        expected_program_name,
        expected_path,
        expected_details_sha256,
    } = command(&mut input).await?
    else {
        return Err("expected_deny_next");
    };
    session::deny_next(
        &invitation,
        &candidate,
        &expected_program_name,
        &expected_path,
        expected_details_sha256.as_deref(),
    )
    .await
}

async fn command(input: &mut (impl AsyncBufRead + Unpin)) -> Result<Command> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let available = input.fill_buf().await.map_err(|_| "stdin_unavailable")?;
        if available.is_empty() {
            return Err("stdin_closed");
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(count) > MAX_PIXEL_COMMAND_BYTES {
            return Err("command_too_large");
        }
        bytes.extend_from_slice(&available[..count]);
        input.consume(count);
        if newline.is_some() {
            let command = serde_json::from_slice(&bytes).map_err(|_| "invalid_command")?;
            if bytes.len() > MAX_COMMAND_BYTES && !matches!(command, Command::EnrollPixels { .. }) {
                return Err("command_too_large");
            }
            return Ok(command);
        }
    }
}

fn emit(value: serde_json::Value) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value).map_err(|_| "stdout_unavailable")?;
    output.write_all(b"\n").map_err(|_| "stdout_unavailable")?;
    output.flush().map_err(|_| "stdout_unavailable")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)] as char,
                DIGITS[usize::from(byte & 15)] as char,
            ]
        })
        .collect()
}

async fn connect(invitation: &PairingInvitation) -> Result<tokio::net::TcpStream> {
    let fields = invitation.fields();
    let route = RouteId::new(fields.route).map_err(|_| "invalid_route")?;
    tokio::time::timeout(
        STEP_LIMIT,
        relay_service::connect_rendezvous(
            fields.relay_address,
            Registration::new(Role::Phone, route),
            CancellationToken::new(),
        ),
    )
    .await
    .map_err(|_| "relay_timeout")?
    .map(|carrier| carrier.into_stream())
    .map_err(|_| "relay_unavailable")
}

fn driver(
    stream: tokio::net::TcpStream,
    invitation: &PairingInvitation,
    candidate: &SyntheticRkp,
) -> Result<SocketDriver> {
    let identity = TlsIdentity::from_trusted_host(
        EndpointRole::Client,
        Arc::new(candidate.transport_signer()),
    )
    .map_err(|_| "tls_identity_rejected")?;
    let budget = Arc::new(ConnectionBudget::new(1).map_err(|_| "transport_budget")?);
    let transport = PeerTransport::client(
        budget,
        identity,
        invitation.fields().pc_transport_key.clone(),
        Instant::now(),
    )
    .map_err(|_| "tls_pin_rejected")?;
    SocketDriver::new(
        stream,
        transport,
        Arc::new(CiClock),
        SocketLimits::default(),
        CancellationToken::new(),
    )
    .map_err(|_| "socket_rejected")
}

async fn next_frame(driver: &mut SocketDriver) -> Result<Vec<u8>> {
    tokio::time::timeout(STEP_LIMIT, async {
        loop {
            match driver.next_event().await.map_err(|_| "transport_failed")? {
                SocketEvent::Frame(frame) => return Ok(frame.into_bytes()),
                SocketEvent::Ready | SocketEvent::OutboundDrained => (),
                SocketEvent::PeerClosed | SocketEvent::LocallyClosed => return Err("peer_closed"),
            }
        }
    })
    .await
    .map_err(|_| "frame_timeout")?
}

fn queue(driver: &mut SocketDriver, bytes: &[u8]) -> Result<()> {
    let frame = service_protocol::encode_frame(bytes).map_err(|_| "frame_rejected")?;
    driver.queue_frame(frame).map_err(|_| "outbound_rejected")
}

async fn close(driver: &mut SocketDriver) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut closing = false;
        loop {
            if !closing {
                match driver.begin_close() {
                    Ok(()) => closing = true,
                    // The PC may have coalesced its close_notify with the last
                    // authenticated frame. Consume that existing close before
                    // declaring success; never mistake NotReady for closure.
                    Err(framed_transport::SocketError::Transport(
                        framed_transport::TransportError::Busy
                        | framed_transport::TransportError::NotReady,
                    )) => (),
                    Err(_) => return Err("close_rejected"),
                }
            }
            match driver.next_event().await.map_err(|_| "close_failed")? {
                SocketEvent::PeerClosed | SocketEvent::LocallyClosed => return Ok(()),
                SocketEvent::Ready | SocketEvent::OutboundDrained => (),
                SocketEvent::Frame(_) => return Err("unexpected_frame_on_close"),
            }
        }
    })
    .await
    .map_err(|_| "close_timeout")?
}
