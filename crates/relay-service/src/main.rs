// SPDX-License-Identifier: GPL-2.0-or-later
//! Optional foreground CLI. It does not install or launch a system daemon.
#![forbid(unsafe_code)]

use std::{ffi::OsStr, net::SocketAddr, process::ExitCode};

use relay_service::{CancellationToken, RelayLimits, run};
use tokio::net::TcpListener;

enum Arguments {
    Help,
    Listen(SocketAddr),
}

fn arguments() -> Result<Arguments, &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let Some(first) = arguments.next() else {
        return Ok(Arguments::Listen(SocketAddr::from(([127, 0, 0, 1], 7443))));
    };
    if first == OsStr::new("--help") || first == OsStr::new("-h") {
        return if arguments.next().is_none() {
            Ok(Arguments::Help)
        } else {
            Err("unsupported relay arguments; use --help")
        };
    }
    if first != OsStr::new("--listen") {
        return Err("unsupported relay arguments; use --help");
    }
    let address = arguments
        .next()
        .ok_or("--listen requires a numeric socket address")?;
    if arguments.next().is_some() {
        return Err("unsupported relay arguments; use --help");
    }
    let address = address
        .to_str()
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .ok_or("--listen requires a numeric socket address")?;
    Ok(Arguments::Listen(address))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let address = match arguments() {
        Ok(Arguments::Help) => {
            println!(
                "relay-service [--listen IP:PORT]\n\
                Default: 127.0.0.1:7443 (loopback only).\n\
                Non-loopback binding requires an explicit --listen argument.\n\
                This is an untrusted opaque TCP carrier, not an approval/authentication server.\n\
                Endpoints must mutually pin inner TLS peers after WUACPAIR\\0; no plaintext fallback.\n\
                Ctrl+C cancels waiting and active connections. No daemon is installed."
            );
            return ExitCode::SUCCESS;
        }
        Ok(Arguments::Listen(address)) => address,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("relay listener could not be bound");
            return ExitCode::FAILURE;
        }
    };
    let cancellation = CancellationToken::new();
    let running = run(listener, RelayLimits::default(), cancellation.clone());
    tokio::pin!(running);
    let result = tokio::select! {
        result = &mut running => result,
        signal = tokio::signal::ctrl_c() => {
            cancellation.cancel();
            let result = running.await;
            if signal.is_err() {
                eprintln!("relay shutdown signal could not be observed");
                return ExitCode::FAILURE;
            }
            result
        }
    };
    match result {
        Ok(report) => {
            println!(
                "relay stopped: accepted={}, routing_matches={}, capacity_rejections={}, remaining_connections={}",
                report.accepted,
                report.paired,
                report.rejected_capacity,
                report.remaining_connections
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
