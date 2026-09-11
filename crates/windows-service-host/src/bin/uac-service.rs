// SPDX-License-Identifier: GPL-2.0-or-later
#![forbid(unsafe_code)]

use std::{
    io::{self, Write},
    process::ExitCode,
};
use windows_service_host::{Command, ServiceError};

fn run() -> Result<(), ServiceError> {
    let command = Command::parse(std::env::args_os().skip(1))?;
    if command == Command::Help {
        writeln!(
            io::stdout().lock(),
            "uac-service [status|service|install|start|stop|restart|uninstall|probe-once|help]\n\
             uac-service remove <32자리 소문자 휴대폰 식별자>\n\
             uac-service relay <숫자 IP:포트>\n\
             uac-service pair <64자리 소문자 공개 식별자>\n\
             uac-service pair-renderer <64자리 공개 식별자> <64자리 표시 식별자>\n\
             기본 동작은 상태 확인입니다. 설치·시작·중지·재시작·제거는 관리자 권한이 필요합니다.\n\
             서비스 실행 상태는 휴대폰 연결이나 Windows 승인 기능의 동작을 뜻하지 않습니다."
        )
        .map_err(|_| ServiceError::OutputUnavailable)?;
        return Ok(());
    }
    if command == Command::Service {
        return windows_service_host::dispatch_service();
    }
    if let Command::Pair(id) = command {
        // Captured/canonicalized once above. The helper path does not recapture
        // argv, retry, echo the identifier or produce an enrollment receipt.
        return windows_service_host::run_pair_helper(id);
    }
    if let Command::PairRenderer(invocation) = command {
        return windows_service_host::run_pair_renderer(invocation);
    }
    if command == Command::ProbeOnce {
        let accepted = windows_service_host::request_probe_once()?;
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &accepted)
            .map_err(|_| ServiceError::OutputUnavailable)?;
        return writeln!(output).map_err(|_| ServiceError::OutputUnavailable);
    }
    let snapshot = match command {
        Command::Status => windows_service_host::query_status(),
        Command::Install => windows_service_host::install(),
        Command::Start => windows_service_host::start(),
        Command::Stop => windows_service_host::stop(),
        Command::Restart => windows_service_host::restart(),
        Command::Uninstall => windows_service_host::uninstall(),
        Command::Relay(endpoint) => {
            windows_service_host::configure_relay(endpoint)?;
            windows_service_host::query_status()
        }
        Command::RemoveDevice(device) => {
            windows_service_host::remove_device(device)?;
            windows_service_host::query_status()
        }
        Command::Service
        | Command::Help
        | Command::ProbeOnce
        | Command::Pair(_)
        | Command::PairRenderer(_) => {
            return Err(ServiceError::InvalidArguments);
        }
    }?;
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, &snapshot).map_err(|_| ServiceError::OutputUnavailable)?;
    writeln!(output).map_err(|_| ServiceError::OutputUnavailable)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The fixed error schema deliberately cannot retain input or paths.
            let _ = writeln!(io::stderr().lock(), "{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
