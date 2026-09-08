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
            "uac-service [status|service|install|start|stop|restart|uninstall|help]\n\
             기본 동작은 상태 확인입니다. 설치·시작·중지·재시작·제거는 관리자 권한이 필요합니다.\n\
             서비스 실행 상태는 휴대폰 연결이나 Windows 승인 기능의 동작을 뜻하지 않습니다."
        )
        .map_err(|_| ServiceError::OutputUnavailable)?;
        return Ok(());
    }
    if command == Command::Service {
        return windows_service_host::dispatch_service();
    }
    let snapshot = match command {
        Command::Status => windows_service_host::query_status(),
        Command::Install => windows_service_host::install(),
        Command::Start => windows_service_host::start(),
        Command::Stop => windows_service_host::stop(),
        Command::Restart => windows_service_host::restart(),
        Command::Uninstall => windows_service_host::uninstall(),
        Command::Service | Command::Help => return Err(ServiceError::InvalidArguments),
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
