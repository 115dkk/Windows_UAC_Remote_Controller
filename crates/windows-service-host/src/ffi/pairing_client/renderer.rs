// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed final renderer bootstrap on its initial private desktop. NONVISUAL:
//! no window, QR, bitmap, font, switch, network, secret input or grant exists.

use super::{
    ClientEndpoint, Error as ClientError, PairingClient, PairingClientProgress, Stage,
    helper_launch::{PairingLaunchError as Error, RendererTerminal},
    peer_error_at,
};
use crate::{
    RendererInvocation,
    ffi::pairing_peer::renderer as native_renderer,
    pairing_handoff::{Frame, RendererObjects, RendererRequest},
};
use std::{
    ffi::{OsStr, OsString},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        StationsAndDesktops::{GetProcessWindowStation, GetThreadDesktop, UOI_NAME},
        Threading::{GetCurrentProcess, GetCurrentThread, GetCurrentThreadId},
    },
};

static INVOKED: AtomicBool = AtomicBool::new(false);
const POLL: Duration = Duration::from_millis(25);
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    HelloWrite,
    ObjectsWrite,
    AwaitBound,
    Bound,
    Terminal,
}
struct Owner {
    client: Option<PairingClient>,
    terminal: Option<RendererTerminal>,
    phase: Phase,
    invocation: RendererInvocation,
    objects: RendererObjects,
    cutoff: u64,
    deadline: Instant,
}
fn mapped(error: crate::PairingPeerError) -> Error {
    peer_error_at(Stage::QueryOwnIdentity, error).into()
}

pub(crate) fn run_pair_renderer(invocation: RendererInvocation) -> Result<(), Error> {
    if INVOKED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(Error::InvalidPhase);
    }
    // Mandatory one-shot creation record is a safety bound, never authority.
    // No fallback TTL; native service registration must independently agree.
    let cutoff = cutoff_record(std::env::vars_os())?;
    let (start, deadline) = native_renderer::budget_from_cutoff(cutoff).map_err(mapped)?;
    native_renderer::check_setup_cutoff(cutoff).map_err(mapped)?;
    let mut client = PairingClient::connect(ClientEndpoint::Renderer, start, deadline)?;
    client.inner_mut().fence()?;
    let connection = client
        .inner_ref()
        .connection
        .as_ref()
        .ok_or(Error::InvalidPhase)?;
    native_renderer::require_owner(&connection.own.token, connection.own.session)
        .map_err(mapped)?;
    let sid = connection.service_sid.clone();
    // SAFETY: borrowed actual current process/thread/desktop/station only. These
    // initial user-object handles are NEVER closed or attached elsewhere here.
    let process = unsafe { GetCurrentProcess() };
    let native_thread = unsafe { GetCurrentThread() };
    let thread_id = unsafe { GetCurrentThreadId() };
    let desktop = unsafe { GetThreadDesktop(thread_id) }
        .map_err(|error| mapped(native_renderer::native(2, error)))?;
    let station = unsafe { GetProcessWindowStation() }
        .map_err(|error| mapped(native_renderer::native(2, error)))?;
    native_renderer::verify_descriptor(process, native_renderer::Profile::Process, &sid)
        .map_err(mapped)?;
    native_renderer::verify_descriptor(native_thread, native_renderer::Profile::Thread, &sid)
        .map_err(mapped)?;
    native_renderer::verify_descriptor(HANDLE(desktop.0), native_renderer::Profile::Desktop, &sid)
        .map_err(mapped)?;
    native_renderer::check_station(HANDLE(station.0)).map_err(mapped)?;
    if native_renderer::object_text(HANDLE(desktop.0), UOI_NAME).map_err(mapped)?
        != native_renderer::display_name(invocation)
    {
        return Err(Error::Protocol);
    }
    let objects = RendererObjects {
        thread: thread_id,
        desktop: desktop.0 as usize as u64,
        station: station.0 as usize as u64,
    };
    let mut owner = Owner {
        client: Some(client),
        terminal: None,
        phase: Phase::HelloWrite,
        invocation,
        objects,
        cutoff,
        deadline,
    };
    let outcome = (|| {
        let hello = Frame::RendererHello(
            RendererRequest::new(invocation, cutoff).map_err(|_| Error::Protocol)?,
        );
        owner
            .client_mut()?
            .begin_write(&hello.encode().map_err(|_| Error::Protocol)?)?;
        loop {
            if owner.step()? {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::DeadlineElapsed.into());
            }
            thread::sleep(POLL.min(remaining));
        }
    })();
    if outcome.is_err() {
        owner.cancel();
    }
    loop {
        match owner.drain() {
            Ok(true) => break,
            Ok(false) => (),
            Err(error) => return outcome.and(Err(error)),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return outcome.and(Err(Error::CleanupUnconfirmed));
        }
        thread::sleep(POLL.min(remaining));
    }
    outcome
}
impl Owner {
    fn client_mut(&mut self) -> Result<&mut PairingClient, Error> {
        self.client.as_mut().ok_or(Error::InvalidPhase)
    }
    fn budget(&self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            return Err(ClientError::DeadlineElapsed.into());
        }
        native_renderer::check_cutoff(self.cutoff).map_err(mapped)?;
        if !matches!(self.phase, Phase::Bound | Phase::Terminal) {
            native_renderer::check_setup_cutoff(self.cutoff).map_err(mapped)?;
        }
        Ok(())
    }
    fn step(&mut self) -> Result<bool, Error> {
        self.budget()?;
        if self.phase == Phase::Terminal {
            let terminal = self.terminal.as_mut().ok_or(Error::InvalidPhase)?;
            if terminal.poll()? {
                terminal.finish()?;
                return Ok(true);
            }
            return Ok(false);
        }
        let progress = self.client_mut()?.poll()?;
        self.budget()?;
        match (self.phase, progress) {
            (_, PairingClientProgress::Pending) => (),
            (Phase::HelloWrite, PairingClientProgress::Written) => {
                let frame = Frame::RendererObjects {
                    invocation: self.invocation,
                    objects: self.objects,
                };
                self.client_mut()?
                    .begin_write(&frame.encode().map_err(|_| Error::Protocol)?)?;
                self.phase = Phase::ObjectsWrite;
            }
            (Phase::ObjectsWrite, PairingClientProgress::Written) => {
                self.client_mut()?.begin_read()?;
                self.phase = Phase::AwaitBound;
            }
            (Phase::AwaitBound | Phase::Bound, PairingClientProgress::Read(bytes)) => {
                // Only an actual normally authenticated completion reaches this
                // decoder. The terminal transfer cannot accept external bytes.
                match Frame::decode(&bytes).map_err(|_| Error::Protocol)? {
                    Frame::RendererBound(request)
                        if self.phase == Phase::AwaitBound
                            && request.invocation == self.invocation =>
                    {
                        if request.cutoff != self.cutoff {
                            return Err(Error::Protocol);
                        }
                        native_renderer::check_cutoff(request.cutoff).map_err(mapped)?;
                        self.phase = Phase::Bound;
                        self.client_mut()?.begin_read()?;
                    }
                    Frame::Close(id) if id == self.invocation.pending() => {
                        let client = self.client.take().ok_or(Error::InvalidPhase)?;
                        self.terminal = Some(RendererTerminal::after_close(client, id));
                        self.phase = Phase::Terminal; // Retain before possibly pending Ack.
                        self.terminal.as_mut().ok_or(Error::InvalidPhase)?.start()?;
                    }
                    _ => return Err(Error::Protocol),
                }
            }
            _ => return Err(Error::Protocol),
        }
        self.budget()?;
        Ok(false)
    }
    fn cancel(&mut self) {
        if let Some(client) = self.client.as_mut() {
            client.cancel();
        }
        if let Some(terminal) = self.terminal.as_mut() {
            terminal.cancel();
        }
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if let Some(client) = self.client.as_mut() {
            return client.drain().map_err(Into::into);
        }
        self.terminal.as_mut().ok_or(Error::InvalidPhase)?.drain()
    }
}
fn cutoff_record(values: impl IntoIterator<Item = (OsString, OsString)>) -> Result<u64, Error> {
    let mut found = None;
    for (index, (name, value)) in values.into_iter().enumerate() {
        if index >= 64 {
            return Err(Error::Protocol);
        }
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if name_text.eq_ignore_ascii_case(native_renderer::CUTOFF_ENV) {
            if name != OsStr::new(native_renderer::CUTOFF_ENV) || found.is_some() {
                return Err(Error::Protocol);
            }
            let value = value.to_str().ok_or(Error::Protocol)?;
            if value.len() != 16
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(Error::Protocol);
            }
            let value = u64::from_str_radix(value, 16).map_err(|_| Error::Protocol)?;
            if value == 0 || value > i64::MAX as u64 {
                return Err(Error::Protocol);
            }
            found = Some(value);
        }
    }
    found.ok_or(Error::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(name: &str, value: &str) -> (OsString, OsString) {
        (name.into(), value.into())
    }
    #[test]
    fn mandatory_creation_record_rejects_absence_alias_duplicates_and_malformed_values() {
        assert_eq!(
            cutoff_record([record(native_renderer::CUTOFF_ENV, "0000000000000001")]),
            Ok(1)
        );
        assert!(cutoff_record([]).is_err());
        for value in [
            "",
            "0",
            "0000000000000000",
            "000000000000000A",
            " 000000000000001",
            "ffffffffffffffff",
            "8000000000000000",
            "0000000000000001x",
        ] {
            assert!(cutoff_record([record(native_renderer::CUTOFF_ENV, value)]).is_err());
        }
        assert!(
            cutoff_record([record("uac_remote_renderer_cutoff_qpc", "0000000000000001")]).is_err()
        );
        assert!(
            cutoff_record([
                record(native_renderer::CUTOFF_ENV, "0000000000000001"),
                record(native_renderer::CUTOFF_ENV, "0000000000000002")
            ])
            .is_err()
        );
        assert!(
            cutoff_record([
                record(native_renderer::CUTOFF_ENV, "0000000000000001"),
                record("uac_remote_renderer_cutoff_qpc", "0000000000000001")
            ])
            .is_err()
        );
        // Parsed nonzero text is not provenance. Its absolute cutoff and original
        // service Hello binding are independently checked before readiness.
    }
}
