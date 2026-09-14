// SPDX-License-Identifier: GPL-2.0-or-later
//! Native checks run by the fixed service-created SYSTEM child in WinSta0.
//! The Session0 parent independently retains the original renderer identity and
//! all policy/image/token checks; this owner retains the actual USER objects.
use super::*;
use windows_prompt_probe::pairing_inspection::{Binding, Failure, Inspector};

#[derive(Default)]
pub(in crate::ffi) struct NativeInspector {
    bound: Option<Bound>,
    claimed: bool,
    failed: bool,
}
struct Bound {
    binding: Binding,
    process: Handle,
    thread: Handle,
    token: TokenFacts,
    session: SessionEpoch,
    desktop: Option<UserObject>,
    station: Option<UserObject>,
    sid: Vec<u8>,
    invocation: RendererInvocation,
}
fn failure(error: Error) -> Failure {
    match error {
        Error::Service(ServiceError::RendererNative { stage, hresult }) => {
            Failure { stage, hresult }
        }
        Error::Native { hresult, .. } => Failure { stage: 23, hresult },
        _ => Failure {
            stage: 23,
            hresult: 0x8007_000d_u32 as i32,
        },
    }
}
fn object_stage(stage: u8, error: Error) -> Error {
    match error {
        Error::Service(ServiceError::RendererNative { stage: 2, hresult }) => {
            Error::Service(ServiceError::RendererNative { stage, hresult })
        }
        _ => error,
    }
}
impl Inspector for NativeInspector {
    fn bind(&mut self, binding: Binding) -> Result<(), Failure> {
        let result = (|| {
            if self.claimed {
                return Err(Error::InvalidPhase);
            }
            self.claimed = true;
            check_cutoff(binding.cutoff)?;
            let (own, station) = unsafe {
                // SAFETY: borrowed own process/station; not closed or changed.
                (
                    GetCurrentProcess(),
                    windows::Win32::System::StationsAndDesktops::GetProcessWindowStation(),
                )
            };
            let own = TokenFacts::observe(own)?;
            let session = SessionEpoch::observe(own.session)?;
            check_station(HANDLE(station.map_err(|e| native(24, e))?.0))
                .map_err(|error| object_stage(24, error))?;
            let invocation = RendererInvocation::new(
                crate::PendingElevationId::from_bytes(binding.pending).map_err(Error::Service)?,
                crate::PendingElevationId::from_bytes(binding.display).map_err(Error::Service)?,
            )
            .map_err(Error::Service)?;
            let sid = OwnServiceSid::lookup().map_err(Error::Service)?.bytes();
            // SAFETY: candidate supplied only by actual SCM SYSTEM parent on its
            // authenticated PID-bound channel, read/duplicate/synchronize only.
            let process = Handle::new(
                unsafe {
                    OpenProcess(
                        PROCESS_ACCESS_RIGHTS(PROCESS_RIGHTS),
                        false,
                        binding.process,
                    )
                }
                .map_err(|e| native(3, e))?,
                super::super::PairingPeerStage::QueryProcess,
            )?;
            let thread = Handle::new(
                unsafe { OpenThread(THREAD_ACCESS_RIGHTS(THREAD_RIGHTS), false, binding.thread) }
                    .map_err(|e| native(3, e))?,
                super::super::PairingPeerStage::QueryProcess,
            )?;
            let token = TokenFacts::observe(process.raw())?;
            require_owner(&token, session.id)?;
            self.bound = Some(Bound {
                binding,
                process,
                thread,
                token,
                session,
                desktop: None,
                station: None,
                sid,
                invocation,
            });
            let bound = self.bound.as_mut().ok_or(Error::InvalidPhase)?;
            bound.identity()?;
            duplicate_object(
                bound.process.raw(),
                binding.desktop,
                DESKTOP_INSPECT,
                5,
                &mut bound.desktop,
            )
            .map_err(|error| object_stage(25, error))?;
            duplicate_object(
                bound.process.raw(),
                binding.station,
                STATION_INSPECT,
                21,
                &mut bound.station,
            )
            .map_err(|error| object_stage(26, error))?;
            bound.check()
        })();
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(failure)
    }
    fn check(&mut self) -> Result<(), Failure> {
        let result = if self.failed {
            Err(Error::Rejected)
        } else {
            self.bound
                .as_ref()
                .ok_or(Error::InvalidPhase)
                .and_then(Bound::check)
        };
        if result.is_err() {
            self.failed = true;
        }
        result.map_err(failure)
    }
    fn close(&mut self) -> Result<(), Failure> {
        if let Some(bound) = self.bound.as_mut() {
            for object in [&mut bound.desktop, &mut bound.station]
                .into_iter()
                .flatten()
            {
                object.close().map_err(failure)?;
            }
        }
        self.bound = None;
        cleanup_state().map_err(failure)
    }
}
impl Bound {
    fn identity(&self) -> Result<(), Error> {
        check_cutoff(self.binding.cutoff)?;
        if process_identity(self.process.raw(), self.binding.process)? != self.binding.created
            || thread_creation(self.thread.raw())? != self.binding.thread_created
            // SAFETY: exact retained initial-thread query handle.
            || unsafe { GetProcessIdOfThread(self.thread.raw()) } != self.binding.process
            || TokenFacts::observe(self.process.raw())? != self.token
            || SessionEpoch::observe(self.session.id)? != self.session
        {
            return Err(Error::Rejected);
        }
        require_owner(&self.token, self.session.id)?;
        verify_descriptor(self.process.raw(), Profile::Process, &self.sid)?;
        verify_descriptor(self.thread.raw(), Profile::Thread, &self.sid)?;
        cleanup_state()
    }
    fn check(&self) -> Result<(), Error> {
        self.identity()?;
        let desktop = self.desktop.as_ref().ok_or(Error::InvalidPhase)?;
        let station = self.station.as_ref().ok_or(Error::InvalidPhase)?;
        if !matches!(desktop.kind, ObjectKind::Desktop)
            || !matches!(station.kind, ObjectKind::Station)
            || object_text(desktop.raw, UOI_NAME).map_err(|error| object_stage(27, error))?
                != display_name(self.invocation)
        {
            return Err(Error::Rejected);
        }
        verify_descriptor(desktop.raw, Profile::Desktop, &self.sid)?;
        check_station(station.raw).map_err(|error| object_stage(28, error))?;
        // SAFETY: same-session retained original thread; borrowed assigned
        // desktop compared to independently duplicated object, never closed.
        let assigned =
            unsafe { GetThreadDesktop(self.binding.thread) }.map_err(|e| native(29, e))?;
        if !unsafe { CompareObjectHandles(HANDLE(assigned.0), desktop.raw) }.as_bool() {
            return Err(Error::Rejected);
        }
        self.identity()
    }
}
impl Drop for NativeInspector {
    fn drop(&mut self) {
        if self.close().is_err()
            && let Some(bound) = self.bound.take()
        {
            BOUNDARY_HEALTH.quarantine();
            mem::forget(bound);
        }
    }
}
