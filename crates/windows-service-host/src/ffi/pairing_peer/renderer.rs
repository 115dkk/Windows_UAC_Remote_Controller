// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed registered renderer/native-object inspection. No visual operation,
//! secret input, generic process selector or independently renewed attempt.

use std::{
    fmt, mem, ptr,
    rc::Rc,
    slice,
    sync::Mutex,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::{
            CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, FILETIME, HANDLE,
            HLOCAL, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SE_WINDOW_OBJECT},
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
            IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SE_DACL_PRESENT, SE_DACL_PROTECTED, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR_CONTROL,
            SECURITY_DESCRIPTOR_RELATIVE,
        },
        Storage::FileSystem::READ_CONTROL,
        System::{
            Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
            StationsAndDesktops::{
                CloseDesktop, CloseWindowStation, GetThreadDesktop, GetUserObjectInformationW,
                HDESK, HWINSTA, UOI_FLAGS, UOI_NAME, UOI_TYPE, USER_OBJECT_INFORMATION_INDEX,
                USEROBJECTFLAGS,
            },
            Threading::{
                GetCurrentProcess, GetExitCodeProcess, GetProcessIdOfThread, GetThreadTimes,
                OpenProcess, OpenThread, PROCESS_ACCESS_RIGHTS, PROCESS_DUP_HANDLE,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, THREAD_ACCESS_RIGHTS,
                THREAD_QUERY_LIMITED_INFORMATION, THREAD_SYNCHRONIZE, WaitForSingleObject,
            },
        },
        UI::WindowsAndMessaging::WSF_VISIBLE,
    },
    core::{Error as WinError, HRESULT},
};

use super::{
    ADMINISTRATORS, BOUNDARY_HEALTH, GROUP_DENY_ONLY, GROUP_ENABLED, Handle,
    PairingPeerError as Error, PairingPeerRole, PairingPipe, ServiceContext, SessionEpoch,
    TokenFacts, bounded_sid, check_image, cleanup_state, process_identity, service_positive,
};
use crate::{
    RendererInvocation, ServiceError,
    ffi::security::{OwnServiceSid, SecurityDescriptor},
    pairing_handoff::{RendererObjects, RendererProcess},
};

pub(in crate::ffi) const PROCESS_RIGHTS: u32 = PROCESS_QUERY_LIMITED_INFORMATION.0
    | PROCESS_DUP_HANDLE.0
    | PROCESS_SYNCHRONIZE.0
    | READ_CONTROL.0;
pub(in crate::ffi) const THREAD_RIGHTS: u32 =
    THREAD_QUERY_LIMITED_INFORMATION.0 | THREAD_SYNCHRONIZE.0 | READ_CONTROL.0;
pub(in crate::ffi) const DESKTOP_RIGHTS: u32 = 0x0002_0183;
const DESKTOP_INSPECT: u32 = 0x0002_0081;
const STATION_INSPECT: u32 = 0x0002_0002;
const MAX_DESCRIPTOR: usize = 65_536;
const GROUP_OWNER: u32 = 8;
pub(in crate::ffi) const CUTOFF_ENV: &str = "UAC_REMOTE_RENDERER_CUTOFF_QPC";
struct CounterState {
    frequency: u64,
    last: u64,
    failed: bool,
}
static COUNTER: Mutex<CounterState> = Mutex::new(CounterState {
    frequency: 0,
    last: 0,
    failed: false,
});
impl CounterState {
    fn record(&mut self, frequency: i64, value: i64) -> Result<(u64, u64), Error> {
        if self.failed {
            return Err(Error::InvalidDeadline);
        }
        if frequency <= 0
            || value <= 0
            || (self.frequency != 0 && self.frequency != frequency as u64)
            || (value as u64) < self.last
        {
            self.failed = true;
            return Err(Error::InvalidDeadline);
        }
        self.frequency = frequency as u64;
        self.last = value as u64;
        Ok((self.last, self.frequency))
    }
}

// Fixed diagnostic stages, not OS prose, caller paths or enum-discriminant casts.
pub(in crate::ffi) fn native(stage: u8, error: WinError) -> Error {
    Error::Service(ServiceError::RendererNative {
        stage,
        hresult: error.code().0,
    })
}
pub(in crate::ffi) fn require_owner(token: &TokenFacts, session: u32) -> Result<(), Error> {
    token.require(PairingPeerRole::Helper, session)?;
    if !token.groups.iter().any(|(sid, flags)| {
        sid == ADMINISTRATORS
            && flags & (GROUP_ENABLED | GROUP_OWNER) == (GROUP_ENABLED | GROUP_OWNER)
            && flags & GROUP_DENY_ONLY == 0
    }) {
        return Err(Error::Rejected);
    }
    Ok(())
}
pub(in crate::ffi) fn display_name(invocation: RendererInvocation) -> String {
    format!("UacRemote.Pairing.{}", invocation.display().argument())
}
pub(crate) fn original_cutoff(deadline: Instant) -> Result<u64, Error> {
    // QPC BEFORE same-thread Instant. Pinned Rust's Instant is floor(QPC*1e9/f)
    // plus a constant offset, which cancels in remaining Duration. Floor the
    // tick conversion and reserve ceil(f/1e9)+2 ticks: <1ns conversion rounding
    // plus the documented cross-thread +/-1tick ambiguity (two-sided reserve).
    let (before, frequency) = counter()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::DeadlineElapsed)?;
    cutoff_ticks(before, frequency, remaining)
}
pub(crate) fn check_cutoff(cutoff: u64) -> Result<(), Error> {
    let (now, _) = counter()?;
    if cutoff == 0 || cutoff > i64::MAX as u64 || now >= cutoff {
        Err(Error::DeadlineElapsed)
    } else {
        Ok(())
    }
}
fn counter() -> Result<(u64, u64), Error> {
    let mut state = COUNTER.lock().map_err(|_| Error::InvalidDeadline)?;
    let mut frequency = 0_i64;
    let mut value = 0_i64;
    // SAFETY: initialized fixed outputs. Same-host QPC/QPF only, no UTC/CPU
    // instruction, timer-resolution adjustment or guessed millisecond quantum.
    unsafe { QueryPerformanceFrequency(&mut frequency) }.map_err(|error| {
        state.failed = true;
        native(7, error)
    })?;
    unsafe { QueryPerformanceCounter(&mut value) }.map_err(|error| {
        state.failed = true;
        native(7, error)
    })?;
    state.record(frequency, value)
}
fn cutoff_ticks(before: u64, frequency: u64, remaining: Duration) -> Result<u64, Error> {
    if frequency == 0 {
        return Err(Error::InvalidDeadline);
    }
    let ticks = remaining
        .as_nanos()
        .checked_mul(u128::from(frequency))
        .ok_or(Error::InvalidDeadline)?
        / 1_000_000_000;
    let ticks = u64::try_from(ticks).map_err(|_| Error::InvalidDeadline)?;
    let reserve = frequency
        .div_ceil(1_000_000_000)
        .checked_add(2)
        .ok_or(Error::InvalidDeadline)?;
    let usable = ticks
        .checked_sub(reserve)
        .filter(|value| *value != 0)
        .ok_or(Error::DeadlineElapsed)?;
    before
        .checked_add(usable)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(Error::InvalidDeadline)
}
pub(in crate::ffi) fn budget_from_cutoff(cutoff: u64) -> Result<(Instant, Instant), Error> {
    // Receiver order is deliberately reversed: Instant BEFORE counter. Adding
    // only floored remaining ticks cannot reanchor this original cutoff late.
    let start = Instant::now();
    let (now, frequency) = counter()?;
    let span = remaining_duration(cutoff, now, frequency)?;
    let deadline = start.checked_add(span).ok_or(Error::InvalidDeadline)?;
    if Instant::now() >= deadline {
        return Err(Error::DeadlineElapsed);
    }
    Ok((start, deadline))
}
fn remaining_duration(cutoff: u64, now: u64, frequency: u64) -> Result<Duration, Error> {
    if cutoff > i64::MAX as u64 || frequency == 0 {
        return Err(Error::InvalidDeadline);
    }
    let ticks = cutoff
        .checked_sub(now)
        .filter(|ticks| *ticks != 0)
        .ok_or(Error::DeadlineElapsed)?;
    let nanos = u128::from(ticks)
        .checked_mul(1_000_000_000)
        .ok_or(Error::InvalidDeadline)?
        / u128::from(frequency);
    let nanos = u64::try_from(nanos).map_err(|_| Error::InvalidDeadline)?;
    if nanos == 0 || nanos > 300_000_000_000 {
        return Err(Error::InvalidDeadline);
    }
    Ok(Duration::from_nanos(nanos))
}
pub(in crate::ffi) fn check_setup_cutoff(cutoff: u64) -> Result<(), Error> {
    let (now, frequency) = counter()?;
    let reserve = frequency.checked_mul(30).ok_or(Error::InvalidDeadline)?;
    let setup = cutoff.checked_sub(reserve).ok_or(Error::DeadlineElapsed)?;
    if now >= setup {
        Err(Error::DeadlineElapsed)
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub(in crate::ffi) enum Profile {
    Process,
    Thread,
    Desktop,
}
pub(in crate::ffi) fn descriptor(
    profile: Profile,
    sid: &[u8],
) -> Result<SecurityDescriptor, Error> {
    if sid.len() != 32 || sid[..12] != [1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0] {
        return Err(Error::Malformed);
    }
    let mut principal = String::from("S-1-5-80");
    for word in sid[12..].chunks_exact(4) {
        principal.push_str(&format!(
            "-{}",
            u32::from_le_bytes(word.try_into().map_err(|_| Error::Malformed)?)
        ));
    }
    let (admin, service) = match profile {
        Profile::Process => (PROCESS_RIGHTS, PROCESS_RIGHTS),
        Profile::Thread => (THREAD_RIGHTS, THREAD_RIGHTS),
        Profile::Desktop => (DESKTOP_RIGHTS, DESKTOP_INSPECT),
    };
    SecurityDescriptor::from_sddl(&format!(
        "O:BAG:BAD:P(A;;0x{service:08x};;;SY)(A;;0x{admin:08x};;;BA)(A;;0x{service:08x};;;{principal})(A;;RC;;;OW)"
    )).map_err(Error::Service)
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: exact GetSecurityInfo allocation, after every bounded read.
        if !unsafe { LocalFree(Some(HLOCAL(self.0.0))) }.0.is_null() {
            BOUNDARY_HEALTH.quarantine();
        }
    }
}
pub(in crate::ffi) fn verify_descriptor(
    handle: HANDLE,
    profile: Profile,
    sid: &[u8],
) -> Result<(), Error> {
    let object = match profile {
        Profile::Desktop => SE_WINDOW_OBJECT,
        _ => SE_KERNEL_OBJECT,
    };
    let expected = descriptor(profile, sid)?;
    let actual = read_descriptor(handle, object)?;
    // SAFETY: both descriptors are successful owned Windows allocations, still
    // live here; validity/length/control checks precede each bounded slice.
    let actual = unsafe { descriptor_parts(actual.0)? };
    // SAFETY: the expected ConvertStringSecurityDescriptor allocation is owned.
    let expected = unsafe { descriptor_parts(expected.ptr())? };
    if actual != expected {
        return Err(Error::Rejected);
    }
    cleanup_state()
}
fn read_descriptor(handle: HANDLE, object: SE_OBJECT_TYPE) -> Result<Descriptor, Error> {
    let mut pointer = PSECURITY_DESCRIPTOR::default();
    // SAFETY: actual retained registered process/thread/user object; only owner
    // and DACL, no SACL privilege or asserted descriptor bytes from a client.
    let result = unsafe {
        GetSecurityInfo(
            handle,
            object,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut pointer),
        )
    };
    if result.0 != 0 {
        return Err(Error::Service(ServiceError::RendererNative {
            stage: 4,
            hresult: HRESULT::from_win32(result.0).0,
        }));
    }
    if pointer.0.is_null() {
        return Err(Error::Malformed);
    }
    Ok(Descriptor(pointer))
}
unsafe fn descriptor_parts(pointer: PSECURITY_DESCRIPTOR) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // SAFETY: caller retains a successful Windows descriptor allocation.
    if !unsafe { IsValidSecurityDescriptor(pointer) }.as_bool() {
        return Err(Error::Malformed);
    }
    let mut control = SECURITY_DESCRIPTOR_CONTROL::default();
    let mut revision = 0;
    // SAFETY: initialized fixed outputs and live native descriptor.
    unsafe { GetSecurityDescriptorControl(pointer, &mut control.0, &mut revision) }
        .map_err(|error| native(4, error))?;
    let required = SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED;
    if revision != 1 || control.0 & required.0 != required.0 {
        return Err(Error::Rejected);
    }
    // SAFETY: the valid owned descriptor reports its allocation extent.
    let length = unsafe { GetSecurityDescriptorLength(pointer) } as usize;
    if !(mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=MAX_DESCRIPTOR).contains(&length) {
        return Err(Error::Malformed);
    }
    // SAFETY: bounded by the native owned allocation length checked above.
    let bytes = unsafe { slice::from_raw_parts(pointer.0.cast::<u8>(), length) };
    descriptor_bytes(bytes)
}
fn descriptor_bytes(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if bytes.len() < 20 {
        return Err(Error::Malformed);
    }
    let owner = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| Error::Malformed)?) as usize;
    let acl = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| Error::Malformed)?) as usize;
    if owner < 20 || acl < 20 || acl.checked_add(8).is_none_or(|end| end > bytes.len()) {
        return Err(Error::Malformed);
    }
    let owner = bounded_sid(bytes, owner)?;
    if owner != ADMINISTRATORS {
        return Err(Error::Rejected);
    }
    let length = u16::from_le_bytes(
        bytes[acl + 2..acl + 4]
            .try_into()
            .map_err(|_| Error::Malformed)?,
    ) as usize;
    if length < 8 || acl.checked_add(length).is_none_or(|end| end > bytes.len()) {
        return Err(Error::Malformed);
    }
    // Equality with our explicit descriptor rejects null/extra/inherited/unknown
    // ACEs and alternate masks. No generic user-supplied ACL policy is accepted.
    Ok((owner, bytes[acl..acl + length].to_vec()))
}
pub(in crate::ffi) fn object_text(
    handle: HANDLE,
    field: USER_OBJECT_INFORMATION_INDEX,
) -> Result<String, Error> {
    let mut text = [0_u16; 256];
    let mut needed = 0;
    // SAFETY: retained native user object, fixed bounded UTF-16 output.
    unsafe {
        GetUserObjectInformationW(
            handle,
            field,
            Some(text.as_mut_ptr().cast()),
            mem::size_of_val(&text) as u32,
            Some(&mut needed),
        )
    }
    .map_err(|error| native(2, error))?;
    if needed < 2 || needed as usize > mem::size_of_val(&text) || needed % 2 != 0 {
        return Err(Error::Malformed);
    }
    let units = needed as usize / 2;
    if text[units - 1] != 0 || text[..units - 1].contains(&0) {
        return Err(Error::Malformed);
    }
    String::from_utf16(&text[..units - 1]).map_err(|_| Error::Malformed)
}
pub(in crate::ffi) fn check_station(station: HANDLE) -> Result<(), Error> {
    if object_text(station, UOI_TYPE)? != "WindowStation"
        || !object_text(station, UOI_NAME)?.eq_ignore_ascii_case("WinSta0")
    {
        return Err(Error::Rejected);
    }
    let mut flags = USEROBJECTFLAGS::default();
    let mut needed = 0;
    // SAFETY: exact initialized fixed-size flags output on retained station.
    unsafe {
        GetUserObjectInformationW(
            station,
            UOI_FLAGS,
            Some(ptr::from_mut(&mut flags).cast()),
            mem::size_of_val(&flags) as u32,
            Some(&mut needed),
        )
    }
    .map_err(|error| native(2, error))?;
    if needed as usize != mem::size_of_val(&flags)
        || flags.dwFlags & WSF_VISIBLE as u32 != WSF_VISIBLE as u32
    {
        return Err(Error::Rejected);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Unknown,
    Desktop,
    Station,
}
struct UserObject {
    raw: HANDLE,
    kind: ObjectKind,
}
impl UserObject {
    fn classify(&mut self) -> Result<(), Error> {
        self.kind = match object_text(self.raw, UOI_TYPE)?.as_str() {
            "Desktop" => ObjectKind::Desktop,
            "WindowStation" => ObjectKind::Station,
            _ => return Err(Error::Rejected),
        };
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.raw.is_invalid() {
            return Ok(());
        }
        // Do not guess CloseHandle for an unclassified user-object candidate.
        let result = match self.kind {
            // SAFETY: owned duplicate classified by native User32 object type;
            // the service never attaches a thread to it.
            ObjectKind::Desktop => unsafe { CloseDesktop(HDESK(self.raw.0)) },
            // SAFETY: owned duplicate, never set as this process's station.
            ObjectKind::Station => unsafe { CloseWindowStation(HWINSTA(self.raw.0)) },
            ObjectKind::Unknown => return Err(Error::CleanupUnconfirmed),
        };
        result.map_err(|error| native(10, error))?;
        self.raw = HANDLE::default();
        Ok(())
    }
}
struct Inner {
    process: Option<Handle>,
    thread: Option<Handle>,
    context: Option<Rc<ServiceContext>>,
    token: Option<TokenFacts>,
    session: Option<SessionEpoch>,
    metadata: Option<RendererProcess>,
    thread_created: u64,
    sid: Vec<u8>,
    invocation: Option<RendererInvocation>,
    desktop: Option<UserObject>,
    station: Option<UserObject>,
    claimed: bool,
    objects_claimed: bool,
    objects_bound: bool,
    closed: bool,
    failure: Option<Error>,
    cleanup_failure: Option<Error>,
}
pub(crate) struct RendererRegistration {
    inner: Option<Box<Inner>>,
}
impl fmt::Debug for RendererRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendererRegistration(redacted, nonvisual)")
    }
}
impl RendererRegistration {
    pub(crate) fn new() -> Self {
        Self {
            inner: Some(Box::new(Inner {
                process: None,
                thread: None,
                context: None,
                token: None,
                session: None,
                metadata: None,
                thread_created: 0,
                sid: Vec::new(),
                invocation: None,
                desktop: None,
                station: None,
                claimed: false,
                objects_claimed: false,
                objects_bound: false,
                closed: false,
                failure: None,
                cleanup_failure: None,
            })),
        }
    }
    pub(crate) fn register(
        &mut self,
        parent: &mut PairingPipe,
        metadata: RendererProcess,
    ) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            if inner.claimed || !metadata.valid() {
                return Err(Error::InvalidPhase);
            }
            inner.claimed = true;
            let parent = parent.renderer_peer()?;
            if parent.role() != PairingPeerRole::Helper || metadata.pid == parent.pid {
                return Err(Error::Rejected);
            }
            parent.recheck()?;
            inner.context = Some(Rc::clone(&parent.endpoint.context));
            inner.sid = OwnServiceSid::lookup().map_err(Error::Service)?.bytes();
            inner.metadata = Some(metadata);
            service_positive(|| Ok(()))?;
            // SAFETY: candidate arrived only on the original authenticated
            // Helper's fixed registration phase; retained immediately, no PID kill.
            let process =
                unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(PROCESS_RIGHTS), false, metadata.pid) }
                    .map_err(|error| native(3, error))?;
            inner.process = Some(Handle::new(process, super::PairingPeerStage::QueryProcess)?);
            if process_identity(process, metadata.pid)? != metadata.created {
                return Err(Error::Rejected);
            }
            check_image(&parent.endpoint, process)?;
            let token = TokenFacts::observe(process)?;
            require_owner(&token, parent.interactive.id)?;
            inner.token = Some(token);
            inner.session = Some(SessionEpoch::observe(parent.interactive.id)?);
            verify_descriptor(process, Profile::Process, &inner.sid)?;
            // SAFETY: fixed registered initial-thread candidate; actual process
            // association is verified before it can bind any renderer state.
            let thread =
                unsafe { OpenThread(THREAD_ACCESS_RIGHTS(THREAD_RIGHTS), false, metadata.thread) }
                    .map_err(|error| native(3, error))?;
            inner.thread = Some(Handle::new(thread, super::PairingPeerStage::QueryProcess)?);
            if unsafe { GetProcessIdOfThread(thread) } != metadata.pid {
                return Err(Error::Rejected);
            }
            inner.thread_created = thread_creation(thread)?;
            if inner.thread_created < metadata.created {
                return Err(Error::Rejected);
            }
            verify_descriptor(thread, Profile::Thread, &inner.sid)?;
            parent.recheck()?;
            inner.recheck()
        })();
        result.map_err(|error| inner.fail(error))
    }
    pub(crate) fn check_connected(&mut self, pipe: &mut PairingPipe) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = (|| {
            inner.recheck()?;
            let peer = pipe.renderer_peer()?;
            let metadata = inner.metadata.ok_or(Error::InvalidPhase)?;
            if peer.role() != PairingPeerRole::Helper
                || peer.pid != metadata.pid
                || peer.created != metadata.created
                || !Rc::ptr_eq(
                    &peer.endpoint.context,
                    inner.context.as_ref().ok_or(Error::InvalidPhase)?,
                )
                || Some(&peer.interactive) != inner.session.as_ref()
            {
                return Err(Error::Rejected);
            }
            peer.recheck()?;
            inner.recheck()
        })();
        result.map_err(|error| inner.fail(error))
    }
    pub(crate) fn bind_objects(
        &mut self,
        pipe: &mut PairingPipe,
        invocation: RendererInvocation,
        objects: RendererObjects,
    ) -> Result<(), Error> {
        self.check_connected(pipe)?;
        let inner = self.inner_mut();
        let result = (|| {
            if inner.objects_claimed {
                return Err(Error::InvalidPhase);
            }
            inner.objects_claimed = true;
            inner.invocation = Some(invocation);
            let metadata = inner.metadata.ok_or(Error::InvalidPhase)?;
            if objects.thread != metadata.thread {
                return Err(Error::Rejected);
            }
            let process = inner.process.as_ref().ok_or(Error::InvalidPhase)?.raw();
            duplicate_object(
                process,
                objects.desktop,
                DESKTOP_INSPECT,
                &mut inner.desktop,
            )?;
            duplicate_object(
                process,
                objects.station,
                STATION_INSPECT,
                &mut inner.station,
            )?;
            let desktop = inner.desktop.as_ref().ok_or(Error::InvalidPhase)?;
            if !matches!(desktop.kind, ObjectKind::Desktop)
                || object_text(desktop.raw, UOI_NAME)? != display_name(invocation)
            {
                return Err(Error::Rejected);
            }
            verify_descriptor(desktop.raw, Profile::Desktop, &inner.sid)?;
            let station = inner.station.as_ref().ok_or(Error::InvalidPhase)?;
            if !matches!(station.kind, ObjectKind::Station) {
                return Err(Error::Rejected);
            }
            check_station(station.raw)?;
            // SAFETY: retained actual initial thread. This returned desktop is
            // borrowed, never closed; failure across sessions is not bypassed.
            let assigned =
                unsafe { GetThreadDesktop(metadata.thread) }.map_err(|error| native(2, error))?;
            // SAFETY: actual assigned desktop and retained independently duplicated object.
            if !unsafe { CompareObjectHandles(HANDLE(assigned.0), desktop.raw) }.as_bool() {
                return Err(Error::Rejected);
            }
            inner.recheck()?;
            inner.objects_bound = true;
            Ok(())
        })();
        result.map_err(|error| inner.fail(error))?;
        self.check_connected(pipe)
    }
    pub(crate) fn objects_bound(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|inner| inner.objects_bound && inner.failure.is_none())
    }
    pub(crate) fn failure(&self) -> Option<Error> {
        self.inner
            .as_ref()
            .and_then(|inner| inner.failure.or(inner.cleanup_failure))
    }
    /// Cleanup-only: no liveness/current-policy prerequisite and no termination.
    pub(crate) fn drain(&mut self) -> Result<bool, Error> {
        self.inner_mut().drain()
    }
    pub(crate) fn is_drained(&self) -> bool {
        self.inner.as_ref().is_some_and(|inner| inner.closed)
    }
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner
            .as_deref_mut()
            .expect("renderer registration exists until Drop")
    }
}
impl Inner {
    fn fail(&mut self, error: Error) -> Error {
        self.objects_bound = false;
        *self.failure.get_or_insert(error)
    }
    fn recheck(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        service_positive(|| {
            self.context
                .as_ref()
                .ok_or(Error::InvalidPhase)?
                .recheck()?;
            let metadata = self.metadata.ok_or(Error::InvalidPhase)?;
            let process = self.process.as_ref().ok_or(Error::InvalidPhase)?.raw();
            let thread = self.thread.as_ref().ok_or(Error::InvalidPhase)?.raw();
            if process_identity(process, metadata.pid)? != metadata.created || thread_creation(thread)? != self.thread_created
                // SAFETY: exact retained initial-thread query handle.
                || unsafe { GetProcessIdOfThread(thread) } != metadata.pid
            {
                return Err(Error::Rejected);
            }
            let token = TokenFacts::observe(process)?;
            let session = self.session.as_ref().ok_or(Error::InvalidPhase)?;
            require_owner(&token, session.id)?;
            if Some(&token) != self.token.as_ref() || SessionEpoch::observe(session.id)? != *session
            {
                return Err(Error::Rejected);
            }
            verify_descriptor(process, Profile::Process, &self.sid)?;
            verify_descriptor(thread, Profile::Thread, &self.sid)?;
            self.context
                .as_ref()
                .ok_or(Error::InvalidPhase)?
                .installation
                .check_service_image(
                    &super::super::pairing_client::process_image(process)
                        .map_err(|_| Error::Rejected)?,
                )
                .map_err(Error::Service)?;
            if self.objects_bound {
                let desktop = self.desktop.as_ref().ok_or(Error::InvalidPhase)?.raw;
                if object_text(desktop, UOI_NAME)?
                    != display_name(self.invocation.ok_or(Error::InvalidPhase)?)
                {
                    return Err(Error::Rejected);
                }
                verify_descriptor(desktop, Profile::Desktop, &self.sid)?;
                check_station(self.station.as_ref().ok_or(Error::InvalidPhase)?.raw)?;
                // SAFETY: the same retained initial thread; borrowed association,
                // never a CloseDesktop/SetThreadDesktop capability for service use.
                let assigned = unsafe { GetThreadDesktop(metadata.thread) }
                    .map_err(|error| native(2, error))?;
                if !unsafe { CompareObjectHandles(HANDLE(assigned.0), desktop) }.as_bool() {
                    return Err(Error::Rejected);
                }
            }
            cleanup_state()
        })
    }
    fn drain(&mut self) -> Result<bool, Error> {
        if self.closed {
            return Ok(true);
        }
        if let Some(error) = self.cleanup_failure {
            return Err(error);
        }
        if let Some(process) = self.process.as_ref() {
            // SAFETY: exact retained registered process, zero-time cleanup query.
            match unsafe { WaitForSingleObject(process.raw(), 0) } {
                WAIT_TIMEOUT => return Ok(false),
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    // SAFETY: signalled retained process; exit is observed, not a timeout.
                    unsafe { GetExitCodeProcess(process.raw(), &mut code) }
                        .map_err(|error| native(9, error))?;
                    if code != 0 {
                        self.failure.get_or_insert(Error::Rejected);
                    }
                }
                _ => return Err(native(9, WinError::from_thread())),
            }
        }
        for object in [&mut self.desktop, &mut self.station].into_iter().flatten() {
            if let Err(error) = object.close() {
                self.cleanup_failure = Some(error);
                BOUNDARY_HEALTH.quarantine();
                return Err(error);
            }
        }
        self.desktop = None;
        self.station = None;
        drop(self.thread.take());
        drop(self.process.take());
        drop(self.context.take());
        cleanup_state()?;
        self.closed = true;
        Ok(true)
    }
}
fn duplicate_object(
    process: HANDLE,
    value: u64,
    access: u32,
    slot: &mut Option<UserObject>,
) -> Result<(), Error> {
    let value = usize::try_from(value).map_err(|_| Error::Malformed)?;
    if value == 0 || value == usize::MAX {
        return Err(Error::Malformed);
    }
    let mut duplicate = HANDLE::default();
    // SAFETY: source is the actual registered child; candidate comes only from
    // its authenticated exact descriptor phase. Retain before classification.
    unsafe {
        DuplicateHandle(
            process,
            HANDLE(value as *mut _),
            GetCurrentProcess(),
            &mut duplicate,
            access,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    }
    .map_err(|error| native(5, error))?;
    *slot = Some(UserObject {
        raw: duplicate,
        kind: ObjectKind::Unknown,
    });
    if duplicate.is_invalid() {
        return Err(Error::Malformed);
    }
    slot.as_mut().ok_or(Error::InvalidPhase)?.classify()
}
fn thread_creation(thread: HANDLE) -> Result<u64, Error> {
    let mut created = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: retained actual thread and four initialized fixed outputs.
    unsafe { GetThreadTimes(thread, &mut created, &mut exit, &mut kernel, &mut user) }
        .map_err(|error| native(3, error))?;
    let value = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if value == 0 {
        Err(Error::Malformed)
    } else {
        Ok(value)
    }
}
impl Drop for RendererRegistration {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && !matches!(inner.drain(), Ok(true))
        {
            BOUNDARY_HEALTH.quarantine();
            mem::forget(inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qpc_mapping_reserves_real_ticks_and_never_rounds_a_duration_up() {
        assert_eq!(
            cutoff_ticks(100, 10_000_000, Duration::from_secs(1)),
            Ok(10_000_097)
        );
        assert_eq!(
            cutoff_ticks(100, 3_125_000, Duration::from_nanos(1_280)),
            Ok(101)
        );
        assert_eq!(
            cutoff_ticks(100, 3_000_000_007, Duration::from_nanos(10)),
            Ok(124)
        );
        assert_eq!(
            remaining_duration(124, 100, 3_000_000_007),
            Ok(Duration::from_nanos(7))
        );
        for frequency in [1_u64, 3_125_000, 10_000_000, 999_999_937, 3_000_000_007] {
            let duration = Duration::new(7, 123_456_789);
            let cutoff = cutoff_ticks(50, frequency, duration).unwrap();
            let reserve = frequency.div_ceil(1_000_000_000) + 2;
            assert!(
                u128::from(cutoff - 50 + reserve) * 1_000_000_000
                    <= duration.as_nanos() * u128::from(frequency)
            );
            // Receiver conversion remains floored even at fractional frequency.
            let remaining = remaining_duration(cutoff, 50, frequency).unwrap();
            assert!(
                remaining.as_nanos() * u128::from(frequency)
                    <= u128::from(cutoff - 50) * 1_000_000_000
            );
        }
    }
    #[test]
    fn near_cutoff_overflow_forged_long_window_and_regression_fail_closed() {
        assert!(cutoff_ticks(1, 10_000_000, Duration::ZERO).is_err());
        assert!(cutoff_ticks(1, 3_125_000, Duration::from_nanos(320)).is_err());
        assert!(cutoff_ticks(i64::MAX as u64, 10_000_000, Duration::from_secs(1)).is_err());
        assert!(cutoff_ticks(1, 0, Duration::from_secs(1)).is_err());
        assert!(remaining_duration(100, 100, 10_000_000).is_err());
        assert!(remaining_duration(99, 100, 10_000_000).is_err());
        assert!(remaining_duration(i64::MAX as u64, 1, 10_000_000).is_err());
        let mut clock = CounterState {
            frequency: 0,
            last: 0,
            failed: false,
        };
        assert_eq!(clock.record(10_000_000, 100), Ok((100, 10_000_000)));
        assert!(clock.record(10_000_000, 99).is_err());
        assert!(clock.record(10_000_000, 101).is_err());
        let mut changed = CounterState {
            frequency: 10_000_000,
            last: 100,
            failed: false,
        };
        assert!(changed.record(3_125_000, 101).is_err());
        assert!(changed.record(10_000_000, 102).is_err());
    }
    #[test]
    fn parent_minimum_is_a_narrowing_not_a_new_source_deadline() {
        let service = cutoff_ticks(100, 10_000_000, Duration::from_secs(200)).unwrap();
        let parent = cutoff_ticks(101, 10_000_000, Duration::from_secs(150)).unwrap();
        let narrowed = service.min(parent);
        assert_eq!(narrowed, parent);
        assert!(narrowed <= service);
        // Sender's ceil(nanosecond)+2 reserve exceeds +/-1 comparison ambiguity.
        assert!(narrowed + 1 < 101 + 150 * 10_000_000);
    }
}
