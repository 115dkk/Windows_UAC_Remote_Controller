// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed protected helper only. No inherited handles, shell, caller arguments,
//! environment-sourced image path, foreign token, breakaway or privilege changes.
use super::{ActiveRun, Handle, native, preflight::Preflight};
use crate::{ProbeSupervisorError as Error, SupervisorStage as Stage};
use std::{mem, os::windows::ffi::OsStrExt};
use windows::{
    Win32::{
        Foundation::{FILETIME, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
        },
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_BASIC_LIMIT_INFORMATION,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            },
            Pipes::{
                CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_MESSAGE,
            },
            SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW},
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
                CreateProcessAsUserW, GetProcessId, GetProcessTimes, PROCESS_INFORMATION,
                PROCESS_NAME_FORMAT, QueryFullProcessImageNameW, STARTUPINFOW,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};
use windows_prompt_probe::supervision::{PIPE_BUFFER_BYTES, PIPE_PREFIX};

const HELPER_COMMIT_LIMIT: usize = 256 * 1024 * 1024;

fn job_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY,
            ActiveProcessLimit: 1,
            ..Default::default()
        },
        ProcessMemoryLimit: HELPER_COMMIT_LIMIT,
        JobMemoryLimit: HELPER_COMMIT_LIMIT,
        ..Default::default()
    }
}

pub(super) fn job(preflight: &Preflight) -> Result<Handle, Error> {
    let descriptor = preflight
        .sid
        .probe_descriptor()
        .map_err(|_| Error::ServiceConfiguration)?;
    let attributes = attributes(descriptor.ptr().0);
    // SAFETY: unnamed fresh job, noninheritable fixed SYSTEM/service-SID ACL.
    // Descriptor and attributes remain live for the synchronous creation call.
    let raw = unsafe { CreateJobObjectW(Some(&attributes), PCWSTR::null()) }
        .map_err(|error| native(Stage::CreateJob, error))?;
    let job = Handle::new(raw, Stage::CreateJob)?;
    // A COM provider can allocate a BSTR before the helper can inspect its
    // length. Bound this owned helper's committed memory before it runs. These
    // limits do not cover the OS UIA server, kernel buffers or working-set size;
    // allocation failure is not exit proof, so the deadline/reap still apply.
    let limits = job_limits();
    // SAFETY: owned empty job, exact initialized fixed structure; no breakaway,
    // security-token/desktop manipulation or external process assignment.
    unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            mem::size_of_val(&limits) as u32,
        )
    }
    .map_err(|error| native(Stage::CreateJob, error))?;
    Ok(job)
}

pub(super) fn child(run: &mut ActiveRun) -> Result<(), Error> {
    let token = run
        .preflight
        .token
        .for_session(run.preflight.session.id, &run.preflight.sid_bytes)?;
    run.preflight.recheck()?;
    let descriptor = run
        .preflight
        .sid
        .probe_descriptor()
        .map_err(|_| Error::ServiceConfiguration)?;
    let attributes = attributes(descriptor.ptr().0);
    let image = wide(run.preflight.pins.probe().as_os_str())?;
    let mut command_line = crate::probe_supervisor::quoted_image_command_line(&image)?;
    let directory = wide(
        run.preflight
            .pins
            .probe()
            .parent()
            .ok_or(Error::ProtectedHelperUnavailable)?
            .as_os_str(),
    )?;
    let environment = environment()?;
    let mut desktop: Vec<u16> = "winsta0\\winlogon\0".encode_utf16().collect();
    let startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    run.budget()?;
    // SAFETY: only our checked duplicate primary token and fixed pinned binary.
    // Only quoted argv[0] for that fixed module, no extra arguments, no std
    // handles and bInheritHandles=false (Windows
    // disallows cross-session inheritance). Trusted minimal Unicode environment,
    // pinned working directory and fixed desktop all outlive this call. Three
    // conservative required privileges were already enabled, never activated here.
    // Process stays suspended until the caller owns/authenticates/assigns it.
    unsafe {
        CreateProcessAsUserW(
            Some(token.raw()),
            PCWSTR(image.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            Some(&attributes),
            Some(&attributes),
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(directory.as_ptr()),
            &startup,
            &mut info,
        )
    }
    .map_err(|error| native(Stage::CreateChild, error))?;
    // Adopt successful OS outputs BEFORE fallible identity checks. Constructing
    // these fields directly cannot early-return and strand a suspended process.
    run.child = Some(Handle {
        value: Some(info.hProcess),
        _thread: std::marker::PhantomData,
    });
    run.thread = Some(Handle {
        value: Some(info.hThread),
        _thread: std::marker::PhantomData,
    });
    run.pid = info.dwProcessId;
    if info.hProcess.is_invalid()
        || info.hThread.is_invalid()
        || info.dwProcessId == 0
        || info.dwThreadId == 0
    {
        return Err(Error::PeerMismatch);
    }
    run.creation = creation(info.hProcess)?;
    Ok(())
}

pub(super) fn assign_and_authenticate(run: &mut ActiveRun) -> Result<(), Error> {
    // SAFETY: own fresh EMPTY job and retained newly CREATED suspended child.
    // An empty Session0-created job may take this first target-session process;
    // the API, not a fabricated creator-session restriction, decides compatibility
    // with any inherited parent job. Failure kills only this owned child.
    unsafe { AssignProcessToJobObject(run.job.raw(), run.process()?) }
        .map_err(|error| native(Stage::AssignJob, error))?;
    run.assigned = true;
    authenticate_child(run)
}

pub(super) fn authenticate_child(run: &ActiveRun) -> Result<(), Error> {
    let process = run.process()?;
    // SAFETY: retained child query handle, scalar PID read, no reopen by PID.
    if unsafe { GetProcessId(process) } != run.pid || creation(process)? != run.creation {
        return Err(Error::PeerMismatch);
    }
    let mut image = [0u16; 1024];
    let mut length = image.len() as u32;
    // SAFETY: retained query handle and initialized bounded path buffer. The
    // image path is a protected-installation provenance check, not Authenticode,
    // a hash of mapped pages or the executable requesting Windows elevation.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(image.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| native(Stage::AuthenticatePeer, error))?;
    if length == 0 || length as usize >= image.len() || image[..length as usize].contains(&0) {
        return Err(Error::PeerMismatch);
    }
    let actual = String::from_utf16(&image[..length as usize]).map_err(|_| Error::PeerMismatch)?;
    let expected = run
        .preflight
        .pins
        .probe()
        .to_str()
        .ok_or(Error::ProtectedHelperUnavailable)?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::PeerMismatch);
    }
    run.preflight
        .token
        .verify_child(process, run.preflight.session.id, &run.preflight.sid_bytes)
}

pub(super) fn pipe(preflight: &Preflight, pid: u32) -> Result<Handle, Error> {
    if pid == 0 {
        return Err(Error::PeerMismatch);
    }
    let descriptor = preflight
        .sid
        .probe_descriptor()
        .map_err(|_| Error::ServiceConfiguration)?;
    let attributes = attributes(descriptor.ptr().0);
    let name: Vec<u16> = format!("{PIPE_PREFIX}{pid}\0").encode_utf16().collect();
    // SAFETY: fixed local namespace + retained created PID, first instance only,
    // one message-mode endpoint, remote clients rejected, SYSTEM/service-SID DACL.
    // A collision is failure, never attachment to a preexisting pipe. The child
    // is suspended until this endpoint and pending connect exist.
    let raw = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            Some(&attributes),
        )
    };
    Handle::new(raw, Stage::CreatePipe)
}

fn attributes(descriptor: *mut std::ffi::c_void) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: false.into(),
    }
}
fn wide(value: &std::ffi::OsStr) -> Result<Vec<u16>, Error> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.is_empty() || value.len() > 1023 || value.contains(&0) {
        return Err(Error::ProtectedHelperUnavailable);
    }
    value.push(0);
    Ok(value)
}
fn creation(process: HANDLE) -> Result<u64, Error> {
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: retained query process and four distinct initialized output values.
    unsafe { GetProcessTimes(process, &mut created, &mut exit, &mut kernel, &mut user) }
        .map_err(|error| native(Stage::AuthenticatePeer, error))?;
    let value = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    if value == 0 {
        return Err(Error::PeerMismatch);
    }
    Ok(value)
}
fn environment() -> Result<Vec<u16>, Error> {
    let mut windows = [0u16; 1024];
    let mut system = [0u16; 1024];
    // SAFETY: two initialized bounded buffers, native OS directories only. No
    // environment/registry/user-controlled DLL search path is inherited.
    let windows_length = unsafe { GetWindowsDirectoryW(Some(&mut windows)) } as usize;
    // SAFETY: same bounded native directory query invariant, separate output.
    let system_length = unsafe { GetSystemDirectoryW(Some(&mut system)) } as usize;
    if windows_length == 0
        || windows_length >= windows.len()
        || system_length == 0
        || system_length >= system.len()
    {
        return Err(Error::ProtectedHelperUnavailable);
    }
    let windows = String::from_utf16(&windows[..windows_length])
        .map_err(|_| Error::ProtectedHelperUnavailable)?;
    let system = String::from_utf16(&system[..system_length])
        .map_err(|_| Error::ProtectedHelperUnavailable)?;
    if windows.contains(['\0', '=']) || system.contains(['\0', '=']) {
        return Err(Error::ProtectedHelperUnavailable);
    }
    // Unicode environment sorted by name, terminated by an extra NUL. No user
    // profile, TEMP, app paths, credentials or inherited library override values.
    Ok(
        format!("PATH={system}\0SystemRoot={windows}\0WINDIR={windows}\0\0")
            .encode_utf16()
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_job_caps_one_process_and_committed_memory_without_breakaway() {
        let limits = job_limits();
        assert_eq!(
            limits.BasicLimitInformation.LimitFlags,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY
        );
        assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
        assert_eq!(limits.ProcessMemoryLimit, 256 * 1024 * 1024);
        assert_eq!(limits.JobMemoryLimit, limits.ProcessMemoryLimit);
    }
}
