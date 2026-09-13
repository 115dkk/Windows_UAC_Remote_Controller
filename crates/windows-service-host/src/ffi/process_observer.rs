// SPDX-License-Identifier: GPL-2.0-or-later
//! Owning-service startup contract for limited process observers. This private
//! no-argument mutation can target only GetCurrentProcess. It never opens a PID,
//! takes ownership, changes tokens/privileges, or writes owner/group/SACL/MIC.
//!
//! Invariants: exact SYSTEM/service SID, protected own image and original SCM
//! self-PID are checked before and after publication. Native descriptors have
//! one LocalFree owner; borrowed views never outlive it. The new DACL has owned
//! DWORD-aligned storage through the synchronous call and is never null. The
//! current-process pseudo-handle is borrowed and never closed.

mod policy;

use std::mem;
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        ACL,
        Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
        GetSecurityDescriptorLength, IsValidAcl, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_SELF_RELATIVE,
        SECURITY_DESCRIPTOR_RELATIVE,
    },
    System::Threading::GetCurrentProcess,
};
use windows_service::service::{Service, ServiceState};

use super::{filesystem::ValidatedInstallation, security::OwnServiceSid};
use crate::{ServiceError, ServiceOperation};

// Fixed lab API phases survive the outer startup error projection. This file
// is separate from the generic failure report, which replaces its old content.
macro_rules! observe {
    ($phase:literal, $result:expr) => {{
        #[cfg(feature = "lab-software-identity")]
        {
            let result = $result;
            note(
                $phase,
                result
                    .as_ref()
                    .err()
                    .map_or(0, |error: &ServiceError| error.service_diagnostic_code()),
            );
            result
        }
        #[cfg(not(feature = "lab-software-identity"))]
        {
            $result
        }
    }};
}

#[cfg(feature = "lab-software-identity")]
fn note(phase: &'static str, code: u32) {
    write_lab_line(&format!("observer {phase} {code}\n"));
}

// Callers supply only literal phases/numeric codes or the private policy's
// bounded fixed-class ACL summary, never error text or SID/descriptor bytes.
#[cfg(feature = "lab-software-identity")]
fn write_lab_line(line: &str) {
    use std::{fs::OpenOptions, io::Write};
    let Some(root) = std::env::var_os("ProgramData") else {
        return;
    };
    let path = std::path::PathBuf::from(root)
        .join(crate::INSTALLATION_FOLDER)
        .join("process-observer.txt");
    if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(path)
        && file
            .metadata()
            .is_ok_and(|metadata| metadata.len().saturating_add(line.len() as u64) <= 8192)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn release(mut self) -> Result<(), ServiceError> {
        let original = mem::take(&mut self.0);
        // SAFETY: exact non-null successful GetSecurityInfo allocation, once,
        // after every borrowed byte view was copied and ended. Never retried.
        if unsafe { LocalFree(Some(HLOCAL(original.0))) }.0.is_null() {
            Ok(())
        } else {
            Err(ServiceError::UnsafePermissions)
        }
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.0.is_null() {
            // SAFETY: early-error cleanup of the same sole native allocation.
            // Startup is already failing; no pending native I/O borrows it.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
}

fn read_current_descriptor() -> Result<policy::Snapshot, ServiceError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: current-process pseudo-handle is borrowed only. Returned owner,
    // group and DACL share one owned native descriptor. No SACL/label query is
    // needed: publication requests ONLY DACL and cannot write MIC/SACL.
    let result = unsafe {
        GetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if result.0 != 0 {
        return Err(ServiceError::WindowsCall {
            operation: ServiceOperation::ReadSecurity,
            code: result.0,
        });
    }
    if descriptor.0.is_null() {
        return Err(ServiceError::UnsafePermissions);
    }
    let allocation = Descriptor(descriptor);
    // SAFETY: successful native allocation, never a caller address. Structural
    // validation precedes interpretation of contiguous self-relative bytes.
    if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
        return Err(ServiceError::UnsafePermissions);
    }
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: live valid native descriptor and exclusive initialized outputs.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|error| super::win_error(ServiceOperation::ReadSecurity, error))?;
    if revision != 1 || control & SE_SELF_RELATIVE.0 == 0 {
        return Err(ServiceError::UnsafePermissions);
    }
    // SAFETY: the validated self-relative descriptor reports its contiguous
    // extent; enforce an independent cap before forming a Rust borrowed view.
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if !(mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>()..=65_536).contains(&length) {
        return Err(ServiceError::UnsafePermissions);
    }
    // SAFETY: native-valid contiguous extent, immutable through allocation.
    // The pure parser bounds every offset and copies components before release.
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.0.cast::<u8>(), length) };
    let snapshot = policy::snapshot(bytes)?;
    allocation.release()?;
    Ok(snapshot)
}

fn recheck_startup(
    installation: &ValidatedInstallation,
    original: &Service,
) -> Result<(), ServiceError> {
    windows_identity::verify_service_context().map_err(ServiceError::from_identity)?;
    let status = original
        .query_status()
        .map_err(|_| ServiceError::ConfigurationConflict)?;
    policy::startup_guard(
        crate::entry::stop_requested(),
        status.current_state == ServiceState::Running,
        status.controls_accepted.is_empty(),
        status.process_id == Some(std::process::id()),
    )?;
    // Revalidate fixed registration/config/security and actual SCM self-PID,
    // retaining the original SCM handle and original protected path pins too.
    let _current = crate::native::running_service_for_probe(installation.executable())?;
    let _image = super::validate_installation(true)?;
    windows_identity::verify_service_context().map_err(ServiceError::from_identity)
}

pub(crate) fn provision_current_process_observer() -> Result<(), ServiceError> {
    observe!(
        "context",
        windows_identity::verify_service_context().map_err(ServiceError::from_identity)
    )?;
    let installation = observe!("installation", super::validate_installation(true))?;
    let service = observe!(
        "scm",
        crate::native::running_service_for_probe(installation.executable())
    )?;
    observe!("startup_before", recheck_startup(&installation, &service))?;
    let service_sid = OwnServiceSid::lookup()?.bytes();
    let before = observe!("read_before", read_current_descriptor())?;
    #[cfg(feature = "lab-software-identity")]
    for line in policy::diagnostic_summary(&before, &service_sid) {
        write_lab_line(&format!("before {line}\n"));
    }
    let merged = observe!("merge", policy::merge(&before, &service_sid))?;
    if merged.is_empty() || !merged.len().is_multiple_of(4) {
        return Err(ServiceError::UnsafePermissions);
    }
    // DWORD storage gives the ACL its native alignment, unlike a Vec<u8>.
    let aligned: Vec<u32> = merged
        .chunks_exact(4)
        .map(|part| u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
        .collect();
    // SAFETY: pure policy validated every ACL/ACE bound; this complete owned
    // DWORD-aligned allocation remains immutable through validation/publication.
    if !unsafe { IsValidAcl(aligned.as_ptr().cast::<ACL>()) }.as_bool() {
        return Err(ServiceError::UnsafePermissions);
    }
    observe!(
        "startup_before_set",
        recheck_startup(&installation, &service)
    )?;
    // Detect a concurrent policy edit before attempting the approved merge.
    // There is no retry/overwrite loop and no compensating ACL reset.
    if observe!("read_before_set", read_current_descriptor())? != before {
        return Err(ServiceError::UnsafePermissions);
    }
    if crate::entry::stop_requested() {
        return Err(ServiceError::ConfigurationConflict);
    }
    // SAFETY: exact owning process only, no adopted/parameterized handle. Only
    // DACL_SECURITY_INFORMATION is requested. Owner/group/SACL are not supplied;
    // no protected/unprotected or label bits are set. The nonempty validated
    // DWORD-aligned ACL stays live unchanged through the synchronous call.
    let result = unsafe {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(aligned.as_ptr().cast::<ACL>()),
            None,
        )
    };
    if result.0 != 0 {
        return observe!(
            "set_dacl",
            Err(ServiceError::WindowsCall {
                operation: ServiceOperation::HardenService,
                code: result.0,
            })
        );
    }
    #[cfg(feature = "lab-software-identity")]
    note("set_dacl", 0);
    let after = observe!("read_after", read_current_descriptor())?;
    #[cfg(feature = "lab-software-identity")]
    for line in policy::diagnostic_summary(&after, &service_sid) {
        write_lab_line(&format!("after {line}\n"));
    }
    observe!(
        "readback",
        policy::verify_readback(&before, &after, &merged, &service_sid)
    )?;
    observe!("startup_after", recheck_startup(&installation, &service))
}
