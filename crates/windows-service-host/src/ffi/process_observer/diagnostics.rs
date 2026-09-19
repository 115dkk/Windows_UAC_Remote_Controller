// SPDX-License-Identifier: GPL-2.0-or-later
//! Failure-only production diagnosis. No raw error text, SID, ACL, path, token,
//! user name or request data reaches EventLog. Not an authorization input.
use super::policy::Rejection;
use crate::ServiceError;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::{
    Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    },
    core::{PCWSTR, w},
};

static REPORTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Context,
    Installation,
    Scm,
    StartupBefore,
    ServiceSid,
    SubjectBefore,
    LogonBefore,
    ReadBefore,
    Merge,
    MergedShape,
    NativeAclValidation,
    StartupBeforeSet,
    ReadBeforeSet,
    DescriptorDrift,
    SubjectBeforeSet,
    StopBeforeSet,
    SetDacl,
    SubjectAfter,
    ReadAfter,
    Readback,
    StartupAfter,
}
impl Phase {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Installation => "installation",
            Self::Scm => "scm",
            Self::StartupBefore => "startup_before",
            Self::ServiceSid => "service_sid",
            Self::SubjectBefore => "subject_before",
            Self::LogonBefore => "logon_before",
            Self::ReadBefore => "read_before",
            Self::Merge => "merge",
            Self::MergedShape => "merged_shape",
            Self::NativeAclValidation => "native_acl_validation",
            Self::StartupBeforeSet => "startup_before_set",
            Self::ReadBeforeSet => "read_before_set",
            Self::DescriptorDrift => "descriptor_drift",
            Self::SubjectBeforeSet => "subject_before_set",
            Self::StopBeforeSet => "stop_before_set",
            Self::SetDacl => "set_dacl",
            Self::SubjectAfter => "subject_after",
            Self::ReadAfter => "read_after",
            Self::Readback => "readback",
            Self::StartupAfter => "startup_after",
        }
    }
}

pub(super) struct Trace {
    phase: Phase,
    pub(super) policy: Rejection,
}
impl Trace {
    pub(super) const fn new() -> Self {
        Self {
            phase: Phase::Context,
            policy: Rejection::None,
        }
    }
    pub(super) fn enter(&mut self, phase: Phase) {
        self.phase = phase;
        self.policy = Rejection::None;
    }
    pub(super) fn report(&self, error: ServiceError) {
        if REPORTED.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some(text) = record(self.phase, self.policy, error) else {
            return;
        };
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        // SAFETY: fixed local source; one bounded NUL-terminated insertion,
        // no user SID or binary payload, and one owned EventLog handle. All
        // calls are synchronous. Failure remains best-effort; never retry,
        // change the original error, reset the startup budget or weaken checks.
        unsafe {
            if let Ok(handle) =
                RegisterEventSourceW(PCWSTR::null(), w!("UACRemoteController.Startup"))
            {
                let _ = ReportEventW(
                    handle,
                    EVENTLOG_ERROR_TYPE,
                    0,
                    7,
                    None,
                    0,
                    Some(&[PCWSTR(wide.as_ptr())]),
                    None,
                );
                let _ = DeregisterEventSource(handle);
            }
        }
    }
}

fn classification(error: ServiceError) -> (&'static str, u32) {
    match error {
        ServiceError::WindowsCall { code, .. } => ("windows", code),
        ServiceError::IdentityWindows { hresult, .. } => ("identity_windows", hresult as u32),
        ServiceError::UnsafePermissions => ("permissions", 0),
        ServiceError::UnsafePath => ("path", 0),
        ServiceError::UntrustedInstallation => ("installation", 0),
        ServiceError::ConfigurationConflict => ("configuration", 0),
        ServiceError::IdentityPolicy(_) => ("identity_policy", error.service_diagnostic_code()),
        ServiceError::IdentityMalformed(_) => {
            ("identity_malformed", error.service_diagnostic_code())
        }
        _ => ("service", error.service_diagnostic_code()),
    }
}

fn record(phase: Phase, policy: Rejection, error: ServiceError) -> Option<String> {
    let (class, code) = classification(error);
    let text = format!(
        "UAC_STARTUP_V1 version={} pid={} stage=7 phase={} class={class} code={code:08x} policy={}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        phase.name(),
        policy as u8
    );
    (text.is_ascii() && text.len() <= 256).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceOperation;

    #[test]
    fn native_detail_and_closed_policy_are_preserved_without_error_text() {
        let text = record(
            Phase::SetDacl,
            Rejection::None,
            ServiceError::WindowsCall {
                operation: ServiceOperation::HardenService,
                code: 5,
            },
        )
        .unwrap();
        assert!(text.ends_with("phase=set_dacl class=windows code=00000005 policy=0"));
        assert!(text.len() <= 256 && text.is_ascii());
        let text = record(
            Phase::Merge,
            Rejection::Trustee,
            ServiceError::UnsafePermissions,
        )
        .unwrap();
        assert!(text.ends_with("phase=merge class=permissions code=00000000 policy=10"));
        assert!(!text.contains("unsafe") && !text.contains("SID") && !text.contains('\\'));
    }

    #[test]
    fn next_phase_cannot_misattribute_previous_policy_rejection() {
        let mut trace = Trace::new();
        trace.policy = Rejection::Owner;
        trace.enter(Phase::ReadAfter);
        assert_eq!(trace.policy, Rejection::None);
        assert!(
            record(
                trace.phase,
                trace.policy,
                ServiceError::ConfigurationConflict
            )
            .unwrap()
            .ends_with("phase=read_after class=configuration code=00000000 policy=0")
        );
    }
}
