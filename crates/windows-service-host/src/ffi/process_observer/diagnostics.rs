// SPDX-License-Identifier: GPL-2.0-or-later
//! Failure-only production diagnosis. No raw error text, SID, ACL, path, token,
//! user name or request data reaches EventLog. Not an authorization input.
use super::policy::Rejection;
use crate::{ServiceError, native::RegistrationRejection};
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
    // One fixed registration term each, so a refused startup names the term
    // instead of collapsing eleven distinct checks into a single label.
    ScmOpen,
    ScmAbsent,
    ScmConfigQuery,
    ScmConfigBinaryEncoding,
    ScmConfigBinaryPath,
    ScmConfigServiceType,
    ScmConfigAccount,
    ScmConfigDisplayName,
    ScmConfigDependencies,
    ScmConfigLoadOrder,
    ScmConfigErrorControl,
    ScmConfigStartType,
    ScmSecurity,
    ScmSidTypeQuery,
    ScmSidType,
    ScmStatus,
    ScmState,
    ScmProcess,
    ScmControls,
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
            Self::ScmOpen => "scm_open",
            Self::ScmAbsent => "scm_absent",
            Self::ScmConfigQuery => "scm_config_query",
            Self::ScmConfigBinaryEncoding => "scm_config_binary_encoding",
            Self::ScmConfigBinaryPath => "scm_config_binary_path",
            Self::ScmConfigServiceType => "scm_config_service_type",
            Self::ScmConfigAccount => "scm_config_account",
            Self::ScmConfigDisplayName => "scm_config_display_name",
            Self::ScmConfigDependencies => "scm_config_dependencies",
            Self::ScmConfigLoadOrder => "scm_config_load_order",
            Self::ScmConfigErrorControl => "scm_config_error_control",
            Self::ScmConfigStartType => "scm_config_start_type",
            Self::ScmSecurity => "scm_security",
            Self::ScmSidTypeQuery => "scm_sid_type_query",
            Self::ScmSidType => "scm_sid_type",
            Self::ScmStatus => "scm_status",
            Self::ScmState => "scm_state",
            Self::ScmProcess => "scm_process",
            Self::ScmControls => "scm_controls",
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
    /// Narrows the already entered registration phase to the fixed term that
    /// refused it. The ACL policy reason is a different axis and stays as the
    /// entered phase left it. An unreported refusal keeps the coarse phase.
    pub(super) fn classify_registration(&mut self, reason: RegistrationRejection) {
        self.phase = match reason {
            RegistrationRejection::None => return,
            RegistrationRejection::Open => Phase::ScmOpen,
            RegistrationRejection::NotInstalled => Phase::ScmAbsent,
            RegistrationRejection::ConfigQuery => Phase::ScmConfigQuery,
            RegistrationRejection::BinaryEncoding => Phase::ScmConfigBinaryEncoding,
            RegistrationRejection::BinaryPath => Phase::ScmConfigBinaryPath,
            RegistrationRejection::ServiceType => Phase::ScmConfigServiceType,
            RegistrationRejection::Account => Phase::ScmConfigAccount,
            RegistrationRejection::DisplayName => Phase::ScmConfigDisplayName,
            RegistrationRejection::Dependencies => Phase::ScmConfigDependencies,
            RegistrationRejection::LoadOrderGroup => Phase::ScmConfigLoadOrder,
            RegistrationRejection::ErrorControl => Phase::ScmConfigErrorControl,
            RegistrationRejection::StartType => Phase::ScmConfigStartType,
            RegistrationRejection::Security => Phase::ScmSecurity,
            RegistrationRejection::SidTypeQuery => Phase::ScmSidTypeQuery,
            RegistrationRejection::SidType => Phase::ScmSidType,
        };
    }
    pub(super) fn report(&self, error: ServiceError) {
        if REPORTED.swap(true, Ordering::Relaxed) {
            return;
        }
        crate::public_diagnostics::record(crate::public_diagnostics::Event::StartupGuard {
            phase: self.phase as u8,
            policy: self.policy as u8,
            code: classification(error).1,
        });
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
    fn every_registration_term_names_a_distinct_startup_phase() {
        use RegistrationRejection as R;
        let terms = [
            R::Open,
            R::NotInstalled,
            R::ConfigQuery,
            R::BinaryEncoding,
            R::BinaryPath,
            R::ServiceType,
            R::Account,
            R::DisplayName,
            R::Dependencies,
            R::LoadOrderGroup,
            R::ErrorControl,
            R::StartType,
            R::Security,
            R::SidTypeQuery,
            R::SidType,
        ];
        let mut seen = Vec::new();
        for term in terms {
            let mut trace = Trace::new();
            trace.enter(Phase::Scm);
            trace.classify_registration(term);
            let name = trace.phase.name();
            assert!(name.starts_with("scm"), "{name}");
            assert_ne!(name, "scm", "{term:?} must narrow the coarse phase");
            assert!(!seen.contains(&name), "duplicate phase {name}");
            // The projection must still fit the fixed bounded ASCII record.
            let text = record(
                trace.phase,
                trace.policy,
                ServiceError::ConfigurationConflict,
            );
            assert!(text.is_some(), "{name}");
            seen.push(name);
        }
        assert_eq!(seen.len(), terms.len());
    }

    #[test]
    fn an_unreported_registration_refusal_keeps_the_coarse_phase() {
        let mut trace = Trace::new();
        trace.enter(Phase::Scm);
        trace.policy = Rejection::Owner;
        trace.classify_registration(RegistrationRejection::None);
        assert_eq!(trace.phase.name(), "scm");
        // Narrowing the phase is a different axis from the ACL policy reason
        // and must not silently discard or invent one.
        assert_eq!(trace.policy, Rejection::Owner);
        trace.classify_registration(RegistrationRejection::StartType);
        assert_eq!(trace.phase.name(), "scm_config_start_type");
        assert_eq!(trace.policy, Rejection::Owner);
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
