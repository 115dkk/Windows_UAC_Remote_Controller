// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed read-only policy watch for one original Starter. This is NOT a Windows
//! consent receipt, an issuance grant, or permission to display/enroll anything.
//! The original peer owns this lease before its asynchronous watch is armed.

use std::{fmt, mem, rc::Rc};
use windows::{
    Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR},
        Security::{TokenElevationTypeDefault, TokenElevationTypeLimited},
        System::{
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_DWORD,
                REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_SECURITY, REG_VALUE_TYPE,
                RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, RegQueryValueExW,
            },
            Threading::{CreateEventW, WaitForSingleObject},
        },
    },
    core::{Error as WinError, HRESULT, PCWSTR, w},
};

use super::{
    ADMINISTRATORS, BOUNDARY_HEALTH, GROUP_DENY_ONLY, GROUP_ENABLED, Handle, PairingPeer,
    PairingPeerError as Error, PairingPeerRole, PairingPeerStage as Stage, ServiceContext,
    TokenFacts, cleanup_state, native_error, service_positive,
};

const KEY: PCWSTR = w!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueName {
    EnableLua,
    SecureDesktop,
    UiaDesktopToggle,
    AdminPrompt,
    UserPrompt,
    FilterAdministrator,
}
impl ValueName {
    fn name(self) -> PCWSTR {
        match self {
            Self::EnableLua => w!("EnableLUA"),
            Self::SecureDesktop => w!("PromptOnSecureDesktop"),
            Self::UiaDesktopToggle => w!("EnableUIADesktopToggle"),
            Self::AdminPrompt => w!("ConsentPromptBehaviorAdmin"),
            Self::UserPrompt => w!("ConsentPromptBehaviorUser"),
            Self::FilterAdministrator => w!("FilterAdministratorToken"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StarterClass {
    LimitedAdministrator { built_in: bool },
    StandardUser,
}
fn classify_starter(token: &TokenFacts) -> Result<StarterClass, Error> {
    token.require(PairingPeerRole::Starter, token.session)?;
    let admin = token.groups.iter().find(|(sid, _)| sid == ADMINISTRATORS);
    let built_in = built_in_administrator(&token.user);
    if token.elevation_type == TokenElevationTypeLimited.0 as u32
        && admin
            .is_some_and(|(_, flags)| flags & GROUP_DENY_ONLY != 0 && flags & GROUP_ENABLED == 0)
    {
        Ok(StarterClass::LimitedAdministrator { built_in })
    } else if token.elevation_type == TokenElevationTypeDefault.0 as u32
        && admin.is_none()
        && !built_in
    {
        Ok(StarterClass::StandardUser)
    } else {
        Err(Error::Rejected)
    }
}
fn built_in_administrator(sid: &[u8]) -> bool {
    // Only the actual already-bounded S-1-5-21-domain-RID SID is classified.
    sid.len() == 28
        && sid[..8] == [1, 5, 0, 0, 0, 0, 0, 5]
        && sid[8..12] == 21_u32.to_le_bytes()
        && sid[24..28] == 500_u32.to_le_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Values {
    common: [u32; 3],
    prompting: u32,
    built_in_filter: Option<u32>,
}
impl Values {
    fn accepts(self, starter: StarterClass) -> bool {
        if self.common != [1, 1, 0] {
            return false;
        }
        match starter {
            // 1..=4 prompt; 5 is the documented non-Windows-binary default.
            // The fixed product helper is not a Windows administrative binary.
            StarterClass::LimitedAdministrator { built_in } => {
                (1..=5).contains(&self.prompting)
                    && self.built_in_filter == if built_in { Some(1) } else { None }
            }
            // The actual default-token user's credential policy is independent
            // of an administrator's no-prompt setting. Secure desktop is above.
            StarterClass::StandardUser => {
                [1, 3].contains(&self.prompting) && self.built_in_filter.is_none()
            }
        }
    }
    fn read(key: HKEY, starter: StarterClass) -> Result<Self, Error> {
        Self::read_with(starter, |name| {
            let mut kind = REG_VALUE_TYPE::default();
            let mut bytes = [0_u8; 4];
            let mut length = bytes.len() as u32;
            // SAFETY: fixed local key and fixed value names; four owned output
            // bytes, initialized exact type/size outputs. No sizing/default path.
            let result = unsafe {
                RegQueryValueExW(
                    key,
                    name.name(),
                    None,
                    Some(&mut kind),
                    Some(bytes.as_mut_ptr()),
                    Some(&mut length),
                )
            };
            status(Stage::QueryUacPolicy, result)?;
            dword(kind, length, bytes)
        })
    }
    fn read_with(
        starter: StarterClass,
        mut read: impl FnMut(ValueName) -> Result<u32, Error>,
    ) -> Result<Self, Error> {
        let common = [
            read(ValueName::EnableLua)?,
            read(ValueName::SecureDesktop)?,
            read(ValueName::UiaDesktopToggle)?,
        ];
        let (prompt, built_in) = match starter {
            StarterClass::LimitedAdministrator { built_in } => (ValueName::AdminPrompt, built_in),
            StarterClass::StandardUser => (ValueName::UserPrompt, false),
        };
        let prompting = read(prompt)?;
        // FilterAdministratorToken applies ONLY to the built-in account. A
        // normal account's absent value is not a default/value inference: that
        // irrelevant field (and the other class's prompt field) is never read.
        let built_in_filter = if built_in {
            Some(read(ValueName::FilterAdministrator)?)
        } else {
            None
        };
        Ok(Self {
            common,
            prompting,
            built_in_filter,
        })
    }
}
fn dword(kind: REG_VALUE_TYPE, length: u32, bytes: [u8; 4]) -> Result<u32, Error> {
    if kind != REG_DWORD || length != 4 {
        Err(Error::Malformed)
    } else {
        Ok(u32::from_le_bytes(bytes))
    }
}
fn status(stage: Stage, value: WIN32_ERROR) -> Result<(), Error> {
    if value.0 == 0 {
        Ok(())
    } else {
        Err(Error::Native {
            stage,
            hresult: HRESULT::from_win32(value.0).0,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Armed,
    Current,
    Burned,
}
struct PolicyState {
    starter: StarterClass,
    phase: Phase,
    original: Option<Values>,
    failure: Option<Error>,
}
impl PolicyState {
    fn new(starter: StarterClass) -> Self {
        Self {
            starter,
            phase: Phase::Prepared,
            original: None,
            failure: None,
        }
    }
    fn burn(&mut self, error: Error) -> Error {
        self.phase = Phase::Burned;
        *self.failure.get_or_insert(error)
    }
    fn claim_arm(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Prepared || self.failure.is_some() {
            return Err(self.burn(Error::InvalidPhase));
        }
        self.phase = Phase::Armed; // Burn the one call BEFORE native registration.
        Ok(())
    }
    fn observe(&mut self, changed: bool, values: Values) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !matches!(self.phase, Phase::Armed | Phase::Current)
            || changed
            || !values.accepts(self.starter)
            || self.original.is_some_and(|original| original != values)
        {
            return Err(self.burn(Error::Rejected));
        }
        self.original = Some(values);
        self.phase = Phase::Current;
        Ok(())
    }
}

/// Only the original peer can create/store this. No serialization, clone or
/// handle extraction; the Rc also retains its service reservation on uncertainty.
pub(super) struct UacPolicyLease {
    inner: Option<Box<Inner>>,
}
impl fmt::Debug for UacPolicyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UacPolicyLease(redacted, not_consent)")
    }
}
struct Inner {
    key: HKEY,
    key_opened: bool,
    key_close: KeyClose,
    event: Option<Handle>,
    state: PolicyState,
    cleanup_failure: Option<Error>,
    closed: bool,
    _context: Rc<ServiceContext>,
}
#[derive(Default)]
struct KeyClose {
    attempted: bool,
    closed: bool,
}
impl KeyClose {
    fn confirm(&mut self, close: impl FnOnce() -> Result<(), Error>) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        if self.attempted {
            return Err(Error::CleanupUnconfirmed);
        }
        self.attempted = true;
        close()?;
        self.closed = true;
        Ok(())
    }
}
impl UacPolicyLease {
    /// Pure construction. The original peer stores this before native resource
    /// preparation too, so every prearm failure retains the whole original peer.
    pub(super) fn new(peer: &PairingPeer) -> Result<Self, Error> {
        if peer.role() != PairingPeerRole::Starter {
            return Err(Error::Rejected);
        }
        let class = classify_starter(&peer.token)?;
        Ok(Self {
            inner: Some(Box::new(Inner {
                key: HKEY::default(),
                key_opened: false,
                key_close: KeyClose::default(),
                event: None,
                state: PolicyState::new(class),
                cleanup_failure: None,
                closed: false,
                _context: Rc::clone(&peer.endpoint.context),
            })),
        })
    }
    pub(super) fn prepare(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = service_positive(|| {
            if inner.key_opened
                || inner.state.phase != Phase::Prepared
                || inner.state.failure.is_some()
            {
                return Err(Error::InvalidPhase);
            }
            let mut key = HKEY::default();
            // SAFETY: fixed local read/query+notify access only, 64-bit policy
            // view. No creation, fallback, privilege change or value write.
            status(Stage::QueryUacPolicy, unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    KEY,
                    None,
                    KEY_QUERY_VALUE | KEY_NOTIFY | KEY_WOW64_64KEY,
                    &mut key,
                )
            })?;
            inner.key = key;
            inner.key_opened = true; // Adopt before event creation or late errors.
            if key.is_invalid() {
                return Err(Error::Malformed);
            }
            // SAFETY: fresh unnamed noninheritable manual-reset event. Never
            // reset/reused for another registration or attempt.
            let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
                .map_err(|error| native_error(Stage::CreateEvent, error))?;
            inner.event = Some(Handle::new(event, Stage::CreateEvent)?);
            Ok(())
        });
        result.map_err(|error| inner.state.burn(error))
    }
    pub(super) fn require_prepared(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        if inner.state.phase != Phase::Prepared
            || inner.state.failure.is_some()
            || !inner.key_opened
            || inner.key_close.attempted
            || inner.event.is_none()
        {
            return Err(inner.state.burn(Error::InvalidPhase));
        }
        Ok(())
    }
    pub(super) fn arm(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = service_positive(|| {
            if !inner.key_opened || inner.key_close.attempted || inner.event.is_none() {
                return Err(Error::InvalidPhase);
            }
            inner.state.claim_arm()?;
            let event = inner.event.as_ref().ok_or(Error::Malformed)?.raw();
            // SAFETY: this entire owner is already retained in the original
            // peer. Persistent service worker; one registration, never rearmed.
            status(Stage::WatchUacPolicy, unsafe {
                RegNotifyChangeKeyValue(
                    inner.key,
                    false,
                    REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                    Some(event),
                    true,
                )
            })?;
            inner.observe()
        });
        result.map_err(|error| inner.state.burn(error))
    }
    pub(super) fn check(&mut self) -> Result<(), Error> {
        let inner = self.inner_mut();
        let result = service_positive(|| inner.observe());
        result.map_err(|error| inner.state.burn(error))
    }
    pub(super) fn close(&mut self) -> Result<(), Error> {
        self.inner_mut().close()
    }
    fn inner_mut(&mut self) -> &mut Inner {
        self.inner
            .as_deref_mut()
            .expect("policy owner exists until Drop")
    }
}
impl Inner {
    fn changed(&self) -> Result<bool, Error> {
        let event = self.event.as_ref().ok_or(Error::Closed)?.raw();
        // SAFETY: exact retained manual-reset event, zero-time observation only.
        match unsafe { WaitForSingleObject(event, 0) } {
            WAIT_TIMEOUT => Ok(false),
            WAIT_OBJECT_0 => Ok(true),
            WAIT_FAILED => Err(native_error(Stage::WatchUacPolicy, WinError::from_thread())),
            _ => Err(Error::Malformed),
        }
    }
    fn observe(&mut self) -> Result<(), Error> {
        if let Some(error) = self.state.failure {
            return Err(error);
        }
        if !self.key_opened || self.key_close.attempted || self.closed {
            return Err(Error::Closed);
        }
        // A change-and-restore still signals the original event. RegRestoreKey
        // is not covered by this API; this is not an exhaustive policy audit.
        if self.changed()? {
            return Err(self.state.burn(Error::Rejected));
        }
        let values = Values::read(self.key, self.state.starter)?;
        let changed = self.changed()?;
        self.state.observe(changed, values)
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        if let Some(error) = self.cleanup_failure {
            return Err(error);
        }
        self.state.burn(Error::Cancelled);
        // Cleanup is deliberately independent of stop, deadline and policy.
        // Closing the watched key cancels/signals its notification before the
        // event is released. An uncertain key close is never retried.
        if self.key_opened {
            let key = self.key;
            if let Err(error) = self.key_close.confirm(|| {
                // SAFETY: exact uniquely owned RegOpenKeyExW result, once.
                status(Stage::CloseUacPolicy, unsafe { RegCloseKey(key) })
            }) {
                self.cleanup_failure = Some(error);
                BOUNDARY_HEALTH.quarantine();
                return Err(error);
            }
        }
        drop(self.event.take()); // The watch key is confirmed closed first.
        if let Err(error) = cleanup_state() {
            self.cleanup_failure = Some(error);
            return Err(error);
        }
        self.closed = true;
        Ok(())
    }
}
impl Drop for UacPolicyLease {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take()
            && inner.close().is_err()
        {
            BOUNDARY_HEALTH.quarantine();
            // Keep key/event and exact service reservation together. The normal
            // PairingPipe path additionally retains the entire original peer.
            mem::forget(inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{INTERACTIVE, MEDIUM_IL, service_positive_with};
    use super::*;
    use std::cell::Cell;

    fn values() -> Values {
        Values {
            common: [1, 1, 0],
            prompting: 5,
            built_in_filter: None,
        }
    }
    fn administrator() -> StarterClass {
        StarterClass::LimitedAdministrator { built_in: false }
    }
    fn token(limited: bool) -> TokenFacts {
        TokenFacts {
            user: vec![1, 1, 0, 0, 0, 0, 0, 5, 22, 0, 0, 0],
            integrity: MEDIUM_IL.to_vec(),
            groups: if limited {
                vec![
                    (INTERACTIVE.to_vec(), GROUP_ENABLED),
                    (ADMINISTRATORS.to_vec(), GROUP_DENY_ONLY),
                ]
            } else {
                vec![(INTERACTIVE.to_vec(), GROUP_ENABLED)]
            },
            token_id: 1,
            logon_id: 2,
            session: 1,
            elevation: 0,
            elevation_type: if limited {
                TokenElevationTypeLimited.0 as u32
            } else {
                TokenElevationTypeDefault.0 as u32
            },
            app_container: 0,
            ui_access: 0,
        }
    }
    #[test]
    fn actual_token_profile_rejects_ambiguous_admin_or_elevated_shortcuts() {
        assert_eq!(classify_starter(&token(true)), Ok(administrator()));
        assert_eq!(
            classify_starter(&token(false)),
            Ok(StarterClass::StandardUser)
        );
        let mut wrong = token(true);
        wrong.groups.pop();
        assert!(classify_starter(&wrong).is_err());
        let mut wrong = token(false);
        wrong
            .groups
            .push((ADMINISTRATORS.to_vec(), GROUP_DENY_ONLY));
        assert!(classify_starter(&wrong).is_err());
        let mut wrong = token(true);
        wrong.elevation = 1;
        assert!(classify_starter(&wrong).is_err());
    }
    #[test]
    fn exact_policy_profiles_have_no_missing_or_no_prompt_fallback() {
        assert!(values().accepts(administrator()));
        let mut user = values();
        user.prompting = 3;
        assert!(user.accepts(StarterClass::StandardUser));
        for (index, bad) in [(0, 0), (1, 0), (2, 1)] {
            let mut changed = values();
            changed.common[index] = bad;
            assert!(!changed.accepts(administrator()));
        }
        for bad in [0, 6, u32::MAX] {
            let mut changed = values();
            changed.prompting = bad;
            assert!(!changed.accepts(administrator()));
        }
        for bad in [0, 2, 4, 5, u32::MAX] {
            user.prompting = bad;
            assert!(!user.accepts(StarterClass::StandardUser));
        }
        let built_in = StarterClass::LimitedAdministrator { built_in: true };
        assert!(!values().accepts(built_in));
        let mut enabled = values();
        enabled.built_in_filter = Some(1);
        assert!(enabled.accepts(built_in));
        for bad in [0, 2, u32::MAX] {
            enabled.built_in_filter = Some(bad);
            assert!(!enabled.accepts(built_in));
        }
        for value in 1..=5 {
            let mut profile = values();
            profile.prompting = value;
            assert!(profile.accepts(administrator()));
        }
    }
    #[test]
    fn only_applicable_fields_are_required_missing_relevant_values_fail_closed() {
        let read = |field| match field {
            ValueName::EnableLua | ValueName::SecureDesktop => Ok(1),
            ValueName::UiaDesktopToggle => Ok(0),
            ValueName::AdminPrompt => Ok(5),
            ValueName::UserPrompt | ValueName::FilterAdministrator => Err(Error::Malformed),
        };
        let ordinary = Values::read_with(administrator(), read).unwrap();
        assert_eq!(ordinary.built_in_filter, None); // No guessed default value.
        assert!(ordinary.accepts(administrator()));
        let built_in = StarterClass::LimitedAdministrator { built_in: true };
        assert_eq!(Values::read_with(built_in, read), Err(Error::Malformed));
        for missing in [
            ValueName::EnableLua,
            ValueName::SecureDesktop,
            ValueName::UiaDesktopToggle,
            ValueName::AdminPrompt,
        ] {
            assert_eq!(
                Values::read_with(administrator(), |field| if field == missing {
                    Err(Error::Malformed)
                } else {
                    read(field)
                }),
                Err(Error::Malformed)
            );
        }
        let mut queried = Vec::new();
        let standard = Values::read_with(StarterClass::StandardUser, |field| {
            queried.push(field);
            match field {
                ValueName::EnableLua | ValueName::SecureDesktop => Ok(1),
                ValueName::UiaDesktopToggle => Ok(0),
                ValueName::UserPrompt => Ok(3),
                _ => panic!("must not query irrelevant administrator settings"),
            }
        })
        .unwrap();
        assert!(standard.accepts(StarterClass::StandardUser));
        assert_eq!(
            queried,
            [
                ValueName::EnableLua,
                ValueName::SecureDesktop,
                ValueName::UiaDesktopToggle,
                ValueName::UserPrompt
            ]
        );
        assert_eq!(
            Values::read_with(StarterClass::StandardUser, |field| {
                if field == ValueName::UserPrompt {
                    Err(Error::Malformed)
                } else {
                    read(field)
                }
            }),
            Err(Error::Malformed)
        );
    }
    #[test]
    fn only_exact_native_dword_and_width_are_decoded() {
        assert_eq!(dword(REG_DWORD, 4, [1, 0, 0, 0]), Ok(1));
        for length in [0, 1, 3, 5, u32::MAX] {
            assert_eq!(dword(REG_DWORD, length, [0; 4]), Err(Error::Malformed));
        }
        assert_eq!(dword(REG_VALUE_TYPE(1), 4, [0; 4]), Err(Error::Malformed));
    }
    #[test]
    fn watch_must_precede_observation_and_cannot_be_rearmed_or_restored() {
        let mut early = PolicyState::new(administrator());
        assert!(early.observe(false, values()).is_err());
        assert!(early.claim_arm().is_err());
        let mut original = PolicyState::new(administrator());
        original.claim_arm().unwrap();
        original.observe(false, values()).unwrap();
        assert!(original.observe(true, values()).is_err()); // change then restore
        assert!(original.observe(false, values()).is_err());
        assert!(original.claim_arm().is_err());
        let mut drift = PolicyState::new(administrator());
        drift.claim_arm().unwrap();
        drift.observe(false, values()).unwrap();
        let mut changed = values();
        changed.prompting = 2;
        assert!(drift.observe(false, changed).is_err()); // still healthy, not original
    }
    #[test]
    fn stop_after_watch_arm_burns_publication_without_losing_first_error() {
        let stopped = Cell::new(false);
        let mut state = PolicyState::new(administrator());
        let result = service_positive_with(
            || stopped.get(),
            || {
                state.claim_arm()?;
                state.observe(false, values())?;
                stopped.set(true);
                Ok(())
            },
        );
        assert_eq!(result, Err(Error::Cancelled));
        state.burn(result.unwrap_err());
        assert!(state.observe(false, values()).is_err());
        let mut failed = PolicyState::new(administrator());
        failed.claim_arm().unwrap();
        assert_eq!(failed.burn(Error::Malformed), Error::Malformed);
        assert_eq!(failed.burn(Error::Cancelled), Error::Malformed);
    }
    #[test]
    fn unknown_key_close_retains_event_and_cannot_retry_the_handle() {
        let calls = Cell::new(0);
        let event_released = Cell::new(false);
        let mut key = KeyClose::default();
        let close = key.confirm(|| {
            calls.set(calls.get() + 1);
            Err(Error::Malformed)
        });
        if close.is_ok() {
            event_released.set(true);
        }
        assert_eq!(close, Err(Error::Malformed));
        assert!(!event_released.get());
        assert_eq!(
            key.confirm(|| {
                calls.set(calls.get() + 1);
                Ok(())
            }),
            Err(Error::CleanupUnconfirmed)
        );
        assert_eq!(calls.get(), 1);
        assert!(!key.closed);
        let mut confirmed = KeyClose::default();
        confirmed
            .confirm(|| {
                assert!(!event_released.get());
                Ok(())
            })
            .unwrap();
        assert!(confirmed.closed);
        event_released.set(true); // Production releases event only after confirm.
        confirmed
            .confirm(|| panic!("must not close twice"))
            .unwrap();
        assert!(event_released.get());
    }
}
