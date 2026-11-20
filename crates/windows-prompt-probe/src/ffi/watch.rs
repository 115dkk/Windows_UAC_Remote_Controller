// SPDX-License-Identifier: GPL-2.0-or-later
//! Secure-desktop watcher. Desktop handles and UIA/process owners stay on the
//! thread that acquired them. Only bounded value observations cross thread joins.
//! The authenticated pipe peer and absolute lifetime are fixed before this runs.

use super::{
    Candidate, candidate_for, enumerate_matching_without_budget, enumerate_without_budget,
    object_name, parked_candidate_for,
    pipe_client::{WatchChannel, WatchRead},
    resources::{CleanupLog, OwnedDesktop},
    security, system_consent_path, uia, verify_input_desktop, verify_window_station,
    watch_transition::{
        Census, CycleAction, CycleFault, CyclePlan, Observation, OutcomeObservation, Tracked,
        Transition, WatchState, WindowIdentity, cycle_action, fold_outcome_observations,
    },
};
use crate::{
    NativeOperation, ProbeCounts, ProbeFailure, ProbeReport,
    supervision::{
        ApplyOutcome, HelperMessage, MAX_PARKED_PROMPTS, RefusalReason, ServiceMessage,
        TargetIdentity,
    },
};
use std::{
    ffi::c_void,
    sync::Arc,
    time::{Duration, Instant},
};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        StationsAndDesktops::{
            DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, HDESK, OpenInputDesktop, SetThreadDesktop,
        },
        Threading::{GetCurrentProcess, GetCurrentProcessId},
    },
    UI::WindowsAndMessaging::GetClassNameW,
};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const PARKED_WINDOW_CLASS: &str = "$$$Secure UAP Dummy Window Class For Interim Dialog";
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const OUTCOME_INTERVAL: Duration = Duration::from_millis(100);
const OUTCOME_WINDOW: Duration = Duration::from_millis(2_000);

type Result<T> = std::result::Result<T, ()>;

pub(super) fn run(
    channel: &mut WatchChannel,
    cleanup: &CleanupLog,
    mut recheck_peer: impl FnMut() -> Result<()>,
) -> Result<()> {
    let began = Instant::now();
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: borrowed current-process pseudo-handle and scalar ID, never closed.
    let (own, own_pid) = unsafe { (GetCurrentProcess(), GetCurrentProcessId()) };
    security::native64(own).map_err(|_| ())?;
    let session = security::process_identity(own, own_pid, None, cleanup).map_err(|_| ())?;
    verify_window_station().map_err(|_| ())?;
    let image = system_consent_path().map_err(|_| ())?;
    lab_note!("watch helper started: session={session} own_pid={own_pid}");
    let mut state = WatchState::new(Instant::now());
    let mut last_desktop = String::new();

    while began.elapsed() < MAX_LIFETIME {
        recheck_peer()?;
        match channel.poll_read()? {
            WatchRead::Message(ServiceMessage::Stop) | WatchRead::Eof => break,
            WatchRead::Message(ServiceMessage::Apply {
                target,
                action,
                content_digest,
            }) => {
                let outcome = match state.tracked() {
                    None => ApplyOutcome::Refused(RefusalReason::UnknownTarget),
                    Some(current) if current.identity != target => {
                        ApplyOutcome::Refused(RefusalReason::UnknownTarget)
                    }
                    Some(current) => {
                        apply(session, &image, current, action, content_digest, cleanup)?
                    }
                };
                if began.elapsed() >= MAX_LIFETIME {
                    break;
                }
                state =
                    publish_observation(channel, state, Observation::Applied { target, outcome })?;
            }
            WatchRead::Pending => {}
        }

        // Freeze the capture plan before native work. Crossing the heartbeat
        // interval during an identity-only census cannot become a renewal.
        let plan = state.cycle_plan(Instant::now());
        let desktop = match open_input_desktop(cleanup) {
            Ok(desktop) => desktop,
            Err(()) => {
                state = publish_observation(
                    channel,
                    state,
                    Observation::DesktopFault(CycleFault::InputDesktopUnavailable),
                )?;
                let Some(next) = finish_watch_cycle(began, channel, state, plan.heartbeat_due)?
                else {
                    break;
                };
                state = next;
                continue;
            }
        };
        let desktop_name = match object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName)
        {
            Ok(name) => name,
            Err(_) => {
                state = publish_observation(
                    channel,
                    state,
                    Observation::DesktopFault(CycleFault::InputDesktopNameUnavailable),
                )?;
                drop(desktop);
                let Some(next) = finish_watch_cycle(began, channel, state, plan.heartbeat_due)?
                else {
                    break;
                };
                state = next;
                continue;
            }
        };
        if desktop_name != last_desktop {
            lab_note!("input desktop: {desktop_name}");
            last_desktop = desktop_name.clone();
        }
        if began.elapsed() >= MAX_LIFETIME {
            drop(desktop);
            break;
        }
        if !desktop_name.eq_ignore_ascii_case("Winlogon") {
            state = publish_observation(channel, state, Observation::DesktopChanged)?;
            if state.parked_census_due(Instant::now()) {
                let attempted_at = Instant::now();
                let count = scoped_parked_census(desktop.raw(), session, &image, cleanup).ok();
                if count.is_none() {
                    // An optional census failure keeps the previous count.
                    lab_note!("parked prompt census failed; retaining count");
                }
                state = publish_observation(
                    channel,
                    state,
                    Observation::Parked {
                        attempted_at,
                        count,
                    },
                )?;
            }
        } else {
            if let Err(error) = verify_input_desktop(desktop.raw()) {
                state = publish_observation(
                    channel,
                    state,
                    Observation::DesktopFault(CycleFault::InputDesktopVerification(
                        error.failure(),
                    )),
                )?;
                drop(desktop);
                let Some(next) = finish_watch_cycle(began, channel, state, plan.heartbeat_due)?
                else {
                    break;
                };
                state = next;
                continue;
            }
            state.check_census_sequence()?;
            let census = scoped_census(desktop.raw(), session, &image, plan, cleanup)?;
            if began.elapsed() >= MAX_LIFETIME {
                drop(desktop);
                break;
            }
            lab_note!("winlogon census: {}", census_kind(&census));
            state = publish_observation(channel, state, Observation::Census(census))?;
        }
        drop(desktop);

        let Some(next) = finish_watch_cycle(began, channel, state, plan.heartbeat_due)? else {
            break;
        };
        state = next;
    }
    channel.finish()
}

fn publish_observation(
    channel: &mut WatchChannel,
    state: WatchState,
    observation: Observation,
) -> Result<WatchState> {
    write_transition(state.transition(Instant::now(), observation)?, |message| {
        channel.write(message)?;
        Ok(Instant::now())
    })
}

fn write_transition(
    transition: Transition,
    mut write: impl FnMut(&HelperMessage) -> Result<Instant>,
) -> Result<WatchState> {
    let Transition { mut next, messages } = transition;
    for message in &messages {
        next.output_written(write(message)?);
    }
    Ok(next)
}

fn finish_watch_cycle(
    began: Instant,
    channel: &mut WatchChannel,
    state: WatchState,
    heartbeat_due: bool,
) -> Result<Option<WatchState>> {
    if began.elapsed() >= MAX_LIFETIME {
        return Ok(None);
    }
    let state = publish_observation(channel, state, Observation::FinishCycle { heartbeat_due })?;
    let remaining = MAX_LIFETIME.saturating_sub(began.elapsed());
    if remaining.is_zero() {
        return Ok(None);
    }
    std::thread::sleep(POLL_INTERVAL.min(remaining));
    Ok(Some(state))
}

fn open_input_desktop(cleanup: &CleanupLog) -> Result<OwnedDesktop> {
    // SAFETY: fixed zero flags, no inheritance and READOBJECTS only.
    let raw = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
        .map_err(|_| ())?;
    OwnedDesktop::acquired(raw, cleanup).map_err(|_| ())
}

fn scoped_parked_census(
    desktop: HDESK,
    session: u32,
    image: &[u16],
    cleanup: &CleanupLog,
) -> Result<u8> {
    let token = desktop.0 as usize;
    let cleanup = Arc::clone(cleanup);
    std::thread::scope(|scope| {
        scope
            .spawn(move || worker_parked_census(token, session, image, &cleanup))
            .join()
            .map_err(|_| ())?
    })
}

fn worker_parked_census(
    token: usize,
    session: u32,
    image: &[u16],
    cleanup: &CleanupLog,
) -> Result<u8> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: private token is a parent-owned HDESK retained through this scoped join.
    let desktop = HDESK(token as *mut c_void);
    // SAFETY: this fresh worker has created no USER or COM objects. The input
    // desktop handle remains owned by the parent until this worker joins.
    unsafe { SetThreadDesktop(desktop) }.map_err(|_| ())?;
    // The user's desktop holds far more windows than the Winlogon census
    // admits, so only windows of the parked class are collected.
    let windows =
        enumerate_matching_without_budget(desktop, parked_class_matches).map_err(|_| ())?;
    let mut count = 0u8;
    for hwnd in windows {
        if parked_candidate_for(hwnd, session, image, cleanup).map_err(|_| ())? {
            count = count.saturating_add(1).min(MAX_PARKED_PROMPTS);
            if count == MAX_PARKED_PROMPTS {
                break;
            }
        }
    }
    lab_note!("parked prompt candidates: {count}");
    Ok(count)
}

/// Any other window on the desktop is simply not a match: a long class name
/// (WPF's `HwndWrapper[...;;<guid>]` exceeds 63 units) or a window that closed
/// mid-enumeration must not fail the census for every parked prompt.
fn parked_class_matches(hwnd: windows::Win32::Foundation::HWND) -> bool {
    // Window class names are at most 256 characters; one more unit shows truncation.
    let mut units = [0u16; 258];
    // SAFETY: read-only class query into an initialized bounded buffer for a
    // handle returned by this desktop's synchronous enumeration.
    let length = unsafe { GetClassNameW(hwnd, &mut units) };
    let Some(length) = usize::try_from(length)
        .ok()
        .filter(|length| *length > 0 && *length < units.len() - 1)
    else {
        return false;
    };
    PARKED_WINDOW_CLASS
        .encode_utf16()
        .eq(units[..length].iter().copied())
}

fn scoped_census(
    desktop: HDESK,
    session: u32,
    image: &[u16],
    plan: CyclePlan,
    cleanup: &CleanupLog,
) -> Result<Census> {
    let token = desktop.0 as usize;
    let cleanup = Arc::clone(cleanup);
    std::thread::scope(|scope| {
        scope
            .spawn(move || worker_census(token, session, image, plan, &cleanup))
            .join()
            .map_err(|_| ())?
    })
}

fn worker_census(
    token: usize,
    session: u32,
    image: &[u16],
    plan: CyclePlan,
    cleanup: &CleanupLog,
) -> Result<Census> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: private token is a parent-owned HDESK retained through this scoped join.
    let desktop = HDESK(token as *mut c_void);
    // SAFETY: fresh windowless thread has made no user/COM objects. Assignment is
    // first and the desktop belongs to the verified current window station.
    unsafe { SetThreadDesktop(desktop) }.map_err(|_| ())?;
    if let Err(error) = verify_input_desktop(desktop) {
        if cycle_action(CycleFault::InputDesktopVerification(error.failure()))
            == CycleAction::DesktopChanged
        {
            return Ok(Census::DesktopChanged);
        }
        return Err(());
    }
    let began = Instant::now();
    let windows = enumerate_without_budget(desktop).map_err(|_| ())?;
    lab_note!("winlogon windows: {}", windows.len());
    let mut candidates = Vec::new();
    for hwnd in &windows {
        let candidate = match candidate_for(*hwnd, session, image, cleanup) {
            Ok(candidate) => candidate,
            Err(_error) => {
                lab_note!(
                    "window {:#x}: candidate query failed: {_error:?}",
                    hwnd.0 as usize
                );
                match cycle_action(CycleFault::CandidateQuery) {
                    CycleAction::SkipWindow => continue,
                    CycleAction::DesktopChanged
                    | CycleAction::VerificationFailed
                    | CycleAction::Fatal => return Err(()),
                }
            }
        };
        if let Some(candidate) = candidate {
            candidates.push(candidate);
            if candidates.len() > 1 {
                return Ok(Census::Ambiguous);
            }
        }
    }
    lab_note!("winlogon candidates: {}", candidates.len());
    let Some(candidate) = candidates.pop() else {
        return Ok(Census::None);
    };
    let window = window_identity(&candidate)?;
    if candidate.recheck(session, image, cleanup).is_err() {
        return Ok(Census::VerificationFailed);
    }
    if !plan.capture(window) {
        return Ok(Census::One {
            window,
            report: None,
        });
    }
    let counts = ProbeCounts {
        top_level_windows: u16::try_from(windows.len()).map_err(|_| ())?,
        qualified_candidates: 1,
        ..ProbeCounts::default()
    };
    let report = match uia::inspect_without_budget(
        candidate.hwnd,
        candidate.pid,
        began,
        counts,
        cleanup,
        || {
            candidate.recheck(session, image, cleanup)?;
            verify_input_desktop(desktop)?;
            Ok(())
        },
    ) {
        Ok(report) => report,
        Err(_error) => {
            if cycle_action(CycleFault::InputDesktopVerification(_error.failure()))
                == CycleAction::DesktopChanged
            {
                return Ok(Census::DesktopChanged);
            }
            // A window under construction answers UI Automation with incomplete
            // properties (lab run 34648389804: PatternAvailability while consent.exe
            // was starting). That is this cycle's verdict, not a helper failure;
            // the next cycle looks again and nothing is reported meanwhile.
            lab_note!("winlogon candidate inspect failed: {_error:?}");
            return Ok(Census::VerificationFailed);
        }
    };
    if candidate.recheck(session, image, cleanup).is_err() {
        if cycle_action(CycleFault::PostCaptureRecheck) == CycleAction::VerificationFailed {
            return Ok(Census::VerificationFailed);
        }
        return Err(());
    }
    Ok(Census::One {
        window,
        report: Some(report),
    })
}

#[cfg(feature = "lab-diagnostics")]
fn census_kind(census: &Census) -> &'static str {
    match census {
        Census::None => "none",
        Census::DesktopChanged => "desktop_changed",
        Census::VerificationFailed => "verification_failed",
        Census::One { report: None, .. } => "one_same",
        Census::One {
            report: Some(_), ..
        } => "one_captured",
        Census::Ambiguous => "ambiguous",
    }
}

fn window_identity(candidate: &Candidate) -> Result<WindowIdentity> {
    let hwnd = u64::try_from(candidate.hwnd.0 as usize).map_err(|_| ())?;
    if hwnd == 0 || candidate.pid == 0 || candidate.creation == 0 {
        return Err(());
    }
    Ok(WindowIdentity {
        hwnd,
        pid: candidate.pid,
        created: candidate.creation,
    })
}

fn native_identity(candidate: &Candidate, identity: TargetIdentity) -> bool {
    u64::try_from(candidate.hwnd.0 as usize).ok() == Some(identity.hwnd)
        && candidate.pid == identity.pid
        && candidate.creation == identity.created
}

fn apply(
    session: u32,
    image: &[u16],
    tracked: &Tracked,
    action: crate::PromptAction,
    content_digest: [u8; 32],
    cleanup: &CleanupLog,
) -> Result<ApplyOutcome> {
    let desktop = open_input_desktop(cleanup)?;
    if !object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName)
        .map_err(|_| ())?
        .eq_ignore_ascii_case("Winlogon")
    {
        return Ok(ApplyOutcome::Refused(RefusalReason::TargetChanged));
    }
    if let Err(error) = verify_input_desktop(desktop.raw()) {
        if error.failure() == ProbeFailure::SecureInputDesktopProfileRequired {
            return Ok(ApplyOutcome::Refused(RefusalReason::TargetChanged));
        }
        return Err(());
    }
    let token = desktop.raw().0 as usize;
    let cleanup = Arc::clone(cleanup);
    let worker_cleanup = Arc::clone(&cleanup);
    let retained = tracked.report.clone();
    let target = tracked.identity;
    let result = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                worker_apply(WorkerApply {
                    token,
                    session,
                    image,
                    target,
                    retained: &retained,
                    action,
                    content_digest,
                    cleanup: &worker_cleanup,
                })
            })
            .join()
            .map_err(|_| ())?
    })?;
    if let Some(reason) = result {
        return Ok(ApplyOutcome::Refused(reason));
    }
    let outcome_began = Instant::now();
    let mut observations = Vec::new();
    while outcome_began.elapsed() < OUTCOME_WINDOW {
        std::thread::sleep(OUTCOME_INTERVAL);
        observations.push(observe_target_outcome(session, image, tracked, &cleanup)?);
        let outcome = fold_outcome_observations(observations.iter().copied());
        if matches!(outcome, ApplyOutcome::Gone) {
            return Ok(outcome);
        }
    }
    Ok(fold_outcome_observations(observations))
}

struct WorkerApply<'a> {
    token: usize,
    session: u32,
    image: &'a [u16],
    target: TargetIdentity,
    retained: &'a ProbeReport,
    action: crate::PromptAction,
    content_digest: [u8; 32],
    cleanup: &'a CleanupLog,
}

fn worker_apply(request: WorkerApply<'_>) -> Result<Option<RefusalReason>> {
    let WorkerApply {
        token,
        session,
        image,
        target,
        retained,
        action,
        content_digest,
        cleanup,
    } = request;
    // SAFETY: scoped parent-owned desktop token on a fresh windowless worker.
    let desktop = HDESK(token as *mut c_void);
    // SAFETY: this is the first USER/COM operation on this worker.
    unsafe { SetThreadDesktop(desktop) }.map_err(|_| ())?;
    let began = Instant::now();
    let windows = enumerate_without_budget(desktop).map_err(|_| ())?;
    let mut found = None;
    let mut count = 0;
    for hwnd in &windows {
        if let Some(candidate) = candidate_for(*hwnd, session, image, cleanup).map_err(|_| ())? {
            count += 1;
            if native_identity(&candidate, target) {
                found = Some(candidate);
            }
        }
    }
    if count != 1 {
        return Ok(Some(RefusalReason::TargetChanged));
    }
    let Some(candidate) = found else {
        return Ok(Some(RefusalReason::TargetChanged));
    };
    let counts = ProbeCounts {
        top_level_windows: u16::try_from(windows.len()).map_err(|_| ())?,
        qualified_candidates: 1,
        ..ProbeCounts::default()
    };
    uia::apply(
        uia::ApplyRequest {
            hwnd: candidate.hwnd,
            pid: candidate.pid,
            began,
            seed: counts,
            retained,
            action,
            content_digest,
            cleanup,
        },
        || {
            candidate.recheck(session, image, cleanup)?;
            verify_input_desktop(desktop)
        },
    )
    .map_err(|_| ())
}

fn observe_target_outcome(
    session: u32,
    image: &[u16],
    tracked: &Tracked,
    cleanup: &CleanupLog,
) -> Result<OutcomeObservation> {
    let desktop = match open_input_desktop(cleanup) {
        Ok(desktop) => desktop,
        Err(()) => return Ok(OutcomeObservation::Unobservable),
    };
    let desktop_name = match object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName) {
        Ok(name) => name,
        Err(_) => return Ok(OutcomeObservation::Unobservable),
    };
    if !desktop_name.eq_ignore_ascii_case("Winlogon") {
        return Ok(OutcomeObservation::Gone);
    }
    scoped_target_outcome(desktop.raw(), session, image, tracked.identity, cleanup)
}

fn scoped_target_outcome(
    desktop: HDESK,
    session: u32,
    image: &[u16],
    target: TargetIdentity,
    cleanup: &CleanupLog,
) -> Result<OutcomeObservation> {
    let token = desktop.0 as usize;
    let cleanup = Arc::clone(cleanup);
    std::thread::scope(|scope| {
        scope
            .spawn(move || target_outcome_census(token, session, image, target, &cleanup))
            .join()
            .map_err(|_| ())?
    })
}

fn target_outcome_census(
    token: usize,
    session: u32,
    image: &[u16],
    target: TargetIdentity,
    cleanup: &CleanupLog,
) -> Result<OutcomeObservation> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: private token is a parent-owned HDESK retained through this scoped join.
    let desktop = HDESK(token as *mut c_void);
    // SAFETY: fresh windowless thread has made no user/COM objects. Assignment is
    // first and the desktop belongs to the verified current window station.
    unsafe { SetThreadDesktop(desktop) }.map_err(|_| ())?;
    if let Err(error) = verify_input_desktop(desktop) {
        return match cycle_action(CycleFault::InputDesktopVerification(error.failure())) {
            CycleAction::DesktopChanged => Ok(OutcomeObservation::Unobservable),
            CycleAction::SkipWindow | CycleAction::VerificationFailed | CycleAction::Fatal => {
                Err(())
            }
        };
    }
    let windows = enumerate_without_budget(desktop).map_err(|_| ())?;
    let mut complete = true;
    for hwnd in &windows {
        let candidate = match candidate_for(*hwnd, session, image, cleanup) {
            Ok(candidate) => candidate,
            Err(_error) => {
                lab_note!(
                    "outcome window {:#x}: candidate query failed: {_error:?}",
                    hwnd.0 as usize
                );
                match cycle_action(CycleFault::CandidateQuery) {
                    CycleAction::SkipWindow => {
                        complete = false;
                        continue;
                    }
                    CycleAction::DesktopChanged
                    | CycleAction::VerificationFailed
                    | CycleAction::Fatal => return Err(()),
                }
            }
        };
        if let Some(candidate) = candidate
            && native_identity(&candidate, target)
        {
            return if candidate.recheck(session, image, cleanup).is_ok() {
                Ok(OutcomeObservation::StillPresent)
            } else if cycle_action(CycleFault::PostCaptureRecheck)
                == CycleAction::VerificationFailed
            {
                Ok(OutcomeObservation::Unobservable)
            } else {
                Err(())
            };
        }
    }
    if !complete {
        return Ok(OutcomeObservation::Unobservable);
    }
    if let Err(error) = verify_input_desktop(desktop) {
        return match cycle_action(CycleFault::InputDesktopVerification(error.failure())) {
            CycleAction::DesktopChanged => Ok(OutcomeObservation::Unobservable),
            CycleAction::SkipWindow | CycleAction::VerificationFailed | CycleAction::Fatal => {
                Err(())
            }
        };
    }
    Ok(OutcomeObservation::Gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LabelKind, PromptContentObservation, PromptLabel};

    #[test]
    fn failed_appeared_write_returns_no_committed_watch_state() {
        let start = Instant::now();
        let report = ProbeReport::from_observation(
            ProbeCounts {
                top_level_windows: 1,
                qualified_candidates: 1,
                elements: 2,
                enabled_elements: 2,
                maximum_depth: 1,
                ..ProbeCounts::default()
            },
            PromptContentObservation::from_parts(
                vec![1],
                String::new(),
                vec![PromptLabel::new(1, 1, LabelKind::Text, true, "synthetic".into()).unwrap()],
            )
            .unwrap(),
        )
        .unwrap();
        let observation = || {
            Observation::Census(Census::One {
                window: WindowIdentity {
                    hwnd: 1,
                    pid: 2,
                    created: 3,
                },
                report: Some(report.clone()),
            })
        };
        let state = write_transition(
            WatchState::new(start)
                .transition(start, observation())
                .unwrap(),
            |_| panic!("settling must not write"),
        )
        .unwrap();
        let pending = state
            .transition(start + Duration::from_secs(1), observation())
            .unwrap();
        let mut writes = 0;
        let result = write_transition(pending, |message| {
            assert!(
                matches!(message, HelperMessage::Appeared { target, .. } if target.sequence == 1)
            );
            writes += 1;
            Err(())
        });
        assert!(result.is_err());
        assert_eq!(writes, 1);
    }
}
