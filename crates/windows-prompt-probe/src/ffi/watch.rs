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
};
use crate::{
    NativeOperation, ProbeCounts, ProbeFailure, ProbeReport,
    settle::{SettleGate, Settled},
    supervision::{
        ApplyOutcome, GoneReason, HelperMessage, MAX_PARKED_PROMPTS, RefusalReason, ServiceMessage,
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
const PARKED_CENSUS_INTERVAL: Duration = Duration::from_secs(1);
const PARKED_WINDOW_CLASS: &str = "$$$Secure UAP Dummy Window Class For Interim Dialog";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const OUTCOME_INTERVAL: Duration = Duration::from_millis(100);
const OUTCOME_WINDOW: Duration = Duration::from_millis(2_000);

type Result<T> = std::result::Result<T, ()>;

struct Tracked {
    identity: TargetIdentity,
    report: ProbeReport,
}

enum Census {
    None,
    DesktopChanged,
    VerificationFailed,
    One {
        identity: TargetIdentity,
        report: Option<ProbeReport>,
    },
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CycleFault {
    InputDesktopUnavailable,
    InputDesktopNameUnavailable,
    InputDesktopVerification(ProbeFailure),
    CandidateQuery,
    PostCaptureRecheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CycleAction {
    DesktopChanged,
    SkipWindow,
    VerificationFailed,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutcomeObservation {
    Gone,
    StillPresent,
    Unobservable,
}

fn fold_outcome_observations(
    observations: impl IntoIterator<Item = OutcomeObservation>,
) -> ApplyOutcome {
    if observations
        .into_iter()
        .any(|observation| observation == OutcomeObservation::Gone)
    {
        ApplyOutcome::Gone
    } else {
        ApplyOutcome::StillPresent
    }
}

const fn cycle_action(fault: CycleFault) -> CycleAction {
    match fault {
        CycleFault::InputDesktopUnavailable | CycleFault::InputDesktopNameUnavailable => {
            CycleAction::DesktopChanged
        }
        CycleFault::InputDesktopVerification(ProbeFailure::SecureInputDesktopProfileRequired) => {
            CycleAction::DesktopChanged
        }
        CycleFault::InputDesktopVerification(_) => CycleAction::Fatal,
        CycleFault::CandidateQuery => CycleAction::SkipWindow,
        CycleFault::PostCaptureRecheck => CycleAction::VerificationFailed,
    }
}

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
    let mut tracked: Option<Tracked> = None;
    // A new or changed prompt waits here until its content stops changing;
    // only then is it published. While it waits, nothing is tracked.
    let mut settling = SettleGate::new();
    // After apply refused a changed dialog, look at its content on the very next
    // cycle instead of at the next heartbeat, so the phone is asked again soon.
    let mut recheck_content = false;
    let mut sequence = 0u32;
    let mut last_output = Instant::now();
    let mut last_desktop = String::new();
    let mut last_parked = 0u8;
    let mut last_parked_census: Option<Instant> = None;

    while began.elapsed() < MAX_LIFETIME {
        recheck_peer()?;
        match channel.poll_read()? {
            WatchRead::Message(ServiceMessage::Stop) | WatchRead::Eof => break,
            WatchRead::Message(ServiceMessage::Apply {
                target,
                action,
                content_digest,
            }) => {
                let outcome = match tracked.as_ref() {
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
                channel.write(&HelperMessage::Applied { target, outcome })?;
                last_output = Instant::now();
                if matches!(
                    outcome,
                    ApplyOutcome::Refused(RefusalReason::ContentChanged)
                ) {
                    recheck_content = true;
                }
                if matches!(outcome, ApplyOutcome::Gone)
                    && tracked.as_ref().map(|current| current.identity) == Some(target)
                {
                    tracked = None;
                }
            }
            WatchRead::Pending => {}
        }

        // A heartbeat carrying a tracked sequence is also a fresh same-content
        // witness. Decide before census: crossing the interval during a census
        // that skipped UIA must not accidentally publish a renewal witness.
        let heartbeat_due = last_output.elapsed() >= HEARTBEAT_INTERVAL;
        let desktop = match open_input_desktop(cleanup) {
            Ok(desktop) => desktop,
            Err(()) => {
                handle_desktop_cycle_fault(
                    CycleFault::InputDesktopUnavailable,
                    channel,
                    &mut tracked,
                    &mut settling,
                    &mut last_output,
                )?;
                if !finish_watch_cycle(began, channel, &mut last_output, heartbeat_due, sequence)? {
                    break;
                }
                continue;
            }
        };
        let desktop_name = match object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName)
        {
            Ok(name) => name,
            Err(_) => {
                handle_desktop_cycle_fault(
                    CycleFault::InputDesktopNameUnavailable,
                    channel,
                    &mut tracked,
                    &mut settling,
                    &mut last_output,
                )?;
                drop(desktop);
                if !finish_watch_cycle(began, channel, &mut last_output, heartbeat_due, sequence)? {
                    break;
                }
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
            withdraw_for_desktop_change(channel, &mut tracked, &mut settling, &mut last_output)?;
            let census_due =
                last_parked_census.is_none_or(|at| at.elapsed() >= PARKED_CENSUS_INTERVAL);
            if census_due {
                last_parked_census = Some(Instant::now());
                match scoped_parked_census(desktop.raw(), session, &image, cleanup) {
                    Ok(count) if count != last_parked => {
                        channel.write(&HelperMessage::Parked { count })?;
                        last_parked = count;
                        last_output = Instant::now();
                    }
                    Ok(_) => {}
                    Err(()) => {
                        // This optional census must not terminate or perturb the
                        // secure-desktop approval path. Retain the last count.
                        lab_note!("parked prompt census failed; retaining count={last_parked}");
                    }
                }
            }
        } else {
            if let Err(error) = verify_input_desktop(desktop.raw()) {
                handle_desktop_cycle_fault(
                    CycleFault::InputDesktopVerification(error.failure()),
                    channel,
                    &mut tracked,
                    &mut settling,
                    &mut last_output,
                )?;
                drop(desktop);
                if !finish_watch_cycle(began, channel, &mut last_output, heartbeat_due, sequence)? {
                    break;
                }
                continue;
            }
            let next_sequence = sequence.checked_add(1).ok_or(())?;
            let census = scoped_census(
                desktop.raw(),
                session,
                &image,
                tracked.as_ref(),
                heartbeat_due || recheck_content,
                next_sequence,
                cleanup,
            )?;
            recheck_content = false;
            if began.elapsed() >= MAX_LIFETIME {
                drop(desktop);
                break;
            }
            lab_note!("winlogon census: {}", census_kind(&census));
            match census {
                Census::DesktopChanged => {
                    withdraw_for_desktop_change(
                        channel,
                        &mut tracked,
                        &mut settling,
                        &mut last_output,
                    )?;
                }
                Census::None => {
                    settling.clear();
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Closed,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::Ambiguous => {
                    settling.clear();
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Ambiguous,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::VerificationFailed => {
                    settling.clear();
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::VerificationFailed,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::One {
                    identity,
                    report: None,
                } => {
                    if tracked.as_ref().map(|value| value.identity) != Some(identity)
                        && let Some(current) = tracked.take()
                    {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Replaced,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::One {
                    identity,
                    report: Some(report),
                } => {
                    // The phone's copy of a changed prompt is withdrawn at once;
                    // its replacement is published once it has settled.
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Replaced,
                        })?;
                        last_output = Instant::now();
                    }
                    let window = (identity.hwnd, identity.pid, identity.created);
                    let settled =
                        settling.observe(Instant::now(), window, report, |held, fresh| {
                            fresh.content() == held.content()
                                && fresh.counts().describes_the_same_prompt(held.counts())
                        });
                    if let Settled::Publish(report) = settled {
                        let message = HelperMessage::Appeared {
                            target: identity,
                            report: report.clone(),
                        };
                        if message.fits_watch_frame() {
                            channel.write(&message)?;
                            sequence = identity.sequence;
                            tracked = Some(Tracked { identity, report });
                            last_output = Instant::now();
                        } else {
                            // Capture admits more content than one watch frame. An
                            // unpublishable observation is this cycle's verification
                            // failure; no write is attempted and nothing is tracked.
                            settling.clear();
                            lab_note!("winlogon candidate exceeds watch frame");
                        }
                    }
                }
            }
        }
        drop(desktop);

        if !finish_watch_cycle(began, channel, &mut last_output, heartbeat_due, sequence)? {
            break;
        }
    }
    channel.finish()
}

fn finish_watch_cycle(
    began: Instant,
    channel: &mut WatchChannel,
    last_output: &mut Instant,
    heartbeat_due: bool,
    sequence: u32,
) -> Result<bool> {
    if began.elapsed() >= MAX_LIFETIME {
        return Ok(false);
    }
    if heartbeat_due && last_output.elapsed() >= HEARTBEAT_INTERVAL {
        channel.write(&HelperMessage::Heartbeat { sequence })?;
        *last_output = Instant::now();
    }
    let remaining = MAX_LIFETIME.saturating_sub(began.elapsed());
    if remaining.is_zero() {
        return Ok(false);
    }
    std::thread::sleep(POLL_INTERVAL.min(remaining));
    Ok(true)
}

fn handle_desktop_cycle_fault(
    fault: CycleFault,
    channel: &mut WatchChannel,
    tracked: &mut Option<Tracked>,
    settling: &mut SettleGate<(u64, u32, u64), ProbeReport>,
    last_output: &mut Instant,
) -> Result<()> {
    if cycle_action(fault) != CycleAction::DesktopChanged {
        return Err(());
    }
    withdraw_for_desktop_change(channel, tracked, settling, last_output)
}

fn withdraw_for_desktop_change(
    channel: &mut WatchChannel,
    tracked: &mut Option<Tracked>,
    settling: &mut SettleGate<(u64, u32, u64), ProbeReport>,
    last_output: &mut Instant,
) -> Result<()> {
    settling.clear();
    if let Some(current) = tracked.take() {
        channel.write(&HelperMessage::Gone {
            target: current.identity,
            reason: GoneReason::DesktopChanged,
        })?;
        *last_output = Instant::now();
    }
    Ok(())
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
    tracked: Option<&Tracked>,
    verify_content: bool,
    next_sequence: u32,
    cleanup: &CleanupLog,
) -> Result<Census> {
    let token = desktop.0 as usize;
    let cleanup = Arc::clone(cleanup);
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                worker_census(
                    token,
                    session,
                    image,
                    tracked,
                    verify_content,
                    next_sequence,
                    &cleanup,
                )
            })
            .join()
            .map_err(|_| ())?
    })
}

fn worker_census(
    token: usize,
    session: u32,
    image: &[u16],
    tracked: Option<&Tracked>,
    verify_content: bool,
    next_sequence: u32,
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
    let same = tracked.is_some_and(|value| native_identity(&candidate, value.identity));
    let identity = if same {
        tracked.ok_or(())?.identity
    } else {
        target_identity(&candidate, next_sequence)?
    };
    if candidate.recheck(session, image, cleanup).is_err() {
        return Ok(Census::VerificationFailed);
    }
    if same && !verify_content {
        return Ok(Census::One {
            identity,
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
    if same
        && tracked.is_some_and(|prior| {
            report.content() == prior.report.content()
                && report
                    .counts()
                    .describes_the_same_prompt(prior.report.counts())
        })
    {
        return Ok(Census::One {
            identity,
            report: None,
        });
    }
    Ok(Census::One {
        // Changed content under the same HWND is a replacement, not renewal.
        identity: target_identity(&candidate, next_sequence)?,
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
        } => "one_new",
        Census::Ambiguous => "ambiguous",
    }
}

fn target_identity(candidate: &Candidate, sequence: u32) -> Result<TargetIdentity> {
    let hwnd = u64::try_from(candidate.hwnd.0 as usize).map_err(|_| ())?;
    if hwnd == 0 || candidate.pid == 0 || candidate.creation == 0 || sequence == 0 {
        return Err(());
    }
    Ok(TargetIdentity {
        hwnd,
        pid: candidate.pid,
        created: candidate.creation,
        sequence,
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

    #[test]
    fn externally_controlled_cycle_faults_are_recoverable_without_accepting_a_candidate() {
        assert_eq!(
            cycle_action(CycleFault::InputDesktopUnavailable),
            CycleAction::DesktopChanged
        );
        assert_eq!(
            cycle_action(CycleFault::InputDesktopNameUnavailable),
            CycleAction::DesktopChanged
        );
        assert_eq!(
            cycle_action(CycleFault::InputDesktopVerification(
                ProbeFailure::SecureInputDesktopProfileRequired,
            )),
            CycleAction::DesktopChanged
        );
        assert_eq!(
            cycle_action(CycleFault::CandidateQuery),
            CycleAction::SkipWindow
        );
        assert_eq!(
            cycle_action(CycleFault::PostCaptureRecheck),
            CycleAction::VerificationFailed
        );
    }

    #[test]
    fn unexpected_desktop_verification_failures_remain_fatal() {
        for failure in [
            ProbeFailure::ThreadImpersonationPresent,
            ProbeFailure::MalformedNativeData(NativeOperation::DesktopInput),
            ProbeFailure::NativeCall {
                operation: NativeOperation::DesktopInput,
                hresult: -1,
            },
        ] {
            assert_eq!(
                cycle_action(CycleFault::InputDesktopVerification(failure)),
                CycleAction::Fatal
            );
        }
    }

    #[test]
    fn any_gone_observation_establishes_gone() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::StillPresent,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Gone,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::Gone
        );
    }

    #[test]
    fn all_unobservable_observations_do_not_establish_disappearance() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::StillPresent
        );
    }

    #[test]
    fn still_present_then_unobservable_does_not_establish_disappearance() {
        assert_eq!(
            fold_outcome_observations([
                OutcomeObservation::StillPresent,
                OutcomeObservation::Unobservable,
                OutcomeObservation::Unobservable,
            ]),
            ApplyOutcome::StillPresent
        );
    }

    #[test]
    fn unobservable_then_gone_establishes_disappearance() {
        assert_eq!(
            fold_outcome_observations(
                [OutcomeObservation::Unobservable, OutcomeObservation::Gone,]
            ),
            ApplyOutcome::Gone
        );
    }
}
