// SPDX-License-Identifier: GPL-2.0-or-later
//! Secure-desktop watcher. Desktop handles and UIA/process owners stay on the
//! thread that acquired them. Only bounded value observations cross thread joins.
//! The authenticated pipe peer and absolute lifetime are fixed before this runs.

use super::{
    Candidate, candidate_for, enumerate_without_budget, object_name,
    pipe_client::{WatchChannel, WatchRead},
    resources::{CleanupLog, OwnedDesktop},
    security, system_consent_path, uia, verify_input_desktop, verify_window_station,
};
use crate::{
    NativeOperation, ProbeCounts, ProbeFailure, ProbeReport,
    supervision::{
        ApplyOutcome, GoneReason, HelperMessage, RefusalReason, ServiceMessage, TargetIdentity,
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
};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
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
    VerificationFailed,
    One {
        identity: TargetIdentity,
        report: Option<ProbeReport>,
    },
    Ambiguous,
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
    let mut tracked: Option<Tracked> = None;
    let mut sequence = 0u32;
    let mut last_output = Instant::now();

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
                if matches!(outcome, ApplyOutcome::Gone)
                    && tracked.as_ref().map(|current| current.identity) == Some(target)
                {
                    tracked = None;
                }
            }
            WatchRead::Pending => {}
        }

        let desktop = open_input_desktop(cleanup)?;
        let desktop_name =
            object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName).map_err(|_| ())?;
        if began.elapsed() >= MAX_LIFETIME {
            drop(desktop);
            break;
        }
        if !desktop_name.eq_ignore_ascii_case("Winlogon") {
            if let Some(current) = tracked.take() {
                channel.write(&HelperMessage::Gone {
                    target: current.identity,
                    reason: GoneReason::DesktopChanged,
                })?;
                last_output = Instant::now();
            }
        } else {
            verify_input_desktop(desktop.raw()).map_err(|_| ())?;
            let next_sequence = sequence.checked_add(1).ok_or(())?;
            let census = scoped_census(
                desktop.raw(),
                session,
                &image,
                tracked.as_ref().map(|value| value.identity),
                next_sequence,
                cleanup,
            )?;
            if began.elapsed() >= MAX_LIFETIME {
                drop(desktop);
                break;
            }
            match census {
                Census::None => {
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Closed,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::Ambiguous => {
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Ambiguous,
                        })?;
                        last_output = Instant::now();
                    }
                }
                Census::VerificationFailed => {
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
                    if let Some(current) = tracked.take() {
                        channel.write(&HelperMessage::Gone {
                            target: current.identity,
                            reason: GoneReason::Replaced,
                        })?;
                    }
                    channel.write(&HelperMessage::Appeared {
                        target: identity,
                        report: report.clone(),
                    })?;
                    sequence = identity.sequence;
                    tracked = Some(Tracked { identity, report });
                    last_output = Instant::now();
                }
            }
        }
        drop(desktop);

        if began.elapsed() >= MAX_LIFETIME {
            break;
        }
        if last_output.elapsed() >= HEARTBEAT_INTERVAL {
            channel.write(&HelperMessage::Heartbeat { sequence })?;
            last_output = Instant::now();
        }
        let remaining = MAX_LIFETIME.saturating_sub(began.elapsed());
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL.min(remaining));
    }
    channel.finish()
}

fn open_input_desktop(cleanup: &CleanupLog) -> Result<OwnedDesktop> {
    // SAFETY: fixed zero flags, no inheritance and READOBJECTS only.
    let raw = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }
        .map_err(|_| ())?;
    OwnedDesktop::acquired(raw, cleanup).map_err(|_| ())
}

fn scoped_census(
    desktop: HDESK,
    session: u32,
    image: &[u16],
    tracked: Option<TargetIdentity>,
    next_sequence: u32,
    cleanup: &CleanupLog,
) -> Result<Census> {
    let token = desktop.0 as usize;
    let cleanup = Arc::clone(cleanup);
    std::thread::scope(|scope| {
        scope
            .spawn(move || worker_census(token, session, image, tracked, next_sequence, &cleanup))
            .join()
            .map_err(|_| ())?
    })
}

fn worker_census(
    token: usize,
    session: u32,
    image: &[u16],
    tracked: Option<TargetIdentity>,
    next_sequence: u32,
    cleanup: &CleanupLog,
) -> Result<Census> {
    security::reject_impersonation(cleanup).map_err(|_| ())?;
    // SAFETY: private token is a parent-owned HDESK retained through this scoped join.
    let desktop = HDESK(token as *mut c_void);
    // SAFETY: fresh windowless thread has made no user/COM objects. Assignment is
    // first and the desktop belongs to the verified current window station.
    unsafe { SetThreadDesktop(desktop) }.map_err(|_| ())?;
    verify_input_desktop(desktop).map_err(|_| ())?;
    let began = Instant::now();
    let windows = enumerate_without_budget(desktop).map_err(|_| ())?;
    let mut candidates = Vec::new();
    for hwnd in &windows {
        if let Some(candidate) = candidate_for(*hwnd, session, image, cleanup).map_err(|_| ())? {
            candidates.push(candidate);
            if candidates.len() > 1 {
                return Ok(Census::Ambiguous);
            }
        }
    }
    let Some(candidate) = candidates.pop() else {
        return Ok(Census::None);
    };
    let same = tracked.is_some_and(|value| native_identity(&candidate, value));
    let identity = if same {
        tracked.ok_or(())?
    } else {
        target_identity(&candidate, next_sequence)?
    };
    if candidate.recheck(session, image, cleanup).is_err() {
        return Ok(Census::VerificationFailed);
    }
    if same {
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
    let report = uia::inspect_without_budget(
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
    )
    .map_err(|_| ())?;
    candidate.recheck(session, image, cleanup).map_err(|_| ())?;
    Ok(Census::One {
        identity,
        report: Some(report),
    })
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
    while outcome_began.elapsed() < OUTCOME_WINDOW {
        std::thread::sleep(OUTCOME_INTERVAL);
        if target_is_gone(session, image, target, &cleanup)? {
            return Ok(ApplyOutcome::Gone);
        }
    }
    Ok(ApplyOutcome::StillPresent)
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

fn target_is_gone(
    session: u32,
    image: &[u16],
    target: TargetIdentity,
    cleanup: &CleanupLog,
) -> Result<bool> {
    let desktop = open_input_desktop(cleanup)?;
    if !object_name(HANDLE(desktop.raw().0), NativeOperation::DesktopName)
        .map_err(|_| ())?
        .eq_ignore_ascii_case("Winlogon")
    {
        return Ok(true);
    }
    let census = scoped_census(
        desktop.raw(),
        session,
        image,
        Some(target),
        target.sequence,
        cleanup,
    )?;
    Ok(!matches!(
        census,
        Census::One {
            identity,
            report: None
        } if identity == target
    ))
}
