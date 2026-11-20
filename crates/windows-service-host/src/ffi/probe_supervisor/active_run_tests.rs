// SPDX-License-Identifier: GPL-2.0-or-later
use super::{
    Error, Stage,
    active_run::{ActiveRun, RunIo},
    io::{Completed, Kind},
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc, time::Instant};

#[derive(Default)]
struct State {
    events: Vec<String>,
    next: usize,
    exited: bool,
    missing_child: bool,
    empty: bool,
    fail_cancel: bool,
    fail_poll: bool,
    terminal_error: bool,
    completions: VecDeque<Option<Completed>>,
}
#[derive(Clone, Default)]
struct FakeIo(Rc<RefCell<State>>);
struct Operation {
    io: FakeIo,
    id: usize,
    pending: bool,
    expected: Option<usize>,
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.io.event(format!("account:{}", self.id));
        assert!(!self.pending, "pending storage must be retained");
    }
}
impl FakeIo {
    fn event(&self, event: impl Into<String>) {
        self.0.borrow_mut().events.push(event.into());
    }
    fn complete(&self, completed: Option<Completed>) {
        self.0.borrow_mut().completions.push_back(completed);
    }
    fn finished(&self) {
        let mut state = self.0.borrow_mut();
        state.exited = true;
        state.empty = true;
    }
}
impl RunIo for FakeIo {
    type Operation = Operation;
    fn recheck(&self) -> Result<(), Error> {
        self.event("recheck");
        Ok(())
    }
    fn launch_child(&mut self, _: bool, _: Option<u64>, _: Instant) -> Result<(), Error> {
        self.event("launch");
        Ok(())
    }
    fn assign_and_authenticate(&mut self, _: Option<u64>) -> Result<(), Error> {
        self.event("assign_and_authenticate");
        Ok(())
    }
    fn resume(&self) -> Result<(), Error> {
        self.event("resume");
        Ok(())
    }
    fn authenticate_pipe(&self, _: Option<u64>) -> Result<(), Error> {
        Ok(())
    }
    fn session(&self) -> u32 {
        7
    }
    fn start(&self, kind: Kind<'_>, _: Stage, _: Option<Instant>) -> Result<Operation, Error> {
        let mut state = self.0.borrow_mut();
        let id = state.next;
        state.next += 1;
        state.events.push(format!("begin:{id}"));
        Ok(Operation {
            io: self.clone(),
            id,
            pending: true,
            expected: match kind {
                Kind::Write(bytes) => Some(bytes.len()),
                _ => None,
            },
        })
    }
    fn poll(&self, operation: &mut Operation) -> Result<Option<Completed>, Error> {
        self.event(format!("poll:{}", operation.id));
        let mut state = self.0.borrow_mut();
        if state.fail_poll {
            return Err(Error::InvalidReport);
        }
        if state.terminal_error {
            operation.pending = false;
            return Err(Error::InvalidReport);
        }
        let completed = state.completions.pop_front().unwrap_or(None);
        if completed.is_some() {
            operation.pending = false;
        }
        Ok(completed)
    }
    fn cancel(&self, operation: &mut Operation) -> Result<(), Error> {
        self.event(format!("cancel:{}", operation.id));
        if self.0.borrow().fail_cancel {
            Err(Error::CleanupUnconfirmed)
        } else {
            Ok(())
        }
    }
    fn in_flight(operation: &Operation) -> bool {
        operation.pending
    }
    fn expected_write_bytes(operation: &Operation) -> Option<usize> {
        operation.expected
    }
    fn wait_operation(&self, _: &Operation, _: u32) -> Result<(), Error> {
        Ok(())
    }
    fn wait_cleanup(&self, _: Option<&Operation>) -> bool {
        true
    }
    fn process_exited(&self, _: u32) -> Result<Option<bool>, Error> {
        let state = self.0.borrow();
        Ok((!state.missing_child).then_some(state.exited))
    }
    fn exit_code(&self) -> Result<u32, Error> {
        Ok(0)
    }
    fn job_empty(&self) -> Result<bool, Error> {
        Ok(self.0.borrow().empty)
    }
    fn terminate(&self, _: bool) -> Result<(), Error> {
        self.event("terminate");
        Ok(())
    }
    fn close_job(&mut self) {
        self.event("close_job");
    }
    fn close_failed(&self) -> bool {
        false
    }
}

fn connected_watch(io: &FakeIo) -> ActiveRun<FakeIo> {
    let mut run = ActiveRun::with_io(io.clone());
    run.launch_watch().unwrap();
    io.complete(Some(Completed::Count(0)));
    assert!(matches!(
        run.poll_watch().unwrap(),
        super::WatchPoll::Pending
    ));
    run.write_watch(&windows_prompt_probe::supervision::ServiceMessage::Stop)
        .unwrap();
    run
}

#[test]
fn launch_adopts_connect_before_resume_and_exit_drains_it_once() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.launch_watch().unwrap();
    assert_eq!(
        io.0.borrow().events,
        [
            "recheck",
            "launch",
            "assign_and_authenticate",
            "begin:0",
            "recheck",
            "resume",
        ]
    );
    io.finished();
    io.complete(Some(Completed::Count(0)));
    assert!(run.poll_cleanup().unwrap());
    assert!(run.poll_cleanup().unwrap());
    assert_eq!(
        io.0.borrow()
            .events
            .iter()
            .filter(|e| *e == "account:0")
            .count(),
        1
    );
}

#[test]
fn inspection_cannot_begin_with_watch_io_pending() {
    let io = FakeIo::default();
    let mut run = connected_watch(&io);
    assert_eq!(run.begin_inspection_write(&[1]), Err(Error::Busy));
    assert_eq!(
        run.begin_inspection_read(1, Stage::ReportRead),
        Err(Error::Busy)
    );
    assert_eq!(io.0.borrow().next, 3);
    io.finished();
    io.complete(Some(Completed::Eof));
    io.complete(Some(Completed::Count(1)));
    assert!(run.poll_cleanup().unwrap());
}

#[test]
fn shutdown_preserves_distinct_cancel_and_drain_failures() {
    use super::active_run::ShutdownDrainError;
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    io.0.borrow_mut().fail_cancel = true;
    assert!(matches!(
        run.drain_shutdown(),
        Err(ShutdownDrainError::Cancel)
    ));
    {
        let mut state = io.0.borrow_mut();
        state.fail_cancel = false;
        state.fail_poll = true;
    }
    assert!(matches!(
        run.drain_shutdown(),
        Err(ShutdownDrainError::Drain)
    ));
    assert_eq!(run.begin_inspection_write(&[2]), Err(Error::Busy));
    assert!(
        !io.0
            .borrow()
            .events
            .iter()
            .any(|e| e == "account:0" || e == "close_job")
    );
    io.0.borrow_mut().fail_poll = false;
    io.finished();
    io.complete(Some(Completed::Count(1)));
    assert!(matches!(run.drain_shutdown(), Ok(true)));
}

#[test]
fn cancellation_precedes_job_close_and_close_is_not_completion() {
    let io = FakeIo::default();
    let mut run = connected_watch(&io);
    run.close_for_shutdown().unwrap();
    let events = io.0.borrow().events.clone();
    let at = |event: &str| events.iter().position(|value| value == event).unwrap();
    assert!(at("cancel:1") < at("close_job"));
    assert!(at("cancel:2") < at("close_job"));
    assert!(!run.poll_cleanup().unwrap());
    io.finished();
    io.complete(Some(Completed::Eof));
    io.complete(Some(Completed::Count(1)));
    assert!(run.poll_cleanup().unwrap());
    run.close_for_shutdown().unwrap();
    drop(run);
    assert_eq!(
        io.0.borrow()
            .events
            .iter()
            .filter(|e| *e == "close_job")
            .count(),
        1
    );
}

#[test]
fn exit_drain_accounts_each_pending_operation_once_including_delayed_completion() {
    let io = FakeIo::default();
    let mut run = connected_watch(&io);
    io.finished();
    io.complete(None);
    io.complete(Some(Completed::Count(1)));
    assert!(!run.poll_cleanup().unwrap());
    io.complete(Some(Completed::Eof));
    assert!(run.poll_cleanup().unwrap());
    assert!(run.poll_cleanup().unwrap());
    for id in 0..3 {
        assert_eq!(
            io.0.borrow()
                .events
                .iter()
                .filter(|e| **e == format!("account:{id}"))
                .count(),
            1
        );
    }
}

#[test]
fn failed_cancel_keeps_job_and_pending_operation_until_cleanup_is_confirmed() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    io.0.borrow_mut().fail_cancel = true;
    assert_eq!(run.close_for_shutdown(), Err(Error::CleanupUnconfirmed));
    assert_eq!(run.cleanup(), Err(Error::CleanupUnconfirmed));
    assert!(
        !io.0
            .borrow()
            .events
            .iter()
            .any(|e| e == "close_job" || e == "account:0")
    );
    io.0.borrow_mut().fail_cancel = false;
    io.finished();
    io.complete(Some(Completed::Count(1)));
    assert!(run.cleanup().unwrap());
}

#[test]
fn failed_in_flight_drain_retains_operation_and_does_not_confirm_cleanup() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    io.finished();
    io.0.borrow_mut().fail_poll = true;
    assert_eq!(run.poll_cleanup(), Err(Error::CleanupUnconfirmed));
    assert!(!io.0.borrow().events.iter().any(|e| e == "account:0"));
    io.0.borrow_mut().fail_poll = false;
    io.complete(Some(Completed::Count(1)));
    assert!(run.poll_cleanup().unwrap());
}

#[test]
fn terminal_drain_error_releases_storage_but_still_requires_job_accounting() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    {
        let mut state = io.0.borrow_mut();
        state.exited = true;
        state.terminal_error = true;
    }
    assert!(!run.poll_cleanup().unwrap());
    io.finished();
    assert!(run.poll_cleanup().unwrap());
    assert_eq!(
        io.0.borrow()
            .events
            .iter()
            .filter(|e| *e == "account:0")
            .count(),
        1
    );
}

#[test]
fn inspection_cannot_replace_a_pending_operation() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    assert_eq!(run.begin_inspection_write(&[2]), Err(Error::Busy));
    assert_eq!(
        run.begin_inspection_read(1, Stage::ReportRead),
        Err(Error::Busy)
    );
    assert_eq!(io.0.borrow().next, 1);
    io.complete(Some(Completed::Count(1)));
    assert_eq!(
        run.poll_inspection_operation().unwrap(),
        Some(Completed::Count(1))
    );
    run.begin_inspection_read(1, Stage::EofRead).unwrap();
    io.complete(Some(Completed::Eof));
    assert_eq!(
        run.poll_inspection_operation().unwrap(),
        Some(Completed::Eof)
    );
}

#[test]
fn operation_wait_drains_buffered_completion_after_child_exit() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_read(1, Stage::EofRead).unwrap();
    io.finished();
    io.complete(None);
    io.complete(Some(Completed::Eof));
    assert_eq!(
        run.poll_inspection_operation().unwrap(),
        Some(Completed::Eof)
    );
    assert!(run.poll_cleanup().unwrap());
    assert_eq!(
        io.0.borrow()
            .events
            .iter()
            .filter(|e| *e == "account:0")
            .count(),
        1
    );
}

#[test]
fn no_child_is_not_exit_but_cleanup_can_account_an_empty_job() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    {
        let mut state = io.0.borrow_mut();
        state.missing_child = true;
        state.empty = true;
    }
    assert_eq!(run.process_exited(0), Err(Error::PeerMismatch));
    assert!(matches!(run.poll_watch(), Err(Error::PeerMismatch)));
    assert!(run.poll_cleanup().unwrap());
}

#[test]
fn dropping_owner_closes_its_job() {
    let io = FakeIo::default();
    drop(ActiveRun::with_io(io.clone()));
    assert_eq!(io.0.borrow().events, ["close_job"]);
}

#[test]
fn retaining_uncertain_owner_closes_job_without_releasing_pending_storage() {
    let io = FakeIo::default();
    let mut run = ActiveRun::with_io(io.clone());
    run.begin_inspection_write(&[1]).unwrap();
    run.retain_uncertain();
    assert_eq!(io.0.borrow().events, ["begin:0", "close_job"]);
}
