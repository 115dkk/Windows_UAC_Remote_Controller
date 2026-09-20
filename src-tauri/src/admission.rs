// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded native work admission, not an authorization decision.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Default)]
pub(super) struct CommandAdmission(Arc<AtomicBool>);

impl CommandAdmission {
    pub(super) fn try_enter(&self) -> Option<CommandLease> {
        self.0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| CommandLease(Arc::clone(&self.0)))
    }
}

/// Moved into the actual blocking task: cancelling its caller cannot admit a
/// second task while native work still runs. Unwind also releases the lease.
pub(super) struct CommandLease(Arc<AtomicBool>);

impl Drop for CommandLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::CommandAdmission;

    #[test]
    fn clones_share_one_slot_and_rejection_does_not_queue_work() {
        let admission = CommandAdmission::default();
        let clone = admission.clone();
        let first = admission.try_enter().expect("first task admitted");
        for _ in 0..1024 {
            assert!(clone.try_enter().is_none());
        }
        drop(first);
        assert!(clone.try_enter().is_some());
    }

    #[test]
    fn a_worker_owns_the_slot_until_it_finishes_even_if_caller_is_gone() {
        let admission = CommandAdmission::default();
        let lease = admission.try_enter().expect("first task admitted");
        let (release, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _lease = lease;
            wait.recv().expect("root test release");
        });
        assert!(admission.try_enter().is_none());
        release.send(()).expect("worker exists");
        worker.join().expect("worker finished");
        assert!(admission.try_enter().is_some());
    }

    #[test]
    fn unwind_releases_admission_without_changing_runtime_poison_rules() {
        let admission = CommandAdmission::default();
        let result = std::panic::catch_unwind(|| {
            let _lease = admission.try_enter().expect("first task admitted");
            panic!("synthetic worker unwind");
        });
        assert!(result.is_err());
        assert!(admission.try_enter().is_some());
    }
}
