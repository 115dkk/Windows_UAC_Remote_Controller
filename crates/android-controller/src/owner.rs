// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use notification_policy::{CapacityLimits, NotificationPolicy, RequestKey};
use phone_request_core::{InboxCheckpoint, InboxClock, InboxFault, PhoneBootId, PhoneInbox};
use phone_state_store::{
    CommitReceipt, Durability, NativePrivateDirectory, SnapshotStore, Transition,
};
use service_protocol::{ClockCorrelation, VerifiedPcEvent};

use crate::{CommittedCheck, CommittedUpdate, DurableFailure, DurableFault, InboxCounts};

#[derive(Clone, Copy, Debug)]
enum RequiredDurability {
    DirectorySynced,
    #[cfg(not(target_os = "android"))]
    ExplicitHostModel,
}

impl RequiredDurability {
    fn check(self, receipt: CommitReceipt) -> Result<CommitReceipt, DurableFault> {
        let accepted = match self {
            Self::DirectorySynced => receipt.durability() == Durability::DirectorySynced,
            #[cfg(not(target_os = "android"))]
            Self::ExplicitHostModel => matches!(
                receipt.durability(),
                Durability::DirectorySynced | Durability::FileSyncedOnly
            ),
        };
        if accepted {
            Ok(receipt)
        } else {
            Err(DurableFault::DirectorySynchronizationRequired)
        }
    }
}

/// One native owner, one inbox, and one lifetime-locked snapshot store.
///
/// Neither owned component is cloneable or exposed. Every mutable domain method
/// reserves intent first, keeps its candidate private, then serializes/commits
/// the complete checkpoint. No-op candidates still complete their reservation.
/// Errors latch this owner until drop; there is no retry, reset, or raw mutation.
///
/// The snapshot policy is the sole policy source here. Open never substitutes
/// separate preferences or creates a new AppRuntime. Native directory ownership,
/// fresh-enrollment authority, backup/rollback protection, current enrolled peer
/// verification and real boot/clock observations remain caller requirements.
pub struct DurableInbox {
    store: SnapshotStore,
    inbox: PhoneInbox,
    required_durability: RequiredDurability,
    fault: Option<DurableFault>,
}

impl fmt::Debug for DurableInbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableInbox")
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

impl DurableInbox {
    /// Explicit native fresh-state creation; never a fallback from an open error.
    ///
    /// Requires actual DirectorySynced receipts for both the initial empty state
    /// and the first clock transition. A rejected/failed creation can leave store
    /// artifacts; no cleanup or claim that the prior state survived is made.
    pub fn create_fresh(
        directory: NativePrivateDirectory,
        policy: NotificationPolicy,
        limits: CapacityLimits,
        boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::create_with_durability(
            directory,
            policy,
            limits,
            boot,
            clock,
            RequiredDurability::DirectorySynced,
        )
    }

    /// Open only existing native state. Reserve intent before decoding/restoring
    /// the domain state, commit restore/poll effects, then expose the owner.
    /// Missing/invalid/interrupted state never becomes fresh/default state.
    pub fn open_existing(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::open_with_durability(
            directory,
            boot,
            clock,
            RequiredDurability::DirectorySynced,
            false,
        )
    }

    /// Staging policy ABI preflight under the same writer lock. This refuses
    /// request-bearing state BEFORE a recovery can commit and consume effects.
    pub fn open_existing_policy_only(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::open_with_durability(
            directory,
            boot,
            clock,
            RequiredDurability::DirectorySynced,
            true,
        )
    }

    /// Explicit non-Android filesystem model only. Windows FileSyncedOnly receipts
    /// are allowed here, not in the native factory. This API does not compile on
    /// Android and provides no Android power-loss/device durability evidence.
    #[cfg(not(target_os = "android"))]
    pub fn create_fresh_host_model(
        directory: NativePrivateDirectory,
        policy: NotificationPolicy,
        limits: CapacityLimits,
        boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::create_with_durability(
            directory,
            policy,
            limits,
            boot,
            clock,
            RequiredDurability::ExplicitHostModel,
        )
    }

    /// Explicit non-Android filesystem model; never an automatic native fallback.
    #[cfg(not(target_os = "android"))]
    pub fn open_existing_host_model(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::open_with_durability(
            directory,
            boot,
            clock,
            RequiredDurability::ExplicitHostModel,
            false,
        )
    }

    pub const fn fault(&self) -> Option<DurableFault> {
        self.fault
    }

    /// Only available while no uncommitted/uncertain owner transition exists.
    pub fn policy(&self) -> Result<&NotificationPolicy, DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.policy())
    }

    pub fn limits(&self) -> Result<CapacityLimits, DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.limits())
    }

    pub fn counts(&self) -> Result<InboxCounts, DurableFault> {
        self.ensure_healthy()?;
        Ok(InboxCounts {
            active: self.inbox.active_count(),
            retained: self.inbox.retained_count(),
            retained_bodies: self.inbox.retained_body_count(),
            recovering: self.inbox.recovering_count(),
            sources: self.inbox.source_count(),
        })
    }

    pub fn inbox_fault(&self) -> Result<Option<InboxFault>, DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.fault())
    }

    /// Scheduling hint only, never permission to display or approve a request.
    pub fn next_deadline_nanos(&self) -> Result<Option<u64>, DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.next_deadline_nanos())
    }

    pub fn is_quarantined(&self) -> Result<bool, DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.is_quarantined())
    }

    pub fn receive_opened(
        &mut self,
        event: &VerifiedPcEvent,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> Result<CommittedUpdate, DurableFailure> {
        let (receipt, update) =
            self.transition(|inbox| inbox.receive_opened(event, correlation, clock))?;
        Ok(CommittedUpdate { receipt, update })
    }

    pub fn resolve_pc(
        &mut self,
        event: &VerifiedPcEvent,
        correlation: &mut ClockCorrelation,
        clock: InboxClock,
    ) -> Result<CommittedUpdate, DurableFailure> {
        let (receipt, update) =
            self.transition(|inbox| inbox.resolve_pc(event, correlation, clock))?;
        Ok(CommittedUpdate { receipt, update })
    }

    pub fn observe_service_clock(
        &mut self,
        correlation: &ClockCorrelation,
        clock: InboxClock,
    ) -> Result<CommittedUpdate, DurableFailure> {
        let (receipt, update) =
            self.transition(|inbox| inbox.observe_service_clock(correlation, clock))?;
        Ok(CommittedUpdate { receipt, update })
    }

    pub fn poll(&mut self, clock: InboxClock) -> Result<CommittedUpdate, DurableFailure> {
        let (receipt, update) = self.transition(|inbox| inbox.poll(clock))?;
        Ok(CommittedUpdate { receipt, update })
    }

    pub fn update_policy(
        &mut self,
        policy: NotificationPolicy,
        clock: InboxClock,
    ) -> Result<CommittedUpdate, DurableFailure> {
        let (receipt, update) = self.transition(|inbox| inbox.update_policy(policy, clock))?;
        Ok(CommittedUpdate { receipt, update })
    }

    pub fn check_pending(
        &mut self,
        key: RequestKey,
        clock: InboxClock,
    ) -> Result<CommittedCheck, DurableFailure> {
        let (receipt, check) = self.transition(|inbox| inbox.check_pending(key, clock))?;
        Ok(CommittedCheck { receipt, check })
    }

    fn create_with_durability(
        directory: NativePrivateDirectory,
        policy: NotificationPolicy,
        limits: CapacityLimits,
        boot: PhoneBootId,
        clock: InboxClock,
        required_durability: RequiredDurability,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        let mut inbox = PhoneInbox::with_phone_boot(policy, limits, boot);
        let initial = match encode(&inbox) {
            Ok(initial) => initial,
            Err(cause) => return Err(stop_unowned(&mut inbox, cause)),
        };
        let (store, receipt) = match SnapshotStore::create_fresh(directory, &initial) {
            Ok(created) => created,
            Err(error) => return Err(stop_unowned(&mut inbox, DurableFault::Storage(error))),
        };
        if let Err(cause) = required_durability.check(receipt) {
            return Err(stop_unowned(&mut inbox, cause));
        }
        let mut owner = Self {
            store,
            inbox,
            required_durability,
            fault: None,
        };
        // The initial empty checkpoint is already durable. Clock observation is
        // a separate domain mutation and must reserve intent before it occurs.
        let initialized = owner.poll(clock)?;
        Ok((owner, initialized))
    }

    fn open_with_durability(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
        required_durability: RequiredDurability,
        policy_only: bool,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        let mut store = SnapshotStore::open_existing(directory)
            .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?;
        // The store already bounds this metadata-only copy to 384 KiB. It lets
        // the store's exclusive guard remain alive through decoding/restoration.
        let bytes = store
            .snapshot()
            .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?
            .to_vec();
        if policy_only {
            let preview = InboxCheckpoint::from_bytes(&bytes)
                .map_err(|error| DurableFailure::new(DurableFault::Checkpoint(error)))?;
            if !preview.is_policy_only() {
                return Err(DurableFailure::new(
                    DurableFault::LifecycleIntegrationRequired,
                ));
            }
        }
        let transition = store
            .begin_transition()
            .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?;
        let checkpoint = InboxCheckpoint::from_bytes(&bytes)
            .map_err(|error| DurableFailure::new(DurableFault::Checkpoint(error)))?;
        let (mut inbox, update) = PhoneInbox::restore_checkpoint(checkpoint, boot, clock)
            .map_err(|error| DurableFailure::new(DurableFault::Checkpoint(error)))?;
        let receipt = match commit_candidate(transition, &inbox, required_durability) {
            Ok(receipt) => receipt,
            Err(cause) => return Err(stop_unowned(&mut inbox, cause)),
        };
        Ok((
            Self {
                store,
                inbox,
                required_durability,
                fault: None,
            },
            CommittedUpdate { receipt, update },
        ))
    }

    fn ensure_healthy(&self) -> Result<(), DurableFault> {
        self.fault.map_or(Ok(()), Err)
    }

    fn transition<T>(
        &mut self,
        operation: impl FnOnce(&mut PhoneInbox) -> T,
    ) -> Result<(CommitReceipt, T), DurableFailure> {
        self.ensure_healthy().map_err(DurableFailure::new)?;
        // Read-only APIs must not expose a candidate if an unexpected unwind is
        // caught by a native caller. Only complete durable success clears this.
        self.fault = Some(DurableFault::TransitionIncomplete);
        let result = run_transition(
            &mut self.store,
            &mut self.inbox,
            self.required_durability,
            operation,
        );
        match result {
            Ok(committed) => {
                self.fault = None;
                Ok(committed)
            }
            Err(cause) => {
                self.fault = Some(cause);
                Err(stop_unowned(&mut self.inbox, cause))
            }
        }
    }
}

fn encode(inbox: &PhoneInbox) -> Result<Vec<u8>, DurableFault> {
    inbox
        .checkpoint()
        .and_then(|checkpoint| checkpoint.to_bytes())
        .map_err(DurableFault::Checkpoint)
}

fn commit_candidate(
    transition: Transition<'_>,
    inbox: &PhoneInbox,
    required_durability: RequiredDurability,
) -> Result<CommitReceipt, DurableFault> {
    let bytes = encode(inbox)?;
    let receipt = transition.commit(&bytes).map_err(DurableFault::Storage)?;
    required_durability.check(receipt)
}

fn stop_unowned(inbox: &mut PhoneInbox, cause: DurableFault) -> DurableFailure {
    // Clear-all is deliberately stronger than enumerating just this candidate's
    // withdrawals: it covers old OS notifications and undecodable saved IDs.
    drop(inbox.stop_for_owner_failure());
    DurableFailure::new(cause)
}

struct UncommittedInbox<'a> {
    inbox: &'a mut PhoneInbox,
    completed: bool,
}

impl Drop for UncommittedInbox<'_> {
    fn drop(&mut self) {
        if !self.completed {
            drop(self.inbox.stop_for_owner_failure());
        }
    }
}

fn run_transition<T>(
    store: &mut SnapshotStore,
    inbox: &mut PhoneInbox,
    required_durability: RequiredDurability,
    operation: impl FnOnce(&mut PhoneInbox) -> T,
) -> Result<(CommitReceipt, T), DurableFault> {
    let transition = store.begin_transition().map_err(DurableFault::Storage)?;
    let mut candidate_owner = UncommittedInbox {
        inbox,
        completed: false,
    };
    let candidate = operation(&mut *candidate_owner.inbox);
    let receipt = commit_candidate(transition, &*candidate_owner.inbox, required_durability)?;
    candidate_owner.completed = true;
    Ok((receipt, candidate))
}
