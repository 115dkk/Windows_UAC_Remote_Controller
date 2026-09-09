// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use activity_journal::{OutcomeHistory, OutcomeHistoryLimits, OutcomeHistoryRecord, UnixMillis};
use notification_policy::{CapacityLimits, NotificationPolicy, RequestKey};
use phone_request_core::{
    InboxClock, InboxFault, OutcomeDeliveryId, PendingOutcome, PhoneBootId, PhoneInbox,
};
use phone_state_store::{
    CommitReceipt, Durability, NativePrivateDirectory, SnapshotStore, Transition,
};
use service_protocol::{ClockCorrelation, VerifiedPcEvent};

use crate::{
    CommittedCheck, CommittedHistoryMutation, CommittedOutcomeAcknowledgment, CommittedUpdate,
    ControllerCheckpoint, DurableFailure, DurableFault, InboxCounts, LocalAttestationChallenge,
    LocalKeyHandle, LocalKeyLedger, LocalKeyMutationError, LocalKeyObservation,
    LocalKeySetDescriptor,
};

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
    history: OutcomeHistory,
    local_keys: LocalKeyLedger,
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
            |_| Ok(()),
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
            |_| Ok(()),
        )
    }

    /// Native Application preflight runs under the existing byte-store lock,
    /// after strict decoding and policy-only checks, but BEFORE migration or
    /// restore writes. It may inspect/reopen native keys, never generate them.
    /// The caller owns partial native-reference cleanup if its callback fails.
    pub fn open_existing_policy_only_with_key_preflight(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
        preflight: impl FnOnce(&ControllerCheckpoint) -> Result<(), DurableFault>,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::open_with_durability(
            directory,
            boot,
            clock,
            RequiredDurability::DirectorySynced,
            true,
            preflight,
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
            |_| Ok(()),
        )
    }

    /// Explicit host filesystem test profile for the identical preflight order;
    /// never compiled into Android and never a native durability fallback.
    #[cfg(not(target_os = "android"))]
    pub fn open_existing_host_model_with_key_preflight(
        directory: NativePrivateDirectory,
        boot: PhoneBootId,
        clock: InboxClock,
        preflight: impl FnOnce(&ControllerCheckpoint) -> Result<(), DurableFault>,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        Self::open_with_durability(
            directory,
            boot,
            clock,
            RequiredDurability::ExplicitHostModel,
            true,
            preflight,
        )
    }

    pub fn local_keys(&self) -> Result<&LocalKeyLedger, DurableFault> {
        self.ensure_healthy()?;
        Ok(&self.local_keys)
    }

    /// Local generation bookkeeping, not pairing or permission to retry native
    /// creation. A caller must generate handle/challenge through the trusted
    /// pairing owner, durably reserve here, then consume its native request once.
    pub fn begin_local_key_creation(
        &mut self,
        handle: LocalKeyHandle,
        challenge: LocalAttestationChallenge,
    ) -> Result<CommitReceipt, LocalKeyMutationError> {
        self.ensure_healthy()
            .map_err(|fault| LocalKeyMutationError::Owner(DurableFailure::new(fault)))?;
        let mut candidate = self.local_keys.clone();
        candidate
            .begin_creation(handle, challenge)
            .map_err(LocalKeyMutationError::Rejected)?;
        self.transition_all(|_, _, keys| {
            *keys = candidate;
            Ok(())
        })
        .map(|(receipt, ())| receipt)
        .map_err(LocalKeyMutationError::Owner)
    }

    /// Preserve only exact native-observed public key identities. This does not
    /// attest them or enroll a PC. On a failed write, surviving native aliases
    /// must not be deleted or recreated as a purported rollback.
    pub fn record_local_key_creation(
        &mut self,
        descriptor: LocalKeySetDescriptor,
    ) -> Result<(CommitReceipt, LocalKeyObservation), LocalKeyMutationError> {
        self.ensure_healthy()
            .map_err(|fault| LocalKeyMutationError::Owner(DurableFailure::new(fault)))?;
        let mut candidate = self.local_keys.clone();
        let observation = candidate
            .record_created(descriptor)
            .map_err(LocalKeyMutationError::Rejected)?;
        self.transition_all(|_, _, keys| {
            *keys = candidate;
            Ok(observation)
        })
        .map_err(LocalKeyMutationError::Owner)
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

    /// Sole source for native outcome delivery, from the last committed state.
    /// Insert each row idempotently into the durable journal by delivery_id,
    /// then call acknowledge_outcome. Reading/retrying is not OS delivery and
    /// does not emit notifications/history or change a request's original life.
    pub fn pending_outcomes(&self) -> Result<&[PendingOutcome], DurableFault> {
        self.ensure_healthy()?;
        Ok(self.inbox.pending_outcomes())
    }

    /// Last committed body-free display history, oldest insertion first. This
    /// is not an approval result and cannot supply request/peer authority.
    pub fn history(&self) -> Result<&[OutcomeHistoryRecord], DurableFault> {
        self.ensure_healthy()?;
        Ok(self.history.records())
    }

    /// Put pending outcomes into history and remove exactly those producer rows
    /// in ONE snapshot commit. No native timestamp means the caller must not
    /// invoke this operation; UNIX time affects display/retention, not decisions.
    /// A commit failure exposes neither the candidate history nor an ACK.
    pub fn record_pending_outcomes(
        &mut self,
        recorded_at: UnixMillis,
    ) -> Result<CommittedHistoryMutation, DurableFailure> {
        let (receipt, affected) = self.transition_owner(|inbox, history| {
            // The queue is already bounded/committed by this same sole owner.
            // Snapshot consistency forbids recorded/pending overlap, including
            // a supposed partial write from a second recipient (none exists).
            let pending = inbox.pending_outcomes().to_vec();
            if pending.iter().any(|row| {
                history
                    .records()
                    .iter()
                    .any(|record| record.delivery_id() == row.delivery_id().as_bytes())
            }) {
                return Err(DurableFault::Composite(
                    crate::ControllerCheckpointError::RecordedPendingOverlap,
                ));
            }
            for row in &pending {
                history
                    .record_pending(row, recorded_at)
                    .map_err(DurableFault::History)?;
                if inbox.acknowledge_outcome(row.delivery_id())
                    != phone_request_core::OutcomeAcknowledgment::Removed
                {
                    return Err(DurableFault::TransitionIncomplete);
                }
            }
            // Even an empty outbox can have aged visible history. Never touches
            // source watermarks, suppression guards, policy or authentication.
            let _ = history.prune(recorded_at);
            Ok(pending.len())
        })?;
        Ok(CommittedHistoryMutation { receipt, affected })
    }

    /// Delete the currently visible history only. Pending rows are deliberately
    /// preserved; native UI must reconcile them first if clearing that whole
    /// displayed view. Replay/source state is never erased by this command.
    pub fn clear_history(&mut self) -> Result<CommittedHistoryMutation, DurableFailure> {
        let (receipt, affected) = self.transition_owner(|_, history| Ok(history.clear()))?;
        Ok(CommittedHistoryMutation { receipt, affected })
    }

    /// Commit-backed removal only, after the native journal has durably inserted
    /// or deduplicated this exact delivery ID. This API cannot prove that journal
    /// operation occurred. Unknown/duplicate IDs report NotPending, never delivered.
    /// No clock or request state is fabricated merely to acknowledge metadata.
    pub fn acknowledge_outcome(
        &mut self,
        id: OutcomeDeliveryId,
    ) -> Result<CommittedOutcomeAcknowledgment, DurableFailure> {
        let (receipt, acknowledgment) = self.transition(|inbox| inbox.acknowledge_outcome(id))?;
        Ok(CommittedOutcomeAcknowledgment {
            receipt,
            acknowledgment,
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
        let history = OutcomeHistory::new(OutcomeHistoryLimits::default());
        let local_keys = LocalKeyLedger::default();
        let initial = match encode(&inbox, &history, &local_keys) {
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
            history,
            local_keys,
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
        preflight: impl FnOnce(&ControllerCheckpoint) -> Result<(), DurableFault>,
    ) -> Result<(Self, CommittedUpdate), DurableFailure> {
        let mut store = SnapshotStore::open_existing(directory)
            .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?;
        // The store already bounds this metadata-only copy to 384 KiB. It lets
        // the store's exclusive guard remain alive through decoding/restoration.
        let bytes = store
            .snapshot()
            .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?
            .to_vec();
        let (transition, preview) = if policy_only {
            let preview = ControllerCheckpoint::from_bytes(&bytes)
                .map_err(|error| DurableFailure::new(DurableFault::Composite(error)))?;
            if !preview.inbox().is_policy_only() {
                return Err(DurableFailure::new(
                    DurableFault::LifecycleIntegrationRequired,
                ));
            }
            preflight(&preview).map_err(DurableFailure::new)?;
            let transition = store
                .begin_transition()
                .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?;
            (transition, preview)
        } else {
            // Keep the original full recovery contract: once full restoration
            // starts, even invalid domain bytes leave its durable intent. Only
            // the explicit policy/key preflight path rejects before mutation.
            let transition = store
                .begin_transition()
                .map_err(|error| DurableFailure::new(DurableFault::Storage(error)))?;
            let preview = ControllerCheckpoint::from_bytes(&bytes)
                .map_err(|error| DurableFailure::new(DurableFault::Composite(error)))?;
            preflight(&preview).map_err(DurableFailure::new)?;
            (transition, preview)
        };
        let (checkpoint, history, local_keys) = preview.into_parts();
        let (mut inbox, update) = PhoneInbox::restore_checkpoint(checkpoint, boot, clock)
            .map_err(|error| DurableFailure::new(DurableFault::Checkpoint(error)))?;
        let receipt = match commit_candidate(
            transition,
            &inbox,
            &history,
            &local_keys,
            required_durability,
        ) {
            Ok(receipt) => receipt,
            Err(cause) => return Err(stop_unowned(&mut inbox, cause)),
        };
        Ok((
            Self {
                store,
                inbox,
                history,
                local_keys,
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
        self.transition_owner(|inbox, _| Ok(operation(inbox)))
    }

    fn transition_owner<T>(
        &mut self,
        operation: impl FnOnce(&mut PhoneInbox, &mut OutcomeHistory) -> Result<T, DurableFault>,
    ) -> Result<(CommitReceipt, T), DurableFailure> {
        self.transition_all(|inbox, history, _| operation(inbox, history))
    }

    fn transition_all<T>(
        &mut self,
        operation: impl FnOnce(
            &mut PhoneInbox,
            &mut OutcomeHistory,
            &mut LocalKeyLedger,
        ) -> Result<T, DurableFault>,
    ) -> Result<(CommitReceipt, T), DurableFailure> {
        self.ensure_healthy().map_err(DurableFailure::new)?;
        // Read-only APIs must not expose a candidate if an unexpected unwind is
        // caught by a native caller. Only complete durable success clears this.
        self.fault = Some(DurableFault::TransitionIncomplete);
        let result = run_transition(
            &mut self.store,
            &mut self.inbox,
            &mut self.history,
            &mut self.local_keys,
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

fn encode(
    inbox: &PhoneInbox,
    history: &OutcomeHistory,
    local_keys: &LocalKeyLedger,
) -> Result<Vec<u8>, DurableFault> {
    let checkpoint = inbox.checkpoint().map_err(DurableFault::Checkpoint)?;
    ControllerCheckpoint::with_local_keys(checkpoint, history.clone(), local_keys.clone())
        .and_then(|value| value.to_bytes())
        .map_err(DurableFault::Composite)
}

fn commit_candidate(
    transition: Transition<'_>,
    inbox: &PhoneInbox,
    history: &OutcomeHistory,
    local_keys: &LocalKeyLedger,
    required_durability: RequiredDurability,
) -> Result<CommitReceipt, DurableFault> {
    let bytes = encode(inbox, history, local_keys)?;
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
    history: &mut OutcomeHistory,
    local_keys: &mut LocalKeyLedger,
    required_durability: RequiredDurability,
    operation: impl FnOnce(
        &mut PhoneInbox,
        &mut OutcomeHistory,
        &mut LocalKeyLedger,
    ) -> Result<T, DurableFault>,
) -> Result<(CommitReceipt, T), DurableFault> {
    let transition = store.begin_transition().map_err(DurableFault::Storage)?;
    let mut candidate_owner = UncommittedInbox {
        inbox,
        completed: false,
    };
    let candidate = operation(&mut *candidate_owner.inbox, history, local_keys)?;
    let receipt = commit_candidate(
        transition,
        &*candidate_owner.inbox,
        history,
        local_keys,
        required_durability,
    )?;
    candidate_owner.completed = true;
    Ok((receipt, candidate))
}
