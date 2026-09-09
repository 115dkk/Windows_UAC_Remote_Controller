// SPDX-License-Identifier: GPL-2.0-or-later

//! Native commit-before-effects phone inbox ownership, not authorization.
//!
//! [`DurableInbox`] exclusively owns one domain inbox and one locked byte store.
//! Every mutating call reserves durable intent before classification and commits
//! the complete body-free checkpoint before releasing an update or request view.
//! File/codec failures latch the owner and require clearing its OS request
//! notifications; no failed candidate effects or bodies escape.
//!
//! All storage I/O is blocking. Use one native background owner, not the UI or a
//! renderer command. A successful commit is neither OS delivery nor approval:
//! callers must take fresh native time after I/O, recheck current pending state,
//! enrollment, screen-lock and per-use authentication before any applicable
//! native action. This crate contains no notification, authentication, signing,
//! private-key, FFI or application-runtime implementation. The optional peer
//! socket owner binds the existing TLS/socket pipeline to a recorded association;
//! it does not establish pairing or activate Application intake/authentication.

#![forbid(unsafe_code)]

mod approval;
mod associated_request;
mod checkpoint;
mod denial;
mod liveness;
mod local_keys;
mod owner;
mod peer_associations;
mod peer_socket;
mod types;

pub use approval::{
    ApprovalAttempt, ApprovalClock, ApprovalClockError, ApprovalError, ApprovalPlan,
    ApprovalPlanOwner, ApprovalSubmission, ApprovalTime, ApprovalTransition,
};
pub use associated_request::{
    AssociatedPendingRequest, AssociatedRequestIssue, CommittedAssociatedCheck,
    RequestSourceFailure,
};
pub use checkpoint::{ControllerCheckpoint, ControllerCheckpointError};
pub use denial::{DenialAttempt, DenialError, DenialOwner, DenialTransition, PreparedDenial};
pub use liveness::{NativePeerLease, PeerLeaseError};
pub use local_keys::{
    LocalAttestationChallenge, LocalKeyError, LocalKeyHandle, LocalKeyLedger, LocalKeyObservation,
    LocalKeySetDescriptor, LocalKeySetPhase, MAX_LOCAL_KEY_LEDGER_BYTES, MAX_LOCAL_KEY_SETS,
};
pub use owner::DurableInbox;
pub use peer_associations::{
    MAX_PEER_ASSOCIATION_LEDGER_BYTES, MAX_PEER_ASSOCIATIONS, PeerAssociation,
    PeerAssociationDescriptor, PeerAssociationError, PeerAssociationLedger,
    PeerAssociationMutation, PeerAssociationRef, PeerAssociationRemoval,
};
pub use peer_socket::{
    ApprovalSendOutcome, ApprovalSendTransition, ApprovalWriteProgress, AssociatedPcSocket,
    AssociatedUpdate, DenialSendOutcome, DenialSendTransition, DenialWriteProgress, PcSocketEvent,
    PcSocketInputs, PeerSocketError, QueuedApproval, QueuedDenial, ReceivedPcEvent, SendIssue,
    SendRetry,
};
pub use types::{
    CommittedCheck, CommittedHistoryMutation, CommittedOutcomeAcknowledgment, CommittedUpdate,
    DurableFailure, DurableFault, InboxCounts, LocalKeyMutationError, NotificationCleanup,
    PeerAssociationMutationError,
};
