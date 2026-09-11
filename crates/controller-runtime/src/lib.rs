// SPDX-License-Identifier: GPL-2.0-or-later
//! Native-owned presentation orchestration. This crate does not authorize UAC.
#![forbid(unsafe_code)]

mod contract;
mod phone_history;
mod phone_requests;
mod runtime;
mod storage;
mod unwired;
#[cfg(windows)]
mod windows;
#[cfg(all(windows, target_pointer_width = "64"))]
mod windows_pairing;

pub use contract::*;
pub use notification_policy::{AlertMode, NotificationPolicy, Schedule};
pub use phone_history::{
    MAX_PHONE_HISTORY_JSON_BYTES, decode_phone_history_json, encode_phone_history,
    phone_history_issue,
};
pub use phone_requests::{
    MAX_PHONE_REQUEST_DETAILS_JSON_BYTES, MAX_PHONE_REQUESTS_JSON_BYTES, PhoneRequestCatalog,
    RequestCatalogState, RequestCatalogView, RequestDetailsView, RequestReviewView,
    check_request_locator, decode_phone_request_details_json, decode_phone_requests_json,
    phone_request_issue,
};
pub use runtime::{
    AppRuntime, DecisionIntent, MAX_COMPUTER_NAME_BYTES, MAX_COMPUTER_NAME_CHARACTERS,
    ObservedServiceState, PairingAttemptHandle, PairingFailure, PairingStarter, PairingUiPhase,
    PairingUiState, PlatformAdapter, PlatformError, ServiceCommandOutcome, ServiceObservation,
    UnavailablePairingStarter, UnavailablePlatformAdapter,
};
pub use storage::{
    AppPrivateDirectory, MAX_POLICY_DOCUMENT_BYTES, POLICY_DOCUMENT_VERSION, POLICY_FILE_NAME,
    POLICY_LOCK_FILE_NAME, POLICY_STAGING_FILE_NAME, PreferenceError,
    decode_notification_policy_document, decode_notification_policy_json,
};
pub use unwired::UnwiredCapability;
#[cfg(windows)]
pub use windows::WindowsPlatformAdapter;
#[cfg(all(windows, target_pointer_width = "64"))]
pub use windows_pairing::WindowsPairingStarter;
