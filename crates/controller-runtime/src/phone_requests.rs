// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict display-only native request projection. No keys, wire or authority.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{AppIssue, RequestState, RequestView};

pub const MAX_PHONE_REQUESTS_JSON_BYTES: usize = 512 * 1024;
pub const MAX_PHONE_REQUEST_DETAILS_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_REQUESTS: usize = 32;
const MAX_CONTENT_FIELD_BYTES: usize = 96 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestCatalogState {
    Unavailable,
    Reconciling,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCatalogView {
    pub status: RequestCatalogState,
    /// Canonical decimal u64, never a lossy JavaScript number.
    pub revision: String,
    pub peer_count: u8,
    pub connected_peer_count: u8,
}

#[derive(Debug)]
pub struct PhoneRequestCatalog {
    pub catalog: RequestCatalogView,
    pub requests: Vec<RequestView>,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReviewView {
    pub locator: String,
    pub revision: String,
}

impl std::fmt::Debug for RequestReviewView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequestReviewView([redacted])")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CatalogDocument {
    version: u8,
    status: RequestCatalogState,
    revision: String,
    peer_count: u8,
    connected_peer_count: u8,
    requests: Vec<RequestView>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequestDetailsView {
    pub version: u8,
    pub id: String,
    pub program_name: String,
    pub executable_path: String,
    pub details: String,
    pub remaining_seconds: u32,
    pub refresh_after_millis: u32,
}

impl std::fmt::Debug for RequestDetailsView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RequestDetailsView([redacted])")
    }
}

pub const fn phone_request_issue() -> AppIssue {
    AppIssue {
        code: "phone_request_unavailable",
        message: "요청을 확인할 수 없어요.",
        next_action: Some("컴퓨터에서 요청 상태를 확인하세요."),
    }
}

/// A native-generated review locator only. Matching this format grants nothing.
pub fn check_request_locator(value: &str) -> Result<(), AppIssue> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(phone_request_issue())
    }
}

fn valid_display_window(remaining_seconds: u32, refresh_after_millis: u32) -> bool {
    (1..=300).contains(&remaining_seconds)
        && refresh_after_millis <= 60_000
        && refresh_after_millis <= remaining_seconds * 1000
}

fn valid_text(value: &str, max_utf16: usize) -> bool {
    !value.contains('\0') && value.encode_utf16().count() <= max_utf16
}

pub fn decode_phone_requests_json(bytes: &[u8]) -> Result<PhoneRequestCatalog, AppIssue> {
    if bytes.len() > MAX_PHONE_REQUESTS_JSON_BYTES {
        return Err(phone_request_issue());
    }
    let document: CatalogDocument =
        serde_json::from_slice(bytes).map_err(|_| phone_request_issue())?;
    let revision = document
        .revision
        .parse::<u64>()
        .map_err(|_| phone_request_issue())?;
    if document.version != 1
        || revision.to_string() != document.revision
        || usize::from(document.peer_count) > MAX_REQUESTS
        || document.connected_peer_count > document.peer_count
        || document.requests.len() > MAX_REQUESTS
        || document.peer_count == 0 && !document.requests.is_empty()
    {
        return Err(phone_request_issue());
    }
    let mut seen = BTreeSet::new();
    for request in &document.requests {
        check_request_locator(&request.id)?;
        if !seen.insert(&request.id)
            || request.computer_name != "연결한 컴퓨터"
            || !valid_text(&request.program_name, 512)
            || !valid_text(&request.executable_path, 1024)
            || (request.program_elided || request.path_elided) && !request.has_details
            || !valid_display_window(request.remaining_seconds, request.refresh_after_millis)
            || request.state == RequestState::Expired
            || request.can_approve && request.state != RequestState::Pending
            || request.state == RequestState::Unavailable && request.can_deny
        {
            return Err(phone_request_issue());
        }
    }
    Ok(PhoneRequestCatalog {
        requests: if document.status == RequestCatalogState::Ready {
            document.requests
        } else {
            Vec::new()
        },
        catalog: RequestCatalogView {
            status: document.status,
            revision: document.revision,
            peer_count: document.peer_count,
            connected_peer_count: document.connected_peer_count,
        },
    })
}

/// On-demand details must still match the locator requested by this invocation.
/// Caller/renderer may display these strings as text only, never markup or code.
pub fn decode_phone_request_details_json(
    bytes: &[u8],
    expected_locator: &str,
) -> Result<RequestDetailsView, AppIssue> {
    check_request_locator(expected_locator)?;
    if bytes.len() > MAX_PHONE_REQUEST_DETAILS_JSON_BYTES {
        return Err(phone_request_issue());
    }
    let value: RequestDetailsView =
        serde_json::from_slice(bytes).map_err(|_| phone_request_issue())?;
    if value.version != 1
        || value.id != expected_locator
        || !valid_display_window(value.remaining_seconds, value.refresh_after_millis)
        || [&value.program_name, &value.executable_path, &value.details]
            .into_iter()
            .any(|field| field.len() > MAX_CONTENT_FIELD_BYTES || field.contains('\0'))
    {
        return Err(phone_request_issue());
    }
    Ok(value)
}
