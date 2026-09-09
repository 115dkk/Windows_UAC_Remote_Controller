// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded native-history presentation, never an approval/result assertion.
use std::collections::BTreeSet;

use activity_journal::{MAX_OUTCOME_HISTORY_RECORDS, OutcomeHistoryRecord, UnixMillis};
use notification_policy::RequestOutcome;
use serde::{Deserialize, Serialize};

use crate::{ActivityKind, ActivityView, AppIssue};

pub const MAX_PHONE_HISTORY_JSON_BYTES: usize = 128 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryDocument {
    schema_version: u8,
    records: Vec<HistoryRow>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryRow {
    id: String,
    timestamp_millis: u64,
    kind: HistoryKind,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum HistoryKind {
    Cancelled,
    Expired,
    PcCompleted,
}

pub const fn phone_history_issue() -> AppIssue {
    AppIssue {
        code: "phone_history_unavailable",
        message: "활동 기록을 읽지 못했어요.",
        next_action: Some("휴대폰에서 앱을 다시 열어 확인해 주세요."),
    }
}

/// Caller supplies the last committed native history, not a renderer/peer body.
/// Most recent INSERTION first, preserving clock corrections without reordering.
pub fn encode_phone_history(records: &[OutcomeHistoryRecord]) -> Result<String, AppIssue> {
    if records.len() > MAX_OUTCOME_HISTORY_RECORDS {
        return Err(phone_history_issue());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let records = records
        .iter()
        .rev()
        .map(|record| {
            let mut id = String::with_capacity(64);
            for byte in record.delivery_id() {
                id.push(char::from(HEX[usize::from(byte >> 4)]));
                id.push(char::from(HEX[usize::from(byte & 15)]));
            }
            HistoryRow {
                id,
                timestamp_millis: record.timestamp().get(),
                kind: match record.outcome() {
                    RequestOutcome::CancelledByPc => HistoryKind::Cancelled,
                    RequestOutcome::ExpiredLocally | RequestOutcome::ExpiredByPc => {
                        HistoryKind::Expired
                    }
                    RequestOutcome::CompletedByPc => HistoryKind::PcCompleted,
                },
            }
        })
        .collect();
    let json = serde_json::to_string(&HistoryDocument {
        schema_version: 1,
        records,
    })
    .map_err(|_| phone_history_issue())?;
    if json.len() > MAX_PHONE_HISTORY_JSON_BYTES {
        return Err(phone_history_issue());
    }
    Ok(json)
}

/// Native bridge data only. Invalid/unknown data is unavailable, never empty.
pub fn decode_phone_history_json(bytes: &[u8]) -> Result<Vec<ActivityView>, AppIssue> {
    if bytes.len() > MAX_PHONE_HISTORY_JSON_BYTES {
        return Err(phone_history_issue());
    }
    let document: HistoryDocument =
        serde_json::from_slice(bytes).map_err(|_| phone_history_issue())?;
    if document.schema_version != 1 || document.records.len() > MAX_OUTCOME_HISTORY_RECORDS {
        return Err(phone_history_issue());
    }
    let mut seen = BTreeSet::new();
    document
        .records
        .into_iter()
        .map(|row| {
            if row.id.len() != 64
                || !row
                    .id
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
                || !seen.insert(row.id.clone())
                || UnixMillis::new(row.timestamp_millis).is_err()
            {
                return Err(phone_history_issue());
            }
            Ok(ActivityView {
                id: row.id,
                timestamp_millis: row.timestamp_millis,
                kind: match row.kind {
                    HistoryKind::Cancelled => ActivityKind::Cancelled,
                    HistoryKind::Expired => ActivityKind::Expired,
                    HistoryKind::PcCompleted => ActivityKind::PcCompleted,
                },
            })
        })
        .collect()
}
