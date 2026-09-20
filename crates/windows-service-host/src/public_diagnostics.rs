// SPDX-License-Identifier: GPL-2.0-or-later
//! Readable diagnostics, never authorization state. Producers supply closed
//! variants/numbers only. No request text, identities, keys or arbitrary strings.
use activity_journal::ActivityEvent;
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
};
use windows_prompt_probe::supervision::RefusalReason;

pub(crate) const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Event {
    Activity { event: ActivityEvent },
    StartupFailure { stage: u8, code: u32 },
    StartupGuard { phase: u8, policy: u8, code: u32 },
    PromptRefused { reason: PromptRefusal },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptRefusal {
    UnknownTarget,
    TargetChanged,
    ContentChanged,
    UnrecognizedButtons,
    AmbiguousButtons,
    PatternUnavailable,
    InvokeFailed,
}
impl From<RefusalReason> for PromptRefusal {
    fn from(reason: RefusalReason) -> Self {
        match reason {
            RefusalReason::UnknownTarget => Self::UnknownTarget,
            RefusalReason::TargetChanged => Self::TargetChanged,
            RefusalReason::ContentChanged => Self::ContentChanged,
            RefusalReason::UnrecognizedButtons => Self::UnrecognizedButtons,
            RefusalReason::AmbiguousButtons => Self::AmbiguousButtons,
            RefusalReason::PatternUnavailable => Self::PatternUnavailable,
            RefusalReason::InvokeFailed => Self::InvokeFailed,
        }
    }
}

#[derive(Serialize)]
struct Record {
    schema: u8,
    version: &'static str,
    unix_millis: Option<u64>,
    pid: u32,
    #[serde(flatten)]
    event: Event,
}

/// Lock contention or any IO error drops this diagnostic only. No wait loop,
/// recovery of authority, interpretation of old contents or service failure.
fn append(file: &mut File, record: &Record) -> io::Result<()> {
    let mut line = serde_json::to_vec(record)?;
    if line.len() > 512 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    line.push(b'\n');
    file.try_lock()
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
    let result = (|| {
        let size = file.metadata()?.len();
        if size > MAX_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if size + line.len() as u64 > MAX_BYTES {
            // Bounded diagnostic rollover only. The protected activity journal
            // remains the independent source of history and retention policy.
            file.set_len(0)?;
        }
        file.seek(SeekFrom::End(0))?;
        file.write_all(&line)?;
        file.flush()?;
        file.sync_data()
    })();
    let unlocked = file.unlock();
    result.and(unlocked)
}

#[cfg(windows)]
pub(crate) fn record(event: Event) {
    let Ok(mut opened) = crate::ffi::public_diagnostics::open_file() else {
        return;
    };
    let unix_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok());
    let _ = append(
        &mut opened.file,
        &Record {
            schema: 1,
            version: env!("CARGO_PKG_VERSION"),
            unix_millis,
            pid: std::process::id(),
            event,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn row(event: Event) -> Record {
        Record {
            schema: 1,
            version: "test",
            unix_millis: Some(123),
            pid: 7,
            event,
        }
    }

    #[test]
    fn closed_records_have_no_request_or_key_fields() {
        let events = [
            Event::Activity {
                event: ActivityEvent::Service(activity_journal::ServiceOutcome::Started),
            },
            Event::StartupFailure { stage: 7, code: 5 },
            Event::StartupGuard {
                phase: 2,
                policy: 1,
                code: 5,
            },
            Event::PromptRefused {
                reason: RefusalReason::ContentChanged.into(),
            },
        ];
        for event in events {
            let value = serde_json::to_value(row(event)).unwrap();
            let fields = value.as_object().unwrap();
            assert!(fields.keys().all(|key| {
                [
                    "schema",
                    "version",
                    "unix_millis",
                    "pid",
                    "kind",
                    "event",
                    "stage",
                    "code",
                    "phase",
                    "policy",
                    "reason",
                ]
                .contains(&key.as_str())
            }));
        }
    }

    #[test]
    fn file_is_bounded_and_contention_never_waits_or_writes() {
        let mut file = tempfile::tempfile().unwrap();
        let record = row(Event::StartupFailure { stage: 7, code: 5 });
        file.set_len(MAX_BYTES).unwrap();
        append(&mut file, &record).unwrap();
        assert!(file.metadata().unwrap().len() < 513);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap()["kind"],
            "startup_failure"
        );
        file.set_len(MAX_BYTES + 1).unwrap();
        assert!(append(&mut file, &record).is_err());
        assert_eq!(file.metadata().unwrap().len(), MAX_BYTES + 1);
    }

    #[test]
    fn an_independent_open_lock_rejects_without_changing_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("diagnostics.jsonl");
        let first = File::create(&path).unwrap();
        first.lock().unwrap();
        let mut second = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(
            append(
                &mut second,
                &row(Event::StartupFailure { stage: 7, code: 5 })
            )
            .is_err()
        );
        assert_eq!(first.metadata().unwrap().len(), 0);
    }
}
