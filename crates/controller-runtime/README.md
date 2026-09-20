# controller-runtime

SPDX-License-Identifier: GPL-2.0-or-later

Safe Rust orchestration for the native Windows/Android presentation shell. This
crate has `#![forbid(unsafe_code)]`, no Tauri dependency, no own FFI and no
network, key, credential, signing, generic execution or prompt-action surface.
The UI receives presentation snapshots, not authorization state.

Implementation status: **implemented_unverified**. Tests have been authored but
not executed by the implementation child. ROOT owns all fmt/build/test/Clippy,
Rust Analyzer and device/native validation. Pure adapter/filesystem tests are
not Windows elevation or Android OS evidence.

## Host integration

The ROOT Tauri host obtains an existing app-private directory from the native
path resolver and constructs one runtime. No command accepts a storage path,
platform override, helper path, computer name or mobile-readiness assertion
from the renderer.

```rust,ignore
let private_directory = AppPrivateDirectory::from_native_app_data(native_app_data)?;
let runtime = AppRuntime::open(
    private_directory,
    Platform::Windows,
    actual_os_computer_name.as_deref(),
    Box::new(WindowsPlatformAdapter),
)?;
```

`WindowsPlatformAdapter` exists only on Windows. Android and unsupported hosts
use `UnavailablePlatformAdapter` for service control. Android readiness enters
through the trusted Rust/Kotlin lifecycle, not this adapter or saved settings.
The optional Windows name is bounded to 256 UTF-8 bytes and 64 characters;
control/bidirectional/invisible formatting characters cause rejection. Missing
or rejected names are empty, never replaced with a fabricated machine identity.

Public entry points:

| API | Outcome |
| --- | --- |
| `AppPrivateDirectory::from_native_app_data(path) -> Result<Self, PreferenceError>` | Checks an existing absolute directory with explicit native-host provenance; creates no directory. |
| `AppRuntime::open(directory, platform, Option<&str>, Box<dyn PlatformAdapter>) -> Result<Self, AppIssue>` | Opens and locks validated preferences; performs no native service query/mutation. |
| `snapshot(&mut self) -> AppSnapshot` | Refreshes read-only native service state; Android uses the last trusted readiness observation. |
| `decode_notification_policy_json(&[u8]) -> Result<NotificationPolicy, AppIssue>` | Strict bounded frontend decoding, including required schedule/alert fields. |
| `save_policy(&mut self, NotificationPolicy) -> Result<AppSnapshot, AppIssue>` | Commits validated local preferences before reporting saved state. |
| `control_service(&mut self, ServiceAction) -> Result<AppSnapshot, AppIssue>` | Only explicit service-mutation entry; fixed enum actions through the native owner. |
| `update_mobile_readiness_from_native(&mut self, MobileReadiness) -> Result<(), AppIssue>` | Native-host-only Android observation. Must not be registered as a Tauri command. |
| `begin_pairing`, `remove_device`, `decide`, `read_activity`, `clear_activity` | Fixed unavailable errors; no simulated state mutation. |

`remove_device` takes `&str`; `decide` takes `&str` and `DecisionIntent`;
`read_activity` returns `Result<Vec<ActivityView>, AppIssue>`. Other unavailable
actions return `Result<AppSnapshot, AppIssue>`. Unsupported IDs are not echoed,
retained or interpreted. There is no credentials, QR or signing method.

All runtime methods are synchronous. ROOT must serialize one runtime (for
example, using the native managed mutex) and run disk work and especially
`control_service` on its background task/thread, never the WebView/UI thread.
The native helper may wait for Windows-owned elevation and a bounded process
wait. The helper revalidates the protected executable and SCM identity when an
action is requested; `allowedActions` is never an authorization grant.

## Truthful presentation

DTO field names match `ui/src/contracts.ts`: snapshot/view fields use camelCase;
the established notification policy remains snake_case. Snapshot schema is 1.

- `NotInstalled` comes only from a successful native absence observation. A
  first read error yields `service: null`; later failures retain a labelled
  stale state with all stale service actions disabled.
- `Running` never sets `remoteRequestsReady`: no real request/identity/transport
  owner is connected. Devices, requests and activity remain empty *with explicit
  unavailable metadata*, never presented as successful known-empty owner reads.
- `canPair`, `canUnpair` and `canClearActivity` remain false. Unsupported command
  calls return fixed Korean issues and cannot create fake successes or entries.
- Screen lock configured/missing/unavailable are distinct. Initial/error state
  is unavailable, not missing. Native readiness is not authentication evidence
  and never enables remote approval.
- The root-provided `windows-service-host::is_control_helper_available()` performs
  the existing protected-helper validation read-only. False means an actually
  absent expected helper. Trust/OS errors preserve lifecycle observation while
  disabling management with a fixed issue. No environment/renderer/path heuristic
  supplies availability.

Helper outcomes are deliberately different:

- `UserCancelled` returns the unchanged fresh pre-command snapshot.
- `Completed` uses the native owner's actual refreshed snapshot; this still
  does not prove remote-approval readiness.
- `HelperFailed` returns an issue-bearing snapshot with actions disabled until
  a read-only refresh, not a success label or raw helper exit code.
- `StillRunning` and `CompletionStatusUnknown` keep a pending/unknown issue and
  disable later service mutations for this runtime. A later SCM read may update
  lifecycle state, but cannot prove the outstanding helper has finished. Native
  wait/exit-code read failures after launch also map to completion unknown.

There is deliberately no renderer-callable "clear pending" boolean. The current
native helper API does not retain a waitable operation handle after returning an
unresolved outcome. Recovery currently instructs the user to confirm the Windows
operation has finished and then reopen the app. A future automatic reconciliation
requires a real native operation owner; it must not infer completion from Running.

## Preference storage and provenance

The only persisted content is a versioned notification policy:

```json
{"schema_version":1,"policy":{"schedule":{"mode":"always"},"alert":"sound"}}
```

Both fields are mandatory in existing files. The generic notification-policy
crate permits omitted schedule/alert defaults, so this crate uses a strict
wrapper before constructing that validated type. `{}`, malformed JSON, partial
policies, unknown fields, duplicate fields, invalid/overfull weekly windows,
unsupported versions and oversized files do not silently become defaults.
Always+Sound is selected automatically only when the policy file does not exist.

The whole document and the actual read are bounded to 16 KiB. File metadata
limits are followed by a `take(MAX + 1)` bound. Schedule construction and
deserialization reuse `notification-policy`'s maximum 32 validated time windows.
No screen-lock status, administrator flag, public/private key, authority field,
request, credential, identifier registry or unrelated arbitrary object is saved.

`notification-policy.lock` is a zero-byte lifetime-exclusive OS writer lock.
The lock path is never removed, including Drop. Saves create exactly one fixed
same-directory `notification-policy.staging` file with exclusive creation, write
and sync it, then atomically replace `notification-policy.json`. In-memory policy
changes only after replacement succeeds. This is not a cross-platform power-loss
durability guarantee; the containing directory is not synced.

The bounded current bytes are compared before saving; an external edit or deleted
existing policy is not silently overwritten. A leftover staging file blocks
open/save for explicit recovery. This implementation exposes no recovery/delete
command and never promotes or automatically deletes an unfinished file. Failed
writes preserve the previous current file and leave at most that fixed staging
entry. User-facing errors contain fixed Korean outcome/next-action copy, not
paths, input values or OS/JSON error text.

Symlink/reparse directories and file entries are rejected. On Windows safe std
opens use `FILE_FLAG_OPEN_REPARSE_POINT`; ancestor directory handles and the
writer lock exclude share-delete. On Unix safe std opens use `O_NOFOLLOW` and
`O_NONBLOCK` constants from libc, but **make no libc FFI calls**. Unix files reject
multiple hard links and compare opened device/inode identity with the path.

The host must establish app-private directory ownership/ACLs and protect ancestor
replacement. This crate does not establish those ACLs or claim preference files
are tamper-proof. Portable path-based rename cannot defeat a writer who can mutate
the trusted private hierarchy; Unix ancestor pinning/handle-relative rename is
not implemented. Windows hard-link counts/ownership are not proven by safe std
here. No preference is ever authentication or authorization state. Future key or
privileged state storage must use its separate reviewed native owner, not extend
this preference store. ROOT must verify actual host provenance during native QA.

## Root-only validation still required

From the workspace root, after integrating the native helper-availability API:

```text
cargo fmt --all -- --check
cargo test -p controller-runtime
cargo clippy --workspace --all-targets -- -D warnings
```

ROOT also runs real Rust Analyzer diagnostics, affected workspace gates and native
Tauri/Windows/Android checks. No ignored failures, mocks as devices, or child-run
validation may be used as a passing receipt. Integration tests explicitly label
their synthetic native adapters and isolated temporary filesystem fixtures.

Authoring receipt:
`.superloopy/evidence/controller-runtime-implementation.md`.
