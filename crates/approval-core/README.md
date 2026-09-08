# Service-owned decision core

Status: implemented_unverified. This crate does not implement Windows prompt
discovery/action, phone pairing, Android OS authentication, credential entry, key
attestation, encrypted transport, relay handling or durable enrollment storage.

## Small host interface

1. The privileged service constructs `PrivilegedDeviceRegistry`, enrolls verified
   device identities and separate `DeviceKeys`, then moves it into
   `ApprovalEngine::initialize_for_privileged_host`.
2. An OS adapter opens an immutable verified target through
   `open_from_privileged_host`. The engine chooses random boot/request challenges,
   snapshots current device identities/keys/revisions and records a deadline.
3. A bounded, decrypted decision is decoded by `approval-protocol`; the service
   passes it to `submit_decision` with fresh host monotonic time. Only an exact
   binding and current snapshotted purpose-key signature can win.
4. The first valid decision removes the request and returns a non-Clone,
   non-serializable `AuthorizedDecision`. The matching adapter consumes it once
   for an action attempt. Returning the token is not an OS-success report.

After initialization, enrollment changes use the engine's narrow
`enroll_device_from_privileged_host`, `replace_device_from_privileged_host` and
`revoke_device_from_privileged_host` methods. It never exposes a mutable registry:
swapping in a newly initialized registry would reset revision allocation and
could restore an old pending enrollment snapshot. Replacing the entire engine
instead generates a new random boot epoch and discards its old pending state.

There is no local approval, signing, credential, process-launch or input-injection
API. Privileged-host methods are internal service APIs, **not** proof of Windows
privilege. In-process Rust visibility does not authenticate callers.

The engine owns at most 32 current devices and 128 pending requests; configured
bounds may be smaller. TTL is 1–120000 ms. Exact deadline is expired. Unknown,
completed, canceled, changed-binding, old-epoch, revoked and replaced enrollment
responses fail closed. Invalid live responses do not consume state. Enrollment
revisions never wrap or get reused; even replacing identical keys or revoking
and re-enrolling them invalidates existing snapshots. Newly enrolled keys cannot
gain authority over requests opened earlier. Independent request IDs/nonces mean
signature encoding is never replay identity.

Each immutable content payload is shared with its `PendingChallenge` clones and
the eventual `AuthorizedDecision` through `Arc`, avoiding extra body/command-line
copies inside these transitions. Each payload is bounded to 288 KiB of text, so
128 live pending entries hold at most 36 MiB of text, plus bounded key snapshots,
allocation/map headers and transport framing outside this crate. Host-retained
old challenges or explicit `RequestContent` clones are not bounded by the engine:
the host must release them when requests finish and cap its own queues/caches.
Sharing is not zeroization or permission to persist/log the body.

## Required host security boundaries, not implemented claims

- Keep the engine and registry inside a protected Windows service. Its internal
  opening, cancellation, enrollment/replacement/revocation and restart operations
  must not be reachable by a web view, generic IPC endpoint, relay or unelevated
  local process. Persist enrollment with privileged-only integrity and rollback
  protection; do not treat a UI choice as privilege.
- Establish enrollment through an authenticated, user-approved bootstrap. Verify
  hardware-generated P-256 attestation and key ownership, PC/device identity and
  approval-key per-use Android OS-authentication policy. A denial key is separate
  and does not require that per-use authentication. A signature alone does not
  establish these enrollment facts. No caller-supplied `authenticated = true`
  flag exists.
- Identify the exact live Windows prompt and logon session through a reviewed OS
  mechanism. Preserve a service-owned OS target handle/identity and immutable
  capture alongside the binding. Matching display text or its digest is not OS
  origin authentication. Defend against target replacement and session reuse.
- Serialize the engine under one service owner or mutex. The one-shot token must
  be dispatched under the same synchronization boundary as revocation, restart,
  cancellation and target lifecycle. Check current epoch, exact target/session,
  live enrollment policy and the fresh actual monotonic deadline **after** crypto
  and immediately before dispatch. Already-issued tokens cannot be recalled by
  the core; never persist, defer, duplicate or retry them. Drop them on shutdown,
  target changes, failure, cancellation, revocation or expiry.
- Use fresh trusted `Instant` values, never remote clocks or stale queue times.
  Deliver through authenticated, end-to-end encrypted transport and bounded,
  rate-limited queues; verify endpoint identities and resist hostile relays.
  Transport confidentiality, server ACLs and network rate limits are outside this
  core. No plaintext credential or bootstrap-secret transport is provided.
- Call `expire_from_privileged_host` on deadline wakeups and before opening more
  requests if the host needs every expired request ID for cancellation messages
  or history. Opening a request opportunistically reclaims expired entries; that
  reclamation alone emits no PC-to-phone event. Likewise, the host must translate
  explicit cancellation/restart/decision results into authenticated lifecycle
  messages. Phone-local expiration remains independent. No event delivery has
  been implemented or proven here.
- Preserve Secure Desktop, UAC, LSA protection and Windows policy. If the OS
  adapter can appropriately handle Windows-required credentials entered on an
  enrolled phone, that later branch remains allowed; otherwise ignore those
  prompt types. An application signature never replaces Windows authentication.
- Do not log request content, identifiers, signatures, keys, credentials or
  bootstrap secrets. Public types redact sensitive-bearing Debug output. Display
  strings remain data, never executable commands.

This scope defends protocol/state boundaries against unelevated local malware,
hostile networks/relays, unpaired/revoked devices, replay, tampering and request
confusion under an intact OS. Already-compromised SYSTEM/kernel is explicitly
excluded; that exclusion does not remove ordinary service-boundary obligations.

Pure-core fixtures are not proof of a Windows/Android end-to-end workflow. Root
must validate formatting, Clippy, tests and real Rust Analyzer diagnostics before
reporting even these crates as verified.
