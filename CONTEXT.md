# Domain language

This repository is a Windows service and Android companion approval product,
not a general remote desktop or arbitrary remote execution tool.

- **Pairing ceremony**: an owner-authorized, one-time enrollment of a phone's
  separate connection, approval and denial keys. Later QR issuance requires a new
  Windows UAC action. The final privileged host owns the enrolled-key registry.
- **Prompt**: the actual Windows-owned request on the relevant user's Secure
  Desktop. A title, PID, screenshot or process name alone is not prompt identity.
- **Request**: immutable information about one prompt, its PC/session identity,
  unpredictable challenge, content digest and bounded lifetime.
- **Request lease**: one immutable signed binding within a live Prompt's Request
  lineage. A fresh same-content native observation may replace a still-pending
  lease through ApprovalEngine: the RequestId, content and eligible devices stay
  fixed while nonce and expiry change. Old decisions cannot authorize the new
  lease. Renewal is not a new prompt, a Windows outcome or permission to restore
  a suppressed request. The live Prompt module retains the immediate predecessor
  so reconnect publication remains `Renewed`, never a fabricated `Opened`.
- **Decision**: one enrolled phone's request-bound signed approval or denial.
  An approval key must require that phone's OS authentication for each use;
  a denial key is separate and does not require it.
- **Authorization**: the Rust core has accepted a decision once. This is not
  proof that Windows accepted or applied it. The prompt adapter still has to
  bind the action to the same live prompt and confirm the result.
- **Denial scope**: a process-local, original-request operation that also fences
  further approval while denial and native cleanup are outstanding. Cancellation,
  native retirement, a local socket write and Windows denial are distinct events.
  See [ADR0014](docs/adr/0014-native-denial-fence-and-cleanup.md).
- **Credential entry**: the user supplies what Windows itself requests from the
  phone. It does not turn phone biometrics into Windows credentials. The user
  permits ignoring credential prompt types that cannot be handled appropriately.
- **Notification schedule**: the phone user's local weekdays and time windows.
  Unconfigured means always; explicitly disabled means never. Off-hours requests
  are discarded, not queued or added to user-visible history.
- **Suppression marker**: minimal identity/lifetime state preventing a discarded
  request from being redisplayed by delayed or repeated delivery. It contains no
  credential, request body or user-visible off-hours history.
- **Activity journal**: bounded, expiring operational history with typed events.
  It is not an authorization registry or a tamper-proof audit trail. It must not
  contain passwords, private keys, QR secrets or full command lines.
- **Mapping obligation**: one mapping the service added on the router, retained
  for bounded cleanup with its exact local/gateway path and actual expiry. For
  PCP it also keeps the server-scoped nonce; for UPnP IGD (v1 or v2) it keeps the
  control URL and external port, and cleanup deletes the entry only while it
  still names this PC and internal port (ADR 0039).
  Route displacement withdraws its candidate without erasing the obligation;
  only the matching restored path can attempt cleanup, including at shutdown.
  An unanswered cleanup is not evidence that the mapping disappeared. This
  routing ownership grants no peer or request authorization.
- **Release metadata**: the common product version in package.json, the root
  package-lock entries, Tauri configuration, Cargo workspace and owned Cargo.lock
  packages. Main preparation and tagged publication share its consistency checks;
  external dependency versions are not release metadata. A matching version is
  not evidence of a passed release gate or an observed Windows outcome.

## Confirmed threat scope

Assume Windows and its SYSTEM/kernel protection mechanisms are intact. The user
explicitly excludes an already-compromised SYSTEM/kernel. Defend against
unelevated local malware, unpaired/revoked devices and hostile networks/relays.
Do not turn an exclusion into permission to let unelevated malware gain
privilege through this service. Keep Secure Desktop and other OS protections on.

## Current implementation boundary

Shared libraries, actual local TCP/TLS test paths, Android Application policy and
history ownership, and hosted Windows/Linux/Android quality builds have been
implemented and verified by root. The product remains in development. The Windows
observer/probe and dormant service supervisor do not implement request-bound UAC
approval. Enrolled-key initialization interfaces are trusted-host interfaces, not
public IPC. No real Windows approval/credential-entry adapter, native phone
authentication/notification journey, trusted QR enrollment, or deployed cross-device
transport has yet been proven. ABI8 now composes a Rust-only provisioned socket,
full durable startup/effect reconciliation, opaque request projections and native
notification/action routes. Host tests exercise synthetic actual TCP/TLS, not
physical-phone authentication or Windows UAC. No QR enrollment or carrier
discovery is supplied by those trusted-host interfaces. See
[ADR0015](docs/adr/0015-native-intake-and-request-presentation.md) and
[the implementation plan](docs/IMPLEMENTATION_PLAN.md) for remaining work.
