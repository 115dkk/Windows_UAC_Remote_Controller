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
- **Decision**: one enrolled phone's request-bound signed approval or denial.
  An approval key must require that phone's OS authentication for each use;
  a denial key is separate and does not require it.
- **Authorization**: the Rust core has accepted a decision once. This is not
  proof that Windows accepted or applied it. The prompt adapter still has to
  bind the action to the same live prompt and confirm the result.
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

## Confirmed threat scope

Assume Windows and its SYSTEM/kernel protection mechanisms are intact. The user
explicitly excludes an already-compromised SYSTEM/kernel. Defend against
unelevated local malware, unpaired/revoked devices and hostile networks/relays.
Do not turn an exclusion into permission to let unelevated malware gain
privilege through this service. Keep Secure Desktop and other OS protections on.

## Current implementation boundary

Shared libraries and local quality gates have been implemented and tested by root;
the product remains in development. The Windows observer reads desktop categories
without detecting or operating a UAC prompt. Enrolled-key initialization
interfaces are trusted-host interfaces, not public IPC. No real Windows approval,
credential-entry adapter, Android authentication/notification integration, trusted
QR ceremony or encrypted network transport has yet been proven. See
[the implementation plan](docs/IMPLEMENTATION_PLAN.md) for remaining work.
