# ADR0015 — one native intake owner and revocable presentation

Status: implementation checkpoint; Android package/device and new CI evidence
pending. Supersedes only the temporary policy-only startup restriction in
ADR0005/0006/0008/0011/0012/0014. Other trust and cleanup decisions remain.

## Decision

ABI8 composes one lazy current-thread Tokio reactor with the existing
MobileController/DurableInbox. `attach_provisioned_stream` accepts an owned
`std::net::TcpStream` and existing full peer association in Rust only. It adopts
nonblocking I/O inside its own enabled runtime. No renderer endpoint, peer pin,
enrollment, arbitrary command or signing-byte setter is introduced.

Each peer owns one socket and bounded typed work. Busy retains that work; private
admission notifications do not grant retries of failed native cleanup. A fixed
25ms maintenance cadence is not reset by ready events, and parked positive work
checks actual socket liveness before an inbox commit or display. Cancellation and
original input/output/handshake/lifetime bounds remain active. A native callback
panic outside admission closes shared lifetime and cleans owned resources.

An immutable native-monotonic/Instant coordinate and per-socket floors provide
socket time; no continuing Android Instant fallback exists. Successful accepted
clock correlations schedule private refresh at4min, inside the existing5min
validity. Unrelated messages and sent-but-not-accepted probes cannot reset it.
Existing request mappings/deadlines are never remapped by refresh.

Full DirectorySynced startup performs key preflight and consumes all committed
restore/withdrawal/terminal effects. Initial notification cleanup uses the same
failure latch as later cleanup. Exact terminal binding+issuance settles delivery
fences before atomic history recording/outbox ACK. Existing same-request approval
drain and explicit-retry versus continuation rules remain.

## Presentation and native Android

Opaque revocable request handles hold bounded previews and on-demand original
text, not signing authority. Live exact request leases may be shared; connection
leases remain distinct and revoked leases never rearm. Android keeps at most32
active requests/64 retained handles and uses generation-specific notification
tags so delayed old cleanup cannot cancel a replacement. OS posting and cleanup
are serialized per notification owner; stale publication is compensated downward.

Native Android owns stable sound/vibration/silent channels, per-use approval
authentication, immutable explicit notification intents and private denial
receiver. Details/tap are review only. Background posting does not require an
Activity. Restore/update is silent; OS/user settings still govern delivery.
Known live light-clock invalidation awaits rewarming distinctly from fatal clock
failure. Old preview epochs cannot publish, and native actions still recheck
current policy/time. Existing sockets may close conservatively during invalidation.
This is not automatic carrier reconnection.

AppSnapshotv3/native JSONv1 is bounded display data. It distinguishes unpaired,
disconnected, reconciling and known empty inventory. Full commands are absent
from the bulk preview and loaded as inert text on demand. The renderer subtracts
bridge latency from display validity, drops stale/hidden bodies and never turns
queue admission into a Windows result. Native commands recheck independently.
Sticky native review revision plus empty wake events avoids listener-start races;
each new review selects/focuses the exact request without auto-authentication.

## Verification boundary and remaining work

ROOT host tests cover actual synthetic TCP/TLS intake/typed approval/denial,
deadline/wake pressure, abnormal exit, temporal refresh and display contracts.
Children author/static-review only. Local raw TCP half-close control also fails
outside Rust/TLS (.NET); this is not converted to a pass or authenticated closure.
Strict clean-host CI tests remain required. The reviewed channel source hash was
updated for a no-progress liveness observation; proof formulas/guards are intact.

Chromium captures are synthetic client evidence. The independent Android36x86_64
gallery APK compiles the exact renderer/resources but no production owner, key,
network or authentication; production packaging remains ARM64. Neither replaces
physical-phone auth/boot/Doze or Windows Secure Desktop tests.

Trusted QR ceremony, carrier provisioning/reconnection, actual Windows producer
and request-bound action, credential-prompt feasibility, timing measurements,
complete symbolic proofs, final whole-product audit/refactor and release remain
outstanding. This checkpoint must not be shipped as a completed UAC approver.
