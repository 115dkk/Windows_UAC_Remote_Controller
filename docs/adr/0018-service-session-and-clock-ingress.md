# 0018 — One service session and closed authenticated-peer ingress

Status: implementation source; ROOT CI/native evidence is separate.

The actual Windows worker owns ServiceSession instead of discarding its registry
checkpoint. One real ServiceRegistry feeds one exactly restored ApprovalEngine,
with unchanged epoch-start Instant and a borrowed original thread-affine
PcIdentityKey. The existing TLS signing bridge is serviced on that worker.

ROOT approved deterministic PcIdentity = SHA-256 of exact ASCII
`Windows-UAC-Remote-Controller/pc-identity/v1` followed by ONE NUL byte and the
canonical91-byte PC SIGNING-key SPKI; zero rejects. This is identity, not enrollment
proof. Native key/registry initialization and recovery rules are unchanged.

The sealed carrier has no public constructor/IPC decoder or production callsite.
Its device selector chooses an enrolled TLS pin, not a verified-peer Boolean.
The closed adapter owns actual SocketDriver/PeerTransport; only real TLS Ready ->
Frame creates its private process-local envelope. Exact device/revision/decision
keys/transport pin/owner/epoch are revalidated before/after key work and before
queue/drain. Retirement withdraws queued events and existing guarded output.
No engine/registry mutable escape or reset is provided.

Only existing ClockProbeRequest and SignedDecision codecs are dispatched. Clock
responses use the same engine epoch and original epoch-relative tick. Decisions
must match the authenticated transport's DeviceId and enter that same engine.
No production request is opened. With no OS adapter, any test-authorized decision
is explicitly AuthorizedButNotApplied; no Approved/Denied OS result is emitted.

There are at most32 retained I/O owners, one input/output queue slot per peer,
and the existing shared connection/signing budgets. I/O never owns the native key.
Normal stop/errors/unwind retain the session outside the runtime catch boundary:
cancel/close signing, poll, join only actually finished owners, then close registry
and key. CleanupPending never becomes success from timeout. Existing SCM timeout
errors remain possible while ownership is retained; no false Finished is emitted.

ROOT approved a last-resort Drop invariant fallback: cancel/close, join completed
owners, then abort ONLY if a real I/O owner remains unjoined. No detached reaper,
forgotten handle or blocking live join. Normal staged shutdown must not use it;
empty/no-peer destruction does not abort.

No SYSTEM Internet listener, dialer, carrier source, QR/enrollment route, generic
local request API or remote-readiness flag is enabled. Test-only software keys and
typed registry fixtures exercise real TCP/TLS and Android AssociatedPcSocket;
they are not TPM, ACL, Android hardware/authentication or UAC acceptance evidence.
