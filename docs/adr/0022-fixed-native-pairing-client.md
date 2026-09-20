<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0022: Fixed-role Windows pairing clients authenticate the native server

Status: implementation authored; ROOT validation pending.

## Context

The existing private pairing server authenticates its actual GUI/helper peers,
but had no corresponding native client. Initial pairing must not accept a
caller-provided PID, path, administrator flag or service assertion. Ordinary
GUI callers also cannot assume permission to inspect a SYSTEM process token or
read the SCM object's security descriptor. Existing service permissions remain
unchanged.

## Decision

Provide two opaque constructors on `PairingClient`: fixed installed medium GUI
starter and fixed installed elevated helper. Neither constructor launches UAC.
Both independently inspect the actual own process token, current thread's lack
of impersonation, process creation identity and active session epoch, retaining
their original protected installation pins. The owner is thread-confined and
noncloneable.

Open exactly one fixed local named pipe with concrete rights `0x0012019b`,
OVERLAPPED and explicit IDENTIFICATION SQOS. No generic write, create-instance
right, inherited handle, alternate path, wait/reconnect or network endpoint is
accepted. Before protocol bytes, require the actual pipe's SYSTEM owner and
exact protected role DACL through its READ_CONTROL handle. Also bind its native
server PID/session0 to the fixed SCM registration, Restricted service SID mode,
completed readiness, retained live process/creation identity and protected
service image. Requery both retained and current registration. Metadata failure
means unavailable, not a weaker authentication method.

One original caller-captured start/deadline remains bounded to five minutes.
Before issuing and publishing I/O, recheck identity and that original lifetime.
The client reuses the existing private `overlapped_pipe::PendingOperation`:
one in-flight operation, stable event/storage, reads detecting messages beyond
4096 bytes, and exact completed writes. Debug and errors omit payloads/identity.
No bytes or write success escape after identity/deadline loss.

Cancellation requests cleanup; it is not completion. Drain requires actual
quiescence. An uncertain Drop retains the whole owner, pipe, storage/event,
identity/installation/SCM pins and process-wide reservation, preventing a second
client from replacing an outstanding kernel borrow. Checked native handle/free
failures poison later client admission. Existing SCM wrapper close limitations
remain explicit; drain is not an attestation about every upstream destructor.

## Scope and follow-on integration

This boundary does not provide a pairing grant, local approval API, command
execution, key generation, registry mutation, QR display, network bootstrap or
UAC result. The next integration must retain the original GUI and actual launched
helper in one service-session pending slot. Its public pending ID selects that
slot but cannot confer authority. No second registry/engine/coordinator is needed.

ROOT validates exact source with Windows/Linux fmt, Clippy, tests and actual
Analyzer CI. Authored ACL, lifetime/completion and ordinary-test-image rejection
fixtures do not establish an installed GUI-to-service pairing or a human UAC
approval. Those actual native scenarios remain separate evidence requirements.
