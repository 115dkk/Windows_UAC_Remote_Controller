<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0023: Pairing helper launch remains bound to the original native owners

Status: ROOT-approved design; implementation and validation in progress.

## Context

The fixed server/client pipe boundaries authenticate actual installed processes.
They do not establish a fresh pairing ceremony. The next source slice provides
the real one-shot helper launcher/consumer while keeping the original GUI pipe
and actual launched helper together. Endpoint activation and the single pending
slot inside the existing ServiceSession remain the following integration step.

## Closed invocation and native launch

Only `pair <64 lowercase ASCII hexadecimal digits>` accepts a second CLI
argument. The nonzero32-byte PendingElevationId is public correlation data, not
a secret, transferable grant or proof of consent. Parse argv once; retain the
typed value and redact diagnostics. Preserve existing lifecycle verbs.

The launch operation consumes an idle authenticated Starter client that has not
already sent/received protocol data. Its Offer is read from that original native
connection, not passed as a caller argument. Claim one launch attempt before
entering ShellExecuteExW with the fixed protected helper and internally formatted
arguments. Retain Windows' actual returned process handle immediately, inspect
its identity through that handle and send the observed tuple on the original
Starter pipe before waiting for exit. The ordinary lifecycle launcher is unchanged.

Windows owns UAC and its timing. A late return cannot renew the original client
deadline or authorize a late binding. No retry, alternate executable, process
kill or unsafe Send conversion is introduced. The original reservation transfers
once into the consuming launch owner; it remains occupied through helper cleanup.

## Exact local handshake and terminal ordering

The private protocol has six exact-length versioned kinds:

| Kind | Producer | Meaning |
| --- | --- | --- |
| Offer | Service | Public ID for this original pending slot |
| HelperLaunched | Original Starter | Handle-observed helper PID/creation identity |
| Hello | Native helper | Join candidate selected by public ID |
| Bound | Service | Live rendezvous information, not a grant or enrollment |
| Close | Service | Authenticated transition to cleanup only |
| CloseAck | Original client | Fixed terminal acknowledgement |

The future service matcher must compare actual retained peer identities and
original slot/epoch/deadline regardless of message arrival order. The helper may
connect before ShellExecute returns to its GUI parent. No ID-only join is valid.

Bound retains both original owners. A helper must not exit just after writing
CloseAck: the server's post-read identity fence still requires it to be alive.
After a genuine Close from normal authenticated completion, a private cleanup
path sends only the fixed acknowledgement and waits for terminal transport EOF.
The server consumes acknowledgements while clients remain live, then closes the
original pipes. Only then does the helper drain/exit and the Starter observe its
actual exit. Unexpected bytes, premature EOF and uncertain completion fail.

The cleanup path publishes no new upward data, clears no prior failure and
preserves the original deadline. Normal I/O authentication fences are unchanged.
Close before Bound may complete cleanup, but cannot imply successful binding.
Cancellation closes/drains the Starter pipe to revoke its future slot while the
outer owner retains a still-live helper and reservation. Uncertain Drop retains
or poisons the required ownership, preventing a replacement attempt.

## Scope and evidence

This slice enables no GUI pairing button, service endpoint producer, registration,
key operation, QR display, remote transport or Windows approval. The existing
ServiceSession will own the next pending slot; no second coordinator is needed.
ROOT validates the exact source with portable phase/CLI tests, Windows compile
and full quality gates. Synthetic ordering tests are not human consent evidence.
Actual positive launch/rendezvous remains a separately authorized native check.
