# ADR0010: retain the original receiving generation per request

Status: accepted implementation boundary; native actions remain incomplete.

## Decision and invariants

Retain an optional nonzero local association generation beside each original
request guard, alongside its existing full binding and service issuance. The PC
identity already belongs to that binding. A generation resolves the immutable
recipient DeviceId, PC registry revision, local handle and key tuple only while
the corresponding peer association remains current. Peer generations never
repeat and the local key tuple for a Created handle cannot change.

The actual association-bound socket supplies the generation after its frozen
PC/TLS/key/current-owner checks. Private source-aware durable methods validate
original binding, issuance and exact Option source before intent. The core repeats
the gate before advancing any local/source clock. None is not a wildcard: neither
legacy None nor Some(A) can become Some(B) during duplicate delivery or recovery.
Existing low-level unassociated APIs retain None-to-None behavior and do not
become a signing path. A rejected authenticated old message does not discard the
current connection's other valid work.

No fifth store or parallel replay owner is added. Inbox checkpointv3 appends a
tag0 (None) or tag1 plus u64 to every retained row. Explicitv2 migration supplies
None and preserves its outcome tail; v1 retains its existing policy-only rule.
All restore paths copy the original Option, including closed/suppressed guards
and changed boots. At512rows the maximum extension is4,608bytes; existing384-KiB
limits remain. The composite checks generation highwater and prevents the same
generation from referring to different PCs across active peers and all retained
sources. It permits revoked/noncurrent historical references, not their reuse.

Guard retirement, original expiry, quiet-hour suppression, source watermarks and
terminal outboxes are unchanged. An outbox surviving a retired guard has no
receiving generation, but its terminal identity still cannot become active.
Parsing is structural; file rollback and the actual native enrollment witness
remain the existing protected-storage/enrollment owner's responsibilities.

## Body lookup and effects

The associated pending CHECK performs normal maintenance/commit first, preserving
expiry/quiet-hour withdrawals. It then withholds the body if its original source
is absent or no longer resolves to the current association. It never retags from
the newest record for the PC. Its result exposes committed effects/receipt,
optional issue and optional associated body snapshot, not a raw unassociated body.

The snapshot retains exact association/local public metadata and a fresh owner
instance identity. It is neither Clone nor a native authentication result. An
owner-identity comparison does not prove liveness. Before native display or
signing, the future action owner still needs current pending state, original
deadline, current association, native readiness and per-use authentication;
blocking IO and callbacks can invalidate a returned snapshot.

## Verification boundary

ROOT alone runs the authored pure source/codec tests and real-loopback recovery,
re-enrollment, legacy non-upgrade and downward-withdrawal tests. Conservative
independent maximum components total331,675bytes, below393,216bytes; an actual
all512-bound-guard/four-component fixture additionally exercises the composite.
Synthetic keys and host storage are not native Android authentication, trusted
QR enrollment, power-loss behavior or Windows UAC evidence. No frontend, native
permission, key generation, signing or Application startup activation is added.
