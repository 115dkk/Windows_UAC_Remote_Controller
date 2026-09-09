# ADR0009: bind phone receiving state to an association generation

Status: accepted implementation boundary; enrollment/native acceptance incomplete.

## Context

The Application could reopen local keys and read policy/history, but had no
record joining a PC signing/TLS pin to its recipient DeviceId, PC registry revision
and local key tuple. A verified PC event previously discarded its verification
key. Attaching whatever key is current for a PC ID to an old pending request would
lose the original receiving context across removal/re-enrollment or owner restart.
Local CreatedUnverified metadata is not authority to sign or pair.

## Decision

Store up to32 explicit native-host associations inside controller checkpointv3,
alongside the inbox, history and local keys. Keep the existing384-KiB total bound.
The peer component is independently canonical and bounded to8,920bytes. Its local
generation allocator cannot wrap or reset on removal; stale references cannot
remove or resolve a newly recorded association. A fresh in-memory Arc identity
distinguishes every durable owner instance, including identical saved bytes.

An association's PC/device/revision/local handle and both PC P-256 pins are
immutable. Within one PC the signing and TLS keys may intentionally match.
Across active PCs, device IDs, local handles and PC keys cannot be reused; PC
keys cannot equal any Created local role key. Composite validation repeats these
relationships after future local-key changes. Detached invalid candidates are
rejected before intent; successful metadata is published only after commit.

Migration from explicit older composite versions supplies absent association
metadata, never discoveries or enrollment authority. Preserve both existing
recovery contracts: full recovery reserves intent before domain decode, while
policy-only/key preflight runs under the locked store before migration writes.

Connect the existing real peer-pinned TLS/SocketDriver to this record through
AssociatedPcSocket. Validate the client transport key against the associated
local tuple before constructing its client transport. Freeze both PC keys and
the complete association/owner context. ReceivedPcEvent has no public constructor
and is created only from a real complete TLS frame and the expected PC signature.
VerifiedPcEvent retains the actual verification key without changing its wire.

Do not hold the inbox across a socket wait. Applying a message rechecks exact
connection identity, owner instance and current full association/local tuple
before intent. The connection privately owns its pending clock probe and
correlation and queues only a fixed clock request. A raw old correlation is not
imported into a new association merely because PC/service epoch match.

Fatal errors, cancellation, observed normal termination, abort and Drop invalidate
shared context and clear clock state. Queued messages cannot create new state
after termination. Cancellation is connection-local via a child token; it cannot
cancel the shared parent/other PCs. Already committed downward effects must still
be processed when the source later becomes invalid. Native display must recheck
fresh time and context after blocking work; commits cannot promise atomicity with
an independently arriving cancellation.

## Authority and remaining work

The trusted-host association mutation is a narrow library extension point, not
an enrollment witness, renderer command or native callback accepting paired:true.
Its eventual caller must prove the real grant/receipt, entire key bundle and
hardware/authentication policy. No startup connection or policy-only gate change
is included. The unanswered pairing UX and protected-display candidate are not
silently selected by this record format.

AssociatedUpdate describes the triggering event's source and committed effects;
it is not the retained source of every active body or an approval plan. Next work
must retain per-request association/issuance context through native intake,
notification dispatch and opaque one-shot authentication plans. Removal must
withdraw relevant native views without erasing replay/source/history guards.
Phone authentication, real key signing, Windows actions and native device tests
remain incomplete. The user deferred actual UAC/phone-authentication acceptance.

ROOT alone runs the authored schema/generation/durability/real-loopback tests and
full platform CI. Synthetic keys and host files are not Android hardware-key,
power-loss, notification or Secure Desktop evidence.
