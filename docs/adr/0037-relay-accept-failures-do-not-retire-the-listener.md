<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0037: A refused accept costs one connection, not the relay

Status: implemented source with unit coverage; the coordinator's own socket
tests are the existing gate. This changes only how the rendezvous coordinator
reacts to two failures. It adds no frame, no authentication, no route knowledge
and no configuration surface, and it does not touch
[ADR0031](0031-embedded-relay-and-install-shortcuts.md)'s embedded listener.

## Evidence

`run_loop` is one `tokio::select!` that owns the listener, the registration
mailbox and every connection task. Almost all of it already fails at the right
size. A full connection budget closes the new socket and continues. A failed
`set_nodelay` drops that socket and continues. Every counter is
`saturating_add`, the connection identifier is `checked_add`, and the waiting
rooms are reaped on each registration. The deadlines an idle client could abuse
are already in `RelayLimits`: five seconds for the forty-three-byte header,
thirty for a waiting room, five minutes of inactivity and an hour absolute.

Two branches were the exception, and both ended the whole run:

```rust
Err(_) => break Some(RelayError::AcceptFailed),
```

```rust
Some(Err(_)) => { report.task_failures += 1; break Some(RelayError::TaskFailed); }
```

The first is reachable from outside. `accept` fails for reasons that pass: a
descriptor shortage, or a client that resets while the kernel is still
completing its handshake. Under the old branch any one of those retired the
listener for everyone, which means a client could end the service by failing to
finish its own connection.

## Decision

**An accept failure costs a wait.** The coordinator counts consecutive
refusals, clears the count on the first accepted connection, and sets a fifty
millisecond backoff. The backoff disables the accept branch rather than
awaiting inside it, so a struggling listener never stalls cancellation,
registration or task retirement; the sleeping branch is last in the biased
select for the same reason. A run of sixty-four refusals is a listener that is
broken rather than busy, so the run then stops with `AcceptFailed`. Swallowing
the failure with no backoff would spin at full speed, which is a denial of
service of its own, and swallowing it forever would hide a dead listener. The
count is reported as `accept_failures` and printed by the CLI, because a
survivable refusal now ends the run successfully and this is the only place an
operator would see it.

**A task failure is bounded, not made free.** Nothing is aborted while the loop
runs, so a `JoinError` there is a panic. The task unwound its own sockets and
permits, so the connection is already gone and the rest of the service is
untouched, and serving on is right. What does not happen is `finish_task`:
tokio names the failed task with an identifier this crate cannot read on stable,
so the coordinator cannot say which route died, and that route entry survives,
holding the retained follower socket and its slot until shutdown clears the map.
The prescription that fits the accept branch therefore does not fit this one.
Eight panics are tolerated and then the run stops, which keeps the strand well
under the sixty-four connection ceiling, and `task_failures` still makes the run
return `TaskFailed` at shutdown, so nothing is silently swallowed.

The panic isolation this relies on exists only because the release profile
unwinds. `panic = "abort"` would end the process on the first panic and make
tokio's per-task isolation meaningless. It is absent today and must stay absent.

**The invariant tripwire stays fatal.** `finish_task` returns `TaskFailed` when
a task's claim on a route contradicts the coordinator's own record, such as a
second follower trying to fill a retained slot. That is not a failure the
service should survive: it means the ownership state is already wrong, and
continuing would risk overwriting a live socket. It keeps ending the run on the
first occurrence.

## Scope

Unchanged: the wire, the route identifiers, the header, the deadlines, the
connection and waiting-room ceilings, the assignment and handoff ownership
rules, and the shutdown sequence with its `ShutdownIncomplete` bound. No limit
became configurable; the backoff and both ceilings are fixed policy an operator
cannot widen.

Not established here: that a connection task can panic at all. That path has no
`unsafe`, no attacker-sized allocation, no indexing by a received value and no
unchecked arithmetic, so the tolerance is depth behind a defence rather than a
fix for a known fault. The accept branch is the one that was reachable.
