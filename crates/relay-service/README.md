# relay-service

SPDX-License-Identifier: GPL-2.0-or-later

An intentionally small, bounded raw-TCP rendezvous carrier. It pairs a PC-role
socket and phone-role socket under an opaque route, then forwards bytes. It is
**not** an authentication, enrollment, signing, approval or execution server.
There is no application-message parser, key store, payload history or persistence.

This crate is implementation work, not an Internet deployment or completed
Windows/Android product. Root-only validation is required; the implementation
child did not start a listener, run a binary or execute any tests/build/lint.

## Endpoint security requirement

The outer TCP stream is deliberately not TLS. After rendezvous, the two endpoints
must run the real `secure-channel` mutually pinned inner TLS session. Never
interpret a route, role, ready marker or successful byte copy as peer identity or
user authorization. There is no plaintext application-data fallback. In
particular, credentials/requests/decisions must not be sent as plaintext here.
The relay cannot enforce this by examining bytes without ceasing to be an opaque
carrier; enforcing peer TLS belongs to each actual endpoint.

The relay can observe route IDs, roles, source addressing at the network layer,
traffic sizes and timing, and can drop/delay/misdirect traffic. The implementation
does not log peer addresses or routes, but it does not claim metadata anonymity
or denial-of-service immunity. An untrusted party can guess/use a known route or
occupy finite slots; inner peer pinning must reject that party. Route knowledge is
not enrollment or authority. Native TPM/Keystore ownership, enrollment, push
delivery and hosting remain separate work.

## Fixed version-one wire contract

Each connecting endpoint sends exactly this 43-byte registration prefix:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `WUACRLY\0` |
| 8 | 2 | Big-endian version 1 |
| 10 | 1 | Role 1 = PC; role 2 = phone |
| 11 | 32 | Nonzero opaque RouteId |

All-zero routes, unsupported roles/versions, bad magic and malformed/incomplete
headers are rejected by closing the socket, not by reflecting input or sending
raw error text. Reads are bounded and use one absolute registration deadline;
trickling bytes does not reset it. A Registration value and RouteId constructor
describe wire syntax, not authenticated participants.

Two opposite roles on the **same** route are a routing match. The relay writes
the fixed nine-byte **untrusted** marker `WUACPAIR\0` to both endpoints before
forwarding any bytes in either direction. Endpoints consume the complete marker
and begin their actual inner TLS deadline. The marker is not encrypted,
authenticated or a substitute for that handshake.

A live duplicate role never overwrites or kicks the first waiting participant.
While a route is active, further registrations for it are rejected rather than
starting a parallel room. Different routes never cross-connect. Routes disappear
when their owned participant/pair finishes; stale completion IDs cannot remove
a newer owner of the same route.

Correct endpoints should wait for the marker before TLS. A cancel-safe one-byte
read detects a waiting EOF, using the same read path as active copying. If a peer
pipelines data, at most one opaque byte stays in its own Peer and remaining bytes
stay unread in the socket. The byte is placed in that direction's existing copy
buffer and forwarded exactly once only after both markers. It is never parsed,
echoed before pairing or reused in another route. EOF behind unread pipelined
data remains subject to the absolute waiting deadline; the relay does not busy
poll readable data or accumulate an unbounded buffer while waiting. The
16-KiB bound is for each application's copy buffer, not a claim about the OS's
TCP buffering/TIME_WAIT implementation.

## Public library API

```text
run(TcpListener, RelayLimits, CancellationToken)
  -> async Result<RelayReport, RelayError>

connect_rendezvous(SocketAddr, Registration, CancellationToken)
  -> async Result<RendezvousCarrier, RendezvousError>

RelayLimits::new(max_connections, max_waiting_rooms) -> Result<RelayLimits, RelayLimitsError>
RelayLimits::with_timeouts(header, waiting, inactivity, absolute, shutdown)
  -> Result<RelayLimits, RelayLimitsError>

RouteId::new([u8; 32]) -> Result<RouteId, RegistrationError>
Registration::new(Role, RouteId) -> Registration
Registration::{to_wire, from_wire, role, route}
```

`CancellationToken` is re-exported for callers. The listener is already bound by
the caller, which owns the interface-selection decision. Tests use ephemeral
loopback only. Limits have read-only getters and cannot exceed these ceilings:

The endpoint connector has a five-second connection deadline and a separate
30-second registration/marker deadline. Both are cancelable; partial marker
input never extends the deadline. It reads only the fixed nine-byte marker,
preserving any coalesced following bytes. `RendezvousCarrier::into_stream()`
returns an **unauthenticated** byte stream for the bounded peer-pinned TLS
actor, never a trusted/paired service connection. Both product connector and
relay accepted sockets set TCP_NODELAY for small control records. That socket
policy is not an EOF guarantee or a claimed solution to the open native EOF
test failure.

| Resource/deadline | Default and hard maximum |
| --- | --- |
| Accepted live connections, including headers/waiters/active peers | 64 |
| Waiting rooms | 32 |
| Absolute header read | 5 seconds from acceptance |
| Counterpart wait, including mailbox admission | 30 seconds after valid header |
| Pair handoff + both markers | 5 seconds from routing match, or shorter absolute lifetime |
| Active inactivity | 5 minutes since actual forwarded write progress in either direction |
| Absolute pair lifetime | 1 hour from routing match |
| Explicit server shutdown | 5 seconds total |
| Copy buffer | Fixed 16 KiB per direction; at most one early byte per waiting peer |
| Registration control mailbox | Exactly configured accepted-connection limit |

Configuration may tighten deadlines (positive values only). Connection count is
2–64 and waiting rooms are 1–32, additionally bounded by the connection limit.
Inactivity and absolute lifetime remain independent; forwarding traffic cannot
reset the absolute lifetime.

The accept loop reserves an OwnedSemaphorePermit **before spawning** each
connection task. When full, newly accepted sockets are immediately closed. The
permit travels with the socket, including a bounded one-shot handoff to the pair
leader, and is released only when the owning socket/task drops. No detached
per-direction tasks, per-IP maps or unbounded payload/control queues are created.

The two copy futures—including both read and partial-write loops—run under the
pair's cancellation, inactivity and absolute deadline selection. Successful
forwarded writes update only a one-slot timestamp watch. A blocked write remains
cancelable and deadline-bound. EOF or I/O failure in either direction ends both
directions. The coordinator retires the exact route generation before dropping
the returned sockets/permits, so client-observed EOF cannot precede stale-route
retirement in the returned-task path. Pending Lead cancellation drains and
retains any already-handed peer; an exact-generation follower that returns
before handoff stays in one bounded Active slot until leader retirement. Stale
follower IDs cannot fill a newer generation's slot. Seven ROOT lifecycle
regressions pass, but the independent Windows raw-socket EOF failure and full
relay EOF/deadline tests are still unresolved. This carrier does not keep
an orphan half-open connection waiting
indefinitely for the other side. Root's concurrent EOF regression gate remains
required; isolated passing runs are not treated as proof that a race is solved.

`RelayReport` contains aggregate counts only. `paired` counts routing matches,
not authenticated peers, delivered application messages or successful decisions.
Socket/task/route errors expose only fixed categories. Debug output never includes
route bytes, socket addresses or payloads.

## Shutdown ownership

Cancel and **await** `run` for graceful bounded cleanup. It cancels only its own
child cancellation token, closes the listener and bounded control mailboxes,
drops waiting assignments, allows workers to observe cancellation, then aborts
and joins any remainder before the final deadline. A successful report requires
all socket permits returned (`remaining_connections == 0`). Uncompleted cleanup
returns a fixed failure, not a success claim.

Dropping the run future triggers its cancellation guard and JoinSet aborts; it
does not detach tasks. As with other async APIs, dropping a future is not itself
an awaited shutdown receipt. Root tests must use explicit cancellation and join
to prove socket/task cleanup. No blocking task or custom unsafe socket operation
exists in this crate.

Dependencies are pinned to the verified Tokio 1.53.1 and tokio-util 0.7.19 APIs;
first-party code forbids unsafe, while dependency internals are a separate
boundary. JoinSet abortion must be followed by joining its tasks, which this
implementation does.
[Tokio](https://docs.rs/tokio/1.53.1/tokio/),
[CancellationToken](https://docs.rs/tokio-util/0.7.19/tokio_util/sync/struct.CancellationToken.html).

## Optional foreground CLI

The binary binds only `127.0.0.1:7443` with no arguments. Binding any non-loopback
interface requires explicit `--listen IP:PORT`; addresses must be numeric. There
is no environment-driven public-interface default, service installation, daemon
mode, firewall mutation, TLS-key option, account setup or deployment command.
`--help` documents the byte-carrier boundary. Ctrl+C cancels and awaits the relay.
Only aggregate counts or fixed failures are printed, never peer IPs, routes or
raw OS errors. This child did not run that binary or open any listening port.

## Validation boundary

Tests are real LOCALHOST TCP fixtures with clear synthetic byte payloads. Those
test bytes deliberately exercise raw forwarding; they are **not** production
plaintext fallback or TLS/native-authentication evidence. ROOT alone executes
each TDD slice, formatting, builds, Clippy `-D warnings`, real Rust Analyzer and
the integration tests. No passing gate may be inferred from test authoring.

This relay does not complete peer TLS/native key integration, remote UAC,
credential-entry feasibility, Android push reception, deployment or operational
hardening. The full product objective remains unchanged.

SUPERLOOPY_EVIDENCE: .superloopy/evidence/relay-service-implementation.md
