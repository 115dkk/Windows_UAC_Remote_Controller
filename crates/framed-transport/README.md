# framed-transport

The bounded owner between `secure-channel::Channel` and
`service-protocol::FrameDecoder`. It owns one enrolled TLS connection, one
outgoing frame, one partial decoder and one 16-KiB decrypted suffix.
`PeerTransport` itself performs no socket I/O. The production `SocketDriver`
now composes it with one already connected Tokio TCP stream. Neither layer
performs protocol-signature verification, enrollment, OS authentication,
notification or a Windows action.

## Production socket owner

`SocketDriver::new(socket, transport, clock, limits, cancellation)` consumes an
already connected `tokio::net::TcpStream` and a **fresh, unused** `PeerTransport`
whose shared `ConnectionBudget` reservation is already held. For relay connections, pass
`relay_service::RendezvousCarrier::into_stream()`; its public marker is not TLS
authentication. There is no listener, connector, TOFU, new key, fixture peer,
unbounded channel or background task in this driver.

Create the transport after rendezvous, then adopt it before calling any mutating
PeerTransport method. Read-only status/count inspection is allowed. A previously
driven, drained, fed or queued transport is rejected with `InvalidTransportState`:
the driver cannot reconstruct an earlier socket-send deadline or external byte
buffer. The original TLS creation deadline is preserved, never restarted by
adoption. Constructor inputs are immediately grouped so every early error closes
the socket before releasing its transport reservation, as ordinary owner Drop does.

The native owner supplies `Arc<dyn SocketClock>` with
`now() -> Result<std::time::Instant, SocketClockUnavailable>`. Use the **same
trusted suspend-inclusive projection** used to construct PeerTransport. No
default clock or Android raw-Instant fallback is provided. Read failure or
regression terminates the socket; values are never clamped into validity.
Fresh time and cancellation are checked after synchronous TLS/native signer
calls before an event is returned. A synchronous signer cannot be interrupted
mid-call by this async driver; bounded native signing execution remains its
owner's responsibility.

| API | Meaning |
| --- | --- |
| `queue_frame(Vec<u8>)` | One already length-prefixed frame after Ready. Busy includes ciphertext still pending in the actual socket-write buffer. No second application queue. Busy/NotReady consume/drop rejected input without replacing the current frame. |
| `next_event().await` | Drives bounded duplex I/O and existing TLS/framing; returns one event. The future has an explicit compiler-checked Send contract. |
| `SocketEvent::Ready` | Local peer-pinned TLS/readiness state, once; not enrollment or remote application acceptance. |
| `SocketEvent::Frame(ReceivedFrame)` | One framed message requiring the caller's expected-peer/signature/domain verification before use. No completed-message queue is retained. |
| `SocketEvent::OutboundDrained` | The original queued frame's ciphertext reached the local TCP socket. Not remote receipt, notification delivery, approval or Windows success. |
| `SocketEvent::PeerClosed` | Authenticated close_notify and complete application framing; the actual socket is then closed. Unsent output does not become a drain success. |
| `begin_close()` / `SocketEvent::LocallyClosed` | Explicit local graceful close only with no queued output/unread framing. Continue driving until the close_notify reaches local TCP. This does not claim peer acknowledgment. |
| `abort()` | Immediate socket/TLS/buffer withdrawal, including revocation; no graceful close or successful remote result is asserted. |
| `reject_protocol_message()` | Irreversible actual socket closure for caller-side protocol/signature rejection; always an error result. |
| `pending_counts()`, `failure_reason()` | Bounded counts and fixed categories only; no socket extraction, addresses, keys or bodies. |

`SocketLimits::new(idle_timeout, lifetime)` accepts only positive values no
greater than the five-minute idle and one-hour absolute hard limits; defaults
use those limits. `with_io_chunk_bytes(1..=16384)` bounds work per socket
operation without changing allocations, frame limits or deadlines. The driver
uses exactly one 16-KiB retained read buffer and one 16-KiB partial-write buffer;
the buffers and PeerTransport are heap-owned so async state/return values do not
contain large arrays. PeerTransport's fixed decrypted suffix is likewise a
boxed slice, allocated after its budget reservation. No unbounded Vec/channel
is added. This is bounded allocation, not whole-process heap-zeroization proof.

One nonblocking partial write/read is attempted per drive turn. A WouldBlock
wait selects cancellation, a deadline/clock timer and relevant read/write
readiness; read-only waiting cannot strand pending output. Actual partial write
offsets persist in the owner. A frame's original ten-second deadline continues
until all its ciphertext reaches TCP, including after PeerTransport has handed
it to this driver. Retained RX chunks, pending wire chunks and local closure
also have fixed ten-second budgets. No progress resets those original budgets.
The existing handshake/readiness/frame timeouts still run through fresh calls
to PeerTransport. Socket activity may reset idle, but never absolute lifetime.

The containing native actor must **continuously drive** `next_event` while
connected. No timer or socket work runs in the background after its future is
abandoned. A dropped in-progress future preserves partial I/O and deadlines in
the owner; a later call checks time/cancellation before doing more work. Drop
of the owner closes the actual socket before dropping the PeerTransport and
releasing its budget. Errors close socket/buffers immediately but retain the
reservation until owner Drop; they do not free capacity while a live owner
retains resources. A cancelled/failed/closed driver cannot reconnect or reset.

`tests/tcp_pipeline.rs` now uses this production owner for the real TCP relay +
TLS + signed PC event exchange; its helper only consumes public events. It no
longer implements socket pumping itself. Synthetic keys remain explicitly
test-only, not proof of TPM, Keystore, pairing, service activation or phone UI.
`tests/socket_driver.rs` adds real TCP partial-write/backpressure, future-drop,
cancellation, clock/deadline, queue, close and invalid-input cases. Its small
socket buffers and controlled clock are explicit test fixtures, not production
settings or native clock/authentication evidence. ROOT owns all executions.

## Construction and connection budget

Create one `Arc<ConnectionBudget>` for the containing host/actor:
`Arc::new(ConnectionBudget::new(limit)?)`, with `1 <= limit <= 32`. Pass that same
Arc to every client/server constructor. `limit()` and `active()` are nonsecret
snapshots; they are not a mutable quota or authorization API.

`PeerTransport::client(budget, identity, enrolled_pc_key, now)` and
`PeerTransport::server(budget, identity, enrolled_phone_key, now)` reserve a slot
**before** invoking their actual Channel constructor. A constructor error has no
surviving transport and drops its reservation. Once construction succeeds, its
unique reservation survives all failure/close paths until PeerTransport itself
is dropped. Closing only the inner TLS state does not free a slot while an
outer owner/socket may remain alive. There is no manual release or reset API.

This is not a kernel socket limiter. The native owner must independently bound
accepted sockets and handshake/admission/reconnect rates, close rejected sockets,
and couple actor teardown to actual relay/socket teardown. Do not create separate
budgets per connection and then describe them as a global limit.

## API

| Operation | Contract |
| --- | --- |
| `feed_tls(chunk, now)` | Returns consumed ciphertext bytes; retain the unconsumed suffix. At most Channel's 16-KiB ingress chunk. `Ok(0)` is backpressure and never EOF. Poll frames before retrying when decrypted data remains unread. |
| `drain_tls(output, now)` | Copies at most Channel's 16-KiB ciphertext drain. Retain partial actual socket writes externally. Copying bytes out is not delivery/acknowledgment. |
| `queue_frame(Vec<u8>, now)` | Takes one **already u32-length-prefixed** frame, including its four-byte header. Requires ready state and no existing outbound frame. Length and retained Vec capacity must be at most `MAX_PC_EVENT_BYTES + 4`; exact header length is validated without cloning. Busy/NotReady consumes and drops the rejected Vec; the caller should inspect pending state before generating another frame. |
| `poll_frame(now)` | Processes at most one 16-KiB decrypted chunk and returns at most one complete `ReceivedFrame`. A large frame can require multiple calls returning None. The suffix is retained, not copied to a second queue. |
| `ReceivedFrame::into_bytes()` | Consumes the redacted, non-Clone framing wrapper. The returned bytes are **not** signature-verified or authorized. Process or discard before polling again. |
| `tick(now)` | Checks Channel/receive/send deadlines and advances one bounded outgoing chunk while idle. No internal sleeps, timers, network loop or worker task. |
| `transport_eof(now)` | Reports actual relay EOF. Only Channel's `AuthenticatedPeerClose` disposition can finish the decoder; `LocalAlreadyClosed` is not peer authentication. Unexpected TLS EOF is fatal. |
| `close(now)` | Immediate local abort, dropping queued data/TLS/decoder state; reservation remains until Drop. Owner must close the real relay/socket. |
| `reject_protocol_message(now)` | Irreversibly fails/closes after caller-side PC signature, decision or protocol decoding failure. Always signals an error rather than accepting unknown bytes. |
| `status()`, `pending_counts()`, `failure_reason()` | Nonsecret state/counts and fixed failure reasons. No inner Channel/config/verifier/key-log access. |

`PendingCounts::outbound_frame` remains true even when all plaintext was accepted
by TLS but ciphertext is still queued. There is no second pending frame and no
complete-received-frame queue. Debug output does not include message bodies,
display text, keys or signatures. Buffer dropping is not a crash-dump or heap
zeroization guarantee.

## Absolute deadlines and backpressure

All operations receive a **fresh trusted, suspend-inclusive** Instant domain.
Channel enforces monotonicity and TLS/readiness deadlines. Android owners must
consistently project `elapsedRealtimeNanos` from one checked anchor onto one
Instant origin; raw std::Instant may exclude deep sleep. Never mix raw/projected
clocks, renderer/relay timestamps or old queued-event timestamps. The native
owner samples again after blocking signing work; this wrapper performs no
post-feed Channel mutation using the pre-signing timestamp.

Incoming frame lifetime is ten seconds starting with its first authenticated
header byte. Arrival time is retained even before the caller polls the decoder,
and a later chunk never restarts the partial-frame deadline. Later-frame headers
already in a suffix retain that suffix's original admission time. While a suffix
or Channel plaintext is unread, new ciphertext is backpressured; this prevents
mixing arrivals from different operations into one untracked plaintext bucket.
The limit also bounds caller-side delay in processing an admitted batch. A
deadline expires **at or after** its limit, including during slow-drip input.

An outgoing frame has a separate ten-second absolute deadline from queueing until
both its plaintext prefix and Channel's TLS output queue are fully drained.
Successful progress or Busy retries never extend it. One at-most-16-KiB plaintext
chunk is written only when the TLS output queue is below 16 KiB, keeping room
for peer control traffic and avoiding large-duplex output starvation. The lower
Channel's hard 64-KiB queue caps still apply. No unbounded flush loop exists.

The outgoing deadline stops when the wrapper hands all ciphertext to the caller,
not when a socket sends it. The actual socket writer must retain one bounded
partial-write buffer, enforce its own deadline and never label a drain as remote
acceptance. UI/request expiry and Windows target validation remain independent.

## Receiving rate, close and fatal states

At most 128 completed frames may be returned per one-second fixed window,
anchored at transport construction. The 129th frame in that window fails before
it reaches the caller's expensive protocol verification. Exactly at the next
window boundary the counter resets; this is not a sliding-window claim. It is a
per-transport-instance limit; the host still owns admission/reconnect and any
per-enrolled-device aggregate limits.

On authenticated TLS close_notify, `PeerClosing` allows already authenticated
bytes to be framed one result at a time. New plaintext writes stop, but an
existing outbound deadline is not erased. `FrameDecoder::finish` runs when all
decrypted bytes/suffixes are drained. A partial final header or body is fatal;
only its successful finish produces `PeerClosed`. A complete frame before a
later truncated tail may already have been returned; the incomplete tail is
never returned as a complete frame. Process/verify each frame independently.

Normal peer close does not discard a valid incoming frame merely because a local
outgoing frame was pending. The owner should drain/process incoming frames, then
abort/drop the peer; it must not retain an unsendable outbound frame beyond its
original deadline. Local close does not prove authenticated peer EOF and cannot
release additional received frames.

Frame errors, deadlines, rate excess, TLS failures and protocol rejection drop
all accessible queued state and irreversibly latch failure. Future operations
return Failed; there is no in-place reconnect/reset/bypass. The native owner must
close the actual relay and drop the PeerTransport to release its budget slot.

## What this layer does not prove

`ReceivedFrame` only binds complete length framing to an authenticated TLS
stream. The caller must select the expected PC/signing key, verify and decode the
PC event/decision, reject unknown versions/kinds, check live enrollment and
request correlation/expiry, and enforce the native Windows/phone authentication
boundary. Call `reject_protocol_message` on verification/decoding rejection.
TLS readiness or a framed Vec is never permission to approve, sign arbitrary
data, inject input or act on Windows.

One budget bounds this owner's simultaneous allocations: at most 32 transports,
each with one bounded TX frame, one bounded decoder allocation, one 16-KiB suffix
and Channel's bounded buffers plus engine/native overhead. Returned frames and
socket buffers are caller-owned; do not accumulate an unbounded external queue.
This crate provides no network/relay deployment or Windows/Android OS integration.

Tests use real Channel endpoints and test-only deterministic P-256 software
signers. They exercise maximum duplex frames, fragmentation, multiple frames,
malformed lengths, slow drip, rate windows, time regression, closure/truncation,
budget lifetime/concurrency and protocol rejection. The implementation child did
not run them; ROOT owns formatting, all builds/tests/lint/analyzer and integration
verification. Synthetic TLS tests do not prove device or end-to-end UAC behavior.
