# Service-origin protocol v1

First-party `forbid(unsafe_code)` codec for **signed PC events inside confidential,
authenticated transport**. This is not an enrollment authority, an OS observer,
an approval gateway or proof that a native notification/UAC action occurred.

The PC signing key is selected from a trusted enrollment mapping. It is distinct
from a phone's approval and denial keys. A network/relay process must not be
allowed to request arbitrary signatures from the privileged PC key owner.
The actual owner constructs events from its immutable OS target and lifecycle;
Rust constructors alone do not prove its privilege or native observations.

## Messages and signature

| Kind | Content |
| --- | --- |
| Opened (1) | Full existing `RequestBinding`, original service-issued tick, exact program name/path/details, and verified content digest |
| Resolved (2) | The same full binding and original issued tick, plus actual Approved/Denied/Cancelled/Expired/Failed outcome |
| Clock (3) | PC, service epoch, fresh phone probe nonce and service sample tick |

All numeric fields are big-endian. The body starts with version `u16=1` and a
one-byte kind. Request binding fields use the same order as approval-protocol:
PC32, boot32, session-u32, logon-u64, request32, nonce32, content-digest32,
expiry-u64. Issued/sample ticks are u64 nanoseconds on that service epoch, not
wall-clock timestamps. Zero issuance/sample is valid at epoch start. Expiry is
still positive and original request lifetime is strictly `0 < expiry-issued <=
120,000,000,000` ns. Text fields are separately u32-length-prefixed, exact UTF-8,
and retain approval-protocol's 98,304-byte per-field limits.

Sign `Windows-UAC-Remote-Controller/pc-event/v1` followed by NUL and the entire
body using P-256/SHA-256. Android/JCA-style SHA256withECDSA hashes those bytes;
Windows digest-signing code must hash them exactly once. Nothing signs JSON or
an untrusted renderer's reconstructed description. The wire record is:

`WUACSRV\0 | u32 body_length | body | u16 DER_length | DER`

DER is strictly canonical and 8–72 bytes. Both valid S representatives verify;
signature bytes are never replay identity. The decoder validates the bounded
record, verifies its signature, then parses/allocates display strings. It rejects
unknown versions/kinds, invalid identifiers, lengths, trailing bytes, malformed
DER/UTF-8, NUL text, lifetime errors and a content-digest mismatch even when a
synthetic test key signs the malformed body.

`UnsignedPcEvent` is validated data, `SignedPcEvent` is syntactically signed data,
and only `VerifiedPcEvent` is a signature-checked expected-PC message. Public
event data may be constructed without authentication; receiving application
interfaces must require the verified wrapper, not a cloned bare enum.

## Framing and memory

An encrypted application stream prefixes each payload with a u32 length. The
incremental `FrameDecoder` validates length before allocating and emits at most
one frame per feed. Input chunks are at most 16 KiB; one frame is bounded by
`MAX_PC_EVENT_BYTES` (288 KiB text plus fixed metadata/signature). A caller must
consume the returned frame before advancing the unconsumed input. Invalid
length or oversized input poisons the decoder. EOF inside any header/body is
truncation, never an implicit complete message.

The decoder holds one partial frame, not an unbounded queue. The host must bound
connections, finished frames, processing rate and content retention separately.
Use only decrypted, authenticated TLS application bytes; length framing is not
encryption or authentication. No credential/password message exists here.

Debug output redacts display text, paths, IDs and signatures. Request details
remain transient display data and must not reach ordinary logs/history, even
though they are correctly signed. Redaction is not heap zeroization or a crash
dump policy.

## Required integration, still incomplete

- A trusted QR/native enrollment ceremony, attestation and live key revocation.
- Exact Windows prompt capture and actual result generation, not signature
  acceptance relabelled as Windows success.
- The supplied authenticated monotonic clock correlation must be connected to
  native clocks. Never start a new full TTL at each receipt/reconnect; retain
  each request's first mapping and suppression state.
- Phone-side off-hours pre-display drop, restart/replay reconciliation and
  Android-owned expiry/cancellation withdrawal.
- TLS/relay actors with bounded queues. The secure-channel crate authenticates
  transport peers but does not itself establish the above authority.

Root has exercised the event/framing tests using synthetic keys. These do not
create a paired phone or prove native Windows/Android behavior.

## Conservative clock mapping

`ClockProbe::start` creates a new CSPRNG nonce. Consuming `complete` requires a
verified Clock event for that PC/nonce and a trusted phone round trip no longer
than ten seconds. The correlation freezes the service sample and PHONE SEND
time, not receipt or an estimated midpoint. Mapping uses
`phone_sent + (service_expiry - service_sample)`; network delay cannot add a new
TTL. Mappings reject wrong PC/epoch, expired/future/overflowing values and anchors
older than five minutes. A native monotonic regression irreversibly faults the
correlation. Issuance preceding the phone origin saturates to zero; expiry is
never extended or saturated forward to rescue an invalid request.

Keep the first mapping for the entire request. The phone inbox retains extra
body-free replay guards until the first probe's received-anchor upper expiry;
pruning at the conservative lower expiry alone could let a later, more favorable
clock probe resurrect the request. Neither this codec nor a fresh TLS connection
provides cross-process persistence; durable drop guards/delivery reconciliation
remain required native-owner work. Clock inputs must have consistent units and
include device suspend, not use UI/relay timestamps.
