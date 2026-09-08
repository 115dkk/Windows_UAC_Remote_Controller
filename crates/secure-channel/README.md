# secure-channel

A safe, owned, sans-I/O TLS 1.3 transport for one enrolled phone/PC pair. This
crate contains **no socket, relay account, enrollment UI, QR secret, PKI roots,
production identity-key generator/export or software-private-key fallback**.
It uses pinned rustls 0.23.44 with an explicit ring provider. It does not install
or inherit a process-global provider.
Rustls generates its ordinary ephemeral TLS session keys through that provider;
this is not a fallback identity key.

## Trust boundary

The privileged/native owner supplies one `TlsIdentity` and one already enrolled
`TlsPublicKey` for the peer. Peer authentication means possession of that pinned
**transport** key. It is not approval, Android per-use authentication, TPM or
Keystore attestation, pairing consent, Windows credentials or Windows UAC success.
The registry/enrollment owner must enforce distinct transport, approval and
denial keys. This crate additionally rejects equal local/peer transport keys.

Revocation is not inferred from a cached pin: serialize registry revocation with
the owning channel, call `close` immediately and close the relay, then perform a
fresh registry lookup before a new `Channel` is constructed. Never reuse an
established session as evidence that enrollment is still current.

## Public API

| Type / operation | Meaning |
| --- | --- |
| `TlsPublicKey::from_spki_der(&[u8])` | Validates one exact canonical 91-byte P-256 SPKI: id-ecPublicKey/prime256v1 and an uncompressed nonidentity curve point. Alternate encoding, wrong curves, malformed DER and trailing bytes are rejected. `as_spki_der` returns public bytes; Debug is redacted. |
| `CertificateVerifySignature::from_der(&[u8])` | Validates canonical P-256 ECDSA DER into a fixed 72-byte capacity; parsing is not cryptographic verification. Debug is redacted. |
| `PlatformTlsSigner` | Trusted native extension with `public_key` and `sign_certificate_verify(CertificateVerifyInput)`. No private bytes are requested. Failure is a fixed `SignerError`. |
| `CertificateVerifyInput` | Private constructor; only an exact TLS 1.3 client/server CertificateVerify domain with 64 spaces, context, separator and 32/48-byte transcript hash can reach a signer. `role` and `as_bytes` are available to the native owner. No arbitrary-message constructor, Deserialize or Clone. |
| `TlsIdentity::from_trusted_host(role, Arc<dyn PlatformTlsSigner>)` | Snapshots the native public key and fixes client/server role. Wrong-role use is rejected. Every returned native signature is verified against that own key before Rustls can use it. |
| `Channel::client(identity, enrolled_pc, now)` | Starts the phone side, pinned to one PC key. |
| `Channel::server(identity, enrolled_phone, now)` | Starts the PC side and requires a client raw key/signature. |
| `feed_tls(chunk, now) -> Result<usize, ChannelError>` | Consumes a bounded prefix of untrusted relay ciphertext. Keep/retry the unconsumed suffix. Empty input is not EOF. `Ok(0)` is backpressure, not successful receipt. |
| `drain_tls(output, now) -> Result<usize, ChannelError>` | Writes a bounded prefix of queued ciphertext into caller-owned memory. Caller owns actual delivery and must retain partial network writes. |
| `write_plaintext(bytes, now) -> Result<usize, ChannelError>` | Accepts application bytes only after authenticated readiness. May accept a prefix or zero under output backpressure; caller retains the remainder. No early plaintext queue. |
| `read_plaintext(output, now) -> Result<PlaintextRead, ChannelError>` | Returns `Data(n)`, `WouldBlock` or authenticated `PeerClosed`. Never returns handshake/preface bytes. This is a stream, not complete application messages. |
| `tick(now)` | Checks time and advances bounded internal readiness when no new relay bytes arrive. Required while handshaking; no sleeps/timers are created internally. |
| `status`, `buffered_tls_bytes`, `buffered_plaintext_bytes`, `failure_reason` | Redacted/nonsecret state from the last observed operation. Status is not a user approval or live registry lookup. |
| `close(now)` | Immediate irreversible local abort; drops connection/buffers, including queued application data. Owner also closes transport. Suitable for revocation. |
| `close_gracefully(now)` | Requires readiness and no queued TLS output. Enqueues authenticated close_notify and disables all application I/O. Only bounded TLS drain remains; it does not assert peer acknowledgment. On backpressure use immediate `close` if necessary. |
| `transport_eof(now)` | Report actual relay EOF. Returns `AuthenticatedPeerClose` only after peer close_notify, `LocalAlreadyClosed` for a locally closed no-op (not authentication), otherwise fatal `Truncated`. An empty feed is not EOF. |

No Rustls config, connection, custom verifier injection, key log or secret
extraction API is exposed. `Channel` is not Clone or serializable. All state
changes require exclusive `&mut` ownership.

## Authentication and readiness

Only TLS 1.3, exact ALPN `wuac-control/1` and ECDSA_NISTP256_SHA256 handshake
signatures are accepted. Both certificate verifiers require RFC 7250 raw keys,
reject chains and compare the exact enrolled canonical SPKI. CertificateVerify
is additionally checked with real P-256/SHA-256 verification and the correct TLS
role frame. TLS 1.2 signature callbacks reject unconditionally. No CA or TOFU
fallback exists. Both raw-key resolver flags match their verifiers.
Canonical DER does not impose a low-S rule: mathematically valid high-S ECDSA
signatures, as a native SHA256withECDSA signer may return, remain accepted.

Early data, server half-RTT data, client resumption, server session storage,
session tickets (including requests for extra tickets), certificate compression,
key logging and secret extraction are disabled. The server supplies an
unavailable ticket provider; it does not create a ticket key.

Local TLS client completion alone does not prove the PC processed its client
Finished. Therefore the PC writes the fixed, versioned 18-byte preface
`WUAC-TLS13-READY\0\x01` **inside authenticated TLS application data**, only after
mandatory client CertificateVerify and Finished verification. The client must
consume that exact preface before app I/O. Partial records and partial preface
plaintext are handled without mixing the preface into application payload.

Server readiness means the PC authenticated the client and queued the preface;
it does not mean the phone received it. Client readiness means the authenticated
PC preface arrived. Neither is an approval result. Application framing must
define its own request/response semantics.

## Bounds, time and failure

- Ingress chunk: at most 16 KiB. Records may span several calls; callers must
  retain any unconsumed suffix.
- One application write: at most 16 KiB. One application read/TLS drain: at most
  16 KiB copied, even when a larger output slice is supplied.
- Queued outgoing ciphertext and readable application plaintext each have a
  checked 64 KiB upper bound. Rustls write buffering has record-overhead headroom;
  ingress is backpressured when output is near capacity. Rustls 0.23.44's own
  received-plaintext limit is stricter, and its handshake deframer has a 65535-byte
  message bound. These are queue limits, not a promise that total process memory
  is 64 KiB. The runtime owner must also cap simultaneous channels.
- The handshake/readiness deadline is 10 seconds, expiring at or after the
  deadline. Every `now` must be a fresh trusted host `Instant`, not a renderer,
  relay timestamp or stale queued-event time. Time regression is fatal even
  after readiness. A fresh subsequent operation checks the deadline after a
  potentially blocking native signing callback before readiness/application
  bytes are released. Call `tick` to confirm readiness when no I/O is pending.
  The owner-provided elapsed-time domain must include suspend. Android's raw
  std::Instant may exclude deep sleep, so the native owner must use one checked
  projection from an elapsedRealtimeNanos anchor onto a single Instant origin
  for every call; never mix projected timestamps with raw Instant::now. This
  crate does not prove a raw Android Instant gives a wall/suspend-inclusive
  ten-second timeout. PC request expiry is separately enforced by its owner.
- There is no internal network loop, sleep, async task or unbounded app queue.
  Each operation performs bounded I/O and delegates TLS parsing/crypto to Rustls.
- Fatal TLS, negotiation, readiness, limit, clock and truncation failures drop
  the inner connection, clear accessible buffer counts and latch. Later calls
  return `Failed`; the same object cannot be reset or reinitialized.
- Oversized local app writes and pre-readiness app calls reject without queuing
  data; caller backpressure is recoverable. Oversized untrusted ingress is fatal.
- After authenticated peer close_notify, previously received application bytes
  can be drained; new app writes are rejected. Unexpected EOF makes remaining
  data inaccessible. Bytes already delivered cannot be recalled, so the next
  layer must buffer/validate complete frames and reject truncated frames.
- Immediate local abort does not emit a graceful close_notify and may appear as
  truncation to the peer. That is intentional, especially for revocation.

## Validation and scope

Tests use real Rustls handshakes and explicitly synthetic software P-256 keys
confined to cfg(test). They cover pin mismatches, missing client key, malformed
SPKI/signature encodings, wrong signer role/key, bad/partial readiness preface,
legitimate high-S native-signature interoperability in both directions,
ALPN/version downgrade attempts, ciphertext tampering/replay, queue limits,
partial I/O, closure, fatal latching and deterministic time advancement.

The implementation worker did not execute these tests or any build/lint/fmt
gate. ROOT must run and preserve actual results. No Android device, TPM,
Keystore, relay, runtime enrollment/revocation integration, packaged native
application or end-to-end UAC behavior is proven by this crate alone.
