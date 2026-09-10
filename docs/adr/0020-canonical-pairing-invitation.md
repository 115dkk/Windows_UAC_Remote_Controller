<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0020: Canonical original pairing invitation with numeric relay addressing

Status: ROOT-approved wire/address design; implementation authored; ROOT validation pending.

## Context

The frozen-candidate statement already binds `InvitationContextDigest`, but that
width-only type did not define which original invitation bytes PC and phone must
hash. No first-party QR invitation encoder/parser, native scanner or reachable
original-QR ceremony source exists. The existing relay connector accepts
`std::net::SocketAddr` and the existing relay registration contains a role and a
nonzero public 32-byte `RouteId`; neither confers identity or enrollment authority.

Define one shared, bounded original-invitation codec in `service-protocol` rather
than letting native callers hash independently chosen JSON, URLs, display text or
fields copied from a later candidate. This is not a new persistence owner, relay
registration codec, native grant, network listener or deployment.

## Decision and exact binary format

`PairingInvitationFields` contains the original ceremony nonce, attestation
challenge, PC identity, PC-assigned recipient device ID, PC signing/transport
public keys, numeric relay address and public route bytes. `PairingInvitation`
validates shape and retains these fields privately. It is explicitly copyable
public metadata, not a single-use capability. It has no serde or Display
implementation; invitation fields, invitation and errors have redacted Debug.

All multi-byte integers are big-endian. The entire binary body is canonical:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 8 | Exact magic `WUACQRI\0` |
| 8 | 2 | Version 1 |
| 10 | 1 | Kind 1 |
| 11 | 1 | Reserved, exactly zero |
| 12 | 32 | Nonzero `PairingNonce` |
| 44 | 32 | Nonzero `PairingChallenge` |
| 76 | 32 | Nonzero `PcIdentity` |
| 108 | 16 | ORIGINAL PC-assigned nonzero `DeviceId` |
| 124 | 91 | Canonical PC signing P-256 SPKI |
| 215 | 91 | Canonical PC transport P-256 SPKI |
| 306 | 1 | Address family, exactly 4 or 6 |
| 307 | 2 | Nonzero relay port |
| 309 | 4 or 16 | IPv4 or IPv6 address octets, respectively |
| 313 or 325 | 32 | Nonzero PUBLIC route name |

The only accepted binary lengths are 345 bytes (IPv4) and 357 bytes (IPv6).
Length bounds are checked before key decoding. Unknown versions/kinds/reserved
values, malformed/noncanonical keys, zero IDs/route/port, unknown address family,
family/length mismatch, truncation and trailing bytes reject without fallback.
The established `TlsPublicKey` codec is reused. The PC may deliberately use its
same domain-separated key for both PC roles; no fourth or pre-created phone key
is invented. The existing role-labelled phone key digest is separate, created
only after the phone's actual three-role key set exists.

## Numeric-address and relay policy

The v1 endpoint is `SocketAddr`, not a URI or unresolved host string. There is no
DNS name, path, query, user-info or implicit URL parsing. IPv6 flowinfo and scope
ID must both be zero. IPv4-mapped IPv6 is rejected rather than silently normalized
into IPv4; use the IPv4 form for that endpoint. Equivalent textual spellings of
the same ordinary IPv6 numeric address already map to the same address octets
before entering this typed codec.

Nonzero ports from 1 through 65535 are representable. The codec does not claim
that a numeric address is deployed, reachable, suitable for a particular network,
or permitted by native egress policy. It does not resolve, connect, open a socket
or mutate firewall/network policy. Later DNS/URL support requires a versioned
format decision, not implicit normalization or reinterpretation of v1 bytes.

`route: [u8; 32]` carries the existing relay's public routing name. It is not a
secret, PIN, identity or enrollment credential. Future carrier composition must
reuse `relay_service::RouteId::new(invitation.fields().route)` and the existing
`Registration`/`connect_rendezvous` flow. This codec does not allocate a route,
duplicate registration, change the connector or depend on the relay daemon.

## Exact QR text and context digest

The text envelope is exactly ASCII `uac-remote:v1:` followed by unpadded URL-safe
Base64 of the full binary body. It is 474 bytes for IPv4 or 490 bytes for IPv6.
There is no whitespace trimming, padding, case folding, percent decoding,
standard-Base64 alphabet acceptance or trailing-junk tolerance. Text is bounded
before decoding into a fixed 357-byte stack buffer. The already-locked
`base64 = "=0.22.1"` engine uses strict `URL_SAFE_NO_PAD`; both legal body sizes
are multiples of three and have no partial final Base64 symbol.

`PairingInvitation::context_digest()` returns the existing
`InvitationContextDigest` and computes exactly:

```text
SHA-256(
  ASCII("Windows-UAC-Remote-Controller/pairing-invitation/v1") || 0x00
  || full_canonical_invitation_binary_body
)
```

This binds the complete header, original nonce/challenge/PC/recipient/pins and
relay address/port/family/route. It does not hash the textual prefix or Base64
spelling and is distinct from the frozen-candidate signing domain, comparison-code
domain, enrollment-acceptance domain and phone-role digest domain. Native PC and
phone owners compute it from their independently retained ORIGINAL invitation,
never from a supplied digest or a context reconstructed from a frozen reply.

## Authority, time and remaining native work

Parsed bytes, successful re-encoding, a digest and QR possession prove shape
only. The codec does not authenticate the display/scanner, show consent, verify
fresh UAC, attest keys, sign an acceptance or commit a registry. It has no QR image,
camera, WebView, JNI/UniFFI or Windows application path. No PC display name or
extra identity presentation metadata is included; native UI/identity metadata is
a separate flow.

The original five-minute monotonic lifetime remains owned by the existing native
ceremony state. There is no QR UTC/expiry field, newly minted phone lifetime or
signed claim of currentness. Repeated parsing deliberately remains possible;
QR replay must be rejected by the actual live PC ceremony's nonce/handshake and
native owners. Capturing a QR may cause denial of service, but must never confer
candidate authorization under the required strict single-freeze, SAS comparison
and native-confirmation conditions. Those conditions are not enforced or proven
by this codec and remain necessary before any enrollment commit.

## Validation boundary

Source tests cover exact IPv4/IPv6 binary and text roundtrips, an independent
Base64 bit oracle and domain/body hash oracle, every original field's digest
binding, header/key/ID/route/endpoint failures, address-normalization policy,
every truncation, trailing and oversized input, text-prefix/alphabet/padding/
whitespace/non-ASCII errors, mixed frozen/acceptance formats and debug redaction.
A compile-fail example guards against implicit Display conversion.

ROOT owns actual formatting, test/doctest execution, Clippy, Rust Analyzer and CI.
The implementation child executed none of those checks and did not regenerate
the lockfile. These are synthetic codec tests, not QR provenance, native consent,
attestation, physical-phone authentication, deployed-relay or end-to-end proof.
