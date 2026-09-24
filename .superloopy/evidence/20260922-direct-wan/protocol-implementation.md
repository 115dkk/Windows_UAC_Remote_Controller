# Direct-address protocol implementation

Status: implementation and static source review only; child ran no build, test,
lint, formatting, network, executable or device checks. ROOT owns CI validation,
security proof source bindings, release and native verification.

## Scope and compatibility

- `secure-channel` offers/prefer `wuac-control/2`, retains `wuac-control/1`.
  Existing TLS1.3, exact enrolled raw P-256 key pinning, no-resumption/no-early-data,
  CertificateVerify and encrypted readiness requirements remain unchanged.
- `ControlProtocol::{V1,V2}` and `negotiated_protocol() -> Option<ControlProtocol>`
  are exposed by Channel, PeerTransport and SocketDriver. Capability is available
  only after authenticated readiness. Hosts send address frames only on V2.
- `PcEvent` and old approval/clock wire formats are unchanged.
- `PairingInvitation::new` and `fields()` retain their existing field DTO.
  Empty alternatives preserve the exact original V1 binary/QR/digest. The new
  `with_alternatives(Vec<SocketAddr>)` permits up to three distinct alternatives,
  and `candidates()` returns primary then alternatives.
- V2 invitations use wire version2, `uac-remote:v2:` prefix and separate V2 digest
  domain. The full ordered candidate suffix is bound into the original context
  digest. Empty V2 suffixes and cross-version QR prefixes are rejected. Original
  V1 remains strict: exactly345/357 binary bytes. Combined max415 bytes /568 text.

## Address-control contract

- Independent eight-byte magic `WUACADR\0`, version2, kind1 query / kind2 ad.
  Header includes a zero reserved byte. Classification does not validate bytes.
- Query fields: PC32, device16, route32, ClockProbeNonce32. All-zero identities,
  route and nonce are rejected; exact query size124 bytes.
- Signed ad repeats that exact query context, then BootEpoch32, BE TTL-u32,
  endpoint-count-u8, 0..4 endpoints and length-prefixed canonical P-256 DER.
  Signature domain is `Windows-UAC-Remote-Controller/address-advertisement/v2\0`.
  Max311 bytes, below existing framed PC-event budget. An independently supplied
  PcPublicKey verifies the transcript into a private-construction proof type.
- Endpoints encode family-u8, BE port-u16 and4/16 raw address octets. Reject
  zero ports, unspecified/loopback/multicast, IPv4 broadcast/0/8/reserved240/4,
  IPv6 mapped/flow/scope/link-local, and duplicate endpoints. Private LAN and ULA
  are accepted as shapes; native owner decides actual mapping/reachability.
- Live endpoint lists require TTL1..3600 seconds. Empty list requires TTL0,
  meaning withdrawal of alternate hints. TTL is a fresh-status limit, not an
  authorization, request-lifetime extension or enduring reachability claim.
  Expired retained coordinates may be used only as untrusted dialing guesses,
  with mandatory fresh pinned TLS and current-state checks. A replay may not
  refresh a hint or undo withdrawal; pending nonce/context/epoch/query-age and
  consume-once validation belong to the receiver. No immutable pairing changes.

## Added test sources (not executed by child)

- AddressQuery independent layout oracle, exact length/header/nonzero rejection.
- Signed advertisements: correct and wrong key, every context field plus endpoint
  tamper, separate signature domain, replay signature-vs-freshness distinction,
  zero epoch, truncation/trailing/oversize, TTL, withdrawal, candidate bounds,
  LAN acceptance and invalid-address families.
- Invitations: retained V1 independent binary/base64 oracle, exact V2 layout,
  digest binding and mutation, candidate order, prefix/version mismatch, empty
  V2 suffix, duplicates, over-limit candidates and maximum binary/QR size.
- TLS byte-pump fixtures: legacy client to new server V1 fallback, new client to
  legacy server V1 fallback only after readiness, V2 preference and normal modern
  V2 handshake. Native end-to-end compatibility remains ROOT/device evidence.

## Integration ownership

ROOT owns Windows query/context validation and restricted service signing, signed
advertisement generation, actual mapping/public reachability judgment and CI.
Android worker owns pending nonce/current association and clock epoch matching,
monotonic freshness, untrusted locator cache/withdrawal and bounded pinned dialing.
No source-binding manifest, generated proof hash or security gate was changed.
