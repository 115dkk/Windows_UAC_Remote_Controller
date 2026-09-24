# Direct gateway implementation — source evidence

Date: 2026-09-22. Worker: direct_gateway. This is implementation/static-review
evidence, not test execution or proof of off-LAN reachability. No build, tests,
formatter, lint, device execution, router discovery or live mapping was run by
this worker. ROOT owns CI and native acceptance results.

## Ownership and public API

Owned changes: `crates/relay-service/Cargo.toml`, `src/hosted.rs`, `src/lib.rs`
exports, `src/direct.rs`, and `src/direct/` modules/tests. Cargo.lock, runtime,
protocol, Android and presentation are owned by other lanes.

- `HostedRelay::start_embedded(port)` tries one dual-stack socket, then IPv4.
  The existing `run` is called exactly once, so IPv4/IPv6 share room state.
  `supports_ipv6()` lets runtime exclude unavailable IPv6 candidates.
- `local_endpoint()` reads routing-selected IPv4 source with UDP connect and no
  send; when unavailable it tries a global IPv6 source the same way.
- `DirectGatewayOwner::start(SocketAddr)` owns one cancellable worker/reactor.
  `start_with_mapping_nonce(SocketAddr, [u8; 12])` is an optional protected
  persistence seam; zero nonce is rejected. Default start uses OS randomness.
  `snapshot()` uses `try_lock` and returns no candidates on contention/staleness.
  `cancel`, nonblocking `drain`, and `remaining_owners` mirror hosted lifecycle.
- Snapshot: `state`, `validity_seconds`, `candidates()`, and
  `remaining_validity_seconds()`. At most LAN + two same-adapter global IPv6 +
  one mapped external candidate. Debug contains counts/states, not addresses.
- States: Discovering, LanOnly, MappedCandidate, Ipv6Candidate, PublicIpv4Candidate, Unavailable,
  Stopped. None means external TCP, paired TLS, Android delivery or UAC succeeded.

## Boundary decisions

- Windows-only safe `ipconfig=0.3.4` adapter API; actual routing-selected source
  must match exactly one up adapter. Do not prefer Ethernet/Wi-Fi over a VPN.
  Require exactly one on-link IPv4 gateway for mapping; ambiguous configuration
  remains a routing candidate only. IPv6 candidates come from the same adapter.
- PCP: fixed-size TCP MAP subset, OS-random 96-bit nonce, no THIRD_PARTY option;
  prefer internal port (7443 by default), accept a gateway-assigned public port.
  Validate exact source via connected UDP, nonce, opcode/version/result, protocol,
  internal port, response size and positive granted lifetime. Candidate policy
  requires a <=600s lease and global external address; a longer or nonpublic grant
  is retained as cleanup-only ownership, not discarded or advertised. Renewal
  preserves the server-scoped nonce/assigned endpoint; deletion carries exact
  nonce/TCP/internal-port ownership, with BOTH external suggestion fields zero.
  This is not a wildcard delete. Lost/unknown responses are not candidates.
- NAT-PMP: read-only public-address probe only. It lacks an ownership nonce or
  nonmutating existing-map query, so it cannot safely prove ownership for mutation.
- IGD production support is READ-ONLY discovery/address probing, not automatic
  UPnP mapping. Tightly scoped v2 WANIPConnection service, gateway-only SSDP,
  numeric IPv4 same-origin URLs, no DNS/proxy/redirect, capped HTTP bytes/headers/
  chunks, bounded XML node/depth counts, no DTD or external entities/schema fetch.
  Production sends only GetExternalIPAddress after descriptor retrieval. It does
  not advertise that address without a PCP-owned mapping. AddAny/readback fixture
  code is explicitly `cfg(test)` only. No production AddPortMapping/AddAny,
  DeletePortMapping, router-wide settings or permanent lease requests.
- All I/O is a maximum-three-second cancellable future, with finite PCP retry and
  capped retry backoff; snapshots refresh every 30 seconds. Cancellation does not
  detach sockets/tasks. Cleanup is one bounded nonce-owned PCP attempt on the
  still-matching route. Cleanup-only mappings remain owned for retries until a
  matching zero-lifetime acknowledgement or actual granted expiry. A changed
  route is never used to clean the old router. Final shutdown attempts cleanup
  once; a silent gateway can retain its actual granted mapping beyond shutdown.
- Conservative public-address classifier rejects private, CGNAT, loopback,
  documentation, multicast, link-local and selected transition/reserved blocks.

## ROOT decision and direct-connect limitations

ROOT chose read-only production IGD and rejected a same-host TOCTOU waiver.
Readback plus a second mutation is not atomic. Even initial AddAny allocation
with external port zero has wildcard/same-client ambiguity, so its production
mutation was removed before handoff to CI.
The official IGD2 service specification §2.5.17 (page 53) says AddAnyPortMapping
updates an existing entry based on internal client, external port and protocol;
description and internal port are not an ownership condition. A hostile same-PC
process can race between readback and update. Choosing another free port on a
different-host conflict does not close that same-host race. Therefore continuous
IGD port stability and strict unchanged-unknown-map guarantees cannot both be
claimed from this protocol. PCP is the only automatic mapping mechanism shipped.
The default PCP nonce is per owner; durable restart reuse needs ROOT-owned
protected persistence through `start_with_mapping_nonce` if required. Per-owner
PCP renewals keep the normal assigned port while the service runs. Routers without
PCP, IPv6 inbound reachability, or another surviving direct route may remain LAN
only. An offline/Doze phone cannot bootstrap after all cached endpoints expire
and no route survives. Dynamic public IP, CGNAT/double NAT, firewall policy and
gateway changes remain network limitations; no cloud fallback is introduced.
No actual phone off-LAN TCP/TLS/UAC proof was executed by this lane.

## Tests written, not executed

- Native loopback IPv4 PC + IPv6 phone registration and byte transfer through one
  embedded listener/room owner, bounded read deadlines.
- PCP request structure, nonce/protocol/port/size/finite-lease negatives; reserved
  address negatives; real loopback UDP fake gateway with wrong-source response;
  cancellation against a silent loopback gateway.
- IGD test-only exact ownership/lifetime negatives and real loopback HTTP fixture
  sequence for allocation + readback (not production mapping proof);
  SSRF/control-origin, redirect/framing/body/chunk
  boundaries; XML DTD/depth/duplicate/malformed input; silent HTTP cancellation.
- Snapshot redaction, lease expiry, nonblocking mutex contention, owner retention
  until thread finishes, invalid endpoint rejection and cancellation of backoff.

## Source inspection

- RFC 6887, PCP packet/ownership/lifetime rules:
  https://www.rfc-editor.org/rfc/rfc6887.html
- RFC 6886, NAT-PMP ownership limitation:
  https://www.rfc-editor.org/rfc/rfc6886.html
- Official WANIPConnection v2 §2.5.17, retrieved through indexed official text:
  https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
- `igd-next 0.17.1` `aio/tokio.rs`: discovery parses LOCATION and fetches device
  and schema before caller validation; its HTTP collectors are unbounded. This
  discovery API was rejected, not wrapped after the unsafe fetch.
  https://docs.rs/crate/igd-next/0.17.1/source/src/aio/tokio.rs
- Exact `ipconfig 0.3.4` adapter API and Windows gateway/prefix ownership source:
  https://docs.rs/crate/ipconfig/0.3.4/source/src/adapter.rs
- Existing locked `quick-xml 0.42.0` string-based event API inspected directly:
  https://docs.rs/crate/quick-xml/0.42.0/source/src/events/mod.rs

Dependencies added: socket2=0.6.5 and quick-xml=0.42.0 (already present in lock),
getrandom and sha2 workspace, Windows-only ipconfig=0.3.4. First-party code remains safe Rust.

## Security review corrections (source changes, not executed)

- RFC 6887 §15.1: lifetime-zero MAP sends zero suggested external port/address,
  retaining nonce, TCP and the nonzero internal port. A loopback fake gateway
  checks the exact deletion packet and a matching acknowledgement.
- §11.2: `start_with_mapping_nonce` now explicitly accepts a protected base seed;
  a domain-separated SHA-256 derivation binds the numeric PCP gateway/port and
  local mapping tuple. Different gateways get different wire nonces; retry and
  renewal on the same mapping preserve it. A two-loopback-gateway test captures
  distinct wire nonces and stable same-server reuse. This identifies a numeric
  PCP server, not an authenticated router identity.
- §15: a legal >600s reply retains its real granted lifetime/nonce as cleanup-only
  state. It is never a candidate, and is not described as expiring within 600s.
  Wrong/missing cleanup acknowledgement preserves the obligation while this
  owner remains alive. Route-displaced obligations are retained in a maximum-four
  queue, cleaned only if the corresponding route returns, and expire against the
  actual grant. At capacity, no more mappings are allocated. IPv6 candidate
  rotation alone does not change the IPv4 mapping path. A fake gateway grants 7200s, rejects the
  first cleanup acknowledgement, then confirms the second. Epoch-regressed and
  nonpublic successful responses also become cleanup-only.
- Public local IPv4 with no NAT mapping is `PublicIpv4Candidate`, including the
  no-PCP-gateway branch. This is an unverified route, not reachability proof.
  Read-only IGD/NAT-PMP public-address-to-port7443 guesses are not yet emitted;
  no UPnP mutation was restored.
- No validation commands were executed by this worker for these corrections.
