# Windows direct-address integration

Status: source implementation/static review complete. Child executed no builds,
tests, lint, formatting, network, executable checks or native QA. ROOT owns CI,
artifact/native verification, security review and release.

## Native ownership and compatibility

- The service session owns the embedded HostedRelay and one DirectGatewayOwner.
  Router discovery starts only for the selected address while the owned listener
  is running, and runs on its bounded background owner, not the service worker.
- Source withdrawal cancels gateway discovery and retires current peer output
  guards. Mode replacement drains the gateway, old dialer and listener before
  configuring the replacement. Shutdown polls/drains/counts the discovery owner
  alongside the existing service I/O owners. Nothing is detached or force-killed.
- A listener without IPv6 support does not advertise IPv6 candidates or use an
  IPv6 primary. Gateway status/candidates are read without blocking discovery.
- Embedded DeviceDialer uses only127.0.0.1:7443 and current privileged-registry
  route IDs, regardless of retained historical advertised coordinates. External
  mode retains its exact configured-address filter. No route/key rows are reset.
- EnrollmentInputs retains `relay` as the canonical original invitation address
  and preserves the existing original-context/route/address equality checks.
  A trusted-owner-only `embedded_loopback` flag separately selects the fixed
  loopback dial target. Pairing invitation includes up to three currently fresh
  alternative candidates, excluding the canonical primary. This avoids PC-side
  NAT hairpinning without changing original invitation provenance or digest.

## Address response boundary

- Only a genuine peer Ready event supplies the negotiated protocol. Routing
  queries require V2, a drained clock response, live same-source ownership,
  current PC/device/route and registry tuple, and unexpired received-frame window.
- A five-second per-peer query interval and existing four-response queue bound
  signing/output work. Unexpected versions/kinds/contexts fail closed.
- The signer receives only internally built fixed AddressAdvertisementFields:
  current engine PC/epoch, peer device, matched route, query nonce and actual
  snapshot candidates/remaining validity. The service verifies its signature,
  rechecks identity, route/registry, candidate set and deadline before queueing.
- Existing retained PeerState outbound guards revoke queued/partial output on
  source/mode retirement. Empty/zero-TTL replies withdraw hints in external mode
  or when discovery has no fresh candidates. Address hints authorize no request,
  change no request lifetime and replace no immutable pairing descriptor.
- QueryDirect is read-only for the existing GUI class. DirectStatus contains only
  embedded/listening booleans and bounded state, no addresses or keys. A candidate
  state requires live listener and nonempty fresh supported candidates; it is
  not an externally measured connection result. Legacy Snapshot remains intact.

## Added test sources (unexecuted by child)

- Real loopback TCP/pinned TLS/framing fixtures exercise a correct query and
  independently verified signed withdrawal, wrong PC/device/route, stale registry
  route, absent clock exchange, query rate limit, and source retirement.
- A post-sign hook changes the registry route before publication and asserts no
  address reply enters the queue. It is a synthetic registry/software-key race
  fixture, not native isolation or hardware evidence.
- Dispatch V1 rejection is a labeled capability fixture; actual V1/V2 TLS
  negotiation compatibility is tested by secure-channel byte-pump test sources.
- Embedded route selection preserves historical coordinates and route IDs while
  dialing loopback; external filtering remains unchanged.
- Enrollment loopback selection leaves canonical invitation bytes/digest/address
  unchanged. GUI QueryDirect and mode withdrawal output-guard behavior are tested.

Unverified here: router mappings, WAN reachability, native dual-stack listening,
real Windows/Android reconnect, Secure Desktop UAC and phone per-use authentication.
The latter user-acceptance checks remain explicit release-note test items.
