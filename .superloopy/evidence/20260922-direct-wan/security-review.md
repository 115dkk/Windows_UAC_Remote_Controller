# Direct-WAN security and correctness audit

Date: 2026-09-22. Scope: full working-tree product delta against `8be9af9`,
including new untracked Rust/UI files. The reviewer read the gateway, protocol,
Android and Windows implementation receipts and the frontend contract/receipt
in `20260921T184406Z-direct-wan-firewall`, then inspected production source and
relevant test sources. This reviewer made no product edits, spawned no children,
ran no validation/device/network probes, read no credentials, and opened no
public ports. ROOT owns integration, CI, source hash updates and physical QA.

## Current verdict

No unresolved new high/medium authentication, signing-domain,
original-invitation, replay or request-lifetime bypass was found in the inspected
delta. Concrete availability/router-protocol findings D1–D5 were sent to ROOT,
corrected and re-reviewed as recorded below. Public-IPv4 status integration is
also corrected. This source-level candidate can proceed to ROOT's exact-commit
CI; no build, prover, artifact, router or physical-device result is asserted.
The shutdown cleanup edge was subsequently corrected by the A1 ownership module
and re-reviewed below. Source inspection and synthetic tests are not proof of
real off-LAN operation.

## Findings and required disposition

### D1 — valid short-TTL replies provoke peer disconnection (medium; fix required)

Android `peer_socket/addresses.rs::apply_routing_candidates` originally scheduled
refresh after `valid_for_seconds.max(1)`, while Windows
`peer_runtime/direct.rs::respond_addresses` retires a peer querying again within
five seconds. A legitimate empty withdrawal has TTL zero. A later ordinary
intake event at one to four seconds can trigger the phone's next query and cause
the PC to disconnect the authenticated peer. TTL one to four has the same bug.

Required: share the protocol's minimum request interval between both endpoints;
enforce it for withdrawal/short TTL without turning it into a freshness or
authorization extension. Test a valid signed withdrawal/short hint followed by
events at one to four seconds and a valid later refresh. ROOT is implementing
this integration correction; final source re-review remains below.

Source disposition: fixed and re-reviewed. The shared five-second minimum has
a one-second client margin, with `next_query_at` independent of signed
`fresh_until`. Withdrawal does not become fresh for six seconds. Expired pending
queries are retired before generating a new random nonce; a delayed old response
cannot answer the replacement query. New test source covers TTL zero through
four, early events, permitted later query and stale-response rejection. CI is
still required.

### D2 — initial pairing fallback stops at unauthenticated READY (availability limitation)

Established-association retries rotate candidate order even when an endpoint
returns READY and fails pinned TLS. Initial pairing does not: its
`connect_candidates` returns the first carrier, then `run_ceremony` sends the
candidate submission and runs one pinned TLS/candidate/confirmation exchange.
A hostile/stale first endpoint that returns READY can prevent reaching a valid
later alternative on every identical fresh pairing attempt. Pins still reject
the wrong peer; this is not an enrollment bypass.

Required disposition: either a separately reviewed bounded fresh-attempt
selection strategy, or explicitly accept/document that initial pairing fallback
covers unavailable carriers only. Do not replay an already frozen/confirmed
ceremony or loosen original invitation validation to implement fallback. A
simple TLS retry before any candidate exchange is not the current protocol:
CandidateSubmission precedes TLS and has native ownership obligations.

Source disposition: the Android owner implemented a narrowly bounded pre-sign
fallback and it was re-reviewed. At most four candidates share the original key
creation, invitation, plaintext submission and overall ceremony deadline; each
multi-candidate attempt has an eight-second bound. The atomic downward marker
is set at the very first entry to native `sign_certificate_verify`, before any
validation or provider invocation. Any later failure, including uncertain or
rejected signing, terminates the entire ceremony instead of trying another
endpoint. Failed futures drop their socket/driver/signer before the next attempt;
there is no detached asynchronous signer job. Successful selection exits at
authenticated Ready, before frozen-candidate/confirmation/acceptance processing.
No already frozen or confirmed enrollment is reset. The added host fixture
covers READY+EOF fallback and attempted-signature failure with no alternate
connection. This is not physical Android signing evidence.

### D3 — PCP deletion encodes nonzero suggested external fields (medium; fix required)

`Lease::release` passes the prior external endpoint to the generic request
encoder with lifetime zero; that encoder writes nonzero suggested port/address.
Required: zero those suggested fields for deletion while retaining the exact
nonce, client IP, TCP protocol and internal port. Add an independent wire test.
This remains a single owned mapping deletion, never an internal-port wildcard.
The normative deletion format is [RFC 6887 §15.1](https://www.rfc-editor.org/rfc/rfc6887.html#section-15.1).

Source disposition: fixed. The encoder ignores external suggestions at lifetime
zero. Cleanup requires a matching header/nonce/TCP/internal-port and zero-lifetime
ack before recording completion. An unconfirmed cleanup retains the live owned
lease for bounded retries; shutdown performs one final bounded attempt.

### D4 — same owner nonce is reused after a PCP server change (medium; fix required)

`direct::run` can replace its discovered gateway while retaining the original
owner nonce. Required: use server-scoped nonce ownership, preserving identical
nonce on retries/renewals to one server but changing it for a different server.
Test same-local-source gateway replacement and ensure old-router cleanup is not
sent through the replacement route. See [RFC 6887 §11.2](https://www.rfc-editor.org/rfc/rfc6887.html#section-11.2).

Source disposition: fixed for the discovered numeric-server identity. A private
random base seed is domain-separated with the gateway address/PCP port and local
tuple into a 96-bit wire nonce. The base seed is not transmitted. Same-server
retries preserve ownership; a different numeric server/local tuple derives a
different nonce. This is not cryptographic authentication of a router, and the
gateway/route checks still control where cleanup may be sent.

### D5 — rejected larger lease loses cleanup tracking (medium; disposition required)

The parser rejects a grant greater than the requested 600 seconds, and the caller
drops active ownership. Server grants can exceed the request. A rejected reply
therefore does not establish that no mapping exists or that it lasts at most
600 seconds. Required: retain a bounded cleanup obligation or attempt exact-nonce
cleanup for a structurally verified out-of-policy grant; never advertise it as
a valid candidate. Unknown/lost-response lifetime must stay explicitly unknown.
See [RFC 6887 §15](https://www.rfc-editor.org/rfc/rfc6887.html#section-15).

Source disposition: fixed. Structurally verified oversized or non-public grants
become cleanup-only leases with the returned expiry; they never enter candidate
publication. A wrong/missing deletion acknowledgement retains the obligation.
Uncertain renewal similarly stops advertisement and requests cleanup rather
than erasing the known lease. New UDP fixture source covers a 7200-second grant,
wrong acknowledgement followed by a matching acknowledgement, exact deletion
bytes, and distinct gateway nonces. These tests have not been executed by this
reviewer. Route loss and unanswered router operations still cannot establish
that a mapping vanished or lasted at most the requested interval.

Additional source review: route-displaced obligations are retained in a bounded
four-entry set and recovered only on the same IPv4 internal/gateway path. New
mapping creation stops at the cap. A restored matching obligation is selected
before creating another mapping; IPv6 candidate changes do not displace IPv4
ownership. Cancellation immediately after returning to a displaced path can
still skip that displaced cleanup because the current shutdown tail checks the
active lease only. ROOT was notified of the optional one-attempt cleanup
improvement; this does not authorize contacting an old gateway over another
route, and unconfirmed mapping disappearance remains explicitly unverified.

Final A1 disposition: corrected by `direct/obligations.rs`, reviewed at the
current `5063620` source. The same `select_path` transition now governs polling
and shutdown. It first retires an unmatched active path, restores only an exact
matching displaced obligation, and keeps restored grants cleanup-only. Shutdown
selects at most one current matching lease for one bounded cleanup attempt;
absent/mismatched/expired paths select none. Candidate publication occurs after
the ordinary poll transition, so a restored obligation cannot briefly reappear
as a candidate. Maximum ownership count four, actual granted expiry, retry
backoff, failed-cleanup retention, nonce checks and read-only IGD/NAT-PMP remain
unchanged. Pure transition tests cover restoration immediately before shutdown;
the synthetic Lease constructor is `cfg(test)` only. No validation was executed
by the reviewer.

### Integration note — public IPv4 candidate

The gateway correction added `PublicIpv4Candidate` for a routing-selected public
IPv4 address that needs no PCP mapping. ROOT was notified to handle this new
variant in Windows `direct_status`, including the case where the only candidate
equals the primary address. It must project to a neutral candidate only when its
fresh supported endpoint exists, not infer measured Internet reachability.

Final source disposition: Windows now handles the new variant explicitly and
requires a nonempty `current_direct_candidates()` result before projecting
`Candidate`. An empty/stale result projects `Discovering`. The public primary
case is no longer mislabeled LAN-only; no measured-reachability claim is added.

## Preserved boundaries found in source

- TLS still requires TLS 1.3, exact enrolled raw public-key pins, role-bound
  CertificateVerify and encrypted readiness; no resumption, tickets, early data,
  key logging or secret extraction was enabled. V2 is preferred and V1 retained;
  negotiated capability is unavailable before genuine Ready.
- Address advertisements use a separate fixed magic/version/signature domain,
  bounded candidate count/DER/TTL and canonical numeric endpoint shapes. They
  cannot decode as an approval decision or replace per-use authentication.
- Windows accepts address queries only from the actual V2-ready, clock-served
  peer, with the original peer Arc, live registry revision/keys, PC/device/route,
  bounded frame age, query rate and output queue. The signer receives an
  internally built fixed statement, not arbitrary caller bytes. Identity,
  registry/route, candidate set and deadline are rechecked after signing. Existing
  output guards retire queued/partial responses on source/mode withdrawal.
- Android requires its exact socket/owner/association generation, independent
  pending random nonce, route/device/PC, correlated PC boot epoch, enrolled
  application signature and bounded suspend-inclusive query age. It consumes
  the nonce before mutation. Failed checks abort the socket; no renderer action
  or public generic signing/network interface was added.
- Composite checkpoint v4 separates locator hints from unchanged association
  descriptors and keys. Legacy versions have explicit decoding; malformed v4
  does not fall back to legacy. The candidate book is bounded and exact-generation
  scoped. Removal prunes it; replacement cannot inherit delayed old-generation
  writes. Reboot restores numeric guesses, not TTL, trust, request or clock state.
- Steady-state dialing tries a bounded sequential list, drops failed/timed-out
  carriers, rotates starts across later attempts, keeps one admitted peer per
  association and retains network cancellation checks inside owner admission.
  Each candidate must establish fresh pinned TLS; stale saved addresses are not
  reachability/authentication evidence. It does not repeat biometric decisions.
- Original V1 invitation bytes/digest remain unchanged when no alternatives
  exist. V2 binds the complete ordered suffix under its separate original-context
  digest. PC loopback is a separate trusted-owner transport choice: canonical
  invitation address, route, digest, candidate matching, confirmation and signed
  acceptance checks are retained. Android caches alternatives only after actual
  enrollment commit and preserves post-commit warning semantics.
- The dual-stack listener feeds one existing bounded rendezvous room owner.
  IPv4 fallback is explicit; unsupported IPv6 is not advertised. Discovery owns
  one cancellable worker. Routing-selected source and a unique up adapter/on-link
  gateway are required; no deliberate Wi-Fi selection or VPN bypass was added.
- Production PCP is fixed TCP MAP with finite requests and no THIRD_PARTY option.
  Responses are received from the connected selected gateway and checked for
  shape/nonce/protocol/port/global endpoint. Read-only NAT-PMP and IGD do not map
  or delete ports. IGD URLs remain numeric gateway-only/same-origin, without DNS,
  proxies, redirects or credential interfaces. HTTP/XML work has explicit byte,
  header, chunk, node, depth and deadline bounds; DTD/external references are not
  interpreted. Mapping mutations in IGD fixtures are `cfg(test)` only.
- QueryDirect is a separate optional read-only GUI request. Its closed enum has
  no endpoint/secret payload. Old Snapshot/query bytes are unchanged, and failure
  of the optional read does not discard an independently valid old-service
  snapshot. Mutating management verbs still require the elevated client class.
- UI output distinguishes discovering/LAN-only/candidate/unavailable/stopped/
  unknown, withdraws candidate styling on stale reads, and explicitly asks for
  a mobile-network test. A live LAN peer is not promoted to WAN proof. Firewall
  guidance names only the product service; it adds no security-app control API.

## Tamarin source-binding review

Exactly three existing manifest-bound files changed against `8be9af9`:

1. `crates/secure-channel/src/config.rs`
2. `crates/secure-channel/src/channel.rs`
3. `crates/windows-service-host/src/peer_runtime.rs`

ROOT may update their exact final-source hashes after corrections. This reviewer
did not modify the manifest or calculate substitute proof results. The first two
files extend ALPN capability without changing pinning, signature or Ready
requirements. The third adds a disjoint routing exchange and listener lifecycle
ownership; existing approval signature validation, frozen eligibility, global
one-shot consumption, request origin and lease/deadline transitions are unchanged.

Original symbolic assumptions remain aligned for peer pins and request
authorization. The models do not establish address-query freshness, checkpoint
refinement, PCP ownership, native isolation, endpoint availability or physical
UAC application. No rule, theorem, expected verdict, negative control or trusted
authentication premise may be weakened to accommodate this work. ROOT must run
the complete exact-source prover and negative controls in CI.

## Evidence limits and acceptance work

### Final incremental source review

The management status integration retains one verified-pipe connection attempt.
The optional direct-status call waits 350 ms after the preceding ordinary
snapshot to accommodate the existing 250 ms listener rearm, then uses a separate
one-second exchange budget. Normal management operations retain their original
30-second budget. This is not a retry around identity/ACL denial or uncertain
cleanup. The Windows adapter still preserves the ordinary snapshot when the
optional read fails or is unsupported. The one-second budget bounds the
exchange, not a guaranteed total completion bound for native cancellation/drain;
the existing cleanup obligation is not skipped. Source inspection cannot prove
that every real service scheduling delay fits the settling margin.

The `_committed` binding retains the already checked receipt from the same
fallible durable commit; it neither swallows an error nor skips persistence.
`COMPOSITE_ROUTING_CANDIDATES` adds one closed diagnostic category matching the
native error enum, not arbitrary error text or a new authority channel. Removing
the two Arabic bidirectional control characters preserves executable names and
permission guidance, and changes no application gate. CONTEXT/ADR additions
describe the ownership boundary and evidence limits without asserting measured
WAN/authentication success.

ROOT reported the `3391008` measurement APK and UI-gallery lanes passed while
quality failures motivated these source corrections. This reviewer did not run
or independently validate those jobs/artifacts. Fresh exact-commit quality,
protocol and native/device evidence remains ROOT-owned; earlier lane results
are not promoted to a passing final gate for `5063620`.

PCP-capable router behavior, native IPv6/firewall reachability, dynamic public-IP
and gateway changes, off-LAN Android reconnect, Doze/reboot and actual phone
authentication/UAC application remain unverified. An unreachable private address
cannot become publicly reachable through retries alone. No account/quota/cloud
dependency was added, but CGNAT/double NAT/no PCP/no reachable IPv6 and loss of all
saved coordinates remain real direct-network limitations.

ROOT must review actual CI artifacts, signed installers/APKs, native connection
and controlled authentication/apply timing. Synthetic TLS/socket/UDP fixtures
and client screenshots cannot substitute for that evidence. V3/firewall security
software interaction remains user-operated; automatic security-app control is
outside the computer-use permission boundary even when requested. No such
interaction was performed in this audit.
