# Android native direct-WAN implementation

Status: source implementation and test cases written; no child validation executed.
ROOT owns formatting, compilation, Rust Analyzer, lint, test, CI and artifact review.

## Implementation

- `android-controller/src/routing_candidates.rs`: bounded last-known numeric coordinates keyed by PC and exact local association generation. At most four alternative coordinates per association; canonical IPv4/IPv6, duplicate, scope, malformed and count checks. No key, receipt, TTL, authentication, freshness or reachability state is persisted here.
- `checkpoint.rs`: composite v4 adds a separately length-delimited candidate-book section. Legacy composite v1/v2/v3 and original policy-only migration paths remain explicit; v3 preserves original local-key/peer-ledger bytes and initializes no candidates. Malformed current versions do not fall back to legacy decoding. Maximum snapshot cap is unchanged.
- The association ledger holds the separate routing book, but `PeerAssociation` and `PeerAssociationDescriptor` do not change. Existing frozen socket/request descriptor equality, pins, revision and generation comparisons remain intact. Removal prunes the exact association's book entry; stale references cannot replace a new association's hints. Local owner updates use existing prevalidation and durable metadata-commit paths.
- `peer_socket/addresses.rs`: only negotiated `ControlProtocol::V2` sends the closed AddressQuery. An independently generated nonce is bound to current pinned TLS socket, healthy owner, immutable enrollment, device, route, current correlated PC boot epoch and native monotonic query age (10 seconds maximum). Received advertisements require the enrolled PC application signature and original socket context before commit. One pending exchange is retained; the nonce is consumed before any cache mutation. Socket/owner changes, wrong query context, expired age and replay reject the response. TTL only schedules refresh; it does not extend a request or authentication lifetime. TTL0/empty withdraws hints.
- `android-bindings/src/intake.rs`: the existing native background reactor/admission path applies verified routing events and initiates refreshes. No renderer or UniFFI generic network/signing surface is added; no ABI change is required.
- `connectivity.rs`: bounded sequential carrier fallback across original endpoint and up to four distinct alternatives (five seconds per coordinate when alternatives exist; the shipped single-endpoint timeout profile is retained otherwise). Each failed/timed-out future drops its socket. No parallel TLS or decision signing is introduced. Ordering rotates on subsequent dial attempts, including after a bad TLS peer sends READY, to avoid permanently preferring a stale candidate. Existing network-generation cancellation and post-admission token checks prevent old dials attaching; existing one-peer-per-association admission remains authoritative.
- `pairing/ceremony.rs`: new invitations use all invitation candidates for carrier fallback while retaining the original canonical invitation, pins, digest, candidate, confirmation and signed acceptance checks. Alternative coordinates are persisted only after accepted durable enrollment, using its exact resulting association reference. Storage failure is surfaced as the existing post-commit warning path, preserving actual enrollment outcome.

## Written test cases (not executed by child)

- Host durable-store restart with different phone boot retains coordinates while enrollment descriptor remains unchanged.
- Removal/re-enrollment rejects delayed old-generation coordinate mutation; empty withdrawal removes the book entry.
- Strict v3-to-v4 migration, current-format truncation/trailing bytes, foreign generation, duplicate addresses, invalid addresses, and unchanged maximum composite capacity with 32x4 IPv6 hints.
- Actual host localhost pinned TLS exchange with synthetic fixture keys: valid advertisement, wrong PC/device/route/nonce/boot epoch/signing key, old association callback, expired query, replayed signed response, and authenticated withdrawal.
- Restored coordinates do not produce request-show effects or create a live socket/clock/authentication context.
- Carrier fallback fixture exercises an unavailable primary and successful alternative; existing exact network cancellation tests remain present.

## Boundaries and remaining verification

- These test sources are not proof of Android Keystore, phone authentication, Doze behavior, public Internet reachability, NAT/firewall mapping or real UAC approval. ROOT/CI must compile and execute them.
- A stale coordinate can be tried after reboot or hint TTL expiry, but only a fresh pinned TLS session and existing current-context checks can admit useful work. No persisted address is authority.
- When every saved locator stops reaching the PC (for example, public IP change with no surviving path), the phone has no new discovery channel. No cloud relay, STUN, DNS/account service, VPN bypass or router-policy weakening was added.
- Existing native background/boot and credential-protected key lifecycle are unchanged.

## Static security review follow-up

- Query cadence now uses the shared server minimum (`ADDRESS_QUERY_MIN_INTERVAL_SECONDS = 5`) plus one second. `next_query_at` is independent of the actual advertised `fresh_until` TTL, including withdrawal and PC epoch changes. Expired outstanding queries are cleared after ten seconds; a later query receives a new independent random nonce, and a late old response fails the exact pending-context check.
- Initial pairing now falls back through the complete pinned TLS handshake, not just an unauthenticated READY carrier. Each candidate is bounded (eight seconds with alternatives, thirty seconds for the original single-endpoint path; at most four invitation candidates), retains the same original invitation/submission/generated keys, and drops the unsuccessful socket/signer before another attempt.
- A native-only per-attempt one-way fence is set before any CertificateVerify signer invocation. Once set, even an uncertain or rejected signature callback prevents another candidate attempt. Fallback stops at TLS Ready; frozen candidate, comparison confirmation and enrollment acceptance remain single-use afterward. No UniFFI ABI change.
- Additional unexecuted tests cover actual TTL0/1/2/3/4 advertisements with no query for the first five seconds, expired-query replacement rejecting the late prior reply, READY-impostor fallback to a genuine pinned endpoint, and a consumed/rejected signer callback preventing any connection to the next candidate. Loopback candidate injection is confined to the native Rust selector test seam; production candidates still originate from the canonical validated invitation.
