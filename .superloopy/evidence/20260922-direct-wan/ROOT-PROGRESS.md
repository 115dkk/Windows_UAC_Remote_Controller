# Root direct-WAN execution checkpoint

Baseline8be9af9; implementation19acfd6; current pushed product3391008. Metadata
1.3.0-alpha.1; no new tag/release yet. User excludes cloud relay/quota. PCP and
public local IPv4/IPv6 are candidates, not observed Internet success. UPnP and
NATPMP production operations are read-only. Existing pins/keys/auth remain.

USB03:59/04:02KST: one authorized physical phone, alpha.2/versionCode1002000,
promoted/READY/activationON, callback reset count2, Dozing. No authentication or
UAC canary attempted. One-shot04:00 heartbeat4-usb paused after root check.
Computer Use skill forbids security-app automation; V3 was not automated despite
user's app-specific allowance request. No global firewall/router/VPN change.
Earlier address-only probes and null Windows UPnP COM collection do not prove
V3 denial or permanent router non-support; no live mapping created.

Security D1-D5 fixes re-reviewed: query cadence, pre-sign pairing fallback,
PCP zero-suggestion deletion, gateway-scoped nonce and long-grant ownership.
Only reviewed hashes of config.rs/channel.rs/peer_runtime.rs were rebound;
proof models and negative controls unchanged. First CI failed AR bidi controls
and2collapsible-if warnings, corrected3391008. Subsequent CI found missing closed
COMPOSITE_ROUTING_CANDIDATES label and unused already-checked CommitReceipt;
root fixes are local pending integration. No gate weakened.

Exact3391008 runs: Quality35644278826 (failed jobs), Android35644279055,
minified35644278795, lifecycle35644278777, Windows35644278838,
Windowslab35644279400, gallery35644278818, notifications35644278980,
i18n35644278971, attestation35644279089. Fresh statuses required. Duplicate PR
runs cancelled, not counted as success. CandidateAPK35644175508 is not release.

Fresh architecture A1 approved in architecture-approval.md: private ownership
module shared by poll/shutdown; agent direct_final_architecture implementing.
Root owns CI/native QA. Subsequent exact-source gates, artifact review,
publication and physical Internet/authentication acceptance remain incomplete.
