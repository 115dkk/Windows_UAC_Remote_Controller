<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0038: Direct routing candidates remain separate from authority

Status: implementation candidate, 2026-09-22. Executable CI and physical outside-
network acceptance are separate evidence. Supersedes ADR0031's IPv4-only and
no-router-request restrictions only for the bounded direct-connect work below.

Superseded in part: UPnP IGD now adds and renews the service's own mapping, so
"UPnP/NAT-PMP production operations are read-only" holds only for NAT-PMP, which
is not used. See [ADR 0039](0039-service-owned-network-reach.md).

The user's direction excludes account-backed cloud relays and their quota cost.
The PC retains the embedded opaque relay. A single dual-stack listener shares
one room owner; its own PC leg uses loopback, not its externally advertised
address, avoiding a NAT-hairpin requirement. Original external-relay mode remains
explicit and does not silently turn into a cloud service.

The native gateway owner uses PCP finite mapping leases with a server-scoped
nonce, bounded discovery/retry/cleanup and exact internal TCP tuple. It retains
cleanup responsibility for unexpected long grants; a failed cleanup is not
reported as confirmed router deletion. IPv4/IPv6 public local addresses and
successful mappings are candidates, not proof of an Internet connection.
UPnP/NAT-PMP production operations are read-only: their examined mutation
interfaces do not provide the required atomic exclusion of unknown same-host
mappings. No other application's mapping or router-wide policy is changed.

Modern endpoints negotiate pinned TLS ALPN wuac-control/2 while preserving /1.
Only /2 carries bounded, domain-separated signed address advertisements tied to
the current PC/device/route, fresh query nonce and service epoch. Advertisements
never enter the approval inbox or extend request lifetime. Query freshness and
minimum query spacing are distinct. Previously learned coordinates may remain
as untrusted reconnect guesses, but every use needs a fresh pinned connection.

Android persists a separate bounded routing book keyed by association generation
in composite checkpoint v4. Existing authorization descriptors, keys and
revisions remain unchanged; prior snapshots migrate with an empty routing book.
Removal/re-enrollment cannot inherit old hints. V2 original invitations include
alternatives in their canonical digest; V1 bytes and decoding remain supported.
Initial candidate fallback stops before any native transport signing attempt or
authenticated readiness; confirmed/frozen enrollment is never restarted.

The UI distinguishes a local listener, a public coordinate candidate and an
actually connected device. It asks the user to verify the program named in a
firewall prompt, not disable the firewall or allow arbitrary programs. Optional
direct-status management reads preserve the legacy Snapshot format and have a
short separate deadline; unavailable extension data remains unknown.

No scheme here guarantees traversal of every upstream policy. Missing PCP,
unusable IPv6, private upstream mappings and fully lost address-discovery paths
can leave only LAN connectivity. Mapping success, STUN/ping, loopback fixtures
and emulator tests do not establish physical phone authentication or Windows
application. The existing pinned keys, per-use phone authentication, original
request binding, denial scope, replay checks and Windows protections stay intact.
