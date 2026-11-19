<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0054: The embedded relay limits what a known route can do

Status: implemented source. Unit tests with a paused clock and loopback TCP
tests ran on the development PC. Not observed against a real phone changing
networks, and not against a real attacker.

## Evidence

A security review of 1.13.0 (2026-11-19, findings F10 and F11) read the relay:

- A registration is 43 unencrypted bytes: magic, version, role, route. The
  route is created once at pairing, never changes, and is written at the start
  of every connection, including to addresses learned from unauthenticated
  DNS-SD hints.
- Any registration on a route with an active pair evicted that pair (ADR 0039's
  rule, which lets a phone that changed networks replace its dead pair at
  once). A same-role registration on a waiting route was refused as a
  duplicate.
- So whoever has seen one registration can, from any host that reaches port
  7443, keep a phone and its PC apart: evict the pair, then either wait as the
  phone (the PC pairs with it and fails pinned TLS) or wait as the PC (the real
  PC is refused and backs off for up to 60 s).
- No approval can be forged or read; both ends still require pinned TLS. Until
  the fixes of ADR 0052 a pair that ended at the wrong moment also stopped the
  service, which made this worse than a reconnect.
- The embedded relay runs inside the service, and the service's own dialer
  always registers as the PC from 127.0.0.1. Nothing else legitimately
  registers as a PC there.
- The relay discarded its counters, so abuse left no trace.

## Decision

1. The embedded relay accepts the PC role only from a loopback source
   (127.0.0.0/8, ::1 and their IPv4-mapped forms). Anything else is refused
   before it can evict a pair or occupy a waiting room. The standalone relay
   keeps accepting PCs from anywhere.
2. Eviction stays, with a cooldown per route. When a registration evicts a
   pair, the pair it then becomes part of is watched: if that pair ends, or is
   about to be evicted in turn, within 10 s, the route gets a strike. The first
   strike costs nothing. From the second consecutive strike, registrations that
   would evict an active pair on that route are refused for 30 s, doubling per
   further strike to 300 s. A pair that lives past 10 s clears the strikes.
   Registrations on a route with no active pair are never refused by this.
3. The first strike is free because a real phone on a poor connection produces
   that pattern: it changes network, its fresh pair dies at once, and it
   registers again. Refusing that would turn a one-second reconnect into thirty.
4. The relay counts evictions, duplicate refusals, refused PC sources and
   refused evictions. The service writes them to public diagnostics as
   `relay_abuse` when a counter has moved, at most once a minute, with no
   address and no route.

## Not decided here: authenticated registration

The cooldown bounds how often an unauthenticated registration can evict. It is
not a bound on total outage under sustained attack, and a party that only
occupies the waiting room as the phone is not affected by it. The fix that
removes the capability is a registration that proves possession of a key: the
relay sends a nonce and the phone answers with a signature the embedded relay
checks against the enrolled device, with a ratchet so a device that has used the
new form is never again admitted by the old one. That changes the relay wire
format, the phone's signing path and the trust registry, and it changes how a
phone reconnects, which this project has only ever got right by measuring on a
real phone (ADR 0039 and the reconnect work of September 2026). It is left to
its own change with hardware verification.

## Consequences

- A phone that changes network, loses the new connection within 10 s and tries
  again is admitted once more at once. A third such attempt in a row waits 30 s.
- A remote host can no longer pose as the PC at the embedded relay.
- Abuse of a route is visible in `diagnostics.jsonl`.
- With ADR 0052 an evicted pair costs a reconnect, not the service.
