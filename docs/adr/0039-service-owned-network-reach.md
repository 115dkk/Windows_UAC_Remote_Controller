<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0039: The PC service owns its network reach

Status: implemented, 2026-09-26. Records the 1.5.x network boundary and the port
choice added with this record. Supersedes
the network sentences of ADR0018, ADR0027 §3, ADR0031 and ADR0038 named below;
each of those records now points here and keeps its text as history.

## Why this record exists

The earlier records were written at intermediate stages. Read alone, ADR0018 says
the service has no Internet listener or dialer, ADR0027 says it dials outward only
and needs an external relay address before pairing, ADR0031 says it makes no router
request and claims no NAT traversal, and ADR0038 says UPnP is read-only. None of
these describes the product. The service accepts the phone's connection itself,
asks the router for a mapping, learns its public address and hands the phone
signed routes. An external relay is an option, not a requirement.

## What the service owns

1. **Embedded relay listener.** One dual-stack TCP 7443 listener inside the
   installed service, started after full SCM readiness (ADR0031, ADR0038). The
   PC's own leg joins its room over loopback, so no NAT hairpin is needed. The
   installer adds one exact-program inbound rule for the private profile only.
   A failed start is retried after one second; it never fails TPM or service
   initialization.
2. **Dialers.** The same service dials the embedded or a configured external
   relay for the pairing stream and for one steady connection per enrolled
   device (ADR0027 §3). A fresh registration on an active route evicts the stale
   pair, so a phone that left Wi-Fi without a FIN is not locked out.
3. **External address.** `direct_network::ExternalAccess` has three modes,
   persisted as one canonical line in `trust/external-access.v1` (`v1 auto`,
   `v1 forward <port>`, `v1 fixed <ip:port>`). No file means automatic. Only the
   elevated helper (`external …`) or an elevated management client
   (`SetExternalAccess`) changes it; any local client may read it
   (`QueryExternal`). A change drains the gateway owner and starts a new one.
   - *Automatic*: a PCP lease, then UPnP IGD over SSDP answered by the gateway
     only (WANIPConnection:2, WANIPConnection:1, WANPPPConnection:1). The service
     **adds** a 600 s mapping to its own listener and renews it. An entry owned
     by another client or another internal port is never overwritten; another
     port from 20000..=60999 is tried instead, and cleanup deletes only an entry
     that still names this PC and port. This replaces ADR0038's rule that UPnP
     production operations are read-only (commit e074b9c). NAT-PMP is not used.
   - *RouterForward*: the user opened a port on the router. No router traffic.
     The public IPv4 comes from a STUN Binding request to two fixed servers
     (Google, then Cloudflare) sent from the selected adapter, refreshed every
     five minutes and kept for fifteen after the last answer.
   - *Fixed*: a global address the user typed, published as given.
4. **Routes to the phone.** Addresses reach the phone only as signed, nonce-bound
   advertisements over `wuac-control/2` (ADR0038), stored in the phone's routing
   book per association. The phone dials its candidates in parallel and keeps the
   first that completes pinned TLS.

Router discovery, PCP, IGD and STUN live in the `direct-network` crate.
`relay-service` stays a rendezvous carrier. Neither crate holds a key, the
registry or an approval capability; every candidate is a routing hint and every
use still needs a fresh mutually pinned connection.

## External port choice

The app recommends no fixed external port and no DMZ. In RouterForward the port
field starts empty. A button beside it fills the field with a port drawn
uniformly from 20000..=60999, and the user then edits the router and saves. The
draw is presentation only (`ui/src/externalAccess.ts`): the service validates
1..65535 as for any typed number and never learns that the number was drawn.
The range matches the one `igd.rs` draws from by convention; no constant is
shared, so the presentation stays out of the network crate.

Two reasons justify the button. Every PC's internal port is 7443, so two PCs in
one home need different external ports. And a random high port rarely collides
with a forward the household already has. It hides nothing: Internet-wide
scanners sweep every port, and the connection is protected by the pinned keys,
not by the number. Changing a saved number breaks the router rule and the
phone's stored route until the phone visits the home network again, so the UI
presents it as a one-time choice and warns when a port is already saved.

There is no check for whether the drawn port is in use on the PC. The external
port lives on the router; a forward from external N to PC:7443 does not touch
PC:N, so a program holding a local port (certificate plug-ins, for example) does
not conflict with it. The only real collision is another forwarding rule on the
router, and a router that answers neither PCP nor UPnP cannot be asked which
ports are taken.

DMZ is not suggested anywhere. A home router's DMZ host receives every
unsolicited inbound connection, which leaves Windows Firewall as the PC's only
barrier, usually under the private profile.

## Limits

No mode traverses carrier-grade or double NAT; there the UI names the private
upstream address and the external relay remains the answer. A mapping, a STUN
answer or a typed address is a candidate, not proof of reachability. On
hardware, a manual port forward carried an LTE phone to the PC and a UAC prompt
was approved from outside the home network (1.5.1 and 1.5.2; docs/PROGRESS.md,
9월 24일 section).
Automatic PCP or UPnP mapping has not been observed on a physical router in this
project's records, because the test router offers neither.
