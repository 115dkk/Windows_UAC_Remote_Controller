<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0043: A phone finds its PC again on the local network by DNS-SD

Status: implementation candidate, 2026-10-01. The unit tests cover the naming,
the hint store and the dial order. Whether the phone finds the PC after a real
address change has to be checked on the devices; CI cannot show it.

## Evidence

On 2026-10-01 the phone had not reached the PC since the evening before. The PC
service (1.7.2) was running and listening on 7443. Its last diagnostics rows
were a UAC prompt at 2026-09-30 20:53 that ended `delivery_failed` because no
phone was connected. What had changed was the addresses. The home router's DHCP
had given the PC 192.168.219.102 and the phone 192.168.219.103, which had been
the PC's address when it was paired and when the router's port forward
(TCP 7443 → 192.168.219.103:7443, set 2026-09-24) was made.

- From the phone's shell, 192.168.219.102:7443 accepted a TCP connection and
  192.168.219.103:7443 was refused (it is the phone itself).
- The PC has no global IPv6 address, so it had no candidate besides the LAN
  address and the forwarded public address.
- Both stored candidates therefore led to the phone itself. The LAN address is
  its own; the public address is forwarded to it by the router.

The phone learns addresses in only two ways: from the pairing invitation, and
from a signed advertisement it asks for over a live connection (ADR 0038,
ADR 0039 §4). Nothing lets it learn an address while it cannot connect, so
after the change it could never connect again short of removing the PC and
pairing again. ADR 0031 already said "a changed LAN address can require
reconnect/re-pairing"; this record removes that requirement when the phone and
the PC share a network.

## Decision

1. **The PC announces itself.** While the embedded relay listener runs and its
   local endpoint is a private IPv4 address, the service registers one DNS-SD
   instance through the Windows DNS-SD API (`DnsServiceRegister`, crate
   `windows-dns-sd`). The service type is `_uacremote._tcp`, the port is the
   relay port, the SRV target is the computer's own DNS host name under
   `.local`, and there is one TXT entry, `v=1`. The Windows DNS Client answers
   the queries, so its own mDNS firewall rules apply and the installer adds no
   rule.

   The SRV target has to be the computer's host name. `DnsServiceRegister`
   publishes no A or AAAA record for any other host name, even when the
   instance carries an address: a registration with `<instance>.local` resolved
   to that host and port 7443 but no address on the development PC. For its
   own host name the DNS Client already answers A queries, and it answers with
   the address of the interface the query came in on. Asked from WSL through
   the host's virtual adapter, it answered 172.18.32.1, the address of that
   adapter, so a phone asking over Wi-Fi gets the Wi-Fi address. The
   registration follows the
   endpoint: a changed address replaces it, and a stopped listener withdraws
   it. A refused registration writes one `lan_announce_failed {code}` row and
   is retried a minute later.
2. **The name says which PC without saying who.** The instance label is
   `uacremote-` followed by 20 hex digits of
   SHA-256(`Windows-UAC-Remote-Controller/lan-instance/v1\0` ‖ PC identity)
   (`service_protocol::lan_instance_label`). A phone paired with several PCs
   computes each label and dials only the PC the label belongs to. The label
   does not contain the computer name. The SRV target does, but the DNS Client
   already answers for that name, so the announcement adds no new information
   about the PC.
3. **The phone looks while it is not connected.** The foreground service
   browses `_uacremote._tcp` with Android's `NsdManager` while some paired PC is
   not connected and the default network is Wi-Fi or Ethernet. It resolves only
   names of the label's shape and hands each result to native code
   (`lan_service_seen` / `lan_service_lost`).
4. **What it finds is a hint, not a route.** Native code keeps at most 8
   instances with at most 2 addresses each, only private IPv4 and IPv6 ULA
   addresses, for an hour, in memory only. A network change clears them.
   They never enter the routing book, which holds only signed advertisements.
   A new or changed hint ends the matching PC's backoff. The hint's addresses
   are dialled first, including by a recovery dial already in progress. After a
   connection is made, the ordinary signed advertisement replaces the routing
   book with the PC's current addresses.

## Security

A discovered address gets exactly the treatment of a stale stored one. The
phone opens a rendezvous there and needs a mutually pinned TLS handshake before
anything else happens. Anyone on the network can announce the label, and the
label is stable, so a device on the same network can:

- **learn that a paired PC is present.** Windows already answers for the PC's
  name, so this reveals only that the PC runs this program.
- **attract the phone's rendezvous registration by announcing a false address.**
  The registration carries the route identifier in plain text (ADR 0038). With
  it, a device can register on the real relay and end the phone's session.
  The same device could already do this whenever it held an address the phone
  had stored, and on a shared network it can disrupt the connection in simpler
  ways. It gains no approval, denial or request content.

The PC announces nothing when its endpoint is a public address, and the phone
does not browse on a cellular network.

## Limits

- The phone must be on the same network as the PC. Away from home, a changed
  LAN address still breaks the router's port forward, which only the person can
  fix on the router. The app's advice stays: give the PC a fixed DHCP
  assignment and point the forward at it.
- Networks that filter multicast between clients (guest Wi-Fi, some mesh
  systems, client isolation) stop DNS-SD. There the phone still has only its
  stored candidates.
- A PC whose DNS Client mDNS is disabled by policy cannot announce. The row
  `lan_announce_failed` says so.

## Related changes in the same release

- The phone's "refused" guidance no longer claims that the PC answered. A
  refusal at a stored address is just as likely to come from another device
  that now holds it.
- An install now removes every copy of the embedded relay firewall rule before
  adding one. Each install used to add another copy; the development PC had 25
  identical rules.
