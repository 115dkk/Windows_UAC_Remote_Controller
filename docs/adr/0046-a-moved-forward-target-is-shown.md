<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0046: A router forward saved for another PC address is shown

Status: implemented source with unit coverage. The warning has not yet been
seen on a real PC whose address changed.

## Evidence

On 2026-10-05 the phone, switched to 5G on purpose, could not reach the PC.
The PC (adapter "Wi-Fi 2") had 192.168.219.102 and answered on
`192.168.219.102:7443` from the LAN, but its public address
`122.35.235.188:7443` did not answer even from the PC itself. The same router
had carried that hairpin on 2026-09-24, when the PC was 192.168.219.103 and the
forward TCP 7443 → .103 was set. Nothing held .103 any more (ARP Incomplete).
The router's DHCP reservation for the PC existed but was switched off, so the
PC moved to .102 on 2026-10-01 (ADR 0043) and the forward pointed at nobody.
After the user switched the reservation on and pointed the forward at .102, the
hairpin to `122.35.235.188:7443` succeeded at once.

The 외부 연결 tab showed the STUN address with the configured port as the
external candidate. Nothing on the PC or the phone could tell that the router
no longer forwarded to this PC, and the tab gave no hint that the PC's address
had changed since the forward was set.

## Decision

The stored router-forward line records the PC's LAN IPv4 at the moment the
mode is saved: `v1 forward <port> <ipv4>`. The old line `v1 forward <port>`
still decodes, with no recorded address; the running service then records the
current LAN IPv4 once it is known. An older service reads the new line as
invalid and runs Automatic, which is the existing rule for unusable content
and does not stop it.

`ExternalStatus` carries the recorded address next to the current LAN address.
When the mode is router forward and the two differ, the tab opens with a
warning naming both addresses, with only the differing digits in bold, and two
steps: point the router's forward at the current IP, and check that the DHCP
reservation is switched on. Its button saves the same port again, which makes
the service record the current address and closes the warning.

The comparison is between two observations of this PC. It does not claim that
the router forwards anywhere in particular: the forward may already have been
corrected before the button is pressed, and a forward pointing at the wrong
host while the address never changed is not detected. A hairpin self-test was
rejected for now: success would prove the forward, but failure proves nothing
on a router without hairpin NAT.
