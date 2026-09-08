# ADR-0003: Separate peer transport, PC events and phone decisions

Status: implementing, 2026-09-09; native enrollment/transport owners are not yet
connected. This decision does not close the outstanding pairing/UAC gates.

Use TLS 1.3 with mutually pinned P-256 raw public keys over an untrusted byte
relay. Disable 0-RTT, session tickets and resumption in the first version. The
transport key is not an approval key; a successful handshake is not Android
per-request authentication. Native TPM/Keystore ownership and enrollment are
separate integration requirements. A relay's public web certificate never
substitutes for the paired endpoint identity.

Keep the privileged service's event signature across the forwarding boundary.
`service-protocol` carries original full request bindings and PC lifecycle/clock
events with a distinct signing domain. `approval-protocol` continues to carry
phone approval/denial signatures, verified by `approval-core` against its live
request/registry. An attacker controlling a relay cannot manufacture either
authority from delivery status, route IDs or UI booleans.

No generic signing/input/execution operation is added to a local management
endpoint. Real native outcomes must be observed before emitting corresponding
Resolved events. Pending QR candidates cannot be committed merely because they
know a QR secret or return an attestation chain.

The phone maps service deadlines conservatively from a fresh signed clock probe,
using the phone's send-time monotonic anchor. Re-receiving a request does not
restart its lifetime; existing request/suppression mappings are retained. The
Windows owner always enforces its own actual monotonic deadline independently.

The normal user desktop cannot be assumed confidential against unelevated local
malware. The precise trusted pairing display/confirmation and fresh-UAC proof
remain gated in FEASIBILITY.md. An encrypted channel with preinstalled fixture
keys is useful test evidence, but not proof of QR enrollment or the product.
