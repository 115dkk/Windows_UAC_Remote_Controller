<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0053: The pairing comparison code is committed before it is revealed

Status: implemented source. Codec, loopback ceremony and software-phone tests
ran on the development PC; the Windows UAC lab pairs the CI software phone on
the new protocol. Not observed with a real phone, over USB, or on the protected
desktop.

## Evidence

A security review of 1.13.0 (2026-11-19, finding F4) read the pairing ceremony
and found that every input of the six-digit comparison code was known or chosen
before the code was shown:

- The code was `SHA-256(domain || frozen body) mod 1,000,000`. The frozen body
  held only values from the invitation, the phone's key digest and
  `intended_registry_revision`, which the PC chooses and the phone never
  constrains.
- In USB mode the invitation, which carries the PC key pins, leaves the service
  through a medium-integrity starter and an unauthenticated accessory transfer.
  Code running as the signed-in user can replace it.
- With a replaced invitation the victim phone pins the attacker's key. The
  attacker lets its own phone complete a ceremony with the real PC, reads the
  code shown there, and has its fake PC try revisions until the victim phone
  shows the same six digits (about a million hashes; the phone waits 120 s).
  The person then confirms a match and the attacker's phone is enrolled.

A QR invitation is drawn on the protected desktop and cannot be replaced this
way, but one ceremony serves both modes.

## Decision

1. The phone draws 32 random bytes before it builds its submission and sends
   only their commitment: `SHA-256(".../pairing-sas-commitment/v1" || ceremony
   nonce || invitation context || phone key digest || reveal)`. The submission
   is version 2 and carries the commitment after the invitation context.
2. The PC draws 32 fresh random bytes only after it has received and verified
   that submission, and signs frozen candidate version 2, whose body ends with
   its random value and the phone's commitment. The signing domain is
   `.../candidate-frozen/v2`.
3. The phone verifies the signature against the pinned key and that the body
   carries its own commitment, then sends `PairingReveal` (nonce, key digest,
   digest of the exact signed candidate, the 32 bytes) inside TLS. It shows no
   code before that message has been written.
4. The PC shows no code, and accepts no confirmation, before a reveal that
   opens the commitment has arrived. It waits 10 s for it. A wrong, missing or
   out-of-order reveal fails the ceremony; the service keeps running.
5. The code is `SHA-256(".../pairing-sas/v2" || frozen body || reveal) mod
   1,000,000`. It cannot be computed through the shared library without the
   reveal.
6. Version 1 submissions and frozen candidates are refused. There is one
   ceremony for QR and USB.

Neither side can choose its contribution after seeing the other's: the phone is
bound by its commitment before the PC's random value exists, and the PC has
signed before the phone reveals. A fake PC must sign before it learns the
victim's reveal, and the attacker's phone must commit before the real PC's
random value exists, so the two displayed codes agree with probability about
one in a million per ceremony the person starts.

## Protocol model

Pairing enters the Tamarin models as the trusted `TrustedEnrollment` rule and is
not a proved property (security/tamarin/README.md). No bound source file holds
this exchange, and no theorem, rule or expected verdict changed.

## Consequences

- A 1.13 phone cannot pair with a newer PC, and a newer phone cannot pair with
  a 1.13 PC: the submission is refused. Phones that are already paired keep
  working. Update both before pairing.
- The Kotlin app and its exported interface are unchanged; the reveal happens
  inside the existing "waiting for the PC" phase.
- The ceremony has one more message and one more 10 s deadline.
- An independent read of the implementation found no ordering or binding
  defect and no better attack than the one-in-a-million guess. That read ran no
  code.
