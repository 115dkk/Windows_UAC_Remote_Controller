<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0027: Prerelease enrollment carrier, service-owned relay dialer and protected pairing display

Status: accepted for implementation on 2026-09-11 (Claude root). Native and physical evidence are
separate and are not asserted by this ADR.

## Context

The codecs for the pairing invitation (ADR 0020), the frozen candidate and the enrollment acceptance
exist, the service owns a rendezvous with the Starter and the elevated Helper (ADR 0024), one private
preparation (ADR 0025) and a nonvisual renderer child on a private desktop (ADR 0026). The phone reads
the QR into an existing key-creation intent (C6). Nothing connects these owners: no QR is drawn, no
attestation evidence leaves the phone, no PC code enrolls a device, no side dials anything, and the
signed decision path ends in `AuthorizedButNotApplied`.

ADR 0018 kept every network dialer out of the LocalSystem service on the assumption that a separate
low-privilege carrier process would hand sockets to the service. That carrier does not exist, while the
service already terminates the pinned TLS and parses frames for any attached carrier. Building the
socket-handoff process now would delay a usable prerelease without removing parsing from the service.

## Decision

### 1. One enrollment stream, two phases
Pairing uses the existing relay rendezvous. The invitation carries the numeric relay address and a fresh
public 32-byte route. Both sides register on the relay with that route (PC as `Role::Pc`, phone as
`Role::Phone`).

Phase 1 (plaintext, exactly one message, phone to PC): `CandidateSubmission` with the ceremony nonce,
challenge, PC identity, recipient device, invitation context digest, the three phone SPKIs and their
three leaf-first attestation chains. The PC checks every original field against its own prepared
material, then verifies the chains with `android_attestation::verify_key_bundle` against the fixed
Google roots and a current `fetch_google_status` snapshot. Nothing in phase 1 is secret; a mismatch or
verification failure closes the stream and burns the attempt.

Phase 2 (inside the existing mutually pinned TLS on the same stream): the PC pins the phone transport
SPKI it just verified, the phone pins the PC transport key from the QR. The TLS client signature is the
possession proof for the transport key; attestation with the fresh challenge is the possession proof for
the approval and denial keys. Inside TLS: PC sends `SignedFrozenCandidate`; the phone matches it against
its own retained originals and shows the six-digit comparison code; the phone sends
`PairingConfirmation` after its user confirms; the PC waits for the phone confirmation AND for the
human confirmation on the protected renderer; only then it enrolls the device (registry revision),
signs `SignedEnrollmentAcceptance` and sends it; the phone commits the association. The ceremony
stream then closes. Steady-state connections are made afresh (section 3).

### 2. Protected display
The renderer child of ADR 0026 draws the QR, the comparison code and the two decision buttons on its
private desktop and switches the input desktop to it for the duration; it switches back on every exit
path. The human decision travels to the service on the existing authenticated renderer pipe as a fixed
frame. The QR text is public metadata; the desktop protects the decision, not the QR.

### 3. Service-owned relay dialer
The service dials the configured relay itself, outbound only, for two purposes: the enrollment stream
above and one steady-state connection per enrolled device (route stored with the device in the trust
registry). A steady-state carrier becomes `ServicePeerCarrier` and enters the existing `attach_carrier`
path unchanged. Bounded reconnect with backoff; no listener, no inbound port, no URL or DNS in v1.
This supersedes the "no dialer in the service" boundary of ADR 0018 for the prerelease. The remaining
protections are the memory-safe stack (tokio, rustls, bounded framing), pinned peers, fail-closed
parsing and the existing restricted service token. A future low-privilege carrier process may reclaim
this boundary without changing the wire.

### 4. Relay endpoint and app signer configuration
The relay endpoint is a protected service configuration written only by an elevated command
(`uac-service.exe relay <ip:port>`) and read by the service at startup and before each ceremony.
Without it, pairing reports "중계 서버 주소를 먼저 설정해 주세요". The Android app signer digest for the
attestation policy is a build-time input of the Windows service (`UAC_ANDROID_SIGNER_SHA256`, one or more
hex digests) recorded in the release manifest; it is never learned from a phone or a relay.

### 5. Phone side
`android-bindings` exports one ceremony object created from a read scan. It performs key creation,
submission, TLS upgrade, candidate matching, confirmation and commit on its own worker, exposes a
bounded status for the native Dialog and stores the relay address and route in the association. The
phone keeps one steady-state connection per association from its foreground service.

## Consequences

- Route squatting on the relay is a denial of service only; TLS pins reject any impostor.
- The relay learns connection metadata and timing; it never sees request contents or keys.
- Hosted CI runners have no TPM (probe run 34591263436). A compile-time feature
  `lab-software-identity` in `windows-identity` selects the Microsoft Software Key Storage Provider so the
  full service can run in a disposable CI lab. Release builds must not enable it; the packaging inspection
  rejects binaries built with it. It is not a runtime fallback and does not touch the user's PC.
- Physical acceptance (real phone hardware attestation, 4G, real UAC prompt) remains user evidence.
