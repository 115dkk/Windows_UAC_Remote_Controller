<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Tamarin connection and request-authorization contracts

Status: **authored_unverified**. Neither model has been parsed or proved by its author. ROOT owns Tamarin 1.12 execution, CI integration, counterexample inspection and the final evidence. Expected verdicts below are acceptance criteria, not recorded results.

Tamarin was selected for this slice's mutable registration and one-shot state. This is not a universal ranking over Verifpal/ProVerif or a claim that a symbolic proof verifies the product. The intended tool version is the official [Tamarin 1.12 release](https://github.com/tamarin-prover/tamarin-prover/releases/tag/1.12.0); binary provenance/checksums are ROOT-owned.

## What the models mean

Both models use an active Dolev-Yao attacker through ordinary `In`/`Out`. There is no assumed authenticated private channel, fairness restriction, uniqueness restriction, or restriction asserting the desired security properties. The sole `Equality` restriction implements the explicit equality/decryption/signature checks in the rules, following the [1.12 restriction semantics](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/007_property-specification.md#restrictions).

### PinnedTransport.spthy

Seven rules model a pinned authenticated-channel contract. `CreatePc` creates one PC key; repeated trusted phone enrollments under that PC reuse the **same PC key**. Every flight passes through the attacker. ClientHello supplies a fresh session nonce and ephemeral DH share, but no client certificate identity. The server transcript binds its PC key, that session context and both DH shares; it does **not** bind a phone public key, routing pair ID or separate PC selector before the client has supplied its certificate.

After checking the PC pin, server signature and Finished confirmation, the phone signs a role-separated client transcript containing the server transcript and its own public key. The PC checks the presented phone key against the selected enrolled pin at this client-proof stage, verifies that signature and client confirmation, then sends the key-confirmed ready message. Only after matching that confirmation does the phone release the encrypted application secret.

Routing selectors are public outside the cryptographic transcripts/KDF and authentication events. The attacker may relabel them and forward flights across different enrolled routes sharing a PC key. The model does not obtain stronger pair-ID/channel binding than the implementation supplies: the early phone authentication claim is that the pinned PC offered the same **server transcript**, not that the PC had already authenticated that phone. Full client-identity agreement is checked only at the PC's completed client-proof event.

The same four lemmas concern an executable honest exchange, early phone agreement on the pinned PC's server transcript, PC agreement on the pinned phone's full client transcript, and secrecy of the released application secret. Peer authentication is non-injective session/transcript agreement, not authentication of routing metadata, availability or user approval. Symbolic DH, signatures, encryption and hashing use standard [Tamarin message theories](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/004_cryptographic-messages.md).

This is **not exact TLS 1.3 wire modeling**: transcript encoding, HKDF/key schedules, record-layer AEAD/nonces, raw-public-key extensions, cipher-suite negotiation, malformed group elements, Rustls implementation and native callbacks are abstracted. No long-term/ephemeral key-reveal rule is supplied, so forward secrecy or post-compromise security is not claimed. Pins and private-key ownership are trusted initial enrollment premises, not facts proved merely by generating fresh symbolic keys.

### RequestAuthorization.spthy

Fifteen rules separate `CreatePc` from repeated trusted device enrollment, allowing multiple approvers under the **same PC**. Each device has linear `CurrentRegistry`/`RetiredRegistry` state. A request's `Building(pc, binding)` phase captures immutable per-device `Snapshot` facts containing the exact current revision and purpose keys. Publish consumes Building and creates exactly one **global `Pending(pc, binding)`**. Every eligible device and both decision purposes must consume that same Pending; there is no per-device replay guard.

The short build/publish phase holds the PC's linear owner token, representing the existing engine's exclusive mutation scope: registry mutation/acceptance cannot interleave with snapshot collection. Snapshot capture is impossible after publication because Building no longer exists. Any nonempty subset of current devices can be captured, including the full registry; this includes actual full-registry enumerations but does not prove completeness of recipient enumeration or notification delivery. These are operational state rules, not restrictions assuming the security conclusions.

Accepting, cancelling or expiring consumes the global Pending. Revoking removes the current per-device registration; re-enrollment/replacement uses a fresh revision token, including when keys are unchanged. A new member or new revision cannot adopt a published request's older frozen eligibility. The at-most-once lemma quantifies **different devices, revisions and purposes**; a separate honest trace has two distinct eligible devices sign the same published request before one acceptance.

The complete public binding contains PC identity, PC epoch, Windows session ID, logon LUID, request ID, nonce, content digest and expiry token. The signed statement additionally carries device, protocol version, purpose and its separate approve/deny domain. **Bindings/nonces and signed decisions are public attacker-controlled traffic.** Approval requires a prior exact-binding trusted native authentication ticket consumed by its signer; denial uses its distinct key/domain without an approval-auth event.

Revision freshness abstracts the real allocator's no-reuse behavior, not u64 arithmetic or durable high-water recovery. Expiry is an explicit transition consuming Pending: no proof is claimed about real-time duration, timer scheduling, suspend or clock correction. Multiple devices per PC, independent PCs and arbitrarily many requests/sessions are allowed; numeric device/request capacity limits are not modeled. Actual fan-out transport, epoch restart, storage rollback, process crashes and restoration require separate tests/models. Freshness and linearity are operational facts, not a global restriction forcing each acceptance to be unique.

`UserAuthenticated` is the trusted native per-use authentication boundary being assumed, not a proof of Android CryptoObject/KeyInfo/attestation correctness. `TrustedEnrollment` likewise assumes the real owner-approved QR/attestation/PC receipt procedure, which remains separate unfinished native work. These premises match the intact-OS trust boundary; the excluded already-compromised SYSTEM/kernel case is not introduced as a blocker.

## Model-to-code mapping

| Model operation | Existing implementation boundary |
| --- | --- |
| Exact peer pin and role-bound transcript verification | `crates/secure-channel/src/config.rs`: `PinnedPeer::check_key`, `check_signature`; `src/identity.rs`: `CertificateVerifyInput`, `BoundSigningKey::sign` |
| Handshake/key confirmation and readiness gating | `crates/secure-channel/src/channel.rs`: `feed_tls`, `tick`, readiness handling; this model abstracts Rustls TLS details |
| Bounded/cancellable native socket ownership | `crates/framed-transport/src/socket.rs`: `SocketDriver`; deadlines, guard polling, partial IO and resource bounds are **not** established by the symbolic model |
| Native transport key callbacks | `crates/android-bindings/src/transport.rs`: opaque transport binding/CertificateVerify; `crates/windows-identity/src/lib.rs`: protected PC identity signing; native ownership is outside this proof |
| Full canonical statement and separate signature domains | `crates/approval-protocol/src/lib.rs`: `RequestBinding`, `UnsignedDecision::signing_bytes`, `SignedDecision::from_wire`/`verify` |
| Per-device registry revisions, frozen multi-device eligibility and global Pending | `crates/approval-core/src/lib.rs`: privileged enroll/replace/revoke; `open_from_privileged_host` clones the eligible registry inside one exclusive mutation; `submit_decision` consumes the single request regardless of winning device; cancel/expire |
| Persisted allocator history | `crates/approval-core/src/registry_checkpoint.rs` and `crates/windows-service-host/src/trust_registry.rs`; symbolic fresh revisions do not prove these codecs/filesystem commits |
| PC-origin original binding, content digest, issuance and expiry | `crates/service-protocol/src/message.rs`; this request model does not prove PC-event encoding/signature checking or clock correlation |
| Exact-binding per-use phone approval plan | `crates/android-controller/src/approval.rs` and native auth owner; `ApprovalTicket` abstracts this trusted boundary, not Android execution |

Tuple constructors and cryptography are symbolic; byte-width bounds, Unicode, strict DER/P-256 parsing, signature malleability, constant-time behavior, memory/resource safety, pairing UX, availability/DoS, notification/history effects and actual Windows application of a decision are not proved. The two models do not automatically constitute a composed end-to-end implementation proof.

## Lemmas and required ROOT verdicts

| Model | Lemma | Kind | Expected default verdict |
| --- | --- | --- | --- |
| PinnedTransport | `honest_channel_trace` | exists-trace | verified: an honest trace exists |
| PinnedTransport | `phone_pins_authenticated_pc` | all-traces | verified: an honest pinned PC offered the same server transcript, without an early client-identity claim |
| PinnedTransport | `pc_pins_authenticated_phone` | all-traces | verified: full client transcript including the pinned phone key |
| PinnedTransport | `application_secret_confidential` | all-traces | verified |
| RequestAuthorization | `honest_approve_trace` | exists-trace | verified |
| RequestAuthorization | `honest_deny_without_approval_auth_trace` | exists-trace | verified, with no same-binding approval-auth event |
| RequestAuthorization | `honest_two_approvers_single_winner_trace` | exists-trace | verified, two distinct captured devices sign the same publication and only one accepts |
| RequestAuthorization | `accepted_approval_requires_same_binding_auth` | all-traces | verified |
| RequestAuthorization | `accepted_decision_matches_opened_request` | all-traces | verified |
| RequestAuthorization | `request_accepted_at_most_once` | all-traces | verified across different devices, revisions and purposes |
| RequestAuthorization | `no_accept_after_revision_revoked` | all-traces | verified |
| RequestAuthorization | `no_accept_after_request_cancelled` | all-traces | verified |
| RequestAuthorization | `no_accept_after_request_expired` | all-traces | verified |

ROOT commands from repository root:

```text
tamarin-prover security/tamarin/PinnedTransport.spthy --quit-on-warning --prove
tamarin-prover security/tamarin/RequestAuthorization.spthy --quit-on-warning --prove
```

Use the exact selected 1.12 executable and ROOT's bounded process/CI timeout. The documented CLI supports `--prove=lemma_name`; `--quit-on-warning` prevents ignoring model well-formedness warnings. See the [1.12 command-line manual](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/003_example.md#running-tamarin-on-the-command-line).

ROOT must require every listed lemma's actual completed verdict, not just process exit zero or a log substring from another model. A parse error, warning, timeout, unfinished proof or missing lemma is not success. Preserve exact source/artifact identity and prover output. No proof filters, assumed source lemmas or hand-written `by sorry` proofs are supplied.

## Required negative controls: exact single-fragment mutations

Make each mutant as a separate generated copy of the **current secure source** under ROOT's artifact directory. Do not edit the committed production models. Require exactly one occurrence of the complete OLD fragment/marker span, replace that one span, require the old span absent, and compare against that exact single-edit result. The replacement text need not be globally unique: `Pending(pc, binding)` already legitimately appears elsewhere. Match complete old fragments, not marker-name prefixes shared with a `_DISABLED` marker. Apply only one mutation per mutant; keep all other bytes/rules/restrictions/lemmas unchanged and record both source hashes and the diff.

### PC pin omission

In `PinnedTransport.spthy`, replace exactly:

```text
Eq(presented_pc_key, pinned_pc_key), // CANARY_PC_PIN
```

with:

```text
Eq(presented_pc_key, presented_pc_key), // CANARY_PC_PIN_DISABLED
```

Run the generated `PinnedTransport.no-pc-pin.spthy`:

```text
tamarin-prover PinnedTransport.no-pc-pin.spthy --quit-on-warning --prove=phone_pins_authenticated_pc --prove=application_secret_confidential
```

Both selected lemmas must be **falsified with a counterexample**, not merely fail to finish. Expected attack: substitute an attacker-owned PC signing key and DH share, sign/confirm the forged transcript, produce the ready confirmation using the attacker-known DH key, then learn the encrypted application secret. The remaining signature/Finished checks still execute; an already-authenticated channel was never assumed.

### Approval signature-check omission

In `RequestAuthorization.spthy`, replace exactly:

```text
Eq(verify(signature, approval_message, approval_key), true), // CANARY_APPROVAL_SIGNATURE
```

with:

```text
Eq('unchecked-signature', 'unchecked-signature'), // CANARY_APPROVAL_SIGNATURE_DISABLED
```

```text
tamarin-prover RequestAuthorization.no-approval-signature.spthy --quit-on-warning --prove=accepted_approval_requires_same_binding_auth
```

The selected lemma must be **falsified**: observe the public opened binding and inject a forged approval/signature without any matching UserAuthenticated event. No secret nonce or encrypted channel is needed for this attack.

### Consumed-Pending replay-guard omission

In `RequestAuthorization.spthy`, replace exactly the comment:

```text
// CANARY_REPLAY_GUARD
```

with:

```text
, Pending(pc, binding)
```

```text
tamarin-prover RequestAuthorization.retain-pending.spthy --quit-on-warning --prove=request_accepted_at_most_once
```

The selected lemma must be **falsified**: obtain one genuine request-bound approval, then replay that same public decision after the first acceptance. Alternatively, two already-eligible devices can both be accepted when this shared guard is wrongly retained. Signature verification remains enabled. The mutation really preserves the global linear Pending; it does not inject a fake violation event or change the cross-device at-most-once lemma.

The canaries test the model/runner's sensitivity to the specified missing mechanisms. They are not vulnerabilities asserted in the secure product. If ROOT's real prover cannot produce the required positive and negative verdicts, keep this work unverified and inspect the model/trace rather than weakening the lemmas or silently skipping a control.
