<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Tamarin connection and request-authorization contracts

Status: **verification_in_progress**. ROOT's first supported-tool CI (`187bdc0`) proved the four channel lemmas and exposed both required PC-pin-omission counterexamples. The request model timed out; a later runner shutdown prevented full artifact upload. This is not a passing full protocol gate. Model authors do not run verification; ROOT owns execution, counterexample inspection and final evidence. Expected verdicts below remain acceptance criteria.

Tamarin was selected for this slice's mutable registration and one-shot state. This is not a universal ranking over Verifpal/ProVerif or a claim that a symbolic proof verifies the product. The intended tool version is the official [Tamarin 1.12 release](https://github.com/tamarin-prover/tamarin-prover/releases/tag/1.12.0); binary provenance/checksums are ROOT-owned.

CI pins both Tamarin1.12.0 and its supported Maude3.5.1 distribution by SHA-256,
including Maude's sibling prelude/modules. Every positive lemma now runs in its
own bounded process (120 seconds, 2GiB GHC heap, bounded streamed transcript).
All13 positive lemmas and all3 broken-model controls remain mandatory. A timeout,
heap/output limit, missing tool or incomplete result fails; limits never become
proof bounds. Partial summaries start/retain passed:false and logs are written
during execution. The request model's `heuristic: i` changes search ranking only,
as documented for stateful protocols; its effectiveness is not assumed.

## What the models mean

Both models use an active Dolev-Yao attacker through ordinary `In`/`Out`. There is no assumed authenticated private channel, fairness restriction, uniqueness restriction, or restriction asserting the desired security properties. The sole `Equality` restriction implements the explicit equality/decryption/signature checks in the rules, following the [1.12 restriction semantics](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/007_property-specification.md#restrictions).

### PinnedTransport.spthy

Seven rules model a pinned authenticated-channel contract. `CreatePc` creates one PC key; repeated trusted phone enrollments under that PC reuse the **same PC key**. Every flight passes through the attacker. ClientHello supplies a fresh session nonce and ephemeral DH share, but no client certificate identity. The server transcript binds its PC key, that session context and both DH shares; it does **not** bind a phone public key, routing pair ID or separate PC selector before the client has supplied its certificate.

After checking the PC pin, server signature and Finished confirmation, the phone signs a role-separated client transcript containing the server transcript and its own public key. The PC checks the presented phone key against the selected enrolled pin at this client-proof stage, verifies that signature and client confirmation, then sends the key-confirmed ready message. Only after matching that confirmation does the phone release the encrypted application secret.

Routing selectors are public outside the cryptographic transcripts/KDF and authentication events. The attacker may relabel them and forward flights across different enrolled routes sharing a PC key. The model does not obtain stronger pair-ID/channel binding than the implementation supplies: the early phone authentication claim is that the pinned PC offered the same **server transcript**, not that the PC had already authenticated that phone. Full client-identity agreement is checked only at the PC's completed client-proof event.

The same four lemmas concern an executable honest exchange, early phone agreement on the pinned PC's server transcript, PC agreement on the pinned phone's full client transcript, and secrecy of the released application secret. Peer authentication is non-injective session/transcript agreement, not authentication of routing metadata, availability or user approval. Symbolic DH, signatures, encryption and hashing use standard [Tamarin message theories](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/004_cryptographic-messages.md).

This is **not exact TLS 1.3 wire modeling**: transcript encoding, HKDF/key schedules, record-layer AEAD/nonces, raw-public-key extensions, cipher-suite negotiation, malformed group elements, Rustls implementation and native callbacks are abstracted. No long-term/ephemeral key-reveal rule is supplied, so forward secrecy or post-compromise security is not claimed. Pins and private-key ownership are trusted initial enrollment premises, not facts proved merely by generating fresh symbolic keys.

### RequestAuthorization.spthy

Fifteen rules separate `CreatePc` from repeated trusted device enrollment, allowing multiple approvers under the **same PC**. Each device has one linear `RegistrySlot(revision, pc, device, 'active'/'retired')`, while its unchanged public purpose keys reside in persistent `EnrollmentKeys`. A request's `RequestSlot(request_id, pc, binding, 'building')` phase captures immutable per-device `Snapshot` facts containing the exact current revision and purpose keys. Publish changes that slot to `'pending'`. Every eligible device and both decision purposes must consume the same **global pending request slot**; there is no per-device replay guard. The phase alternatives here are notation only: every rule uses one exact quoted phase constant, never a free phase variable.

There is deliberately **no global `PcAvailable` owner token**. Enrollment requires the already-existing persistent HostContext instead. Registry changes and other requests may interleave between snapshot captures, so this model overapproximates the Rust owner's atomic collection/serialization and admits more adversarial schedules. Each capture still requires that device's linear active registration; capture remains impossible after publication because the request slot is no longer `'building'`. The existing serial full-registry enumerations remain possible, alongside nonempty subsets and additional interleavings. Neither atomic collection nor completeness of notification delivery is proved by this abstraction.

Removing the global token retains former traces while adding behavior. A completed proof of the same six all-traces request-safety lemmas would therefore not weaken their conclusions. The three exists-trace lemmas demonstrate non-vacuity of the enlarged model, not automatically the realizability of every witness in the real serialized owner. ROOT must inspect actual prover witnesses. That earlier token-removal step added no restriction, derived fact, assumed lemma, session bound or signature/authentication change. The separate immutable-provenance representation below preserves this already-enlarged model's traces.

#### Immutable provenance without new trust assumptions

`EnrollmentKeys(pc, device, approval_key, denial_key)` is produced **only by the existing TrustedEnrollment rule**, from the same fresh keys already placed in PhoneKeys and public output. RegistrySlot retains revision/PC/device and its exact phase; capture, acceptance and same-key re-enrollment/replacement join the immutable keys when needed. The frozen Snapshot still carries the complete keys, revision and binding. This is not persistent membership: revocation still removes the active phase, and the surviving key fact cannot authorize an acceptance without that exact active revision and global pending request slot.

`RequestOrigin(request_id, pc, binding)` is produced **only by OpenActualRequest**, alongside the building request slot, with the same existing fresh request ID already in the binding. It is a redundant premise on capture, publication, both acceptance rules, cancellation and expiry. Every corresponding old Building/Pending/Snapshot already descends from that same open, and the additional fact is never consumed. It does not replace the request slot or Snapshot, publish binding data early, or allow capture after publication. UserAuthenticatesExactApproval and both signing rules remain unchanged and receive the same attacker-controlled public traffic; no origin predicate filters their inputs. The ID index and premise priorities are explained separately below.

The earlier immutable-provenance step's intended trace-equivalence is to the **current overapproximating model**, not a new implementation proof: after undoing the subsequent origin-index and phase encodings below, reattach the unique EnrollmentKeys tuple to each three-field current/retired fact to recover the former five-field state; erase the two original derived persistent fact kinds. Conversely, every old enrollment/open can produce those facts, and their new premises were already implied by the old reachable states. The original theory already keeps each fresh device's keys unchanged across revisions; splitting them out does not introduce key rotation or prove arbitrary same-device key replacement. All nine lemmas, action facts, public messages, signature checks and canary marker spans are retained. No sources/reuse axiom, assumed conclusion, trace restriction or device/session bound was added.

This representation aims to expose a short source for immutable keys and request bindings instead of reconstructing them through repeated mutable-state transitions. Persistent-fact guidance is in the [Tamarin 1.12 rule manual](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/005_protocol-specification-rules.md#linear-versus-persistent-facts). The equivalence argument is static; convergence and all positive/negative proof verdicts remain ROOT-owned validation, not results claimed by this edit.

#### One tag per linear state: an intended bijection

This representation-only step retains the already-overapproximating rules and traces. Its inverse on reachable states is:

| New linear fact | Previous linear fact |
| --- | --- |
| `RegistrySlot(revision, pc, device, 'active')` | `CurrentRegistry(pc, device, revision)` |
| `RegistrySlot(revision, pc, device, 'retired')` | `RetiredRegistry(pc, device, revision)` |
| `RequestSlot(request_id, pc, binding, 'building')` | `Building(pc, binding)` |
| `RequestSlot(request_id, pc, binding, 'pending')` | `Pending(pc, binding)` |

The added request first argument is redundant: it is uniquely the existing fifth component of the binding created by OpenActualRequest, not a second identifier or an attacker-supplied equality assumption. Open uses its existing `Fr(~request_id)`; every later consumer binds `request_id` from that same linear slot. Capture carries the identical slot, publication changes only its phase, and accept/cancel/expire consume its pending phase. Undoing the representation erases that redundant first argument; conversely it can be recovered from each old reachable binding. That phase-only step left `RequestOrigin`, `EnrollmentKeys` and the FULL `Snapshot` unchanged; the later origin-index step below preserves their existing provenance.

The registry first term is likewise the existing fresh revision. Initial enrollment/re-enrollment/replacement use their existing `Fr` revision; reads/captures/acceptance consume and reproduce that exact active slot. Revocation changes only active to retired; re-enrollment consumes the old retired slot and creates a new fresh revision. That phase-only step added no freshness source, restriction, lemma/induction/priority annotation, trust check or phone-input filter. All15 rules and all9 lemma headers/formulas remain the obligations of the same model.

The [Tamarin1.12 injective-fact detection](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/011_advanced-features.md#reasoning-about-exclusivity-facts-symbols-with-injective-instances) can derive exclusivity from the existing fresh-or-same-tag-consumed first term. This is a prover-derived optimization to expose, not an asserted uniqueness invariant or a promise of convergence. Uniqueness of a live slot is not itself a one-accept theorem: the replay mutant still consumes and restores that same global pending slot and must admit the real two-accept attack. ROOT must check inverse-erasure rule equivalence, unchanged lemmas and all ordinary positive/negative verdicts; no execution/result is claimed by this representation edit.

#### Indexed request origin only; revision-origin experiment withdrawn

`RequestOrigin(request_id, pc, binding)` now exposes the slot-ID join explicitly. Its sole producer still uses OpenActualRequest's existing `~request_id`, identical to RequestSlot's first term and the fifth binding component. Every already-existing RequestOrigin premise uses the same `request_id` variable as its RequestSlot. No new origin premise was added to phone authentication, signing or public-input rules.

The redundant `RevisionOrigin(revision, pc, device)` experiment has been removed: all three producer outputs and seven consumer premises, including their priority hints, are gone. The exact active/retired RegistrySlot checks remain. No new helper, rule, bound or abstraction replaces this metadata; full Snapshot and EnrollmentKeys, original slot phases and global pending consumption remain unchanged.

This rollback follows actual unsuccessful evidence, not a newly successful proof. ROOT reported that normal source `0c6e7ae` timed out on all nine request baselines and both request controls, including the authentication lemma that had previously completed. Its retained [diagnostic log](../../.superloopy/evidence/tamarin/0c6e7ae/diagnostic/DIAGNOSTIC_ONLY-tBDE4M/diagnostic.log) is58,239bytes and reports the selected honest lemma as **analysis incomplete (251 steps), 53.62s**; the earlier ROOT-observed diagnostic was15steps/about4s. OpenActualRequest/CaptureEligibleDevice case1/2/3 branching is visible, with three revision-origin creator alternatives. This motivates removing our redundant experiment, not a causal performance guarantee or a claim that the remaining model now converges.

The six existing RequestOrigin **input premises** retain `[+]`; its sole output and all other facts remain unannotated. The [pinned fact-annotation manual](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/manual/src/011_advanced-features.md#sec:fact-annotations) defines the retained hint as local heuristic priority, not a unification change. No `no_precomp`, theorem/assumption, trace restriction, bound, rule action or phone-input condition is introduced.

Erasing just RevisionOrigin facts and their seven annotations from `0c6e7ae` yields the intended current rules. On reachable states every registry slot already descends from the existing fresh-creation rules, so the removed provenance premise was redundant; no exact membership check was removed. The indexed RequestOrigin still joins the same request ID already fixed by its binding. Removing its ID argument and six annotations separately would recover the preceding request-origin representation. These are static correspondences for the **current overapproximating model**, not an implementation proof. ROOT must compare the precise erasure and unchanged all15 rules/all9 lemma headers/formulas, public messages, actions, FULL Snapshot, EnrollmentKeys and signing domains. Manifest/canary text remains untouched: the replay mutant restores the same global pending RequestSlot and must expose the real two-accept attack. Fresh normal verdicts are still required.

Accepting, cancelling or expiring consumes the global pending request slot. Revoking retires the current per-device registration; re-enrollment/replacement uses a fresh revision token, including when keys are unchanged. A new member or new revision cannot adopt a published request's older frozen eligibility. The at-most-once lemma quantifies **different devices, revisions and purposes**; a separate honest trace has two distinct eligible devices sign the same published request before one acceptance.

The complete public binding contains PC identity, PC epoch, Windows session ID, logon LUID, request ID, nonce, content digest and expiry token. The signed statement additionally carries device, protocol version, purpose and its separate approve/deny domain. **Bindings/nonces and signed decisions are public attacker-controlled traffic.** Approval requires a prior exact-binding trusted native authentication ticket consumed by its signer; denial uses its distinct key/domain without an approval-auth event.

Revision freshness abstracts the real allocator's no-reuse behavior, not u64 arithmetic or durable high-water recovery. Expiry is an explicit transition consuming Pending: no proof is claimed about real-time duration, timer scheduling, suspend or clock correction. Multiple devices per PC, independent PCs and arbitrarily many requests are allowed; each modeled PC has one fixed initial epoch/session/logon context. Numeric device/request capacity limits are not modeled. Actual same-PC session changes, fan-out transport, epoch restart, storage rollback, process crashes and restoration require separate tests/models. Freshness and linearity are operational facts, not a global restriction forcing each acceptance to be unique.

`UserAuthenticated` is the trusted native per-use authentication boundary being assumed, not a proof of Android CryptoObject/KeyInfo/attestation correctness. `TrustedEnrollment` likewise assumes the real owner-approved QR/attestation/PC receipt procedure, which remains separate unfinished native work. These premises match the intact-OS trust boundary; the excluded already-compromised SYSTEM/kernel case is not introduced as a blocker.

## Model-to-code mapping

| Model operation | Existing implementation boundary |
| --- | --- |
| Exact peer pin and role-bound transcript verification | `crates/secure-channel/src/config.rs`: `PinnedPeer::check_key`, `check_signature`; `src/identity.rs`: `CertificateVerifyInput`, `BoundSigningKey::sign` |
| Handshake/key confirmation and readiness gating | `crates/secure-channel/src/channel.rs`: `feed_tls`, `tick`, readiness handling; this model abstracts Rustls TLS details |
| Bounded/cancellable native socket ownership | `crates/framed-transport/src/socket.rs`: `SocketDriver`; deadlines, guard polling, partial IO and resource bounds are **not** established by the symbolic model |
| Native transport key callbacks | `crates/android-bindings/src/transport.rs`: opaque transport binding/CertificateVerify; `crates/windows-identity/src/lib.rs`: protected PC identity signing; native ownership is outside this proof |
| Full canonical statement and separate signature domains | `crates/approval-protocol/src/lib.rs`: `RequestBinding`, `UnsignedDecision::signing_bytes`, `SignedDecision::from_wire`/`verify` |
| Per-device registry revisions, frozen multi-device eligibility and global Pending | `crates/approval-core/src/lib.rs`: privileged enroll/replace/revoke; `open_from_privileged_host` atomically clones eligibility (the model additionally allows interleaved collection); `submit_decision` consumes the single request regardless of winning device; cancel/expire |
| Persisted allocator history | `crates/approval-core/src/registry_checkpoint.rs` and `crates/windows-service-host/src/trust_registry.rs`; symbolic fresh revisions do not prove these codecs/filesystem commits |
| PC-origin original binding, content digest, issuance and expiry | `crates/service-protocol/src/message.rs`; this request model does not prove PC-event encoding/signature checking or clock correlation |
| Exact-binding per-use phone approval plan | `crates/android-controller/src/approval.rs` and native auth owner; `ApprovalTicket` abstracts this trusted boundary, not Android execution |

Tuple constructors and cryptography are symbolic; byte-width bounds, Unicode, strict DER/P-256 parsing, signature malleability, constant-time behavior, memory/resource safety, pairing UX, availability/DoS, notification/history effects and actual Windows application of a decision are not proved. The two models do not automatically constitute a composed end-to-end implementation proof.

### Ordinary serial witness candidates for ROOT review

These are candidate rule sequences, **not executed/proved traces**. They require no interleaving that the actual exclusive PC owner forbids. `Capture(d)` means `CaptureEligibleDevice` for that current device; `Auth(d)`/`Sign(d)` mean the exact-binding authentication/signing rules. The binding and signatures are public after their Out rules, so the attacker can relay or replay them.

| Witness | Serial rule sequence |
| --- | --- |
| `honest_approve_trace` | CreatePc; TrustedEnrollment(d1); OpenActualRequest; Capture(d1); PublishRequest; Auth(d1); Sign(d1); AcceptApproval(d1) |
| `honest_deny_without_approval_auth_trace` | Same prefix through PublishRequest; SignDenialWithoutApprovalAuthentication(d1); AcceptDenial(d1), without an Auth event |
| `honest_two_approvers_single_winner_trace` | CreatePc; TrustedEnrollment(d1); TrustedEnrollment(d2), d1 != d2; OpenActualRequest; Capture(d1); Capture(d2); PublishRequest; Auth/Sign(d1); Auth/Sign(d2); AcceptApproval(d1). The ordinary global Pending is consumed; the second device cannot also accept. |
| Missing-signature canary | First sequence through PublishRequest; attacker injects the public binding plus an arbitrary forged approval signature; mutated AcceptApproval, with no Auth/Sign rule. |
| Retained-Pending canary | Honest approval sequence through its first AcceptApproval; attacker replays that already-public same decision; mutated AcceptApproval executes again because it restored the same global Pending. |

The unchanged PC-pin canary likewise needs only a serial phone session: CreatePc; TrustedEnrollment; PhoneStarts; attacker forges its own server-key/DH/confirmation flight; mutated PhoneChecksPinSignatureAndConfirmation; attacker supplies the matching ready confirmation; PhoneReleasesEncryptedApplicationSecret; attacker decrypts with the known forged-session key. Actual positive/counterexample verdicts and witness correspondence remain ROOT-owned gates.

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

ROOT must require every listed lemma's actual completed verdict, not just process exit zero or a log substring from another model. A parse error, warning, timeout, unfinished proof or missing lemma is not success. Preserve exact source/artifact identity and prover output. Normal invocations select each registered lemma separately; all are required by the aggregate gate. No assumed source lemmas or hand-written `by sorry` proofs are supplied in the production theories.

### Failure diagnostics are not proof evidence

The CI-only diagnostic helper is separate from the normal runner and its
artifacts. It admits a completed, failed normal result only after checking the
full planned run set and its current manifest/model/source bindings. It selects
at most one failed request baseline, never a replacement acceptance criterion.

The depth8 / heuristic `i` / stop-on-trace `NONE` invocation is limited to60seconds
and4MiB combined stdout/stderr. Without an output-file flag, Tamarin prints its
analyzed theory and proof-method skeleton into that bounded log. Cut leaves are
unproved; this is not a full dump of unresolved constraint systems or an actual
honest/attack witness. A timeout can still leave only partial output. Metadata is
always `eligibleAsProof:false`, even for an unexpectedly completed diagnostic.
The helper never rewrites a normal summary/model, reruns with increasing bounds,
or supplies its generated text as a production proof. The normal failed step
keeps CI red. The [pinned batch implementation](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/src/Main/Mode/Batch.hs)
and [proof-depth implementation](https://github.com/tamarin-prover/tamarin-prover/blob/1.12.0/lib/theory/src/Theory/Proof.hs)
define this output and cutoff behavior.

## Required negative controls: exact single-fragment mutations

Make each mutant as a separate generated copy of the **current secure source** under ROOT's artifact directory. Do not edit the committed production models. Require exactly one occurrence of the complete OLD fragment/marker span, replace that one span, require the old span absent, and compare against that exact single-edit result. The replacement text need not be globally unique: `RequestSlot(request_id, pc, binding, 'pending')` already legitimately appears elsewhere. Match complete old fragments, not marker-name prefixes shared with a `_DISABLED` marker. Apply only one mutation per mutant; keep all other bytes/rules/restrictions/lemmas unchanged and record both source hashes and the diff.

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
, RequestSlot(request_id, pc, binding, 'pending')
```

```text
tamarin-prover RequestAuthorization.retain-pending.spthy --quit-on-warning --prove=request_accepted_at_most_once
```

The selected lemma must be **falsified**: obtain one genuine request-bound approval, then replay that same public decision after the first acceptance. Alternatively, two already-eligible devices can both be accepted when this shared guard is wrongly retained. Signature verification remains enabled. The mutation restores the very same global pending RequestSlot, including its consumed `request_id`; it does not create a per-device slot, inject a fake violation event or change the cross-device at-most-once lemma.

The canaries test the model/runner's sensitivity to the specified missing mechanisms. They are not vulnerabilities asserted in the secure product. If ROOT's real prover cannot produce the required positive and negative verdicts, keep this work unverified and inspect the model/trace rather than weakening the lemmas or silently skipping a control.
