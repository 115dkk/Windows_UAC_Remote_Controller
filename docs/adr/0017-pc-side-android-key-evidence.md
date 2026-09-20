# 0017 — PC-side Android key evidence and fixed rejection-list fetch

Status: accepted implementation boundary; native enrollment remains unwired.

## Decision

`android-attestation` is a safe Rust, PC-side prerequisite for protected device
registration. It verifies three separately generated P-256 public keys: approval,
denial and transport. It does not grant enrollment intent or Windows elevation.
`ServiceRegistry` enrollment/replacement consumes its privately constructed,
non-Clone result instead of shape-only public keys.

The protected ceremony owner supplies the unpredictable challenge, expected keys
and explicit release configuration. None may be learned as trusted defaults from
the renderer, relay, first phone or a debug signing certificate. There is no
production default release signer. The fixed application package, minimum app
version, signing-certificate digest set, OS and patch floors are checked against
the authenticated description. Approval needs per-operation hardware-backed
authentication; denial and transport must not require it. The three roles cannot
reuse a public key.

## Certificate boundary

Each leaf-first chain is bounded to eight certificates, 8 KiB per certificate and
32 KiB total. Original signed TBS bytes are checked using ring; DER/X.509 parsing
uses `der`/`x509-cert`. Duplicate extensions/certificates, unknown critical
extensions and unsupported algorithms/layouts reject. The only description must
be on the direct target key, so an appended application-created leaf cannot
replace the hardware-issued claim.

Release-owned Google RSA and P-384 roots are embedded. Candidate roots, the
system certificate store and first-seen trust are not alternatives. The accepted
profiles are the observed four-certificate factory chain under the RSA root and
five-certificate remotely provisioned chain. The narrow factory compatibility
rules accommodate expired factory issuers and the observed non-CA attester with
digital-signature-only usage; they do not apply to RKP or arbitrary layouts.
RKP issuer expiry bounds proof lifetime. Device-selected leaf dates do not prove
freshness. Positive serial magnitudes up to 32 bytes and signed Time choices are
preserved without replacing signed bytes with re-encoded data.

Both description hardware levels must agree under the selected project policy,
including factory paths. RKP's authenticated attester organization must also
match that level. Optional noncritical provisioning CBOR is position-checked but unused;
no manufacturer-validated entity, same-physical-phone or current-uncompromised
phone claim is made from it. Unsupported devices remain unsupported rather than
silently falling back to software keys.

Description version pairs are closed rather than inferred from numeric order.
The observed `(attestationVersion=3, keyMintVersion=41)` pair in Google's pinned
Sony/sdk33 fixture is an explicit compatibility case alongside published schema
pairs; it still undergoes all application, challenge, authentication and patch
policy checks.

## Authenticated rejection status

`verify_key_bundle` performs no I/O. The separate, no-argument
`fetch_google_status` may only GET the literal Google attestation-status HTTPS
endpoint. It is an explicitly accepted outbound network trust boundary, not a
generic fetch service. The client uses fixed WebPKI roots/ring, no ambient proxy,
redirects, caller trust settings or credentials. It accepts bounded complete JSON
only and rejects unavailable, malformed, compressed or stale responses.

HTTP freshness accounts for Date, Age, max-age and request time, with a total
24-hour ceiling before age subtraction. The original pre-fetch monotonic sample
anchors the deadline, including download and parse residence. Zero freshness,
clock rollback, replacement status identity and changed release policy invalidate
a pending proof. No serialized status restoration, empty-on-error or stale cache
fallback exists. A successful proof is additionally consumable for at most
30 seconds and no longer than the accepted RKP issuer interval.

DNS resolution has a separate single outstanding worker permit. A timed-out
system resolver call cannot be forcibly cancelled by safe Rust's standard API;
its worker retains the permit until the actual lookup returns. Further attempts
fail while it remains outstanding, and a late result is discarded. This bounds
resource accumulation, not a claim of resolver quiescence at caller timeout.

## Remaining enrollment obligations

The actual protected owner must still validate a live one-shot owner-approved QR
ceremony (fresh Windows consent after initial installation), the exact complete
bundle/challenge/device/PC binding, possession of each key, original deadline and
commit/receipt recovery. Key-property verification cannot replace any of these.
No QR, scanner, native consent adapter, network enrollment listener or service
capability flag is enabled by this library. Registry freshness checks happen at
the existing logical mutation point; durable publication has its own failure
contract.

## Evidence and limits

Tests use public certificate-only fixtures with retained upstream Apache-2.0
notices and clearly synthetic software-signed composition fixtures. Public
fixture validity instants are test-only; the production verifier always samples
the PC clock. The public API rejects the synthetic root. Those tests establish
parser/signature/policy behavior, not Android hardware, QR secrecy, phone
authentication, actual Windows UAC or live enrollment acceptance. ROOT alone
executes validation; child authors/reviewers do not.

Sources checked on 2026-09-10:

- [Android key-attestation verification and roots](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP attestation schema](https://source.android.com/docs/security/features/keystore/attestation)
- [Pinned Google public fixtures](https://github.com/android/keyattestation/tree/a48898a68337b920cbd368eab5824f696d7bbf3d/testdata)
- [HTTP freshness calculation](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3)

The exact project restrictions and compatibility exceptions above are project
policy; the linked sources are not evidence that this implementation passed.
