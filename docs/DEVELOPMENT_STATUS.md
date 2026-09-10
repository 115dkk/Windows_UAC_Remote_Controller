# Development handoff — 2026-09-10

This inventory prevents duplicate implementation. It is not a readiness claim.
Verified implementation baseline: `a8cf6c4155deff4c2ed8ac8faea59f61b9ea595f` on
`codex/native-runtime`. Updates in the final section are work in progress until
ROOT records new exact-source validation.

## Reuse these owners; do not build alternatives

| Responsibility | Existing implementation | Missing reachable integration |
| --- | --- | --- |
| Approval state and one-shot decisions | `approval-core::ApprovalEngine`; `approval-protocol::SignedDecision` | Actual Windows prompt capture/dispatch owner and target-bound OS application |
| Encrypted framing/carrier | `secure-channel`, `framed-transport::PeerTransport`/`SocketDriver`, `relay-service::connect_rendezvous` | Windows low-privilege carrier/service boundary and deployed cross-device provisioning |
| PC identity and registration | `windows-identity::PcIdentityKey`; `windows-service-host::ServiceRegistry` | Same service-owned peer/clock/decision coordinator; protected real enrollment caller |
| Phone hardware-key adjudication | `android-attestation::verify_key_bundle`, fixed-origin status fetch, required `VerifiedKeyBundle` registry input | Production ceremony and app-signer policy; never replace with a trusted boolean |
| Enrollment confirmation | `service-protocol::pairing`; `android-controller::pairing::PendingPairingAcceptance` | Original real QR ceremony, PC receipt producer and native callers |
| Android persistence | One `MobileController`/`DurableInbox`, Preparing/CreatedUnverified commits, ABI9 one-shot native creation transaction and existing pending acceptance | Real ceremony/scanner must call the existing owner; no second journal/preference owner |
| Android native keys | One Application-owned `AndroidNativePlatform.keyStore`, ABI9 `create_local_key_set`, `DeviceKeyStore.createKeySet`, exact reopening/reference registry and original-clock admission | Real authorized ceremony caller; native generation alone is not enrollment |
| Android service and presentation | `ApplicationPolicyActor`, boot/foreground service, native intake and notification coordinators | Genuine first pairing/provisioning plus physical device acceptance |
| React/Tauri UI | Existing shared client, IBM Plex Sans KR, settings/request/history screens | Native pairing activation; the current pairing-unavailable state is intentional |

The earlier prerelease pairing map's proposed acceptance codec/phone commit
slice is now implemented. Do not implement it again. Its remaining original
ceremony/scanner/caller gaps still apply. Likewise, attestation and installer
payload packaging are present; older documents describing them as absent are
historical.

## Actual checks before the consumer-copy change

- Quality run34451023513: Windows full Rust/Analyzer/canaries14m8, Linux8m59,
  Android Rust target3m29 all passed. The whole run is RED only in its separate
  Tamarin job; ROOT collected native watch exit1.
- Android package34451023504: actual APK and Kotlin tests passed7m25.
- Windows package34451023482: installer build/passive payload checks passed11m32.
- UI gallery34439778443 at the unchanged a40ee3b client: both44 cases/65 captures, with actual custom font
  observations; ROOT reviewed representative original PNGs.
- Android notification renderer34451023577 passed5m11. This isolated renderer
  test is not physical phone approval/authentication or full production proof.
- Tamarin's pinned-channel properties and two request-binding properties passed;
  seven request baselines and two request negative controls timed out. The
  normal gate remains failed. No counterexample is asserted for secure source
  merely because proof search timed out.

## Current implementation assignments

1. Android key creation: connect the existing durable Preparing intent to the
   existing Application-owned native creator, then exact CreatedUnverified
   persistence and the existing pending acceptance. Narrow callback ABI9; no
   public raw Tauri create/sign API or fake original ceremony.
2. PC TLS signing: owned private-constructible Server CertificateVerify witness
   and a bounded intra-trusted-process bridge to the original thread-affine PC
   key. This does not implement low-privilege IPC or authorize enrollment.

Both slices are implemented and passed the exact a8cf6c4 quality/package CI above.
Static review corrected acceptance-time stop handling, explicit cleanup-retry
ownership and native generation admission after waits before that validation.
Do not implement either slice again. ROOT alone executes validation. The next
integration must retain one original clock/owner, current registry revisions,
bounded work and explicit fail-closed state. Native key generation does not mean
enrolled; an authorized decision does not mean Windows applied it; SCM Running
does not mean remote requests are ready.

Next slices (not yet validated): a Windows `ServiceSession` composes that same
registry/engine/key/clock with bounded authenticated peer ownership, and G010
reworks consumer-facing purpose/activation wording plus native notification
presentation. These do not create a production listener, a QR ceremony or a
Windows prompt producer.

The isolated formal branch proved `building_precedes_open` and its dependent
`request_opened_unique` together in baseline and both fixed negative-control
contexts (e237a73, run34457423427; 4.37s/4.30s/4.32s). These are helper proofs,
not the original security properties or the required counterexamples. The normal
security gate remains RED; no experimental branch has been merged into it.

## Remaining release blockers and execution boundaries

Real QR issuance/scan and first enrollment, Windows live prompt/peer/decision
composition, target-bound Secure Desktop application, credential-type feasibility,
required formal proofs, final security audit, fresh approved architecture pass,
release automation and native acceptance remain unfinished. No usable full-product
prerelease has been published.

No UAC experiment before19:00 KST on2026-09-10. At/after that time ask the user
before actual elevation; the clock alone is not approval. No local screen-access
workaround. C/E cleanup waits until actual prerelease publication, not just a
draft/build. Preserve source, keys, user data and sufficient release/evidence
artifacts. Low disk space is not permission to delete them early.

Current task quota is available. The app goal record still reports an older
`usageLimited` state; this document does not claim to reset/resume that scheduler
state. Continue explicit user-requested work without pretending background
implementation agents remain active after they finish.
