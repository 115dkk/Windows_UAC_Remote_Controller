# Development handoff — 2026-09-10

This inventory prevents duplicate implementation. It is not a readiness claim.
Verified implementation baseline: `7b9df1fd3901f5dc2fbca4312d640b8fe5520b2b` on
`codex/native-runtime`. This document separates that baseline, installed native
experiments and unmerged protocol experiments. New edits require new ROOT checks.

## Latest evidence — September 10 evening

- `7b9df1f` Windows/Linux full Rust quality and Android Rust-core jobs passed in
  [Quality34461333180](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34461333180).
  The overall run failed its normal Tamarin job. Actual APK and Windows package
  runs also passed; this does not establish remote approval or native startup.
- `ServiceSession` now composes the existing registry, decision engine, original
  PC key, clock and bounded authenticated peer ownership. Do not build a second
  coordinator. The real Windows request producer, low-privilege carrier boundary,
  first-pairing caller and target-bound OS application are still missing.
- Consumer wording/activation UI is implemented and ROOT reviewed the final
  Windows/Linux 47-case,73-image galleries plus eight Android shared-renderer
  cases. Original screenshots are published in
  [issue1](https://github.com/115dkk/Windows_UAC_Remote_Controller/issues/1#issuecomment-5616495027).
  Renderer/client evidence is not real boot, phone authentication or UAC evidence.
- Real user-approved native installation of `7b9df1f` failed at the first
  `NCryptOpenStorageProvider` call with `0x80090030`; SCM recorded `0xE6070030`.
  An ordinary medium-user provider-open/close succeeded on the same machine.
  A fresh native service restart reproduced the failure.
- The separate `645991e` startup-order experiment moved the provider operation
  after acknowledged SCM `SERVICE_RUNNING` with no accepted controls. Its real
  installation at21:02KST still failed at the same provider operation. These
  experimental binaries are currently installed, with previous real-copy backups;
  the branch is **not merged**. No TPM/key reset, key deletion, service SID/ACL
  relaxation, UAC/Secure Desktop or antivirus change was made.
- Daybreak Blue proposed a separate fixed-function SYSTEM provider diagnostic to
  distinguish restricted-token effects from LocalSystem context. ROOT requested
  explicit user permission, which the user granted. Source preparation is in
  progress; the diagnostic service has not been created or executed. The error
  alone does not prove TPM failure or an access-denied cause.
- Isolated protocol `65664b8`
  [CI34475391432](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34475391432)
  proved four helpers plus the unchanged revocation property together in19.26s.
  Its eight other original obligations and both request canaries were unselected.
  Earlier one-property diagnostics proved five other request-safety properties,
  but witnesses and required canaries remain incomplete in the normal gate.
  Integration of same-invocation helper checks is under development, not a pass.

## Reuse these owners; do not build alternatives

| Responsibility | Existing implementation | Missing reachable integration |
| --- | --- | --- |
| Approval state and one-shot decisions | `approval-core::ApprovalEngine`; `approval-protocol::SignedDecision` | Actual Windows prompt capture/dispatch owner and target-bound OS application |
| Encrypted framing/carrier | `secure-channel`, `framed-transport::PeerTransport`/`SocketDriver`, `relay-service::connect_rendezvous` | Windows low-privilege carrier/service boundary and deployed cross-device provisioning |
| PC identity and registration | `windows-identity::PcIdentityKey`; `windows-service-host::ServiceRegistry` and `ServiceSession` | Resolve native provider initialization; protected real enrollment caller, carrier and prompt/OS integration |
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

Those next slices, `ServiceSession` and G010 consumer wording/presentation, are
now implemented and validated at the scoped7b9df1f baseline above. They do not
create a production listener, QR ceremony or Windows prompt producer.

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

The latest user approval window ends22:00KST on2026-09-10; earlier times are
superseded and the one-time reminder was deleted. The user explicitly authorized
the separate one-time SYSTEM diagnostic install/run/remove experiment. Execution
still follows ROOT review and actual build checks. Local screen access remains
unavailable; CI galleries and supplied images are the visual evidence paths.
C/E cleanup waits until actual prerelease publication, not just a
draft/build. Preserve source, keys, user data and sufficient release/evidence
artifacts. Low disk space is not permission to delete them early.

ROOT remains the only validation executor. Child work is source authoring or
static review, not proof. Preserve the last preauthorized reset credit until the
user's remaining-usage threshold is met; an available credit is not itself
permission to consume it early.
