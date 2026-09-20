# ADR 0013: default-on service boot and symbolic protocol verification

Status: source implementation; ROOT hosted verification and native boot evidence
are separate. This does not complete the remote UAC product.

## Boot requirement

The user explicitly requires boot auto-start by default when either service is
started. Windows installation already configures AutoStart after protecting the
service object and data directories; a provisioning failure leaves it disabled.
Actual local installation/reboot has not been performed by the agent.

Android previously had only Application-on-launch initialization. It now declares
a default-enabled private Direct Boot-aware boot/update receiver and connected-
device foreground service for interaction with the PC over the network. The
framework-required normal network-state permission is declared; this does not
add location/Bluetooth/overlay/exact-alarm/battery exemption or change user network
settings. Foreground promotion and static notification precede native owner work.

Locked boot does not open credential-protected files, Rust state or key references.
Actual UserManager unlock observation permits initialization; a broadcast alone
does not. There is no secret migration to device-protected storage, startup Activity
or authentication prompt. Automatic boot/visible-app starts respect explicit
disable; explicit service start enables boot again. System force-stop and OS/OEM
background policies are not bypassed or represented as guaranteed uptime.

One Application owner remains. Startup read buffering is bounded; writes do not
turn into delayed successful mutations. A failed/closing owner is not replaced
until actual generated handle and key cleanup reports CLOSED. Service status copy
describes local preparation/settings availability, not unimplemented PC reception.
The APK's decoded merged manifest is checked in CI; that is not a reboot test.

## Protocol security tool

ROOT compared primary documentation for Verifpal, ProVerif and Tamarin. Tamarin
was selected for stateful registry/revocation/one-shot transitions and concurrent
protocol roles; this is a project-specific choice, not a universal tool ranking.

CI downloads the official1.12.0 Linux release and verifies its pinned SHA-256,
runs the real prover with quit-on-warning, and records exact immutable model
snapshots, hashes, proof verdicts and generated broken-model counterexamples.
Process exit0 alone is not success. Required missing, falsified or inconclusive
positive lemmas fail; broken pin/signature/replay controls must actually falsify
the targeted production properties. Non-vacuity requires honest executable traces,
including multiple approvers competing for one shared pending request.

The model-to-code files have reviewed LF-normalized source hashes; changes require
reviewing model alignment. Hash equality is NOT implementation refinement. The
channel model abstracts TLS details and native key storage. Enrollment, intact OS
and per-use hardware authentication remain explicit trusted assumptions, not
properties conjured by creating fresh model keys. Numeric timer guarantees,
storage rollback, runtime isolation, availability/DoS, actual QR ceremony, native
boot, real user authentication/UAC and measured4G latency remain separate gates.

No release workflow existed at this audit point; PR/main release integration is
still tracked in the full goal. The new protocol job runs for Quality PR/main and
the active feature branch; final release must not bypass it.

Primary references:

- https://developer.android.com/develop/background-work/services/fgs/service-types
- https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- https://developer.android.com/privacy-and-security/direct-boot
- https://tamarin-prover.com/manual/master/book/001_introduction.html
- https://tamarin-prover.com/manual/master/book/003_example.html
- https://github.com/tamarin-prover/tamarin-prover/releases/tag/1.12.0
- https://bblanche.gitlabpages.inria.fr/proverif/
- https://verifpal.com/
