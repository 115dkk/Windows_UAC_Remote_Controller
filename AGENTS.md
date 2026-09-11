# Project instructions

## Scope and evidence

- Preserve the user's complete Windows/Android remote UAC approval objective.
- The user has authorized a credential-prompt feasibility branch: support entry
  from the phone when Windows-required credentials can be handled appropriately;
  otherwise ignore those credential prompt types. Do not replace Windows
  authentication with an application authentication result.
- Never disable or bypass Secure Desktop, UAC, LSA protection, or Windows policy.
- The user explicitly excludes an already-compromised SYSTEM/kernel from the
  threat model. Do not repeatedly treat that excluded case as a blocker.
  Defend against unelevated local malware, hostile networks/relays, unpaired
  devices, replay, tampering and authorization bypass under an intact OS.
- Pure-core tests are not evidence of Windows or Android end-to-end behavior.
- Only the root agent runs builds, tests, lint, executable checks, or device QA.
  Child agents may write tests and perform static source review, but must not run
  validation. This includes format/check commands.
- User steering on 2026-09-09 authorizes CI screenshot galleries when local
  screen approval is unavailable. Root downloads and visually reviews the actual
  CI artifacts. Browser/client screenshots must not stand in for native proof.
- The user will perform actual UAC approval and phone authentication acceptance
  later. Keep those cases explicitly unverified until results are supplied; do
  not block client CI on them or claim those deferred checks already passed.
- Assign non-overlapping files to workers. They share the tree: never revert
  another agent's or the user's changes.
- Child agents must not create children. The final, newly spawned architecture
  refactoring agent is the sole exception: after understanding the structure it
  may delegate implementation to children that cannot delegate further.
- After completed implementation, use a security reviewer for static audit and
  fixes, then a fresh agent with `improve-codebase-architecture`. Root validates.
- The user delegates the final architecture skill's approval/selection steps to
  the root agent, including overnight. The fresh refactoring agent must first
  deliver its candidate report and wait for ROOT, not ask the user to choose.
  Root reviews the report, invariants, scope and risks, records which plans are
  approved (and any conditions), then sends that decision back to the SAME agent.
  Only approved refactors may be implemented; unclear proposals return to the
  agent for revision. Root also handles the skill's subsequent design questions.
  This delegation does not authorize changing product requirements, weakening
  security, or skipping root-only validation.

## Implementation

- First-party Rust is safe by default. Android and shared crates forbid unsafe.
  Any required Windows FFI must live in an explicitly reviewed Windows-only
  module/crate with ownership, lifetime and privilege invariants documented.
- Tauri/React owns presentation, not authorization, credentials or service logic.
- Authentication, signatures and encrypted transport must fail closed. Never
  introduce a local generic approval, signing, input-injection or execution API.
- No real keys, credentials, QR bootstrap secrets or command lines containing
  secrets in tests, logs, screenshots, source control or CI artifacts.
- User-visible Korean copy describes outcomes and next actions, not internal
  event names or unproven claims about safety/accuracy. Use Superloopy for UI.
- Rust fmt, Clippy with `-D warnings`, and real Rust Analyzer diagnostics are
  required gates. Only root executes them locally. A passing gate must not be
  fabricated with skipped work, mocks presented as real devices or ignored exits.
- License original project code as GPL-2.0-or-later; retain third-party notices.
- Latest user steering: use Cargo Deny and deny.toml for Rust license checks.
  Stop further bespoke license-source searches and original-material collection.
  Preserve already collected material; legacy collector scripts are not CI gates.
- Starting the Windows or Android service means boot auto-start is enabled by
  default. Windows installs AutoStart after hardening. Android must have an actual
  default-enabled boot/foreground-service path; Application launch alone is not
  boot startup. Keep credential-protected state/keys unopened before first unlock,
  never start an Activity/auth prompt from boot, and respect OS force-stop rules.
- CI must run a real connection/protocol security prover with source-mapped
  assumptions, executable honest traces and broken-protocol negative controls.
  Missing, falsified or inconclusive required proofs fail CI. A symbolic proof is
  not evidence of native isolation, hardware authentication or implementation refinement.

## Conditional Claude handoff and cleanup

- User steering on 2026-09-11: if the general Codex account bucket reaches
  50% remaining or less BEFORE the genuine final architecture-refactoring phase
  starts, freeze this agent's implementation work, write a committed Claude
  handoff plan, create and run a desktop Claude bridge following the existing
  desktop bridge pattern, clean confirmed reproducible C:/E: artifacts, then
  end Codex work. The later user correction explicitly requires CLEANING the
  drives, not leaving them unchanged. This handoff cleanup is authorized even
  before prerelease publication and supersedes the ordinary timing rule below.
- ROOT checks the actual general `codex` usage windows (usedPercent >= 50), not
  the separate Spark bucket. Missing usage is unknown, not zero. Observations
  saved in evidence are historical; obtain a fresh reading before deciding the
  threshold or final-refactoring exception. The final reset credit was already
  redeemed; no additional reset is authorized/available under that grant.
- If final architecture refactoring genuinely starts while more than50% remains,
  ignore this handoff threshold and continue the normal completion workflow.
  Routine code cleanup or partial-feature refactoring does not qualify. Record
  a fresh usage observation at that phase boundary; never advance the phase early.
- Before handoff, ROOT quiesces child writers and records exact branch/commit,
  dirty state, last real CI/native results, unresolved work, authority limits and
  ownership. Preserve the complete original objective; handoff is not a claim
  that the remote-UAC product is complete. Existing one-shot UAC authorization
  remains consumed/cancelled; Claude requires new authorization for another run.
- Existing desktop `.cmd` bridges call
  `C:/Users/32170336/.claude/tools/bridge-up.ps1` with a unique Name and exact Dir.
  That tool starts Claude `remote-control` with worktree sessions. The new bridge
  must target this repository, preserve its normal configured authentication and
  not copy/extract credentials. Handoff instructions/evidence needed in a new
  worktree must be committed or otherwise explicitly preserved. Do not launch
  the new bridge early while the threshold is unmet.

## Cleanup timing and safety

- Outside the conditional handoff above, C: and E: drive cleanup follows a prerelease that has actually
  been published, following implementation, final refactoring and validation.
  A draft release or successful build is not publication. This is not authorization to begin
  deleting files during the ongoing programming work to relieve disk pressure.
- First inventory exact absolute candidates, sizes, ownership and active use.
  Remove only confirmed reproducible build outputs/caches or clearly disposable
  task artifacts; preserve source, git history, keys/certificates, user data,
  required release files, handoff/bridge files and dependencies, and sufficient
  validation evidence. Do not remove caches or outputs used by active builds,
  other agents/projects or the newly running Claude bridge.
- Never recursively delete a drive, home, repository/workspace root, an unverified
  computed target, or a reparse-point destination. Root reviews the exact targets
  and owns deletion verification. Unclear data requires a user decision.
- Report what was removed, recoverability, and measured free-space changes on
  each drive. No claimed recovered space from estimates alone.

## RunPod child task relay

Before spawning any `runpod_*` agent, stage its exact plaintext task under the
same task name. Do not spawn if staging fails:

```powershell
$task | py -3 "$env:USERPROFILE/.codex/runpod-agents/controller.py" `
  stage-task --task-name <task_name>
```

Keep normal tools enabled unless the user explicitly restricts them.
