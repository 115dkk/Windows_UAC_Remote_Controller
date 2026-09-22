# Root direct-WAN execution checkpoint

## Latest checkpoint (supersedes historical detail below)

Claude took over on 2026-09-22 evening after ASTRA stopped at its quota. Both GPT
workers died on HTTP 429 during this session, so all three work items were done
directly.

A second Claude session resumed on 2026-09-23 after the first was cut off.
Tag v1.3.0 is 422497aafe5200821fe4cb1b12775987bb0ee6a9. Release run 35797210141
passed every exact-SHA gate and published the stable, latest release at
2026-09-22T23:48:24Z: https://github.com/115dkk/Windows_UAC_Remote_Controller/releases/tag/v1.3.0

The first release candidate 7901171 failed the Windows UAC lab with HardenService
access denied, and 1ced55f's diagnosis (reboot message needs SE_SHUTDOWN_NAME)
was wrong: the lab failed the same way with null there. ChangeServiceConfig2
refuses SC_ACTION_RESTART unless the handle carries SERVICE_START, and install()
opened its handle without it. 422497a adds that right (no stop or delete right,
install still never starts the service) and the lab passed on 422497a in run
35795791852. The Android minified startup failure on 7901171 did not recur on
1ced55f or 422497a; tools/android-first-unlock.mjs stays unchanged.

The prerelease suffix is dropped at the user's explicit instruction. No alpha
wording is hardcoded anywhere: release.yml derives the label from whether the
version string contains a hyphen, so removing the suffix is the whole change.
Going stable makes the persistent Android keystore mandatory and pins the signer
digest; the four secrets exist and security/android-release-signer.sha256 matches
the certificate CI already produces. Android versionCode stays 1003000.

Three product changes landed.

1. Reboot outage. Four cold boots since 09-15 failed with 0xE5000007 while manual
   starts succeeded from the same registration and account. The shipped startup
   diagnostic produced its first reading: stage 7, phase scm, class configuration,
   which is registered-configuration verification, before any key or ACL work. The
   installed 1.0.0 binary already carries the alpha.39 scm_status split, so the
   earlier stale-StartPending hypothesis is excluded. Comparing against the user's
   MacType Tauri service on the same PC found the gap: it configures an SCM
   recovery contract (restart at 5 s and 30 s, reset 86400 s, non-crash flag) and
   this product configured none, so one failed automatic start was permanent. The
   same contract is now applied at install time and to an already running
   registration, command_matches compares the path the way Windows compares paths
   while keeping the quoting and the fixed argument exact, and phase scm is split
   into fifteen named terms. The contract was also applied to this PC's live
   installation by hand, so the next boot is already covered.
2. Refusal-sounding copy. Four authored strings named only what the program was
   not doing. They now name the cause where the app knows it and the next action,
   across all eleven catalogues.
3. Android lifecycle gate. AndroidDiagnosticSaveInstrumentationTest polled for a
   node then re-queried the live DocumentsUI tree, which is what threw Required
   value was null and blocked the release. Find and act are now one bounded
   operation. The gate passed on 7ec44aa.

Unresolved and recorded in docs/release-verification.md: which registration term
refuses the first boot attempt, and whether the first attempt now succeeds. The
recovery contract shortens the outage; it does not cure the refusal. The user
chose to publish before the reboot evidence exists, so that evidence remains
outstanding after publication.

After publication, at the user's request, the ten release gates trigger on
pull_request without path filters plus workflow_dispatch, never on push. A PR
commit can be tagged without manual dispatch, and main runs each gate once via
main-release.yml. release-gates.mjs accepts a pull_request run only while main is
an ancestor of the tagged commit, since such a run builds the merge with main.
See docs/CI.md. PR #5 is still open: merging it makes main-release.yml pick the
next version from v1.3.0 and publish again, so decide before merging.

### Previous session checkpoint

Product/tag now5f654a1205c4de82e4cb6e9b6d84ad0c540d221b, v1.3.0-alpha.1.
Exact quality35649676136 SUCCESS (Windows/Linux full tests, Clippy, analyzer,
Android core/shell, CargoDeny and Tamarin). Windows package35649676779 SUCCESS.
Android35649676536, minified35649676499, UI35649676189, notification35649676260,
i18n35649676345, attestation35649676310 SUCCESS. Lifecycle35649676477 and
Windowslab35649676384 are still running. Tag is pushed; publication is pending.

Windows-only test failure on ca717f2 was a fixture with2s overall deadline shorter
than production5s per-candidate budget and a released-port reuse race.5f654a1
keeps primary port owned without READY, confirms it was attempted, and verifies
the distinct alternate within10s. Production behavior unchanged. Exact Windows
quality then passed. No lint/test gate skipped or suppressed.

Physical Android measurement APK6c96074 installed normally in place; boot receiver,
foreground promotion and ownerREADY observed. See physical-update.md. Later commits
change only tests/quality collection. No biometric approval latency sample acquired.

### Earlier integration checkpoints

Pushed 6c96074b5f887b9d6558362854a10f2f68f56b35. A1 architecture refactor is implemented
and statically security-reviewed. Follow-up CI corrections retain must-use receipts,
box only the failed dial-request return, and handle the HTTP fixture's first read.
No proof or lint gate relaxed. Root visually reviewed four actual client gallery
PNGs; see frontend/20260921T184406Z-direct-wan-firewall/VISUAL_QA.md.

Exact-source manual runs: quality35647031736, Android35647032232,
minified35647032277, lifecycle35647032548, Windows35647032245,
Windowslab35647031861, gallery35647032010, notifications35647032027,
i18n35647032252, attestation35647032343. All need final statuses recorded.
Duplicate PR runs explicitly cancelled; they are not passing evidence.

At approximately04:43KST, Windows UacRemoteController remains Running PID20508;
one authorized USB phone has dev.dkk115.uacremote1.2.0-alpha.2/code1002000.
No physical per-use authentication sample or WAN success recorded. No1.3release yet.

## Historical checkpoints

Baseline8be9af9; implementation19acfd6; current pushed product3391008. Metadata
1.3.0-alpha.1; no new tag/release yet. User excludes cloud relay/quota. PCP and
public local IPv4/IPv6 are candidates, not observed Internet success. UPnP and
NATPMP production operations are read-only. Existing pins/keys/auth remain.

USB03:59/04:02KST: one authorized physical phone, alpha.2/versionCode1002000,
promoted/READY/activationON, callback reset count2, Dozing. No authentication or
UAC canary attempted. One-shot04:00 heartbeat4-usb paused after root check.
Computer Use skill forbids security-app automation; V3 was not automated despite
user's app-specific allowance request. No global firewall/router/VPN change.
Earlier address-only probes and null Windows UPnP COM collection do not prove
V3 denial or permanent router non-support; no live mapping created.

Security D1-D5 fixes re-reviewed: query cadence, pre-sign pairing fallback,
PCP zero-suggestion deletion, gateway-scoped nonce and long-grant ownership.
Only reviewed hashes of config.rs/channel.rs/peer_runtime.rs were rebound;
proof models and negative controls unchanged. First CI failed AR bidi controls
and2collapsible-if warnings, corrected3391008. Subsequent CI found missing closed
COMPOSITE_ROUTING_CANDIDATES label and unused already-checked CommitReceipt;
root fixes are local pending integration. No gate weakened.

Exact3391008 runs: Quality35644278826 (failed jobs), Android35644279055,
minified35644278795, lifecycle35644278777, Windows35644278838,
Windowslab35644279400, gallery35644278818, notifications35644278980,
i18n35644278971, attestation35644279089. Fresh statuses required. Duplicate PR
runs cancelled, not counted as success. CandidateAPK35644175508 is not release.

Fresh architecture A1 approved in architecture-approval.md: private ownership
module shared by poll/shutdown; agent direct_final_architecture implementing.
Root owns CI/native QA. Subsequent exact-source gates, artifact review,
publication and physical Internet/authentication acceptance remain incomplete.
