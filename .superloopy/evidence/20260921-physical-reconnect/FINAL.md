# Connection/measurement delivery: published; actual authentication still needed

## Published product

- Tag:v1.2.0-alpha.2; product source:a1c5ae8d925486d13964cb3b38966d4979f39324.
- Release:https://github.com/115dkk/Windows_UAC_Remote_Controller/releases/tag/v1.2.0-alpha.2
- Published2026-09-21T14:38:03Z; isDraft=false, isPrerelease=true.
- Release run35610136489 attempt2: all jobs success, native watch exit0.
- Every required exact-source gate succeeded. The repeated tag Quality35610394592
  also succeeded; the recovered release gate selected that current run.
- Android APK SHA256:730dd43040bc9d9b8cee75253833ca266f736863147d9743edaa22ddd0245a68
- Windows installer SHA256:eb594b2d6041a2783f3c7cb22b2d06591056a400bfb7040064bb3c4e5a740c53
- Published SHA256SUMS.txt was downloaded and compared with the exact APK bytes
  installed on the physical phone. Match confirmed. Persistent signer remains
  c975b78a34dd622d19c4af329e4f71bfa895693ff04db5116aa718fd9aa20c22.
- Windows passive inspection passed; installer size48792613bytes and hash agree
  with the uploaded asset. The installer was not executed on the user's PC.

## Implemented and observed

Android default-network observation now wakes bounded native recovery, cancels
old generations and resets dial backoff without changing pairing, keys, request
deadlines or authorization. Native action-generation ownership prevents stale
callbacks overwriting a newer action's presentation. Bounded same-request
receipts and actual OS-auth/signature timestamps support physical measurement
and the future feedback UI; they are not a winning-phone identity proof.

The final published APK was installed in place on the authorized SM-S948N,
Android16/API36, WebView151.0.7922.202. No application/credential data was erased.
Package replacement started the foreground owner to READY before an explicit
Activity launch. On the exact published APK, actual Wi-Fi disable/restore kept
the owner READY, incremented network reset requests0→1→2, restored Wi-Fi to1,
and re-established one phone→PC TCP connection. VPN/relay/router/firewall settings
were unchanged. This is callback/TCP recovery proof, not authenticated UAC proof.

The installed PC service remained Running, PID20508, exit0, version1.0.0; fresh
public diagnostic request events and its listener/phone socket were observed.
This does not claim the new Windows package was locally installed.

Diagnostic file-save separate from sharing and release-note cleanup previously
shipped alpha.1 and remain present. The published alpha.2 body contains only four
changes since alpha.1, no unresolved checksum placeholders, and a separate
version/SHA-bound release-verification.md attachment/link. It does not accumulate
the repository's entire historical change list.

Independent security review found no remaining new high/medium finding in the
reviewed deltas. A fresh architecture review and ROOT selection concluded no
additional product refactor was justified for this delivery. Those judgments
are not substitutes for actual authentication evidence.

## Unfinished objective and exact next input

No valid physical authentication latency sample exists. Two fixed Windows
canaries were attempted; both had zero PhoneDecisionVerified approval and zero
WindowsApplied approval records, no observed successful process exit, and no
eligible phone decision sample. The roughly122second waits are unconfirmed
whole-request waits and are excluded, as are ping and software-phone CI timing.
The phone was observed Dozing. A ready service/TCP socket does not establish why
no authentication occurred or prove the whole approval path worked.

User must be ready to unlock the phone, choose the fixed test request and perform
their own OS authentication. No further canary is sent until readiness is given.
Then run tools/measure-physical-approval.ps1 -Run once and read
tools/read-physical-decision-metrics.ps1. Corroborate actual auth/signature,
eligible same-request PC receipt, controlled Windows verified/application events
and successful fixed process exit. Separate human/authentication time from
post-authentication time. Native-action timing excludes the preceding JS queue;
do not label it full tap-to-painted-result latency. A single sample is not p95.

Feedback UI is DESIGN ONLY in
.superloopy/evidence/frontend/20260921T135008Z-physical-decision-feedback/UX_CONTRACT.md.
Its native prerequisites are implemented, but the requested measurement-first
condition is unmet. After a valid working path is observed, implement immediate
local choice, real progress and retained body-free PC outcome, then repeat
appropriate native/client/security/architecture/CI/release verification.

Current configured endpoint is a private LAN address, so the present setup is
effectively LAN-only despite no SSID/subnet rule in authentication. Mobile data
requires an authorized externally reachable PC path or relay. No server was
created and no billable hosting/public port/router change was performed. Need
user-provided reachable endpoint or deployment choice/budget before that work.
For a separate external-relay migration, PC set_relay changes only global config
while the dialer filters per-device stored endpoints; Android has no endpoint-only
update and differing descriptors conflict. Preserve keys/pins/route IDs and add
explicit endpoint migration rather than deleting/re-pairing as a workaround.
A routed public path to the same embedded relay has a different PC-side scope;
do not assume every public-path choice needs the same migration.

## Evidence and repository state

See physical-trial-01.md, physical-trial-02.md, release-apk-device.md,
ci-a1c5ae8.md, security-review.md, security-followup.md,
architecture-candidates.md, architecture-approval.md and architecture-result.md.
Current measurement/release artifacts are retained for the unfinished physical
work. No local files were deleted in this delivery and no disk-space recovery
is claimed. Existing user .claude/ and .codex-remote-attachments/ remain untouched.
PR5 remains open; main was not merged or changed. Published tag/assets are fixed.
Any subsequent evidence-only commit is distinct from the tested product SHA.

The active whole-product Superloopy plan remains incomplete; G006/C001 retains
an unmet native happy-path result. Publication is a completed delivery step,
not completion of physical authentication, mobile-WAN reachability or feedback UI.
