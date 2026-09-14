<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0034: Session-local independent pairing object inspection

Status: implemented, native CI validation pending.

## Evidence and decision

Native CI34805229439 at a314cb6 reached actual initial UAC Yes, authenticated
Helper/Renderer connection and RendererObjectsReady (including the renderer's
own exact desktop descriptor check). Session0's desktop DuplicateHandle then
failed with stage5/80070005. Station duplication was not reached. Microsoft's
API contract supports desktop handles but does not guarantee this cross-session
transfer. The receiving session/station is the current topology hypothesis;
the same-session full native CI must establish the correction.

Keep ADR0026's independent inspection contract. Session0 retains and rechecks
the original renderer process/thread, creation times, token/session epoch,
protected image and exact process/thread descriptors. A separately created
SYSTEM child of the service performs the USER-object checks in the registered
renderer's session and WinSta0. It is not the older High creator/helper.

The inspector uses the fixed protected service executable, fixed `pair-inspector`
argument, explicit creation-time SYSTEM/service-SID process/thread ACLs, no
inherited handles, a bounded kill-on-close job and only the service's own copied
primary token. Its session must equal the already registered renderer's session.
This path never enables privileges, including in lab builds. The existing
consent watch process keeps its separate lifetime and lease.

The child receives exactly one Bind from the actual SCM-bound Session0 service
over a first-instance, kernel-local, PID-bound protected pipe. No target is
accepted from CLI, environment, management UI or arbitrary pipe caller. Bind
contains only original renderer metadata, public ceremony IDs and original QPC
cutoff. It exposes no key, credential, QR content, execution or input operation.
Subsequent Check/Close requests have strict increasing sequence numbers; wrong
phases, duplicate Bind, stale/crossed replies, EOF/death and timeouts fail closed.

The native duplicate/type/name/exact-descriptor/station checks remain mandatory.
A read-only OpenDesktop in the inspector's WinSta0 must identify the SAME native
object as the retained independent duplicate. The original renderer creates one
invisible, disabled, empty fixed-class top-level witness on its already verified
private desktop, before receiving any QR contents. The inspector uses complete
bounded EnumDesktopWindows and GetWindowThreadProcessId observations to prove
that exact HWND belongs to that desktop and the original retained live PID/TID.
This replaces the incompatible foreign GetThreadDesktop operation; it is not a
name-only or renderer-asserted desktop association. A thread cannot switch its
desktop while it owns windows there (SetThreadDesktop's documented constraint).

Every positive step repeats native membership/class/visibility/owner checks,
bracketed by original process/thread liveness, creation/token/session checks.
Unexpected witness destruction, visibility/enabling or loss permanently fails
the renderer; it cannot recreate a witness in the same invocation. The witness
is independent from visible QR UI: UI may close before CloseAck, but the witness
stays alive through actual service EOF, then is destroyed on its original thread.
Callbacks are bounded, nonallocating, nonpanicking and never dispatch user
decisions. No QR content, input-desktop switch or visible window precedes binding.
The new mandatory HWND uses exact revised private wire shapes (UCPH2/UPI2).

The original ceremony cutoff is never extended. Separate short operation
timeouts bound IPC waits; cleanup retains/cancels pending buffers, reaps only
the newly service-created inspector and quarantines uncertain ownership. It
never terminates the separately UAC-created renderer or changes Windows policy.

## Historical GetThreadDesktop experiments (superseded)

Native b90ed5f attempt2 passed duplicate/type/name/exact-descriptor/station
checks in the session-local inspector, then failed GetThreadDesktop with
stage29/80070005. The inspector additionally opens the already retained private
desktop through OpenDesktopW using its exact generated name and unchanged
limited mask. It retains that typed handle and compares it to the independent
duplicate before the original actual-thread GetThreadDesktop comparison on
every check. No name-only identity, thread/desktop switch, ACL or privilege
change is accepted. USER-side opening is a compatibility hypothesis pending CI,
not proof that all GetThreadDesktop calls succeed.

The explicit open passed natively at1a8bdf8, but stage29 remained. Renderer
bootstrap now initializes its windowless original thread's message queue after
the initial protected-desktop checks, using the documented PeekMessage/WM_USER/
PM_NOREMOVE pattern, then refreshes and revalidates actual desktop/station before
export. Station/desktop queries alone are not explicit GUI-queue initialization.
No window, queued-message removal, input injection or authority is created by
this readiness step; independent native thread association still gates the QR.
Resolution of stage29 remains subject to actual CI.

The f418c3e controlled native access matrix isolated the missing capability:
with unchanged process/thread access, GetThreadDesktop failed on limited desktop
handles even under full descriptors; a separate full-access OpenDesktop handle
to the independently duplicated/verified SAME object made the original-thread
lookup succeed. Keeping the initial limited duplicate was compatible. Removing
any of DELETE/WRITE_DAC/WRITE_OWNER from the otherwise full handle still failed
in those tests. This is an observed Windows API requirement, not an assertion
that our inspector performs these mutations.

An intermediate experiment granted DESKTOP_ALL_ACCESS (0xf01ff) only to SYSTEM and the exact service SID in
the private desktop descriptor. The High renderer/creator BA mask stays0x20183,
OW retains only READ_CONTROL, and process/thread/station masks do not change.
The inspector retains its limited independent duplicate, then opens the already
verified private object with the service-only association mask. Exact native
object equality and actual original-thread lookup remain mandatory. No new
input, desktop switch, descriptor setter or generic operation is exposed by the
inspector. This still failed in the actual product: the source renderer's
desktop handle was deliberately limited. A later source20183 native control
reproduced that failure even with full observer access and full descriptors.
That intermediate capability expansion is REVERTED. SYSTEM/service SID and
both inspector desktop handles again use0x20081; BA stays0x20183 and OWRC.
The current independent window-membership proof does not need full desktop
handles, broader process/thread access, SYSTEM UI or foreign-token duplication.

## Validation

The early native access-contract job retains the historical getter observations
and separately requires hidden-window membership for every mask (including exact
limited source/observer), with wrong PID, TID and desktop negative controls.
It is explicitly a scratch-target API contract, not production creation isolation.

The existing failing installed-app QR/pairing/signed-denial CI is the native
regression test. Closed frame/command tests cover malformed and crossed inputs;
quality, Clippy and Rust Analyzer run on CI. Physical Android hardware identity,
biometrics and actual phone approval remain separate acceptance items. A CI
software identity is not a hardware attestation result.
