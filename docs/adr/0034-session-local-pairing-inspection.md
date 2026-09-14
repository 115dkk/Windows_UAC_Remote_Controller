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

The same native duplicate/type/name/exact-descriptor/station checks and actual
GetThreadDesktop/CompareObjectHandles association remain mandatory. The child
holds actual duplicated objects and original process/thread handles through the
ceremony. Every former positive object recheck requests a fresh child check;
the service authenticates the original inspector and its token/session around
each reply. No one-shot success cache replaces these observations.

The original ceremony cutoff is never extended. Separate short operation
timeouts bound IPC waits; cleanup retains/cancels pending buffers, reaps only
the newly service-created inspector and quarantines uncertain ownership. It
never terminates the separately UAC-created renderer or changes Windows policy.

## Validation

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

The existing failing installed-app QR/pairing/signed-denial CI is the native
regression test. Closed frame/command tests cover malformed and crossed inputs;
quality, Clippy and Rust Analyzer run on CI. Physical Android hardware identity,
biometrics and actual phone approval remain separate acceptance items. A CI
software identity is not a hardware attestation result.
