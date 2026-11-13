<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0048: A busy owner does not cost the person their decision

Status: implemented source with unit coverage (Rust, JVM, UI). Not yet seen on
a real phone. The causes below were found by reading the code after the
report; no diagnostic file from the affected phone was read.

## Evidence

The user reported on 2026-11-13 that the phone app keeps saying it is busy and
breaks the approval off: the request screen is gone when they go to press
approve and comes back a few seconds later. They asked that a signature made
before the app became busy still be used, or that one made while it is busy be
kept and sent when it stops being busy.

Four places answer "busy" on the way from a tap to the PC, and each of them
dropped the work it was handed.

1. The app's command slot (`CommandAdmission`) admits one native command at a
   time and refuses the rest. The request screen reads a snapshot every five
   seconds, on every native wake and shortly before a display lease ends, and
   each read holds the slot. `useController` deliberately sent approval and
   denial without waiting for that read, so a tap during a read was refused as
   `app_busy`, and the refusal path withdrew the request bodies and marked the
   screen stale until the next read.
2. The Rust owner (`MobileController::enter`) admits one thread and answers
   Busy to the other at once. The I/O reactor holds it while it applies one PC
   message or runs one maintenance pass. `ApplicationApprovalCoordinator`
   answered a Busy from `beginApproval`, `claimApproval` or `finishApproval`
   by cancelling the session, including after the identity check had passed
   and the signature had been produced. The request went back to pending and
   the person had to approve and authenticate again.
3. A signed approval waiting to be handed to the socket is advanced by the
   maintenance pass. A pass that met a busy owner did nothing and asked for no
   other pass, so the approval waited for whatever event came next.
4. A preview's display validity ended with the wall minute whatever the next
   minute allowed. Every request left the screen at each minute boundary for
   as long as the next read took, and the screen asked for a new lease without
   pause for the last 1.2 s before it, each read holding the command slot.

## Decision

Busy is a reason to wait where waiting is safe, and never a reason to discard
a decision the person has made.

- **Owner admission waits on the decision path.** `enter_waiting` waits up to
  750 ms for the owner instead of answering Busy at once. It is used by
  `request_catalog_status`, `maintain_native_requests`,
  `check_pending_request`, `refresh_native_request`, `begin_approval`,
  `claim_approval`, `finish_approval`, `request_approval_delivery`,
  `reserve_denial`, `advance_denial` and `finish_denial`, which the native
  worker calls. A call from inside a native callback is still Busy at once,
  and the reactor keeps `enter` and its own wake. One caller is admitted at a
  time, as before.
- **A Busy approval job runs again.** When one of the three approval calls is
  still Busy after that wait, the same job is scheduled again
  (`ApprovalBusyRetry`: 25, 50, 100, 200, 400, 400 ms) instead of cancelling
  the session. The prompt is not shown again and nothing is signed again. The
  signature is put back for the repeated `finishApproval`. A Busy that did
  reach the owner leaves a cancelled plan, and the owner refuses the repeated
  call itself. The session deadline and cancellation still end it.
- **A held approval asks for another pass.** A maintenance pass that met a busy
  owner while a signed approval is held schedules another pass on the same
  budget. Without a held approval a Busy pass still waits for a real event.
- **The screen keeps the tap.** A decision waits for the read that holds the
  command slot. If that read still shows the request, the decision goes out
  with the locator the tapped card had; if it does not, the tap is dropped and
  the read is shown. A decision answered `app_busy` is offered again after 60,
  120, 250, 500 and 500 ms while the request is on screen and inside its
  display lease. Only after that does the busy line appear, and the request
  stays where it was: the refusal happened before anything began, so the
  screen is not stale. Any other refusal still withdraws the request and marks
  the screen stale.
- **A background read that found the owner busy reads again** after 150, 300
  and 600 ms instead of leaving a withdrawn request for the periodic read.
- **Display validity follows the schedule.** `display_until` extends a preview
  past the minute boundary for each following local minute the same policy
  snapshot allows, up to the request deadline and never more than five
  minutes. The screen asks early once per lease, not repeatedly for a lease
  that ends with the request.

## What does not change

No decision is authorized by any of this. The tap carries the locator of the
card that was tapped, and the native registry and the Rust owner check it
again; an approval still needs the phone's identity check for that exact
request lease, and a renewed lease still cannot be answered by an old
signature. A wall-clock or zone change moves the time epoch and invalidates
previews at once; a changed policy withdraws the request through the inbox.
Display validity is display only.

## Not covered

- The PC renews a live prompt's lease in its last 30 s (80 s in). An identity
  check that is open at that moment is cancelled with the old lease, and the
  request is presented again. This is unchanged.
- Whether the I/O reactor ever drops a PC connection on a Busy of its own
  (`UAC_NATIVE_INTAKE_V1 site=PEER_WORK error=BUSY`) was not established. No
  path to one was found in the source, and no diagnostic file was read.
- The waits were chosen from the code, not measured on a device.
