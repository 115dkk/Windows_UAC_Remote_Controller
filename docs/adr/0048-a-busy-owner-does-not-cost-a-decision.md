<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0048: A busy owner does not cost the person their decision

Status: implemented source with unit coverage (Rust, JVM, UI). Not yet seen on
a real phone. The causes below were found by reading the code after the
report; no diagnostic file from the affected phone was read. A static audit of
the first version found four defects, listed under Review, and this is the
corrected decision.

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
  the read is shown. A decision refused as busy before the native side took it
  is offered again after 60, 120, 250, 500 and 500 ms while the request is on
  screen and inside its display lease. Only after that does the busy line
  appear, and the request stays where it was: nothing began, so the screen is
  not stale. Any other refusal still withdraws the request and marks the
  screen stale.
- **Only a refused decision is offered again.** The snapshot a decision
  returns is read after the decision, so `app_busy` on it can come from one of
  those reads while the decision went in. The native reply for a decision that
  was not admitted now carries its own code, `request_action_busy`, and the
  screen repeats a decision for that code or for a command-slot rejection, and
  for nothing else.
- **A busy answer that read nothing is not a withdrawn request.** When the
  reads behind a decision's answer found the owner busy, the answer lists no
  requests. The card stays; a refused decision is offered again, and an
  admitted one is followed by a read.
- **Leaving the app gives up a kept tap.** A page that goes to the background
  withdraws its request text. A decision still waiting for a read is not sent
  after that, and an answer that arrives on a hidden page puts no request text
  back. A denial needs no identity check, so it would otherwise have gone
  through for a request no longer on screen.
- **A background read that found the owner busy reads again** after 150, 300
  and 600 ms instead of leaving a withdrawn request for the periodic read.
- **A preview is valid for as long as the schedule allows it.** The schedule
  is evaluated per local minute, which is why display validity ended with the
  minute. With no schedule every local minute is allowed, so the preview holds
  until the request deadline. A weekly schedule is walked forward one local
  minute at a time while the same policy snapshot allows the next one, up to
  the deadline and never more than five minutes past the end of the current
  minute. The walk takes the next wall minute to be the next local minute, so
  it also stops at the zone's next UTC offset change: the native time
  observation now carries that instant (`offset_change_nanos`, from the zone
  rules), because a daylight-saving change keeps the zone and the UTC clock
  and so moves no time epoch. That instant is counted from the first elapsed
  reading of the sample and gives up the millisecond the wall reading was
  rounded down within, as the minute's own end already does, so it is never
  later than the change. The screen asks early once per lease, not repeatedly
  for a lease that ends with the request.

## What does not change

No decision is authorized by any of this. The tap carries the locator of the
card that was tapped, and the native registry and the Rust owner check it
again; an approval still needs the phone's identity check for that exact
request lease, and a renewed lease still cannot be answered by an old
signature. A wall-clock or zone change moves the time epoch, and from then on
the native registry and the Rust owner refuse anything issued under the old
one; a changed policy withdraws the request through the inbox. What is already
drawn follows after that, see 'Not covered'. Display validity is display only.

## Review

The first version was audited from the source before it was merged. Four
findings, all corrected above:

1. A decision was repeated whenever the returned snapshot's issue was
   `app_busy`, which a read made after an admitted decision also produces.
2. Display validity was extended minute by minute through a weekly schedule's
   windows. That assumes the next local minute is the next wall minute, and a
   daylight-saving change inside one zone breaks it without moving the time
   epoch, so a preview could outlive a window that had just ended. 1.11.3
   shipped without the extension for weekly schedules; it came back once the
   observation carried the next offset change to stop at.
3. A refused decision whose answer read nothing published that empty answer
   and took the request off the screen.
4. A denial kept behind a read was sent after the app had been left.

The weekly walk was audited again when it came back. One finding, corrected
above: the next offset change was converted from whole wall milliseconds
without giving up the millisecond the reading was rounded down within, so the
bound could be up to a millisecond later than the change.

## Not covered

- At a daylight-saving change a request shown under a weekly schedule is read
  again, and leaves the screen for as long as that read takes.
- A card already on the screen is not taken off the moment the clock, the
  zone or the policy changes under it. The change wakes the screen to read
  again, and the card stays, with its buttons, until a read answers or the
  lease the screen holds ends; a read that finds the owner busy leaves it
  there, as it did before this change. A tap on it is checked again natively
  and refused. The lease the screen holds used to end with the minute and now
  ends up to 60 s after the read, the most one read is ever given.
- The system notification of a request is given the request's expiry as its
  timeout, not its display validity. It is withdrawn at a schedule boundary
  by the maintenance pass that sees the new minute, not by the system timer.
  Its actions are checked again natively as well. This is unchanged.

- The PC renews a live prompt's lease in its last 30 s (80 s in). An identity
  check that is open at that moment is cancelled with the old lease, and the
  request is presented again. This is unchanged.
- Whether the I/O reactor ever drops a PC connection on a Busy of its own
  (`UAC_NATIVE_INTAKE_V1 site=PEER_WORK error=BUSY`) was not established. No
  path to one was found in the source, and no diagnostic file was read.
- The waits were chosen from the code, not measured on a device.
