<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0036: Let the person leave the pairing takeover, and tell them first

Status: implemented source; ROOT device and CI evidence is recorded separately.
This changes what the protected renderer shows and which local inputs it reads.
It changes no frame, grant, key, enrollment, desktop right or authorization rule,
and it does not touch [ADR0026](0026-protected-pairing-renderer-bootstrap.md)'s
bootstrap or [ADR0020](0020-canonical-pairing-invitation.md)'s invitation.

## Evidence

The pairing renderer switches the input desktop and paints the QR over the whole
display. Until now that screen had no cancel control, and `pump` read the Escape
key only on the comparison screen, so `Screen::Invitation` accepted no input at
all. A person who wanted out had to wait for the attempt to expire.

The user reported the result plainly: the screen frightens them, and they build
this software. The combination is the visual grammar of a ransom note. The whole
display is replaced without warning, the familiar desktop is gone, a countdown
labelled `남은 시간` runs down, a large high-contrast machine-readable field owns
the centre, nothing on screen names the program, and there is no way out.

Only one of those is load-bearing. The private desktop is the property that keeps
other processes off this UI and stays exactly as it is.

## Decision

**The ceremony announces itself before it shows anything.** The window opens on
`Screen::Introduction`: what the steps are, that the phone's QR connection should
be turned on first, that Escape or [취소] stops it at any time, and a caution that
someone else asking you to start this is the shape of an attack and that the code
must never be shared. It advances only on its own `START_ID` control or Enter.
There is no timer on it. A person who walks away expires the attempt, which is
the correct outcome, and the screen that follows is the one the button named.

`START_ID` is 1003 and never `CONFIRM_ID`. That identifier means "the six digits
match" and may not be worn by any other question. Each screen honours only the
identifiers whose question it is asking, so a control that outlived its screen
could not answer for the next one. Moving to the comparison destroys the whole
control row and builds it again.

**Escape leaves from every screen that still offers a way out**, and the QR
screen carries a visible cancel button plus a line naming the key. Leaving before
any comparison exists decides nothing, so it is not routed through
`begin_decision`: the renderer retires with `PairingLaunchError::ClosedByUser`,
which closes the window, restores the original input desktop and drains the pipes
through the cancellation path that already existed. No decision frame is written
and no grant, key or enrollment is created, refused or implied.

**The countdown says when the screen ends and gives the ending no agent.** The
same seconds now read `{:02}:{:02} 후 종료`. Counting down what is left is a
deadline the reader races, and the obvious softening, telling them it closes by
itself, hands the agency to the screen and so states a second time that they are
not in control. The bare form attributes the ending to nobody. For the same
reason the QR screen carries no line promising that it will disappear on its
own: a reassurance the reader did not ask for, about the machine acting
unprompted, is worse than saying nothing. The old `남은 시간` key is gone from
all eleven catalogues.

**The takeover is signed, once.** The product mark and name are painted in the
leading top corner only, from axis-aligned primitives and a stock null pen; no
image, file or resource is loaded. A repeated mark would read as a seal, which is
the thing being avoided. The card is painted over that corner afterwards, so a
translated name with no room left is dropped rather than sliced: a wordmark cut
by the card edge reads as a rendering fault, and the mark alone still signs the
screen. Every control row is sized from the longest translation rather than from
Korean, which is always the shortest; the comparison row is 240 by 72 because at
184 by 60 the French and European Portuguese labels needed three lines and had
room for two.

**The QR itself is not reduced.** Its size was never the problem, and it is a
functional surface for both a phone camera and the lab's screenshot decoder.
`invitation_layout` measures the code first and anchors the footer to the card, so
a cramped display gives up margin rather than legibility, with `MIN_MODULE_PX`
holding the module size the lab already decodes. The layout is a free function
over a client rectangle, and a test walks the display sizes that matter to assert
the code stays legible, never covers the copy above it, and never has the way out
laid over it.

## Scope

Unchanged: the private desktop and its switch, the handle and GDI ownership rules,
the single comparison decision, the frames on the wire, the deadline the service
sets, the invitation text and the enrollment path. The renderer still reads no
text, clipboard or input hook, and still creates no process, connection, key or
grant.

The CI lab now presses the introduction's own control before capturing, as a
person would, and refuses to capture while it is still shown. That is a fidelity
gain, not a bypass: no operator-side shortcut past the screen exists.

Not established here: that the ceremony reduces fear for anyone but the reporter,
and that the native paint matches the reviewed geometry on real hardware. Both
wait on the user's own test.
