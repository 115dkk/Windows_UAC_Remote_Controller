<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0052: One peer, one ceremony or one helper cycle does not stop the service

Status: implemented source. Unit, loopback and real-pipe tests ran on the
development PC. Two independent reads of the diff found the defects recorded
under "Review" and those were fixed. Nothing here was observed with the
installed service, a real phone or a real consent prompt.

## Evidence

A security review of 1.13.0 on 2026-11-19 read `crates` and `src-tauri` and
reported nineteen findings, none critical or high. Fifteen were ways for the
service, its watch helper or pairing to stop for a cause that one remote peer,
one local unprivileged process or ordinary timing controls. They were found by
reading; none was run.

- F1, F2, F3, F12: `check_peer` failed both when a peer's connection had ended
  and when the registry no longer matched it, and every failure ended the
  session. A phone whose connection closed while the PC was inside a TPM
  signature (clock answer, address answer) or just after its decision was
  verified stopped the service. Windows restarts it twice a day; the third time
  it stays down.
- F5, F18: a pairing whose attestation proof had expired by the time of the
  commit, or whose phone disconnected before the frozen candidate or the
  acceptance could be sent, ended the session instead of the ceremony.
- F8, F17: the activity journal refused a record older than its newest one, and
  the service treated a refused record as fatal. A clock that stepped back
  stopped the service on its next event and on every restart until real time
  caught up.
- F14, F15, F16: the watch helper exited when the input desktop could not be
  opened or named, when a window vanished between enumeration and its queries,
  and when the secure desktop went away mid-census. After nine exits in a row
  the service stopped relaunching it until the service itself restarted; a
  sign-out of about five minutes reached the same state with no attacker.
- F7: after a client failed authentication the service closed its end of a
  pipe and re-created the name as first instance; a client that kept its handle
  open kept the old instance alive, creation failed, and pairing stayed off for
  good. The Management pipe failed the same way while the handle was held.
- F9: the helper's pipe was named after the helper's process id and created
  after the helper, so any local user could create the name first.
- F6: the pairing pipe decoder admitted only the two version 1 invitation
  lengths, so an invitation with direct candidates (ADR 0038) ended the
  ceremony before a QR code was drawn.
- F13: on the phone a DNS-SD hint was dialled ahead of every stored route and
  never demoted, so a host on the same network that announced the PC's label
  won every reconnect and failed pinned TLS each time.
- F19: the diagnostics folder was opened by passing its bare path to the shell,
  which may run a same-named program placed beside it in `C:\ProgramData`.

F4 is ADR 0053. F10 and F11 are ADR 0054.

## Decision

1. A peer that is no longer connected is a rejected peer, not a failed
   session. Liveness is tested apart from identity: the connection ending
   retires that peer and the session continues; a registry, key, revision or
   boot-epoch mismatch still ends the session. A decision is handed to Windows
   only while its sender is still connected, tested again immediately before
   the hand-over; if the sender left after its decision was verified, the
   request is settled as failed and nothing is applied.
2. A pairing that cannot proceed fails as a pairing. A device counts as
   enrolled once its acceptance has drained to the transport. If the ceremony
   or the whole session ends between the registry commit and that moment, the
   device is revoked from the registry and the engine before the failure is
   reported; if the acceptance had drained and only the close failed, the
   device is enrolled and reported so.
3. The journal stores a record whose time is older than its newest record at
   the newest record's time. After the service is ready, a journal write or
   purge that fails writes `journal_append_failed` or `journal_purge_failed`
   to public diagnostics, at most once a minute per fault, and the service
   continues. Failing to open the journal at start is unchanged (ADR 0041).
4. The watch helper treats an input desktop it cannot open or name, and a
   desktop that stopped being the secure one, as "not the consent desktop":
   it withdraws a tracked prompt, skips the cycle and keeps its heartbeat. A
   window it can no longer query is skipped and is never a candidate. A prompt
   too large for a watch frame is not published. After pressing a button, not
   being able to look is not evidence that the dialog went away: only an
   established disappearance is reported as applied, otherwise the result is
   unknown. Pipe failure, impersonation, a protocol violation and the lifetime
   limit still end the helper, and every check before a button press is as it
   was.
5. The service relaunches the helper for as long as it runs: after the ninth
   failure in a row it keeps trying every 60 s. A launch refused because no
   one is signed in does not count as a failure.
6. A server pipe is disconnected before it is closed when its exchange failed
   or never authenticated, so a lingering client cannot hold the name. After a
   completed exchange it is closed without disconnecting, so a reply the
   client has not read yet stays readable; the Management pipe first waits up
   to 2 s for the client to finish. The next instance is created at once after
   the previous one has drained; a creation that fails is retried every 250 ms
   and reported once.
7. The helper's pipe name ends in 128 random bits, the pipe exists before the
   helper is created, and the helper receives the name as an argument. The
   helper still checks that the server is the service process and the service
   still checks that the client is the helper it created.
8. Invitation frames of every length between the shortest and the longest
   invitation are admitted; the invitation codec decides the rest.
9. On the phone, a hint address whose connection did not reach the pinned
   channel is distrusted until a connection to that PC succeeds or the network
   changes. A distrusted address is tried only after every other candidate has
   failed. One new hint address per back-off interval is tried first; others
   wait behind the stored routes. A dial counts as successful only once the
   pinned channel is ready.
10. The diagnostics folder is opened as a shell item of the validated
    directory, not as a path for the shell to resolve.

## Review

The diff was read by a model other than the one that wrote each part. Fixed as
a result: the hand-over to Windows did not re-test the sender (decision 1); a
failed delivery after the acceptance was queued left the device enrolled
(decision 2); the helper reported an unobservable outcome as applied
(decision 4); a re-arm waited 250 ms even after a normal exchange, and
disconnecting on every close discarded unread replies (decision 6); a
distrusted hint still won the connection race (decision 9). A change that
answered a failed relay-setting write with a refusal was withdrawn: the write
can succeed and then fail to read back, so the session ends as before.

## Protocol model

`peer_runtime.rs` and `watch.rs` are bound to the Tamarin models and were
re-hashed with a review section in `security/tamarin/README.md`. The changes
are to failure handling: which failures end a peer, a ceremony or a helper
cycle. No message, signature, admission rule or decision check changed, and no
theorem, rule, canary or expected verdict changed.

## Consequences

- A phone that drops at the wrong moment costs that phone a reconnect.
- A decision whose sender disconnected before the hand-over is not applied; the
  person answers again.
- New rows in `diagnostics.jsonl`: `journal_append_failed`,
  `journal_purge_failed`, `relay_abuse` (ADR 0054).
- The helper and the service must be the same build: the pipe name scheme
  changed (`PromptProbe.v4`). The installer already replaces both together.
- Activity records written while the clock is behind share one timestamp.
