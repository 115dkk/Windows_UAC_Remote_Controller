<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0026: Final pairing renderer ownership begins at process creation

Status: accepted; nonvisual bootstrap implemented. CI results and native
qualification are separate evidence and are not asserted by this ADR.

## Context

[ADR0024](/E:/Windows_UAC_Remote_Controller/docs/adr/0024-service-owned-pairing-rendezvous.md)
binds the original Starter and elevated Helper to one service-owned attempt.
[ADR0025](/E:/Windows_UAC_Remote_Controller/docs/adr/0025-policy-qualified-private-pairing-preparation.md)
adds applicable UAC-policy observation and one private, volatile preparation.
Neither Bound nor Prepared grants consent, QR disclosure or enrollment.

A future invitation must not pass through the ordinary Tauri shell or the old
Helper's potentially readable memory. High integrity alone does not establish
read confidentiality, and late access-control changes cannot prove that no
earlier handle exists. Building a parent-owned UI and relocating it later would
create another sensitive ownership transition without solving that boundary.

## Decision

The existing ServiceSession remains the sole registry/engine/key coordinator.
Its [ServicePairing owner](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/peer_runtime/pairing.rs)
may claim one final renderer bootstrap only after successful C4 preparation and
fresh original peer, policy, epoch, deadline and stop checks. Renderer resources
share the original admitted attempt; they do not create another ceremony owner.

The original High Helper owns launch/control and a non-rendering desktop
bootstrap reference. The
[fixed launcher](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/ffi/pairing_client/helper_launch/renderer_launch.rs)
creates the renderer suspended with explicit protected process/thread descriptors
and its final private application desktop in STARTUPINFO. Successful native
handles are adopted before fallible checks. The renderer owns its initial thread
and desktop from first execution, not after a temporary UI on Default. No
privileges or existing Windows desktop policies are changed.

Registration travels over the original authenticated Helper control pipe.
The [service inspector](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/ffi/pairing_peer/renderer.rs)
independently retains and validates the exact child PID/creation identity,
initial thread, token/session, protected image and process/thread descriptors
before acknowledgement permits one resume attempt. Native desktop references
are independently inspected and compared with the actual initial-thread
association before RendererBound. Names, supplied descriptors and caller flags
cannot replace these observations. Unsupported native access or association
checks fail closed.

The renderer uses one direct fixed service pipe, reusing the existing native
authentication and overlapped-I/O owners. This avoids both plaintext forwarding
through the parent and falsely treating a duplicated parent pipe as having the
child's kernel client identity. The closed
[protocol](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/pairing_handoff.rs)
and [CLI](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/contract.rs)
carry bounded public correlations and native binding candidates only. They add
no arbitrary executable, handle-import, drawing, input, signing or enrollment API.

## Original time and one-use lifetime

Renderer startup, connection and acknowledgement cannot renew the original
five-minute attempt or its closing reserve. QPC/QPF supplies a shared local
monotonic cutoff because GetTickCount64's update resolution cannot establish the
required non-extending conversion. The implementation floors checked integer
conversions and reserves `ceil(f/1e9)+2` counter ticks for Instant conversion and
cross-thread ordering uncertainty; invalid frequency, regression and overflow
fail closed.

The freshly constructed creation environment contains one mandatory bounded
public cutoff record. The
[renderer entry](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/ffi/pairing_client/renderer.rs)
captures it once before connecting, with no fallback startup TTL. Local budget
conversion samples Instant before QPC; absolute-cutoff checks remain mandatory.
The service independently matches the child's Hello cutoff to the original
registered/narrowed value. Environment data is a safety bound, not authority.

The [enclosing HelperRun](/E:/Windows_UAC_Remote_Controller/crates/windows-service-host/src/ffi/pairing_client/helper_launch.rs)
retains its original client reservation through child and desktop cleanup.
Draining one pipe cannot permit a replacement while required owners remain.
Normal termination requires:

```text
all three CloseAcks → renderer pipe EOF → actual child exit and inspection drain
                   → original control EOF and held-launch cleanup
```

The parent acknowledges Close without waiting for child exit; the renderer stays
alive after its Ack until service EOF. This preserves the server's post-read
liveness checks and avoids an exit/ack deadlock. Stop, expiry and errors instead
cancel and drain, preserving the original failure separately from cleanup.
Pending or uncertain native ownership cannot become successful quiescence or
rearm through timeout, Drop or a repeated close attempt.

A suspended child cannot cooperatively exit before it runs. The sole termination
exception is therefore one attempt through the exact handle returned by this
owner's successful suspended creation, **before any ResumeThread attempt**.
Resume-attempt is latched before the OS call: failed or uncertain resume also
disables this exception permanently. There is no PID kill, resumed-child kill,
retry or imported job-kill policy. Termination still requires actual signalling
and exit observation before ownership is released; it is not registration or
approval success.

## Consequences and qualification boundary

This is **NONVISUAL bootstrap**, not a completed protected display: no application
window, QR, bitmap, font, input-desktop switch, secret-input method or public
canPair capability exists. Later native UI must be added inside this same final
renderer under Superloopy, while Tauri remains the management shell.

Creation-time child descriptors and parent handle-right reduction do not prove
the old parent's default read/DUP_HANDLE policy or absence of previously opened
handles. Parent duplication/injection, child memory and loaded-code isolation,
actual access-mask compatibility, cross-session object inspection, presentation/
capture isolation and safe return/crash behavior require native qualification.
No claim that High MIC supplies confidentiality is made.

Actual fresh/install issuance provenance, first-install entitlement, provisioned
carrier/route, release signer and attestation/possession policy, phone scanning
and the existing durable enrollment-receipt composition remain separate gates.
The [canonical invitation](/E:/Windows_UAC_Remote_Controller/docs/adr/0020-canonical-pairing-invitation.md)
is reused later; no substitute route, key, grant or registry is invented here.
Provider failure `0x80090030` is not repaired by renderer bootstrap.

ROOT owns executable quality checks and retained CI/native evidence. Source
fixtures and static review are not proof of real UAC, confidential pixels,
physical-phone acceptance or end-to-end pairing. This decision is not the final
architecture-refactoring phase and authorizes no local native experiment.
