# ADR 0012: bind native TLS and queued approval writes to live owner state

Status: implementation; ROOT CI required. No whole-product/native acceptance claim.

## Native transport key

The native Rust factory creates a Client-only TLS identity from the existing
phone owner and exact current peer association. It does not choose an address,
enroll a peer, open a socket or start Application intake. Its private signer
mints an opaque one-shot input only from secure-channel's real, validated Client
TLS1.3 CertificateVerify message. The generated ABI6 exports no input/binding
constructor or generic signing command.

The same AndroidNativePlatform and DeviceKeyStore capture the exact original
TRANSPORT key registration/reference. Release/reopen with equal public bytes
cannot rebind an old signer. Each direct off-main callback rechecks native key
policy, identity, hardware, credential storage and secure-lock observations;
signs the full fixed130/146-byte input once with SHA256withECDSA; and returns
bounded DER for the existing Rust TLS verifier. No approval/denial key,
BiometricPrompt, positive auth window, private export or fallback is used.

One private identity/Channel owns the signer; concurrent callbacks are rejected.
Closing an identity invalidates its binding before its at-most-one native release
callback. The native adapter keeps partial/failed wrapper cleanup in its bounded
map until explicit owner cleanup. Successful temporary/binding closes are not
repeated, entries are removed last, and canonical persistent key references are
not released merely because one TLS connection closes.

## Downward state leases

DurableInbox owns a nonpersistent registry of at most64 weak leases (up to32
connections and32 queued messages). Only dead weak references release capacity;
cloning shares an entry and revoked-but-retained leases still count. A lease
captures exact association/local tuple and owner instance. Request leases also
capture the original mapped window and nonzero receiving generation.

Every successful owner transaction reconciles these leases against current
state before returning. Withdrawal, registration/key changes, source expiry,
faults, failed commits, unwinds and owner Drop invalidate applicable leases.
Harmless no-ops/history changes do not cancel valid sends. Invalidation is
irreversible; leases are not stored, restored, paired grants or action permits.
The new core snapshot predicate only supports downward invalidation and cannot
replace fresh committed request checks.

## Actual approval output

AssociatedPcSocket accepts only a prepared ApprovalSubmission, not caller bytes.
It checks the original owner, association, local tuple, current connection/service
epoch, committed pending request and fresh native time/policy after blocking IO.
Busy/not-ready cases retain the same signature and original deadline for bounded
caller retry; they do not create another authentication window.

The queue retains SharedPlan cancellation, a live request lease and connection
state through all TLS buffers and partial TCP writes. A socket-domain observation
is taken before the final phone-clock read; adding the remaining original TTL to
that earlier Instant does not extend the request deadline. Both clock domains
must use the same suspend-inclusive native projection. The SocketDriver uses
the minimum of that absolute deadline and its original10second frame deadline,
checks guard/time around work and every partial write, and clears the guard only
at actual drain or terminal cleanup. Already handed-to-TCP bytes cannot be recalled.

If an authenticated clock response changes service epoch while an approval is
queued, the committed clock update is preserved and the connection is aborted.
Native clock errors also abort while preserving already committed maintenance.
There is no claim of an atomic transaction with the remote PC.

A queued receipt distinguishes Queued, WrittenToSocket and Stopped. Stopped can
mean partial/uncertain transport, not proof the peer received nothing. WrittenToSocket
means local TCP accepted the ciphertext, not peer receipt or Windows approval.
The PC must independently verify the signature, current enrollment/revision,
original request binding/deadline and one-time native action before reporting an
outcome. Phone history is not marked approved merely because bytes drained.

## Remaining native integration

The Application policy-only startup gate is unchanged. Real registered connection
provisioning, foreground intake/notification posting and recovery, denial, outgoing
native actor ownership, PC service receive/action wiring and QR ceremony still
remain. Quiet-hours/timezone transitions require the foreground owner to wake,
poll/update policy and reconcile leases; passage of wall time alone does not
change an atomic lease. This slice does not claim that missing native scheduler.

ROOT runs real loopback/host tests, actual TLS/callback integration, JVM/package
and full quality gates. Synthetic software keys/host files do not prove Android
Keystore, actual phone authentication, real UAC or4G latency. User-deferred native
acceptance remains unverified. No cleanup of C:/E: occurs during programming.
