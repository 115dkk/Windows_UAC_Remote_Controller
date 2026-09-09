# ADR 0011: bind each native authentication to one original approval request

Status: implemented source boundary; actual Android authentication and complete
request/delivery integration remain unverified. This is not production activation.

## Decision

Keep one process-local `ApprovalPlanOwner` beside the existing `DurableInbox`.
It uses the original receiving generation introduced in ADR0010, full immutable
request/window, exact current peer association and local key tuple. A local key
record alone cannot produce a plan. A selection supplies only the full request
identifiers; it cannot supply a statement, key, purpose, generation or auth flag.

Begin, claim and finish retain committed CHECK effects and observe actual native
time after blocking commits. Finish also observes time after signature verification.
The original conservative deadline and current notification policy still apply.
Claims and finish are one-shot across copied generated handles. Cancel is immediate
shared atomic invalidation, including an already claimed signing attempt. Cancel
does not mean a native crypto operation stopped; slot retirement requires actual
terminal cleanup. Process death, owner close and owner replacement cannot restore
authentication or adopt old handles. None of this state is serialized.

The generated ABI5 exposes opaque plan/attempt/submission objects, with no public
constructors or generic signer. Its exclusive admitted operation temporarily
moves both Rust owners outside their mutexes before native clock callbacks. A
callback re-entry sees Busy. An unwind guard invalidates outstanding handles and
retains downward cleanup obligations. Native preparation, human authentication
and actual key signing occur after the Rust call/admission has returned.

## Android operation

The existing Application actor retains the same AndroidNativePlatform and
DeviceKeyStore. One bounded auth slot uses the existing worker; a separate Activity
or receiver never creates another controller/key owner. The exact already
registered APPROVAL key is inspected again for hardware policy, public identity,
credential storage and configured secure lock. No key is generated or silently
reopened in response to an approval failure.

Initialize exactly one AndroidKeyStore `SHA256withECDSA` Signature and give that
object to API30+ platform BiometricPrompt as its CryptoObject. Use strong biometric
OR device credential; PIN/pattern/password-only devices are eligible. Only the
actual native success callback with the exact retained Signature object can
advance. A success boolean, unlocked-device flag, another Signature or a positive
authentication window is not equivalent. No private key/Signature/CryptoObject
getter or raw byte-signing entry point is exported.

The actual resumed MainActivity instance presents the prompt. Credential UI can
pause/cover it; completion waits for that same host to resume. Destruction,
replacement, explicit request-view departure or original expiry cancels. No
new Activity inherits a prompt or successful authentication. Sign and finish are
separate FIFO worker phases so queued domain changes can precede finish. Native
terminal cleanup has reserved bounded queue capacity/retry from worker finally
paths; cancellation cannot release a still-running native signing slot.

The fixed canonical Approve statement is passed to the retained Signature without
prehashing; native DER is bounded to72bytes. Rust parses canonical DER and verifies
against the frozen approval key, retaining the protocol's valid high-S handling.
Only explicit missing-lock observation yields LockRequired; unavailable/unsupported
observations do not tell an already configured user to enable a lock again.

## Results, cleanup and limits

`NativeApprovalSubmission` means prepared signature data only. It exports neither
wire bytes nor a Windows-success result. Native holder retirement after successful
finish closes its preparation phase without canceling the independently retained
submission. Explicit cancellation and owner shutdown still invalidate it.

Committed request withdrawals invalidate the corresponding native operation before
notification cancellation. Terminal history remains in the existing durable outcome
outbox. It is not relabelled as an outgoing decision outbox or a Windows approval.
No late/duplicate callback restarts or extends an operation. Generated handles are
retired only after native quiescence; uncertain OS cancellation retains the slot.

The Application's existing policy-only startup gate remains. This slice does not
install a sample request, enable a Tauri approval action, start background pairing,
claim QR/attestation authority, send a decision, implement denial, or trigger Windows
input. The real enrolled intake/notification dispatcher, outgoing delivery owner
and Windows application of a decision must still be connected. Actual biometric,
PIN, hardware Keystore, OS lifecycle and end-to-end acceptance are user-deferred.
Pure Rust/JVM tests and an APK build are not substitutes for those results.

## References

- https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt
- https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int)
- https://developer.android.com/reference/android/app/Application.ActivityLifecycleCallbacks
