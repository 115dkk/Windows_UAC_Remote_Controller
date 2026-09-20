# ADR 0014: retain one request's denial fence through native cleanup

Status: accepted design, implementation in progress. Actual Android key use,
notification actions, authenticated Application intake and native delivery remain
unverified. This decision does not activate a working denial button.

## Decision

Use the existing Application worker, DurableInbox and native key owner. A denial
uses the original associated request and the separate DENIAL key. It never asks
for approval authentication, substitutes for Windows credentials, creates a key
or signs renderer-supplied bytes. Configured secure screen lock and access to
credential-encrypted storage are still required; a currently locked screen after
first unlock is not the same as missing secure-lock configuration.

Reserve a bounded, body-free **denial scope** for the exact PC, service epoch and
request before cancelling that request's approval contexts. At most32 scopes are
retained strongly by Rust, even if native wrappers disappear. Duplicate selection
returns the original scope rather than a new deadline or operation. Validate actual
associated pending state and fresh native time before retaining a new scope.

The scope is also an **approval fence**. It blocks subsequent approval begin,
claim, finish and eventual send admission for the same request, including checks
after blocking callbacks. Request-scoped cancellation reaches still-live retired
submissions and partial-write guards; it does not recall bytes already written.
An unrelated request is not cancelled by this fence.

## Native drain and signing

Before denial signing, require both the actual matching Android approval session
to finish cleanup and the matching Rust native approval slot to be absent.
`has_native_slot_for` includes cancelled, terminal and logically closed slots until
explicit retirement. False is not proof of native quiescence or absence of a live
retired signature. A missing current Android session alone is also insufficient.

Native observations identify the retained session/operation associated with an
opaque scope. Copied generated wrappers are compared through Rust identity, not
Kotlin object identity or a caller-supplied identifier. Callbacks neither wait for
the sole worker nor synchronously reenter controller retirement. They schedule
one coalesced progress wake and report pending until actual cleanup completes.

One DenialOwner native slot exists alongside ApprovalPlanOwner. The native attempt
exposes only fixed canonical Deny signing bytes through one shared atomic claim.
Android uses the existing exact DENIAL reference and SHA256withECDSA without a
prehash or BiometricPrompt. It rechecks key policy, public identity, configured
secure lock, cancellation and original deadline around provider work. Rust accepts
bounded DER as input and performs strict signature and original-context checks.
PreparedDenial remains private in Rust; neither DER nor wire bytes are exported.

Native quiescence means the exact tracked operation is terminal and cannot start
again, every provider call that actually began has returned (zero calls is valid),
and temporary input/DER/holder cleanup has completed. An operation that aborts
after claiming bytes but before entering the provider can therefore be cleanly
terminal. Unknown tracking or uncertain in-flight work cannot claim quiescence.

## Cancellation, stop and release

The scope retains the original core attempt's cancellation control even after
native wrapper retirement. A strong one-time attempt reference with a weak scope
back-reference avoids ownership cycles. Successful native retirement alone does
not cancel a private prepared result; explicit scope cancellation always does.

Stop first forbids new work and cancels existing controls. It retains the exact
logically closed approval/denial owners and native cleanup cursors until retirement
and reference cleanup finish. Destroying the Rust owner before the remaining
native session can retire would prevent shutdown from completing. Cleanup-only
operations remain possible; positive operations cannot resume.

Failed cleanup retains its exact failed step and original arguments. Ordinary
progress must not repeatedly invoke that failed step. An explicit cleanup retry
allows one retry without resetting byte claims, recreating references, signing
again or returning to Ready. A failed signing operation and uncertain cleanup
are distinct states.

For the current unsent integration, cancellation plus confirmed native/core and
reference cleanup permits scope release. The future transport owner must record
possible exposure before entering queue admission. Once a frame may have been
written, cancellation, a missing body or a stopped sender alone cannot release
the fence: require matching committed terminal evidence or the original local
deadline, together with completed cleanup. Do not add an empty transport map and
label prepared data delivered. Native retirement, local write and scope release
are never Windows denial outcomes.

## Verification boundary

Root alone executes validation. Host fixtures may establish synthetic enrollment
through existing trusted-host test APIs, but request provenance must then pass
through actual loopback TLS, signed service messages and the existing commit path.
Such tests do not prove a real enrollment ceremony, Android Keystore behavior or
Windows action. Current Application constructors remain policy-only until the
complete authenticated intake/effect dispatcher and real transport owner exist.
