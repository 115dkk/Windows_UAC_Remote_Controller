# CI software phone fixture

Non-shipping, one-shot GitHub Windows CI process. It is a separate protocol peer,
not an Android application, hardware-backed key owner, biometric authenticator,
or substitute for user acceptance testing. ROOT runs validation in CI.

Launch with no arguments and private redirected stdin/stdout. Required markers:
`CI=true`, `GITHUB_ACTIONS=true`, `RUNNER_OS=Windows`, numeric `GITHUB_RUN_ID`, and
`WUAC_CI_PHONE_FIXTURE=1`; target OS must be Windows. These markers prevent
accidental use, not malicious local impersonation. Service protection comes from
its separately gated non-shipping lab configuration and normal privileged trust
boundary. Never enable synthetic roots in shipping builds.

## Private control protocol

Send one JSON object per newline. Do not echo these commands or enable process
transcription. No key is accepted as input, exported, or persisted. The process
has no approval, generic signing, listening, input-injection, or execution API.

1. `prepare` optionally includes `expected_relay_ip`. Default is `127.0.0.1`.
   For the embedded relay's LAN address, the native harness must independently
   verify the supplied IP belongs to this CI runner before sending it. The QR
   must match this exact IP and port 7443; its route is retained unchanged.
   `prepared` returns **public** `root_der_base64`, `app_signer_sha256` ([8;32]),
   package `dev.dkk115.uacremote`, and explicit software-fixture identity.
   ROOT installs only that public root in its protected CI-only service policy.
2. `enroll_pixels` includes `png_base64` containing an actual native-screen PNG.
   The process bounds decoded PNG to 8 MiB, each dimension to 4096 pixels,
   decoder allocations to 128 MiB, requires exactly one detected QR, and decodes
   it privately with rqrr. It accepts only canonical pairing invitation text.
   For a harness that already decodes real pixels privately, `enroll` with `qr`
   uses the same enrollment path. Neither form is written or echoed.
3. Wait for `awaiting_comparison`. Send `confirm_comparison` with `code` containing
   the six digits read from the actual PC comparison screen over a private pipe.
   The fixture independently verifies SignedFrozenCandidate against the QR-pinned
   PC key and exact original context, then compares all six digits. It sends the
   protocol phone confirmation only after that match. The state
   `phone_confirmation_queued` is local intent, not remote receipt.
4. The harness performs native PC confirmation. Wait for `enrollment_accepted`,
   emitted only after a verified SignedEnrollmentAcceptance matching nonce,
   challenge, PC/device, three-key digest, both PC keys and frozen revision,
   followed by actual transport closure. Public device ID and revision accompany
   this state. The same in-memory role keys remain owned by this process.
5. Send `deny_next` with `expected_program_name` exactly `UacCiHarmlessRequest`
   and the independently known harmless executable's `expected_path`. The name
   field is a fixed distinctive CI marker, not an exact localized UAC caption.
   If the signed content exposes a path, it must equal `expected_path` exactly;
   the marker must occur in its program name or details. If Windows omits the
   path, the marker must occur specifically in the signed details. Optional
   `expected_details_sha256` is lowercase SHA-256 of exact UTF-8 details and,
   when provided, must match exactly. ROOT isolates this single harmless launch
   and verifies that its executable did not run.
   The fixture reconnects on the retained relay route and both pinned TLS keys,
   completes a fresh signed clock-probe/epoch exchange, then emits `session_ready`.
6. Trigger the harmless native CI request **after** `session_ready`. The fixture
   verifies the signed Opened event, recomputed full content/binding digest,
   conservative clock freshness and the CI metadata constraints above. It emits
   `request_verified` with only public request
   ID/content digest, signs only Deny with the enrolled denial key, queues it,
   and verifies the service's signed Resolved event against the exact original
   binding and issuance. `pc_resolution` reports the actual signed outcome;
   anything except `denied` exits with failure. `completed` follows closure.

Any unexpected command, extra field, signature/context/metadata mismatch, expired
request, peer failure or timeout fails closed with a static error code and exit 1.
Only pixel command lines may exceed 16 KiB; their absolute line bound is 12 MiB.
The whole process is limited to 300 seconds; individual network steps to 120
seconds, close to 10 seconds. ROOT should keep the pipe private and publish only
whitelisted sanitized states, never raw input, native QR captures or panic data.

## Evidence boundary

Marker matching tolerates UAC's localized composite captions and collapsed
details; it is not proof of full UIA label fidelity or executable identity by
itself. Isolation, the known native launch, the service's native target binding,
and actual not-executed evidence remain ROOT harness responsibilities. Omitting
the optional expected details hash never omits the protocol's mandatory full
content-digest recomputation, PC signature, freshness, or exact resolution binding.

Successful execution corroborates a real native Windows enrollment and signed
request/denial transport path with a software CI peer. It does not prove Android
hardware isolation, phone authentication, real Secure Desktop approval, or actual
user UAC acceptance. The signed PC outcome is reported exactly; no pairing flag
or canned result replaces the exchange. Pure tests in `src/tests.rs` only check
fixture command/key boundaries and are not native proof.
