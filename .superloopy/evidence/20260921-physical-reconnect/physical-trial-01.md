# Physical trial 01 — unconfirmed, excluded from latency samples

ROOT executed the explicitly requested fixed Windows canary once with an
unelevated interactive parent and no existing consent process. The command was
the system cmd.exe with /d /c exit 0; no dialog or biometric was automated.

- Installed phone: physical SM-S948N, 1.2.0-alpha.1, existing pairing retained.
- Windows service: Running, PID20508, exit code0. Public diagnostics only.
- Request start: Unix milliseconds1789995061711.
- Whole request wait:122378.0128ms; process exit not observed.
- PhoneDecisionVerified approve records:0; WindowsApplied approve records:0.
- Public request events showed observed/notification_sent, cancellation, then
  observation/notification again; no verified phone decision or application.
- Phone was observed Dozing. That does not by itself establish the cancellation
  cause. A later observation still showed a READY foreground-service owner.

This is not an authentication latency sample. The wait includes request
delivery, user reaction and an unconfirmed end. Ping/TCP reachability and a
software-phone CI denial are also excluded from physical authentication timing.
No mean, percentile, time-to-authentication or post-authentication latency can
be derived from this trial.

Next valid trial needs the instrumented same-signer APK, actual user OS
authentication, eligible same-request receipt, and controlled Windows verified
decision/application/process completion. The phone receipt alone does not prove
which paired phone won a multi-approver race. No keys, request body, program
details from unrelated requests, or device serial are stored here.
