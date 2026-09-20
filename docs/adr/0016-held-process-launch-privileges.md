<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# 0016: Require held launch privileges, not premature activation

Status: accepted source policy; actual native launch remains unverified.
Date: 2026-09-10.

The service-only prompt supervisor previously required Tcb, IncreaseQuota and
AssignPrimaryToken all already enabled. Microsoft documents the latter two as
present but disabled in an ordinary LocalSystem token. CreateProcessAsUserW
temporarily enables its necessary held privileges for that call. Requiring them
enabled before reaching the API rejects that documented default.

The native owner still resolves each fixed privilege LUID against its actual
current primary token. Missing or removed privileges reject the attempt. Tcb
must remain already enabled because the earlier TokenSessionId operation needs
it. IncreaseQuota and AssignPrimaryToken may be present-disabled; the launcher
does not call AdjustTokenPrivileges, grant account rights, change SCM policy or
fall back to another token/account/process-creation API. The documented exemption
for some restricted-token launches is not assumed: assignment privilege presence
is still conservatively required.

Preserve native64, no impersonation, actual SYSTEM/service identity, Restricted
SID, full group/privilege equality across duplication and child authentication,
session, pinned executable, fixed desktop, job, deadline and cleanup checks.
Actual API errors remain errors. If Windows does not restore attributes as
expected, the existing exact-facts check must reject the operation; it must not
be relaxed to obtain a successful launch.

Tests distinguish absent/removed privileges, default-disabled launch privileges,
enabled-by-default versus enabled-now, and disabled Tcb. They prove only the
attribute policy. Native compatibility still needs an authorized Windows test.
This occurs in the lazy prompt diagnostic path and is **not** a diagnosis or fix
for the earlier TPM/key-provider startup failure. It adds no remote approval,
generic launch endpoint or new pairing authority.

Primary contracts: [LocalSystem privileges](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account),
[CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw),
[TokenSessionId](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class),
[SetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation).
