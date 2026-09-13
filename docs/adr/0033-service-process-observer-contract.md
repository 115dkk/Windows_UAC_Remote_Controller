<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0033: Service-owned process observation

Status: accepted for implementation; exact native validation pending.

## Context

The medium-integrity management client authenticates its local pipe, fixed SCM
registration and original process before reading metadata. Native CI at
999f818 passed the client identity, installation, SCM and pipe checks, then
failed `OpenProcess(QUERY_LIMITED_INFORMATION | SYNCHRONIZE)` with 0x80070005.
Removing process identity or termination checks would weaken that interface.

The first publisher assumed the process was owned by SYSTEM or an explicitly
known static principal. Native CI at 439cf32 instead observed an unidentified
20-byte owner SID with full process access and an Administrators ACE granting
only 0x1400. SYSTEM was not an explicit trustee. SID length is not authority;
the publisher must match an owner to its own authenticated token rather than
trust a SID shape or expand Administrators/SYSTEM access to fit a template.

## Decision

- A private, no-argument module provisions only the running service's own process
  after the original SCM Running/no-controls acknowledgement and before key work,
  Ready and listeners. Actual LocalSystem identity, enabled service SID, fixed
  protected image, original SCM self-PID, startup state and stop checks remain.
- An optional logon SID is obtained from the service's actual primary token's
  bounded groups. A flagged candidate must be unique, fully LOGON_ID-marked,
  enabled, not deny-only and exactly S-1-5-5-X-Y. No arbitrary SID matching that
  prefix is trusted. The captured token facts are rechecked around publication.
- Trusted process owners/trustees may include only the existing static trusted
  principals and that exact token-bound logon SID. Effective control is derived
  from the actual SYSTEM/service/logon subject, not from an assumed SYSTEM ACE
  or unverified Administrators membership. Documented QUERY_INFORMATION implies
  QUERY_LIMITED_INFORMATION for sufficiency checking; raw ACEs remain unchanged.
- Preserve existing trusted ACE bytes/order and administrator restrictions. Add
  or extend only a noninheriting INTERACTIVE observer ACE to exactly 0x00101000:
  limited process information and synchronization. Deny, unknown, malformed,
  inherited or overbroad untrusted policies remain errors, not repair targets.
- Publish DACL only on the current process. Do not change owner, group, token,
  SACL, integrity, privileges, other processes or Windows/UAC policy. Mandatory
  owner/group/DACL reads and exact permitted readback remain. MIC/SACL preservation
  follows the setter's strict scope, not a claim that their contents were read.
- Do not remove any client identity/image/SCM/pipe/liveness fence, introduce a
  generic PID/descriptor operation, or repair a foreign process from presentation.
  Each new service process establishes its own observation contract.

## Validation and limits

Pure tests cover descriptor bounds, wrong principals, absent/changed logon
identity, legacy right implications, denied or excess rights and readback.
They are not native evidence. CI must additionally exercise the real medium GUI
and retain the same service/listener through repeated reads and rejected clients.
Nineteen native sensitive process/token handle-acquisition controls must fail with
access denied; unexpected handles are closed unused and a sticky failure prevents
later retries from erasing the finding. Diagnostics use bounded fixed classes and
numeric metadata, not SID values, keys, credentials or request contents.

Native calls are not interruptible or an atomic policy compare-and-swap. Startup
rechecks reject observed drift/stop and retain the original budget; no rollback,
permission escalation or retry mutation is promised. Actual process default-policy
compatibility remains a CI gate. Real UAC approval and phone authentication remain
separate user acceptance items.
