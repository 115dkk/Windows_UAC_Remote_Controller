<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0028: Unrestricted service SID so the service can persist its identity key

Status: accepted on 2026-09-11 (Claude root) from disposable-runner evidence. Whether this also
removes the developer PC's `0x80090030` is not asserted here; that machine has not been re-tested.

## Context

Since ADR 0016 and ADR 0019 the LocalSystem service was registered with
`SERVICE_SID_TYPE_RESTRICTED`, which gives the process a write-restricted token: every write access
must pass a second check against the restricting SIDs (the service SID, WRITE RESTRICTED, Everyone
and the logon SID). The identity policy (`windows-identity`) creates one persisted ECDSA P-256 machine
key through CNG and refuses every fallback.

The service has never reached `Running` anywhere:

- Developer PC (September 10, user-authorized install): `NCryptOpenStorageProvider` on the Platform
  Crypto Provider failed with `0x80090030` inside the service, while the same call succeeded from an
  ordinary user session.
- Hosted `windows-2025` runner, lab build with the Software KSP (`windows-uac-lab.yml`, run
  34609160710 at `cfb2604`): with the restricted SID the service stopped with `0xE4000004` and the
  recorded cause was `NCryptFinalizeKey` -> `0x80090010` (`NTE_PERM`). The same binary, restarted
  after `sc.exe sidtype UacRemoteController unrestricted`, created and finalized the key and reached
  the next policy check (`ProtectedServiceDaclRequired`, `0xE100000D`, a separate descriptor
  question tracked in the lab). Nothing else differed between the two starts.

Key storage providers persist keys in system-owned locations (`%ProgramData%\Microsoft\Crypto\Keys`
for the Software KSP, the PCP key store and TBS for the TPM provider). Their descriptors grant SYSTEM
and Administrators; none of them grants a per-service SID, so a write-restricted SYSTEM token fails
the second access check. That matches the runner result exactly and is the leading explanation for
the developer PC as well (TBS access is also an access check on the caller's token).

## Decision

1. The service is registered with `SERVICE_SID_TYPE_UNRESTRICTED`. The service SID stays in the
   token as an ordinary enabled group, so every existing ACL that names it (pipes, the product data
   and trust directories, the key descriptor's second ACE) keeps working. Only the second
   write-access check disappears.
2. `install` applies the new SID type to an existing stopped registration as well, so a machine that
   still carries the restricted setting is repaired by reinstalling; every CLI verb that checked for
   the restricted type now checks for the unrestricted type and still refuses anything else.
3. The identity key policy is unchanged: LocalSystem, the service SID present, no impersonation,
   Platform Crypto Provider only in release builds, a protected DACL with exactly the SYSTEM and
   service-SID ACEs, machine key, signing only, not exportable.
4. Compensating controls that remain: the service DACL hardening (`harden_service`), the fixed
   installed image and directory pins, the private desktop and job-limited helpers, the process-wide
   admission and the fail-closed policies of ADR 0019. Nothing about UAC, Secure Desktop or LSA is
   touched.

## Consequences

- The disposable lab can now proceed past key creation and observe the real descriptor that the
  Software KSP returns; the next lab question is the `ProtectedServiceDaclRequired` mismatch.
- A future low-privilege carrier process (ADR 0018) is still the way to remove network parsing from
  the LocalSystem process; write-restriction was never a substitute for that.
- The developer PC needs one reinstall from the prerelease before any claim about `0x80090030`.
