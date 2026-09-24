# Reboot startup failure: observation, comparison and repair

Date: 2026-09-22. Author: ROOT.

## What the shipped diagnostic finally produced

The 2026-09-19 diagnostic addition (see `../20260919-finalization/startup-diagnostics.md`)
was added without a reading. It now has one.

Kernel boot 2026-09-22 20:35:09 KST, SCM event 7024 at 20:35:17 with
service-specific code `3841982471` (`0xE5000007`). Application log, source
`UACRemoteController.Startup`, event 7:

```
UAC_STARTUP_V1 version=1.0.0 pid=5792 stage=7 phase=scm class=configuration code=00000000 policy=0
```

`C:\ProgramData\UACRemoteController-Logs\diagnostics.jsonl` carries the same
observation as `startup_guard phase=2 policy=0 code=0` then `startup_failure
stage=7 code=5`. The 2026-09-20 boot recorded the identical phase and class on
`0.1.0-alpha.38`.

This is the payoff the addition was made for. Before it, stage 7 named only
`provision_current_process_observer`. It now names the subphase, which excludes
every later observer step: token facts, descriptor read, merge, `SetSecurityInfo`
and readback were never reached, and neither was identity key work or Ready.

The installed binary reports `1.0.0`. `git diff 5e0f0b9..HEAD` over
`native.rs`, `runtime.rs`, `startup_phase.rs`, `ffi/process_observer.rs`,
`ffi/process_observer/`, `ffi/filesystem.rs` and `policy.rs` is empty, so the
installed startup path is the current source. The alpha.39 `scm_status`/
`scm_state`/`scm_process`/`scm_controls` split is present in it, which rules out
the earlier stale-`StartPending` hypothesis: `scm` now covers only
`registered_service_for_probe`.

## Boot-only, with a provably correct registration

| | observed |
| --- | --- |
| Boots 09-15, 09-19, 09-20, 09-22 | all failed, same code |
| Manual start 09-21 06:46:56 and 09-22 20:57:35 | both succeeded |
| `sc qc` / `HKLM\SYSTEM\CurrentControlSet\Services\UacRemoteController` | every term `verify_config` requires is correct |
| `sc qsidtype` | `UNRESTRICTED`, as required |

`ImagePath` is `"C:\Program Files\휴대폰 승인\uac-service.exe" service`,
`Type` 0x10, `Start` 2, `ErrorControl` 1, `ObjectName` `LocalSystem`,
`DisplayName` `휴대폰 승인`, no dependencies, no load-order group. Both the
failing boot start and the succeeding manual start run as LocalSystem from that
same registration. Source reading cannot narrow this further, because one phase
label still covers eleven distinct checks.

## Comparison with the MacType Tauri service on the same PC

`E:\mactype_tauri` runs `MacTypeControlCenter`, a plain `AUTO_START`,
`WIN32_OWN_PROCESS`, `LocalSystem` service with no dependencies, and it survives
reboot. Two differences matter.

**It has an SCM recovery contract and this product had none.**
`service-runtime/setup/src/windows/scm/configuration/metadata.rs` applies a
fixed plan: restart after 5 s, restart after 30 s, reset period 86400 s, and
`IncludeNonCrashFailures(true)`. `sc qfailure MacTypeControlCenter` and
`sc qfailureflag MacTypeControlCenter` confirm it on the installed service.
`sc qfailure UacRemoteController` returned reset period 0 and no actions.

The flag is the decisive half. A refused startup here reports `SERVICE_STOPPED`
with a service-specific code, which Windows does not classify as a crash, so
without `fFailureActionsOnNonCrashFailures` no recovery action would apply to
exactly the failure this product produces. One failed automatic start therefore
left the service stopped until a person pressed the button.

**It compares the registered image path by normalization, not by string.**
`service_configuration.rs:75` parses the quoted path out of `ImagePath`,
canonicalizes both it and the protected root, and checks containment. This
product compared the whole command line with `==` against a path built from
`SHGetKnownFolderPath`, while `validate_installation` in the same crate already
compared the same path with `eq_ignore_ascii_case`. A registration that the
binary-identity check accepts could therefore be refused by the registration
check on ASCII case alone.

## Repair

1. `native.rs` now applies the same bounded recovery contract at install time,
   including the non-crash flag, and also repairs an already running
   registration installed before the contract existed. No reboot action and no
   command line is configured. Every restart re-runs the whole fail-closed
   startup sequence, so this bounds the outage without relaxing admission.
2. `policy::command_matches` keeps the quoting shape and the single fixed
   argument exact and compares only the path itself ASCII case-insensitively,
   the way Windows compares paths and the way this crate's own binary-identity
   check already did. A short 8.3 alias, a different folder, an extra argument
   and an unquoted command all stay refused; tests cover each.
3. `registered_service_for_probe` reports a closed `RegistrationRejection`
   naming which fixed term refused it, and the startup trace narrows `scm` to
   one of fifteen phases (`scm_open`, `scm_config_binary_path`,
   `scm_config_service_type`, `scm_sid_type`, and so on). Admission, the
   returned error and the SCM exit code are unchanged. The record keeps its
   fixed bounded ASCII schema; only new phase literals were added, and the
   read-only PowerShell projection accepts exactly those.

## What is still open

The exact term that refuses the boot start is not yet established. Item 2 is the
only mechanically possible cause that survives the evidence above, but it is not
proven, and it is defensible on its own as an internal inconsistency. Item 3
settles it at the next boot that still fails. Item 1 keeps the service running
either way, which is what the user requires; it is a bounded recovery, not a
cure, and this document must not be read as claiming the first attempt now
succeeds.

Nothing here was verified against a real reboot yet. The next cold boot supplies
that evidence: either no 7024 at all, or a 7024 followed by a successful restart
and an Application event naming the exact term.
