# Local diagnostic files

Windows writes metadata-only JSON lines without requiring the PC GUI to be open:

`%ProgramData%\UACRemoteController-Logs\diagnostics.jsonl`

The activity page's **Open log folder** button opens this fixed directory in
Explorer. No administrator confirmation is needed to read or copy it. An absent
directory is reported as an open failure; the GUI does not create privileged
folders. Starting the updated service creates the diagnostic folder if its fixed
location passes the protected-path checks.

The folder action requires a normally launched, unelevated GUI. An elevated GUI
does not invoke user-configured shell handlers; open the folder from ordinary
Explorer or relaunch the app without administrator elevation.

## Contents and access

- Committed activity outcomes, service startup failure codes, process-startup
  guard phases and native prompt refusal reasons. A stored external-access
  setting the service could not parse is recorded as `configuration_ignored`;
  the service then starts in automatic mode.
- Schema/version, process ID and timestamp (or null if unavailable).
- No program names, request bodies, full command lines, device identities,
  public/private keys, credentials, signatures, QR contents or arbitrary errors.
- Local built-in Users may read. Only SYSTEM/Administrators may write.
- The original private activity journal, enrollment records and keys retain their
  existing ACLs. These public diagnostics are never read as authorization state.
- File IO failure, lock contention or unsafe preexisting paths drop a diagnostic
  only; they do not grant authority, recreate keys or restart the service.

The file is capped at1MiB. When the next record would exceed the cap, it restarts
from that new record. This is a bounded troubleshooting log, not a tamper-proof
audit archive. Copy relevant records before rollover. The protected activity
journal retains its own independent retention policy. Ordinary users cannot
delete or edit the shared log; automatic rollover limits disk usage.

PowerShell read example (normal user, no GUI):

```powershell
Get-Content -LiteralPath "$env:ProgramData\UACRemoteController-Logs\diagnostics.jsonl" -Tail 50
```

Windows Event Log diagnostics remain available independently, including when the
public file cannot be opened.

Android keeps bounded `UacBoot` / `UacNative` closed-token diagnostics in its
device-protected private no-backup storage as well as the existing developer
logcat stream. The Activity page's **Export diagnostic logs** action creates a
text file under `Downloads/UAC Remote Approval` and opens the Android Sharesheet.
The file is user-owned and can be selected later from a file picker. No
`READ_LOGS` or storage permission is requested: only this app's private bounded
records and the app's own currently available `UacNative` log buffer are
considered. The exported file contains no request bodies, program details,
device identities, keys, credentials or signatures. Export is explicit; the app
never uploads the file or chooses a recipient.

The separate **Save diagnostic log to file** action opens Android's system file
picker. Choose device storage/Downloads or another available document provider.
The app reports success after writing to that selected document; cancelling the
picker is not an error. It does not open the Sharesheet. The existing export
action remains available when sharing is wanted. Both actions work independently
of service/history readiness and serialize repeated requests.
