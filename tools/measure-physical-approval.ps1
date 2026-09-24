# SPDX-License-Identifier: GPL-2.0-or-later
<# One explicitly requested, harmless Windows UAC measurement.
   User performs the real phone approval/authentication. No dialog automation.
   This first interval includes request delivery and human reaction; it is not
   the isolated authentication or post-authentication latency. #>
[CmdletBinding()]
param([switch]$Run)
$ErrorActionPreference = 'Stop'
if (-not $Run) { throw 'Explicit -Run is required for one real UAC request.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'A normal interactive unelevated requester is required.'
}
if (@(Get-Process consent -ErrorAction SilentlyContinue).Count -ne 0) { throw 'An existing UAC request must finish first.' }
$service = Get-CimInstance Win32_Service -Filter "Name='UacRemoteController'"
if ($service.State -ne 'Running') { throw 'Controller service must be running.' }
$command = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
if (-not (Test-Path -LiteralPath $command -PathType Leaf)) { throw 'Windows command processor unavailable.' }
$started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$clock = [Diagnostics.Stopwatch]::StartNew()
$result = [ordered]@{
    schema = 1
    scope = 'real_windows_request_to_process_exit_including_human_reaction'
    requestedAction = 'approve'
    startedUnixMillis = $started
    requestToProcessExitMillis = $null
    requestElapsedMillis = $null
    processExitCode = $null
    requestErrorCode = $null
    windowsOutcome = 'unconfirmed'
    phoneVerifiedRecords = 0
    windowsAppliedRecords = 0
    isolatedAuthenticationLatencyMeasured = $false
    controlledRemotePathObserved = $false
}
try {
    # /d disables CMD AutoRun. The fixed command only exits; no files/settings.
    $child = Start-Process -FilePath $command -ArgumentList @('/d', '/c', 'exit', '0') -Verb RunAs -PassThru
    if ($null -eq $child -or -not $child.WaitForExit(30000)) { throw 'Fixed test process completion not observed.' }
    $child.Refresh()
    $result.requestToProcessExitMillis = $clock.Elapsed.TotalMilliseconds
    $result.processExitCode = $child.ExitCode
    if ($child.ExitCode -eq 0) { $result.windowsOutcome = 'process_completed' }
} catch {
    $native = $_.Exception
    while ($native.InnerException) { $native = $native.InnerException }
    if ($native -is [ComponentModel.Win32Exception]) {
        $result.requestErrorCode = $native.NativeErrorCode
        if ($native.NativeErrorCode -eq 1223) { $result.windowsOutcome = 'cancelled' }
    }
} finally {
    $clock.Stop()
    $result.requestElapsedMillis = $clock.Elapsed.TotalMilliseconds
    # Read only the existing public closed-token diagnostics. No private journal.
    $log = 'C:\ProgramData\UACRemoteController-Logs\diagnostics.jsonl'
    if (Test-Path -LiteralPath $log) {
        foreach ($line in Get-Content -LiteralPath $log -Tail 100) {
            try {
                $record = $line | ConvertFrom-Json
                if ($record.pid -ne $service.ProcessId -or $record.unix_millis -lt $started -or $record.event.category -ne 'request') { continue }
                if ($record.event.outcome.state -eq 'phone_decision_verified' -and $record.event.outcome.detail.decision -eq 'approve') { $result.phoneVerifiedRecords++ }
                if ($record.event.outcome.state -eq 'windows_applied' -and $record.event.outcome.detail.decision -eq 'approve') { $result.windowsAppliedRecords++ }
            } catch { }
        }
    }
    $result.controlledRemotePathObserved = $result.windowsOutcome -eq 'process_completed' -and
        $result.phoneVerifiedRecords -eq 1 -and $result.windowsAppliedRecords -eq 1
    $result | ConvertTo-Json
}
