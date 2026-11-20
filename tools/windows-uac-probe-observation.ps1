# SPDX-License-Identifier: GPL-2.0-or-later
param(
    [Parameter(Mandatory)][string]$JournalPath,
    [Parameter(Mandatory)][long]$StartedUnixMs,
    [switch]$RequestStarted,
    [switch]$ConsentObserved
)
$ErrorActionPreference = 'Stop'
$observed = $false
if ($RequestStarted -and $ConsentObserved -and (Test-Path -LiteralPath $JournalPath)) {
    foreach ($line in (Get-Content -LiteralPath $JournalPath)) {
        if ($line -notmatch '"category":"request".*"observed"') { continue }
        try {
            $record = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }
        if ($record.event.category -eq 'request' -and
            $record.event.outcome.state -eq 'observed' -and
            [long]$record.timestamp_unix_ms -ge $StartedUnixMs) {
            $observed = $true
            break
        }
    }
}
"probe_observed=$($observed.ToString().ToLowerInvariant())"
