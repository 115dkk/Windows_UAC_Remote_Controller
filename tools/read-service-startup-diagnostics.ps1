# SPDX-License-Identifier: GPL-2.0-or-later
# Read only: never starts a service, changes logging registration or writes files.
param(
    [ValidateRange(1, 7)][int]$Days = 1,
    [ValidateRange(1, 32)][int]$MaximumRecords = 16
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'service-startup-diagnostic.psm1') -Force
$records = @()
$available = $true
try {
    # XPath selects actual records without requiring provider registry metadata.
    # An unregistered classic source intentionally uses the Application log.
    $lookbackMillis = [long]$Days * 86400000
    $filter = "*[System[Provider[@Name='UACRemoteController.Startup'] and (EventID=7) and TimeCreated[timediff(@SystemTime) <= $lookbackMillis]]]"
    $events = @(Get-WinEvent -LogName Application -FilterXPath $filter -MaxEvents $MaximumRecords -ErrorAction Stop)
    foreach ($event in $events) {
        if ($event.Properties.Count -ne 1) { continue }
        $row = ConvertFrom-UacStartupDiagnostic $event.Properties[0].Value
        if ($null -ne $row -and $null -ne $event.TimeCreated) {
            $row | Add-Member -NotePropertyName observedUtc -NotePropertyValue ($event.TimeCreated.ToUniversalTime().ToString('o'))
            $records += $row
        }
    }
} catch {
    # No Message/XML/error text is emitted. An empty successful query is distinct
    # from permission/provider/log access failure; old versions emit no records.
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $available = $false }
}
[pscustomobject]@{ available = $available; records = @($records) } | ConvertTo-Json -Depth 4
