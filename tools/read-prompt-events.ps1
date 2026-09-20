# SPDX-License-Identifier: GPL-2.0-or-later
# Read-only, bounded, payload-free diagnostics. Never opens UAC or starts/stops
# a product process. Reads the structure rows the probe wrote for a consent
# dialog, and the reason Windows refused a decision the phone already signed.
# The dialog's own words are never written to the log and never appear here.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][DateTimeOffset]$Since)
$ErrorActionPreference = 'Stop'
$now = [DateTimeOffset]::UtcNow
if ($Since -gt $now -or ($now - $Since).TotalMinutes -gt 30) {
    throw 'Select a start time within the last 30 minutes.'
}
$stamp = $Since.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
$query = "*[System[Provider[@Name='UACRemoteController.Prompt'] and TimeCreated[@SystemTime>='$stamp']]]"
$events = @()
try { $events = @(Get-WinEvent -LogName Application -FilterXPath $query -MaxEvents 512) }
catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
# The rendered Message is empty because the source has no message DLL, so the
# single insertion string is the record.
$kinds = @('Text','Button','Hyperlink')
$reasons = @('UnknownTarget','TargetChanged','ContentChanged','UnrecognizedButtons','AmbiguousButtons','PatternUnavailable','InvokeFailed')
$labels = [Collections.ArrayList]::new()
$refusals = [Collections.ArrayList]::new()
$invalid = 0
foreach ($event in ($events | Sort-Object RecordId)) {
    if ($event.Id -ne 1 -or $event.Properties.Count -lt 1 -or $event.Properties.Count -gt 2) { $invalid++; continue }
    if ($event.Properties.Count -eq 2) {
        $binary = $event.Properties[1].Value
        if ($null -ne $binary -and -not ($binary -is [byte[]] -and $binary.Length -eq 0)) { $invalid++; continue }
    }
    $value = $event.Properties[0].Value
    if ($value -isnot [string] -or $value.Length -gt 256) { $invalid++; continue }
    $time = $event.TimeCreated.ToUniversalTime().ToString('o')
    if ($value -cmatch '^UAC_PROMPT_V1 version=([0-9A-Za-z.+-]{1,40}) ordinal=([0-9]{1,5}) depth=([0-9]{1,3}) kind=([A-Za-z]{1,16}) enabled=(true|false) automation=([A-Za-z0-9_.-]{1,64}) class=([A-Za-z0-9_.-]{1,64})$') {
        $fields = $Matches.Clone()
        [uint16]$ordinal = 0
        [byte]$depth = 0
        if (-not [uint16]::TryParse($fields[2], [ref]$ordinal) -or -not [byte]::TryParse($fields[3], [ref]$depth) -or $fields[4] -notin $kinds) { $invalid++; continue }
        [void]$labels.Add([ordered]@{ time = $time; recordId = $event.RecordId; version = $fields[1];
            ordinal = $ordinal; depth = $depth; kind = $fields[4]; enabled = ($fields[5] -eq 'true');
            automation = $fields[6]; class = $fields[7] })
        continue
    }
    if ($value -cmatch '^UAC_APPLY_V1 version=([0-9A-Za-z.+-]{1,40}) refused=([A-Za-z]{1,32})$') {
        $fields = $Matches.Clone()
        if ($fields[2] -notin $reasons) { $invalid++; continue }
        [void]$refusals.Add([ordered]@{ time = $time; recordId = $event.RecordId; version = $fields[1]; refused = $fields[2] })
        continue
    }
    $invalid++
}
[ordered]@{ schema = 'UAC_PROMPT_V1'; labels = @($labels); refusals = @($refusals); invalidRecords = $invalid;
    scope = 'Local diagnostics only; element identifiers and positions, never the dialog text.' } | ConvertTo-Json -Depth 5
