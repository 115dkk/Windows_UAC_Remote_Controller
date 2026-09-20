# SPDX-License-Identifier: GPL-2.0-or-later
# Read-only, bounded, payload-free diagnostics. Never opens UAC or starts/stops
# a product process. Records are hints, not authorization/sender attestations.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][DateTimeOffset]$Since)
$ErrorActionPreference = 'Stop'
$now = [DateTimeOffset]::UtcNow
if ($Since -gt $now -or ($now - $Since).TotalMinutes -gt 30) {
    throw 'Select a start time within the last 30 minutes.'
}
$stamp = $Since.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
$query = "*[System[Provider[@Name='UACRemoteController.Pairing'] and TimeCreated[@SystemTime>='$stamp']]]"
$events = @()
try { $events = @(Get-WinEvent -LogName Application -FilterXPath $query -MaxEvents 128) }
catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
$points = @('HelperEnter','HelperConnected','RendezvousBound','HelperFailure','RendererCreate','RendererCreated','RendererResume','RendererEnter','RendererConnected','RendererObjectsReady','RendererBound','WindowOpened','RendererFailure','ServiceFailure')
$classes = @('ok','client-native','launch-native','helper-exit','client','launch','peer-native','peer','service','service-pairing','renderer-native','windows')
$invalid = 0
$records = @(foreach ($event in ($events | Sort-Object RecordId)) {
    if ($event.Id -ne 1 -or $event.Properties.Count -lt 1 -or $event.Properties.Count -gt 2) { $invalid++; continue }
    if ($event.Properties.Count -eq 2) {
        $binary = $event.Properties[1].Value
        if ($null -ne $binary -and -not ($binary -is [byte[]] -and $binary.Length -eq 0)) { $invalid++; continue }
    }
    $value = $event.Properties[0].Value
    if ($value -isnot [string] -or $value.Length -gt 256 -or $value -cnotmatch '^UAC_PAIR_V1 version=([0-9A-Za-z.+-]{1,40}) pid=([0-9]{1,10}) point=([A-Za-z]{1,32}) class=([a-z-]{1,32}) stage=([A-Za-z0-9_]{1,64}|fixed-code|user-cancelled) code=([0-9a-f]{8})$') { $invalid++; continue }
    $fields = $Matches.Clone()
    [uint32]$observedPid = 0
    if (-not [uint32]::TryParse($fields[2], [ref]$observedPid) -or $observedPid -eq 0 -or $fields[3] -notin $points -or $fields[4] -notin $classes) { $invalid++; continue }
    [ordered]@{ time = $event.TimeCreated.ToUniversalTime().ToString('o'); recordId = $event.RecordId;
        version = $fields[1]; pid = $observedPid; point = $fields[3]; category = $fields[4]; stage = $fields[5]; code = $fields[6] }
})
[ordered]@{ schema = 'UAC_PAIR_V1'; records = $records; invalidRecords = $invalid;
    scope = 'Local diagnostics only; no QR/key/credential content or authorization proof.' } | ConvertTo-Json -Depth 5
