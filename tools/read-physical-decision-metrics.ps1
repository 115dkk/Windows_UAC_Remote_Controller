# SPDX-License-Identifier: GPL-2.0-or-later
# Read current app-process closed metrics only. Does not clear logs or invoke an
# approval. Successful authentication still needs the real user and a controlled
# same-request Windows application observation.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$sdkPath = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$adb = Join-Path $sdkPath 'platform-tools\adb.exe'
if (-not (Test-Path -LiteralPath $adb)) { throw 'Configured Android debugging client unavailable.' }
$devices = @(& $adb devices | Where-Object { $_ -match '^\S+\s+device$' })
if ($devices.Count -ne 1) { throw 'Exactly one authorized physical phone is required.' }
$serial = ($devices[0] -split '\s+')[0]
if ((& $adb -s $serial shell getprop ro.kernel.qemu).Trim() -eq '1') { throw 'Physical phone required.' }
$appProcess = (& $adb -s $serial shell pidof dev.dkk115.uacremote).Trim()
if ($appProcess -notmatch '^[1-9][0-9]{0,9}$') { throw 'Exactly one current controller process is required.' }
$pattern = '^UAC_NATIVE_DECISION_V1 sample=([0-9]{1,7}) action=(approve|deny) outcome=(approved|denied|failed|cancelled|expired|expired_locally|pc_completed) timing_eligible=(true|false) action_to_receipt_ms=([0-9]{1,6}) action_to_auth_ms=(none|[0-9]{1,6}) auth_to_receipt_ms=(none|[0-9]{1,6}) local_ready_to_receipt_ms=(none|[0-9]{1,6})$'
$seen = [Collections.Generic.HashSet[string]]::new()
foreach ($line in & $adb -s $serial shell logcat -d --pid=$appProcess -v raw 'UacNative:I' '*:S') {
    if ($line -notmatch $pattern -or -not $seen.Add($line)) { continue }
    $values = @($Matches[5], $Matches[6], $Matches[7], $Matches[8])
    if (@($values | Where-Object { $_ -ne 'none' -and [int]$_ -gt 300000 }).Count -ne 0) { continue }
    [pscustomobject]@{
        sample = [int]$Matches[1]
        action = $Matches[2]
        outcome = $Matches[3]
        scope = 'same_request_pc_result_after_local_action_not_winning_device_proof'
        timingEligible = $Matches[4] -eq 'true'
        actionToReceiptMillis = [int]$Matches[5]
        actionToAuthenticationMillis = if ($Matches[6] -eq 'none') { $null } else { [int]$Matches[6] }
        authenticationToReceiptMillis = if ($Matches[7] -eq 'none') { $null } else { [int]$Matches[7] }
        localReadyToReceiptMillis = if ($Matches[8] -eq 'none') { $null } else { [int]$Matches[8] }
        authenticationSampleCandidate = $Matches[4] -eq 'true' -and $Matches[2] -eq 'approve' -and $Matches[3] -eq 'approved' -and $Matches[6] -ne 'none' -and $Matches[7] -ne 'none'
    } | ConvertTo-Json -Compress
}
if ($LASTEXITCODE -ne 0) { throw 'Current-process metric read failed.' }
