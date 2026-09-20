# SPDX-License-Identifier: GPL-2.0-or-later
# Pure, closed projection. Never prints a rejected record or arbitrary OS text.
function ConvertFrom-UacStartupDiagnostic {
    param([AllowNull()][object]$Value)
    if ($Value -isnot [string] -or $Value.Length -gt 256) { return $null }
    $phases = 'context|installation|scm|scm_status|scm_state|scm_process|scm_controls|startup_before|service_sid|subject_before|logon_before|read_before|merge|merged_shape|native_acl_validation|startup_before_set|read_before_set|descriptor_drift|subject_before_set|stop_before_set|set_dacl|subject_after|read_after|readback|startup_after'
    $classes = 'windows|identity_windows|permissions|path|installation|configuration|identity_policy|identity_malformed|service'
    $pattern = '\AUAC_STARTUP_V1 version=(?<version>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:-alpha\.[0-9]{1,5})?) pid=(?<pid>[0-9]{1,10}) stage=7 phase=(?<phase>' + $phases + ') class=(?<class>' + $classes + ') code=(?<code>[0-9a-f]{8}) policy=(?<policy>0|[1-9]|1[0-9])\z'
    $match = [regex]::Match($Value, $pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { return $null }
    [uint32]$processNumber = 0
    if (-not [uint32]::TryParse($match.Groups['pid'].Value, [ref]$processNumber) -or $processNumber -eq 0) { return $null }
    [pscustomobject]@{
        schema = 1
        version = $match.Groups['version'].Value
        processId = $processNumber
        startupStage = 7
        phase = $match.Groups['phase'].Value
        category = $match.Groups['class'].Value
        nativeCode = $match.Groups['code'].Value
        policyReason = [int]$match.Groups['policy'].Value
    }
}
Export-ModuleMember -Function ConvertFrom-UacStartupDiagnostic
