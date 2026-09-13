# SPDX-License-Identifier: GPL-2.0-or-later
# Official GUI prerequisite on a disposable CI VM, never a product installer hook.
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted Windows CI only' }
function Read-MachineRuntime {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
        try {
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')
            if ($null -ne $key) {
                try {
                    $value = $key.GetValue('pv')
                    if ($value -is [string] -and $value -match '^\d+\.\d+\.\d+\.\d+$' -and [version]$value -gt [version]'0.0.0.0') { return $value }
                } finally { $key.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    return $null
}
$before = Read-MachineRuntime
Write-Output ("Machine WebView2 before setup: {0}" -f $(if($before){$before}else{'absent'}))
if (-not $before) {
    $directory = Join-Path $env:ProgramFiles ('UacCiWebView2-' + [guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $directory) { throw 'Fresh protected SDK directory required' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    $installer = Join-Path $directory 'MicrosoftEdgeWebview2Setup.exe'
    # Microsoft-owned link published in MicrosoftEdge/WebView2Samples.
    Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $installer -TimeoutSec 120
    # Deny replacement/deletion through signature check and the owned launch.
    $pin = [IO.File]::Open($installer,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|, )O=Microsoft Corporation(?:,|$)') { throw 'Microsoft installer signature required' }
        $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
        $process = Start-Process -FilePath $installer -ArgumentList '/silent','/install' -WindowStyle Hidden -PassThru
        if (-not $process.WaitForExit(180000)) { throw 'Official runtime setup completion unknown' }
        if ($process.ExitCode -ne 0) { throw "Official runtime setup failed: $($process.ExitCode)" }
    } finally { $pin.Dispose() }
    Write-Output ("Microsoft bootstrapper SHA256: {0}" -f $hash)
}
$until = [DateTime]::UtcNow.AddSeconds(60)
do {
    $after = Read-MachineRuntime
    if ($after) { break }
    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $until)
if (-not $after) { throw 'Per-machine WebView2 runtime registration missing' }
Write-Output ("Machine WebView2 ready for the standard user: {0}" -f $after)
