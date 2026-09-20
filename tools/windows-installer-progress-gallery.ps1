# SPDX-License-Identifier: GPL-2.0-or-later
# Actual NSIS/MUI page + shipped layout macro; synthetic harmless payload only.
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI only' }
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type -LiteralPath (Join-Path $PSScriptRoot 'InstallerProgressNative.cs')
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $OutputDirectory).Path
$compiler = Join-Path $env:LOCALAPPDATA 'tauri/NSIS/makensis.exe'
$results = @()
foreach ($language in @('English','Korean')) {
    foreach ($fontSize in @(9,18)) {
        foreach ($repair in @(0,1)) {
            $name = "progress-$language-font$fontSize-repair$repair"
            $executable = Join-Path $outputRoot "$name.exe"
            & $compiler /V2 "/DTEST_OUT=$executable" "/DTEST_LANGUAGE=$language" "/DTEST_FONT_SIZE=$fontSize" "/DTEST_REPAIR=$repair" (Join-Path $PSScriptRoot 'installer-progress-fixture.nsi')
            if ($LASTEXITCODE -ne 0) { throw 'NSIS geometry fixture compile failed' }
            $process = Start-Process -FilePath $executable -PassThru -WindowStyle Normal
            try {
                $ids = [Collections.Generic.HashSet[int]]::new()
                [void]$ids.Add($process.Id)
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                $window = $null
                $bar = $null
                while ([DateTime]::UtcNow -lt $deadline) {
                    $processes = @(Get-CimInstance Win32_Process)
                    foreach ($level in 1..4) {
                        foreach ($child in $processes) { if ($ids.Contains([int]$child.ParentProcessId)) { [void]$ids.Add([int]$child.ProcessId) } }
                    }
                    $windows = [Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
                    $window = @($windows | Where-Object { $ids.Contains($_.Current.ProcessId) }) | Select-Object -First 1
                    if ($window) {
                        $controls = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
                        $bar = @($controls | Where-Object { $_.Current.ClassName -eq 'msctls_progress32' -and $_.Current.NativeWindowHandle -ne 0 }) | Select-Object -First 1
                        if ($bar) { break }
                    }
                    Start-Sleep -Milliseconds 200
                }
                if (-not $bar) { throw 'Native MUI progress bar missing' }
                # Observe completion inside the original deadline; a fixed delay
                # is not proof that MUI has finished its page layout transition.
                $complete = $false
                while ([DateTime]::UtcNow -lt $deadline) {
                    $complete = [InstallerProgressNative]::Complete([IntPtr]$window.Current.NativeWindowHandle, [IntPtr]$bar.Current.NativeWindowHandle, [uint32]$window.Current.ProcessId)
                    if ($complete) { break }
                    Start-Sleep -Milliseconds 200
                }
                if (-not $complete) { throw 'Native fixture completion was not observed' }
                $geometry = [InstallerProgressNative]::Measure([IntPtr]$window.Current.NativeWindowHandle, [IntPtr]$bar.Current.NativeWindowHandle, [uint32]$window.Current.ProcessId)
                $fits = $geometry[1] -gt 0 -and $geometry[2] -lt $geometry[0] -and [Math]::Abs(($geometry[0] - $geometry[2]) - $geometry[1]) -le 2
                if ($fits -ne ($repair -eq 1)) { throw "Unexpected $name geometry: $geometry" }
                $bounds = $window.Current.BoundingRectangle
                $bitmap = [Drawing.Bitmap]::new([int]$bounds.Width,[int]$bounds.Height)
                $graphics = [Drawing.Graphics]::FromImage($bitmap)
                try {
                    $graphics.CopyFromScreen([int]$bounds.X,[int]$bounds.Y,0,0,$bitmap.Size)
                    $bitmap.Save((Join-Path $outputRoot "$name.png"),[Drawing.Imaging.ImageFormat]::Png)
                } finally { $graphics.Dispose(); $bitmap.Dispose() }
                $results += @{ language=$language; fontSize=$fontSize; repaired=($repair -eq 1); fits=$fits; completed=$complete; geometry=$geometry; dpi=[InstallerProgressNative]::GetDpiForWindow([IntPtr]$window.Current.NativeWindowHandle); actualProductInstall=$false }
            } finally {
                # These are new, test-owned, no-payload fixture processes only.
                if (-not $process.HasExited) { $process.Kill($true); if (-not $process.WaitForExit(5000)) { throw 'Geometry fixture did not exit' } }
                $process.Dispose()
            }
        }
    }
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputRoot 'geometry.json') -Encoding utf8
