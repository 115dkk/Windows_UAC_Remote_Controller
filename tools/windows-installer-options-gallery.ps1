# SPDX-License-Identifier: GPL-2.0-or-later
# Disposable CI runner only: inspect/capture pre-install pages, never click Install.
param([Parameter(Mandatory)][string]$Installer, [Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI only' }
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
Add-Type -LiteralPath (Join-Path $PSScriptRoot 'InstallerOptionsNative.cs')
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$root = [Windows.Automation.AutomationElement]::RootElement
$scope = [Windows.Automation.TreeScope]::Descendants
foreach ($mode in @('fresh','upgrade')) {
    $arguments = if ($mode -eq 'upgrade') { @('/UPDATE') } else { @() }
    $start = @{ FilePath = $Installer; PassThru = $true; WindowStyle = 'Normal' }
    if ($arguments.Count) { $start.ArgumentList = $arguments }
    $process = Start-Process @start
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $found = $false
        $lastPage = ''
        $ownedIds = [Collections.Generic.HashSet[int]]::new()
        [void]$ownedIds.Add($process.Id)
        while ([DateTime]::UtcNow -lt $deadline) {
            # NSIS may use a child process for its wizard. Follow only the
            # process tree started by this test, not localized window titles.
            $processes = @(Get-CimInstance Win32_Process)
            for ($depth = 0; $depth -lt 4; $depth++) {
                foreach ($child in $processes) {
                    if ($ownedIds.Contains([int]$child.ParentProcessId)) { [void]$ownedIds.Add([int]$child.ProcessId) }
                }
            }
            $windows = $root.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
            $window = @($windows | Where-Object { $ownedIds.Contains($_.Current.ProcessId) }) | Select-Object -First 1
            if (-not $window) { Start-Sleep -Milliseconds 200; continue }
            $elements = @($window.FindAll($scope, [Windows.Automation.Condition]::TrueCondition))
            $page = @($elements | ForEach-Object { "{0} {1} enabled={2}: {3}" -f $_.Current.AutomationId,$_.Current.ControlType.ProgrammaticName,$_.Current.IsEnabled,$_.Current.Name }) -join ' | '
            if ($page -ne $lastPage) { Write-Output "$mode wizard: $($page.Substring(0,[Math]::Min(4000,$page.Length)))"; $lastPage = $page }
            $checks = @($elements | Where-Object { $_.Current.Name -match '^(바탕화면에 추가|시작 메뉴의 앱 목록에 추가|작업표시줄에 추가|Add to desktop|Add to the Start menu app list|Add to taskbar)' })
            $desktop = @($checks | Where-Object { $_.Current.Name -match '바탕화면에 추가|Add to desktop' })
            if ($desktop.Count -eq 1) { $found = $true; break }
            # Only known Welcome/License navigation. Never an Install button.
            $next = @($elements | Where-Object { $_.Current.IsEnabled -and ($_.Current.Name -replace '&','') -match '^(다음|Next|동의함|I Agree)' }) | Select-Object -First 1
            if ($next) { Write-Output "Invoking wizard navigation: $($next.Current.Name)"; [InstallerOptionsNative]::Next([IntPtr]$next.Current.NativeWindowHandle, [uint32]$next.Current.ProcessId) }
            Start-Sleep -Milliseconds 200
        }
        if (-not $found -or $checks.Count -ne 3) { throw "Expected three installer shortcut choices; processExited=$($process.HasExited), ownedPids=$($ownedIds -join ','); lastPage=$lastPage" }
        $expected = $mode -eq 'fresh'
        foreach ($check in $checks) {
            if ([InstallerOptionsNative]::Checked([IntPtr]$check.Current.NativeWindowHandle, [uint32]$check.Current.ProcessId) -ne $expected) { throw "Incorrect $mode default" }
        }
        $bounds = $window.Current.BoundingRectangle
        if ($bounds.Width -lt 100 -or $bounds.Height -lt 100) { throw 'Installer window not rendered' }
        $bitmap = [Drawing.Bitmap]::new([int]$bounds.Width,[int]$bounds.Height)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CopyFromScreen([int]$bounds.X,[int]$bounds.Y,0,0,$bitmap.Size)
            $bitmap.Save((Join-Path $OutputDirectory "installer-$mode.png"),[Drawing.Imaging.ImageFormat]::Png)
        } finally { $graphics.Dispose(); $bitmap.Dispose() }
        Write-Output "PASS: native installer $mode page, three defaults $expected, captured before installation."
    } finally {
        # Only the test-owned uninstalled wizard process tree; no product service.
        if (-not $process.HasExited) {
            $process.CloseMainWindow() | Out-Null
            if (-not $process.WaitForExit(1500)) { & "$env:SystemRoot/System32/taskkill.exe" /PID $process.Id /T /F | Out-Null }
        }
        $process.Dispose()
    }
}
