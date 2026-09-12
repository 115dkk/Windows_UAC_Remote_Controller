# SPDX-License-Identifier: GPL-2.0-or-later
# Disposable CI runner only: inspect/capture pre-install pages, never click Install.
param([Parameter(Mandatory)][string]$Installer, [Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI only' }
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes, System.Drawing
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$root = [Windows.Automation.AutomationElement]::RootElement
$scope = [Windows.Automation.TreeScope]::Descendants
$buttonType = [Windows.Automation.ControlType]::Button
$checkType = [Windows.Automation.ControlType]::CheckBox
foreach ($mode in @('fresh','upgrade')) {
    $arguments = if ($mode -eq 'upgrade') { @('/UPDATE') } else { @() }
    $start = @{ FilePath = $Installer; PassThru = $true; WindowStyle = 'Normal' }
    if ($arguments.Count) { $start.ArgumentList = $arguments }
    $process = Start-Process @start
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $found = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            $windows = $root.FindAll([Windows.Automation.TreeScope]::Children, [Windows.Automation.Condition]::TrueCondition)
            $window = @($windows | Where-Object { $_.Current.Name -match 'UAC 원격 승인' -and $_.Current.ControlType -eq [Windows.Automation.ControlType]::Window }) | Select-Object -First 1
            if (-not $window) { Start-Sleep -Milliseconds 200; continue }
            $checks = @($window.FindAll($scope, [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,$checkType)))
            $desktop = @($checks | Where-Object { $_.Current.Name -match '바탕화면에 추가|Add to desktop' })
            if ($desktop.Count -eq 1) { $found = $true; break }
            $buttons = @($window.FindAll($scope, [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::ControlTypeProperty,$buttonType)))
            # Only known Welcome/License navigation. Never an Install button.
            $next = @($buttons | Where-Object { $_.Current.IsEnabled -and $_.Current.Name -match '^(다음|Next|동의함|I Agree)' }) | Select-Object -First 1
            if ($next) { $next.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke() }
            Start-Sleep -Milliseconds 200
        }
        if (-not $found -or $checks.Count -ne 3) { throw 'Expected three installer shortcut choices' }
        $expected = if ($mode -eq 'fresh') { [Windows.Automation.ToggleState]::On } else { [Windows.Automation.ToggleState]::Off }
        foreach ($check in $checks) {
            if ($check.GetCurrentPattern([Windows.Automation.TogglePattern]::Pattern).Current.ToggleState -ne $expected) { throw "Incorrect $mode default" }
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
