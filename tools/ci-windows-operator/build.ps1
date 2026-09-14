# SPDX-License-Identifier: GPL-2.0-or-later
# CI compilation only. This script never launches the operator or grants UAC.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This tool is restricted to a disposable GitHub-hosted Windows CI VM.'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$output = Join-Path $repo 'target/ci-windows-operator'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$framework = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
$wpf = Join-Path $framework 'WPF'
$sources = @('Program.cs', 'Native.cs', 'ProtectedUi.cs', 'DigitPixels.cs', 'PipeBridge.cs', 'ConsentTarget.cs', 'Diagnostics.cs', 'LocalPipe.cs') | ForEach-Object { Join-Path $PSScriptRoot $_ }
$font = Join-Path $repo 'assets/fonts/native/UACSans-Bold.ttf'
$vocabulary = Join-Path $PSScriptRoot 'diagnostic-vocabulary.json'
$destination = Join-Path $output 'uac-ci-windows-operator.exe'
& $compiler /nologo /target:exe /main:Program /platform:x64 /optimize+ /warnaserror+ /utf8output /codepage:65001 "/out:$destination" "/resource:$font,UACSans-Bold.ttf" "/resource:$vocabulary,CiDiagnosticVocabulary.json" "/reference:$framework\System.Drawing.dll" "/reference:$framework\System.Web.Extensions.dll" "/reference:$wpf\UIAutomationClient.dll" "/reference:$wpf\UIAutomationTypes.dll" "/reference:$wpf\WindowsBase.dll" $sources
if ($LASTEXITCODE -ne 0) { throw "CI Windows operator compilation failed ($LASTEXITCODE)." }
Write-Output $destination
$bridgeDestination = Join-Path $output 'uac-ci-pipe-bridge.exe'
& $compiler /nologo /target:exe /main:PipeBridge /platform:x64 /optimize+ /warnaserror+ /utf8output /codepage:65001 "/out:$bridgeDestination" "/resource:$font,UACSans-Bold.ttf" "/resource:$vocabulary,CiDiagnosticVocabulary.json" "/reference:$framework\System.Drawing.dll" "/reference:$framework\System.Web.Extensions.dll" "/reference:$wpf\UIAutomationClient.dll" "/reference:$wpf\UIAutomationTypes.dll" "/reference:$wpf\WindowsBase.dll" $sources
if ($LASTEXITCODE -ne 0) { throw "CI pipe bridge compilation failed ($LASTEXITCODE)." }
Write-Output $bridgeDestination
$fixtureDestination = Join-Path $output 'uac-ci-consent-target-tests.exe'
$fixtureSources = @('ConsentTarget.cs', 'ConsentTarget.Tests.cs') | ForEach-Object { Join-Path $PSScriptRoot $_ }
& $compiler /nologo /target:exe /main:ConsentTargetTests /platform:x64 /optimize+ /warnaserror+ /utf8output /codepage:65001 "/out:$fixtureDestination" $fixtureSources
if ($LASTEXITCODE -ne 0) { throw "Consent target fixture compilation failed ($LASTEXITCODE)." }
Write-Output $fixtureDestination
$diagnosticDestination = Join-Path $output 'uac-ci-diagnostics-tests.exe'
$diagnosticSources = @($sources) + (Join-Path $PSScriptRoot 'Diagnostics.Tests.cs')
& $compiler /nologo /target:exe /main:DiagnosticsTests /platform:x64 /optimize+ /warnaserror+ /utf8output /codepage:65001 "/out:$diagnosticDestination" "/resource:$font,UACSans-Bold.ttf" "/resource:$vocabulary,CiDiagnosticVocabulary.json" "/reference:$framework\System.Drawing.dll" "/reference:$framework\System.Web.Extensions.dll" "/reference:$wpf\UIAutomationClient.dll" "/reference:$wpf\UIAutomationTypes.dll" "/reference:$wpf\WindowsBase.dll" $diagnosticSources
if ($LASTEXITCODE -ne 0) { throw "CI diagnostic fixture compilation failed ($LASTEXITCODE)." }
Write-Output $diagnosticDestination
$localPipeDestination = Join-Path $output 'uac-ci-local-pipe-tests.exe'
$localPipeSources = @($sources) + (Join-Path $PSScriptRoot 'LocalPipe.Tests.cs')
& $compiler /nologo /target:exe /main:LocalPipeTests /platform:x64 /optimize+ /warnaserror+ /utf8output /codepage:65001 "/out:$localPipeDestination" "/resource:$font,UACSans-Bold.ttf" "/resource:$vocabulary,CiDiagnosticVocabulary.json" "/reference:$framework\System.Drawing.dll" "/reference:$framework\System.Web.Extensions.dll" "/reference:$wpf\UIAutomationClient.dll" "/reference:$wpf\UIAutomationTypes.dll" "/reference:$wpf\WindowsBase.dll" $localPipeSources
if ($LASTEXITCODE -ne 0) { throw "CI local pipe regression compilation failed ($LASTEXITCODE)." }
Write-Output $localPipeDestination
