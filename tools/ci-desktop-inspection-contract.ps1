# SPDX-License-Identifier: GPL-2.0-or-later
# CI-only native fixture. No product installation, elevation or policy mutation.
[CmdletBinding()]
param([string]$OutputDirectory = 'target/desktop-inspection-contract')
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or
    -not [Environment]::Is64BitProcess) { throw 'Hosted x64 Windows CI required.' }
$workspace = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'ci-desktop-inspection-contract.cs'))
if (-not $source.StartsWith($workspace.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture source must be inside this CI workspace.'
}
$artifactDirectory = [IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($OutputDirectory)) { $OutputDirectory } else { Join-Path $workspace $OutputDirectory }))
if (-not $artifactDirectory.StartsWith($workspace.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture output must stay inside this CI workspace.'
}
$ancestor = $artifactDirectory
while ($ancestor -and $ancestor.Length -ge $workspace.Length) {
    if ((Test-Path -LiteralPath $ancestor) -and
        ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Fixture output cannot traverse a reparse point.'
    }
    $ancestor = [IO.Path]::GetDirectoryName($ancestor)
}
$output = Join-Path $artifactDirectory ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $output
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$executable = Join-Path $output 'ci-desktop-inspection-contract.exe'
$compileOut = Join-Path $output 'compile.stdout.txt'
$compileError = Join-Path $output 'compile.stderr.txt'
$arguments = @('/nologo', '/langversion:5', '/platform:x64', '/target:exe', ('/out:"' + $executable + '"'), ('"' + $source + '"'))
$compile = Start-Process -FilePath $compiler -ArgumentList $arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $compileOut -RedirectStandardError $compileError
if (-not $compile.WaitForExit(30000)) {
    $compile.Kill(); $null = $compile.WaitForExit(5000); throw 'Fixture compiler exceeded its bound.'
}
if ($compile.ExitCode -ne 0) {
    foreach ($log in @($compileOut, $compileError)) {
        if ((Get-Item -LiteralPath $log).Length -le 65536) { Get-Content -LiteralPath $log }
    }
    throw 'Fixture compilation failed; inspect retained compiler logs.'
}
$stdout = Join-Path $output 'summary.json'
$stderr = Join-Path $output 'fixture.stderr.txt'
$run = Start-Process -FilePath $executable -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
if (-not $run.WaitForExit(60000)) {
    # Terminating only the exact returned root process closes its owned child job.
    $run.Kill(); $null = $run.WaitForExit(5000); throw 'Fixture exceeded its lifetime bound.'
}
$raw = Get-Content -LiteralPath $stdout -Raw
if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt 16384 -or (Get-Item -LiteralPath $stderr).Length -ne 0) {
    throw 'Unexpected fixture output.'
}
$summary = $raw | ConvertFrom-Json
$sanitized = $summary | ConvertTo-Json -Depth 5 -Compress
$contract = Join-Path $artifactDirectory 'contract.json'
$stream = [IO.File]::Open($contract, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($sanitized + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
Write-Output $sanitized
if ($run.ExitCode -ne 0 -or $summary.configuration -cne 'hidden_static_witness_v1' -or
    $summary.fixtureCompleted -ne $true -or $summary.positiveControl -ne $true -or @($summary.cases).Count -ne 34 -or
    @($summary.cases | Where-Object { $_.windowMembership -ne $true -or $_.wrongPidRejected -ne $true -or
        $_.wrongTidRejected -ne $true -or $_.wrongDesktopRejected -ne $true }).Count -ne 0) {
    throw 'Native contract fixture incomplete or all-access positive control failed.'
}
