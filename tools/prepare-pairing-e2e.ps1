# SPDX-License-Identifier: GPL-2.0-or-later
# Only on a disposable CI VM; no UAC approval is performed by this preparation.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Hosted CI required' }
$root = 'C:\ProgramData\UacRemoteCiE2e'
if (Test-Path -LiteralPath $root) { throw 'CI fixture directory already exists' }
$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
function Security([bool]$directory,[bool]$userRead) {
    $s = if ($directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $s.SetOwner($admin); $s.SetGroup($admin); $s.SetAccessRuleProtection($true,$false)
    $inherit = if ($directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $s.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)) }
    if ($userRead) { $s.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow)) }
    return $s
}
[IO.Directory]::CreateDirectory($root,(Security $true $false)) | Out-Null
function CopyFixture([string]$source,[string]$destination,[bool]$userRead) {
    $stream = [IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::None,(Security $false $userRead))
    try { $bytes = [IO.File]::ReadAllBytes($source); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
./tools/ci-windows-operator/build.ps1
& 'target/ci-windows-operator/uac-ci-consent-target-tests.exe'
if ($LASTEXITCODE -ne 0) { throw 'Consent target negative controls failed' }
foreach ($name in @('uac-ci-windows-operator.exe','uac-ci-pipe-bridge.exe')) { CopyFixture "target/ci-windows-operator/$name" (Join-Path $root $name) $false }
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $csc /nologo /target:exe /platform:x64 /codepage:65001 /warnaserror+ /optimize+ /out:target/ci-windows-operator/uac-ci-requester.exe tools/ci-e2e-request.cs
if ($LASTEXITCODE -ne 0) { throw 'Requester compilation failed' }
& $csc /nologo /target:exe /platform:x64 /codepage:65001 /warnaserror+ /optimize+ /define:REQUEST_TARGET /out:target/ci-windows-operator/uac-ci-request.exe tools/ci-e2e-request.cs
if ($LASTEXITCODE -ne 0) { throw 'Target compilation failed' }
foreach ($name in @('uac-ci-requester.exe','uac-ci-request.exe')) { CopyFixture "target/ci-windows-operator/$name" (Join-Path $env:LAB_DIR $name) $true }
$zip = Join-Path $env:RUNNER_TEMP 'uac-pstools.zip'
$unpack = Join-Path $env:RUNNER_TEMP 'uac-pstools'
Invoke-WebRequest https://download.sysinternals.com/files/PSTools.zip -OutFile $zip
Expand-Archive -LiteralPath $zip -DestinationPath $unpack
$psexec = Join-Path $unpack 'PsExec64.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $psexec
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Microsoft PsExec signature rejected' }
CopyFixture $psexec (Join-Path $root 'PsExec64.exe') $false
# Strengthen only this disposable VM's administrator consent mode; retain LUA,
# Secure Desktop and normal product admission. No already-existing user changes.
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord
