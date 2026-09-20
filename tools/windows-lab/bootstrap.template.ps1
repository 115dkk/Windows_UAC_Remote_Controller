# SPDX-License-Identifier: GPL-2.0-or-later
# LAB ONLY. Fill the two hash literals; encode this reviewed text BEFORE UAC.
# Native System32 PS5.1: -NoProfile -NonInteractive -EncodedCommand. Never -File.
# Rationale: windows-lab-bootstrap-authoring.md.
using namespace System.Security.AccessControl
using namespace System.Security.Principal
$serviceHash = '__UAC_SERVICE_SHA256__'
$probeHash = '__UAC_PROMPT_PROBE_SHA256__'
if ($serviceHash -notmatch '\A[0-9a-fA-F]{64}\z' -or
$probeHash -notmatch '\A[0-9a-fA-F]{64}\z' -or
$serviceHash -match '\A0{64}\z' -or $probeHash -match '\A0{64}\z') {
[Console]::WriteLine('{"schemaVersion":1,"outcome":"rejected","stage":"hash_placeholders"}')
exit 64
}
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$serviceHash = $serviceHash.ToLowerInvariant()
$probeHash = $probeHash.ToLowerInvariant()
$stage = 'runtime_preflight'
$outcome = 'failure'
$exitCode = 1
$installCode = $null
$startCode = $null
$productReady = $false
$product = $null
$sources = @()
$metadataLimit = 8192
$binaryLimit = 268435456L
function Assert-Plain([string]$Path, [bool]$Directory) {
$full = [IO.Path]::GetFullPath($Path)
if ($full -notmatch '\A[A-Za-z]:\\' -or $full.StartsWith('\\')) { throw 'lab_path_rejected' }
$cursor = [IO.Path]::GetPathRoot($full)
if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'lab_reparse_rejected' }
$parts = $full.Substring($cursor.Length).Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries)
for ($index = 0; $index -lt $parts.Length; $index++) {
$cursor = [IO.Path]::Combine($cursor, $parts[$index])
$attributes = [IO.File]::GetAttributes($cursor)
if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'lab_reparse_rejected' }
$mustBeDirectory = $index -lt ($parts.Length - 1) -or $Directory
if ((($attributes -band [IO.FileAttributes]::Directory) -ne 0) -ne $mustBeDirectory) { throw 'lab_path_kind_rejected' }
}
}
function Test-EntryExists([string]$Path) {
try { $null = [IO.File]::GetAttributes($Path); return $true }
catch {
$cause = $_.Exception.GetBaseException()
if ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]) { return $false }
throw 'lab_existence_unavailable'
}
}
function Assert-ServiceAbsent {
$services = [System.ServiceProcess.ServiceController]::GetServices()
try {
foreach ($service in $services) {
if ([string]::Equals($service.ServiceName, 'UacRemoteController', [StringComparison]::OrdinalIgnoreCase)) {
throw 'lab_existing_service'
}
}
} finally { foreach ($service in $services) { $service.Dispose() } }
}
function New-LabSecurity([bool]$Directory) {
if ($Directory) { $security = [DirectorySecurity]::new() }
else { $security = [FileSecurity]::new() }
$admin = [SecurityIdentifier]::new('S-1-5-32-544')
$security.SetOwner($admin)
$security.SetGroup($admin)
$security.SetAccessRuleProtection($true, $false)
$inheritance = [InheritanceFlags]::None
if ($Directory) { $inheritance = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit }
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
$rights = [FileSystemRights]::FullControl
if ($sid -eq 'S-1-5-32-545') { $rights = [FileSystemRights]::ReadAndExecute }
$rule = [FileSystemAccessRule]::new(
[SecurityIdentifier]::new($sid), $rights, $inheritance,
[PropagationFlags]::None, [AccessControlType]::Allow)
$security.AddAccessRule($rule)
}
return $security
}
function Assert-Acl([string]$Path, [bool]$Directory) {
$sections = [AccessControlSections]::Owner -bor [AccessControlSections]::Access
if ($Directory) { $security = [IO.Directory]::GetAccessControl($Path, $sections) }
else { $security = [IO.File]::GetAccessControl($Path, $sections) }
if (-not $security.AreAccessRulesProtected -or $security.GetOwner([SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'lab_security_rejected' }
$rules = $security.GetAccessRules($true, $true, [SecurityIdentifier])
if ($rules.Count -ne 3) { throw 'lab_security_rejected' }
$seen = @{}
foreach ($rule in $rules) {
$sid = $rule.IdentityReference.Value
if ($sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545') -or $seen.ContainsKey($sid) -or
$rule.IsInherited -or $rule.AccessControlType -ne [AccessControlType]::Allow) { throw 'lab_security_rejected' }
$seen[$sid] = $true
$expected = [FileSystemRights]::FullControl
if ($sid -eq 'S-1-5-32-545') { $expected = [FileSystemRights]::ReadAndExecute -bor [FileSystemRights]::Synchronize }
$inheritance = [InheritanceFlags]::None
if ($Directory) { $inheritance = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit }
if ($rule.FileSystemRights -ne $expected -or $rule.InheritanceFlags -ne $inheritance -or
$rule.PropagationFlags -ne [PropagationFlags]::None) { throw 'lab_security_rejected' }
}
}
function Get-LabHash([IO.FileStream]$Stream) {
$sha = [Security.Cryptography.SHA256]::Create()
try { return [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
}
function New-ProtectedFile([string]$Path) {
$rights = [FileSystemRights]::Write
return [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, $rights, [IO.FileShare]::None,
65536, [IO.FileOptions]::WriteThrough, (New-LabSecurity $false))
}
function Invoke-LabCommand([string]$Command) {
if ($Command -notin @('install', 'start')) { throw 'lab_command_rejected' }
$process = [Diagnostics.Process]::new()
try {
$process.StartInfo.FileName = [IO.Path]::Combine($product, 'uac-service.exe')
$process.StartInfo.Arguments = $Command
$process.StartInfo.WorkingDirectory = $product
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
if (-not $process.Start()) { throw 'lab_launch_failed' }
$discardOut = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null, 4096)
$discardError = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null, 4096)
if (-not $process.WaitForExit(30000)) { return [pscustomobject]@{ Confirmed = $false; Code = $null } }
$code = [int]$process.ExitCode
if ($discardOut.IsFaulted) { $null = $discardOut.Exception }
if ($discardError.IsFaulted) { $null = $discardError.Exception }
return [pscustomobject]@{ Confirmed = $true; Code = $code }
} finally {
$process.Dispose()
}
}
try {
if ($args.Count -ne 0 -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
$PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or [Environment]::Version.Major -ne 4 -or
[Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [string]::IsNullOrEmpty($PSCommandPath)) { throw 'lab_runtime_rejected' }
$launch = [Environment]::GetCommandLineArgs()
if ($launch -notcontains '-EncodedCommand' -or $launch -notcontains '-NoProfile' -or $launch -notcontains '-NonInteractive') { throw 'lab_launch_shape_rejected' }
$system = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$expectedHost = [IO.Path]::Combine($system, 'WindowsPowerShell\v1.0\powershell.exe')
$self = [Diagnostics.Process]::GetCurrentProcess()
try { if (-not [string]::Equals($self.MainModule.FileName, $expectedHost, [StringComparison]::OrdinalIgnoreCase)) { throw 'lab_host_rejected' } }
finally { $self.Dispose() }
Assert-Plain $expectedHost $false
$identity = [WindowsIdentity]::GetCurrent()
try {
if (-not ([WindowsPrincipal]::new($identity)).IsInRole([WindowsBuiltInRole]::Administrator)) { throw 'lab_admin_required' }
} finally { $identity.Dispose() }
$null = [Reflection.Assembly]::Load('System.ServiceProcess, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
$stage = 'initial_only_preflight'
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
Assert-Plain $programFiles $true
$product = [IO.Path]::Combine($programFiles, '휴대폰 승인')
if (Test-EntryExists $product) { throw 'lab_existing_product' }
Assert-ServiceAbsent
$stage = 'source_hashes'
$sourceRoot = 'C:\Users\32170336\AppData\Local\Temp\uac-controller-build-165ac850\debug'
foreach ($spec in @(@('uac-service.exe', $serviceHash), @('uac-prompt-probe.exe', $probeHash))) {
$path = [IO.Path]::Combine($sourceRoot, $spec[0])
Assert-Plain $path $false
$stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
$sources += [pscustomobject]@{ Leaf = $spec[0]; Hash = $spec[1]; Stream = $stream }
if ($stream.Length -le 0 -or $stream.Length -gt $binaryLimit -or (Get-LabHash $stream) -cne $spec[1]) { throw 'lab_source_rejected' }
$stream.Position = 0
}
$stage = 'protected_directory'
if (Test-EntryExists $product) { throw 'lab_existing_product' }
([IO.DirectoryInfo]::new($product)).Create((New-LabSecurity $true))
Assert-Plain $product $true
Assert-Acl $product $true
$productReady = $true
$stage = 'protected_copies'
foreach ($source in $sources) {
$destination = [IO.Path]::Combine($product, $source.Leaf)
$target = New-ProtectedFile $destination
try { $source.Stream.CopyTo($target, 65536); $target.Flush($true) }
finally { $target.Dispose() }
Assert-Plain $destination $false
Assert-Acl $destination $false
}
foreach ($source in $sources) { $source.Stream.Dispose() }
$sources = @()
$stage = 'protected_hashes'
foreach ($spec in @(@('uac-service.exe', $serviceHash), @('uac-prompt-probe.exe', $probeHash))) {
$path = [IO.Path]::Combine($product, $spec[0])
Assert-Plain $path $false
$stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try { if ((Get-LabHash $stream) -cne $spec[1]) { throw 'lab_copy_rejected' } }
finally { $stream.Dispose() }
}
Assert-ServiceAbsent
$stage = 'install'
$installed = Invoke-LabCommand 'install'
$installCode = $installed.Code
if (-not $installed.Confirmed) { $outcome = 'unconfirmed'; throw 'lab_install_timeout' }
if ($installCode -ne 0) { throw 'lab_install_failed' }
$stage = 'start'
$started = Invoke-LabCommand 'start'
$startCode = $started.Code
if (-not $started.Confirmed) { $outcome = 'unconfirmed'; throw 'lab_start_timeout' }
if ($startCode -ne 0) { throw 'lab_start_failed' }
$stage = 'complete'
$outcome = 'success'
$exitCode = 0
} catch {
if ($outcome -ne 'unconfirmed') { $outcome = 'failure' }
} finally {
foreach ($source in $sources) {
try { $source.Stream.Dispose() } catch { $outcome = 'unconfirmed'; $exitCode = 1 }
}
}
$installJson = 'null'
$startJson = 'null'
if ($null -ne $installCode) { $installJson = ([int]$installCode).ToString([Globalization.CultureInfo]::InvariantCulture) }
if ($null -ne $startCode) { $startJson = ([int]$startCode).ToString([Globalization.CultureInfo]::InvariantCulture) }
$json = '{"schemaVersion":1,"stage":"' + $stage + '","outcome":"' + $outcome +
'","installExitCode":' + $installJson + ',"startExitCode":' + $startJson +
',"serviceSha256":"' + $serviceHash + '","probeSha256":"' + $probeHash + '"}'
if ($productReady) {
try {
Assert-Plain $product $true
Assert-Acl $product $true
$bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
if ($bytes.Length -gt $metadataLimit) { throw 'lab_result_limit' }
$resultFile = New-ProtectedFile ([IO.Path]::Combine($product, 'lab-bootstrap-result.json'))
try { $resultFile.Write($bytes, 0, $bytes.Length); $resultFile.Flush($true) }
finally { $resultFile.Dispose() }
} catch {
[Console]::WriteLine('{"schemaVersion":1,"outcome":"unconfirmed","stage":"result_write"}')
exit 70
}
}
[Console]::WriteLine($json)
exit $exitCode
