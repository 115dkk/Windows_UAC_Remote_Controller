# SPDX-License-Identifier: GPL-2.0-or-later
using namespace System.IO
using namespace System.Security.AccessControl
using namespace System.Security.Principal
$newHash = '__NEW_SERVICE_SHA256__'
$oldHash = '8419c4f97124a3ecd701a502b9e7077db48de1027d90ccc7de9369f9205f632a'
$ph = 'd27dddbe316165524f942baa068af15e5e9caacef9e3042254b15d36ec3dba76'
if ($newHash -notmatch '\A[0-9a-fA-F]{64}\z' -or $newHash -match '\A0{64}\z' -or $newHash -eq $oldHash) {
[Console]::WriteLine('{"outcome":"rejected","stage":"hash_placeholder"}'); exit 64
}
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$newHash = $newHash.ToLowerInvariant()
$stage = 'runtime_preflight'; $outcome = 'failure'; $exitCode = 1
$ic0 = $null; $sc0 = $null; $im = 'not_run'; $sm = 'not_run'
$ra = $false; $source = $null; $product = $null; $bl = 268435456L
function Plain([string]$Path, [bool]$Directory) {
$full = [Path]::GetFullPath($Path)
if ($full -notmatch '\A[A-Za-z]:\\' -or $full.StartsWith('\\')) { throw 'path_rejected' }
$cursor = [Path]::GetPathRoot($full)
if (([File]::GetAttributes($cursor) -band [FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse_rejected' }
$parts = $full.Substring($cursor.Length).Split([char[]]@('\'), [StringSplitOptions]::RemoveEmptyEntries)
for ($i = 0; $i -lt $parts.Length; $i++) {
$cursor = [Path]::Combine($cursor, $parts[$i]); $a = [File]::GetAttributes($cursor)
if (($a -band [FileAttributes]::ReparsePoint) -ne 0 -or
((($a -band [FileAttributes]::Directory) -ne 0) -ne ($Directory -or $i -lt $parts.Length - 1))) { throw 'path_rejected' }
}
}
function Absent([string]$Path) {
try { $null = [File]::GetAttributes($Path) }
catch {
$e = $_.Exception.GetBaseException()
if ($e -is [FileNotFoundException] -or $e -is [DirectoryNotFoundException]) { return }
throw 'existence_unavailable'
}
throw 'existing_artifact'
}
function Assert-Acl([string]$Path, [bool]$Directory) {
$sections = [AccessControlSections]::Owner -bor [AccessControlSections]::Access
if ($Directory) { $s = [Directory]::GetAccessControl($Path, $sections) }
else { $s = [File]::GetAccessControl($Path, $sections) }
if (-not $s.AreAccessRulesProtected -or $s.GetOwner([SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'acl_rejected' }
$rules = $s.GetAccessRules($true, $true, [SecurityIdentifier]); $seen = @{}
if ($rules.Count -ne 3) { throw 'acl_rejected' }
foreach ($r in $rules) {
$sid = $r.IdentityReference.Value
if ($sid -notin @('S-1-5-18','S-1-5-32-544','S-1-5-32-545') -or $seen.ContainsKey($sid) -or
$r.IsInherited -or $r.AccessControlType -ne [AccessControlType]::Allow) { throw 'acl_rejected' }
$seen[$sid] = $true; $rights = [FileSystemRights]::FullControl; $inherit = [InheritanceFlags]::None
if ($sid -eq 'S-1-5-32-545') { $rights = [FileSystemRights]::ReadAndExecute -bor [FileSystemRights]::Synchronize }
if ($Directory) { $inherit = [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit }
if ($r.FileSystemRights -ne $rights -or $r.InheritanceFlags -ne $inherit -or $r.PropagationFlags -ne [PropagationFlags]::None) { throw 'acl_rejected' }
}
}
function NewFile([string]$Path) {
$s = [FileSecurity]::new()
$s.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)')
return [FileStream]::new($Path, [FileMode]::CreateNew, [FileSystemRights]::Write,
[FileShare]::None, 65536, [FileOptions]::WriteThrough, $s)
}
function StreamHash([FileStream]$Stream, [string]$Hash) {
$length = $Stream.Length
if ($length -le 0 -or $length -gt $bl) { throw 'binary_limit' }
$sha = [Security.Cryptography.SHA256]::Create()
try { $actual = [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($actual -cne $Hash -or $Stream.Length -ne $length) { throw 'hash_rejected' }
}
function FileHash([string]$Path, [string]$Hash) {
Plain $Path $false; Assert-Acl $Path $false
$f = [FileStream]::new($Path, [FileMode]::Open, [FileAccess]::Read, [FileShare]::Read)
try { StreamHash $f $Hash } finally { $f.Dispose() }
}
function CheckService {
$s = [System.Management.ManagementObject]::new('Win32_Service.Name="UacRemoteController"')
try {
$s.Get()
if (-not [string]::Equals([string]$s.GetPropertyValue('PathName'), ('"' + $exe + '" service'), [StringComparison]::OrdinalIgnoreCase) -or
[string]$s.GetPropertyValue('StartName') -cne 'LocalSystem' -or [string]$s.GetPropertyValue('State') -cne 'Stopped' -or
[string]$s.GetPropertyValue('StartMode') -cne 'Disabled') { throw 'service_rejected' }
} finally { $s.Dispose() }
}
function FixedError([byte[]]$Buffer, [int]$Count) {
try { $s = ([Text.UTF8Encoding]::new($false, $true)).GetString($Buffer, 0, $Count).TrimEnd([char[]]@("`r","`n")) }
catch { return 'unrecognized_native_error' }
if ($s.Length -eq 0) { return 'none' }
if ($s -cin @('the service stopped before the requested running state',
'the service lifecycle operation exceeded its bounded deadline',
'protected object owner or access control is unsupported or unsafe',
'protected path validation rejected a reparse point or path alias',
'service identity or configuration does not match this product',
'the service could not initialize its protected PC identity',
'this service state cannot complete the requested operation')) { return $s }
$op = '(OpenManager|OpenService|QueryStatus|QueryConfiguration|QueryToken|KnownFolder|OpenProtectedPath|InspectProtectedPath|ReadSecurity|ResolveServiceSid|CreateService|HardenService|DeleteService|StartService|StopService|Dispatch|RegisterHandler|ReportStatus|LaunchElevatedHelper|WaitElevatedHelper|RequestProbe)'
if ($s -cmatch ('\AWindows call failed at ' + $op + ' \(code 0x[0-9a-f]{8}\)\z') -or
$s -cmatch '\Ainstallation preparation failed; the registration remains disabled: (UnsafePath|UnsafePermissions|Provisioning|Other)\z') { return $s }
$m = [regex]::Match($s, ('\Ainstallation preparation failed; the registration remains disabled: Windows \{ operation: ' + $op + ', code: (0|[1-9][0-9]{0,9}) \}\z'))
[uint32]$number = 0
if ($m.Success -and [uint32]::TryParse($m.Groups[2].Value, [ref]$number)) { return $s }
return 'unrecognized_native_error'
}
function RunCommand([string]$Command) {
if ($Command -notin @('install','start')) { throw 'command_rejected' }
$p = [Diagnostics.Process]::new()
try {
$p.StartInfo.FileName = $exe; $p.StartInfo.Arguments = $Command; $p.StartInfo.WorkingDirectory = $product
$p.StartInfo.UseShellExecute = $false; $p.StartInfo.CreateNoWindow = $true
$p.StartInfo.RedirectStandardOutput = $true; $p.StartInfo.RedirectStandardError = $true
if (-not $p.Start()) { throw 'launch_failed' }
$clock = [Diagnostics.Stopwatch]::StartNew()
$outTask = $p.StandardOutput.BaseStream.CopyToAsync([Stream]::Null, 4096)
$buffer = [byte[]]::new(1024); $used = 0; $done = $false; $eof = $false; $confirmed = $false
$message = 'stderr_unconfirmed'; $discard = $null
$read = $p.StandardError.BaseStream.ReadAsync($buffer, 0, $buffer.Length)
while ($clock.ElapsedMilliseconds -lt 30000) {
if (-not $done -and $read.IsCompleted) {
try { $n = $read.GetAwaiter().GetResult() }
catch { $n = -1; $message = 'stderr_unavailable' }
if ($n -le 0) { $done = $true; $eof = $n -eq 0 }
else {
$used += $n
if ($used -eq $buffer.Length) {
$done = $true; $message = 'stderr_limit'
$discard = $p.StandardError.BaseStream.CopyToAsync([Stream]::Null, 4096)
} else { $read = $p.StandardError.BaseStream.ReadAsync($buffer, $used, $buffer.Length - $used) }
}
}
if ($p.WaitForExit(25)) {
$confirmed = $true
if ($done) { break }
try { $null = $read.Wait(25) } catch { }
}
}
if ($outTask.IsFaulted) { $null = $outTask.Exception }
if ($null -ne $discard -and $discard.IsFaulted) { $null = $discard.Exception }
if (-not $confirmed) { return [pscustomobject]@{ Confirmed = $false; Code = $null; Message = 'command_timeout' } }
if ($eof) { $message = FixedError $buffer $used }
return [pscustomobject]@{ Confirmed = $true; Code = [int]$p.ExitCode; Message = $message }
} finally { $p.Dispose() }
}
try {
if ($args.Count -ne 0 -or $PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or
$PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8 -or [Environment]::Version.Major -ne 4 -or
[Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [string]::IsNullOrEmpty($PSCommandPath)) { throw 'runtime_rejected' }
$launch = [Environment]::GetCommandLineArgs()
if ($launch -notcontains '-EncodedCommand' -or $launch -notcontains '-NoProfile' -or $launch -notcontains '-NonInteractive') { throw 'launch_rejected' }
$hp = [Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System), 'WindowsPowerShell\v1.0\powershell.exe')
$self = [Diagnostics.Process]::GetCurrentProcess()
try { if (-not [string]::Equals($self.MainModule.FileName, $hp, [StringComparison]::OrdinalIgnoreCase)) { throw 'host_rejected' } }
finally { $self.Dispose() }
Plain $hp $false
$id = [WindowsIdentity]::GetCurrent()
try { if (-not ([WindowsPrincipal]::new($id)).IsInRole([WindowsBuiltInRole]::Administrator)) { throw 'admin_required' } }
finally { $id.Dispose() }
$null = [Reflection.Assembly]::Load('System.Management, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
$stage = 'installed_preflight'
$product = [Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles), '휴대폰 승인')
Plain $product $true; Assert-Acl $product $true
$exe = [Path]::Combine($product, 'uac-service.exe')
$next = [Path]::Combine($product, 'uac-service.next-lab.exe')
$backup = [Path]::Combine($product, 'uac-service.previous-lab.exe')
$result = [Path]::Combine($product, 'lab-update-result-01.json')
Absent $next; Absent $backup; Absent $result
CheckService
FileHash $exe $oldHash
FileHash ([Path]::Combine($product, 'uac-prompt-probe.exe')) $ph
$stage = 'source_hash'
$sp = 'C:\Users\32170336\AppData\Local\Temp\uac-controller-build-165ac850\debug\uac-service.exe'
Plain $sp $false
$source = [FileStream]::new($sp, [FileMode]::Open, [FileAccess]::Read, [FileShare]::Read)
StreamHash $source $newHash; $source.Position = 0
$ra = $true; $stage = 'stage_copy'
$target = NewFile $next
try { $source.CopyTo($target, 65536); $target.Flush($true) } finally { $target.Dispose() }
$source.Dispose(); $source = $null
FileHash $next $newHash
CheckService; Absent $backup
$stage = 'atomic_replace'
try { [File]::Replace($next, $exe, $backup) }
catch { $outcome = 'unconfirmed'; throw 'replace_unconfirmed' }
$stage = 'installed_verification'
FileHash $exe $newHash; FileHash $backup $oldHash
FileHash ([Path]::Combine($product, 'uac-prompt-probe.exe')) $ph
$stage = 'install'; $r = RunCommand 'install'; $ic0 = $r.Code; $im = $r.Message
if (-not $r.Confirmed) { $outcome = 'unconfirmed'; throw 'install_timeout' }
if ($ic0 -ne 0) { throw 'install_failed' }
$stage = 'start'; $r = RunCommand 'start'; $sc0 = $r.Code; $sm = $r.Message
if (-not $r.Confirmed) { $outcome = 'unconfirmed'; throw 'start_timeout' }
if ($sc0 -ne 0) { throw 'start_failed' }
$stage = 'complete'; $outcome = 'success'; $exitCode = 0
} catch { } finally {
if ($null -ne $source) { try { $source.Dispose() } catch { $outcome = 'unconfirmed'; $exitCode = 1 } }
}
$ic = 'null'; $sc = 'null'
if ($null -ne $ic0) { $ic = ([int]$ic0).ToString([Globalization.CultureInfo]::InvariantCulture) }
if ($null -ne $sc0) { $sc = ([int]$sc0).ToString([Globalization.CultureInfo]::InvariantCulture) }
$json = '{"schemaVersion":1,"stage":"' + $stage + '","outcome":"' + $outcome +
'","installExitCode":' + $ic + ',"startExitCode":' + $sc + ',"installMessage":"' + $im +
'","startMessage":"' + $sm + '","oldServiceSha256":"' + $oldHash +
'","newServiceSha256":"' + $newHash + '","probeSha256":"' + $ph + '"}'
if ($ra) {
try {
Plain $product $true; Assert-Acl $product $true
$bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
if ($bytes.Length -gt 8192) { throw 'result_limit' }
$f = NewFile $result
try { $f.Write($bytes, 0, $bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
} catch { [Console]::WriteLine('{"outcome":"unconfirmed","stage":"result_write"}'); exit 70 }
}
[Console]::WriteLine($json)
exit $exitCode
