# SPDX-License-Identifier: GPL-2.0-or-later
# CI disposable native service only. Synthetic opaque bytes are not an approval.
param([Parameter(Mandatory)][string]$ServiceExecutable)
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name UacRemoteController
if ($service.Status -ne 'Running') { throw 'Service must be running' }
$policy = New-Object -ComObject HNetCfg.FwPolicy2
$rule = $policy.Rules.Item('dev.dkk115.uacremote.embedded-relay.v1')
if (-not $rule.Enabled -or $rule.Direction -ne 1 -or $rule.Protocol -ne 6 -or $rule.LocalPorts -ne '7443' -or $rule.Profiles -ne 2 -or $rule.ServiceName -ne 'UacRemoteController' -or $rule.ApplicationName -ne $ServiceExecutable -or $rule.EdgeTraversal) { throw 'Embedded relay firewall tuple differs' }
$pc = [Net.Sockets.TcpClient]::new()
$phone = [Net.Sockets.TcpClient]::new()
try {
    $pc.Connect('127.0.0.1',7443)
    $phone.Connect('127.0.0.1',7443)
    $left = $pc.GetStream(); $right = $phone.GetStream()
    foreach ($stream in @($left,$right)) { $stream.ReadTimeout = 5000; $stream.WriteTimeout = 5000 }
    $header = [byte[]]::new(43)
    [Text.Encoding]::ASCII.GetBytes("WUACRLY`0").CopyTo($header,0)
    $header[9] = 1
    for ($i = 11; $i -lt 43; $i++) { $header[$i] = 0x42 }
    $header[10] = 1; $left.Write($header,0,$header.Length)
    $header[10] = 2; $right.Write($header,0,$header.Length)
    foreach ($stream in @($left,$right)) {
        $marker = [byte[]]::new(9)
        $stream.ReadExactly($marker)
        if ([Text.Encoding]::ASCII.GetString($marker) -ne "WUACPAIR`0") { throw 'Missing relay rendezvous marker' }
    }
    $left.WriteByte(0x5A)
    if ($right.ReadByte() -ne 0x5A) { throw 'Opaque relay byte not delivered' }
    $right.WriteByte(0xA5)
    if ($left.ReadByte() -ne 0xA5) { throw 'Reverse opaque relay byte not delivered' }
} finally { $pc.Dispose(); $phone.Dispose() }
& $ServiceExecutable stop
if ($LASTEXITCODE -ne 0) { throw 'Service stop failed' }
$released = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any,7443)
try { $released.Start() } finally { $released.Stop() }
& $ServiceExecutable start
if ($LASTEXITCODE -ne 0) { throw 'Service restart failed' }
$probe = [Net.Sockets.TcpClient]::new()
try { $probe.Connect('127.0.0.1',7443) } finally { $probe.Dispose() }
Write-Output 'PASS: installed service owns bounded duplex relay; narrow private firewall tuple; stop releases port; start reopens listener. No physical phone/TLS/UAC acceptance claim.'
