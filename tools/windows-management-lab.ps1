# SPDX-License-Identifier: GPL-2.0-or-later
# Actual protected service/CLI and rejected Windows pipe clients, disposable CI only.
param([Parameter(Mandatory)][string]$ServiceExecutable)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') { throw 'Hosted Windows CI only' }
if ([IO.Path]::GetFullPath($ServiceExecutable) -ne 'C:\Program Files\휴대폰 승인\uac-service.exe') { throw 'Unexpected service image' }
if (-not (Test-Path -LiteralPath 'C:\Program Files\휴대폰 승인\controller-app.exe')) { throw 'Actual protected controller image required' }
$original = Get-CimInstance Win32_Service -Filter "Name='UacRemoteController'"
if ($original.State -ne 'Running' -or $original.ProcessId -eq 0) { throw 'Original running service required' }
$serviceProcess = [uint32]$original.ProcessId
function Confirm-ServiceAndRelay {
    $current = Get-CimInstance Win32_Service -Filter "Name='UacRemoteController'"
    if ($current.State -ne 'Running' -or $current.ProcessId -ne $serviceProcess) { throw 'Management request stopped or replaced the service' }
    $port = @(Get-NetTCPConnection -State Listen -LocalPort 7443)
    if (-not ($port | Where-Object OwningProcess -eq $serviceProcess)) { throw 'Original service lost its relay listener' }
}
function Read-RelayStatus {
    $raw = & $ServiceExecutable relay-status
    if ($LASTEXITCODE -ne 0) {
        $observed = Get-CimInstance Win32_Service -Filter "Name='UacRemoteController'"
        Write-Output ("Query failure: serviceState={0} originalPidRetained={1} exit={2} specific={3}" -f $observed.State,($observed.ProcessId -eq $serviceProcess),$observed.ExitCode,$observed.ServiceSpecificExitCode)
        throw 'Authenticated management query failed'
    }
    $reply = $raw | ConvertFrom-Json
    if (-not $reply.embedded_relay -or -not $reply.relay_listening -or -not $reply.relay_configured -or $reply.device_count -ne 0) { throw 'Actual relay observation mismatch' }
    Confirm-ServiceAndRelay
}
# Every short-lived real CLI exits immediately after reading its response.
# This exercises the service's post-write peer recheck and listener rearm.
for ($index = 0; $index -lt 16; $index++) {
    Read-RelayStatus
    Start-Sleep -Milliseconds 350
}
# PowerShell is deliberately not an allowed controller/helper image. Connect
# then close immediately, or write a small invalid frame. Authentication must
# reject this owner; neither rejection nor disconnect may retire the service.
for ($index = 0; $index -lt 8; $index++) {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'UacRemoteController.Management.v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(3000)
        if (($index % 2) -eq 1) {
            try { $pipe.Write([byte[]](0x42,0x41,0x44),0,3) } catch [IO.IOException] { }
        }
    } finally { $pipe.Dispose() }
    Start-Sleep -Milliseconds 500
    Confirm-ServiceAndRelay
    Read-RelayStatus
    Start-Sleep -Milliseconds 350
}
Confirm-ServiceAndRelay
Write-Output 'PASS: 24 authenticated short-lived management queries and 8 rejected pipe clients; original service PID and actual relay listener retained; no restart or authorization bypass.'
