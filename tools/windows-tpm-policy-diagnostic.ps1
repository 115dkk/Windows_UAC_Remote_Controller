# SPDX-License-Identifier: GPL-2.0-or-later
# Operator-triggered local hardware diagnostic. No existing-key open, finalize,
# signing, export, delete, TPM provisioning or service configuration operation.
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevation required' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Diagnostic output already exists' }
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class UacTpmPolicyObservation {
  [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr h, string name, uint flags);
  [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptCreatePersistedKey(IntPtr p, out IntPtr k, string alg, string name, uint spec, uint flags);
  [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptGetProperty(IntPtr h, string name, byte[] bytes, int capacity, out int size, uint flags);
  [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptSetProperty(IntPtr h, string name, byte[] bytes, int size, uint flags);
  [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr h);
  static string Code(int v) { return "0x" + unchecked((uint)v).ToString("X8"); }
  static void Observe(Dictionary<string,object> r, IntPtr h, string name, bool text) {
    byte[] bytes = new byte[512]; int size;
    int status = NCryptGetProperty(h, name, bytes, bytes.Length, out size, 0x40);
    r[name + "Status"] = Code(status);
    if (status != 0 || size < 0 || size > bytes.Length) return;
    if (!text) { if (size == 4) r[name] = BitConverter.ToUInt32(bytes,0); return; }
    string value = Encoding.Unicode.GetString(bytes,0,size).TrimEnd('\0');
    r[name] = value == "ECDSA" || value == "ECDSA_P256" || value == "ECDH" || value == "ECDH_P256" ? value : "OTHER";
  }
  public static Dictionary<string,object> Read() {
    var r = new Dictionary<string,object>(); IntPtr p=IntPtr.Zero, k=IntPtr.Zero;
    try {
      int status=NCryptOpenStorageProvider(out p,"Microsoft Platform Crypto Provider",0);
      r["OpenProvider"] = Code(status); if(status!=0) return r;
      // Unique diagnostic name, never the production identity. No finalize call
      // exists in this tool: releasing the unfinalized handle discards it.
      status=NCryptCreatePersistedKey(p,out k,"ECDSA_P256","UacRemoteController.UnfinalizedDiagnostic."+Guid.NewGuid().ToString("N"),0,0x20);
      r["CreateUnfinalized"] = Code(status); if(status!=0) return r;
      r["SetExportPolicy"] = Code(NCryptSetProperty(k,"Export Policy",BitConverter.GetBytes((uint)0),4,0));
      r["SetUsage"] = Code(NCryptSetProperty(k,"Key Usage",BitConverter.GetBytes((uint)2),4,0));
      Observe(r,k,"Algorithm Name",true); Observe(r,k,"Algorithm Group",true);
      Observe(r,k,"Length",false); Observe(r,k,"Key Usage",false);
      Observe(r,k,"Export Policy",false); Observe(r,k,"Key Type",false);
    } finally {
      if(k!=IntPtr.Zero) r["FreeUnfinalized"] = Code(NCryptFreeObject(k));
      if(p!=IntPtr.Zero) r["FreeProvider"] = Code(NCryptFreeObject(p));
    }
    return r;
  }
}
'@
$tpm = Get-Tpm
$report = [ordered]@{
    observedAt = [DateTimeOffset]::Now.ToString('o')
    scope = 'LOCAL_TPM_UNFINALIZED_POLICY_ONLY'
    finalizedKey = $false
    existingKeyOpened = $false
    tpm = ($tpm | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,RestartPending,LockedOut)
    policy = [UacTpmPolicyObservation]::Read()
}
# Diagnostic-generated metadata only; CreateNew refuses replacement of a file.
$stream = [IO.File]::Open($OutputPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($report | ConvertTo-Json -Depth 5))
    $stream.Write($bytes,0,$bytes.Length)
} finally { $stream.Dispose() }
