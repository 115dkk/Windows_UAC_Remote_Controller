# SPDX-License-Identifier: GPL-2.0-or-later
# CI-only, Windows PowerShell 5.1 / PowerShell 7, 64-bit. Never shipped.
[CmdletBinding()]
param([switch]$InspectOnly)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitProcess) {
    throw 'This launcher requires a 64-bit Windows GitHub-hosted CI process.'
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace UacCiMedium {
    public sealed class TokenFacts {
        public string tokenType;
        public int integrityRid;
        public int elevation;
        public string elevationType;
        public bool adminEnabled;
        public bool sessionInteractive;
        public bool isSystem;
        public bool isAppContainer;
        public bool uiAccess;
    }

    // Only this owner's original child handles may be stopped/closed. No
    // process lookup, external PID adoption, service control or token mutation.
    public sealed class Launcher : IDisposable {
        private IntPtr sourceToken, level, reducedToken, process, thread;
        public TokenFacts Facts { get; private set; }
        public uint ClientPid { get; private set; }
        private static readonly string Application = @"C:\Program Files\" +
            "\uD734\uB300\uD3F0 \uC2B9\uC778" + @"\controller-app.exe";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo {
            public uint cb;
            public string lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
            public uint dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr handle, uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int kind,
            IntPtr information, uint length, out uint returned);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SaferCreateLevel(uint scope, uint levelId,
            uint flags, out IntPtr level, IntPtr reserved);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SaferComputeTokenFromLevel(IntPtr level,
            IntPtr input, out IntPtr output, uint flags, IntPtr reserved);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SaferCloseLevel(IntPtr level);
        [DllImport("advapi32.dll")]
        private static extern bool IsValidSid(IntPtr sid);
        [DllImport("advapi32.dll")]
        private static extern bool IsWellKnownSid(IntPtr sid, int type);
        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr environment,
            IntPtr token, bool inherit);
        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags,
            string application, StringBuilder commandLine, uint creationFlags,
            IntPtr environment, string directory, ref StartupInfo startup,
            out ProcessInformation information);

        private static Exception Error(string operation) {
            return new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }
        private static void Require(bool condition, string operation) {
            if (!condition) throw new InvalidOperationException(operation);
        }

        public Launcher() {
            try {
                // QUERY | DUPLICATE | ASSIGN_PRIMARY; no privilege adjustment.
                if (!OpenProcessToken(GetCurrentProcess(), 0x000B, out sourceToken))
                    throw Error("OpenProcessToken(current)");
                // SAFER_SCOPEID_MACHINE, NORMALUSER, SAFER_LEVEL_OPEN.
                if (!SaferCreateLevel(1, 0x20000, 1, out level, IntPtr.Zero))
                    throw Error("SaferCreateLevel(NORMALUSER)");
                if (!SaferComputeTokenFromLevel(level, sourceToken,
                    out reducedToken, 0, IntPtr.Zero))
                    throw Error("SaferComputeTokenFromLevel(NORMALUSER)");
                Require(reducedToken != IntPtr.Zero, "SAFER returned no token");
                Facts = Inspect(reducedToken);
            } catch {
                Dispose();
                throw;
            }
        }

        private sealed class Information : IDisposable {
            public IntPtr Pointer;
            public int Length;
            public Information(IntPtr token, int kind) {
                uint length;
                bool initial = GetTokenInformation(token, kind, IntPtr.Zero, 0, out length);
                int code = Marshal.GetLastWin32Error();
                Require(!initial && code == 122 && length > 0 && length <= 1048576,
                    "Invalid variable token information size: class=" + kind + " code=" + code + " bytes=" + length);
                Pointer = Marshal.AllocHGlobal(checked((int)length));
                try {
                    uint returned;
                    if (!GetTokenInformation(token, kind, Pointer, length, out returned))
                        throw Error("GetTokenInformation");
                    Require(returned > 0 && returned <= length, "Invalid token information length");
                    Length = checked((int)returned);
                } catch { Dispose(); throw; }
            }
            public int Integer(int offset) {
                Require(offset >= 0 && offset <= Length - 4, "Token integer out of bounds");
                return Marshal.ReadInt32(Pointer, offset);
            }
            public IntPtr Sid(int offset) {
                Require(offset >= 0 && offset <= Length - IntPtr.Size, "SID field out of bounds");
                IntPtr sid = Marshal.ReadIntPtr(Pointer, offset);
                long relative = sid.ToInt64() - Pointer.ToInt64();
                Require(relative >= 0 && relative <= Length - 8, "SID header out of bounds");
                int count = Marshal.ReadByte(sid, 1);
                Require(count > 0 && count <= 15 && relative + 8 + count * 4 <= Length,
                    "SID data out of bounds");
                Require(IsValidSid(sid), "Invalid token SID");
                return sid;
            }
            public void Dispose() {
                if (Pointer != IntPtr.Zero) {
                    Marshal.FreeHGlobal(Pointer);
                    Pointer = IntPtr.Zero;
                }
            }
        }
        private static int Scalar(IntPtr token, int kind) {
            // Same exact-DWORD contract as the product. Fixed token classes
            // do not share the variable-size NULL-buffer probe contract.
            IntPtr value = Marshal.AllocHGlobal(4);
            try {
                Marshal.WriteInt32(value, 0);
                uint returned;
                if (!GetTokenInformation(token, kind, value, 4, out returned))
                    throw Error("GetTokenInformation(scalar " + kind + ")");
                Require(returned == 4, "Invalid scalar token size: class=" + kind);
                return Marshal.ReadInt32(value);
            } finally { Marshal.FreeHGlobal(value); }
        }
        private static TokenFacts Inspect(IntPtr token) {
            TokenFacts facts = new TokenFacts();
            int type = Scalar(token, 8);
            facts.tokenType = type == 1 ? "Primary" : type == 2 ? "Impersonation" : "Unknown";
            facts.elevation = Scalar(token, 20);
            int elevationType = Scalar(token, 18);
            facts.elevationType = elevationType == 1 ? "Default" :
                elevationType == 2 ? "Full" : elevationType == 3 ? "Limited" : "Unknown";
            facts.sessionInteractive = Scalar(token, 12) > 0;
            facts.isAppContainer = Scalar(token, 29) != 0;
            facts.uiAccess = Scalar(token, 26) != 0;
            using (Information value = new Information(token, 25)) {
                IntPtr sid = value.Sid(0);
                int count = Marshal.ReadByte(sid, 1);
                facts.integrityRid = Marshal.ReadInt32(sid, 8 + (count - 1) * 4);
            }
            using (Information value = new Information(token, 1)) {
                facts.isSystem = IsWellKnownSid(value.Sid(0), 22); // WinLocalSystemSid.
            }
            using (Information value = new Information(token, 2)) {
                int count = value.Integer(0);
                int start = IntPtr.Size == 8 ? 8 : 4;
                int stride = IntPtr.Size == 8 ? 16 : 8;
                Require(count >= 0 && count <= 1024 && start + count * stride <= value.Length,
                    "Invalid token group bounds");
                for (int index = 0; index < count; index++) {
                    int offset = start + index * stride;
                    if (IsWellKnownSid(value.Sid(offset), 26) &&
                        (value.Integer(offset + IntPtr.Size) & 4) != 0)
                        facts.adminEnabled = true; // SE_GROUP_ENABLED, not deny-only.
                }
            }
            return facts;
        }
        private static void Verify(TokenFacts facts) {
            Require(facts.tokenType == "Primary" && facts.integrityRid == 8192 &&
                facts.elevation == 0 &&
                (facts.elevationType == "Default" || facts.elevationType == "Limited") &&
                !facts.adminEnabled && facts.sessionInteractive && !facts.isSystem &&
                !facts.isAppContainer && !facts.uiAccess,
                String.Format("Reduced token does not satisfy GuiMedium: type={0}, integrityRid={1}, " +
                    "elevation={2}, elevationType={3}, adminEnabled={4}, sessionInteractive={5}, " +
                    "isSystem={6}, isAppContainer={7}, uiAccess={8}", facts.tokenType,
                    facts.integrityRid, facts.elevation, facts.elevationType, facts.adminEnabled,
                    facts.sessionInteractive, facts.isSystem, facts.isAppContainer, facts.uiAccess));
        }

        public void RequireMedium() { Verify(Facts); }

        private IntPtr ChildEnvironment(string profile) {
            IntPtr original;
            if (!CreateEnvironmentBlock(out original, reducedToken, false))
                throw Error("CreateEnvironmentBlock");
            SortedDictionary<string, string> values =
                new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try {
                // Bounded UTF-16 environment walk; no values are logged.
                int at = 0;
                while (at < 131072) {
                    int start = at;
                    while (at < 131072 && Marshal.ReadInt16(original, checked(at * 2)) != 0) at++;
                    Require(at < 131072, "Environment block exceeds bound");
                    if (at == start) break;
                    string entry = Marshal.PtrToStringUni(IntPtr.Add(original, start * 2), at - start);
                    int separator = entry.IndexOf('=', 1);
                    Require(separator > 0, "Invalid environment entry");
                    values[entry.Substring(0, separator)] = entry.Substring(separator + 1);
                    at++;
                }
                Require(at < 131072, "Environment block missing terminator");
            } finally {
                if (!DestroyEnvironmentBlock(original)) throw Error("DestroyEnvironmentBlock");
            }
            values["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] =
                "--remote-debugging-port=19225 --remote-debugging-address=127.0.0.1";
            values["WEBVIEW2_USER_DATA_FOLDER"] = profile;
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> value in values)
                block.Append(value.Key).Append('=').Append(value.Value).Append('\0');
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        public void Launch(string profile) {
            Verify(Facts);
            Require(process == IntPtr.Zero && reducedToken != IntPtr.Zero,
                "Launcher can own only one child");
            Require(File.Exists(Application), "Fixed installed controller application missing");
            Require(Directory.Exists(profile), "Fresh child profile missing");
            IntPtr environment = ChildEnvironment(profile);
            try {
                StartupInfo startup = new StartupInfo();
                startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
                startup.lpDesktop = @"winsta0\default";
                startup.dwFlags = 1; // STARTF_USESHOWWINDOW.
                startup.wShowWindow = 0; // SW_HIDE; no interactive user prompt.
                ProcessInformation information;
                // Explicit fixed lpApplicationName; no shell or arbitrary args.
                // Suspend until the ACTUAL child's primary token is checked.
                if (!CreateProcessWithTokenW(reducedToken, 0, Application,
                    new StringBuilder("\"" + Application + "\""), 0x404,
                    environment, Path.GetDirectoryName(Application), ref startup, out information))
                    throw Error("CreateProcessWithTokenW");
                process = information.hProcess;
                thread = information.hThread;
                ClientPid = information.dwProcessId;
                IntPtr childToken;
                if (!OpenProcessToken(process, 8, out childToken))
                    throw Error("OpenProcessToken(owned child)");
                try {
                    Facts = Inspect(childToken);
                    Verify(Facts);
                } finally {
                    if (!CloseHandle(childToken)) throw Error("CloseHandle(child token)");
                }
                if (ResumeThread(thread) == UInt32.MaxValue) throw Error("ResumeThread(owned child)");
            } finally { Marshal.FreeHGlobal(environment); }
        }

        public void Dispose() {
            Exception failure = null;
            if (process != IntPtr.Zero) {
                uint state = WaitForSingleObject(process, 0);
                if (state == 258) {
                    if (!TerminateProcess(process, 193)) failure = Error("TerminateProcess(owned child)");
                    if (WaitForSingleObject(process, 5000) != 0)
                        failure = new InvalidOperationException("Owned child termination unconfirmed");
                } else if (state != 0) failure = Error("WaitForSingleObject(owned child)");
            }
            foreach (IntPtr handle in new IntPtr[] { thread, process, reducedToken, sourceToken }) {
                if (handle != IntPtr.Zero && !CloseHandle(handle)) failure = Error("CloseHandle(owned)");
            }
            thread = process = reducedToken = sourceToken = IntPtr.Zero;
            if (level != IntPtr.Zero && !SaferCloseLevel(level)) failure = Error("SaferCloseLevel");
            level = IntPtr.Zero;
            if (failure != null) throw failure;
        }
    }
}
'@

$launcher = $null
$nodeExit = 1
try {
    $launcher = New-Object UacCiMedium.Launcher
    # Only enum/bool/fixed integrity facts, never account names, SIDs or tokens.
    $launcher.Facts | ConvertTo-Json -Compress | Write-Output
    $launcher.RequireMedium()
    if ($InspectOnly) { return }

    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
        [string]::IsNullOrWhiteSpace($env:LAB_EVIDENCE)) {
        throw 'RUNNER_TEMP and LAB_EVIDENCE must be set by the hosted lab.'
    }
    $temporaryRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')
    $evidenceRoot = [IO.Path]::GetFullPath($env:LAB_EVIDENCE).TrimEnd('\')
    if (-not [IO.Directory]::Exists($temporaryRoot) -or -not [IO.Directory]::Exists($evidenceRoot)) {
        throw 'Hosted temporary and evidence directories must already exist.'
    }
    $profileDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ('uac-medium-' + [guid]::NewGuid().ToString('N'))))
    if (-not $profileDirectory.StartsWith($temporaryRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $profileDirectory.StartsWith($evidenceRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $profileDirectory.Equals($evidenceRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Directory]::Exists($profileDirectory) -or [IO.File]::Exists($profileDirectory)) {
        throw 'The fresh WebView profile must be outside uploaded evidence.'
    }
    [IO.Directory]::CreateDirectory($profileDirectory) | Out-Null
    # Kept only on this ephemeral hosted VM. Never upload or recursively delete.
    $launcher.Launch($profileDirectory)
    $receipt = [ordered]@{
        clientPid = $launcher.ClientPid
        debugPort = 19225
        profileDirectory = $profileDirectory
        token = $launcher.Facts
    } | ConvertTo-Json -Depth 4
    $receiptPath = Join-Path $evidenceRoot 'medium-client.json'
    $receiptStream = [IO.File]::Open($receiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($receipt + [Environment]::NewLine)
        $receiptStream.Write($bytes, 0, $bytes.Length)
    } finally { $receiptStream.Dispose() }

    & node (Join-Path $PSScriptRoot 'windows-management-webview-lab.mjs')
    $nodeExit = $LASTEXITCODE
    if ($null -eq $nodeExit) { throw 'Node did not supply an exit code.' }
} finally {
    if ($null -ne $launcher) { $launcher.Dispose() }
    # Parent WEBVIEW2 variables were never mutated: the native explicit child
    # environment is separately allocated/freed, so original values remain.
}
if (-not $InspectOnly -and $nodeExit -eq 0) {
    $proofPath = Join-Path $env:LAB_EVIDENCE 'management-gui-proof.json'
    $proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
    Start-Sleep -Seconds 2
    $serviceAfterClose = Get-CimInstance Win32_Service -Filter "Name='UacRemoteController'"
    if ($serviceAfterClose.State -ne 'Running' -or $serviceAfterClose.ProcessId -ne $proof.originalServicePid) {
        throw 'Closing the owned GUI changed the original service lifetime.'
    }
    $proof | Add-Member -NotePropertyName appClosedServiceRetained -NotePropertyValue $true
    $proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $proofPath -Encoding UTF8
}
exit $nodeExit
