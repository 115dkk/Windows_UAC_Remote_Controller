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
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace UacCiMedium {
    public sealed class TokenFacts {
        public string tokenType;
        public int integrityRid;
        public int elevation;
        public string elevationType;
        public bool adminEnabled;
        public bool sessionNonzero;
        public bool isSystem;
        public bool isAppContainer;
        public bool uiAccess;
    }

    // Only this owner's original child handles may be stopped/closed. No
    // process lookup, external PID adoption, service control or token mutation.
    public sealed class Launcher : IDisposable {
        private IntPtr logonToken, password, process, thread, profileProcess, profileThread;
        private string userName;
        private bool accountCreated;
        private const int PasswordCharacters = 36;
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
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct UserInfo1 {
            public string name;
            public IntPtr password;
            public uint passwordAge, privilege;
            public string homeDirectory, comment;
            public uint flags;
            public string scriptPath;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LocalGroupMember3 { public string domainAndName; }
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserAdd(string server, uint level,
            ref UserInfo1 information, out uint parameterError);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetUserDel(string server, string user);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetLocalGroupAddMembers(string server, string group,
            uint level, ref LocalGroupMember3 member, uint count);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
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
        private static extern bool LogonUserW([MarshalAs(UnmanagedType.LPWStr)] string user,
            [MarshalAs(UnmanagedType.LPWStr)] string domain, IntPtr password,
            uint logonType, uint provider, out IntPtr token);
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
                CreateStandardAccount();
                if (!LogonUserW(userName, Environment.MachineName, password, 2, 0, out logonToken))
                    throw Error("LogonUserW(owned standard account)");
                // LOGON_WITH_PROFILE loads this account's real profile. This
                // fixed inert cmd process NEVER resumes; its original handle
                // stays owned so that profile remains loaded for the GUI.
                string probe = Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.System), "cmd.exe");
                ProcessInformation information = CreateSuspended(probe,
                    "\"" + probe + "\" /d /c exit 0", IntPtr.Zero);
                profileProcess = information.hProcess;
                profileThread = information.hThread;
                Facts = InspectProcess(profileProcess);
            } catch {
                Dispose();
                throw;
            }
        }

        private void CreateStandardAccount() {
            userName = "uacm" + Guid.NewGuid().ToString("N").Substring(0, 12);
            password = Marshal.AllocHGlobal((PasswordCharacters + 1) * 2);
            byte[] randomness = new byte[PasswordCharacters - 4];
            try {
                using (RandomNumberGenerator random = RandomNumberGenerator.Create())
                    random.GetBytes(randomness);
                const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                const string prefix = "aA1!";
                for (int index = 0; index < PasswordCharacters; index++) {
                    char character = index < 4 ? prefix[index] : alphabet[randomness[index - 4] & 63];
                    Marshal.WriteInt16(password, index * 2, (short)character);
                }
                Marshal.WriteInt16(password, PasswordCharacters * 2, 0);
            } finally { Array.Clear(randomness, 0, randomness.Length); }
            UserInfo1 user = new UserInfo1();
            user.name = userName;
            user.password = password;
            user.privilege = 1; // USER_PRIV_USER, never administrator.
            user.comment = "Ephemeral hosted CI read-only controller client";
            user.flags = 0x201; // UF_SCRIPT | UF_NORMAL_ACCOUNT.
            uint parameterError;
            uint status = NetUserAdd(null, 1, ref user, out parameterError);
            if (status != 0) throw new InvalidOperationException(
                "NetUserAdd(owned standard account) status=" + status + " field=" + parameterError);
            accountCreated = true;
            // Resolve the built-in Users name through its fixed SID to avoid
            // localized group-name assumptions. No Administrators addition.
            string qualified = ((NTAccount)new SecurityIdentifier("S-1-5-32-545").Translate(
                typeof(NTAccount))).Value;
            string users = qualified.Substring(qualified.LastIndexOf('\\') + 1);
            LocalGroupMember3 member = new LocalGroupMember3();
            member.domainAndName = Environment.MachineName + "\\" + userName;
            status = NetLocalGroupAddMembers(null, users, 3, ref member, 1);
            if (status != 0 && status != 1378) throw new InvalidOperationException(
                "NetLocalGroupAddMembers(Users only) status=" + status);
        }

        private ProcessInformation CreateSuspended(string application, string commandLine,
            IntPtr environment) {
            StartupInfo startup = new StartupInfo();
            startup.cb = (uint)Marshal.SizeOf(typeof(StartupInfo));
            // Documented WithToken inheritance grants this genuine account
            // access to the caller's ordinary desktop, never the secure one.
            // No manual desktop ACL or UAC policy modification is performed.
            startup.lpDesktop = null;
            startup.dwFlags = 1; // STARTF_USESHOWWINDOW.
            startup.wShowWindow = 0; // SW_HIDE.
            ProcessInformation information;
            if (!CreateProcessWithTokenW(logonToken, 1,
                application, new StringBuilder(commandLine), 0x404, environment,
                Path.GetDirectoryName(application), ref startup, out information))
                throw Error("CreateProcessWithTokenW(owned standard account)");
            return information;
        }

        private static TokenFacts InspectProcess(IntPtr ownedProcess) {
            IntPtr token;
            if (!OpenProcessToken(ownedProcess, 8, out token))
                throw Error("OpenProcessToken(owned child)");
            try { return Inspect(token); }
            finally { if (!CloseHandle(token)) throw Error("CloseHandle(child token)"); }
        }

        public byte[] AccountSid() {
            using (Information value = new Information(logonToken, 1)) {
                IntPtr sid = value.Sid(0);
                int length = 8 + Marshal.ReadByte(sid, 1) * 4;
                byte[] bytes = new byte[length];
                Marshal.Copy(sid, bytes, 0, length);
                return bytes;
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
            facts.sessionNonzero = Scalar(token, 12) > 0;
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
                !facts.adminEnabled && facts.sessionNonzero && !facts.isSystem &&
                !facts.isAppContainer && !facts.uiAccess,
                String.Format("Standard child token does not satisfy GuiMedium: type={0}, integrityRid={1}, " +
                    "elevation={2}, elevationType={3}, adminEnabled={4}, sessionNonzero={5}, " +
                    "isSystem={6}, isAppContainer={7}, uiAccess={8}", facts.tokenType,
                    facts.integrityRid, facts.elevation, facts.elevationType, facts.adminEnabled,
                    facts.sessionNonzero, facts.isSystem, facts.isAppContainer, facts.uiAccess));
        }

        public void RequireMedium() { Verify(Facts); }

        private IntPtr ChildEnvironment(string profile) {
            IntPtr original;
            if (!CreateEnvironmentBlock(out original, logonToken, false))
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
            Require(process == IntPtr.Zero && logonToken != IntPtr.Zero && profileProcess != IntPtr.Zero,
                "Launcher can own only one child");
            Require(File.Exists(Application), "Fixed installed controller application missing");
            Require(Directory.Exists(profile), "Fresh child profile missing");
            IntPtr environment = ChildEnvironment(profile);
            try {
                // Explicit fixed lpApplicationName; no shell or arbitrary args.
                // Suspend until the ACTUAL child's primary token is checked.
                ProcessInformation information = CreateSuspended(Application,
                    "\"" + Application + "\"", environment);
                process = information.hProcess;
                thread = information.hThread;
                ClientPid = information.dwProcessId;
                Facts = InspectProcess(process);
                Verify(Facts);
                if (ResumeThread(thread) == UInt32.MaxValue) throw Error("ResumeThread(owned child)");
            } finally { Marshal.FreeHGlobal(environment); }
        }

        public uint OwnedGuiExitCode() {
            if (process == IntPtr.Zero) return 0;
            uint code;
            if (!GetExitCodeProcess(process, out code)) throw Error("GetExitCodeProcess(owned GUI)");
            return code;
        }

        public void Dispose() {
            Exception failure = null;
            foreach (IntPtr ownedProcess in new IntPtr[] { process, profileProcess }) {
                if (ownedProcess == IntPtr.Zero) continue;
                uint state = WaitForSingleObject(ownedProcess, 0);
                if (state == 258) {
                    if (!TerminateProcess(ownedProcess, 193)) failure = Error("TerminateProcess(owned child)");
                    if (WaitForSingleObject(ownedProcess, 5000) != 0)
                        failure = new InvalidOperationException("Owned child termination unconfirmed");
                } else if (state != 0) failure = Error("WaitForSingleObject(owned child)");
            }
            foreach (IntPtr handle in new IntPtr[] { thread, process, profileThread, profileProcess, logonToken }) {
                if (handle != IntPtr.Zero && !CloseHandle(handle)) failure = Error("CloseHandle(owned)");
            }
            thread = process = profileThread = profileProcess = logonToken = IntPtr.Zero;
            if (accountCreated) {
                uint status = NetUserDel(null, userName);
                if (status != 0) failure = new InvalidOperationException(
                    "NetUserDel(owned nonce account) status=" + status);
                else accountCreated = false;
            }
            if (password != IntPtr.Zero) {
                for (int index = 0; index <= PasswordCharacters; index++)
                    Marshal.WriteInt16(password, index * 2, 0);
                Marshal.FreeHGlobal(password);
                password = IntPtr.Zero;
            }
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
    # This fresh standard account needs access only to its own WebView folder.
    # Remove inherited entries; preserve SYSTEM/Admin recovery access. Never
    # broaden RUNNER_TEMP, installed product, service state, or evidence ACLs.
    $profileAcl = New-Object Security.AccessControl.DirectorySecurity
    $profileAcl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $clientSid = [Security.Principal.SecurityIdentifier]::new($launcher.AccountSid(), 0)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($entry in @(
        @{ Sid = $clientSid; Rights = [Security.AccessControl.FileSystemRights]::Modify },
        @{ Sid = $systemSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid = $adminSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl }
    )) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($entry.Sid, $entry.Rights, $inheritance, $propagation, $allow)
        $profileAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $profileDirectory -AclObject $profileAcl
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
    if ($null -ne $launcher) {
        try { Write-Output ("Owned GUI exit code before cleanup: {0}" -f $launcher.OwnedGuiExitCode()) }
        finally { $launcher.Dispose() }
    }
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
    $listenersAfterClose = @(Get-NetTCPConnection -State Listen)
    if ($listenersAfterClose | Where-Object LocalPort -eq 19225) {
        throw 'Owned WebView debugger listener remained after GUI cleanup.'
    }
    if (-not ($listenersAfterClose | Where-Object { $_.LocalPort -eq 7443 -and $_.OwningProcess -eq $proof.originalServicePid })) {
        throw 'Original relay listener disappeared after GUI cleanup.'
    }
    $proof | Add-Member -NotePropertyName appClosedServiceRetained -NotePropertyValue $true
    $proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $proofPath -Encoding UTF8
}
exit $nodeExit
