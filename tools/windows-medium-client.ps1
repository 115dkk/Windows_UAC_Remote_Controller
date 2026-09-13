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

    public sealed class WindowFact {
        public string windowClass;
        public string textClassification;
        public bool visible;
        public bool enabled;
        public bool child;
        public bool textQueryAttempted;
        public bool textQueryCompleted;
    }
    public sealed class OwnedGuiDiagnostics {
        public uint clientPid;
        public uint exitCode;
        public string primaryThreadState;
        public string primaryDesktop;
        public string primaryDesktopType;
        public string primaryDesktopFailureApi;
        public int primaryDesktopWin32Error;
        public string primaryDesktopTypeFailureApi;
        public int primaryDesktopTypeWin32Error;
        public uint? resumePreviousCount;
        public bool modulesEnumerated;
        public bool modulesTruncated;
        public bool webView2Loader;
        public bool embeddedBrowserWebView;
        public bool user32;
        public bool ole32;
        public bool combase;
        public bool dcomp;
        public bool processSnapshotEnumerated;
        public bool processSnapshotTruncated;
        public bool descendantCountsAreSnapshotOnly = true;
        public uint ownThreadCount;
        public int directChildCount;
        public int descendantCount;
        public int webViewDescendantCount;
        public bool windowsTruncated;
        public bool currentDesktopWindowsEnumerated;
        public bool primaryThreadWindowsEnumerated;
        public List<WindowFact> windows = new List<WindowFact>();
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
        public uint? ResumePreviousCount { get; private set; }
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
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ProcessEntry {
            public uint size, usage, pid;
            public UIntPtr defaultHeap;
            public uint moduleId, threads, parentPid;
            public int basePriority;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string executable;
        }
        private delegate bool WindowVisitor(IntPtr window, IntPtr parameter);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetThreadId(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry entry);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry entry);
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(IntPtr process,
            [Out] IntPtr[] modules, uint bytes, out uint needed, uint filter);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetModuleBaseNameW(IntPtr process, IntPtr module,
            StringBuilder name, uint characters);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumWindows(WindowVisitor visitor, IntPtr parameter);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumThreadWindows(uint threadId, WindowVisitor visitor, IntPtr parameter);
        [DllImport("user32.dll")]
        private static extern bool EnumChildWindows(IntPtr parent, WindowVisitor visitor, IntPtr parameter);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassNameW(IntPtr window, StringBuilder name, int characters);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int characters);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SendMessageTimeoutW(IntPtr window, uint message,
            UIntPtr wparam, StringBuilder text, uint flags, uint timeout, out UIntPtr result);
        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")]
        private static extern bool IsWindowEnabled(IntPtr window);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetThreadDesktop(uint threadId);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetUserObjectInformationW(IntPtr handle, int kind,
            StringBuilder value, uint bytes, out uint needed);
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
        private static extern bool CreateProcessWithLogonW(string user, string domain,
            IntPtr password, uint logonFlags,
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
                // fixed inert cmd stays suspended during normal GUI runs so
                // the profile remains loaded. InspectOnly resumes this exact
                // probe once and requires its bounded successful exit.
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
            // Inherit the caller's ordinary desktop, never the secure one.
            // No manual desktop ACL or UAC policy modification is performed.
            startup.lpDesktop = null;
            startup.dwFlags = 1; // STARTF_USESHOWWINDOW.
            startup.wShowWindow = 0; // SW_HIDE.
            ProcessInformation information;
            if (!CreateProcessWithLogonW(userName, Environment.MachineName, password, 1,
                application, new StringBuilder(commandLine), 0x404, environment,
                Path.GetDirectoryName(application), ref startup, out information))
                throw Error("CreateProcessWithLogonW(owned standard account)");
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

        public void ProbeOwnedProfileProcessExit() {
            Verify(Facts);
            Require(process == IntPtr.Zero && profileProcess != IntPtr.Zero && profileThread != IntPtr.Zero,
                "Preflight requires only the original fixed profile probe");
            uint previousCount = ResumeThread(profileThread);
            int resumeError = previousCount == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
            if (previousCount == UInt32.MaxValue)
                throw new Win32Exception(resumeError, "ResumeThread(owned fixed preflight)");
            Require(previousCount == 1, "Owned fixed preflight suspend count was not exactly one: " + previousCount);
            uint result = WaitForSingleObject(profileProcess, 5000);
            if (result == UInt32.MaxValue) throw Error("WaitForSingleObject(owned fixed preflight)");
            Require(result == 0, "Owned fixed preflight did not exit within five seconds");
            uint code;
            if (!GetExitCodeProcess(profileProcess, out code))
                throw Error("GetExitCodeProcess(owned fixed preflight)");
            Require(code == 0, "Owned fixed preflight did not exit with code zero");
        }

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
                uint previousCount = ResumeThread(thread);
                int resumeError = previousCount == UInt32.MaxValue ? Marshal.GetLastWin32Error() : 0;
                ResumePreviousCount = previousCount;
                if (previousCount == UInt32.MaxValue)
                    throw new Win32Exception(resumeError, "ResumeThread(owned child)");
                Require(previousCount == 1, "Owned GUI initial suspend count was not exactly one");
            } finally { Marshal.FreeHGlobal(environment); }
        }

        public uint OwnedGuiExitCode() {
            if (process == IntPtr.Zero) return 0;
            uint code;
            if (!GetExitCodeProcess(process, out code)) throw Error("GetExitCodeProcess(owned GUI)");
            return code;
        }

        // Only fixed classifications leave this method. Caption/control text,
        // module paths, process names and desktop names are never returned.
        private static string ClassifyText(string text) {
            if (String.IsNullOrEmpty(text)) return "Empty";
            string value = text.ToLowerInvariant();
            if (value.Contains("webview")) {
                if (value.Contains("not found") || value.Contains("missing") ||
                    value.Contains("not installed") || value.Contains("could not find") ||
                    value.Contains("couldn't find")) return "WebViewMissing";
                if (value.Contains("error") || value.Contains("failed") ||
                    value.Contains("failure")) return "WebViewError";
                return "WebViewMention";
            }
            if (text == "UAC \uC6D0\uACA9 \uC2B9\uC778" || text == "UAC Remote Approval")
                return "ApplicationTitle";
            return "OtherNonempty";
        }
        private static string ClassifyWindow(string name) {
            if (name == "#32770") return "Dialog";
            if (name == "Static" || name == "Button") return name;
            if (name.StartsWith("Chrome_WidgetWin_", StringComparison.Ordinal)) return "ChromeWidget";
            if (name.StartsWith("Chrome_RenderWidgetHost", StringComparison.Ordinal)) return "ChromeRenderHost";
            if (name.IndexOf("tao", StringComparison.OrdinalIgnoreCase) >= 0) return "TaoWindow";
            if (name.IndexOf("wry", StringComparison.OrdinalIgnoreCase) >= 0) return "WryWindow";
            return String.IsNullOrEmpty(name) ? "Unavailable" : "Other";
        }
        private static string DesktopFact(IntPtr desktop, string desktopFailureApi,
            int desktopError, int kind, out string failureApi, out int win32Error) {
            failureApi = null;
            win32Error = 0;
            if (desktop == IntPtr.Zero) {
                failureApi = desktopFailureApi;
                win32Error = desktopError;
                return "Unavailable";
            }
            StringBuilder value = new StringBuilder(256);
            uint needed;
            if (!GetUserObjectInformationW(desktop, kind, value, 512, out needed)) {
                win32Error = Marshal.GetLastWin32Error();
                failureApi = kind == 2 ? "GetUserObjectInformationW(NAME)" : "GetUserObjectInformationW(TYPE)";
                return "Unavailable";
            }
            string text = value.ToString();
            if (kind == 2) return text.Equals("Default", StringComparison.OrdinalIgnoreCase) ? "Default" : "Other";
            return text.Equals("Desktop", StringComparison.OrdinalIgnoreCase) ? "Desktop" : "Other";
        }

        public OwnedGuiDiagnostics DiagnoseOwnedGui() {
            Require(process != IntPtr.Zero && thread != IntPtr.Zero,
                "Diagnostics require original GUI handles");
            uint ownedPid = GetProcessId(process);
            Require(ownedPid != 0 && ownedPid == ClientPid, "Original GUI handle identity mismatch");
            OwnedGuiDiagnostics facts = new OwnedGuiDiagnostics();
            facts.clientPid = ownedPid;
            facts.exitCode = OwnedGuiExitCode();
            facts.resumePreviousCount = ResumePreviousCount;
            uint state = WaitForSingleObject(thread, 0);
            facts.primaryThreadState = state == 258 ? "Live" : state == 0 ? "Terminated" : "Unavailable";
            uint primaryThread = GetThreadId(thread);
            int desktopError = primaryThread == 0 ? Marshal.GetLastWin32Error() : 0;
            string desktopFailureApi = primaryThread == 0 ? "GetThreadId" : null;
            IntPtr desktop = primaryThread == 0 ? IntPtr.Zero : GetThreadDesktop(primaryThread);
            if (primaryThread != 0 && desktop == IntPtr.Zero) {
                desktopError = Marshal.GetLastWin32Error();
                desktopFailureApi = "GetThreadDesktop";
            }
            // GetThreadDesktop returns a borrowed handle; it must not be closed.
            facts.primaryDesktop = DesktopFact(desktop, desktopFailureApi, desktopError, 2,
                out facts.primaryDesktopFailureApi, out facts.primaryDesktopWin32Error);
            facts.primaryDesktopType = DesktopFact(desktop, desktopFailureApi, desktopError, 3,
                out facts.primaryDesktopTypeFailureApi, out facts.primaryDesktopTypeWin32Error);

            IntPtr[] modules = new IntPtr[1024];
            uint needed;
            facts.modulesEnumerated = EnumProcessModulesEx(process, modules,
                (uint)(modules.Length * IntPtr.Size), out needed, 3);
            facts.modulesTruncated = needed > modules.Length * IntPtr.Size;
            if (facts.modulesEnumerated) {
                int count = Math.Min(modules.Length, (int)(needed / IntPtr.Size));
                for (int index = 0; index < count; index++) {
                    StringBuilder name = new StringBuilder(260);
                    if (GetModuleBaseNameW(process, modules[index], name, 260) == 0) continue;
                    switch (name.ToString().ToLowerInvariant()) {
                        case "webview2loader.dll": facts.webView2Loader = true; break;
                        case "embeddedbrowserwebview.dll":
                        case "embedded_browser_webview.dll": facts.embeddedBrowserWebView = true; break;
                        case "user32.dll": facts.user32 = true; break;
                        case "ole32.dll": facts.ole32 = true; break;
                        case "combase.dll": facts.combase = true; break;
                        case "dcomp.dll": facts.dcomp = true; break;
                    }
                }
            }

            // System snapshot is filtered to own PID/ancestry before emitting
            // counts. No descendant handle is opened/adopted or acted upon.
            IntPtr snapshot = CreateToolhelp32Snapshot(2, 0);
            if (snapshot != new IntPtr(-1)) {
                try {
                    List<ProcessEntry> entries = new List<ProcessEntry>();
                    ProcessEntry entry = new ProcessEntry();
                    entry.size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
                    bool more = Process32FirstW(snapshot, ref entry);
                    facts.processSnapshotEnumerated = more;
                    while (more && entries.Count < 8192) {
                        entries.Add(entry);
                        if (entry.pid == ownedPid) facts.ownThreadCount = entry.threads;
                        if (entry.parentPid == ownedPid) facts.directChildCount++;
                        more = Process32NextW(snapshot, ref entry);
                    }
                    facts.processSnapshotTruncated = more;
                    HashSet<uint> descendants = new HashSet<uint>();
                    descendants.Add(ownedPid);
                    for (int depth = 0; depth < 32; depth++) {
                        bool changed = false;
                        foreach (ProcessEntry item in entries) {
                            if (descendants.Contains(item.parentPid) && descendants.Add(item.pid)) {
                                facts.descendantCount++;
                                if (String.Equals(item.executable, "msedgewebview2.exe",
                                    StringComparison.OrdinalIgnoreCase)) facts.webViewDescendantCount++;
                                changed = true;
                            }
                        }
                        if (!changed) break;
                    }
                } finally { if (!CloseHandle(snapshot)) throw Error("CloseHandle(diagnostic snapshot)"); }
            }

            HashSet<IntPtr> seen = new HashSet<IntPtr>();
            Action<IntPtr, bool, bool> inspectWindow = delegate(IntPtr window, bool child, bool dialog) {
                if (facts.windows.Count >= 128) { facts.windowsTruncated = true; return; }
                uint windowPid;
                GetWindowThreadProcessId(window, out windowPid);
                if (windowPid != ownedPid || !seen.Add(window)) return;
                StringBuilder name = new StringBuilder(128);
                GetClassNameW(window, name, 128);
                string windowClass = ClassifyWindow(name.ToString());
                StringBuilder text = new StringBuilder(512);
                bool textAttempted = false;
                bool textCompleted = false;
                if (child && dialog && windowClass == "Static") {
                    textAttempted = true;
                    UIntPtr result;
                    // WM_GETTEXT only, no input/actions. Each read is bounded
                    // to 25ms; at most 128 windows => 3.2s total send budget.
                    textCompleted = SendMessageTimeoutW(window, 13, new UIntPtr(512), text,
                        2, 25, out result) != IntPtr.Zero;
                } else if (!child) {
                    textAttempted = true;
                    // A zero result is empty OR unavailable; retain unknown.
                    textCompleted = GetWindowTextW(window, text, 512) > 0;
                }
                GetWindowThreadProcessId(window, out windowPid);
                if (windowPid != ownedPid) return;
                facts.windows.Add(new WindowFact {
                    windowClass = windowClass,
                    textClassification = ClassifyText(text.ToString()),
                    visible = IsWindowVisible(window), enabled = IsWindowEnabled(window),
                    child = child, textQueryAttempted = textAttempted,
                    textQueryCompleted = textCompleted
                });
            };
            WindowVisitor visitor = delegate(IntPtr window, IntPtr unused) {
                if (facts.windows.Count >= 128) { facts.windowsTruncated = true; return false; }
                uint windowPid;
                GetWindowThreadProcessId(window, out windowPid);
                if (windowPid != ownedPid) return true;
                StringBuilder name = new StringBuilder(128);
                GetClassNameW(window, name, 128);
                bool dialog = name.ToString() == "#32770";
                inspectWindow(window, false, dialog);
                WindowVisitor childVisitor = delegate(IntPtr child, IntPtr ignored) {
                    inspectWindow(child, true, dialog);
                    return facts.windows.Count < 128;
                };
                EnumChildWindows(window, childVisitor, IntPtr.Zero);
                return facts.windows.Count < 128;
            };
            facts.currentDesktopWindowsEnumerated = EnumWindows(visitor, IntPtr.Zero);
            facts.primaryThreadWindowsEnumerated = primaryThread != 0 &&
                EnumThreadWindows(primaryThread, visitor, IntPtr.Zero);
            return facts;
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

function Write-OwnedManagementObservation {
    param([string]$OwnedProfileDirectory)
    $observation = [ordered]@{ status = 'Unknown'; reason = 'Unavailable'; events = @() }
    try {
        $source = Join-Path $OwnedProfileDirectory 'management-client.txt'
        if (-not [IO.File]::Exists($source)) { throw 'Missing fixed diagnostic file' }
        $attributes = [IO.File]::GetAttributes($source)
        if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -ne 0) { throw 'Unsupported diagnostic file' }
        $stream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $buffer = New-Object byte[] 8193
            $count = 0
            while ($count -lt $buffer.Length) {
                $read = $stream.Read($buffer, $count, $buffer.Length - $count)
                if ($read -eq 0) { break }
                $count += $read
            }
        } finally { $stream.Dispose() }
        if ($count -gt 8192) { throw 'Diagnostic byte bound' }
        $text = ([Text.UTF8Encoding]::new($false, $true)).GetString($buffer, 0, $count)
        $lines = @($text -split '\r?\n')
        if ($lines.Count -gt 1 -and $lines[-1] -eq '') { $lines = @($lines[0..($lines.Count - 2)]) }
        if ($lines.Count -lt 2 -or $lines.Count -gt 64 -or $lines[0] -cne 'uac-ci-startup-notes-do-not-ship') { throw 'Diagnostic envelope' }
        $stages = @('exchange_start','starter_identity','helper_identity','own_impersonation','own_session_id',
            'own_token','own_token_requirement','own_process_identity','own_session_epoch','own_cleanup','own_recheck',
            'connect_budget','connect_reservation','connect_installation','connect_own_identity','connect_scm',
            'connect_service_sid','connect_pipe_open','connect_pipe_security','connect_pipe_identity',
            'connect_server_open','connect_server_identity','connect_first_fence','connect_read_mode','connect_final_fence',
            'fence_own_identity','fence_client_image','fence_scm','fence_pipe_security','fence_server_identity','fence_server_image',
            'exchange_connect','exchange_begin_write','exchange_poll_write','exchange_begin_read','exchange_poll_read','exchange_decode','exchange_cleanup',
            'deny_vm_read','deny_vm_write','deny_vm_operation','deny_duplicate','deny_terminate','deny_create_thread',
            'deny_create_process','deny_suspend','deny_set_information','deny_set_quota','deny_write_dacl','deny_write_owner',
            'deny_read_control','deny_query_information','deny_composite','deny_token_query','deny_token_duplicate','deny_token_impersonate','deny_token_assign')
        $categories = @('ok','busy','closed','invalid_phase','invalid_message','invalid_deadline','deadline_elapsed',
            'cancelled','end_of_stream','rejected','malformed','cleanup_unconfirmed','native','service_windows',
            'service_configuration','service_untrusted_installation','service_unsafe_path','service_unsafe_permissions',
            'service_elevation_required','service_not_installed','service_unexpected_state','service_other','access_denied','unexpected_grant')
        $events = @()
        foreach ($line in $lines[1..($lines.Count - 1)]) {
            if ($line -cnotmatch '^(?<stage>[a-z_]+) (?<category>[a-z_]+) (?<code>-?[0-9]{1,10})$') { throw 'Diagnostic row' }
            if ($stages -cnotcontains $Matches.stage -or $categories -cnotcontains $Matches.category) { throw 'Diagnostic token' }
            $code = [long]$Matches.code
            if ($code -lt -2147483648 -or $code -gt 4294967295) { throw 'Diagnostic code bound' }
            $events += [ordered]@{ stage = $Matches.stage; category = $Matches.category; code = $code }
        }
        $observation.status = 'Observed'
        $observation.reason = 'WhitelistedDiagnostics'
        $observation.events = $events
    } catch {
        # Never echo raw file contents, paths or exception messages.
        $observation.status = 'Unknown'
        $observation.reason = 'ReadOrFormatUnavailable'
        $observation.events = @()
    }
    $json = $observation | ConvertTo-Json -Depth 5
    Write-Output $json
    $path = Join-Path $env:LAB_EVIDENCE 'management-client-observation.json'
    $destination = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes($json + "`n")
        $destination.Write($bytes, 0, $bytes.Length)
    } finally { $destination.Dispose() }
}

function Write-OwnedStartupObservation {
    param([string]$OwnedProfileDirectory)
    $observation = [ordered]@{ status = 'Unknown'; reason = 'Unavailable'; stages = @() }
    $sanitized = $null
    try {
        $source = Join-Path $OwnedProfileDirectory 'controller-startup.txt'
        if ([IO.File]::Exists($source)) {
            $attributes = [IO.File]::GetAttributes($source)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                $observation.reason = 'UnsupportedFile'
            } else {
                $stream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                try {
                    # Read at most bound+1 bytes, including any concurrent append.
                    $buffer = New-Object byte[] 4097
                    $count = 0
                    while ($count -lt $buffer.Length) {
                        $read = $stream.Read($buffer, $count, $buffer.Length - $count)
                        if ($read -eq 0) { break }
                        $count += $read
                    }
                } finally { $stream.Dispose() }
                if ($count -gt 4096) {
                    $observation.reason = 'Oversized'
                } else {
                    $text = ([Text.UTF8Encoding]::new($false, $true)).GetString($buffer, 0, $count)
                    $lines = @($text -split '\r?\n')
                    if ($lines.Count -gt 1 -and $lines[$lines.Count - 1] -eq '') {
                        $lines = @($lines[0..($lines.Count - 2)])
                    }
                    $marker = 'uac-ci-startup-notes-do-not-ship'
                    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                    foreach ($stage in @('run_enter', 'builder_ready', 'setup_enter', 'appid_begin',
                        'appid_end', 'runtime_begin', 'runtime_end', 'window_begin', 'window_end',
                        'setup_end', 'build_end', 'event_loop_enter')) {
                        [void]$allowed.Add($stage)
                    }
                    $valid = $lines.Count -ge 1 -and $lines.Count -le 32 -and $lines[0] -ceq $marker
                    $stages = @()
                    for ($index = 1; $valid -and $index -lt $lines.Count; $index++) {
                        if (-not $allowed.Contains($lines[$index])) { $valid = $false }
                        else { $stages += $lines[$index] }
                    }
                    if ($valid -and $stages.Count -gt 0) {
                        $observation.status = 'Observed'
                        $observation.reason = 'WhitelistedStages'
                        $observation.stages = $stages
                        # Construct output from recognized tokens, not raw bytes.
                        $sanitized = (@($marker) + $stages) -join "`n"
                    } elseif ($valid) { $observation.reason = 'EmptyStages' }
                    else { $observation.reason = 'UnrecognizedFormat' }
                }
            }
        }
    } catch {
        # Missing/inaccessible path, invalid encoding and native read failures
        # are unknown startup progress, never proof that run_enter was absent.
        $observation.status = 'Unknown'
        $observation.reason = 'ReadUnavailable'
        $observation.stages = @()
        $sanitized = $null
    }
    $json = $observation | ConvertTo-Json -Depth 4
    Write-Output $json
    $outputs = @(@{ Name = 'controller-startup-observation.json'; Text = $json })
    if ($null -ne $sanitized) { $outputs += @{ Name = 'controller-startup.txt'; Text = $sanitized } }
    foreach ($output in $outputs) {
        $path = Join-Path $env:LAB_EVIDENCE $output.Name
        $destination = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        try {
            $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes($output.Text + "`n")
            $destination.Write($bytes, 0, $bytes.Length)
        } finally { $destination.Dispose() }
    }
}

$launcher = $null
$nodeExit = 1
try {
    $launcher = New-Object UacCiMedium.Launcher
    # Only enum/bool/fixed integrity facts, never account names, SIDs or tokens.
    $launcher.Facts | ConvertTo-Json -Compress | Write-Output
    $launcher.RequireMedium()
    if ($InspectOnly) {
        $launcher.ProbeOwnedProfileProcessExit()
        Write-Output 'PASS: original fixed standard-account probe resumed once and exited zero within five seconds.'
        return
    }

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
        # Match an ordinary user-owned browser profile, including the ability
        # to create its sandbox ACLs. This fresh cache is not service data.
        @{ Sid = $clientSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
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
        resumePreviousCount = $launcher.ResumePreviousCount
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
        try {
            Write-Output ("Owned GUI exit code before cleanup: {0}" -f $launcher.OwnedGuiExitCode())
            if (-not $InspectOnly -and $launcher.ClientPid -ne 0) {
                try { Write-OwnedStartupObservation -OwnedProfileDirectory $profileDirectory }
                catch { Write-Output 'Owned startup observation artifact unavailable; progress remains unknown.' }
                try { Write-OwnedManagementObservation -OwnedProfileDirectory $profileDirectory }
                catch { Write-Output 'Owned management observation artifact unavailable; progress remains unknown.' }
                try {
                    $diagnostics = $launcher.DiagnoseOwnedGui() | ConvertTo-Json -Depth 5
                    # Contains fixed flags/classifications/counts only. No raw
                    # titles, control text, paths, process/module names or SIDs.
                    Write-Output $diagnostics
                    $diagnosticPath = Join-Path $env:LAB_EVIDENCE 'owned-gui-diagnostics.json'
                    $diagnosticStream = [IO.File]::Open($diagnosticPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
                    try {
                        $diagnosticBytes = ([Text.UTF8Encoding]::new($false)).GetBytes($diagnostics + [Environment]::NewLine)
                        $diagnosticStream.Write($diagnosticBytes, 0, $diagnosticBytes.Length)
                    } finally { $diagnosticStream.Dispose() }
                } catch {
                    # Keep Node's failure and unconditional own-child cleanup.
                    Write-Output ("Owned GUI diagnostic capture incomplete: {0}" -f $_.Exception.GetType().Name)
                }
            }
        }
        finally { $launcher.Dispose() }
    }
    # Parent WEBVIEW2 variables were never mutated: the native explicit child
    # environment is separately allocated/freed, so original values remain.
}
if (-not $InspectOnly -and $nodeExit -eq 0) {
    $proofPath = Join-Path $env:LAB_EVIDENCE 'management-gui-proof.json'
    $proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
    $accessProof = Get-Content -LiteralPath (Join-Path $env:LAB_EVIDENCE 'management-client-observation.json') -Raw | ConvertFrom-Json
    if ($accessProof.status -ne 'Observed') { throw 'Native observer access proof is unavailable.' }
    if ($accessProof.events | Where-Object {
        $_.category -ceq 'unexpected_grant' -or
        ($_.stage.StartsWith('deny_', [StringComparison]::Ordinal) -and ($_.category -cne 'access_denied' -or $_.code -ne 5))
    }) { throw 'Native observer proof contains a failed negative control.' }
    foreach ($stage in @('deny_vm_read','deny_vm_write','deny_vm_operation','deny_duplicate','deny_terminate',
        'deny_create_thread','deny_create_process','deny_suspend','deny_set_information','deny_set_quota',
        'deny_write_dacl','deny_write_owner','deny_read_control','deny_query_information','deny_composite',
        'deny_token_query','deny_token_duplicate','deny_token_impersonate','deny_token_assign')) {
        if (-not ($accessProof.events | Where-Object { $_.stage -ceq $stage -and $_.category -ceq 'access_denied' -and $_.code -eq 5 })) {
            throw "Native observer negative control missing: $stage"
        }
    }
    $proof | Add-Member -NotePropertyName observerSensitiveAccessDenied -NotePropertyValue $true
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
