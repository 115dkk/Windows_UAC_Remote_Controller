// SPDX-License-Identifier: GPL-2.0-or-later
// uac-ci-e2e-do-not-ship: disposable GitHub-hosted Windows VM ONLY.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal static class Program
{
    internal sealed class GateFailure : Exception
    {
        internal readonly string Code;
        internal GateFailure(string code) { Code = code; }
    }
    internal const string Lab = @"C:\ProgramData\UacRemoteCiE2e";
    internal const string Service = ConsentTarget.InstalledImage;
    internal static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 12 * 1024 * 1024 };
    internal static readonly Stopwatch Lifetime = Stopwatch.StartNew();
    internal static int Session;
    internal static DateTime ArmedUtc;
    internal static string ServiceHash;
    internal static string PrivateDesktop;
    internal static int RendererPid;
    internal static long RendererStart;
    internal static string Stage = "startup";
    private static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

    [STAThread]
    private static int Main(string[] args)
    {
        // Process-wide deadline also bounds synchronous UIA/native/pipe calls.
        using (var watchdog = new Timer(_ => Environment.Exit(124), null, 300000, Timeout.Infinite))
        {
            try
            {
                Require(args.Length == 0, "arguments_rejected");
                Require(WindowsIdentity.GetCurrent().User.Equals(SystemSid), "system_required");
                Session = Process.GetCurrentProcess().SessionId;
                Require(Session > 0, "interactive_session_required");
                Require(Native.SetProcessDpiAwarenessContext(new IntPtr(-4)), "dpi_context_rejected");
                CheckProtected(Lab, true, true);
                CheckProtected(Lab + @"\control.json", false, true);
                CheckProtected(Lab + @"\uac-ci-windows-operator.exe", false, true);
                Require(String.Equals(Process.GetCurrentProcess().MainModule.FileName,
                    Lab + @"\uac-ci-windows-operator.exe", StringComparison.OrdinalIgnoreCase), "operator_location_rejected");
                Require(new FileInfo(Lab + @"\control.json").Length <= 4096, "oversized_metadata");
                var metadata = Object(File.ReadAllText(Lab + @"\control.json", Encoding.UTF8), 4096);
                Keys(metadata, "marker", "runNonce", "githubRunId", "githubRunAttempt", "createdUtc", "sessionId", "clientPid", "serviceSha256", "githubActions", "runnerEnvironment");
                Require(Value(metadata, "marker") == "uac-ci-e2e-do-not-ship" &&
                    Value(metadata, "githubActions") == "true" && Value(metadata, "runnerEnvironment") == "github-hosted", "hosted_ci_required");
                string nonce = Value(metadata, "runNonce");
                Require(Regex.IsMatch(nonce, "\\A[0-9a-f]{32}\\z") &&
                    Regex.IsMatch(Value(metadata, "githubRunId"), "\\A[0-9]{1,20}\\z") &&
                    Regex.IsMatch(Value(metadata, "githubRunAttempt"), "\\A[0-9]{1,5}\\z"), "run_identity_rejected");
                DateTime created;
                Require(DateTime.TryParse(Value(metadata, "createdUtc"), null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out created), "run_time_rejected");
                double age = (DateTime.UtcNow - created.ToUniversalTime()).TotalSeconds;
                Require(age >= -5 && age <= 60, "run_not_fresh");
                Require(Int32.Parse(Value(metadata, "sessionId")) == Session, "session_mismatch");
                int clientPid = Int32.Parse(Value(metadata, "clientPid"));
                Require(clientPid > 0, "client_pid_rejected");
                ServiceHash = Value(metadata, "serviceSha256");
                Require(Regex.IsMatch(ServiceHash, "\\A[0-9a-f]{64}\\z"), "service_hash_rejected");
                ValidateService();
                // Atomic one-use claim, containing no QR or comparison material.
                using (var claim = new FileStream(Lab + @"\claimed-" + nonce, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
                var security = new PipeSecurity();
                security.SetAccessRuleProtection(true, false);
                security.SetOwner(SystemSid);
                security.AddAccessRule(new PipeAccessRule(SystemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(AdminSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
                using (var pipe = new NamedPipeServerStream("UacRemoteCiE2e." + nonce, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 65536, security))
                {
                    Stage = "pipe_wait";
                    pipe.WaitForConnection();
                    uint actualPid;
                    Require(Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle, out actualPid) && actualPid == clientPid, "pipe_client_rejected");
                    var computer = new StringBuilder(256);
                    Require(Native.GetNamedPipeClientComputerName(pipe.SafePipeHandle, computer, (uint)computer.Capacity) &&
                        String.Equals(computer.ToString().TrimStart('\\'), Environment.MachineName, StringComparison.OrdinalIgnoreCase), "remote_pipe_rejected");
                    using (var reader = new StreamReader(pipe, new UTF8Encoding(false, true), false, 4096, true))
                    using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), 65536, true) { AutoFlush = true, NewLine = "\n" })
                    {
                        try
                        {
                            int phase = 0;
                            Stage = "arm_wait";
                            while (true)
                            {
                                var request = Object(ReadLine(reader), 4096);
                                string command = Value(request, "command");
                                if (command == "compare_confirm") Keys(request, "command", "code");
                                else Keys(request, "command");
                                // ImpersonateNamedPipeClient uses the last message read.
                                // Establish that context with the bounded read above;
                                // validate it before any command effect or positive reply.
                                bool admin = false;
                                pipe.RunAsClient(() =>
                                {
                                    using (var identity = WindowsIdentity.GetCurrent())
                                        admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                                });
                                Require(admin, "elevated_client_required");
                                if (phase == 0 && command == "arm")
                                {
                                    Require(ProtectedUi.ConsentProcesses().Count == 0, "preexisting_consent");
                                    ArmedUtc = DateTime.UtcNow;
                                    phase = 1;
                                    Stage = "capture_command_wait";
                                    Reply(writer, new { status = "ready" });
                                }
                                else if (phase == 1 && command == "capture_qr")
                                {
                                    Stage = "initial_consent";
                                    ProtectedUi.ApprovePairingConsent();
                                    Stage = "qr_capture";
                                    string png = ProtectedUi.CaptureQr();
                                    phase = 2;
                                    Stage = "comparison_command_wait";
                                    Reply(writer, new { status = "qr_pixels", pngBase64 = png, rendererPid = RendererPid });
                                    png = null;
                                }
                                else if (phase == 2 && command == "read_comparison")
                                {
                                    Stage = "comparison_capture";
                                    string code = ProtectedUi.ReadComparison();
                                    phase = 3;
                                    Stage = "confirmation_command_wait";
                                    Reply(writer, new { status = "comparison_pixels", code = code });
                                    code = null;
                                }
                                else if (phase == 3 && command == "compare_confirm")
                                {
                                    string expected = Value(request, "code");
                                    Require(Regex.IsMatch(expected, "\\A[0-9]{6}\\z"), "comparison_input_rejected");
                                    Stage = "comparison_confirm";
                                    ProtectedUi.ConfirmComparison(expected);
                                    phase = 4;
                                    Stage = "finish_wait";
                                    Reply(writer, new { status = "confirmed" });
                                }
                                else if (phase == 4 && command == "finish")
                                {
                                    Reply(writer, new { status = "done" });
                                    return 0;
                                }
                                else throw new InvalidOperationException("command_phase_rejected");
                            }
                        }
                        catch (Exception error)
                        {
                            // Peer identity is already validated; report before writer disposal.
                            Diagnostics.TryWrite(writer, "operator", Stage, error);
                            return 1;
                        }
                    }
                }
            }
            catch (Exception error)
            {
                // Postconnection failures return above, before writer disposal.
                Diagnostics.TryWriteStartup(Stage, error);
                return 1;
            }
        }
    }

    internal static void Require(bool condition, string code)
    {
        if (!condition) throw new GateFailure(code);
    }

    internal static void Deadline()
    {
        Require(Lifetime.Elapsed.TotalSeconds < 295, "deadline_elapsed");
    }

    private static void Reply(StreamWriter writer, object value) { Deadline(); writer.WriteLine(Json.Serialize(value)); }

    private static string ReadLine(StreamReader reader)
    {
        var line = new StringBuilder();
        while (line.Length <= 4096)
        {
            Deadline();
            int c = reader.Read();
            Require(c >= 0, "pipe_closed");
            if (c == '\n') return line.ToString();
            Require(c != '\r', "noncanonical_line");
            line.Append((char)c);
        }
        throw new InvalidOperationException("oversized_command");
    }

    internal static Dictionary<string, object> Object(string json, int limit)
    {
        Require(Encoding.UTF8.GetByteCount(json) <= limit, "oversized_json");
        var value = Json.DeserializeObject(json) as Dictionary<string, object>;
        Require(value != null, "object_required");
        return value;
    }

    internal static void Keys(Dictionary<string, object> obj, params string[] keys)
    {
        Require(obj.Count == keys.Length, "unknown_fields");
        foreach (string key in keys) Require(obj.ContainsKey(key), "missing_field");
    }

    internal static string Value(Dictionary<string, object> obj, string key)
    {
        object value;
        Require(obj.TryGetValue(key, out value) && (value is string || value is int), "invalid_field");
        return Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    internal static void ValidateService()
    {
        CheckProtected(@"C:\Program Files\휴대폰 승인", true, false);
        CheckProtected(Service, false, false);
        using (var stream = File.OpenRead(Service))
        using (var sha = SHA256.Create())
            Require(BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant() == ServiceHash, "service_changed");
    }

    internal static void ObserveProcess(int pid, out string image, out long creationTicks, out int session)
    {
        // Renderer DACL deliberately does not grant VM_READ or QUERY_INFORMATION.
        // Query only the explicitly admitted limited-information right.
        IntPtr process = Native.OpenProcess(0x1000, false, (uint)pid);
        Require(process != IntPtr.Zero, "process_query_rejected");
        try
        {
            var path = new StringBuilder(1024);
            uint size = (uint)path.Capacity, sessionId;
            long created, exited, kernel, user;
            Require(Native.QueryFullProcessImageName(process, 0, path, ref size), "process_image_unavailable");
            Require(Native.GetProcessTimes(process, out created, out exited, out kernel, out user), "process_creation_unavailable");
            Require(Native.ProcessIdToSessionId((uint)pid, out sessionId), "process_session_unavailable");
            image = path.ToString();
            creationTicks = DateTime.FromFileTimeUtc(created).Ticks;
            session = (int)sessionId;
        }
        finally { Native.CloseHandle(process); }
    }

    // No reparse traversal, protected owner, no write-capable nonprivileged ACE.
    // Lab DACL is strictly SY/BA, while installed files may grant ordinary read/execute.
    internal static void CheckProtected(string path, bool directory, bool strict)
    {
        string cursor = path;
        while (!String.IsNullOrEmpty(cursor))
        {
            Require((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) == 0, "reparse_path_rejected");
            cursor = Path.GetDirectoryName(cursor);
        }
        FileSystemSecurity acl = directory ? (FileSystemSecurity)Directory.GetAccessControl(path) : File.GetAccessControl(path);
        var owner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
        string trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        Require(owner.Equals(SystemSid) || owner.Equals(AdminSid) || (!strict && owner.Value == trustedInstaller), "owner_rejected");
        if (strict && directory) Require(acl.AreAccessRulesProtected, "lab_inheritance_rejected");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            bool privileged = sid.Equals(SystemSid) || sid.Equals(AdminSid) || (!strict && sid.Value == trustedInstaller);
            var writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
            Require(privileged || (!strict && (rule.FileSystemRights & writes) == 0), "writable_by_untrusted_principal");
            if (strict) Require(privileged, "lab_acl_rejected");
        }
    }
}
