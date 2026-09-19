// SPDX-License-Identifier: GPL-2.0-or-later
// uac-ci-e2e-do-not-ship: fixed in-memory pipe relay, never a console UI.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

internal static class PipeBridge
{
    private const string OperatorPath = Program.Lab + @"\uac-ci-windows-operator.exe";
    private const string BridgePath = Program.Lab + @"\uac-ci-pipe-bridge.exe";
    private static string stage = "startup";

    private static int Main(string[] args)
    {
        using (var watchdog = new Timer(_ => Environment.Exit(124), null, 300000, Timeout.Infinite))
        {
            try
            {
                Program.Require(args.Length == 0 && Console.IsInputRedirected && Console.IsOutputRedirected, "private_stdio_required");
                using (var identity = WindowsIdentity.GetCurrent())
                    Program.Require(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator) &&
                        !identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid), "ci_admin_required");
                Program.CheckProtected(Program.Lab, true, true);
                Program.CheckProtected(BridgePath, false, true);
                Program.CheckProtected(OperatorPath, false, true);
                string ownImage;
                long ownCreated;
                int ownSession;
                Program.ObserveProcess(Process.GetCurrentProcess().Id, out ownImage, out ownCreated, out ownSession);
                Program.Require(String.Equals(ownImage, BridgePath, StringComparison.OrdinalIgnoreCase), "bridge_location_rejected");
                stage = "control_wait";
                while (!File.Exists(Program.Lab + @"\control.json"))
                {
                    Program.Require(Program.Lifetime.Elapsed.TotalSeconds < 60, "control_deadline");
                    Thread.Sleep(100);
                }
                Program.CheckProtected(Program.Lab + @"\control.json", false, true);
                Program.Require(new FileInfo(Program.Lab + @"\control.json").Length <= 4096, "oversized_metadata");
                var metadata = Program.Object(File.ReadAllText(Program.Lab + @"\control.json", Encoding.UTF8), 4096);
                Program.Keys(metadata, "marker", "runNonce", "githubRunId", "githubRunAttempt", "createdUtc", "sessionId", "clientPid", "serviceSha256", "githubActions", "runnerEnvironment");
                Program.Require(Program.Value(metadata, "marker") == "uac-ci-e2e-do-not-ship" &&
                    Program.Value(metadata, "githubActions") == "true" && Program.Value(metadata, "runnerEnvironment") == "github-hosted", "hosted_ci_required");
                string nonce = Program.Value(metadata, "runNonce");
                Program.Require(Regex.IsMatch(nonce, "\\A[0-9a-f]{32}\\z") &&
                    Regex.IsMatch(Program.Value(metadata, "githubRunId"), "\\A[0-9]{1,20}\\z") &&
                    Regex.IsMatch(Program.Value(metadata, "githubRunAttempt"), "\\A[0-9]{1,5}\\z"), "run_identity_rejected");
                Program.Require(Int32.Parse(Program.Value(metadata, "clientPid")) == Process.GetCurrentProcess().Id, "bridge_pid_mismatch");
                int targetSession = Int32.Parse(Program.Value(metadata, "sessionId"));
                Program.Require(targetSession > 0, "interactive_session_required");
                DateTime created;
                Program.Require(DateTime.TryParse(Program.Value(metadata, "createdUtc"), null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out created), "run_time_rejected");
                double age = (DateTime.UtcNow - created.ToUniversalTime()).TotalSeconds;
                Program.Require(age >= -5 && age <= 60 && created.ToUniversalTime().Ticks >= ownCreated - TimeSpan.TicksPerSecond * 5,
                    "run_not_fresh");
                Program.ServiceHash = Program.Value(metadata, "serviceSha256");
                Program.Require(Regex.IsMatch(Program.ServiceHash, "\\A[0-9a-f]{64}\\z"), "service_hash_rejected");
                Program.ValidateService();
                stage = "pipe_connect";
                using (var pipe = new NamedPipeClientStream(".", "UacRemoteCiE2e." + nonce, PipeDirection.InOut,
                    PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation))
                {
                    pipe.Connect(60000);
                    uint serverPid;
                    Program.Require(Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out serverPid), "server_pid_unavailable");
                    IntPtr server = Native.OpenProcess(0x1000, false, serverPid);
                    Program.Require(server != IntPtr.Zero, "server_query_rejected");
                    try
                    {
                        string serverImage;
                        long serverCreated;
                        int serverSession;
                        Program.ObserveProcess((int)serverPid, out serverImage, out serverCreated, out serverSession);
                        Program.Require(String.Equals(serverImage, OperatorPath, StringComparison.OrdinalIgnoreCase) &&
                            serverSession == targetSession && serverCreated >= created.ToUniversalTime().Ticks - TimeSpan.TicksPerSecond * 5,
                            "server_identity_rejected");
                        RequireSystemToken(server);
                        stage = "relay";
                        using (var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false, true), false, 4096))
                        using (var output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false), 65536) { AutoFlush = true, NewLine = "\n" })
                        using (var reader = new StreamReader(pipe, new UTF8Encoding(false, true), false, 65536, true))
                        using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true, NewLine = "\n" })
                        {
                            string[] commands = { "arm", "capture_qr", "read_comparison", "compare_confirm", "finish" };
                            string[] statuses = { "ready", "qr_pixels", "comparison_pixels", "confirmed", "done" };
                            int qrCaptures = 0;
                            for (int phase = 0; phase < commands.Length;)
                            {
                                string requestLine = BoundedLine(input, 4096);
                                var request = Program.Object(requestLine, 4096);
                                Program.Keys(request, phase == 3 ? new[] { "command", "code" } : new[] { "command" });
                                string command = Program.Value(request, "command");
                                bool recapture = phase == 2 && command == "capture_qr";
                                Program.Require(command == commands[phase] || recapture, "command_order_rejected");
                                int responsePhase = recapture ? 1 : phase;
                                if (responsePhase == 1) Program.Require(++qrCaptures <= 25, "qr_readiness_timeout");
                                if (phase == 3) Program.Require(Regex.IsMatch(Program.Value(request, "code"), "\\A[0-9]{6}\\z"), "comparison_input_rejected");
                                writer.WriteLine(requestLine);
                                requestLine = null;
                                string responseLine = BoundedLine(reader, 12 * 1024 * 1024);
                                var response = Program.Object(responseLine, 12 * 1024 * 1024);
                                if (Program.Value(response, "status") == "failed")
                                {
                                    object diagnostic;
                                    Program.Require(Diagnostics.TryValidate(response, "operator", out diagnostic), "response_order_rejected");
                                    output.WriteLine(Program.Json.Serialize(diagnostic));
                                    return 1;
                                }
                                Program.Require(Program.Value(response, "status") == statuses[responsePhase], "response_order_rejected");
                                if (responsePhase == 1)
                                {
                                    Program.Keys(response, "status", "pngBase64", "rendererPid");
                                    Program.Require(Program.Value(response, "pngBase64").Length <= 8 * 1024 * 1024 &&
                                        Int32.Parse(Program.Value(response, "rendererPid")) > 0, "pixel_response_rejected");
                                }
                                else if (responsePhase == 2)
                                {
                                    Program.Keys(response, "status", "code");
                                    Program.Require(Regex.IsMatch(Program.Value(response, "code"), "\\A[0-9]{6}\\z"), "comparison_response_rejected");
                                }
                                else Program.Keys(response, "status");
                                output.WriteLine(responseLine);
                                responseLine = null;
                                if (!recapture) phase++;
                            }
                        }
                    }
                    finally { Native.CloseHandle(server); }
                }
                return 0;
            }
            catch (Exception error)
            {
                if (Console.IsOutputRedirected)
                    Diagnostics.TryWrite(Console.Out, "bridge", stage, error);
                return 1;
            }
        }
    }

    private static void RequireSystemToken(IntPtr process)
    {
        IntPtr token;
        Program.Require(Native.OpenProcessToken(process, 0x0008, out token), "server_token_rejected");
        try
        {
            uint needed;
            Native.GetTokenInformation(token, 1, IntPtr.Zero, 0, out needed); // TOKEN_USER
            Program.Require(needed >= IntPtr.Size && needed <= 1024, "server_token_size_rejected");
            IntPtr data = Marshal.AllocHGlobal((int)needed);
            try
            {
                Program.Require(Native.GetTokenInformation(token, 1, data, needed, out needed), "server_token_unavailable");
                var user = new SecurityIdentifier(Marshal.ReadIntPtr(data));
                Program.Require(user.IsWellKnown(WellKnownSidType.LocalSystemSid), "system_server_required");
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        finally { Native.CloseHandle(token); }
    }

    private static string BoundedLine(StreamReader reader, int limit)
    {
        var line = new StringBuilder(Math.Min(limit, 65536));
        while (line.Length <= limit)
        {
            Program.Deadline();
            int c = reader.Read();
            Program.Require(c >= 0, "private_stream_closed");
            if (c == '\n')
            {
                string result = line.ToString();
                Program.Require(Encoding.UTF8.GetByteCount(result) <= limit, "oversized_line");
                return result;
            }
            Program.Require(c != '\r', "noncanonical_line");
            line.Append((char)c);
        }
        throw new Program.GateFailure("oversized_line");
    }
}
