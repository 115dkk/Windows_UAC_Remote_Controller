// SPDX-License-Identifier: GPL-2.0-or-later
// Native transport regression ONLY. Never runs Program.Main, UAC or the service.
using System;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal static class LocalPipeTests
{
    private static int Main(string[] args)
    {
        using (var watchdog = new Timer(_ => Environment.Exit(124), null, 30000, Timeout.Infinite))
        {
            try
            {
                if (args.Length != 0 || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
                    Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted") return 2;
                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var security = new PipeSecurity();
                using (var identity = WindowsIdentity.GetCurrent())
                {
                    Check(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator));
                    // Same exact SY/BA DACL as the operator. BA ownership lets an
                    // elevated CI runner create the transport fixture without
                    // requesting SeRestorePrivilege or launching anything SYSTEM.
                    security.SetOwner(identity.User.Equals(system) ? system : admin);
                }
                security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(admin, PipeAccessRights.ReadWrite, AccessControlType.Allow));
                RejectInvalidNonce(security);
                string nonce = Guid.NewGuid().ToString("N");
                uint ownPid = (uint)Process.GetCurrentProcess().Id;
                SafePipeHandle adopted;
                using (var server = LocalPipe.Create(nonce, security))
                {
                    adopted = server.SafePipeHandle;
                    uint handleFlags, pipeFlags, output, input, max;
                    Check(Native.GetHandleInformation(adopted, out handleFlags) && (handleFlags & 1) == 0);
                    Check(Native.GetNamedPipeInfo(adopted, out pipeFlags, out output, out input, out max));
                    Check((pipeFlags & 1) != 0 && (pipeFlags & 4) == 0 && max == 1);
                    Check(server.TransmissionMode == PipeTransmissionMode.Byte && server.IsAsync);
                    Check(server.GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access) ==
                        security.GetSecurityDescriptorSddlForm(AccessControlSections.Access));
                    RejectDuplicate(nonce, security);
                    Exception clientFailure = null;
                    var clientThread = new Thread(() =>
                    {
                        try
                        {
                            using (var client = new NamedPipeClientStream(".", "UacRemoteCiE2e." + nonce,
                                PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation))
                            {
                                client.Connect(10000);
                                uint serverPid;
                                Check(Native.GetNamedPipeServerProcessId(client.SafePipeHandle, out serverPid) && serverPid == ownPid);
                                client.WriteByte(0x51); // Fixed nonsecret transport marker.
                                client.Flush();
                                Check(client.ReadByte() == 0x41);
                            }
                        }
                        catch (Exception error) { clientFailure = error; }
                    });
                    clientThread.IsBackground = true;
                    IAsyncResult connection = server.BeginWaitForConnection(null, null);
                    clientThread.Start();
                    using (WaitHandle wait = connection.AsyncWaitHandle)
                    {
                        Check(wait.WaitOne(10000));
                        server.EndWaitForConnection(connection);
                    }
                    uint clientPid;
                    Check(Native.GetNamedPipeClientProcessId(server.SafePipeHandle, out clientPid) && clientPid == ownPid);
                    Check(server.ReadByte() == 0x51);
                    bool admitted = false;
                    server.RunAsClient(() =>
                    {
                        using (var identity = WindowsIdentity.GetCurrent())
                            admitted = identity.ImpersonationLevel == TokenImpersonationLevel.Impersonation &&
                                new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
                    });
                    Check(admitted); // Admission occurs only after reading client data.
                    server.WriteByte(0x41);
                    server.Flush();
                    Check(clientThread.Join(10000) && clientFailure == null);
                }
                Check(adopted.IsClosed);
                Console.WriteLine("Native local-only pipe transport regression passed; no UAC or service was executed.");
                return 0;
            }
            catch
            {
                // No exception messages, pipe names, run identifiers or payloads.
                Console.Error.WriteLine("Native local-only pipe transport regression failed.");
                return 1;
            }
        }
    }

    private static void RejectInvalidNonce(PipeSecurity security)
    {
        bool rejected = false;
        try { using (var pipe = LocalPipe.Create("not-a-run-nonce", security)) { } }
        catch (Program.GateFailure error) { rejected = error.Code == "run_identity_rejected"; }
        Check(rejected);
    }

    private static void RejectDuplicate(string nonce, PipeSecurity security)
    {
        bool rejected = false;
        try { using (var pipe = LocalPipe.Create(nonce, security)) { } }
        catch (Program.GateFailure error) { rejected = error.Code == "local_pipe_create_failed"; }
        Check(rejected);
    }

    private static void Check(bool condition)
    {
        if (!condition) throw new InvalidOperationException();
    }
}
