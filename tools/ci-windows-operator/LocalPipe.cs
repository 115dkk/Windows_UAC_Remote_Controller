// SPDX-License-Identifier: GPL-2.0-or-later
// Fixed CI-only namespace and local-only native pipe creation. No fallback.
using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

internal static class LocalPipe
{
    private const uint Duplex = 0x00000003;
    private const uint Overlapped = 0x40000000;
    private const uint FirstPipeInstance = 0x00080000;
    private const uint RejectRemoteClients = 0x00000008;

    internal static NamedPipeServerStream Create(string nonce, PipeSecurity security)
    {
        Program.Require(nonce != null && Regex.IsMatch(nonce, "\\A[0-9a-f]{32}\\z"), "run_identity_rejected");
        Program.Require(security != null, "local_pipe_create_failed");
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        Program.Require(descriptor.Length > 0 && descriptor.Length <= 65536, "local_pipe_create_failed");
        IntPtr copiedDescriptor = Marshal.AllocHGlobal(descriptor.Length);
        SafePipeHandle handle = null;
        try
        {
            Marshal.Copy(descriptor, 0, copiedDescriptor, descriptor.Length);
            var attributes = new Native.SecurityAttributes
            {
                Length = (uint)Marshal.SizeOf(typeof(Native.SecurityAttributes)),
                Descriptor = copiedDescriptor,
                InheritHandle = 0
            };
            // CreateNamedPipe synchronously copies this self-relative descriptor.
            // PIPE_TYPE_BYTE / READMODE_BYTE / WAIT are zero. Remote rejection is
            // an OS admission flag, not a hostname/local-computer string heuristic.
            handle = Native.CreateNamedPipe(@"\\.\pipe\UacRemoteCiE2e." + nonce,
                Duplex | Overlapped | FirstPipeInstance, RejectRemoteClients,
                1, 65536, 4096, 0, ref attributes);
            Program.Require(handle != null && !handle.IsInvalid, "local_pipe_create_failed");
            // The managed stream adopts this sole owning SafePipeHandle. No raw
            // CloseHandle, duplicate handle or second stream owner is introduced.
            var pipe = new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
            handle = null;
            return pipe;
        }
        finally
        {
            // Constructor/native failure leaves ownership here. Successful adopt
            // transfers it to the stream, whose Dispose closes the handle once.
            if (handle != null) handle.Dispose();
            Marshal.FreeHGlobal(copiedDescriptor);
        }
    }
}
