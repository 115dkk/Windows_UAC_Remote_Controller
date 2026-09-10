// SPDX-License-Identifier: GPL-2.0-or-later
// Service-only payload, embedded by the native one-time diagnostic bootstrap.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
public static class PcpContextProbe
{
    const string Name = "UacPcpContextProbe20260910";
    const string Root = @"C:\Program Files\UacPcpContextProbe20260910";
    const string Image = Root + @"\PcpContextProbe.Service.exe";
    const string Observer = Root + @"\observer.ready";
    const int Limit = 65536;
    public static int Main(string[] args)
    {
        try
        {
            if (IntPtr.Size != 8 || args.Length != 1 || args[0] != "service" || Assembly.GetExecutingAssembly().Location != Image || File.Exists(Image + ".config")) throw Rejected();
            using (var identity = WindowsIdentity.GetCurrent())
                if (identity.User == null || identity.User.Value != "S-1-5-18" || Scalar(identity.Token, 8) != 1 || Scalar(identity.Token, 12) != 0) throw Rejected();
            using (var service = new ProbeService()) ServiceBase.Run(service);
            return 0;
        }
        catch { return 1; }
    }
    sealed class ProbeService : ServiceBase
    {
        public ProbeService() { ServiceName = Name; AutoLog = false; CanStop = false; CanPauseAndContinue = false; CanShutdown = false; CanHandlePowerEvent = false; CanHandleSessionChangeEvent = false; }
        protected override void OnStart(string[] args)
        {
            if (args.Length != 0) throw Rejected();
            // No CNG in OnStart. Foreground ownership lasts through self-stop.
            var worker = new Thread(Probe); worker.IsBackground = false; worker.Start();
        }
        void Probe()
        {
            var body = new StringBuilder("probe_version=1\n");
            var budget = Stopwatch.StartNew();
            try
            {
                body.Append("pid=").Append(GetCurrentProcessId()).Append('\n');
                body.Append("utc=").Append(DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
                RecordToken(body);
                using (var scm = OpenSCManagerW(null, null, 1))
                {
                    if (scm.IsInvalid) NativeError();
                    using (var service = OpenServiceW(scm, Name, 4))
                    {
                        if (service.IsInvalid) NativeError();
                        for (;;)
                        {
                            if (budget.Elapsed > TimeSpan.FromSeconds(45)) throw Rejected();
                            Status state; uint needed;
                            if (!QueryServiceStatusEx(service, 0, out state, (uint)Marshal.SizeOf(typeof(Status)), out needed)) NativeError();
                            if (state.ServiceType != 0x10 || (state.CurrentState != 2 && state.CurrentState != 4)) throw Rejected();
                            if (state.CurrentState == 4 && state.ProcessId != GetCurrentProcessId()) throw Rejected();
                            if (state.CurrentState == 4 && state.ControlsAccepted == 0 && ObserveMarker())
                            { body.Append("scm_state_before_pcp=RUNNING\nscm_controls_before_pcp=0\nobserver=retained_process\n"); break; }
                            Thread.Sleep(20);
                        }
                    }
                }
                // Sole provider attempt; no key operations or retry path.
                if (budget.Elapsed > TimeSpan.FromSeconds(45)) throw Rejected();
                IntPtr provider;
                int opened = NCryptOpenStorageProvider(out provider, "Microsoft Platform Crypto Provider", 0);
                int freed = 0;
                if (opened == 0 && provider != IntPtr.Zero) freed = NCryptFreeObject(provider);
                body.Append("pcp_open_status=").Append(Hex(opened)).Append('\n');
                body.Append("pcp_handle_nonzero=").Append(provider == IntPtr.Zero ? "0\n" : "1\n");
                if (opened == 0 && provider != IntPtr.Zero) body.Append("pcp_free_status=").Append(Hex(freed)).Append('\n');
                else body.Append("pcp_free_status=not_called\n");
                if (opened == 0 && provider == IntPtr.Zero) throw Rejected();
                body.Append("payload=complete\n");
            }
            catch (Exception error) { body.Append("payload=incomplete\nerror_hresult=").Append(Hex(error.HResult)).Append('\n'); }
            finally
            {
                try
                {
                    byte[] bytes = new UTF8Encoding(false, true).GetBytes(body.ToString());
                    if (bytes.Length > Limit) throw Rejected();
                    using (var file = new FileStream(Root + @"\probe.txt", FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                }
                catch { ExitCode = 3; }
                Stop(); // Self-stop; external SCM controls remain disabled.
            }
        }
    }
    static bool ObserveMarker()
    {
        using (var file = CreateFileW(Observer, 0x80, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
        {
            if (file.IsInvalid) { if (Marshal.GetLastWin32Error() == 2) return false; NativeError(); }
            FileInfoNative info; var path = new StringBuilder(1024);
            uint size = GetFinalPathNameByHandleW(file, path, 1024, 0);
            if (size == 0 || size >= 1024 || path.ToString() != @"\\?\" + Observer || !GetFileInformationByHandle(file, out info) ||
                (info.Attributes & 0x410) != 0 || info.Links != 1 || info.SizeHigh != 0 || info.SizeLow != 0) throw Rejected();
            return true;
        }
    }
    static void RecordToken(StringBuilder body)
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            IntPtr token = identity.Token;
            uint type = Scalar(token, 8), session = Scalar(token, 12);
            string integrity;
            using (var data = TokenData(token, 25)) integrity = data.Sid(0);
            if (identity.User == null || identity.User.Value != "S-1-5-18" || type != 1 || session != 0 || integrity != "S-1-16-16384") throw Rejected();
            body.Append("user_sid=").Append(identity.User.Value).Append('\n');
            body.Append("token_type=").Append(type).Append('\n');
            body.Append("session_id=").Append(session).Append('\n');
            body.Append("elevation_type=").Append(Scalar(token, 18)).Append('\n');
            body.Append("elevated=").Append(Scalar(token, 20)).Append('\n');
            body.Append("integrity_sid=").Append(integrity).Append('\n');
            string expected = ServiceSid(); bool found = false;
            body.Append("expected_service_sid=").Append(expected).Append('\n');
            foreach (int kind in new[] { 2, 11 }) using (var data = TokenData(token, kind))
            {
                uint count = data.U32(0);
                if (count > 256 || (count != 0 && 8L + 16L * count > data.Size)) throw Rejected();
                body.Append(kind == 2 ? "group_count=" : "restricted_sid_count=").Append(count).Append('\n');
                for (int i = 0; i < count; i++)
                {
                    int offset = 8 + i * 16; string sid = data.Sid(offset); uint flags = data.U32(offset + 8);
                    body.Append(kind == 2 ? "group." : "restricted.").Append(i).Append('=').Append(sid).Append(',').Append(flags.ToString("X8")).Append('\n');
                    if (kind == 2 && sid == expected && (flags & 4) != 0 && (flags & 16) == 0) found = true;
                }
            }
            using (var data = TokenData(token, 3))
            {
                uint count = data.U32(0);
                if (count > 256 || 4L + 12L * count > data.Size) throw Rejected();
                body.Append("privilege_count=").Append(count).Append('\n');
                for (int i = 0; i < count; i++)
                {
                    int offset = 4 + i * 12;
                    body.Append("privilege.").Append(i).Append('=').Append(data.U32(offset + 4).ToString("X8")).Append(data.U32(offset).ToString("X8")).Append(',').Append(data.U32(offset + 8).ToString("X8")).Append('\n');
                }
            }
            if (!found || body.Length > Limit / 2) throw Rejected();
        }
    }
    static string ServiceSid()
    {
        uint bytes = 0, chars = 0, use;
        LookupAccountNameW(null, "NT SERVICE\\" + Name, IntPtr.Zero, ref bytes, null, ref chars, out use);
        if (Marshal.GetLastWin32Error() != 122 || bytes != 32 || chars == 0 || chars > 256) throw Rejected();
        using (var data = new Buffer((int)bytes))
        {
            var domain = new StringBuilder((int)chars);
            if (!LookupAccountNameW(null, "NT SERVICE\\" + Name, data.Pointer, ref bytes, domain, ref chars, out use)) NativeError();
            if (bytes != 32 || use != 5 || !String.Equals(domain.ToString(), "NT SERVICE", StringComparison.OrdinalIgnoreCase) ||
                Marshal.ReadByte(data.Pointer, 0) != 1 || Marshal.ReadByte(data.Pointer, 1) != 6 || data.U32(8) != 80) throw Rejected();
            for (int i = 2; i < 7; i++) if (Marshal.ReadByte(data.Pointer, i) != 0) throw Rejected();
            if (Marshal.ReadByte(data.Pointer, 7) != 5 || !IsValidSid(data.Pointer)) throw Rejected();
            return new SecurityIdentifier(data.Pointer).Value;
        }
    }
    static uint Scalar(IntPtr token, int kind)
    {
        if (kind != 8 && kind != 12 && kind != 18 && kind != 20) throw Rejected();
        using (var data = new Buffer(4))
        {
            uint returned;
            if (!GetTokenInformation(token, kind, data.Pointer, 4, out returned)) NativeError();
            if (returned != 4) throw Rejected();
            return data.U32(0);
        }
    }
    static Buffer TokenData(IntPtr token, int kind)
    {
        uint size; GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
        if (Marshal.GetLastWin32Error() != 122 || size < 4 || size > Limit) throw Rejected();
        var data = new Buffer((int)size);
        try { if (!GetTokenInformation(token, kind, data.Pointer, size, out size)) NativeError(); data.RestrictTo(size); return data; }
        catch { data.Dispose(); throw; }
    }
    sealed class Buffer : IDisposable
    {
        public IntPtr Pointer; public int Size { get; private set; }
        public Buffer(int size) { if (size < 4 || size > Limit) throw Rejected(); Size = size; Pointer = Marshal.AllocHGlobal(size); }
        public void RestrictTo(uint used) { if (used < 4 || used > Size) throw Rejected(); Size = (int)used; }
        public uint U32(int offset) { if (offset < 0 || offset > Size - 4) throw Rejected(); return unchecked((uint)Marshal.ReadInt32(Pointer, offset)); }
        public string Sid(int offset)
        {
            if (offset < 0 || offset > Size - IntPtr.Size) throw Rejected();
            IntPtr sid = Marshal.ReadIntPtr(Pointer, offset); long relative = sid.ToInt64() - Pointer.ToInt64();
            if (relative < 0 || relative > Size - 8) throw Rejected();
            uint length = GetLengthSid(sid);
            if (length < 8 || length > 68 || relative + length > Size || !IsValidSid(sid)) throw Rejected();
            return new SecurityIdentifier(sid).Value;
        }
        public void Dispose() { if (Pointer != IntPtr.Zero) { Marshal.FreeHGlobal(Pointer); Pointer = IntPtr.Zero; } }
    }
    static string Hex(int value) { return "0x" + unchecked((uint)value).ToString("X8"); }
    static Exception Rejected() { return new InvalidOperationException("PCP diagnostic admission rejected."); }
    static void NativeError() { throw new Win32Exception(Marshal.GetLastWin32Error()); }
    public sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    { public ServiceHandle() : base(true) { } protected override bool ReleaseHandle() { return CloseServiceHandle(handle); } }
    [StructLayout(LayoutKind.Sequential)] public struct Status { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, Flags; }
    [StructLayout(LayoutKind.Sequential)] public struct FileInfoNative { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern ServiceHandle OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern ServiceHandle OpenServiceW(ServiceHandle scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool QueryServiceStatusEx(ServiceHandle service, uint level, out Status status, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool LookupAccountNameW(string system, string account, IntPtr sid, ref uint sidSize, StringBuilder domain, ref uint domainSize, out uint use);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] static extern bool IsValidSid(IntPtr sid);
    [DllImport("advapi32.dll")] static extern uint GetLengthSid(IntPtr sid);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern int NCryptOpenStorageProvider(out IntPtr provider, string name, uint flags);
    [DllImport("ncrypt.dll", ExactSpelling = true)] static extern int NCryptFreeObject(IntPtr provider);
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfoNative info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint count, uint flags);
}
