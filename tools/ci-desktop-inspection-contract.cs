// SPDX-License-Identifier: GPL-2.0-or-later
// Disposable hosted-CI access-contract experiment. C# 5 / .NET Framework x64.
// Only target changes its OWN scratch process/thread/desktop descriptors. The
// distinct inspector receives no creator handle. This is not product isolation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

internal static class DesktopContract
{
    const string PipePrefix = "UacCiDesktopContract.";
    const string NamePrefix = "UacCiDesktop.";
    const string ImageName = "ci-desktop-inspection-contract.exe";
    const uint ProcessBase = 0x121040, ThreadBase = 0x120800, InspectBase = 0x20081;
    const uint SecurityFields = 0x80000007; // Protected owner/group/DACL, own objects only.
    static readonly Stopwatch Clock = Stopwatch.StartNew();
    static bool CloseFailed;
    static readonly Profile[] Profiles = {
        new Profile("baseline_ba_renderer", ProcessBase, ThreadBase, 0x20183, InspectBase, InspectBase),
        new Profile("thread_query_information", ProcessBase, ThreadBase | 0x40, 0x20183, InspectBase, InspectBase),
        new Profile("process_query_information", ProcessBase | 0x400, ThreadBase, 0x20183, InspectBase, InspectBase),
        new Profile("desktop_enumerate", ProcessBase, ThreadBase, 0x20183 | 0x40, InspectBase | 0x40, InspectBase | 0x40),
        new Profile("three_query_additions", ProcessBase | 0x400, ThreadBase | 0x40, 0x20183 | 0x40, InspectBase | 0x40, InspectBase | 0x40),
        new Profile("desktop_ba_readonly", ProcessBase, ThreadBase, InspectBase, InspectBase, InspectBase),
        new Profile("desktop_ba_readonly_enumerate", ProcessBase, ThreadBase, InspectBase | 0x40, InspectBase | 0x40, InspectBase | 0x40),
        new Profile("desktop_ba_readonly_createwindow", ProcessBase, ThreadBase, InspectBase | 2, InspectBase | 2, InspectBase | 2),
        new Profile("desktop_ba_readonly_switchdesktop", ProcessBase, ThreadBase, InspectBase | 0x100, InspectBase | 0x100, InspectBase | 0x100),
        new Profile("process_all_only", 0x1fffff, ThreadBase, 0x20183, InspectBase, InspectBase),
        new Profile("thread_all_only", ProcessBase, 0x1fffff, 0x20183, InspectBase, InspectBase),
        new Profile("desktop_all_acl_only", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, InspectBase),
        new Profile("process_thread_all", 0x1fffff, 0x1fffff, 0x20183, InspectBase, InspectBase),
        new Profile("process_desktop_all", 0x1fffff, ThreadBase, 0xf01ff, 0xf01ff, InspectBase),
        new Profile("thread_desktop_all", ProcessBase, 0x1fffff, 0xf01ff, 0xf01ff, InspectBase),
        new Profile("all_acl_limited_desktop_handle", 0x1fffff, 0x1fffff, 0xf01ff, 0xf01ff, InspectBase),
        new Profile("desktop_all_acl_and_handle", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0xf01ff),
        new Profile("desktop_renderer_handle", ProcessBase, ThreadBase, 0x20183, InspectBase, 0x20183),
        new Profile("desktop_renderer_enum_handle", ProcessBase, ThreadBase, 0x201c3, 0x201c3, 0x201c3),
        new Profile("all_acl_renderer_desktop_handle", 0x1fffff, 0x1fffff, 0xf01ff, 0xf01ff, 0x20183),
        new Profile("desktop_all_specific_handle", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0x201ff),
        new Profile("desktop_full_minus_delete", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0xe01ff),
        new Profile("desktop_full_minus_write_dac", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0xb01ff),
        new Profile("desktop_full_minus_write_owner", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0x701ff),
        new Profile("desktop_inspect_plus_delete", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0x30081),
        new Profile("desktop_inspect_plus_write_dac", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0x60081),
        new Profile("desktop_inspect_plus_write_owner", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0xa0081),
        new Profile("limited_dup_then_full_open", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, InspectBase, 0xf01ff),
        new Profile("limited_dup_retire_after_full_open", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, InspectBase, 0xf01ff, true),
        new Profile("all_standard_minimum_specific", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, 0xf0081),
        new Profile("source_renderer_mask_full_observer", ProcessBase, ThreadBase, 0xf01ff, 0xf01ff, InspectBase, 0xf01ff, false, 0x20183),
        new Profile("source_renderer_mask_all_policies", 0x1fffff, 0x1fffff, 0xf01ff, 0xf01ff, InspectBase, 0xf01ff, false, 0x20183),
        new Profile("source_renderer_mask_limited_observer", ProcessBase, ThreadBase, 0x20183, InspectBase, InspectBase, InspectBase, false, 0x20183),
        new Profile("own_scratch_all_access", 0x1fffff, 0x1fffff, 0xf01ff, 0xf01ff, 0xf01ff)
    };
    sealed class Profile
    {
        internal readonly string Name;
        internal readonly uint Process, Thread, DesktopBa, DesktopSy, DesktopOpen, DesktopExplicitOpen, SourceDesktopAccess;
        internal readonly bool RetireDuplicate;
        internal Profile(string name, uint process, uint thread, uint ba, uint sy, uint open, uint? explicitOpen = null, bool retireDuplicate = false, uint sourceDesktopAccess = 0xf01ff)
        { Name = name; Process = process; Thread = thread; DesktopBa = ba; DesktopSy = sy; DesktopOpen = open; DesktopExplicitOpen = explicitOpen ?? open; RetireDuplicate = retireDuplicate; SourceDesktopAccess = sourceDesktopAccess; }
    }
    sealed class Fault : Exception
    {
        internal readonly string Stage; internal readonly int Code;
        internal Fault(string stage, int code) { Stage = stage; Code = code; }
    }
    sealed class Handle : IDisposable
    {
        internal IntPtr Value; readonly bool Desktop;
        internal Handle(IntPtr value, bool desktop)
        { if (value == IntPtr.Zero || value == new IntPtr(-1)) throw new Fault("handle", Marshal.GetLastWin32Error()); Value = value; Desktop = desktop; }
        public void Dispose()
        {
            if (Value == IntPtr.Zero) return;
            bool closed = Desktop ? N.CloseDesktop(Value) : N.CloseHandle(Value);
            if (!closed) { CloseFailed = true; return; }
            Value = IntPtr.Zero;
        }
    }
    sealed class Descriptor : IDisposable
    {
        internal IntPtr Value;
        internal Descriptor(uint ba, uint sy)
        {
            uint length;
            string sddl = "O:BAG:BAD:P(A;;0x" + sy.ToString("x8") + ";;;SY)(A;;0x" + ba.ToString("x8") + ";;;BA)(A;;RC;;;OW)";
            Need(N.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out Value, out length), "descriptor");
        }
        public void Dispose() { if (Value != IntPtr.Zero) { if (N.LocalFree(Value) != IntPtr.Zero) CloseFailed = true; Value = IntPtr.Zero; } }
    }
    sealed class Metadata
    {
        internal uint Pid, Tid; internal ulong Created, ThreadCreated, Desktop, Window;
        internal string Name;
        internal string Encode() { return String.Join("|", new string[] { "target", U(Pid), U(Created), U(Tid), U(ThreadCreated), U(Desktop), Name, U(Window) }); }
        internal static Metadata Parse(string line)
        {
            string[] p = line.Split('|');
            if (p.Length != 8 || p[0] != "target" || !ValidName(p[6], NamePrefix)) throw new Fault("metadata", 0);
            Metadata m = new Metadata(); m.Pid = checked((uint)Number(p[1])); m.Created = Number(p[2]);
            m.Tid = checked((uint)Number(p[3])); m.ThreadCreated = Number(p[4]); m.Desktop = Number(p[5]); m.Name = p[6]; m.Window = Number(p[7]);
            if (m.Pid == 0 || m.Tid == 0 || m.Created == 0 || m.ThreadCreated < m.Created || m.Desktop == 0 || m.Desktop > Int64.MaxValue || m.Window == 0 || m.Window > Int64.MaxValue) throw new Fault("metadata", 0);
            return m;
        }
    }
    sealed class Result
    {
        internal string Name, Stage = "not_run"; internal bool Completed, Got, Equal, OpenGot, OpenEqual, Clean;
        internal bool WindowMembership, WrongPidRejected, WrongTidRejected, WrongDesktopRejected;
        internal int Error, OpenError;
        internal bool MembershipControls { get { return WindowMembership && WrongPidRejected && WrongTidRejected && WrongDesktopRejected; } }
        internal string Wire() { return String.Join("|", new string[] { "result", B(Completed), B(Got), B(Equal), Error.ToString(CultureInfo.InvariantCulture), B(OpenGot), B(OpenEqual), OpenError.ToString(CultureInfo.InvariantCulture), B(WindowMembership), B(WrongPidRejected), B(WrongTidRejected), B(WrongDesktopRejected) }); }
        internal void Parse(string wire)
        {
            string[] p = wire.Split('|'); if (p.Length != 12 || p[0] != "result") throw new Fault("reply", 0);
            Completed = Bit(p[1]); Got = Bit(p[2]); Equal = Bit(p[3]); Error = Integer(p[4]); OpenGot = Bit(p[5]); OpenEqual = Bit(p[6]); OpenError = Integer(p[7]);
            WindowMembership = Bit(p[8]); WrongPidRejected = Bit(p[9]); WrongTidRejected = Bit(p[10]); WrongDesktopRejected = Bit(p[11]);
            if (!Completed || (Equal && !Got) || (OpenEqual && !OpenGot) || (Got && Error != 0) || (OpenGot && OpenError != 0)) throw new Fault("reply", 0);
            Stage = "observed";
        }
        internal string Json()
        {
            return "{\"case\":\"" + Name + "\",\"stage\":\"" + Stage + "\",\"completed\":" + J(Completed) +
                ",\"getThreadDesktop\":" + J(Got) + ",\"sameObject\":" + J(Equal) + ",\"error\":" + Error +
                ",\"afterExplicitOpen\":" + J(OpenGot) + ",\"afterOpenSameObject\":" + J(OpenEqual) +
                ",\"afterOpenError\":" + OpenError + ",\"windowMembership\":" + J(WindowMembership) +
                ",\"wrongPidRejected\":" + J(WrongPidRejected) + ",\"wrongTidRejected\":" + J(WrongTidRejected) +
                ",\"wrongDesktopRejected\":" + J(WrongDesktopRejected) + ",\"cleanup\":" + J(Clean) + "}";
        }
    }
    static int Main(string[] args)
    {
        try
        {
            Guard();
            if (args.Length == 0) return Root();
            if (args.Length != 2) return 2;
            Profile profile = Find(args[1]);
            if (args[0] == "target") return Target(profile);
            if (args[0] == "inspector") return Inspector(profile);
        }
        catch { if (args.Length == 0) Console.WriteLine("{\"fixtureCompleted\":false,\"positiveControl\":false,\"cases\":[]}"); }
        return 2;
    }
    static void Guard()
    {
        if (IntPtr.Size != 8 || Environment.OSVersion.Platform != PlatformID.Win32NT ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows" || Environment.GetEnvironmentVariable("CI") != "true" ||
            Path.GetFileName(Image()) != ImageName || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new Fault("guard", 0);
        IntPtr station = N.GetProcessWindowStation();
        if (!String.Equals(ObjectText(station, 2), "WinSta0", StringComparison.OrdinalIgnoreCase)) throw new Fault("station", 0);
    }
    static int Root()
    {
        List<Result> results = new List<Result>(); bool complete = true, positive = false;
        foreach (Profile profile in Profiles)
        {
            Result result = RunCase(profile); results.Add(result);
            complete &= result.Completed && result.Clean && result.MembershipControls;
            if (profile.Name == "own_scratch_all_access") positive = result.Completed && result.Clean && result.MembershipControls && result.Got && result.Equal && result.OpenGot && result.OpenEqual;
        }
        List<string> json = new List<string>(); foreach (Result result in results) json.Add(result.Json());
        Console.WriteLine("{\"configuration\":\"hidden_static_witness_v1\",\"fixtureCompleted\":" + J(complete) + ",\"positiveControl\":" + J(positive) + ",\"cases\":[" + String.Join(",", json.ToArray()) + "]}");
        return complete && positive && !CloseFailed ? 0 : 1;
    }
    static Result RunCase(Profile profile)
    {
        Result result = new Result(); result.Name = profile.Name;
        Process target = null, inspector = null; Handle job = null; NamedPipeServerStream targetPipe = null, inspectorPipe = null;
        bool targetClean = false, inspectorClean = false;
        try
        {
            Budget(1); job = Job();
            string targetName = PipePrefix + Guid.NewGuid().ToString("N"); targetPipe = Server(targetName);
            target = Child("target", profile, targetName); Need(N.AssignProcessToJobObject(job.Value, target.Handle), "assign_target");
            Connect(targetPipe, target); Write(targetPipe, "start");
            Metadata metadata = Metadata.Parse(Read(targetPipe));
            if (metadata.Pid != target.Id || metadata.Created != Creation(target.Handle, false)) throw new Fault("target_identity", 0);
            CheckProcess(target.Handle, metadata.Pid, metadata.Created);
            string inspectorName = PipePrefix + Guid.NewGuid().ToString("N"); inspectorPipe = Server(inspectorName);
            inspector = Child("inspector", profile, inspectorName); Need(N.AssignProcessToJobObject(job.Value, inspector.Handle), "assign_inspector");
            Connect(inspectorPipe, inspector); Write(inspectorPipe, metadata.Encode()); result.Parse(Read(inspectorPipe));
            inspectorClean = Exited(inspector, 1000) && inspector.ExitCode == 0;
            Write(targetPipe, "close"); targetClean = Exited(target, 1000) && target.ExitCode == 0;
        }
        catch (Fault f) { result.Stage = f.Stage; result.Error = f.Code; result.Completed = false; }
        catch { result.Stage = "fixture_failure"; result.Error = 0; result.Completed = false; }
        finally
        {
            // Exact returned Process handles only; never kill/reopen a candidate PID.
            if (targetPipe != null) targetPipe.Dispose(); if (inspectorPipe != null) inspectorPipe.Dispose();
            bool inspectorReaped = Reap(inspector), targetReaped = Reap(target);
            if (job != null) job.Dispose();
            result.Clean = inspectorReaped && targetReaped && !CloseFailed;
            if (result.Completed && (!targetClean || !inspectorClean)) { result.Completed = false; result.Stage = "child_exit"; }
            if (inspector != null) inspector.Dispose(); if (target != null) target.Dispose();
        }
        return result;
    }
    static int Target(Profile profile)
    {
        using (NamedPipeClientStream pipe = Client())
        {
            try
            {
            if (Read(pipe) != "start") throw new Fault("phase", 0);
            uint tid = N.GetCurrentThreadId(); IntPtr old = N.GetThreadDesktop(tid); if (old == IntPtr.Zero) throw new Fault("original_desktop", Marshal.GetLastWin32Error());
            string name = NamePrefix + Guid.NewGuid().ToString("N");
            using (Descriptor initial = profile.SourceDesktopAccess == 0xf01ff ? new Descriptor(0xf01ff, 0xf01ff) : new Descriptor(profile.DesktopBa, profile.DesktopSy))
            {
                N.SA sa = new N.SA(); sa.Length = Marshal.SizeOf(typeof(N.SA)); sa.Descriptor = initial.Value;
                using (Handle desktop = new Handle(N.CreateDesktopW(name, null, IntPtr.Zero, 0, profile.SourceDesktopAccess, ref sa), true))
                {
                    IntPtr witness = IntPtr.Zero;
                    try
                    {
                        // Scratch target thread only; no input-desktop switch.
                        Need(N.SetThreadDesktop(desktop.Value), "own_thread_desktop");
                        N.MSG message = new N.MSG(); N.PeekMessageW(out message, IntPtr.Zero, 0x400, 0x400, 0);
                        using (Descriptor d = new Descriptor(profile.DesktopBa, profile.DesktopSy))
                        using (Descriptor p = new Descriptor(profile.Process, profile.Process))
                        using (Descriptor t = new Descriptor(profile.Thread, profile.Thread))
                        {
                            // A limited source cannot rewrite its desktop DACL;
                            // its exact final descriptor was supplied at creation.
                            if (profile.SourceDesktopAccess == 0xf01ff) SetOwn(desktop.Value, 7, d);
                            SetOwn(N.GetCurrentProcess(), 6, p); SetOwn(N.GetCurrentThread(), 6, t);
                            Verify(desktop.Value, 7, d); Verify(N.GetCurrentProcess(), 6, p); Verify(N.GetCurrentThread(), 6, t);
                        }
                        // One empty disabled, hidden, TOP-LEVEL system STATIC on
                        // this original scratch thread. No WS_VISIBLE/WS_CHILD,
                        // message-only parent, ShowWindow, posting or UI input.
                        witness = N.CreateWindowExW(0, "STATIC", "", 0x88000000, 0, 0, 1, 1,
                            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                        if (witness == IntPtr.Zero) throw new Fault("witness_create", Marshal.GetLastWin32Error());
                        uint windowPid; uint windowTid = N.GetWindowThreadProcessId(witness, out windowPid);
                        if (windowPid != N.GetCurrentProcessId() || windowTid != tid) throw new Fault("witness_target_owner", Marshal.GetLastWin32Error());
                        if (N.IsWindowVisible(witness)) throw new Fault("witness_target_visible", 0);
                        if (N.GetAncestor(witness, 2) != witness) throw new Fault("witness_target_root", Marshal.GetLastWin32Error());
                        IntPtr actual = N.GetThreadDesktop(tid);
                        if (actual == IntPtr.Zero || !N.CompareObjectHandles(actual, desktop.Value)) throw new Fault("own_association", Marshal.GetLastWin32Error());
                        Metadata metadata = new Metadata(); metadata.Pid = N.GetCurrentProcessId(); metadata.Created = Creation(N.GetCurrentProcess(), false);
                        metadata.Tid = tid; metadata.ThreadCreated = Creation(N.GetCurrentThread(), true); metadata.Desktop = checked((ulong)actual.ToInt64()); metadata.Name = name; metadata.Window = checked((ulong)witness.ToInt64());
                        Write(pipe, metadata.Encode()); if (Read(pipe) != "close") throw new Fault("phase", 0);
                    }
                    finally {
                        // Destroy only this thread's owned witness BEFORE any
                        // attempt to restore its original desktop association.
                        if (witness != IntPtr.Zero && !N.DestroyWindow(witness)) CloseFailed = true;
                        if (!N.SetThreadDesktop(old)) CloseFailed = true;
                    }
                }
            }
            }
            catch (Fault failure) { ReportFailure(pipe, failure); return 2; }
            catch { ReportFailure(pipe, new Fault("fixture_failure", 0)); return 2; }
        }
        return CloseFailed ? 1 : 0;
    }
    static int Inspector(Profile profile)
    {
        using (NamedPipeClientStream pipe = Client())
        {
            try
            {
            Metadata m = Metadata.Parse(Read(pipe));
            if (m.Pid == N.GetCurrentProcessId()) throw new Fault("target_identity", 0);
            using (Handle process = new Handle(N.OpenProcess(profile.Process, false, m.Pid), false))
            using (Handle thread = new Handle(N.OpenThread(profile.Thread, false, m.Tid), false))
            using (Descriptor p = new Descriptor(profile.Process, profile.Process))
            using (Descriptor t = new Descriptor(profile.Thread, profile.Thread))
            using (Descriptor d = new Descriptor(profile.DesktopBa, profile.DesktopSy))
            {
                CheckProcess(process.Value, m.Pid, m.Created);
                if (N.GetProcessIdOfThread(thread.Value) != m.Pid || Creation(thread.Value, true) != m.ThreadCreated) throw new Fault("thread_identity", 0);
                Verify(process.Value, 6, p); Verify(thread.Value, 6, t);
                IntPtr duplicated;
                Need(N.DuplicateHandle(process.Value, new IntPtr(checked((long)m.Desktop)), N.GetCurrentProcess(), out duplicated, profile.DesktopOpen, false, 0), "duplicate");
                using (Handle desktop = new Handle(duplicated, true))
                {
                    if (ObjectText(desktop.Value, 3) != "Desktop" || ObjectText(desktop.Value, 2) != m.Name) throw new Fault("desktop_identity", 0);
                    Verify(desktop.Value, 7, d);
                    IntPtr readerOriginal = N.GetThreadDesktop(N.GetCurrentThreadId());
                    if (readerOriginal == IntPtr.Zero) throw new Fault("witness_reader_attach", Marshal.GetLastWin32Error());
                    Need(N.SetThreadDesktop(desktop.Value), "witness_reader_attach");
                    try {
                    Result result = new Result(); result.Name = profile.Name;
                    CheckMembershipControls(result, desktop.Value, process.Value, thread.Value, m, readerOriginal);
                    N.SetLastError(0); IntPtr actual = N.GetThreadDesktop(m.Tid); int error = Marshal.GetLastWin32Error();
                    result.Got = actual != IntPtr.Zero; result.Error = result.Got ? 0 : error;
                    result.Equal = result.Got && N.CompareObjectHandles(actual, desktop.Value);
                    // Independent explicit-open comparison; neither failure is promoted.
                    using (Handle opened = new Handle(N.OpenDesktopW(m.Name, 0, false, profile.DesktopExplicitOpen), true))
                    {
                        if (!N.CompareObjectHandles(opened.Value, desktop.Value)) throw new Fault("opened_identity", 0);
                        Verify(opened.Value, 7, d);
                        // Own scratch duplicate only. The independently opened
                        // handle already matched it and pins that same object.
                        if (profile.RetireDuplicate) {
                            Need(N.SetThreadDesktop(readerOriginal), "witness_reader_restore");
                            desktop.Dispose(); if (CloseFailed) throw new Fault("handle", 0);
                            Need(N.SetThreadDesktop(opened.Value), "witness_reader_attach");
                        }
                        N.SetLastError(0); IntPtr after = N.GetThreadDesktop(m.Tid); int afterError = Marshal.GetLastWin32Error();
                        result.OpenGot = after != IntPtr.Zero; result.OpenError = result.OpenGot ? 0 : afterError;
                        result.OpenEqual = result.OpenGot && N.CompareObjectHandles(after, opened.Value);
                        // actual/after are borrowed thread associations; never CloseDesktop.
                        CheckProcess(process.Value, m.Pid, m.Created);
                        if (N.GetProcessIdOfThread(thread.Value) != m.Pid || Creation(thread.Value, true) != m.ThreadCreated) throw new Fault("thread_identity", 0);
                        if (profile.RetireDuplicate) Need(N.SetThreadDesktop(readerOriginal), "witness_reader_restore");
                        result.Completed = true; Write(pipe, result.Wire());
                    }
                    } finally { if (!N.SetThreadDesktop(readerOriginal)) CloseFailed = true; }
                }
            }
            }
            catch (Fault failure) { ReportFailure(pipe, failure); return 2; }
            catch { ReportFailure(pipe, new Fault("fixture_failure", 0)); return 2; }
        }
        return CloseFailed ? 1 : 0;
    }
    static void CheckMembershipControls(Result result, IntPtr desktop, IntPtr process, IntPtr thread, Metadata m, IntPtr wrongDesktop)
    {
        CheckWitnessTarget(process, thread, m);
        IntPtr window = new IntPtr(checked((long)m.Window));
        if (N.IsWindowVisible(window)) throw new Fault("witness_reader_visible", 0);
        if (N.GetAncestor(window, 2) != window) throw new Fault("witness_reader_root", Marshal.GetLastWin32Error());
        StringBuilder className = new StringBuilder(64);
        int length = N.GetClassNameW(window, className, className.Capacity);
        if (length <= 0 || length >= className.Capacity || !String.Equals(className.ToString(), "STATIC", StringComparison.OrdinalIgnoreCase))
            throw new Fault("witness_reader_class", Marshal.GetLastWin32Error());
        uint wrongPid = N.GetCurrentProcessId(), wrongTid = N.GetCurrentThreadId();
        if (wrongPid == m.Pid || wrongTid == m.Tid) throw new Fault("witness_negative_setup", 0);
        // Borrowed original inspector Default, captured before read-only attach.
        if (wrongDesktop == IntPtr.Zero || !String.Equals(ObjectText(wrongDesktop, 2), "Default", StringComparison.OrdinalIgnoreCase) ||
            N.CompareObjectHandles(wrongDesktop, desktop)) throw new Fault("witness_negative_setup", 0);
        result.WindowMembership = WindowMember(desktop, window, m.Pid, m.Tid);
        // Negative results must be clean complete enumerations, not API errors.
        result.WrongPidRejected = !WindowMember(desktop, window, wrongPid, m.Tid);
        result.WrongTidRejected = !WindowMember(desktop, window, m.Pid, wrongTid);
        result.WrongDesktopRejected = !WindowMember(wrongDesktop, window, m.Pid, m.Tid);
        result.WindowMembership &= WindowMember(desktop, window, m.Pid, m.Tid);
        CheckWitnessTarget(process, thread, m);
    }
    static void CheckWitnessTarget(IntPtr process, IntPtr thread, Metadata m)
    {
        CheckProcess(process, m.Pid, m.Created);
        if (N.WaitForSingleObject(thread, 0) != 258 || N.GetProcessIdOfThread(thread) != m.Pid || Creation(thread, true) != m.ThreadCreated)
            throw new Fault("thread_identity", 0);
    }
    static bool WindowMember(IntPtr desktop, IntPtr window, uint expectedPid, uint expectedTid)
    {
        Budget(1);
        uint beforePid; uint beforeTid = N.GetWindowThreadProcessId(window, out beforePid);
        if (beforeTid == 0 || beforePid == 0) throw new Fault("witness_reader_owner", Marshal.GetLastWin32Error());
        int count = 0, seen = 0; bool matched = false, callbackFailed = false;
        N.EnumWindow callback = delegate(IntPtr candidate, IntPtr unused) {
            try {
                Budget(1);
                if (++count > 512) { callbackFailed = true; return false; }
                if (candidate == window) {
                    seen++;
                    uint pid; uint tid = N.GetWindowThreadProcessId(candidate, out pid);
                    if (tid == 0 || pid == 0) { callbackFailed = true; return false; }
                    matched = pid == expectedPid && tid == expectedTid;
                }
                return true; // Always complete; finding a candidate is not an early-success stop.
            } catch { callbackFailed = true; return false; } // No managed exception crosses native callback.
        };
        N.SetLastError(0);
        bool complete = N.EnumDesktopWindows(desktop, callback, IntPtr.Zero);
        int error = Marshal.GetLastWin32Error();
        GC.KeepAlive(callback);
        if (!complete || callbackFailed || seen > 1) throw new Fault("witness_enumeration", error);
        uint afterPid; uint afterTid = N.GetWindowThreadProcessId(window, out afterPid);
        if (afterTid == 0 || afterPid == 0 || afterPid != beforePid || afterTid != beforeTid) throw new Fault("witness_identity", 0);
        Budget(1);
        return seen == 1 && matched && beforePid == expectedPid && beforeTid == expectedTid;
    }
    static void SetOwn(IntPtr handle, uint kind, Descriptor descriptor)
    {
        IntPtr owner, group, acl; bool ignored, present;
        Need(N.GetSecurityDescriptorOwner(descriptor.Value, out owner, out ignored), "descriptor");
        Need(N.GetSecurityDescriptorGroup(descriptor.Value, out group, out ignored), "descriptor");
        Need(N.GetSecurityDescriptorDacl(descriptor.Value, out present, out acl, out ignored) && present && acl != IntPtr.Zero, "descriptor");
        uint error = N.SetSecurityInfo(handle, kind, SecurityFields, owner, group, acl, IntPtr.Zero);
        if (error != 0) throw new Fault("own_descriptor", unchecked((int)error));
    }
    static void Verify(IntPtr handle, uint kind, Descriptor expected)
    {
        IntPtr actual, owner, group, acl, sacl;
        uint error = N.GetSecurityInfo(handle, kind, 7, out owner, out group, out acl, out sacl, out actual);
        if (error != 0) throw new Fault("read_descriptor", unchecked((int)error));
        try
        {
            if (actual == IntPtr.Zero || !Parts(actual).Equals(Parts(expected.Value), StringComparison.Ordinal)) throw new Fault("descriptor_mismatch", 0);
        }
        finally { if (actual != IntPtr.Zero && N.LocalFree(actual) != IntPtr.Zero) CloseFailed = true; }
    }
    static string Parts(IntPtr descriptor)
    {
        ushort control; uint revision; IntPtr owner, group, acl; bool ignored, present;
        Need(N.GetSecurityDescriptorControl(descriptor, out control, out revision), "descriptor");
        if (revision != 1 || (control & 0x1004) != 0x1004) throw new Fault("descriptor", 0);
        Need(N.GetSecurityDescriptorOwner(descriptor, out owner, out ignored), "descriptor");
        Need(N.GetSecurityDescriptorGroup(descriptor, out group, out ignored), "descriptor");
        Need(N.GetSecurityDescriptorDacl(descriptor, out present, out acl, out ignored) && present && acl != IntPtr.Zero, "descriptor");
        if (owner == IntPtr.Zero || group == IntPtr.Zero) throw new Fault("descriptor", 0);
        int size = (ushort)Marshal.ReadInt16(acl, 2); if (size < 8 || size > 4096) throw new Fault("descriptor", 0);
        byte[] bytes = new byte[size]; Marshal.Copy(acl, bytes, 0, size);
        return new SecurityIdentifier(owner).Value + "|" + new SecurityIdentifier(group).Value + "|" + Convert.ToBase64String(bytes);
    }
    static Process Child(string role, Profile profile, string pipe)
    {
        ProcessStartInfo info = new ProcessStartInfo(Image(), role + " " + profile.Name);
        info.UseShellExecute = false; info.CreateNoWindow = true; info.WindowStyle = ProcessWindowStyle.Hidden;
        info.EnvironmentVariables["UAC_CI_DESKTOP_PIPE"] = pipe;
        info.EnvironmentVariables["UAC_CI_DESKTOP_PARENT"] = U(N.GetCurrentProcessId());
        info.EnvironmentVariables["UAC_CI_DESKTOP_PARENT_CREATED"] = U(Creation(N.GetCurrentProcess(), false));
        Process child = Process.Start(info); if (child == null) throw new Fault("create_child", 0); return child;
    }
    static NamedPipeServerStream Server(string name)
    {
        PipeSecurity security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 4096, 4096, security);
    }
    static NamedPipeClientStream Client()
    {
        string name = Environment.GetEnvironmentVariable("UAC_CI_DESKTOP_PIPE");
        if (!ValidName(name, PipePrefix)) throw new Fault("pipe_name", 0);
        uint parent = checked((uint)Number(Environment.GetEnvironmentVariable("UAC_CI_DESKTOP_PARENT")));
        ulong created = Number(Environment.GetEnvironmentVariable("UAC_CI_DESKTOP_PARENT_CREATED"));
        NamedPipeClientStream pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            pipe.Connect(Budget(2000)); pipe.ReadMode = PipeTransmissionMode.Message;
            uint pid, session; Need(N.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out pid), "pipe_peer");
            Need(N.GetNamedPipeServerSessionId(pipe.SafePipeHandle.DangerousGetHandle(), out session), "pipe_peer");
            if (pid != parent || session != Session(N.GetCurrentProcessId())) throw new Fault("pipe_peer", 0);
            using (Handle process = new Handle(N.OpenProcess(0x101000, false, pid), false)) CheckProcess(process.Value, pid, created);
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }
    static void Connect(NamedPipeServerStream pipe, Process child)
    {
        IAsyncResult pending = pipe.BeginWaitForConnection(null, null);
        using (pending.AsyncWaitHandle) { if (!pending.AsyncWaitHandle.WaitOne(Budget(2000))) throw new Fault("pipe_timeout", 0); pipe.EndWaitForConnection(pending); }
        uint pid, session; Need(N.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out pid), "pipe_peer");
        Need(N.GetNamedPipeClientSessionId(pipe.SafePipeHandle.DangerousGetHandle(), out session), "pipe_peer");
        if (pid != child.Id || session != Session(N.GetCurrentProcessId())) throw new Fault("pipe_peer", 0);
        CheckProcess(child.Handle, pid, Creation(child.Handle, false));
    }
    static string Read(PipeStream pipe)
    {
        byte[] bytes = new byte[1024]; Task<int> read = pipe.ReadAsync(bytes, 0, bytes.Length);
        if (!read.Wait(Budget(3000))) throw new Fault("read_timeout", 0);
        int count = read.Result;
        if (count <= 0 || !pipe.IsMessageComplete) throw new Fault("frame", 0);
        for (int i = 0; i < count; i++) if (bytes[i] < 32 || bytes[i] > 126) throw new Fault("frame", 0);
        string text = Encoding.ASCII.GetString(bytes, 0, count);
        if (text.StartsWith("failure|", StringComparison.Ordinal)) {
            string[] fields = text.Split('|');
            if (fields.Length != 3 || !KnownStage(fields[1])) throw new Fault("child_failure", 0);
            throw new Fault(fields[1], Integer(fields[2]));
        }
        return text;
    }
    static void ReportFailure(PipeStream pipe, Fault failure)
    {
        // Closed diagnostic only through the already kernel-PID-bound channel;
        // no exception prose, paths, handle values or object names are exported.
        try { Write(pipe, "failure|" + (KnownStage(failure.Stage) ? failure.Stage : "fixture_failure") + "|" + failure.Code.ToString(CultureInfo.InvariantCulture)); }
        catch { }
    }
    static bool KnownStage(string stage)
    {
        switch (stage) {
            case "handle": case "descriptor": case "metadata": case "reply":
            case "guard": case "station": case "phase": case "original_desktop":
            case "own_thread_desktop": case "own_association": case "target_identity":
            case "thread_identity": case "duplicate": case "desktop_identity":
            case "opened_identity": case "own_descriptor": case "read_descriptor":
            case "descriptor_mismatch": case "process_identity": case "image":
            case "creation": case "session": case "object": case "number":
            case "boolean": case "frame": case "read_timeout": case "write_timeout":
            case "deadline": case "fixture_failure": return true;
            case "witness_create": case "witness_identity": case "witness_enumeration":
            case "witness_negative_setup": return true;
            case "witness_target_owner": case "witness_target_visible": case "witness_target_root":
            case "witness_reader_visible": case "witness_reader_root": case "witness_reader_class":
            case "witness_reader_owner": return true;
            case "witness_reader_attach": case "witness_reader_restore": return true;
            default: return false;
        }
    }
    static void Write(PipeStream pipe, string text)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text); if (bytes.Length == 0 || bytes.Length > 1024) throw new Fault("frame", 0);
        Task write = pipe.WriteAsync(bytes, 0, bytes.Length); if (!write.Wait(Budget(2000))) throw new Fault("write_timeout", 0);
    }
    static Handle Job()
    {
        Handle job = new Handle(N.CreateJobObjectW(IntPtr.Zero, null), false);
        try { N.JOB_EXTENDED info = new N.JOB_EXTENDED(); info.Basic.LimitFlags = 0x2008; info.Basic.ActiveProcessLimit = 2;
            Need(N.SetInformationJobObject(job.Value, 9, ref info, (uint)Marshal.SizeOf(typeof(N.JOB_EXTENDED))), "job"); return job; }
        catch { job.Dispose(); throw; }
    }
    static bool Reap(Process child)
    {
        if (child == null) return true;
        try { if (N.WaitForSingleObject(child.Handle, 0) != 0) { if (!N.TerminateProcess(child.Handle, 91)) return false; }
            return N.WaitForSingleObject(child.Handle, 1000) == 0; } catch { return false; }
    }
    static bool Exited(Process child, int milliseconds) { return N.WaitForSingleObject(child.Handle, (uint)Budget(milliseconds)) == 0; }
    static int Budget(int requested) { long left = 55000 - Clock.ElapsedMilliseconds; if (left <= 0) throw new Fault("deadline", 0); return (int)Math.Min(left, requested); }
    static void CheckProcess(IntPtr process, uint pid, ulong created)
    {
        if (N.GetProcessId(process) != pid || Creation(process, false) != created || N.WaitForSingleObject(process, 0) != 258 || Session(pid) != Session(N.GetCurrentProcessId())) throw new Fault("process_identity", 0);
        StringBuilder image = new StringBuilder(2048); uint length = 2048; Need(N.QueryFullProcessImageNameW(process, 0, image, ref length), "image");
        if (length == 0 || length >= 2048 || !String.Equals(image.ToString(), Image(), StringComparison.OrdinalIgnoreCase)) throw new Fault("image", 0);
    }
    static ulong Creation(IntPtr handle, bool thread)
    {
        long created, exit, kernel, user;
        Need(thread ? N.GetThreadTimes(handle, out created, out exit, out kernel, out user) : N.GetProcessTimes(handle, out created, out exit, out kernel, out user), "creation");
        if (created <= 0) throw new Fault("creation", 0); return (ulong)created;
    }
    static uint Session(uint pid) { uint session; Need(N.ProcessIdToSessionId(pid, out session), "session"); if (session == 0) throw new Fault("session", 0); return session; }
    static string ObjectText(IntPtr handle, int index)
    {
        StringBuilder text = new StringBuilder(256); uint needed;
        Need(N.GetUserObjectInformationW(handle, index, text, 512, out needed), "object");
        if (needed < 2 || needed > 512 || needed % 2 != 0) throw new Fault("object", 0); return text.ToString();
    }
    static string Image() { return Process.GetCurrentProcess().MainModule.FileName; }
    static Profile Find(string name) { foreach (Profile p in Profiles) if (p.Name == name) return p; throw new Fault("case", 0); }
    static bool ValidName(string text, string prefix) { if (text == null || text.Length != prefix.Length + 32 || !text.StartsWith(prefix, StringComparison.Ordinal)) return false; foreach (char c in text.Substring(prefix.Length)) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false; return true; }
    static ulong Number(string text) { ulong value; if (String.IsNullOrEmpty(text) || text.Length > 20 || !UInt64.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value)) throw new Fault("number", 0); return value; }
    static int Integer(string text) { int value; if (!Int32.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value)) throw new Fault("number", 0); return value; }
    static bool Bit(string text) { if (text == "1") return true; if (text == "0") return false; throw new Fault("boolean", 0); }
    static string U(ulong value) { return value.ToString(CultureInfo.InvariantCulture); }
    static string B(bool value) { return value ? "1" : "0"; }
    static string J(bool value) { return value ? "true" : "false"; }
    static void Need(bool value, string stage) { if (!value) throw new Fault(stage, Marshal.GetLastWin32Error()); }

    static class N
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal delegate bool EnumWindow(IntPtr window, IntPtr parameter);
        [StructLayout(LayoutKind.Sequential)] internal struct SA { internal int Length; internal IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] internal bool Inherit; }
        [StructLayout(LayoutKind.Sequential)] internal struct POINT { internal int X, Y; }
        [StructLayout(LayoutKind.Sequential)] internal struct MSG { internal IntPtr Window; internal uint Message; internal UIntPtr WParam; internal IntPtr LParam; internal uint Time; internal POINT Point; internal uint Private; }
        [StructLayout(LayoutKind.Sequential)] internal struct JOB_BASIC { internal long ProcessTime, JobTime; internal uint LimitFlags; internal UIntPtr MinWorking, MaxWorking; internal uint ActiveProcessLimit; internal UIntPtr Affinity; internal uint Priority, Scheduling; }
        [StructLayout(LayoutKind.Sequential)] internal struct IO_COUNTERS { internal ulong R, W, O, RB, WB, OB; }
        [StructLayout(LayoutKind.Sequential)] internal struct JOB_EXTENDED { internal JOB_BASIC Basic; internal IO_COUNTERS Io; internal UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll")] internal static extern uint GetCurrentThreadId();
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint GetProcessIdOfThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool ProcessIdToSessionId(uint pid, out uint session);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool DuplicateHandle(IntPtr source, IntPtr handle, IntPtr target, out IntPtr duplicate, uint access, bool inherit, uint options);
        [DllImport("kernelbase.dll", SetLastError=true)] internal static extern bool CompareObjectHandles(IntPtr first, IntPtr second);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetProcessTimes(IntPtr process, out long created, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetThreadTimes(IntPtr thread, out long created, out long exit, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint length);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool SetInformationJobObject(IntPtr job, int kind, ref JOB_EXTENDED info, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint session);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool GetNamedPipeServerSessionId(IntPtr pipe, out uint session);
        [DllImport("kernel32.dll")] internal static extern void SetLastError(uint code);
        [DllImport("kernel32.dll")] internal static extern IntPtr LocalFree(IntPtr value);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("advapi32.dll", SetLastError=true)] internal static extern bool GetSecurityDescriptorControl(IntPtr descriptor, out ushort control, out uint revision);
        [DllImport("advapi32.dll", SetLastError=true)] internal static extern bool GetSecurityDescriptorOwner(IntPtr descriptor, out IntPtr owner, out bool defaulted);
        [DllImport("advapi32.dll", SetLastError=true)] internal static extern bool GetSecurityDescriptorGroup(IntPtr descriptor, out IntPtr group, out bool defaulted);
        [DllImport("advapi32.dll", SetLastError=true)] internal static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr acl, out bool defaulted);
        [DllImport("advapi32.dll")] internal static extern uint GetSecurityInfo(IntPtr handle, uint kind, uint fields, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll")] internal static extern uint SetSecurityInfo(IntPtr handle, uint kind, uint fields, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr CreateDesktopW(string name, string device, IntPtr mode, uint flags, uint access, ref SA attributes);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr OpenDesktopW(string name, uint flags, bool inherit, uint access);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool SetThreadDesktop(IntPtr desktop);
        [DllImport("user32.dll", SetLastError=true)] internal static extern IntPtr GetThreadDesktop(uint tid);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool CloseDesktop(IntPtr desktop);
        [DllImport("user32.dll", SetLastError=true)] internal static extern IntPtr GetProcessWindowStation();
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern bool GetUserObjectInformationW(IntPtr handle, int index, StringBuilder text, uint length, out uint needed);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool PeekMessageW(out MSG message, IntPtr window, uint min, uint max, uint remove);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern IntPtr CreateWindowExW(uint extended, string className, string title, uint style, int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool DestroyWindow(IntPtr window);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll", SetLastError=true)] internal static extern IntPtr GetAncestor(IntPtr window, uint flags);
        [DllImport("user32.dll", SetLastError=true)] internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
        [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)] internal static extern int GetClassNameW(IntPtr window, StringBuilder name, int length);
        [DllImport("user32.dll", SetLastError=true)] internal static extern bool EnumDesktopWindows(IntPtr desktop, EnumWindow callback, IntPtr parameter);
    }
}
