// SPDX-License-Identifier: GPL-2.0-or-later
// uac-ci-e2e-do-not-ship. Fixed harmless target/requester, not a generic launcher.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
[assembly: AssemblyTitle("UacCiHarmlessRequest")]
[assembly: AssemblyDescription("UacCiHarmlessRequest")]
internal static class CiRequest {
    const string Root = @"C:\ProgramData\UacRemoteCiE2e";
    const string Target = @"C:\Program Files\휴대폰 승인\uac-ci-request.exe";
#if REQUEST_TARGET
    static int Main() {
        File.WriteAllText(Root + @"\unexpected-execution.txt", "unexpected elevated target execution");
        return 0;
    }
#else
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct ExecuteInfo {
        public uint size, mask; public IntPtr hwnd;
        public string verb, file, parameters, directory;
        public int show; public IntPtr instance, idList; public string className;
        public IntPtr classKey; public uint hotKey; public IntPtr icon, process;
    }
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool ShellExecuteExW(ref ExecuteInfo info);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [STAThread] static int Main() {
        if (Environment.GetCommandLineArgs().Length != 1 ||
            !String.Equals(Process.GetCurrentProcess().MainModule.FileName,
                @"C:\Program Files\휴대폰 승인\uac-ci-requester.exe", StringComparison.OrdinalIgnoreCase)) return 2;
        var deadline = Stopwatch.StartNew();
        while (!File.Exists(Root + @"\request.trigger")) {
            if (deadline.Elapsed.TotalSeconds >= 280) return 3;
            Thread.Sleep(100);
        }
        var info = new ExecuteInfo { size=(uint)Marshal.SizeOf(typeof(ExecuteInfo)), mask=0x40|0x100|0x400,
            verb="runas", file=Target, directory=Path.GetDirectoryName(Target), show=0 };
        if (ShellExecuteExW(ref info)) {
            if (info.process != IntPtr.Zero) CloseHandle(info.process);
            return 4; // Any elevation is a failing test, even for this inert target.
        }
        return Marshal.GetLastWin32Error() == 1223 ? 0 : 5;
    }
#endif
}
