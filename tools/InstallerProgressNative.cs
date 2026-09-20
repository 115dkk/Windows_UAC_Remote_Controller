// SPDX-License-Identifier: GPL-2.0-or-later
// Read-only geometry of one test-owned native MUI progress control.
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class InstallerProgressNative {
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern int MapWindowPoints(IntPtr from, IntPtr to, ref Rect rect, uint count);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr window, StringBuilder value, int count);
    [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr window);
    public static int[] Measure(IntPtr window, IntPtr progress, uint pid) {
        uint first, second;
        if (GetWindowThreadProcessId(window, out first) == 0 || GetWindowThreadProcessId(progress, out second) == 0 || first != pid || second != pid)
            throw new InvalidOperationException("Test-owned windows required");
        var type = new StringBuilder(64);
        GetClassNameW(progress, type, type.Capacity);
        if (!type.ToString().Equals("msctls_progress32", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Native progress control required");
        Rect client, control;
        if (!GetClientRect(window, out client) || !GetWindowRect(progress, out control)) throw new InvalidOperationException("Geometry unavailable");
        MapWindowPoints(IntPtr.Zero, window, ref control, 2);
        return new[] { client.Right, control.Left, control.Right, control.Bottom - control.Top };
    }
}
