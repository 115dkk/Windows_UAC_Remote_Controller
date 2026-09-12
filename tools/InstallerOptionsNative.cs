// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only standard Win32 button adapter. Not linked or shipped in the product.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class InstallerOptionsNative {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int size);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int size);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)] private static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint message, UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);

    private static string CheckButton(IntPtr hwnd, uint expectedPid) {
        uint actualPid;
        if (hwnd == IntPtr.Zero || GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != expectedPid || !IsWindowEnabled(hwnd)) throw new InvalidOperationException("Owned enabled wizard button required");
        var name = new StringBuilder(64);
        if (GetClassNameW(hwnd, name, name.Capacity) == 0 || !name.ToString().Equals("Button", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Standard wizard button required");
        var text = new StringBuilder(256);
        if (GetWindowTextW(hwnd, text, text.Capacity) == 0) throw new InvalidOperationException("Button label unavailable");
        return text.ToString().Replace("&", "");
    }

    private static ulong Message(IntPtr hwnd, uint message) {
        UIntPtr result;
        if (SendMessageTimeoutW(hwnd, message, UIntPtr.Zero, IntPtr.Zero, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return result.ToUInt64();
    }

    public static void Next(IntPtr hwnd, uint expectedPid) {
        string text = CheckButton(hwnd, expectedPid);
        if (GetDlgCtrlID(hwnd) != 1 || !(text.StartsWith("Next", StringComparison.Ordinal) || text.StartsWith("다음", StringComparison.Ordinal) || text.StartsWith("I Agree", StringComparison.Ordinal) || text.StartsWith("동의함", StringComparison.Ordinal))) throw new InvalidOperationException("Only pre-install Next/Agree is allowed");
        Message(hwnd, 0x00F5); // BM_CLICK. Never the Install or Finish button.
    }

    public static bool Checked(IntPtr hwnd, uint expectedPid) {
        string text = CheckButton(hwnd, expectedPid);
        if (!(text.StartsWith("Add to ", StringComparison.Ordinal) || text.StartsWith("바탕화면에 추가", StringComparison.Ordinal) || text.StartsWith("시작 메뉴의 앱 목록에 추가", StringComparison.Ordinal) || text.StartsWith("작업표시줄에 추가", StringComparison.Ordinal))) throw new InvalidOperationException("Known shortcut choice required");
        ulong value = Message(hwnd, 0x00F0); // BM_GETCHECK, actual Win32 state.
        if (value > 1) throw new InvalidOperationException("Unexpected checkbox state");
        return value == 1;
    }
}
