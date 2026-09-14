// SPDX-License-Identifier: GPL-2.0-or-later
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Automation;

internal static class ProtectedUi
{
    private const string RendererClass = "UacRemoteControllerPairingRenderer";
    private static bool consentConsumed;
    private static bool detailsExpanded;
    private static volatile string[] lastTopologyLines;

    // Publish one completed snapshot only. Callers cannot mutate the retained
    // diagnostic array; none of these observations participate in admission.
    internal static string[] LastTopologyLines
    {
        get
        {
            var snapshot = lastTopologyLines;
            return snapshot == null ? null : (string[])snapshot.Clone();
        }
    }

    internal static List<Process> ConsentProcesses()
    {
        var result = new List<Process>();
        foreach (var process in Process.GetProcessesByName("consent"))
        {
            if (process.SessionId == Program.Session) result.Add(process);
            else process.Dispose();
        }
        return result;
    }

    // Every operation starts on a fresh OS thread: SetThreadDesktop must precede
    // UIA/GDI objects. Never SwitchDesktop, change its DACL, or enable a privilege.
    private static T OnInput<T>(Func<IntPtr, string, T> action)
    {
        T result = default(T);
        Exception failure = null;
        var thread = new Thread(() =>
        {
            IntPtr original = Native.GetThreadDesktop(Native.GetCurrentThreadId());
            IntPtr desktop = IntPtr.Zero;
            try
            {
                // UIA may create its own hidden helper window. Request only
                // object read/write and creation, never switching,
                // hooks, desktop ACL changes or privilege adjustment.
                // EnumDesktopWindows requires READOBJECTS; do not request the
                // separate ENUMERATE right omitted by the product desktop DACL.
                desktop = Native.OpenInputDesktop(0, false, 0x0001 | 0x0002 | 0x0080);
                Program.Require(desktop != IntPtr.Zero, "input_desktop_inaccessible");
                Program.Require(Native.SetThreadDesktop(desktop), "thread_desktop_rejected");
                result = action(desktop, DesktopName(desktop));
            }
            catch (Exception error) { failure = error; }
            finally
            {
                // A UIA-created hidden HWND can prevent detach. In that case leave
                // this one desktop handle until the bounded process exits; never
                // close a handle still assigned to a thread or alter the desktop.
                if (desktop != IntPtr.Zero && Native.SetThreadDesktop(original)) Native.CloseDesktop(desktop);
            }
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.MTA);
        thread.Start();
        while (!thread.Join(100)) Program.Deadline();
        if (failure != null) throw failure;
        return result;
    }

    private static string DesktopName(IntPtr desktop)
    {
        var name = new StringBuilder(256);
        uint needed;
        Program.Require(Native.GetUserObjectInformation(desktop, 2, name, (uint)name.Capacity * 2, out needed), "desktop_name_unavailable");
        return name.ToString();
    }

    private static void StillInput(string expected)
    {
        IntPtr input = Native.OpenInputDesktop(0, false, 1);
        Program.Require(input != IntPtr.Zero, "input_desktop_lost");
        try { Program.Require(DesktopName(input) == expected, "input_desktop_changed"); }
        finally { Native.CloseDesktop(input); }
    }

    private static List<IntPtr> Windows(IntPtr desktop)
    {
        var windows = new List<IntPtr>();
        Program.Require(Native.EnumDesktopWindows(desktop, (window, _) =>
        {
            if (Native.IsWindowVisible(window)) windows.Add(window);
            return windows.Count < 128;
        }, IntPtr.Zero), "desktop_enumeration_rejected");
        Program.Require(windows.Count < 128, "too_many_windows");
        return windows;
    }

    private static string WindowClass(IntPtr window)
    {
        var name = new StringBuilder(256);
        Program.Require(Native.GetClassName(window, name, name.Capacity) > 0, "window_class_unavailable");
        return name.ToString();
    }

    private static bool OrdinaryConsentWindow(IntPtr window)
    {
        // consent.exe also owns visible auxiliary windows. Follow the already
        // qualified product probe's owner/TOOLWINDOW/NOACTIVATE filter, retaining
        // the independent exact location/provider/Yes checks below.
        Native.SetLastError(0);
        IntPtr owner = Native.GetWindow(window, 4); // GW_OWNER
        Program.Require(owner != IntPtr.Zero || Marshal.GetLastWin32Error() == 0, "window_class_unavailable");
        Native.SetLastError(0);
        IntPtr style = Native.GetWindowLongPtr(window, -20); // GWL_EXSTYLE
        Program.Require(style != IntPtr.Zero || Marshal.GetLastWin32Error() == 0, "window_class_unavailable");
        return !ConsentTarget.IsAuxiliaryWindow(owner != IntPtr.Zero, unchecked((uint)style.ToInt64()));
    }

    internal static void ApprovePairingConsent()
    {
        Program.Require(!consentConsumed, "one_consent_only");
        int latchedConsentPid = 0;
        long latchedConsentCreation = 0;
        long readinessUntilMilliseconds = 0;
        while (true)
        {
            Program.Deadline();
            var candidates = ConsentProcesses();
            try
            {
                Program.Require(candidates.Count <= 1, "ambiguous_consent_processes");
                Program.Require(latchedConsentPid == 0 || candidates.Count == 1, "consent_exited");
                if (candidates.Count == 1)
                {
                    var consent = candidates[0];
                    string consentImage;
                    long consentCreation;
                    int consentSession;
                    Program.ObserveProcess(consent.Id, out consentImage, out consentCreation, out consentSession);
                    Program.Require(consentCreation >= Program.ArmedUtc.Ticks && consentSession == Program.Session, "stale_consent");
                    Program.Require(String.Equals(consentImage,
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\consent.exe"),
                        StringComparison.OrdinalIgnoreCase), "consent_image_rejected");
                    if (latchedConsentPid == 0)
                    {
                        latchedConsentPid = consent.Id;
                        latchedConsentCreation = consentCreation;
                        // One monotonic readiness budget for this exact consent.
                        // UIA retries and details expansion never extend it or the
                        // original process deadline enforced by Program.Deadline.
                        readinessUntilMilliseconds = Program.Lifetime.ElapsedMilliseconds + 10000;
                    }
                    Program.Require(consent.Id == latchedConsentPid && consentCreation == latchedConsentCreation,
                        "consent_owner_changed");
                    bool clicked = OnInput((desktop, name) =>
                    {
                        // Credential UAC and UAC on Default are intentionally unsupported.
                        if (!String.Equals(name, "Winlogon", StringComparison.OrdinalIgnoreCase))
                        {
                            if (Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds) return false;
                            ReportLocationTopology(new List<AutomationElement>(), consent.Id);
                            throw new Program.GateFailure("native_program_location_unbound");
                        }
                        var owned = Windows(desktop).Where(window =>
                        {
                            uint pid;
                            Native.GetWindowThreadProcessId(window, out pid);
                            return pid == consent.Id && OrdinaryConsentWindow(window);
                        }).ToList();
                        if (owned.Count == 0)
                        {
                            if (Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds) return false;
                            ReportLocationTopology(new List<AutomationElement>(), consent.Id);
                            throw new Program.GateFailure("native_program_location_unbound");
                        }
                        Program.Require(owned.Count == 1, "ambiguous_consent_windows");
                        var root = AutomationElement.FromHandle(owned[0]);
                        var queue = new Queue<AutomationElement>();
                        queue.Enqueue(root);
                        var yes = new List<AutomationElement>();
                        var details = new List<AutomationElement>();
                        var nativeText = new List<AutomationElement>();
                        bool conflictingPath = false;
                        int count = 0;
                        var walker = TreeWalker.RawViewWalker;
                        while (queue.Count != 0)
                        {
                            Program.Require(++count <= 256, "consent_tree_oversized");
                            var element = queue.Dequeue();
                            var current = element.Current;
                            Program.Require(!current.IsPassword && current.ControlType != ControlType.Edit, "credential_prompt_rejected");
                            string label = current.Name ?? "";
                            Program.Require(label.Length <= 2048, "consent_label_oversized");
                            string trimmed = label.Trim(' ');
                            conflictingPath |= ConsentTarget.HasConflictingPath(trimmed);
                            if (current.ControlType == ControlType.Text && !current.IsOffscreen) nativeText.Add(element);
                            if ((current.ControlType == ControlType.Button || current.ControlType == ControlType.Hyperlink) &&
                                current.IsEnabled && !current.IsOffscreen && ConsentTarget.IsDetailsAction(trimmed)) details.Add(element);
                            if (current.ControlType == ControlType.Button && current.IsEnabled && !current.IsOffscreen &&
                                (trimmed == "Yes" || trimmed == "예" || trimmed == "&Yes" || trimmed == "예(&Y)")) yes.Add(element);
                            var child = walker.GetFirstChild(element);
                            while (child != null)
                            {
                                Program.Require(queue.Count < 256, "consent_tree_oversized");
                                queue.Enqueue(child);
                                child = walker.GetNextSibling(child);
                            }
                        }
                        if (conflictingPath) ReportLocationTopology(nativeText, consent.Id);
                        Program.Require(!conflictingPath, "conflicting_consent_path");
                        if (details.Count != 0)
                        {
                            Program.Require(details.Count == 1, "ambiguous_details_action");
                            Program.Require(AuthenticatedRuntimeId(details[0], consent.Id) != null, "details_provider_unbound");
                            if (!detailsExpanded && Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds)
                            {
                                object detailsPattern;
                                Program.Require(details[0].TryGetCurrentPattern(InvokePattern.Pattern, out detailsPattern), "details_not_invokable");
                                StillInput(name);
                                detailsExpanded = true;
                                ((InvokePattern)detailsPattern).Invoke(); // View action only; no approval.
                                return false; // Re-enumerate the actual expanded OS tree.
                            }
                            // The native button may remain visible while its async
                            // expansion populates the field. Never invoke it twice.
                        }
                        // No basename or arbitrary FileDescription can bind a target.
                        // Require a separate native location-label/value field pair.
                        bool boundLocation = HasNativeLocationField(nativeText, consent.Id);
                        if (!boundLocation)
                        {
                            if (Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds) return false;
                            ReportLocationTopology(nativeText, consent.Id);
                            throw new Program.GateFailure("native_program_location_unbound");
                        }
                        if (yes.Count == 0)
                        {
                            Program.Require(Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds, "native_yes_not_invokable");
                            return false;
                        }
                        Program.Require(yes.Count == 1, "ambiguous_yes_button");
                        Program.Require(AuthenticatedRuntimeId(yes[0], consent.Id) != null, "yes_provider_unbound");
                        Program.ValidateService();
                        Program.Deadline();
                        Program.Require(Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds, "deadline_elapsed");
                        StillInput(name);
                        Program.Require(!consent.HasExited, "consent_exited");
                        var fresh = ConsentProcesses();
                        try
                        {
                            Program.Require(fresh.Count == 1 && fresh[0].Id == latchedConsentPid, "consent_owner_changed");
                            string finalImage;
                            long finalCreation;
                            int finalSession;
                            Program.ObserveProcess(latchedConsentPid, out finalImage, out finalCreation, out finalSession);
                            Program.Require(finalCreation == latchedConsentCreation && finalSession == Program.Session &&
                                String.Equals(finalImage, consentImage, StringComparison.OrdinalIgnoreCase), "consent_owner_changed");
                        }
                        finally { foreach (var process in fresh) process.Dispose(); }
                        object pattern;
                        Program.Require(yes[0].TryGetCurrentPattern(InvokePattern.Pattern, out pattern), "native_yes_not_invokable");
                        Program.Deadline();
                        Program.Require(Program.Lifetime.ElapsedMilliseconds < readinessUntilMilliseconds, "deadline_elapsed");
                        StillInput(name);
                        Program.Require(OrdinaryConsentWindow(owned[0]), "ambiguous_consent_windows");
                        consentConsumed = true; // Consumed before any potentially partial invoke.
                        ((InvokePattern)pattern).Invoke();
                        return true;
                    });
                    if (clicked) return;
                }
            }
            finally { foreach (var process in candidates) process.Dispose(); }
            Thread.Sleep(150);
        }
    }

    private static bool HasNativeLocationField(List<AutomationElement> elements, int consentPid)
    {
        int bindings = 0;
        foreach (var label in elements)
        {
            string labelText = label.Current.Name ?? "";
            if (!ConsentTarget.IsLocationLabel(labelText)) continue;
            string labelId = AuthenticatedRuntimeId(label, consentPid);
            var parent = TreeWalker.RawViewWalker.GetParent(label);
            if (labelId == null || parent == null) return false;
            string parentId = AuthenticatedRuntimeId(parent, consentPid);
            if (parentId == null) return false;
            // Native provider context: distinct label and immediate next sibling
            // text field under one authenticated parent. Descriptions cannot
            // manufacture separate provider elements. WinUI virtual Text elements
            // need not have their own HWND; nonempty RuntimeIds bind those nodes.
            var sibling = TreeWalker.RawViewWalker.GetNextSibling(label);
            if (sibling == null || sibling.Current.ControlType != ControlType.Text || sibling.Current.IsOffscreen) return false;
            string valueId = AuthenticatedRuntimeId(sibling, consentPid);
            var valueParent = TreeWalker.RawViewWalker.GetParent(sibling);
            if (valueId == null || valueId == labelId || valueParent == null ||
                AuthenticatedRuntimeId(valueParent, consentPid) != parentId) return false;
            if (!ConsentTarget.IsInstalledLocation(sibling.Current.Name ?? "")) return false;
            bindings++;
        }
        return bindings == 1;
    }

    private static string AuthenticatedRuntimeId(AutomationElement element, int consentPid)
    {
        var current = element.Current;
        if (current.ProcessId != consentPid) return null;
        int[] runtime = element.GetRuntimeId();
        if (runtime == null || runtime.Length == 0 || runtime.Length > 32) return null;
        IntPtr window = new IntPtr(current.NativeWindowHandle);
        if (window != IntPtr.Zero)
        {
            uint pid;
            Native.GetWindowThreadProcessId(window, out pid);
            if (pid != consentPid) return null;
        }
        return String.Join(",", runtime.Select(value => value.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray());
    }

    private static string RuntimeHash(AutomationElement element, int consentPid)
    {
        if (element == null) return "none";
        string runtime = AuthenticatedRuntimeId(element, consentPid);
        if (runtime == null) return "unbound";
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(Encoding.ASCII.GetBytes(runtime)), 0, 8).Replace("-", "");
    }

    private static void ReportLocationTopology(List<AutomationElement> elements, int consentPid)
    {
        // One failure-only topology record per text node: no text, path, command,
        // code, pixels or pending identifier. Runtime IDs are hashed.
        var lines = new List<string>();
        lines.Add("CI consent topology summary: textNodes=" + elements.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var element in elements.Take(32))
        {
            var current = element.Current;
            string text = current.Name ?? "";
            string automation = current.AutomationId ?? "";
            // Numeric native control IDs or short alphabetic UIA identifiers only.
            // Hex-like, long and arbitrary string-valued IDs are redacted.
            if (!Regex.IsMatch(automation, "\\A(?:[0-9]{1,5}|[A-Za-z_][A-Za-z_.-]{0,39})\\z")) automation = "redacted";
            bool expected = ConsentTarget.IsInstalledLocation(text);
            bool combinedLocation = false;
            foreach (string prefix in new[] { "Program location:", "Program location", "프로그램 위치:", "프로그램 위치" })
                if (text.StartsWith(prefix, StringComparison.Ordinal) &&
                    ConsentTarget.IsInstalledLocation(text.Substring(prefix.Length).Trim())) combinedLocation = true;
            bool hasFormat = false;
            for (int i = 0; i < text.Length; i++)
                if (System.Globalization.CharUnicodeInfo.GetUnicodeCategory(text, i) ==
                    System.Globalization.UnicodeCategory.Format) hasFormat = true;
            var next = TreeWalker.RawViewWalker.GetNextSibling(element);
            string nextType = "None";
            bool nextExpectedPath = false;
            if (next != null)
            {
                var nextCurrent = next.Current;
                nextType = nextCurrent.ControlType == ControlType.Text ? "Text" :
                    nextCurrent.ControlType == ControlType.Button ? "Button" :
                    nextCurrent.ControlType == ControlType.Hyperlink ? "Hyperlink" : "Other";
                nextExpectedPath = ConsentTarget.IsInstalledLocation(nextCurrent.Name ?? "");
            }
            lines.Add("CI consent topology: type=Text id=" + automation +
                " node=" + RuntimeHash(element, consentPid) +
                " parent=" + RuntimeHash(TreeWalker.RawViewWalker.GetParent(element), consentPid) +
                " locationLabel=" + ConsentTarget.IsLocationLabel(text) +
                " locationLabelTrimmed=" + ConsentTarget.IsLocationLabel(text.Trim()) +
                " combinedLocation=" + combinedLocation +
                " hasFormat=" + hasFormat +
                " expectedPath=" + expected +
                " closedPair=" + (expected && text.IndexOf(" pair ", StringComparison.Ordinal) >= 0) +
                " conflictingPath=" + ConsentTarget.HasConflictingPath(text) +
                " nextType=" + nextType + " nextExpectedPath=" + nextExpectedPath);
        }
        lastTopologyLines = lines.ToArray();
        // Stdio is supplementary; the failure envelope carries this snapshot
        // over the existing private pipe even when PsExec does not relay stderr.
        foreach (string line in lines) Console.Error.WriteLine(line);
    }

    // Return zero only while the invitation has not become the active desktop.
    private static IntPtr Renderer(IntPtr desktop, string name, bool allowPending)
    {
        if (!name.StartsWith("UacRemote.Pairing.", StringComparison.Ordinal))
        {
            Program.Require(allowPending && Program.PrivateDesktop == null, "private_desktop_changed");
            return IntPtr.Zero;
        }
        Program.Require(Program.PrivateDesktop == null || Program.PrivateDesktop == name, "pairing_desktop_changed");
        var windows = Windows(desktop).Where(window => WindowClass(window) == RendererClass).ToList();
        if (windows.Count == 0 && allowPending && Program.RendererPid == 0) return IntPtr.Zero;
        Program.Require(windows.Count == 1, "ambiguous_renderer");
        uint pid;
        Native.GetWindowThreadProcessId(windows[0], out pid);
        string rendererImage;
        long start;
        int session;
        Program.ObserveProcess((int)pid, out rendererImage, out start, out session);
        Program.Require(session == Program.Session && String.Equals(rendererImage,
            Program.Service, StringComparison.OrdinalIgnoreCase), "renderer_process_rejected");
        Program.Require(start >= Program.ArmedUtc.Ticks, "stale_renderer");
        Program.Require(Program.RendererPid == 0 || (Program.RendererPid == pid && Program.RendererStart == start), "renderer_changed");
        Program.RendererPid = (int)pid;
        Program.RendererStart = start;
        Program.PrivateDesktop = name;
        Program.ValidateService();
        StillInput(name);
        return windows[0];
    }

    private static Bitmap Capture(IntPtr window, string name)
    {
        Native.Rect rect;
        Program.Require(Native.GetClientRect(window, out rect), "renderer_size_unavailable");
        int width = rect.Right - rect.Left, height = rect.Bottom - rect.Top;
        Program.Require(width >= 640 && height >= 480 && width <= 3840 && height <= 2160, "renderer_size_rejected");
        var origin = new Native.Point();
        Program.Require(Native.ClientToScreen(window, ref origin), "renderer_origin_unavailable");
        StillInput(name);
        var bitmap = new Bitmap(width, height, PixelFormat.Format32bppRgb);
        try
        {
            // Screen DC, not PrintWindow / WM_PRINT / renderer state. These are the
            // actual current input-desktop pixels visible inside the native HWND.
            IntPtr screen = Native.GetDC(IntPtr.Zero);
            Program.Require(screen != IntPtr.Zero, "screen_dc_unavailable");
            try
            {
                using (var graphics = Graphics.FromImage(bitmap))
                {
                    IntPtr target = graphics.GetHdc();
                    try { Program.Require(Native.BitBlt(target, 0, 0, width, height, screen, origin.X, origin.Y, 0x00CC0020), "screen_capture_failed"); }
                    finally { graphics.ReleaseHdc(target); }
                }
            }
            finally { Native.ReleaseDC(IntPtr.Zero, screen); }
            StillInput(name);
            return bitmap;
        }
        catch { bitmap.Dispose(); throw; }
    }

    internal static string CaptureQr()
    {
        while (true)
        {
            Program.Deadline();
            string png = OnInput((desktop, name) =>
            {
                IntPtr window = Renderer(desktop, name, true);
                if (window == IntPtr.Zero) return null;
                Program.Require(Native.GetDlgItem(window, 1001) == IntPtr.Zero, "invitation_already_changed");
                using (var pixels = Capture(window, name))
                using (var memory = new MemoryStream())
                {
                    pixels.Save(memory, ImageFormat.Png);
                    Program.Require(memory.Length <= 6 * 1024 * 1024, "png_oversized");
                    return Convert.ToBase64String(memory.GetBuffer(), 0, (int)memory.Length);
                }
            });
            if (png != null) return png;
            Thread.Sleep(150);
        }
    }

    private static IntPtr ConfirmButton(IntPtr window)
    {
        IntPtr button = Native.GetDlgItem(window, 1001);
        if (button == IntPtr.Zero) return IntPtr.Zero;
        uint pid;
        Native.GetWindowThreadProcessId(button, out pid);
        Program.Require(pid == Program.RendererPid && Native.GetParent(button) == window &&
            String.Equals(WindowClass(button), "Button", StringComparison.OrdinalIgnoreCase), "confirm_control_rejected");
        return Native.IsWindowVisible(button) && Native.IsWindowEnabled(button) ? button : IntPtr.Zero;
    }

    internal static string ReadComparison()
    {
        while (true)
        {
            Program.Deadline();
            string code = OnInput((desktop, name) =>
            {
                IntPtr window = Renderer(desktop, name, false);
                if (ConfirmButton(window) == IntPtr.Zero) return null;
                using (var pixels = Capture(window, name))
                    return DigitPixels.Read(pixels, (int)Math.Max(96, Native.GetDpiForWindow(window)));
            });
            if (code != null) return code;
            Thread.Sleep(150);
        }
    }

    internal static void ConfirmComparison(string expected)
    {
        OnInput((desktop, name) =>
        {
            IntPtr window = Renderer(desktop, name, false);
            IntPtr button = ConfirmButton(window);
            Program.Require(button != IntPtr.Zero, "confirm_control_unavailable");
            using (var pixels = Capture(window, name))
                Program.Require(DigitPixels.Read(pixels, (int)Math.Max(96, Native.GetDpiForWindow(window))) == expected, "comparison_mismatch");
            StillInput(name);
            Program.Require(ConfirmButton(window) == button, "confirm_control_changed");
            IntPtr result;
            // BM_CLICK goes to the actual fixed visible BUTTON, whose normal
            // BN_CLICKED path is the sole product-side comparison decision.
            Program.Require(Native.SendMessageTimeout(button, 0x00F5, IntPtr.Zero, IntPtr.Zero, 0x0002, 2000, out result) != IntPtr.Zero,
                "confirm_click_failed");
            return true;
        });
    }
}
