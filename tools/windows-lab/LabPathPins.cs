// SPDX-License-Identifier: GPL-2.0-or-later
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

// MEDIUM parent only: retain until the elevated installer exits; never load there.
// No file contents, writes, privilege changes, path arguments or exposed handles.
public sealed class LabPathPins : IDisposable
{
    const string Source = @"C:\Users\32170336\AppData\Local\Temp\uac-controller-build-165ac850\debug";
    const int PathLimit = 1024;
    List<SafeFileHandle> handles = new List<SafeFileHandle>();
    readonly Dictionary<string, SafeFileHandle> paths = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
    LabPathPins() { }
    public static LabPathPins Open()
    {
        var pins = new LabPathPins();
        try
        {
            if (IntPtr.Size != 8 || Environment.OSVersion.Platform != PlatformID.Win32NT) throw Rejected();
            using (var identity = WindowsIdentity.GetCurrent())
                if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) throw Rejected();
            pins.Chain(ProgramFiles(), true);
            pins.Chain(Source, false);
            pins.Pin(Source + @"\uac-service.exe", false, false, false);
            pins.Pin(Source + @"\uac-prompt-probe.exe", false, false, false);
            return pins;
        }
        catch { pins.Dispose(); throw Rejected(); }
    }
    void Chain(string path, bool destination)
    {
        path = Canonical(path);
        string cursor = path.Substring(0, 3);
        Pin(cursor, true, true, destination && path.Length == 3);
        if (path.Length == 3) return;
        string[] parts = path.Substring(3).Split('\\');
        if (parts.Length > 32) throw Rejected();
        foreach (string part in parts)
        {
            cursor = Path.Combine(cursor, part);
            Pin(cursor, true, destination, destination && String.Equals(cursor, path, StringComparison.OrdinalIgnoreCase));
        }
    }
    void Pin(string path, bool directory, bool trusted, bool strictParent)
    {
        path = Canonical(path);
        SafeFileHandle existing;
        if (paths.TryGetValue(path, out existing)) { if (trusted) CheckAcl(existing, strictParent); return; }
        if (handles.Count >= 64 || GetDriveTypeW(path.Substring(0, 3)) != 3) throw Rejected();
        // Bit1 is FILE_LIST_DIRECTORY for directories and FILE_READ_DATA for leaves.
        var handle = CreateFileW(path, 0x00020081, trusted ? 3u : 1u, IntPtr.Zero, 3,
            0x00200000u | (directory ? 0x02000000u : 0u), IntPtr.Zero);
        try
        {
            Info info;
            if (handle.IsInvalid || GetFileType(handle) != 1 || !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory) throw Rejected();
            var name = new StringBuilder(PathLimit);
            uint length = GetFinalPathNameByHandleW(handle, name, PathLimit, 0);
            if (length == 0 || length >= PathLimit || !name.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)) throw Rejected();
            if (!String.Equals(Canonical(name.ToString().Substring(4)), path, StringComparison.OrdinalIgnoreCase)) throw Rejected();
            if (trusted) CheckAcl(handle, strictParent);
            handles.Add(handle); paths.Add(path, handle); handle = null;
        }
        finally { if (handle != null) handle.Dispose(); }
    }
    static void CheckAcl(SafeFileHandle handle, bool strictParent)
    {
        IntPtr owner, group, dacl, sacl, descriptor = IntPtr.Zero;
        try
        {
            if (GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor) != 0 || descriptor == IntPtr.Zero) throw Rejected();
            uint size = GetSecurityDescriptorLength(descriptor);
            if (size < 20 || size > 65536 || owner == IntPtr.Zero || dacl == IntPtr.Zero) throw Rejected();
            var bytes = new byte[(int)size]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var security = new RawSecurityDescriptor(bytes, 0);
            if (!Trusted(security.Owner) || security.DiscretionaryAcl == null || security.DiscretionaryAcl.Count > 256) throw Rejected();
            uint forbidden = strictParent ? 0x500d0156u : 0x500d0152u;
            foreach (GenericAce item in security.DiscretionaryAcl)
            {
                if ((item.AceFlags & AceFlags.InheritOnly) != 0) continue;
                if (((int)item.AceFlags & ~0x1f) != 0) throw Rejected();
                var ace = item as CommonAce;
                if (ace == null || ace.IsCallback || (ace.AceQualifier != AceQualifier.AccessAllowed && ace.AceQualifier != AceQualifier.AccessDenied)) throw Rejected();
                uint mask = unchecked((uint)ace.AccessMask);
                if ((mask & ~0xf01f01ffu) != 0) throw Rejected();
                // Denies never justify a risky allow; unknown/group identities are lower trust.
                if (ace.AceQualifier == AceQualifier.AccessAllowed && !Trusted(ace.SecurityIdentifier) && (mask & forbidden) != 0) throw Rejected();
            }
        }
        finally { if (descriptor != IntPtr.Zero && LocalFree(descriptor) != IntPtr.Zero) throw Rejected(); }
    }
    static bool Trusted(SecurityIdentifier sid)
    {
        return sid != null && (sid.Value == "S-1-5-18" || sid.Value == "S-1-5-32-544" ||
            sid.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    }
    static string Canonical(string path)
    {
        if (String.IsNullOrEmpty(path) || path.Length >= PathLimit || path.Length < 3 || !Char.IsLetter(path[0]) || path[1] != ':' || path[2] != '\\') throw Rejected();
        if (path.IndexOfAny(new[] { '/', '"', '<', '>', '|', '?', '*', '\0' }) >= 0 || path.IndexOf(':', 2) >= 0) throw Rejected();
        if (path.Length > 3) foreach (string part in path.Substring(3).Split('\\'))
            if (part.Length == 0 || part == "." || part == ".." || part.EndsWith(".") || part.EndsWith(" ")) throw Rejected();
        if (!String.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase)) throw Rejected();
        return path;
    }
    static string ProgramFiles()
    {
        Guid id = new Guid("905e63b6-c1bf-494e-b29c-65b732d3d21a"); IntPtr text = IntPtr.Zero;
        try
        {
            if (SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out text) < 0 || text == IntPtr.Zero) throw Rejected();
            var path = new StringBuilder(); // API owns a NUL-terminated UTF16 allocation.
            for (int i = 0; i < PathLimit; i++) { char c = (char)Marshal.ReadInt16(text, i * 2); if (c == '\0') return Canonical(path.ToString()); path.Append(c); }
            throw Rejected();
        }
        finally { if (text != IntPtr.Zero) Marshal.FreeCoTaskMem(text); }
    }
    public void Dispose() { var held = Interlocked.Exchange(ref handles, null); if (held != null) for (int i = held.Count - 1; i >= 0; i--) held[i].Dispose(); }
    public override string ToString() { return "LabPathPins(path_metadata_only)"; }
    static Exception Rejected() { return new InvalidOperationException("Lab path pinning rejected."); }
    [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)] static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint count, uint flags);
    [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle file);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint GetDriveTypeW(string root);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle file, uint type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("shell32.dll", ExactSpelling = true)] static extern int SHGetKnownFolderPath(ref Guid folder, uint flags, IntPtr token, out IntPtr path);
}
