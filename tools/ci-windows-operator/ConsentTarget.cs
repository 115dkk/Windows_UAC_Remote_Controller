// SPDX-License-Identifier: GPL-2.0-or-later
// Pure fail-closed recognizer. No executable path comes from the caller.
using System;
using System.Text.RegularExpressions;

internal static class ConsentTarget
{
    internal const string InstalledImage = @"C:\Program Files\휴대폰 승인\uac-service.exe";

    // Same ordinary-window qualification as the product's native prompt probe.
    // This only filters candidates; it never qualifies the executable or Yes.
    internal static bool IsAuxiliaryWindow(bool hasOwner, uint extendedStyle)
    {
        return hasOwner || (extendedStyle & (0x00000080u | 0x08000000u)) != 0;
    }

    internal static bool IsLocationLabel(string text)
    {
        return text == "Program location:" || text == "Program location" ||
            text == "프로그램 위치:" || text == "프로그램 위치";
    }

    internal static bool IsDetailsAction(string text)
    {
        return text == "Show more details" || text == "Show &more details" ||
            text == "자세한 내용 표시" || text == "자세한 내용 표시(&M)";
    }

    internal static bool IsExpandedLocation(string automationId, string text)
    {
        // Observed native consent detail field, not a FileDescription/name match.
        // Caller must additionally authenticate its native provider/ancestry.
        if (automationId != "ExpandedTextLine" || String.IsNullOrEmpty(text) || text.Length > 2048) return false;
        foreach (string prefix in new[] { "Program location:", "프로그램 위치:" })
            if (text.StartsWith(prefix, StringComparison.Ordinal) &&
                IsInstalledLocation(text.Substring(prefix.Length).Trim(' ', '\r', '\n'))) return true;
        return false;
    }

    internal static bool IsInstalledLocation(string text)
    {
        if (String.IsNullOrEmpty(text) || text.Length > 2048) return false;
        // Reject hidden formatting, line breaks, alternate whitespace and aliases.
        foreach (char c in text)
            if (Char.IsControl(c) || Char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format) return false;
        string value = text.Trim(' ');
        string prefix = value.StartsWith("\"", StringComparison.Ordinal) ? "\"" + InstalledImage + "\"" : InstalledImage;
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        string suffix = value.Substring(prefix.Length);
        return suffix.Length == 0 || Regex.IsMatch(suffix, "\\A pair [0-9a-f]{64}\\z");
    }

    internal static bool HasConflictingPath(string text)
    {
        if (String.IsNullOrEmpty(text) || IsInstalledLocation(text)) return false;
        // The ordinary title basename is permitted as nonbinding display text.
        // It can never satisfy the separate Program location field requirement.
        if (String.Equals(text.Trim(' '), "uac-service.exe", StringComparison.OrdinalIgnoreCase)) return false;
        // A label such as "Publisher:" is not a drive path: the final r:
        // is inside a word. Drive letters begin a separate token. The exact
        // native program-location binding remains mandatory independently.
        return Regex.IsMatch(text, @"(?<![\p{L}\p{N}_])[A-Za-z]:|\\|\.exe\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
