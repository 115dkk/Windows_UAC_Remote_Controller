// SPDX-License-Identifier: GPL-2.0-or-later
// Pure recognizer fixtures only: not Windows/native/UAC pass evidence.
using System;

internal static class ConsentTargetTests
{
    private static int Main()
    {
        string image = ConsentTarget.InstalledImage;
        string nonce = new String('a', 64);
        string[] accepted = { image, "\"" + image + "\"", image + " pair " + nonce, "\"" + image + "\" pair " + nonce };
        string[] rejected = {
            "uac-service.exe", @"C:\Users\runner\uac-service.exe", @"C:\Temp\uac-service.exe",
            "Program location: " + image, image + ".evil.exe", image + ":stream", image + "\\child",
            image + " approve " + nonce, image + " pair " + nonce + " extra", image + " pair " + new String('A', 64),
            image + " pair " + new String('a', 63), image + " pair " + nonce + "\r\n", image + "\u202e",
            "\"" + image, image + "\"", @"\\?\" + image, image.Replace(@"\휴대폰 승인\", @"\휴대폰 승인\..\휴대폰 승인\"),
            image + "\tpair " + nonce, image + " pair  " + nonce, image + " --pair " + nonce
        };
        foreach (string value in accepted) if (!ConsentTarget.IsInstalledLocation(value)) return 1;
        foreach (string value in rejected) if (ConsentTarget.IsInstalledLocation(value)) return 2;
        if (!ConsentTarget.HasConflictingPath(@"C:\Users\runner\uac-service.exe") ||
            !ConsentTarget.HasConflictingPath("Program location: " + image) ||
            !ConsentTarget.HasConflictingPath("different.exe") ||
            ConsentTarget.IsLocationLabel("Program location: " + image) ||
            ConsentTarget.IsLocationLabel("uac-service.exe")) return 3;
        if (ConsentTarget.IsAuxiliaryWindow(false, 0) || ConsentTarget.IsAuxiliaryWindow(false, 0x8) ||
            !ConsentTarget.IsAuxiliaryWindow(true, 0) || !ConsentTarget.IsAuxiliaryWindow(false, 0x80) ||
            !ConsentTarget.IsAuxiliaryWindow(false, 0x08000000) || !ConsentTarget.IsAuxiliaryWindow(false, 0x08000080)) return 4;
        foreach (string label in new[] { "Publisher:", "Publisher: Unknown", "File origin: Hard drive on this computer", "Program location:", "Verified publisher:" })
            if (ConsentTarget.HasConflictingPath(label)) return 5;
        foreach (string path in new[] { @"C:\other\program.exe", "C:other", "Program location: C:other", @"\\host\other\program.exe" })
            if (!ConsentTarget.HasConflictingPath(path)) return 6;
        Console.WriteLine("Pure consent target recognizer fixtures passed; native UI remains unverified.");
        return 0;
    }
}
