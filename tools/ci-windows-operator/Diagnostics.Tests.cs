// SPDX-License-Identifier: GPL-2.0-or-later
// Pure diagnostic shape tests only; never invokes native pairing or file writes.
using System;
using System.Collections.Generic;
using System.IO;

internal static class DiagnosticsTests
{
    private static int Main()
    {
        var valid = new Dictionary<string, object> {
            { "status", "failed" }, { "source", "operator" },
            { "stage", "initial_consent" }, { "gate", "native_program_location_unbound" }
        };
        object projected;
        if (!Diagnostics.TryValidate(valid, "operator", out projected)) return 1;
        foreach (string key in new[] { "status", "source", "stage", "gate" })
        {
            var invalid = new Dictionary<string, object>(valid);
            invalid[key] = "unrecognized_ascii_token";
            if (Diagnostics.TryValidate(invalid, "operator", out projected)) return 2;
        }
        var extra = new Dictionary<string, object>(valid);
        extra.Add("qr", "synthetic");
        if (Diagnostics.TryValidate(extra, "operator", out projected)) return 3;
        var output = new StringWriter();
        Diagnostics.TryWrite(output, "operator", "initial_consent", new Program.GateFailure("native_program_location_unbound"));
        if (output.ToString().Contains("\r") || !output.ToString().EndsWith("\n", StringComparison.Ordinal)) return 4;
        output = new StringWriter();
        Diagnostics.TryWrite(output, "bridge", "relay", new InvalidOperationException("synthetic private details"));
        if (output.ToString().Contains("synthetic") || !output.ToString().Contains("unexpected_failure")) return 5;
        output = new StringWriter();
        Diagnostics.TryWrite(output, "operator", "initial_consent", new Program.GateFailure("private/path"));
        if (output.ToString().Contains("private/path") || !output.ToString().Contains("unexpected_failure")) return 6;
        Console.WriteLine("Pure closed-diagnostic fixtures passed; native behavior remains unverified.");
        return 0;
    }
}
