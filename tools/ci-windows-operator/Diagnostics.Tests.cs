// SPDX-License-Identifier: GPL-2.0-or-later
// Pure diagnostic shape tests only; never invokes native pairing or file writes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;

internal static class DiagnosticsTests
{
    private const string Header = "CI consent topology summary: textNodes=";
    private const string Row = "CI consent topology: type=Text id=42 node=0123456789ABCDEF parent=unbound" +
        " locationLabel=False locationLabelTrimmed=True combinedLocation=False hasFormat=False" +
        " expectedPath=False closedPair=False conflictingPath=False nextType=Text nextExpectedPath=True";

    private static bool AcceptsTopology(Dictionary<string, object> failure, object lines)
    {
        var candidate = new Dictionary<string, object>(failure);
        candidate.Add("topologyLines", lines);
        object projected;
        return Diagnostics.TryValidate(candidate, (string)candidate["source"], out projected);
    }

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
        if (!AcceptsTopology(valid, new string[] { Header + "0" }) ||
            !AcceptsTopology(valid, new object[] { Header + "1", Row })) return 7;
        foreach (string id in new[] { "0", "99999", "redacted", "Program.Location_Label", "_", new String('A', 40) })
            if (!AcceptsTopology(valid, new[] { Header + "1", Row.Replace("id=42", "id=" + id) })) return 8;
        foreach (string hash in new[] { "none", "unbound", "FEDCBA9876543210" })
            if (!AcceptsTopology(valid, new[] { Header + "1", Row.Replace("0123456789ABCDEF", hash) })) return 9;
        foreach (string nextType in new[] { "None", "Text", "Button", "Hyperlink", "Other" })
            if (!AcceptsTopology(valid, new[] { Header + "1", Row.Replace("nextType=Text", "nextType=" + nextType) })) return 10;
        var capped = new string[33];
        capped[0] = Header + "256";
        for (int i = 1; i < capped.Length; i++) capped[i] = Row;
        if (!AcceptsTopology(valid, capped)) return 11;
        capped[0] = Header + "32";
        if (!AcceptsTopology(valid, capped)) return 12;
        foreach (object lines in new object[] {
            null, "not-an-array", new object[0], new int[] { 1 },
            new object[] { Header + "1", null }, new object[] { Header + "1", 42 },
            new[] { Header + "0", Row }, new[] { Header + "1" }, new[] { Header + "2", Row },
            new[] { Header + "257" }, new[] { Header + "-1" }, new[] { Header + "01", Row },
            new[] { Header + "1\n", Row }, new[] { Header + "1", Header + "1" },
            new[] { Header + "1", new String('A', 513) }, new string[34]
        })
            if (AcceptsTopology(valid, lines)) return 13;
        foreach (string row in new[] {
            Row + "\n", Row + "\r", Row + " extra=False", " " + Row,
            Row.Replace("type=Text", "type=Edit"), Row.Replace("id=42", "id="),
            Row.Replace("id=42", "id=100000"), Row.Replace("id=42", "id=A1"),
            Row.Replace("id=42", "id=" + new String('A', 41)),
            Row.Replace("id=42", "id=private/path"), Row.Replace("id=42", "id=프로그램"),
            Row.Replace("0123456789ABCDEF", "0123456789abcdef"),
            Row.Replace("0123456789ABCDEF", "0123456789ABCDE"),
            Row.Replace("parent=unbound", "parent=unknown"),
            Row.Replace("locationLabel=False", "locationLabel=false"),
            Row.Replace("locationLabelTrimmed=True", "locationLabelTrimmed=1"),
            Row.Replace(" combinedLocation=False", ""), Row.Replace("hasFormat=False", "hasFormat=null"),
            Row.Replace("nextType=Text", "nextType=Edit"),
            Row.Replace("nextExpectedPath=True", "nextExpectedPath=True\u200B")
        })
            if (AcceptsTopology(valid, new[] { Header + "1", row })) return 14;
        var wrongScope = new Dictionary<string, object>(valid);
        wrongScope["stage"] = "qr_capture";
        if (AcceptsTopology(wrongScope, new[] { Header + "0" })) return 15;
        wrongScope["source"] = "bridge";
        wrongScope["stage"] = "relay";
        if (AcceptsTopology(wrongScope, new[] { Header + "0" })) return 16;
        var withTopology = new Dictionary<string, object>(valid);
        var supplied = new[] { Header + "1", Row };
        withTopology.Add("topologyLines", supplied);
        if (!Diagnostics.TryValidate(withTopology, "operator", out projected)) return 17;
        var json = new JavaScriptSerializer();
        string canonical = json.Serialize(projected);
        supplied[1] = "synthetic private details";
        if (json.Serialize(projected) != canonical) return 18;
        var roundTrip = json.DeserializeObject(canonical) as Dictionary<string, object>;
        if (!Diagnostics.TryValidate(roundTrip, "operator", out projected) || json.Serialize(projected) != canonical) return 19;
        withTopology["topologyLines"] = new[] { Header + "0" };
        withTopology.Add("qr", "synthetic");
        if (Diagnostics.TryValidate(withTopology, "operator", out projected)) return 20;
        Console.WriteLine("Pure closed-diagnostic fixtures passed; native behavior remains unverified.");
        return 0;
    }
}
