// SPDX-License-Identifier: GPL-2.0-or-later
// One closed vocabulary, embedded at build time and shared with the CI reader.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static class Diagnostics
{
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 32768 };
    private static readonly Dictionary<string, HashSet<string>> Vocabulary = Load();
    private static readonly Regex TopologyHeader = new Regex(@"\ACI consent topology summary: textNodes=(0|[1-9][0-9]{0,2})\z", RegexOptions.CultureInvariant);
    private static readonly Regex TopologyRow = new Regex(
        @"\ACI consent topology: type=Text id=(?:[0-9]{1,5}|[A-Za-z_][A-Za-z_.-]{0,39})" +
        @" node=(?:none|unbound|[0-9A-F]{16}) parent=(?:none|unbound|[0-9A-F]{16})" +
        @" locationLabel=(?:True|False) locationLabelTrimmed=(?:True|False) combinedLocation=(?:True|False) hasFormat=(?:True|False)" +
        @" expectedPath=(?:True|False) closedPair=(?:True|False) conflictingPath=(?:True|False)" +
        @" nextType=(?:None|Text|Button|Hyperlink|Other) nextExpectedPath=(?:True|False)\z", RegexOptions.CultureInvariant);

    private static Dictionary<string, HashSet<string>> Load()
    {
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("CiDiagnosticVocabulary.json"))
        {
            if (stream == null || stream.Length > 32768) throw new InvalidOperationException();
            using (var reader = new StreamReader(stream))
            {
                var raw = Json.DeserializeObject(reader.ReadToEnd()) as Dictionary<string, object>;
                if (raw == null || raw.Count != 4) throw new InvalidOperationException();
                var result = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
                foreach (string name in new[] { "operatorStages", "bridgeStages", "gates", "phoneReasons" })
                {
                    object values;
                    if (!raw.TryGetValue(name, out values) || !(values is IEnumerable)) throw new InvalidOperationException();
                    var accepted = new HashSet<string>(StringComparer.Ordinal);
                    foreach (object value in (IEnumerable)values)
                    {
                        var token = value as string;
                        if (String.IsNullOrEmpty(token) || token.Length > 64 || !accepted.Add(token)) throw new InvalidOperationException();
                    }
                    result.Add(name, accepted);
                }
                return result;
            }
        }
    }

    internal static object Failure(string source, string stage, string gate)
    {
        string stages = source == "operator" ? "operatorStages" : source == "bridge" ? "bridgeStages" : null;
        if (stages == null || !Vocabulary[stages].Contains(stage) || !Vocabulary["gates"].Contains(gate))
            throw new InvalidOperationException();
        return new { status = "failed", source = source, stage = stage, gate = gate };
    }

    internal static bool TryValidate(Dictionary<string, object> value, string requiredSource, out object record)
    {
        record = null;
        if (value == null || (value.Count != 4 && value.Count != 5)) return false;
        object status, source, stage, gate;
        if (!value.TryGetValue("status", out status) || !value.TryGetValue("source", out source) ||
            !value.TryGetValue("stage", out stage) || !value.TryGetValue("gate", out gate) ||
            !(status is string) || (string)status != "failed" || !(source is string) || (string)source != requiredSource ||
            !(stage is string) || !(gate is string)) return false;
        try
        {
            object failure = Failure((string)source, (string)stage, (string)gate);
            if (value.Count == 4) { record = failure; return true; }
            object supplied;
            string[] topology;
            if ((string)source != "operator" || (string)stage != "initial_consent" ||
                !value.TryGetValue("topologyLines", out supplied) || !TryValidateTopology(supplied, out topology)) return false;
            record = FailureWithTopology((string)source, (string)stage, (string)gate, topology);
            return true;
        }
        catch { return false; }
    }

    private static object FailureWithTopology(string source, string stage, string gate, string[] topology)
    {
        return new { status = "failed", source = source, stage = stage, gate = gate, topologyLines = topology };
    }

    private static bool TryValidateTopology(object supplied, out string[] topology)
    {
        topology = null;
        // JSON arrays arrive as object[]. Requiring an array also rejects strings,
        // dictionaries and arbitrary enumerable objects at this untrusted seam.
        var input = supplied as object[];
        if (input == null || input.Length < 1 || input.Length > 33) return false;
        var canonical = new string[input.Length];
        int total = 0;
        for (int i = 0; i < input.Length; i++)
        {
            string line = input[i] as string;
            if (line == null || line.Length > 512 || (total += line.Length) > 16384) return false;
            if (i == 0)
            {
                var match = TopologyHeader.Match(line);
                int count;
                if (!match.Success || !Int32.TryParse(match.Groups[1].Value,
                    System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out count) ||
                    count > 256 || input.Length != 1 + Math.Min(count, 32)) return false;
            }
            else if (!TopologyRow.IsMatch(line)) return false;
            canonical[i] = line;
        }
        topology = canonical;
        return true;
    }

    internal static void TryWrite(TextWriter writer, string source, string stage, Exception error)
    {
        // Only closed classifications cross this seam. Exception text is unused.
        try
        {
            var failure = error as Program.GateFailure;
            string gate = failure != null && Vocabulary["gates"].Contains(failure.Code) ? failure.Code : "unexpected_failure";
            object record = Failure(source, stage, gate);
            string[] topology;
            if (source == "operator" && stage == "initial_consent" &&
                TryValidateTopology(ProtectedUi.LastTopologyLines, out topology))
                record = FailureWithTopology(source, stage, gate, topology);
            writer.Write(Json.Serialize(record));
            writer.Write('\n');
            writer.Flush();
        }
        catch { /* Original terminal failure remains authoritative. */ }
    }

    internal static void TryWriteStartup(string stage, Exception error)
    {
        // Fixed diagnostic-only file: fresh CI root, SY/BA at creation, no inputs.
        try
        {
            using (var identity = WindowsIdentity.GetCurrent())
                if (!identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid)) return;
            if (!String.Equals(Assembly.GetExecutingAssembly().Location,
                Program.Lab + @"\uac-ci-windows-operator.exe", StringComparison.OrdinalIgnoreCase)) return;
            Program.CheckProtected(Program.Lab, true, true);
            var text = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            TryWrite(text, "operator", stage, error);
            byte[] bytes = new UTF8Encoding(false).GetBytes(text.ToString());
            if (bytes.Length == 0 || bytes.Length > 512) return;
            var security = new FileSecurity();
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.SetOwner(system); security.SetGroup(admin); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(admin, FileSystemRights.FullControl, AccessControlType.Allow));
            using (var stream = new FileStream(Program.Lab + @"\operator-startup-failure.json", FileMode.CreateNew,
                FileSystemRights.Write, FileShare.None, 512, FileOptions.None, security))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
        }
        catch { /* Diagnostics cannot replace the original error or authorize work. */ }
    }
}
