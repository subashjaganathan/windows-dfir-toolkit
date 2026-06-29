using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using System.Xml;
using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses raw/evtx/*.evtx exports into the event_logs table and emits
/// timeline rows for high-signal events. Filtering is per-channel and
/// in-code (XPath has a 32-expression cap that our ID lists exceed).
/// </summary>
public class EvtxParser : IRawArtifactParser
{
    public string Name => "evtx";

    private const int MaxEventsPerChannel = 100_000;   // runaway-log backstop

    // Curated forensic event IDs per channel. null = take every event
    // (only used for channels that are high-signal end to end).
    private static readonly Dictionary<string, HashSet<int>?> ChannelMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Security"] = [1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702,
                        4719, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4735, 4738, 4740,
                        4756, 4767, 4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799],
        ["System"] = [104, 1074, 6005, 6006, 7034, 7045],
        ["Application"] = [1000, 1001, 1002],   // app crash/hang/WER — exploitation evidence
        ["Microsoft-Windows-PowerShell/Operational"] = [4103, 4104],
        ["Microsoft-Windows-Windows Defender/Operational"] = [1006, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012],
        ["Microsoft-Windows-Sysmon/Operational"] = [1, 3, 6, 7, 8, 10, 11, 12, 13, 22, 25],
        ["Microsoft-Windows-TaskScheduler/Operational"] = [106, 140, 141, 200, 201],
        ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"] = [21, 22, 24, 25],
        ["Microsoft-Windows-WMI-Activity/Operational"] = [5857, 5859, 5860, 5861],
        ["Microsoft-Windows-Bits-Client/Operational"] = [3, 59, 60],
        ["Microsoft-Windows-WinRM/Operational"] = [91, 168],
    };

    // Events that earn a timeline row (kept tight — event_logs holds the rest).
    private static readonly Dictionary<(string Channel, int Id), (string Category, string Label)> TimelineIds = new()
    {
        [("Security", 1102)] = ("DefenseEvasion", "Audit log cleared"),
        [("Security", 4624)] = ("Authentication", "Logon"),
        [("Security", 4625)] = ("Authentication", "Failed logon"),
        [("Security", 4648)] = ("Authentication", "Explicit-credential logon"),
        [("Security", 4697)] = ("Persistence", "Service installed (security)"),
        [("Security", 4698)] = ("Persistence", "Scheduled task created"),
        [("Security", 4699)] = ("Persistence", "Scheduled task deleted"),
        [("Security", 4702)] = ("Persistence", "Scheduled task updated"),
        [("Security", 4720)] = ("AccountManagement", "User account created"),
        [("Security", 4726)] = ("AccountManagement", "User account deleted"),
        [("Security", 4728)] = ("AccountManagement", "Added to security-enabled global group"),
        [("Security", 4732)] = ("AccountManagement", "Added to security-enabled local group"),
        [("Security", 4740)] = ("AccountManagement", "Account locked out"),
        [("System", 104)] = ("DefenseEvasion", "Event log cleared"),
        [("System", 7045)] = ("Persistence", "Service installed"),
        [("Microsoft-Windows-Windows Defender/Operational", 1116)] = ("Malware", "Defender detection"),
        [("Microsoft-Windows-Windows Defender/Operational", 1117)] = ("Malware", "Defender action taken"),
        [("Microsoft-Windows-Windows Defender/Operational", 5001)] = ("DefenseEvasion", "Defender real-time protection disabled"),
        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 21)] = ("LateralMovement", "RDP session logon"),
        [("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 25)] = ("LateralMovement", "RDP session reconnect"),
        [("Microsoft-Windows-TaskScheduler/Operational", 106)] = ("Persistence", "Scheduled task registered"),
    };

    // Fields promoted into the summary line, when present, per event id.
    private static readonly Dictionary<int, string[]> SummaryFields = new()
    {
        [4624] = ["TargetUserName", "LogonType", "IpAddress"],
        [4625] = ["TargetUserName", "LogonType", "IpAddress", "Status"],
        [4648] = ["SubjectUserName", "TargetUserName", "TargetServerName"],
        [4688] = ["NewProcessName", "CommandLine"],
        [4697] = ["ServiceName", "ServiceFileName"],
        [4698] = ["TaskName"],
        [4699] = ["TaskName"],
        [4702] = ["TaskName"],
        [4720] = ["TargetUserName", "SubjectUserName"],
        [4726] = ["TargetUserName", "SubjectUserName"],
        [4728] = ["MemberName", "TargetUserName"],
        [4732] = ["MemberName", "TargetUserName"],
        [4740] = ["TargetUserName"],
        [4768] = ["TargetUserName", "IpAddress"],
        [4769] = ["TargetUserName", "ServiceName", "TicketEncryptionType"],
        [4771] = ["TargetUserName", "IpAddress"],
        [4776] = ["TargetUserName", "Workstation"],
        [7045] = ["ServiceName", "ImagePath", "AccountName"],
        [4104] = ["ScriptBlockText"],
        [1116] = ["Threat Name", "Path"],
        [1117] = ["Threat Name", "Action Name"],
        [1] = ["Image", "CommandLine", "ParentImage"],          // sysmon
        [3] = ["Image", "DestinationIp", "DestinationPort"],
        [11] = ["Image", "TargetFilename"],
        [13] = ["Image", "TargetObject"],
        [22] = ["Image", "QueryName"],
        [21] = ["User", "Address"],                              // RDP LSM
        [25] = ["User", "Address"],
        [106] = ["TaskName", "UserContext"],
    };

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var evtxDir = Path.Combine(sessionDir, "raw", "evtx");
        if (!Directory.Exists(evtxDir)) return 0;

        var total = 0;
        foreach (var file in Directory.EnumerateFiles(evtxDir, "*.evtx").OrderBy(f => f))
        {
            // collector stores channel path separators as %4 (wevtutil convention)
            var channel = Path.GetFileNameWithoutExtension(file).Replace("%4", "/");
            // Archived logs come through as Archive-<Channel>-<timestamp>.evtx —
            // map them back to their base channel name for ID-curated parsing.
            var lookup = channel;
            if (lookup.StartsWith("Archive-", StringComparison.OrdinalIgnoreCase))
            {
                var core = lookup["Archive-".Length..];
                var lastDash = core.LastIndexOf('-');
                if (lastDash > 0) core = core[..lastDash];
                lookup = core.Replace("-", "/");
            }
            try
            {
                // Mapped channel → curated event-ID set. Unmapped channel → still
                // parsed (so every collected log is queryable) but only Critical/
                // Error/Warning events are kept, to avoid flooding the db.
                if (ChannelMap.TryGetValue(lookup, out var wantedIds))
                    total += ParseChannel(conn, file, channel, wantedIds, false, progress);
                else
                    total += ParseChannel(conn, file, channel, null, true, progress);
            }
            catch (Exception ex)
            {
                progress?.Invoke($"WARNING: evtx {channel}: {ex.Message}");
            }
        }
        return total;
    }

    private static int ParseChannel(SqliteConnection conn, string file, string channel,
        HashSet<int>? wantedIds, bool unmapped, Action<string>? progress)
    {
        using var tx = conn.BeginTransaction();
        using var insert = conn.CreateCommand();
        insert.CommandText = """
            INSERT INTO event_logs (ts_utc, channel, provider, event_id, level, computer, user_sid, summary, event_data)
            VALUES ($ts, $ch, $prov, $id, $lvl, $comp, $sid, $sum, $data)
            """;
        var pTs = P(insert, "$ts"); var pCh = P(insert, "$ch"); var pProv = P(insert, "$prov");
        var pId = P(insert, "$id"); var pLvl = P(insert, "$lvl"); var pComp = P(insert, "$comp");
        var pSid = P(insert, "$sid"); var pSum = P(insert, "$sum"); var pData = P(insert, "$data");
        pCh.Value = channel;

        using var tl = conn.CreateCommand();
        tl.CommandText = """
            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            VALUES ($ts, 'eventlog', $cat, $sum, $det, 'event_logs', last_insert_rowid())
            """;
        var tTs = P(tl, "$ts"); var tCat = P(tl, "$cat"); var tSum = P(tl, "$sum"); var tDet = P(tl, "$det");

        var query = new EventLogQuery(file, PathType.FilePath);
        using var reader = new EventLogReader(query);
        var n = 0; var scanned = 0;
        var cap = unmapped ? 20_000 : MaxEventsPerChannel;   // tighter cap for unmapped channels

        for (EventRecord? ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
        {
            using (ev)
            {
                if (++scanned > cap)
                {
                    progress?.Invoke($"evtx {channel}: capped at {cap} events");
                    break;
                }
                if (wantedIds != null && !wantedIds.Contains(ev.Id)) continue;
                // Unmapped channels: keep only Critical/Error/Warning (and
                // LogAlways=0); drop Information/Verbose noise. Level can be null.
                if (unmapped)
                {
                    var lvl = ev.Level ?? 0;
                    if (lvl >= 4) continue;
                }

                var data = ExtractEventData(ev);
                var tsUtc = ev.TimeCreated?.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
                var summary = BuildSummary(ev.Id, channel, data);

                pTs.Value = (object?)tsUtc ?? DBNull.Value;
                pProv.Value = (object?)ev.ProviderName ?? DBNull.Value;
                pId.Value = ev.Id;
                pLvl.Value = ev.Level switch { 1 => "Critical", 2 => "Error", 3 => "Warning", 4 => "Information", 5 => "Verbose", _ => "Unknown" };
                pComp.Value = (object?)ev.MachineName ?? DBNull.Value;
                pSid.Value = (object?)ev.UserId?.Value ?? DBNull.Value;
                pSum.Value = summary;
                pData.Value = JsonSerializer.Serialize(data);
                insert.ExecuteNonQuery();
                n++;

                // timeline rows only for the high-signal subset, and only when dated
                if (tsUtc != null && TimelineIds.TryGetValue((channel, ev.Id), out var t))
                {
                    tTs.Value = tsUtc;
                    tCat.Value = t.Category;
                    tSum.Value = $"{t.Label} (EID {ev.Id}): {summary}";
                    tDet.Value = channel;
                    tl.ExecuteNonQuery();
                }
            }
        }
        tx.Commit();
        progress?.Invoke($"evtx {channel}: {n} of {scanned} events kept");
        return n;
    }

    /// <summary>EventData/UserData name→value pairs from the record XML.</summary>
    private static Dictionary<string, string> ExtractEventData(EventRecord ev)
    {
        var data = new Dictionary<string, string>();
        string xml;
        try { xml = ev.ToXml(); }
        catch { return data; }

        var doc = new XmlDocument();
        try { doc.LoadXml(xml); } catch { return data; }

        var nodes = doc.GetElementsByTagName("Data");
        var unnamed = 0;
        foreach (XmlNode node in nodes)
        {
            var name = node.Attributes?["Name"]?.Value ?? $"Data{unnamed++}";
            var value = node.InnerText;
            if (value.Length > 4096) value = value[..4096] + $"...[{value.Length} chars total]";
            data[name] = value;
        }
        // UserData payloads (TaskScheduler, log-clear 104, ...) have no Data elements
        if (data.Count == 0)
        {
            var userData = doc.GetElementsByTagName("UserData");
            if (userData.Count > 0 && userData[0]!.FirstChild != null)
                foreach (XmlNode child in userData[0]!.FirstChild!.ChildNodes)
                    if (!string.IsNullOrWhiteSpace(child.InnerText))
                        data[child.Name] = child.InnerText.Length > 4096
                            ? child.InnerText[..4096] + "..." : child.InnerText;
        }
        return data;
    }

    private static string BuildSummary(int id, string channel, Dictionary<string, string> data)
    {
        var fields = SummaryFields.TryGetValue(id, out var f) ? f : null;
        IEnumerable<string> parts;
        if (fields != null)
            parts = fields.Where(data.ContainsKey).Select(k => $"{k}={Truncate(data[k], 200)}");
        else
            parts = data.Take(4).Select(kv => $"{kv.Key}={Truncate(kv.Value, 120)}");
        var s = string.Join(" | ", parts);
        return s.Length > 0 ? s : $"EID {id} ({channel})";
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
