using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Detection rules over the parsed event_logs table. Two output shapes:
/// per-event verdicts and aggregate findings (e.g. password spray across
/// hundreds of 4625s) — both land in the findings table.
///
/// Same FP philosophy as MriEngine: single benign-capable signals score
/// low or not at all; convergence and explicit-threat events score high.
/// </summary>
public static class EventScorer
{
    public static int Score(SqliteConnection conn, Action<string>? progress = null)
    {
        var total = 0;
        total += LogCleared(conn);
        total += DefenderDetections(conn);
        total += DefenderDisabled(conn);
        total += SuspiciousServiceInstall(conn);
        total += SuspiciousTaskCreation(conn);
        total += SuspiciousScriptBlocks(conn);
        total += FailedLogonClusters(conn);
        total += InjectedMemory(conn);
        total += RecycleBinExecutables(conn);
        total += SuspiciousTaskXml(conn);
        progress?.Invoke($"event rules: {total} findings");
        return total;
    }

    // ---- helpers -----------------------------------------------------------

    private static int InsertFindings(SqliteConnection conn, string selectSql,
        Func<SqliteDataReader, (string rule, string severity, string summary, string? detail, string? ts, long? eventRow)?> map)
    {
        var rows = new List<(string, string, string, string?, string?, long?)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = selectSql;
            using var r = read.ExecuteReader();
            while (r.Read())
                if (map(r) is { } f) rows.Add(f);
        }
        if (rows.Count == 0) return 0;

        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, ts_utc, artifact_table, artifact_id)
            VALUES ($rule, $sev, $sum, $det, $ts, 'event_logs', $id)
            """;
        var pRule = P(cmd, "$rule"); var pSev = P(cmd, "$sev"); var pSum = P(cmd, "$sum");
        var pDet = P(cmd, "$det"); var pTs = P(cmd, "$ts"); var pId = P(cmd, "$id");
        foreach (var (rule, sev, sum, det, ts, id) in rows)
        {
            pRule.Value = rule; pSev.Value = sev; pSum.Value = sum;
            pDet.Value = (object?)det ?? DBNull.Value;
            pTs.Value = (object?)ts ?? DBNull.Value;
            pId.Value = (object?)id ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return rows.Count;
    }

    private static string? Field(string? json, string name)
    {
        if (json == null) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty(name, out var v) ? v.GetString() : null;
        }
        catch { return null; }
    }

    // ---- rules --------------------------------------------------------------

    /// <summary>1102/104 — log clearing is never routine on an investigated host.</summary>
    private static int LogCleared(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, event_id, summary FROM event_logs
            WHERE (channel = 'Security' AND event_id = 1102) OR (channel = 'System' AND event_id = 104)
            """,
            r => ("event-log-cleared", "critical",
                  $"Event log cleared (EID {r.GetInt64(2)})",
                  r.IsDBNull(3) ? null : r.GetString(3),
                  r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0)));

    /// <summary>Defender 1116/1117 — the AV literally said malware.</summary>
    private static int DefenderDetections(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, summary, event_data FROM event_logs
            WHERE event_id IN (1116, 1117) AND channel LIKE '%Defender%'
            """,
            r => ("defender-detection", "high",
                  $"Defender detection: {Field(r.IsDBNull(3) ? null : r.GetString(3), "Threat Name") ?? "unknown threat"}",
                  r.IsDBNull(2) ? null : r.GetString(2),
                  r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0)));

    /// <summary>Defender 5001 — real-time protection switched off.</summary>
    private static int DefenderDisabled(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, summary FROM event_logs
            WHERE event_id = 5001 AND channel LIKE '%Defender%'
            """,
            r => ("defender-rtp-disabled", "high",
                  "Defender real-time protection disabled",
                  r.IsDBNull(2) ? null : r.GetString(2),
                  r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0)));

    /// <summary>
    /// 7045/4697 service installs — only flagged when the image path itself is
    /// suspicious (user-writable location, shell invocation, or no path at all).
    /// Plain service installs are routine (drivers, updaters) and score nothing.
    /// </summary>
    private static int SuspiciousServiceInstall(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, summary, event_data FROM event_logs WHERE event_id IN (7045, 4697)
            """,
            r =>
            {
                var data = r.IsDBNull(3) ? null : r.GetString(3);
                var image = (Field(data, "ImagePath") ?? Field(data, "ServiceFileName") ?? "").ToLowerInvariant();
                var svc = Field(data, "ServiceName") ?? "?";
                string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\perflogs\", @"\programdata\"];
                // legit products that service-install from ProgramData (verified FPs)
                string[] knownGoodPrefixes =
                [
                    @"\programdata\microsoft\windows defender\platform\",
                    @"\programdata\microsoft\windows defender advanced threat protection\",
                ];
                var shell = image.Contains("cmd ") || image.Contains("cmd.exe") || image.Contains("powershell") ||
                            image.Contains("mshta") || image.Contains("wscript") || image.Contains("rundll32");
                var writable = userWritable.Any(image.Contains) && !knownGoodPrefixes.Any(image.Contains);
                if (!shell && !writable) return null;
                return ("suspicious-service-install",
                        shell ? "critical" : "high",
                        $"Service '{svc}' installed with {(shell ? "shell command" : "user-writable")} image path",
                        $"ImagePath: {Field(data, "ImagePath") ?? Field(data, "ServiceFileName")}",
                        r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0));
            });

    /// <summary>4698 task creation whose content carries encoded-PS / LOLBAS args.</summary>
    private static int SuspiciousTaskCreation(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, summary, event_data FROM event_logs
            WHERE event_id = 4698 AND channel = 'Security'
            """,
            r =>
            {
                var data = (r.IsDBNull(3) ? "" : r.GetString(3)).ToLowerInvariant();
                var bad = data.Contains(" -enc") || data.Contains("-encodedcommand") ||
                          data.Contains("iex(") || data.Contains("downloadstring") ||
                          data.Contains("frombase64string") ||
                          (data.Contains("certutil") && data.Contains("-urlcache")) ||
                          (data.Contains("mshta") && data.Contains("http"));
                if (!bad) return null;
                var task = Field(r.GetString(3), "TaskName") ?? "?";
                return ("suspicious-task-created", "high",
                        $"Scheduled task '{task}' created with suspicious command content",
                        r.IsDBNull(2) ? null : r.GetString(2),
                        r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0));
            });

    /// <summary>
    /// 4104 script blocks — flagged on convergence (2+ distinct techniques),
    /// mirroring the process-rule philosophy: one keyword is not a verdict.
    /// </summary>
    private static int SuspiciousScriptBlocks(SqliteConnection conn) =>
        InsertFindings(conn, """
            SELECT id, ts_utc, event_data FROM event_logs
            WHERE event_id = 4104
            """,
            r =>
            {
                var text = (Field(r.IsDBNull(2) ? null : r.GetString(2), "ScriptBlockText") ?? "").ToLowerInvariant();
                if (text.Length == 0) return null;
                // STRONG techniques: rarely seen in legitimate admin scripting
                string[][] strong =
                [
                    ["frombase64string", "-encodedcommand", " -enc "],
                    ["downloadstring", "downloadfile", "net.webclient"],
                    ["memorystream", "gzipstream", "deflatestream"],
                    ["virtualalloc", "createthread", "delegatetype"],
                    ["amsiutils", "amsiinitfailed"],
                ];
                // WEAK techniques: routine in admin/deployment scripts — only
                // count as corroboration, never alone (verified FP source)
                string[][] weak =
                [
                    ["iex(", "iex ", "invoke-expression"],
                    ["-nop", "-noprofile"],
                    ["bypass", "-ep bypass", "executionpolicy bypass"],
                    ["invoke-webrequest"],
                ];
                var strongHits = strong.Count(g => g.Any(text.Contains));
                var weakHits = weak.Count(g => g.Any(text.Contains));
                var hits = strongHits + weakHits;
                if (strongHits == 0 || hits < 2) return null;
                return ("suspicious-scriptblock", strongHits >= 2 ? "critical" : "high",
                        $"PowerShell script block with {hits} obfuscation/download techniques ({strongHits} strong)",
                        text.Length > 600 ? text[..600] + "..." : text,
                        r.IsDBNull(1) ? null : r.GetString(1), r.GetInt64(0));
            });

    /// <summary>
    /// 4625 clusters per source: ≥10 failures within 10 minutes from one
    /// address = brute force; ≥10 distinct accounts = password spray.
    /// Aggregate finding — individual 4625s are normal life.
    /// </summary>
    private static int FailedLogonClusters(SqliteConnection conn)
    {
        var events = new List<(long id, DateTime ts, string ip, string user)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = """
                SELECT id, ts_utc, event_data FROM event_logs
                WHERE event_id = 4625 AND channel = 'Security' AND ts_utc IS NOT NULL
                ORDER BY ts_utc
                """;
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                var data = r.IsDBNull(2) ? null : r.GetString(2);
                if (!DateTime.TryParse(r.GetString(1), null,
                        System.Globalization.DateTimeStyles.AdjustToUniversal, out var ts)) continue;
                events.Add((r.GetInt64(0), ts,
                    Field(data, "IpAddress") ?? "-", Field(data, "TargetUserName") ?? "-"));
            }
        }
        if (events.Count < 10) return 0;

        var findings = 0;
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, ts_utc, artifact_table, artifact_id)
            VALUES ($rule, 'high', $sum, $det, $ts, 'event_logs', $id)
            """;
        var pRule = P(cmd, "$rule"); var pSum = P(cmd, "$sum");
        var pDet = P(cmd, "$det"); var pTs = P(cmd, "$ts"); var pId = P(cmd, "$id");

        foreach (var bySource in events.GroupBy(e => e.ip))
        {
            var list = bySource.OrderBy(e => e.ts).ToList();
            // sliding 10-minute window
            for (int lo = 0, hi = 0; lo < list.Count; lo++)
            {
                while (hi < list.Count && (list[hi].ts - list[lo].ts) <= TimeSpan.FromMinutes(10)) hi++;
                var window = list[lo..hi];
                if (window.Count < 10) continue;

                var users = window.Select(w => w.user).Distinct().Count();
                pRule.Value = users >= 10 ? "password-spray" : "brute-force";
                pSum.Value = users >= 10
                    ? $"Password spray from {bySource.Key}: {window.Count} failures across {users} accounts in 10 min"
                    : $"Brute force from {bySource.Key}: {window.Count} failed logons in 10 min";
                pDet.Value = $"accounts: {string.Join(", ", window.Select(w => w.user).Distinct().Take(20))}";
                pTs.Value = window[0].ts.ToString("yyyy-MM-ddTHH:mm:ssZ");
                pId.Value = window[0].id;
                cmd.ExecuteNonQuery();
                findings++;
                break;   // one finding per source address
            }
        }
        tx.Commit();
        return findings;
    }

    /// <summary>
    /// Private executable memory (injection/hollowing footprint) from the
    /// injected_memory artifact. FP-resistant by convergence: legitimate JIT
    /// (browsers, .NET, Java) produces RWX too, so a VALID-signed host process
    /// is suppressed. Only unsigned/unknown/invalid hosts with private exec
    /// memory are flagged; RWX or a user-writable image path escalates.
    /// </summary>
    private static int InjectedMemory(SqliteConnection conn)
    {
        var rows = new List<(string rule, string sev, string sum, string det)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT record_json FROM artifact_records WHERE artifact_type = 'injected_memory'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                JsonElement e;
                try { e = JsonDocument.Parse(r.GetString(0)).RootElement; } catch { continue; }

                int priv = e.TryGetProperty("privateExecRegionCount", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;
                int rwx = e.TryGetProperty("rwxRegionCount", out var w) && w.ValueKind == JsonValueKind.Number ? w.GetInt32() : 0;
                if (priv == 0) continue;

                var sig = e.TryGetProperty("signatureStatus", out var s) ? s.GetString() ?? "Unknown" : "Unknown";
                var name = e.TryGetProperty("name", out var n) ? n.GetString() ?? "?" : "?";
                var path = (e.TryGetProperty("path", out var pa) ? pa.GetString() : null) ?? "";
                var pid = e.TryGetProperty("pid", out var pd) && pd.ValueKind == JsonValueKind.Number ? pd.GetInt32() : 0;

                // VALID-signed host: legitimate JIT — suppress (the FP safeguard).
                if (sig == "Valid") continue;

                string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\programdata\"];
                var inUserWritable = userWritable.Any(u => path.ToLowerInvariant().Contains(u));

                string rule, sev;
                if (inUserWritable && rwx > 0) { rule = "injected-memory-rwx-userwritable"; sev = "critical"; }
                else if (rwx > 0) { rule = "private-rwx-memory-unsigned"; sev = "high"; }
                else if (inUserWritable) { rule = "private-exec-memory-userwritable"; sev = "high"; }
                else { rule = "private-exec-memory-unsigned"; sev = "medium"; }

                rows.Add((rule, sev,
                    $"Private executable memory in unsigned process {name} (PID {pid})",
                    $"{priv} private-exec region(s), {rwx} RWX; signature={sig}; path={(path.Length == 0 ? "[none]" : path)}"));
            }
        }
        if (rows.Count == 0) return 0;

        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, artifact_table)
            VALUES ($rule, $sev, $sum, $det, 'injected_memory')
            """;
        var pRule = P(cmd, "$rule"); var pSev = P(cmd, "$sev"); var pSum = P(cmd, "$sum"); var pDet = P(cmd, "$det");
        foreach (var (rule, sev, sum, det) in rows)
        {
            pRule.Value = rule; pSev.Value = sev; pSum.Value = sum; pDet.Value = det;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return rows.Count;
    }

    /// <summary>
    /// Executables/scripts sent to the Recycle Bin (recent_files recycleBin
    /// records) - anti-forensics / tool-staging cleanup signal. Medium: deletion
    /// is common, but deleting a binary specifically is worth a look.
    /// </summary>
    private static int RecycleBinExecutables(SqliteConnection conn)
    {
        string[] exts = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".scr", ".sys", ".js", ".hta"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT record_json FROM artifact_records WHERE artifact_type = 'recent_files'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                JsonElement e; try { e = JsonDocument.Parse(r.GetString(0)).RootElement; } catch { continue; }
                if ((e.TryGetProperty("recordType", out var rt) ? rt.GetString() : null) != "recycleBin") continue;
                var path = e.TryGetProperty("originalPath", out var p) ? p.GetString() : null;
                if (string.IsNullOrEmpty(path)) continue;
                var lower = path.ToLowerInvariant();
                if (!exts.Any(x => lower.EndsWith(x))) continue;
                rows.Add(("recycle-bin-executable-deleted", "medium",
                    $"Executable deleted to Recycle Bin: {System.IO.Path.GetFileName(path)}",
                    path, e.TryGetProperty("deletedUtc", out var d) ? d.GetString() : null));
            }
        }
        return InsertSimple(conn, rows, "recent_files");
    }

    /// <summary>
    /// Suspicious scheduled tasks parsed from the raw Tasks XML (catches tasks
    /// hidden from the Schedule API). Flags encoded-PS / LOLBAS command content,
    /// or an unsigned image in a user-writable path.
    /// </summary>
    private static int SuspiciousTaskXml(SqliteConnection conn)
    {
        string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\programdata\"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT record_json FROM artifact_records WHERE artifact_type = 'scheduled_task_xml'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                JsonElement e; try { e = JsonDocument.Parse(r.GetString(0)).RootElement; } catch { continue; }
                string S(string k) => e.TryGetProperty(k, out var v) ? v.GetString() ?? "" : "";
                var cmd = (S("execute") + " " + S("arguments")).ToLowerInvariant();
                var bin = S("binaryPath").ToLowerInvariant();
                var sig = S("signatureStatus");
                var name = S("taskName");

                var encoded = cmd.Contains(" -enc") || cmd.Contains("-encodedcommand") || cmd.Contains("frombase64string")
                            || cmd.Contains("iex(") || cmd.Contains("downloadstring") || cmd.Contains("downloadfile");
                var lolbas = (cmd.Contains("certutil") && (cmd.Contains("-urlcache") || cmd.Contains("-decode")))
                            || (cmd.Contains("mshta") && cmd.Contains("http"))
                            || (cmd.Contains("regsvr32") && cmd.Contains("/i:http"))
                            || (cmd.Contains("rundll32") && cmd.Contains("javascript:"));
                var unsignedWritable = (sig is "NotSigned" or "Unknown" or "Invalid") && userWritable.Any(bin.Contains) && bin.Length > 0;
                if (!encoded && !lolbas && !unsignedWritable) continue;

                rows.Add(("suspicious-scheduled-task", (encoded || lolbas) ? "high" : "medium",
                    $"Suspicious scheduled task: {name}",
                    (S("execute") + " " + S("arguments")).Trim(),
                    e.TryGetProperty("registeredUtc", out var d) ? d.GetString() : null));
            }
        }
        return InsertSimple(conn, rows, "scheduled_task_xml");
    }

    /// <summary>Bulk-insert simple findings sharing one source table.</summary>
    private static int InsertSimple(SqliteConnection conn,
        List<(string rule, string sev, string sum, string det, string? ts)> rows, string srcTable)
    {
        if (rows.Count == 0) return 0;
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, ts_utc, artifact_table)
            VALUES ($rule, $sev, $sum, $det, $ts, $tbl)
            """;
        var pRule = P(cmd, "$rule"); var pSev = P(cmd, "$sev"); var pSum = P(cmd, "$sum");
        var pDet = P(cmd, "$det"); var pTs = P(cmd, "$ts"); var pTbl = P(cmd, "$tbl");
        pTbl.Value = srcTable;
        foreach (var (rule, sev, sum, det, ts) in rows)
        {
            pRule.Value = rule; pSev.Value = sev; pSum.Value = sum;
            pDet.Value = (object?)det ?? DBNull.Value; pTs.Value = (object?)ts ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return rows.Count;
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
