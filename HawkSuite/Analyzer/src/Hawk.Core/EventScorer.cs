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
        total += LateralMovement(conn);
        total += DeletedExecutables(conn);
        total += UnsignedDrivers(conn);
        total += RemoteAccessTools(conn);
        total += SrumEgress(conn);
        TagTechniques(conn);          // stamp every finding with its MITRE ATT&CK technique
        progress?.Invoke($"event rules: {total} findings");
        return total;
    }

    /// <summary>rule name -> "MITRE ATT&CK id | name". Single source of truth so
    /// every finding (existing + new) is tagged in one pass.</summary>
    private static readonly Dictionary<string, string> AttackMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["log-cleared"]                        = "T1070.001 | Indicator Removal: Clear Windows Event Logs",
        ["defender-detection"]                 = "T1587 | Develop Capabilities (malware detected)",
        ["defender-disabled"]                  = "T1562.001 | Impair Defenses: Disable or Modify Tools",
        ["defender-rtp-off"]                   = "T1562.001 | Impair Defenses: Disable or Modify Tools",
        ["suspicious-service-install"]         = "T1543.003 | Create or Modify System Process: Windows Service",
        ["suspicious-scheduled-task"]          = "T1053.005 | Scheduled Task/Job: Scheduled Task",
        ["suspicious-task-xml"]                = "T1053.005 | Scheduled Task/Job: Scheduled Task",
        ["encoded-powershell"]                 = "T1059.001 | Command and Scripting Interpreter: PowerShell",
        ["suspicious-scriptblock"]             = "T1059.001 | Command and Scripting Interpreter: PowerShell",
        ["failed-logon-cluster"]               = "T1110 | Brute Force",
        ["password-spray"]                     = "T1110.003 | Brute Force: Password Spraying",
        ["injected-memory-rwx-userwritable"]   = "T1055 | Process Injection",
        ["private-rwx-memory-unsigned"]        = "T1055 | Process Injection",
        ["private-exec-memory-userwritable"]   = "T1055 | Process Injection",
        ["private-exec-memory-unsigned"]       = "T1055 | Process Injection",
        ["recycle-bin-executable-deleted"]     = "T1070.004 | Indicator Removal: File Deletion",
        ["mft-deleted-executable"]             = "T1070.004 | Indicator Removal: File Deletion",
        ["lateral-movement-remote-interactive"]= "T1021.001 | Remote Services: Remote Desktop Protocol",
        ["lateral-movement-network-logon"]     = "T1021.002 | Remote Services: SMB/Windows Admin Shares",
        ["unsigned-kernel-driver"]             = "T1014 | Rootkit (possible BYOVD)",
        ["unsigned-driver-userwritable"]       = "T1068 | Exploitation for Privilege Escalation (BYOVD)",
        ["remote-access-tool-present"]         = "T1219 | Remote Access Software",
        ["remote-access-tool-unsigned"]        = "T1219 | Remote Access Software",
        ["srum-egress-userwritable"]           = "T1041 | Exfiltration Over C2 Channel",
    };

    private static void TagTechniques(SqliteConnection conn)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE findings SET technique = $t WHERE rule = $r AND technique IS NULL";
        var pt = P(cmd, "$t"); var pr = P(cmd, "$r");
        foreach (var kv in AttackMap) { pr.Value = kv.Key; pt.Value = kv.Value; cmd.ExecuteNonQuery(); }
        tx.Commit();
    }

    /// <summary>
    /// Unsigned / invalid-signature kernel drivers (drivers artifact) - the BYOVD
    /// surface. FP-resistant: Valid-signed suppressed; a Microsoft/WHQL-signed
    /// driver is trusted. Unsigned in a user-writable path escalates to high.
    /// </summary>
    private static int UnsignedDrivers(SqliteConnection conn)
    {
        string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\programdata\", @"\users\"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT record_json FROM artifact_records WHERE artifact_type = 'drivers'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                JsonElement e; try { e = JsonDocument.Parse(r.GetString(0)).RootElement; } catch { continue; }
                if ((e.TryGetProperty("recordType", out var rt) ? rt.GetString() : null) != "kernelDriver") continue;
                string S(string k) => e.TryGetProperty(k, out var v) ? v.GetString() ?? "" : "";
                var sig = S("signatureStatus");
                if (sig == "Valid" || sig == "Unknown") continue;   // trust signed; Unknown = unresolved path (avoid FP)
                var name = S("name"); var path = S("resolvedPath");
                var lower = path.ToLowerInvariant();
                var inUserWritable = userWritable.Any(u => lower.Contains(u));
                var rule = inUserWritable ? "unsigned-driver-userwritable" : "unsigned-kernel-driver";
                var sev = inUserWritable ? "high" : "medium";
                rows.Add((rule, sev,
                    $"Unsigned kernel driver: {name}",
                    $"signature={sig}; state={S("state")}; startMode={S("startMode")}; path={(path.Length == 0 ? "[unresolved]" : path)}",
                    null));
            }
        }
        return InsertSimple(conn, rows, "drivers");
    }

    /// <summary>
    /// Remote-access / RMM tooling (remote_access_tools artifact). Presence alone
    /// is a lead, not a verdict (many orgs run RMM legitimately) -> medium.
    /// Escalates to high when the tool binary is unsigned or runs from a
    /// user-writable path (attacker-dropped portable RMM).
    /// </summary>
    private static int RemoteAccessTools(SqliteConnection conn)
    {
        string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin"];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT record_json FROM artifact_records WHERE artifact_type = 'remote_access_tools'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                JsonElement e; try { e = JsonDocument.Parse(r.GetString(0)).RootElement; } catch { continue; }
                string S(string k) => e.TryGetProperty(k, out var v) ? v.GetString() ?? "" : "";
                var rt = S("recordType");
                var name = rt == "ratProcess" ? S("name") : rt == "ratService" ? S("displayName") : rt == "ratInstalled" ? S("displayName") : "";
                var path = (S("path") + S("pathName") + S("installLocation")).ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(name)) continue;
                if (!seen.Add(rt + "|" + name)) continue;                 // de-dupe process/service/installed of same tool
                var sig = S("signatureStatus");
                var unsigned = sig == "NotSigned" || sig == "Invalid";
                var inUserWritable = userWritable.Any(u => path.Contains(u));
                string rule, sev;
                if (unsigned || inUserWritable) { rule = "remote-access-tool-unsigned"; sev = "high"; }
                else { rule = "remote-access-tool-present"; sev = "medium"; }
                rows.Add((rule, sev,
                    $"Remote-access/RMM tool present: {name}",
                    $"source={rt}; signature={(sig.Length == 0 ? "n/a" : sig)}; verify this tool is authorized",
                    null));
            }
        }
        return InsertSimple(conn, rows, "remote_access_tools");
    }

    /// <summary>
    /// SRUM network egress from an app whose image sits in a user-writable path
    /// (attacker tooling phoning home / exfil). Conservative: only user-writable
    /// paths with meaningful bytes sent, to stay FP-resistant.
    /// </summary>
    private static int SrumEgress(SqliteConnection conn)
    {
        const long MinSent = 5_000_000;   // 5 MB sent — ignore chatter
        string[] userWritable = [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\programdata\"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            // table may not exist on older dbs; guard with try
            try
            {
                read.CommandText = """
                    SELECT app, MAX(ts_utc), SUM(COALESCE(bytes_sent,0)), SUM(COALESCE(bytes_recvd,0))
                    FROM srum WHERE provider = 'network_data' AND app IS NOT NULL
                    GROUP BY app
                    """;
                using var r = read.ExecuteReader();
                while (r.Read())
                {
                    var app = r.IsDBNull(0) ? "" : r.GetString(0);
                    var ts = r.IsDBNull(1) ? null : r.GetString(1);
                    var sent = r.IsDBNull(2) ? 0 : r.GetInt64(2);
                    var recvd = r.IsDBNull(3) ? 0 : r.GetInt64(3);
                    if (sent < MinSent) continue;
                    var lower = app.ToLowerInvariant();
                    if (!userWritable.Any(u => lower.Contains(u))) continue;
                    rows.Add(("srum-egress-userwritable", "high",
                        $"Network egress from user-writable-path app: {System.IO.Path.GetFileName(app.TrimEnd('\\'))}",
                        $"sent={sent:N0} bytes, received={recvd:N0} bytes; app={app}", ts));
                }
            }
            catch { return 0; }
        }
        return InsertSimple(conn, rows, "srum");
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

    /// <summary>
    /// Lateral-movement logons from 4624. FP-resistant: local/service/loopback
    /// logons are ignored; only genuinely remote sources are flagged. RDP
    /// (type 10) from any remote host is medium (external = high); network
    /// (type 3) is flagged only from a PUBLIC IP. Machine/ANONYMOUS accounts
    /// are excluded. On a normal workstation with no remote logons this yields
    /// zero findings.
    /// </summary>
    private static int LateralMovement(SqliteConnection conn)
    {
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT ts_utc, event_data FROM event_logs WHERE event_id = 4624 AND channel = 'Security'";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                var ts = r.IsDBNull(0) ? null : r.GetString(0);
                var data = r.IsDBNull(1) ? null : r.GetString(1);
                var ip = Field(data, "IpAddress");
                if (!IsRemoteAddr(ip)) continue;                       // local/service/loopback -> ignore
                var lt = Field(data, "LogonType");
                var user = Field(data, "TargetUserName") ?? "?";
                if (user.EndsWith("$") || user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase)) continue;

                if (lt == "10")
                {
                    var pub = IsPublicAddr(ip);
                    rows.Add(("remote-interactive-logon", pub ? "high" : "medium",
                        $"Remote interactive (RDP) logon: {user} from {ip}",
                        $"LogonType 10 (RemoteInteractive), source {ip}", ts));
                }
                else if (lt == "3" && IsPublicAddr(ip))
                {
                    rows.Add(("network-logon-external", "medium",
                        $"Network logon from external IP: {user} from {ip}",
                        $"LogonType 3 (Network), source {ip}", ts));
                }
            }
        }
        return InsertSimple(conn, rows, "event_logs");
    }

    /// <summary>True if the address is a real remote source (not loopback/empty/0.0.0.0).</summary>
    private static bool IsRemoteAddr(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "-" || ip == "::1" || ip == "0.0.0.0" || ip == "127.0.0.1") return false;
        return System.Net.IPAddress.TryParse(ip, out var a) && !System.Net.IPAddress.IsLoopback(a);
    }

    /// <summary>True if the address is a routable public IP (not private/link-local).</summary>
    private static bool IsPublicAddr(string? ip)
    {
        if (!IsRemoteAddr(ip) || !System.Net.IPAddress.TryParse(ip, out var a)) return false;
        var b = a.GetAddressBytes();
        if (b.Length == 4)
            return !(b[0] == 10
                  || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                  || (b[0] == 192 && b[1] == 168)
                  || (b[0] == 169 && b[1] == 254)
                  || b[0] == 0);
        return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal);
    }

    /// <summary>
    /// Deleted executables/scripts recovered from the $MFT (in_use=0). Strong
    /// anti-forensics / tool-cleanup signal and far fewer than live files, so
    /// it is bounded. Medium severity.
    /// </summary>
    private static int DeletedExecutables(SqliteConnection conn)
    {
        if (!TableExists(conn, "mft_entries")) return 0;
        string[] exts = [".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".scr", ".sys", ".js", ".hta", ".jse"];
        var rows = new List<(string rule, string sev, string sum, string det, string? ts)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT file_name, full_path, si_modified_utc FROM mft_entries WHERE in_use = 0 AND is_directory = 0 AND file_name IS NOT NULL LIMIT 100000";
            using var r = read.ExecuteReader();
            while (r.Read())
            {
                var fn = r.GetString(0);
                var low = fn.ToLowerInvariant();
                if (!exts.Any(low.EndsWith)) continue;
                rows.Add(("mft-deleted-executable", "medium",
                    $"Deleted executable in $MFT: {fn}",
                    r.IsDBNull(1) ? fn : r.GetString(1),
                    r.IsDBNull(2) ? null : r.GetString(2)));
            }
        }
        return InsertSimple(conn, rows, "mft_entries");
    }

    private static bool TableExists(SqliteConnection conn, string name)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$n";
        cmd.Parameters.AddWithValue("$n", name);
        return cmd.ExecuteScalar() != null;
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
