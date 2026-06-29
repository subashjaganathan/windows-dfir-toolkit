using System.Dynamic;
using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Shared analysis operations used by both the CLI and the GUI shell.
/// </summary>
public static class AnalysisService
{
    /// <summary>Imports a .hawk session and runs MRI scoring. Returns the hawk.db path.</summary>
    public static string ImportAndScore(string hawkFile, Action<string>? progress = null,
                                        IEnumerable<IRawArtifactParser>? rawParsers = null)
    {
        progress?.Invoke("extracting session container...");
        var importer = new SessionImporter();
        var dbPath = importer.Import(hawkFile, progress: progress, rawParsers: rawParsers);

        using var conn = Db.Open(dbPath);
        string role;
        using (var c = conn.CreateCommand())
        {
            c.CommandText = "SELECT value FROM session WHERE key='role'";
            role = c.ExecuteScalar() as string ?? "workstation";
        }

        var mriConfig = FindMriConfig();
        if (mriConfig == null)
        {
            progress?.Invoke("WARNING: mri-config.json not found — scoring skipped");
            return dbPath;
        }

        var whitelist = LoadWhitelist(progress);
        progress?.Invoke($"MRI scoring (host role: {role})...");
        var engine = new MriEngine(mriConfig, whitelist);
        engine.ScoreProcesses(conn, role);
        engine.ScorePersistence(conn, role);
        EventScorer.Score(conn, progress);
        IocMatcher.Match(conn, progress);

        using (var stat = conn.CreateCommand())
        {
            stat.CommandText = "SELECT band, COUNT(*) FROM mri_scores GROUP BY band";
            using var r = stat.ExecuteReader();
            var parts = new List<string>();
            while (r.Read()) parts.Add($"{r.GetString(0)}={r.GetInt64(1)}");
            progress?.Invoke("worklist: " + string.Join(", ", parts));
        }
        return dbPath;
    }

    /// <summary>MRI-ranked process worklist. Rows are ExpandoObjects (IDictionary).</summary>
    public static List<ExpandoObject> GetWorklist(SqliteConnection conn, bool onlyScored = false)
        => EnumerateWorklist(conn, onlyScored).ToList(); // materialized: callers serialize after the connection closes

    private static IEnumerable<ExpandoObject> EnumerateWorklist(SqliteConnection conn, bool onlyScored)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT s.score, s.band, s.trust_verdict, s.matched_rules,
                   p.id, p.pid, p.ppid, p.name, p.path, p.command_line, p.user,
                   p.start_time_utc, p.sha256, p.md5, p.signature_status, p.signer,
                   p.parent_name, p.parent_path,
                   t.tag, t.note
            FROM mri_scores s
            JOIN processes p ON p.id = s.artifact_id AND s.artifact_table = 'processes'
            LEFT JOIN tags t ON t.artifact_table = 'processes' AND t.artifact_id = p.id
            {(onlyScored ? "WHERE s.score > 0" : "")}
            ORDER BY s.score DESC, p.name
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["score"] = r.GetInt32(0);
            d["band"] = r.GetString(1);
            d["verdict"] = r.GetString(2);
            d["matchedRules"] = r.IsDBNull(3) ? "[]" : r.GetString(3);
            d["id"] = r.GetInt64(4);
            d["pid"] = r.IsDBNull(5) ? null : r.GetInt64(5);
            d["ppid"] = r.IsDBNull(6) ? null : r.GetInt64(6);
            d["name"] = r.IsDBNull(7) ? null : r.GetString(7);
            d["path"] = r.IsDBNull(8) ? null : r.GetString(8);
            d["commandLine"] = r.IsDBNull(9) ? null : r.GetString(9);
            d["user"] = r.IsDBNull(10) ? null : r.GetString(10);
            d["startTimeUtc"] = r.IsDBNull(11) ? null : r.GetString(11);
            d["sha256"] = r.IsDBNull(12) ? null : r.GetString(12);
            d["md5"] = r.IsDBNull(13) ? null : r.GetString(13);
            d["signatureStatus"] = r.IsDBNull(14) ? null : r.GetString(14);
            d["signer"] = r.IsDBNull(15) ? null : r.GetString(15);
            d["parentName"] = r.IsDBNull(16) ? null : r.GetString(16);
            d["parentPath"] = r.IsDBNull(17) ? null : r.GetString(17);
            d["tag"] = r.IsDBNull(18) ? null : r.GetString(18);
            d["tagNote"] = r.IsDBNull(19) ? null : r.GetString(19);
            yield return row;
        }
    }

    /// <summary>Session metadata (case, host, counts) for the GUI header.</summary>
    public static Dictionary<string, object?> GetSessionInfo(SqliteConnection conn)
    {
        var meta = new Dictionary<string, object?>();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT key, value FROM session WHERE key IN ('hostname','caseNumber','role','manifest')";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var key = r.GetString(0);
                if (key == "manifest")
                {
                    meta["manifest"] = r.GetString(1); // raw JSON for the Host Information view
                    try
                    {
                        var root = JsonDocument.Parse(r.GetString(1)).RootElement;
                        meta["os"] = root.GetProperty("host").GetProperty("os").GetProperty("caption").GetString();
                        meta["preset"] = root.TryGetProperty("preset", out var p) ? p.GetString() : null;
                        meta["collectedUtc"] = root.GetProperty("case").GetProperty("collectionStartUtc").GetString();
                        meta["investigator"] = root.GetProperty("case").GetProperty("investigator").GetString();
                    }
                    catch { /* partial manifest is non-fatal for display */ }
                }
                else meta[key] = r.GetString(1);
            }
        }
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = """
                SELECT (SELECT COUNT(*) FROM processes),
                       (SELECT COUNT(*) FROM mri_scores WHERE artifact_table != 'processes'),
                       (SELECT COUNT(*) FROM network_connections),
                       (SELECT COUNT(*) FROM timeline),
                       (SELECT COUNT(*) FROM event_logs),
                       (SELECT COUNT(*) FROM findings)
                """;
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                meta["processCount"] = r.GetInt64(0);
                meta["persistenceCount"] = r.GetInt64(1);
                meta["networkCount"] = r.GetInt64(2);
                meta["timelineCount"] = r.GetInt64(3);
                meta["eventCount"] = r.GetInt64(4);
                meta["findingCount"] = r.GetInt64(5);
            }
        }
        return meta;
    }

    /// <summary>Persist an analyst tag (benign/suspicious/confirmed) on any artifact.</summary>
    public static void SetTag(SqliteConnection conn, string table, long id, string? tag, string? note)
    {
        if (!TaggableTables.Contains(table)) throw new ArgumentException($"untaggable table {table}");
        using var cmd = conn.CreateCommand();
        if (string.IsNullOrEmpty(tag))
        {
            cmd.CommandText = "DELETE FROM tags WHERE artifact_table=$t AND artifact_id=$i";
            cmd.Parameters.AddWithValue("$t", table);
            cmd.Parameters.AddWithValue("$i", id);
        }
        else
        {
            cmd.CommandText = """
                INSERT OR REPLACE INTO tags (artifact_table, artifact_id, tag, note, tagged_at_utc)
                VALUES ($t, $i, $tag, $note, $ts)
                """;
            cmd.Parameters.AddWithValue("$t", table);
            cmd.Parameters.AddWithValue("$i", id);
            cmd.Parameters.AddWithValue("$tag", tag);
            cmd.Parameters.AddWithValue("$note", (object?)note ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ts", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        }
        cmd.ExecuteNonQuery();
    }

    private static readonly HashSet<string> TaggableTables =
        ["processes", "services", "scheduled_tasks", "registry_runkeys", "startup_folder", "wmi_persistence"];

    /// <summary>
    /// Unified persistence worklist: services, run keys, scheduled tasks,
    /// startup items and WMI subscriptions, MRI-ranked.
    /// </summary>
    public static List<ExpandoObject> GetPersistenceWorklist(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT s.score, s.band, s.trust_verdict, s.matched_rules, s.artifact_table,
                   x.id, x.name, x.detail, x.account, x.binary_path, x.signature_status, x.signer,
                   x.md5, x.sha256, t.tag
            FROM mri_scores s
            JOIN (
                SELECT 'services' AS tbl, id, name, path_name AS detail, account,
                       binary_path, signature_status, signer, md5, sha256 FROM services
                UNION ALL
                SELECT 'registry_runkeys', id, key_path || ' \ ' || COALESCE(value_name,''), command,
                       user_sid, binary_path, signature_status, signer, md5, sha256 FROM registry_runkeys
                UNION ALL
                SELECT 'scheduled_tasks', id, COALESCE(task_path,'') || COALESCE(task_name,''),
                       COALESCE(execute,'') || ' ' || COALESCE(arguments,''), run_as,
                       binary_path, signature_status, signer, md5, sha256 FROM scheduled_tasks
                UNION ALL
                SELECT 'startup_folder', id, item_name, COALESCE(target, item_path), user,
                       COALESCE(target, item_path), signature_status, signer, md5, sha256 FROM startup_folder
                UNION ALL
                SELECT 'wmi_persistence', id, COALESCE(object_type,'') || ': ' || COALESCE(name,''),
                       COALESCE(destination, query, filter_ref || ' -> ' || consumer_ref), NULL,
                       NULL, NULL, NULL, NULL, NULL FROM wmi_persistence
            ) x ON x.tbl = s.artifact_table AND x.id = s.artifact_id
            LEFT JOIN tags t ON t.artifact_table = s.artifact_table AND t.artifact_id = x.id
            WHERE s.artifact_table != 'processes'
            ORDER BY s.score DESC, s.artifact_table, x.name
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["score"] = r.GetInt32(0);
            d["band"] = r.GetString(1);
            d["verdict"] = r.GetString(2);
            d["matchedRules"] = r.IsDBNull(3) ? "[]" : r.GetString(3);
            d["table"] = r.GetString(4);
            d["id"] = r.GetInt64(5);
            d["name"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["detail"] = r.IsDBNull(7) ? null : r.GetString(7);
            d["account"] = r.IsDBNull(8) ? null : r.GetString(8);
            d["binaryPath"] = r.IsDBNull(9) ? null : r.GetString(9);
            d["signatureStatus"] = r.IsDBNull(10) ? null : r.GetString(10);
            d["signer"] = r.IsDBNull(11) ? null : r.GetString(11);
            d["md5"] = r.IsDBNull(12) ? null : r.GetString(12);
            d["sha256"] = r.IsDBNull(13) ? null : r.GetString(13);
            d["tag"] = r.IsDBNull(14) ? null : r.GetString(14);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>Network connections joined with process MRI scores where resolvable.</summary>
    public static List<ExpandoObject> GetNetwork(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT n.id, n.protocol, n.local_address, n.local_port, n.remote_address,
                   n.remote_port, n.state, n.pid, n.process_name, n.process_path,
                   n.creation_time_utc, s.score, s.band
            FROM network_connections n
            LEFT JOIN processes p ON p.pid = n.pid AND p.name = n.process_name
            LEFT JOIN mri_scores s ON s.artifact_table = 'processes' AND s.artifact_id = p.id
            ORDER BY COALESCE(s.score, 0) DESC, n.protocol, n.remote_address
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["id"] = r.GetInt64(0);
            d["protocol"] = r.IsDBNull(1) ? null : r.GetString(1);
            d["localAddress"] = r.IsDBNull(2) ? null : r.GetString(2);
            d["localPort"] = r.IsDBNull(3) ? null : r.GetInt64(3);
            d["remoteAddress"] = r.IsDBNull(4) ? null : r.GetString(4);
            d["remotePort"] = r.IsDBNull(5) ? null : r.GetInt64(5);
            d["state"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["pid"] = r.IsDBNull(7) ? null : r.GetInt64(7);
            d["processName"] = r.IsDBNull(8) ? null : r.GetString(8);
            d["processPath"] = r.IsDBNull(9) ? null : r.GetString(9);
            d["creationTimeUtc"] = r.IsDBNull(10) ? null : r.GetString(10);
            d["score"] = r.IsDBNull(11) ? null : r.GetInt32(11);
            d["band"] = r.IsDBNull(12) ? null : r.GetString(12);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>
    /// Timeline events, optionally clamped to a pivot window. Only dated events
    /// exist in the table — unknown timestamps are never substituted.
    /// </summary>
    public static List<ExpandoObject> GetTimeline(SqliteConnection conn, string? fromUtc = null, string? toUtc = null)
    {
        using var cmd = conn.CreateCommand();
        var where = "";
        if (fromUtc != null && toUtc != null)
        {
            where = "WHERE ts_utc >= $from AND ts_utc <= $to";
            cmd.Parameters.AddWithValue("$from", fromUtc);
            cmd.Parameters.AddWithValue("$to", toUtc);
        }
        cmd.CommandText = $"""
            SELECT id, ts_utc, source, category, summary, detail, artifact_table, artifact_id
            FROM timeline {where}
            ORDER BY ts_utc DESC
            LIMIT 20000
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["id"] = r.GetInt64(0);
            d["tsUtc"] = r.IsDBNull(1) ? null : r.GetString(1);
            d["source"] = r.IsDBNull(2) ? null : r.GetString(2);
            d["category"] = r.IsDBNull(3) ? null : r.GetString(3);
            d["summary"] = r.IsDBNull(4) ? null : r.GetString(4);
            d["detail"] = r.IsDBNull(5) ? null : r.GetString(5);
            d["artifactTable"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["artifactId"] = r.IsDBNull(7) ? null : r.GetInt64(7);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>Event-rule findings (log cleared, sprays, suspicious installs...).</summary>
    public static List<ExpandoObject> GetFindings(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, rule, severity, summary, detail, ts_utc, artifact_table, artifact_id
            FROM findings
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 ELSE 3 END, ts_utc
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["id"] = r.GetInt64(0);
            d["rule"] = r.GetString(1);
            d["severity"] = r.GetString(2);
            d["summary"] = r.GetString(3);
            d["detail"] = r.IsDBNull(4) ? null : r.GetString(4);
            d["tsUtc"] = r.IsDBNull(5) ? null : r.GetString(5);
            d["artifactTable"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["artifactId"] = r.IsDBNull(7) ? null : r.GetInt64(7);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>Parsed event-log rows, filterable by channel / event id / text.</summary>
    public static List<ExpandoObject> GetEvents(SqliteConnection conn,
        string? channel = null, long? eventId = null, string? contains = null, int limit = 5000)
    {
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (channel != null) { where.Add("channel = $ch"); cmd.Parameters.AddWithValue("$ch", channel); }
        if (eventId != null) { where.Add("event_id = $eid"); cmd.Parameters.AddWithValue("$eid", eventId); }
        if (contains != null) { where.Add("(summary LIKE $q OR event_data LIKE $q)"); cmd.Parameters.AddWithValue("$q", $"%{contains}%"); }
        cmd.Parameters.AddWithValue("$lim", limit);
        cmd.CommandText = $"""
            SELECT id, ts_utc, channel, provider, event_id, level, computer, user_sid, summary
            FROM event_logs
            {(where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "")}
            ORDER BY ts_utc DESC
            LIMIT $lim
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["id"] = r.GetInt64(0);
            d["tsUtc"] = r.IsDBNull(1) ? null : r.GetString(1);
            d["channel"] = r.IsDBNull(2) ? null : r.GetString(2);
            d["provider"] = r.IsDBNull(3) ? null : r.GetString(3);
            d["eventId"] = r.GetInt64(4);
            d["level"] = r.IsDBNull(5) ? null : r.GetString(5);
            d["computer"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["userSid"] = r.IsDBNull(7) ? null : r.GetString(7);
            d["summary"] = r.IsDBNull(8) ? null : r.GetString(8);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>Full event detail (event_data JSON) for a single row.</summary>
    public static Dictionary<string, object?>? GetEventDetail(SqliteConnection conn, long id)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT ts_utc, channel, provider, event_id, level, computer, user_sid, summary, event_data FROM event_logs WHERE id = $id";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new Dictionary<string, object?>
        {
            ["tsUtc"] = r.IsDBNull(0) ? null : r.GetString(0),
            ["channel"] = r.IsDBNull(1) ? null : r.GetString(1),
            ["provider"] = r.IsDBNull(2) ? null : r.GetString(2),
            ["eventId"] = r.GetInt64(3),
            ["level"] = r.IsDBNull(4) ? null : r.GetString(4),
            ["computer"] = r.IsDBNull(5) ? null : r.GetString(5),
            ["userSid"] = r.IsDBNull(6) ? null : r.GetString(6),
            ["summary"] = r.IsDBNull(7) ? null : r.GetString(7),
            ["eventData"] = r.IsDBNull(8) ? null : r.GetString(8),
        };
    }

    /// <summary>Execution-evidence rollup: prefetch + shimcache + amcache counts.</summary>
    public static List<ExpandoObject> GetExecutionEvidence(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT 'prefetch' AS src, executable AS name, last_run_utc AS ts,
                   'runs: ' || COALESCE(run_count, '?') AS detail, id
            FROM prefetch
            UNION ALL
            SELECT 'shimcache', path, last_modified_utc,
                   'mtime (presence evidence, NOT execution time)' ||
                   CASE WHEN executed = 1 THEN ' — Win7 exec flag SET' ELSE '' END, id
            FROM shimcache
            UNION ALL
            SELECT 'amcache:' || entry_type, COALESCE(path, name), link_date_utc,
                   'sha1: ' || COALESCE(sha1, '-') ||
                   CASE WHEN driver_signed = 0 THEN ' — UNSIGNED DRIVER' ELSE '' END, id
            FROM amcache
            ORDER BY ts DESC
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject();
            var d = (IDictionary<string, object?>)row;
            d["source"] = r.GetString(0);
            d["name"] = r.IsDBNull(1) ? null : r.GetString(1);
            d["tsUtc"] = r.IsDBNull(2) ? null : r.GetString(2);
            d["detail"] = r.IsDBNull(3) ? null : r.GetString(3);
            d["id"] = r.GetInt64(4);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>$MFT entries, filterable by filename/path substring; deleted-first.</summary>
    public static List<ExpandoObject> GetMftEntries(SqliteConnection conn, string? contains = null, bool deletedOnly = false, int limit = 5000)
    {
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (deletedOnly) where.Add("in_use = 0");
        if (contains != null) { where.Add("(file_name LIKE $q OR full_path LIKE $q)"); cmd.Parameters.AddWithValue("$q", $"%{contains}%"); }
        cmd.Parameters.AddWithValue("$lim", limit);
        cmd.CommandText = $"""
            SELECT record_number, in_use, is_directory, file_name, full_path,
                   si_created_utc, si_modified_utc, fn_created_utc, logical_size
            FROM mft_entries
            {(where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "")}
            ORDER BY in_use ASC, si_modified_utc DESC
            LIMIT $lim
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject(); var d = (IDictionary<string, object?>)row;
            d["recordNumber"] = r.GetInt64(0);
            d["inUse"] = r.GetInt64(1) == 1;
            d["isDirectory"] = r.GetInt64(2) == 1;
            d["fileName"] = r.IsDBNull(3) ? null : r.GetString(3);
            d["fullPath"] = r.IsDBNull(4) ? null : r.GetString(4);
            d["siCreatedUtc"] = r.IsDBNull(5) ? null : r.GetString(5);
            d["siModifiedUtc"] = r.IsDBNull(6) ? null : r.GetString(6);
            d["fnCreatedUtc"] = r.IsDBNull(7) ? null : r.GetString(7);
            d["logicalSize"] = r.IsDBNull(8) ? null : r.GetInt64(8);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>USN change-journal records, filterable by name/reason substring; newest first.</summary>
    public static List<ExpandoObject> GetUsnRecords(SqliteConnection conn, string? contains = null, int limit = 5000)
    {
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (contains != null) { where.Add("(file_name LIKE $q OR reasons LIKE $q)"); cmd.Parameters.AddWithValue("$q", $"%{contains}%"); }
        cmd.Parameters.AddWithValue("$lim", limit);
        cmd.CommandText = $"""
            SELECT ts_utc, file_name, reasons, usn, file_ref, parent_ref
            FROM usn_journal
            {(where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "")}
            ORDER BY ts_utc DESC, usn DESC
            LIMIT $lim
            """;
        var rows = new List<ExpandoObject>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var row = new ExpandoObject(); var d = (IDictionary<string, object?>)row;
            d["tsUtc"] = r.IsDBNull(0) ? null : r.GetString(0);
            d["fileName"] = r.IsDBNull(1) ? null : r.GetString(1);
            d["reasons"] = r.IsDBNull(2) ? null : r.GetString(2);
            d["usn"] = r.IsDBNull(3) ? null : r.GetInt64(3);
            d["fileRef"] = r.IsDBNull(4) ? null : r.GetInt64(4);
            d["parentRef"] = r.IsDBNull(5) ? null : r.GetInt64(5);
            rows.Add(row);
        }
        return rows;
    }

    /// <summary>NSRL bloom + org baseline + known-bad list (all optional layers).</summary>
    public static IWhitelist LoadWhitelist(Action<string>? progress = null)
    {
        var dir = FindConfigDir("Whitelist");
        if (dir == null)
        {
            progress?.Invoke("whitelist: Configuration/Whitelist not found — trust ladder runs on signer rules only");
            return new EmptyWhitelist();
        }
        var wl = HawkWhitelist.LoadFrom(dir);
        if (wl.IsEmpty)
        {
            progress?.Invoke("whitelist: no nsrl.bloom / org-baseline.json yet — run `hawk whitelist build` (see Configuration/Whitelist/README.md)");
            return wl;
        }
        progress?.Invoke($"whitelist: NSRL={wl.NsrlCount:N0} baseline={wl.BaselineCount:N0} known-bad={wl.KnownBadCount:N0}");
        return wl;
    }

    private static string? FindMriConfig()
    {
        var dir = FindConfigDir("MRI");
        if (dir == null) return null;
        var path = Path.Combine(dir, "mri-config.json");
        return File.Exists(path) ? path : null;
    }

    /// <summary>
    /// Resolves Configuration/&lt;sub&gt;: HAWK_CONFIG env override first (tests,
    /// portable deployments), then next to the exe (dist), then the repo layout.
    /// </summary>
    public static string? FindConfigDir(string sub)
    {
        var exeDir = AppContext.BaseDirectory;
        var envRoot = Environment.GetEnvironmentVariable("HAWK_CONFIG");
        var candidates = new[]
        {
            envRoot == null ? null : Path.Combine(envRoot, sub),
            Path.Combine(exeDir, "Configuration", sub),
            // repo layout fallback: Analyzer/src/Hawk.Analyzer/bin/<cfg>/net8.0-windows → HawkSuite
            Path.Combine(exeDir, "..", "..", "..", "..", "..", "..", "Configuration", sub),
        };
        return candidates.Where(c => c != null).Select(c => Path.GetFullPath(c!)).FirstOrDefault(Directory.Exists);
    }
}
