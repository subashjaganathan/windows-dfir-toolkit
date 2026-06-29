using System.IO.Compression;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>Imports a .hawk session (ZIP) into a SQLite session database.</summary>
public class SessionImporter
{
    // ---- typed-table mappings: artifact json key → table column ---------------
    // Column order defines parameter order. Number=true binds as INTEGER.
    private sealed record Col(string Column, string Key, bool Number = false);

    private static readonly Dictionary<string, (string Table, Col[] Cols)> TypedMaps = new()
    {
        ["processes"] = ("processes", new Col[]
        {
            new("pid", "pid", true), new("ppid", "ppid", true), new("name", "name"),
            new("path", "path"), new("command_line", "commandLine"), new("user", "user"),
            new("session_id", "sessionId", true), new("start_time_utc", "startTimeUtc"),
            new("sha256", "sha256"), new("md5", "md5"),
            new("signature_status", "signatureStatus"), new("signer", "signer"),
            new("parent_name", "parentName"), new("parent_path", "parentPath"),
        }),
        ["services"] = ("services", new Col[]
        {
            new("name", "name"), new("display_name", "displayName"), new("state", "state"),
            new("start_mode", "startMode"), new("account", "account"),
            new("path_name", "pathName"), new("binary_path", "binaryPath"),
            new("sha256", "sha256"), new("md5", "md5"),
            new("signature_status", "signatureStatus"), new("signer", "signer"),
            new("service_dll", "serviceDll"), new("service_dll_md5", "serviceDllMd5"),
            new("service_dll_sha256", "serviceDllSha256"), new("service_dll_signer", "serviceDllSigner"),
            new("service_dll_sig_status", "serviceDllSigStatus"),
            new("service_type", "serviceType"), new("description", "description"),
            new("process_id", "processId", true),
        }),
        ["scheduled_tasks"] = ("scheduled_tasks", new Col[]
        {
            new("task_name", "taskName"), new("task_path", "taskPath"), new("state", "state"),
            new("author", "author"), new("run_as", "runAs"), new("run_level", "runLevel"),
            new("execute", "execute"), new("arguments", "arguments"),
            new("working_directory", "workingDirectory"), new("binary_path", "binaryPath"),
            new("sha256", "sha256"), new("md5", "md5"),
            new("signature_status", "signatureStatus"), new("signer", "signer"),
            new("last_run_time_utc", "lastRunTimeUtc"), new("next_run_time_utc", "nextRunTimeUtc"),
            new("last_task_result", "lastTaskResult"), new("triggers", "triggers"),
        }),
        ["registry_runkeys"] = ("registry_runkeys", new Col[]
        {
            new("key_path", "keyPath"), new("user_sid", "userSid"),
            new("value_name", "valueName"), new("command", "command"),
            new("binary_path", "binaryPath"), new("sha256", "sha256"), new("md5", "md5"),
            new("signature_status", "signatureStatus"), new("signer", "signer"),
        }),
        ["startup_folder"] = ("startup_folder", new Col[]
        {
            new("user", "user"), new("item_path", "itemPath"), new("item_name", "itemName"),
            new("target", "target"), new("target_arguments", "targetArguments"),
            new("sha256", "sha256"), new("md5", "md5"),
            new("signature_status", "signatureStatus"), new("signer", "signer"),
            new("created_utc", "createdUtc"), new("modified_utc", "modifiedUtc"),
        }),
        ["wmi_persistence"] = ("wmi_persistence", new Col[]
        {
            new("object_type", "objectType"), new("name", "name"), new("query", "query"),
            new("query_language", "queryLanguage"), new("event_namespace", "eventNamespace"),
            new("consumer_type", "consumerType"), new("destination", "destination"),
            new("filter_ref", "filterRef"), new("consumer_ref", "consumerRef"),
        }),
        ["network_connections"] = ("network_connections", new Col[]
        {
            new("protocol", "protocol"), new("local_address", "localAddress"),
            new("local_port", "localPort", true), new("remote_address", "remoteAddress"),
            new("remote_port", "remotePort", true), new("state", "state"),
            new("pid", "pid", true), new("process_name", "processName"),
            new("process_path", "processPath"), new("creation_time_utc", "creationTimeUtc"),
        }),
    };

    public string Import(string hawkFile, string? outputDir = null, Action<string>? progress = null,
                         IEnumerable<IRawArtifactParser>? rawParsers = null)
    {
        if (!File.Exists(hawkFile)) throw new FileNotFoundException(hawkFile);
        outputDir ??= Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(hawkFile))!,
            Path.GetFileNameWithoutExtension(hawkFile) + "_analysis");
        Directory.CreateDirectory(outputDir);

        var extractDir = Path.Combine(outputDir, "session");
        DeleteDirectoryWithRetry(extractDir);
        ZipFile.ExtractToDirectory(hawkFile, extractDir);

        // Manifest is mandatory; refuse unknown schema majors.
        var manifestPath = Path.Combine(extractDir, "manifest.json");
        if (!File.Exists(manifestPath))
            throw new InvalidDataException("Not a valid .hawk session: manifest.json missing");
        using var manifest = JsonDocument.Parse(File.ReadAllText(manifestPath));
        var schemaVersion = manifest.RootElement.GetProperty("schemaVersion").GetString() ?? "0";
        if (!schemaVersion.StartsWith("1."))
            throw new InvalidDataException($"Unsupported session schema {schemaVersion} (importer supports 1.x)");

        var dbPath = Path.Combine(outputDir, "hawk.db");
        if (File.Exists(dbPath)) File.Delete(dbPath);   // re-import = fresh observations
        using var conn = Db.Open(dbPath);

        StoreSessionMeta(conn, manifest);

        var artifactDir = Path.Combine(extractDir, "artifacts");
        if (Directory.Exists(artifactDir))
        {
            foreach (var file in Directory.EnumerateFiles(artifactDir, "*.json").OrderBy(f => f))
            {
                var type = Path.GetFileNameWithoutExtension(file);
                try
                {
                    var count = TypedMaps.TryGetValue(type, out var map)
                        ? ImportTyped(conn, file, map.Table, map.Cols)
                        : ImportGeneric(conn, file, type);
                    progress?.Invoke($"imported {type}: {count} records");
                }
                catch (Exception ex)
                {
                    progress?.Invoke($"WARNING: {type} import failed: {ex.Message}");
                }
            }
        }

        // Raw artifact parsers (EVTX, prefetch, shimcache, amcache) — injected
        // by the host app; each writes its own typed table + timeline rows.
        foreach (var parser in rawParsers ?? [])
        {
            try
            {
                var count = parser.Parse(conn, extractDir, progress);
                progress?.Invoke($"parsed {parser.Name}: {count} records");
            }
            catch (Exception ex)
            {
                progress?.Invoke($"WARNING: {parser.Name} parser failed: {ex.Message}");
            }
        }

        var events = BuildTimeline(conn);
        progress?.Invoke($"timeline: {events} dated events");

        return dbPath;
    }

    /// <summary>
    /// Deletes a previous extraction, retrying on transient locks (OneDrive /
    /// Defender sync handles are common on analyst machines).
    /// </summary>
    private static void DeleteDirectoryWithRetry(string dir)
    {
        if (!Directory.Exists(dir)) return;
        foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            File.SetAttributes(f, FileAttributes.Normal);
        for (var attempt = 1; ; attempt++)
        {
            try { Directory.Delete(dir, true); return; }
            catch (IOException) when (attempt < 5) { Thread.Sleep(300 * attempt); }
            catch (UnauthorizedAccessException) when (attempt < 5) { Thread.Sleep(300 * attempt); }
            catch (Exception ex) when (attempt >= 5)
            {
                throw new IOException(
                    $"Cannot clear previous extraction '{dir}' — close any open files " +
                    "and pause cloud-sync (OneDrive) for the analysis folder, then retry.", ex);
            }
        }
    }

    private static void StoreSessionMeta(SqliteConnection conn, JsonDocument manifest)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT OR REPLACE INTO session(key, value) VALUES ($k, $v)";
        var k = cmd.CreateParameter(); k.ParameterName = "$k"; cmd.Parameters.Add(k);
        var v = cmd.CreateParameter(); v.ParameterName = "$v"; cmd.Parameters.Add(v);

        void Put(string key, string value) { k.Value = key; v.Value = value; cmd.ExecuteNonQuery(); }
        var root = manifest.RootElement;
        Put("manifest", root.GetRawText());
        Put("hostname", root.GetProperty("host").GetProperty("hostname").GetString() ?? "");
        Put("role", root.GetProperty("host").TryGetProperty("role", out var r) ? r.GetString() ?? "unknown" : "unknown");
        Put("caseNumber", root.GetProperty("case").GetProperty("caseNumber").GetString() ?? "");
        tx.Commit();
    }

    private static int ImportTyped(SqliteConnection conn, string artifactFile, string table, Col[] cols)
    {
        using var doc = ParseEnvelope(artifactFile);
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText =
            $"INSERT INTO {table} ({string.Join(",", cols.Select(c => c.Column))}) " +
            $"VALUES ({string.Join(",", cols.Select((_, i) => $"$p{i}"))})";
        var ps = cols.Select((_, i) =>
        {
            var p = cmd.CreateParameter(); p.ParameterName = $"$p{i}"; cmd.Parameters.Add(p); return p;
        }).ToArray();

        var n = 0;
        foreach (var rec in doc.RootElement.GetProperty("records").EnumerateArray())
        {
            for (var i = 0; i < cols.Length; i++)
            {
                object val = DBNull.Value;
                if (rec.TryGetProperty(cols[i].Key, out var el) && el.ValueKind != JsonValueKind.Null)
                    val = cols[i].Number && el.ValueKind == JsonValueKind.Number ? el.GetInt64() : el.ToString();
                ps[i].Value = val;
            }
            cmd.ExecuteNonQuery();
            n++;
        }
        tx.Commit();
        return n;
    }

    private static int ImportGeneric(SqliteConnection conn, string artifactFile, string type)
    {
        using var doc = ParseEnvelope(artifactFile);
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO artifact_records (artifact_type, record_json) VALUES ($t, $j)";
        var t = cmd.CreateParameter(); t.ParameterName = "$t"; t.Value = type; cmd.Parameters.Add(t);
        var j = cmd.CreateParameter(); j.ParameterName = "$j"; cmd.Parameters.Add(j);

        var n = 0;
        foreach (var rec in doc.RootElement.GetProperty("records").EnumerateArray())
        {
            j.Value = rec.GetRawText();
            cmd.ExecuteNonQuery();
            n++;
        }
        tx.Commit();
        return n;
    }

    private static JsonDocument ParseEnvelope(string artifactFile)
    {
        var doc = JsonDocument.Parse(File.ReadAllText(artifactFile));
        if (!doc.RootElement.TryGetProperty("records", out _))
            throw new InvalidDataException("artifact envelope has no 'records' array");
        return doc;
    }

    // ---- timeline -------------------------------------------------------------
    // Only DATED events enter the timeline. Unknown timestamps are NEVER
    // substituted (the old toolkit's collection-time fallback corrupted
    // timelines — that bug is contractually banned here).
    private static int BuildTimeline(SqliteConnection conn)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            SELECT start_time_utc, 'processes', 'Execution',
                   'Process started: ' || COALESCE(name,'?') || ' (PID ' || COALESCE(pid,'?') || ')',
                   COALESCE(command_line, path), 'processes', id
            FROM processes WHERE start_time_utc IS NOT NULL;

            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            SELECT creation_time_utc, 'network', 'Network',
                   protocol || ' ' || COALESCE(local_address,'') || ':' || COALESCE(local_port,'')
                            || ' -> ' || COALESCE(remote_address,'-') || ':' || COALESCE(remote_port,'-')
                            || ' [' || COALESCE(state,'') || ']',
                   COALESCE(process_name,'') , 'network_connections', id
            FROM network_connections WHERE creation_time_utc IS NOT NULL;

            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            SELECT last_run_time_utc, 'tasks', 'Persistence',
                   'Task last ran: ' || COALESCE(task_path,'') || COALESCE(task_name,''),
                   COALESCE(execute,'') || ' ' || COALESCE(arguments,''), 'scheduled_tasks', id
            FROM scheduled_tasks WHERE last_run_time_utc IS NOT NULL;

            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            SELECT created_utc, 'startup', 'Persistence',
                   'Startup item created: ' || COALESCE(item_name,''),
                   COALESCE(target, item_path), 'startup_folder', id
            FROM startup_folder WHERE created_utc IS NOT NULL;

            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            SELECT json_extract(record_json, '$.startTimeUtc'), 'logon', 'Authentication',
                   'Logon session: ' || COALESCE(json_extract(record_json, '$.user'), '?')
                                     || ' (' || COALESCE(json_extract(record_json, '$.logonType'), '?') || ')',
                   'logonId ' || COALESCE(json_extract(record_json, '$.logonId'), '?'),
                   'artifact_records', id
            FROM artifact_records
            WHERE artifact_type = 'logon_sessions'
              AND json_extract(record_json, '$.startTimeUtc') IS NOT NULL;
            """;
        cmd.ExecuteNonQuery();
        tx.Commit();

        using var count = conn.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM timeline";
        return Convert.ToInt32(count.ExecuteScalar());
    }
}
