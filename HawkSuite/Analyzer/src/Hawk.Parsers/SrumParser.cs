using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Hawk.Core;
using Microsoft.Data.Sqlite;
using Microsoft.Isam.Esent.Interop;

namespace Hawk.Parsers;

/// <summary>
/// Parses SRUM (raw/srum/SRUDB.dat) - the System Resource Usage Monitor ESE
/// database - via ManagedEsent. Extracts the high-value providers:
///   network_data  per-app bytes sent/received per interface,
///   app_resource  per-app CPU/IO usage,
///   network_conn  per-app connection start/duration.
/// AppId/UserId integers are resolved through SruDbIdMapTable (app path/package
/// and SID). Unlike amcache, SRUM rows carry REAL host-activity timestamps, so
/// they are strong timeline + exfil-volume evidence.
///
/// Tolerant by contract: a missing SRUDB.dat is a no-op; recovery/parse failure
/// logs a warning and returns 0. Recovery runs on a private copy so the sealed
/// evidence files are never mutated.
/// </summary>
public class SrumParser : IRawArtifactParser
{
    public string Name => "srum";

    private static readonly (string Guid, string Label)[] Providers =
    {
        ("{973F5D5C-1D90-4944-BE8E-24B94231A174}", "network_data"),
        ("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "app_resource"),
        ("{DD6636C4-8929-4683-974E-22C046A43763}", "network_conn"),
    };

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var srumDir = Path.Combine(sessionDir, "raw", "srum");
        var dbPath = Path.Combine(srumDir, "SRUDB.dat");
        if (!File.Exists(dbPath)) return 0;

        // ESE recovery needs a writable working dir and replays logs INTO the
        // database, so operate on a private copy - never mutate sealed evidence.
        var work = Path.Combine(Path.GetTempPath(), "hawk_srum_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        try
        {
            foreach (var f in Directory.GetFiles(srumDir))
                File.Copy(f, Path.Combine(work, Path.GetFileName(f)), true);
            var workDb = Path.Combine(work, "SRUDB.dat");

            using var instance = new Instance("hawk_srum_" + Guid.NewGuid().ToString("N")[..8]);
            instance.Parameters.Recovery = true;            // replay SRU*.log to recover a dirty (VSS-copied) db
            instance.Parameters.CircularLog = true;         // SRUM uses circular logging
            instance.Parameters.BaseName = "sru";
            instance.Parameters.SystemDirectory = work;
            instance.Parameters.LogFileDirectory = work;
            instance.Parameters.TempDirectory = work;
            instance.Parameters.CreatePathIfNotExist = true;
            try { instance.Init(); }
            catch (EsentErrorException ex) { progress?.Invoke($"WARNING: srum recovery/init failed ({ex.Error}); skipping"); return 0; }

            using var session = new Session(instance);
            JET_DBID dbid;
            try
            {
                Api.JetAttachDatabase(session, workDb, AttachDatabaseGrbit.DeleteCorruptIndexes);
                Api.JetOpenDatabase(session, workDb, null, out dbid, OpenDatabaseGrbit.None);
            }
            catch (EsentErrorException ex) { progress?.Invoke($"WARNING: srum attach failed ({ex.Error}); skipping"); return 0; }

            var idMap = ReadIdMap(session, dbid, progress);
            var tableNames = new HashSet<string>(Api.GetTableNames(session, dbid), StringComparer.OrdinalIgnoreCase);

            using var tx = conn.BeginTransaction();
            using var insert = conn.CreateCommand();
            insert.CommandText = """
                INSERT INTO srum (provider, ts_utc, app, user_sid, bytes_sent, bytes_recvd, interface_luid, extra)
                VALUES ($p,$ts,$app,$u,$bs,$br,$luid,$x)
                """;
            var pP = P(insert, "$p"); var pTs = P(insert, "$ts"); var pApp = P(insert, "$app");
            var pU = P(insert, "$u"); var pBs = P(insert, "$bs"); var pBr = P(insert, "$br");
            var pLuid = P(insert, "$luid"); var pX = P(insert, "$x");

            var extraCols = new[] { "ConnectedTime", "ConnectStartTime", "ForegroundBytesRead",
                "ForegroundBytesWritten", "BackgroundBytesRead", "BackgroundBytesWritten", "L2ProfileId" };
            var n = 0;

            foreach (var (guid, label) in Providers)
            {
                if (!tableNames.Contains(guid)) continue;
                try
                {
                    using var table = new Table(session, dbid, guid, OpenTableGrbit.ReadOnly);
                    var cols = Api.GetColumnDictionary(session, table);
                    if (!Api.TryMoveFirst(session, table)) continue;
                    do
                    {
                        try
                        {
                            var appId = ColInt(session, table, cols, "AppId");
                            var userId = ColInt(session, table, cols, "UserId");
                            var ts = ColTimestamp(session, table, cols, "TimeStamp");

                            var extra = new Dictionary<string, object?>();
                            foreach (var ek in extraCols)
                                if (cols.ContainsKey(ek)) { var v = ColLong(session, table, cols, ek); if (v.HasValue) extra[ek] = v.Value; }

                            pP.Value = label;
                            pTs.Value = (object?)ts?.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") ?? DBNull.Value;
                            pApp.Value = appId.HasValue && idMap.TryGetValue(appId.Value, out var a) ? a : DBNull.Value;
                            pU.Value = userId.HasValue && idMap.TryGetValue(userId.Value, out var u2) ? u2 : DBNull.Value;
                            pBs.Value = (object?)ColLong(session, table, cols, "BytesSent") ?? DBNull.Value;
                            pBr.Value = (object?)ColLong(session, table, cols, "BytesRecvd") ?? DBNull.Value;
                            pLuid.Value = (object?)ColLong(session, table, cols, "InterfaceLuid") ?? DBNull.Value;
                            pX.Value = extra.Count > 0 ? JsonSerializer.Serialize(extra) : (object)DBNull.Value;
                            insert.ExecuteNonQuery();
                            n++;
                        }
                        catch { /* skip a single bad row, keep going */ }
                    } while (Api.TryMoveNext(session, table));
                }
                catch (Exception ex) { progress?.Invoke($"WARNING: srum table {label} read failed: {ex.Message}"); }
            }
            tx.Commit();
            progress?.Invoke($"parsed srum: {n} records");
            return n;
        }
        catch (Exception ex) { progress?.Invoke($"WARNING: srum parse failed: {ex.Message}"); return 0; }
        finally { try { Directory.Delete(work, true); } catch { } }
    }

    private static Dictionary<int, string> ReadIdMap(Session session, JET_DBID dbid, Action<string>? progress)
    {
        var map = new Dictionary<int, string>();
        try
        {
            using var table = new Table(session, dbid, "SruDbIdMapTable", OpenTableGrbit.ReadOnly);
            var cols = Api.GetColumnDictionary(session, table);
            if (!cols.ContainsKey("IdIndex") || !cols.ContainsKey("IdBlob")) return map;
            if (!Api.TryMoveFirst(session, table)) return map;
            do
            {
                try
                {
                    var idx = Api.RetrieveColumnAsInt32(session, table, cols["IdIndex"]);
                    var blob = Api.RetrieveColumn(session, table, cols["IdBlob"]);
                    if (idx.HasValue && blob is { Length: > 0 }) map[idx.Value] = DecodeId(blob);
                }
                catch { }
            } while (Api.TryMoveNext(session, table));
        }
        catch (Exception ex) { progress?.Invoke($"srum: id-map unreadable: {ex.Message}"); }
        return map;
    }

    /// <summary>IdBlob is a binary SID (user) or a UTF-16LE string (app path/package/service).</summary>
    private static string DecodeId(byte[] blob)
    {
        if (blob.Length >= 8 && blob[0] == 1)                 // SID revision byte
        {
            int subCount = blob[1];
            if (blob.Length == 8 + 4 * subCount)
            {
                try { return new SecurityIdentifier(blob, 0).Value; } catch { }
            }
        }
        try
        {
            var s = Encoding.Unicode.GetString(blob).TrimEnd('\0');
            if (!string.IsNullOrWhiteSpace(s)) return s;
        }
        catch { }
        return Convert.ToHexString(blob);
    }

    private static int? ColInt(Session s, Table t, IDictionary<string, JET_COLUMNID> c, string name)
        => c.TryGetValue(name, out var id) ? Api.RetrieveColumnAsInt32(s, t, id) : null;

    private static long? ColLong(Session s, Table t, IDictionary<string, JET_COLUMNID> c, string name)
    {
        if (!c.TryGetValue(name, out var id)) return null;
        try { return Api.RetrieveColumnAsInt64(s, t, id); }
        catch { try { return Api.RetrieveColumnAsInt32(s, t, id); } catch { return null; } }
    }

    private static DateTime? ColTimestamp(Session s, Table t, IDictionary<string, JET_COLUMNID> c, string name)
    {
        if (!c.TryGetValue(name, out var id)) return null;
        try { return Api.RetrieveColumnAsDateTime(s, t, id); }
        catch
        {
            try { var l = Api.RetrieveColumnAsInt64(s, t, id); if (l is > 0) return DateTime.FromFileTimeUtc(l.Value); } catch { }
        }
        return null;
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
