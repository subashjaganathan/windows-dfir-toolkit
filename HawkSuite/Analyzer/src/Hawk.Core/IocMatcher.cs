using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Matches an indicator set against the imported session and writes 'ioc-*'
/// rows into the findings table. Indicators load from Configuration/IOC:
///   *.json  → { "ips":[...], "domains":[...], "sha256":[...], "md5":[...] }
///   *.csv   → "type,value[,note]" rows (type ∈ ip|domain|sha256|md5)
///   *.txt   → one indicator per line, type auto-detected by shape
///
/// Matching is exact (hashes, IPs) or suffix-aware (domains: an indicator
/// "evil.com" matches "evil.com" and "*.evil.com"). Private/loopback IPs in
/// the indicator set are ignored — they would match half the session and are
/// almost always a bad indicator list, not a real lead.
/// </summary>
public static class IocMatcher
{
    public static int Match(SqliteConnection conn, Action<string>? progress = null)
    {
        var dir = AnalysisService.FindConfigDir("IOC");
        if (dir == null) return 0;

        var set = IndicatorSet.LoadFrom(dir, progress);
        if (set.IsEmpty) return 0;
        progress?.Invoke($"IOC set: {set.Ips.Count} IPs, {set.Domains.Count} domains, {set.Hashes.Count} hashes");

        var hits = new List<Finding>();
        hits.AddRange(MatchNetwork(conn, set));
        hits.AddRange(MatchDomains(conn, set));
        hits.AddRange(MatchHashes(conn, set));

        if (hits.Count == 0) { progress?.Invoke("IOC matching: no hits"); return 0; }

        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO findings (rule, severity, summary, detail, ts_utc, artifact_table, artifact_id)
            VALUES ($rule, 'critical', $sum, $det, $ts, $tbl, $id)
            """;
        var pRule = P(cmd, "$rule"); var pSum = P(cmd, "$sum"); var pDet = P(cmd, "$det");
        var pTs = P(cmd, "$ts"); var pTbl = P(cmd, "$tbl"); var pId = P(cmd, "$id");
        foreach (var h in hits)
        {
            pRule.Value = h.Rule; pSum.Value = h.Summary; pDet.Value = (object?)h.Detail ?? DBNull.Value;
            pTs.Value = (object?)h.Ts ?? DBNull.Value;
            pTbl.Value = (object?)h.Table ?? DBNull.Value; pId.Value = (object?)h.Id ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        progress?.Invoke($"IOC matching: {hits.Count} hits");
        return hits.Count;
    }

    private sealed record Finding(string Rule, string Summary, string? Detail, string? Ts, string? Table, long? Id);

    private static IEnumerable<Finding> MatchNetwork(SqliteConnection conn, IndicatorSet set)
    {
        if (set.Ips.Count == 0) yield break;
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, remote_address, remote_port, process_name, creation_time_utc FROM network_connections WHERE remote_address IS NOT NULL";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var ip = r.GetString(1);
            if (!set.Ips.Contains(ip)) continue;
            yield return new Finding("ioc-network-ip",
                $"Network connection to known-bad IP {ip}",
                $"port {(r.IsDBNull(2) ? "?" : r.GetInt64(2))}, process {(r.IsDBNull(3) ? "?" : r.GetString(3))}"
                    + IocNote(set, ip),
                r.IsDBNull(4) ? null : r.GetString(4), "network_connections", r.GetInt64(0));
        }
    }

    private static IEnumerable<Finding> MatchDomains(SqliteConnection conn, IndicatorSet set)
    {
        if (set.Domains.Count == 0) yield break;
        // dns_cache + browser history land in the generic artifact_records table.
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, artifact_type, record_json FROM artifact_records WHERE artifact_type IN ('dns_cache','browser_history')";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var json = r.GetString(2);
            string? hay = null;
            try
            {
                using var doc = JsonDocument.Parse(json);
                foreach (var prop in new[] { "entry", "name", "url", "host", "domain", "query" })
                    if (doc.RootElement.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String)
                    { hay = v.GetString(); if (!string.IsNullOrEmpty(hay)) break; }
            }
            catch { continue; }
            if (hay == null) continue;
            var host = ExtractHost(hay).ToLowerInvariant();
            var matched = set.MatchDomain(host);
            if (matched == null) continue;
            yield return new Finding("ioc-domain",
                $"Known-bad domain observed: {matched}",
                $"in {r.GetString(1)}: {Truncate(hay, 200)}" + IocNote(set, matched),
                null, "artifact_records", r.GetInt64(0));
        }
    }

    private static IEnumerable<Finding> MatchHashes(SqliteConnection conn, IndicatorSet set)
    {
        if (set.Hashes.Count == 0) yield break;
        var sources = new (string Table, string HashCol, string NameCol)[]
        {
            ("processes", "sha256", "name"), ("processes", "md5", "name"),
            ("services", "sha256", "name"), ("services", "md5", "name"),
            ("amcache", "sha1", "name"),
        };
        foreach (var (table, hashCol, nameCol) in sources)
        {
            if (!ColumnExists(conn, table, hashCol)) continue;
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT id, {hashCol}, {nameCol} FROM {table} WHERE {hashCol} IS NOT NULL";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var hash = r.GetString(1).ToLowerInvariant();
                if (!set.Hashes.Contains(hash)) continue;
                yield return new Finding("ioc-hash",
                    $"Known-bad file hash in {table}: {(r.IsDBNull(2) ? "?" : r.GetString(2))}",
                    $"{hashCol}={hash}" + IocNote(set, hash),
                    null, table, r.GetInt64(0));
            }
        }
    }

    private static string IocNote(IndicatorSet set, string key) =>
        set.Notes.TryGetValue(key, out var n) && !string.IsNullOrEmpty(n) ? $" — {n}" : "";

    private static string ExtractHost(string s)
    {
        var v = s.Trim();
        if (v.Contains("://")) v = v[(v.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var slash = v.IndexOf('/'); if (slash >= 0) v = v[..slash];
        var colon = v.IndexOf(':'); if (colon >= 0) v = v[..colon];
        return v;
    }

    private static bool ColumnExists(SqliteConnection conn, string table, string col)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table})";
        using var r = cmd.ExecuteReader();
        while (r.Read()) if (r.GetString(1).Equals(col, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "...";
    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }

    // ---------------------------------------------------------------- set
    private sealed class IndicatorSet
    {
        public HashSet<string> Ips { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Domains { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Hashes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> Notes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool IsEmpty => Ips.Count == 0 && Domains.Count == 0 && Hashes.Count == 0;

        /// <summary>Returns the matching indicator (exact or parent suffix), or null.</summary>
        public string? MatchDomain(string host)
        {
            if (string.IsNullOrEmpty(host)) return null;
            if (Domains.Contains(host)) return host;
            var i = host.IndexOf('.');
            while (i >= 0 && i < host.Length - 1)
            {
                var parent = host[(i + 1)..];
                if (Domains.Contains(parent)) return parent;
                i = host.IndexOf('.', i + 1);
            }
            return null;
        }

        public static IndicatorSet LoadFrom(string dir, Action<string>? progress)
        {
            var set = new IndicatorSet();
            foreach (var file in Directory.EnumerateFiles(dir))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                // known-bad-handles.json ships as MRI content, not an IOC list
                if (Path.GetFileName(file).Equals("known-bad-handles.json", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    switch (ext)
                    {
                        case ".json": set.LoadJson(file); break;
                        case ".csv": set.LoadCsv(file); break;
                        case ".txt": set.LoadTxt(file); break;
                    }
                }
                catch (Exception ex) { progress?.Invoke($"WARNING: IOC file {Path.GetFileName(file)} skipped: {ex.Message}"); }
            }
            return set;
        }

        private void LoadJson(string file)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file));
            void Pull(string prop, Action<string> add)
            {
                if (doc.RootElement.TryGetProperty(prop, out var arr) && arr.ValueKind == JsonValueKind.Array)
                    foreach (var e in arr.EnumerateArray())
                        if (e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 } v) add(v.Trim());
            }
            Pull("ips", v => AddIp(v)); Pull("domains", v => AddDomain(v));
            Pull("sha256", v => AddHash(v)); Pull("md5", v => AddHash(v));
            Pull("sha1", v => AddHash(v)); Pull("hashes", v => AddHash(v));
        }

        private void LoadCsv(string file)
        {
            foreach (var raw in File.ReadLines(file))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("type", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = line.Split(',', 3);
                if (parts.Length < 2) continue;
                var type = parts[0].Trim().ToLowerInvariant();
                var value = parts[1].Trim();
                var note = parts.Length > 2 ? parts[2].Trim() : null;
                switch (type)
                {
                    case "ip": AddIp(value, note); break;
                    case "domain": case "host": AddDomain(value, note); break;
                    case "sha256": case "md5": case "sha1": case "hash": AddHash(value, note); break;
                }
            }
        }

        private void LoadTxt(string file)
        {
            foreach (var raw in File.ReadLines(file))
            {
                var v = raw.Trim();
                if (v.Length == 0 || v.StartsWith('#')) continue;
                if (v.All(c => Uri.IsHexDigit(c)) && v.Length is 32 or 40 or 64) AddHash(v);
                else if (System.Net.IPAddress.TryParse(v, out _)) AddIp(v);
                else if (v.Contains('.')) AddDomain(v);
            }
        }

        private void AddIp(string v, string? note = null)
        {
            if (!System.Net.IPAddress.TryParse(v, out var ip)) return;
            if (IsNonRoutable(ip)) return;   // refuse private/loopback indicators
            Ips.Add(v); if (note != null) Notes[v] = note;
        }
        private void AddDomain(string v, string? note = null)
        {
            v = v.ToLowerInvariant().TrimStart('*', '.');
            if (v.Length == 0) return;
            Domains.Add(v); if (note != null) Notes[v] = note;
        }
        private void AddHash(string v, string? note = null)
        {
            v = v.Trim().ToLowerInvariant();
            if (v.Length is not (32 or 40 or 64) || !v.All(Uri.IsHexDigit)) return;
            Hashes.Add(v); if (note != null) Notes[v] = note;
        }

        private static bool IsNonRoutable(System.Net.IPAddress ip)
        {
            if (System.Net.IPAddress.IsLoopback(ip)) return true;
            var b = ip.GetAddressBytes();
            if (b.Length == 4)
                return b[0] == 10
                    || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                    || (b[0] == 192 && b[1] == 168)
                    || (b[0] == 169 && b[1] == 254)
                    || b[0] == 0;
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
        }
    }
}
