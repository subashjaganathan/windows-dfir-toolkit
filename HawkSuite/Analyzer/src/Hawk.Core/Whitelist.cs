using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Production whitelist: NSRL bloom filter (known-good) + org baseline (exact
/// match) + known-bad IOC hash list. Evaluation order is contractual
/// (Configuration/Whitelist/README.md): known-bad wins over everything.
/// </summary>
public sealed class HawkWhitelist : IWhitelist
{
    private readonly BloomFilter? _nsrl;
    private readonly HashSet<string> _baselineMd5;
    private readonly HashSet<string> _knownBadMd5;

    public long NsrlCount => _nsrl?.ItemCount ?? 0;
    public int BaselineCount => _baselineMd5.Count;
    public int KnownBadCount => _knownBadMd5.Count;
    public bool IsEmpty => _nsrl == null && _baselineMd5.Count == 0 && _knownBadMd5.Count == 0;

    private HawkWhitelist(BloomFilter? nsrl, HashSet<string> baseline, HashSet<string> knownBad)
    {
        _nsrl = nsrl; _baselineMd5 = baseline; _knownBadMd5 = knownBad;
    }

    public bool IsKnownGood(string md5)
    {
        var h = md5.ToLowerInvariant();
        return _baselineMd5.Contains(h) || (_nsrl?.MightContain(h) ?? false);
    }

    public bool IsKnownBad(string md5) => _knownBadMd5.Contains(md5.ToLowerInvariant());

    /// <summary>
    /// Loads whatever exists under Configuration/Whitelist: nsrl.bloom,
    /// org-baseline.json, known-bad-md5.txt. All optional — missing files
    /// simply leave that layer empty.
    /// </summary>
    public static HawkWhitelist LoadFrom(string whitelistDir)
    {
        BloomFilter? nsrl = null;
        var bloomPath = Path.Combine(whitelistDir, "nsrl.bloom");
        if (File.Exists(bloomPath)) nsrl = BloomFilter.Load(bloomPath);

        var baseline = new HashSet<string>(StringComparer.Ordinal);
        var baselinePath = Path.Combine(whitelistDir, "org-baseline.json");
        if (File.Exists(baselinePath))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(baselinePath));
            if (doc.RootElement.TryGetProperty("md5", out var arr))
                foreach (var e in arr.EnumerateArray())
                    if (e.GetString() is { Length: 32 } h) baseline.Add(h.ToLowerInvariant());
        }

        var knownBad = new HashSet<string>(StringComparer.Ordinal);
        var knownBadPath = Path.Combine(whitelistDir, "known-bad-md5.txt");
        if (File.Exists(knownBadPath))
            foreach (var line in File.ReadLines(knownBadPath))
            {
                var t = line.Trim().ToLowerInvariant();
                if (t.Length == 32 && t.All(Uri.IsHexDigit)) knownBad.Add(t);
            }

        return new HawkWhitelist(nsrl, baseline, knownBad);
    }
}

/// <summary>
/// Builds nsrl.bloom from NSRL RDS distributions (`hawk whitelist build`).
/// Accepted inputs, autodetected per file:
///   *.db / *.sqlite  — NSRL RDSv3 SQLite (modern minimal set, 2022+)
///   NSRLFile.txt     — legacy RDS CSV ("SHA-1","MD5","CRC32",...)
///   *.txt            — plain text, one MD5 hex per line
/// </summary>
public static class WhitelistBuilder
{
    public static (long count, string bloomPath) Build(
        IReadOnlyList<string> inputs, string outputDir,
        double falsePositiveRate = 1e-4, Action<string>? progress = null)
    {
        foreach (var f in inputs)
            if (!File.Exists(f)) throw new FileNotFoundException(f);
        Directory.CreateDirectory(outputDir);

        // Pass 1 — count, so the filter can be sized before insertion.
        progress?.Invoke("pass 1/2: counting hashes...");
        long total = 0;
        foreach (var f in inputs) total += CountHashes(f, progress);
        if (total == 0) throw new InvalidDataException("no MD5 hashes found in the given inputs");
        progress?.Invoke($"  {total:N0} hashes total");

        // Pass 2 — populate.
        var bloom = BloomFilter.Create(total, falsePositiveRate);
        progress?.Invoke($"pass 2/2: building filter ({bloom.BitCount / 8 / 1024 / 1024.0:F1} MB, k={bloom.HashCount})...");
        long done = 0;
        foreach (var f in inputs)
            foreach (var md5 in EnumerateHashes(f))
            {
                bloom.Add(md5);
                if (++done % 5_000_000 == 0) progress?.Invoke($"  {done:N0} / {total:N0}");
            }

        var bloomPath = Path.Combine(outputDir, "nsrl.bloom");
        bloom.Save(bloomPath);

        var meta = new
        {
            schemaVersion = "1.0",
            builtUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            sources = inputs.Select(Path.GetFileName).ToArray(),
            itemCount = bloom.ItemCount,
            falsePositiveRate,
            bits = bloom.BitCount,
            hashFunctions = bloom.HashCount
        };
        File.WriteAllText(Path.Combine(outputDir, "nsrl.meta.json"),
            JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));

        progress?.Invoke($"done: {bloom.ItemCount:N0} hashes → {bloomPath}");
        return (bloom.ItemCount, bloomPath);
    }

    private static long CountHashes(string file, Action<string>? progress)
    {
        if (IsSqlite(file))
        {
            using var conn = OpenSqlite(file);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT COUNT(DISTINCT md5) FROM {RdsTable(conn)}";
            var n = (long)cmd.ExecuteScalar()!;
            progress?.Invoke($"  {Path.GetFileName(file)}: {n:N0} (RDSv3 SQLite)");
            return n;
        }
        long count = 0;
        foreach (var _ in EnumerateHashes(file)) count++;
        progress?.Invoke($"  {Path.GetFileName(file)}: {count:N0}");
        return count;
    }

    private static IEnumerable<string> EnumerateHashes(string file)
    {
        if (IsSqlite(file))
        {
            using var conn = OpenSqlite(file);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = $"SELECT DISTINCT md5 FROM {RdsTable(conn)}";
            using var r = cmd.ExecuteReader();
            while (r.Read())
                if (!r.IsDBNull(0) && r.GetString(0) is { Length: 32 } h)
                    yield return h.ToLowerInvariant();
            yield break;
        }

        // Text: plain MD5-per-line or legacy NSRLFile.txt CSV. Both handled by
        // scanning each line for its first 32-hex token.
        foreach (var line in File.ReadLines(file))
        {
            var md5 = ExtractMd5(line);
            if (md5 != null) yield return md5;
        }
    }

    /// <summary>First 32-char hex run in the line that is exactly 32 long (skips SHA-1/SHA-256 fields).</summary>
    internal static string? ExtractMd5(string line)
    {
        for (var i = 0; i < line.Length; i++)
        {
            if (!Uri.IsHexDigit(line[i])) continue;
            var start = i;
            while (i < line.Length && Uri.IsHexDigit(line[i])) i++;
            if (i - start == 32) return line.Substring(start, 32).ToLowerInvariant();
        }
        return null;
    }

    private static bool IsSqlite(string file)
    {
        if (new FileInfo(file).Length < 16) return false;
        Span<byte> header = stackalloc byte[16];
        using var fs = File.OpenRead(file);
        fs.ReadExactly(header);
        return System.Text.Encoding.ASCII.GetString(header).StartsWith("SQLite format 3");
    }

    private static SqliteConnection OpenSqlite(string file)
    {
        var conn = new SqliteConnection($"Data Source={file};Mode=ReadOnly");
        conn.Open();
        return conn;
    }

    /// <summary>RDSv3 keeps hashes in FILE; fall back to any table with an md5 column.</summary>
    private static string RdsTable(SqliteConnection conn)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type IN ('table','view')";
        var tables = new List<string>();
        using (var r = cmd.ExecuteReader()) while (r.Read()) tables.Add(r.GetString(0));

        foreach (var t in tables.OrderBy(t => t.Equals("FILE", StringComparison.OrdinalIgnoreCase) ? 0 : 1))
        {
            using var probe = conn.CreateCommand();
            probe.CommandText = $"SELECT * FROM \"{t}\" LIMIT 0";
            try
            {
                using var r = probe.ExecuteReader();
                for (var i = 0; i < r.FieldCount; i++)
                    if (r.GetName(i).Equals("md5", StringComparison.OrdinalIgnoreCase)) return $"\"{t}\"";
            }
            catch (SqliteException) { /* virtual tables etc. */ }
        }
        throw new InvalidDataException("no table with an md5 column found — is this an NSRL RDSv3 database?");
    }
}

/// <summary>
/// Builds org-baseline.json from a session collected on a KNOWN-CLEAN gold
/// image (`hawk baseline create`). Exact-match layer of the trust ladder —
/// Hawk's improvement over Redline, which had no org-level baseline.
/// </summary>
public static class BaselineBuilder
{
    public static (int hashCount, string outputPath) Create(
        string sessionPath, string outputPath, Action<string>? progress = null)
    {
        // Accept either an already-imported hawk.db or a raw .hawk container.
        string dbPath;
        if (sessionPath.EndsWith(".hawk", StringComparison.OrdinalIgnoreCase))
        {
            progress?.Invoke("importing gold-image session...");
            dbPath = new SessionImporter().Import(sessionPath);
        }
        else dbPath = sessionPath;

        using var conn = Db.Open(dbPath);

        string host;
        using (var c = conn.CreateCommand())
        {
            c.CommandText = "SELECT value FROM session WHERE key='hostname'";
            host = c.ExecuteScalar() as string ?? "unknown";
        }

        // Safety net: a "gold image" that contains known-bad hashes is not
        // clean — refuse to launder those into the trusted set.
        var knownBad = AnalysisService.LoadWhitelist();
        var rejected = 0;

        var entries = new List<object>();
        var md5Set = new SortedSet<string>(StringComparer.Ordinal);
        using (var c = conn.CreateCommand())
        {
            c.CommandText = """
                SELECT DISTINCT md5, sha256, path, signer FROM processes
                WHERE md5 IS NOT NULL
                """;
            using var r = c.ExecuteReader();
            while (r.Read())
            {
                var md5 = r.GetString(0).ToLowerInvariant();
                if (knownBad.IsKnownBad(md5))
                {
                    rejected++;
                    progress?.Invoke($"REJECTED known-bad hash {md5} ({(r.IsDBNull(2) ? "?" : r.GetString(2))}) — gold image may be compromised!");
                    continue;
                }
                if (!md5Set.Add(md5)) continue;
                entries.Add(new
                {
                    md5,
                    sha256 = r.IsDBNull(1) ? null : r.GetString(1).ToLowerInvariant(),
                    path = r.IsDBNull(2) ? null : r.GetString(2),
                    signer = r.IsDBNull(3) ? null : r.GetString(3)
                });
            }
        }
        if (md5Set.Count == 0)
            throw new InvalidDataException("session contains no hashed binaries — was the collector run elevated?");
        if (rejected > 0)
            progress?.Invoke($"WARNING: {rejected} known-bad hash(es) excluded. Do NOT trust this image until investigated.");

        var baseline = new
        {
            schemaVersion = "1.0",
            createdUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            sourceHost = host,
            warning = "Baseline must come from a KNOWN-CLEAN gold image. Every hash here is implicitly trusted.",
            md5 = md5Set.ToArray(),
            entries
        };
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        File.WriteAllText(outputPath,
            JsonSerializer.Serialize(baseline, new JsonSerializerOptions { WriteIndented = true }));

        progress?.Invoke($"baseline: {md5Set.Count:N0} unique binaries from {host} → {outputPath}");
        return (md5Set.Count, outputPath);
    }
}
