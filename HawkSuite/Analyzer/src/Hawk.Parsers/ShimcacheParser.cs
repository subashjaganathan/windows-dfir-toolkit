using System.Text;
using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses AppCompatCache (shimcache) from the acquired SYSTEM hive
/// (raw/registry/SYSTEM). Formats: Win8.0 ('00ts'), Win8.1 ('10ts'),
/// Win10/11 ('10ts' with 0x30/0x34 header), and Win7 x64 (0xBADC0FEE).
///
/// Forensic semantics matter here: on Win8+, an entry proves the file was
/// PRESENT (and likely examined by the loader), and the timestamp is the
/// file's $SI last-modified — NOT an execution time. Only Win7 carries an
/// execution flag. Rows are therefore stored in their own table and kept
/// OUT of the timeline to avoid implying execution times that aren't there.
/// </summary>
public class ShimcacheParser : IRawArtifactParser
{
    public string Name => "shimcache";

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var hivePath = Path.Combine(sessionDir, "raw", "registry", "SYSTEM");
        if (!File.Exists(hivePath)) return 0;

        var hive = new RegistryHive(hivePath);

        // resolve current control set (Select\Current), default 1
        var controlSet = 1;
        var select = hive.GetKey("Select");
        if (select != null && hive.GetValue(select, "Current")?.AsDword() is uint cur and > 0)
            controlSet = (int)cur;

        var cacheKey = hive.GetKey($"ControlSet{controlSet:D3}\\Control\\Session Manager\\AppCompatCache");
        var blob = cacheKey == null ? null : hive.GetValue(cacheKey, "AppCompatCache")?.Data;
        if (blob == null || blob.Length < 8)
        {
            progress?.Invoke("shimcache: AppCompatCache value not found in SYSTEM hive");
            return 0;
        }

        List<(string path, DateTime? mtime, bool? executed)> entries;
        try
        {
            entries = ParseBlob(blob);
        }
        catch (Exception ex)
        {
            progress?.Invoke($"WARNING: shimcache format not recognized: {ex.Message}");
            return 0;
        }

        using var tx = conn.BeginTransaction();
        using var insert = conn.CreateCommand();
        insert.CommandText = """
            INSERT INTO shimcache (entry_position, path, last_modified_utc, executed, control_set)
            VALUES ($pos, $path, $mtime, $exec, $cs)
            """;
        var pPos = P(insert, "$pos"); var pPath = P(insert, "$path");
        var pMtime = P(insert, "$mtime"); var pExec = P(insert, "$exec"); var pCs = P(insert, "$cs");
        pCs.Value = controlSet;

        var n = 0;
        foreach (var (path, mtime, executed) in entries)
        {
            pPos.Value = n;
            pPath.Value = path;
            pMtime.Value = (object?)mtime?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? DBNull.Value;
            pExec.Value = (object?)executed ?? DBNull.Value;
            insert.ExecuteNonQuery();
            n++;
        }
        tx.Commit();
        return n;
    }

    private static List<(string, DateTime?, bool?)> ParseBlob(byte[] blob)
    {
        var first = BitConverter.ToUInt32(blob, 0);

        // Win10/11: header size 0x30 or 0x34, then '10ts' entries
        if (first is 0x30 or 0x34) return ParseTsEntries(blob, (int)first, "10ts");
        // Win8.1: header 0x80, '10ts' entries
        if (first == 0x80 && HasSig(blob, 0x80, "10ts")) return ParseTsEntries(blob, 0x80, "10ts");
        // Win8.0: header 0x80, '00ts' entries
        if (first == 0x80 && HasSig(blob, 0x80, "00ts")) return ParseTsEntries(blob, 0x80, "00ts");
        // Win7: 0xBADC0FEE header
        if (first == 0xBADC0FEE) return ParseWin7(blob);

        throw new InvalidDataException($"unknown header 0x{first:X8}");
    }

    private static bool HasSig(byte[] blob, int offset, string sig) =>
        blob.Length >= offset + 4 && Encoding.ASCII.GetString(blob, offset, 4) == sig;

    /// <summary>Win8/8.1/10/11 entry stream: sig, u32 unk, u32 size, payload.</summary>
    private static List<(string, DateTime?, bool?)> ParseTsEntries(byte[] blob, int start, string sig)
    {
        var entries = new List<(string, DateTime?, bool?)>();
        var pos = start;
        while (pos + 12 <= blob.Length)
        {
            if (Encoding.ASCII.GetString(blob, pos, 4) != sig) break;
            var entrySize = BitConverter.ToInt32(blob, pos + 8);
            var dataPos = pos + 12;
            if (entrySize <= 0 || dataPos + entrySize > blob.Length) break;

            var p = dataPos;
            var pathLen = BitConverter.ToUInt16(blob, p); p += 2;
            string path = "";
            if (pathLen > 0 && p + pathLen <= dataPos + entrySize)
            {
                path = Encoding.Unicode.GetString(blob, p, pathLen);
                p += pathLen;
            }
            // Win8.x carries u32 insertion/shim flags before the FILETIME; Win10 doesn't
            if (sig == "00ts" || (sig == "10ts" && start == 0x80)) p += 8;   // 2× u32 flags

            DateTime? mtime = null;
            if (p + 8 <= dataPos + entrySize)
            {
                var ft = BitConverter.ToInt64(blob, p);
                if (ft > 0)
                    try { mtime = DateTime.FromFileTimeUtc(ft); } catch (ArgumentOutOfRangeException) { }
            }
            if (path.Length > 0) entries.Add((path, mtime, null));
            pos = dataPos + entrySize;
        }
        return entries;
    }

    /// <summary>Win7 x64: fixed 0x30-byte records; InsertFlags bit 1 = executed.</summary>
    private static List<(string, DateTime?, bool?)> ParseWin7(byte[] blob)
    {
        var entries = new List<(string, DateTime?, bool?)>();
        var count = BitConverter.ToInt32(blob, 4);
        var pos = 0x80;
        for (var i = 0; i < count && pos + 0x30 <= blob.Length; i++, pos += 0x30)
        {
            var pathLen = BitConverter.ToUInt16(blob, pos);
            var pathOffset = BitConverter.ToInt64(blob, pos + 8);
            var ft = BitConverter.ToInt64(blob, pos + 0x10);
            var insertFlags = BitConverter.ToUInt32(blob, pos + 0x18);

            string path = "";
            if (pathOffset > 0 && pathOffset + pathLen <= blob.Length)
                path = Encoding.Unicode.GetString(blob, (int)pathOffset, pathLen);

            DateTime? mtime = null;
            if (ft > 0)
                try { mtime = DateTime.FromFileTimeUtc(ft); } catch (ArgumentOutOfRangeException) { }

            if (path.Length > 0) entries.Add((path, mtime, (insertFlags & 0x2) != 0));
        }
        return entries;
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
