using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses a raw $MFT (raw/mft/$MFT) into the mft_entries table: file-system
/// inventory with $SI/$FN timestamps, allocated/deleted state, directory flag,
/// size, and a resolved full path. Backbone for file-activity timelining and
/// deleted-file evidence.
///
/// Handles standard 1024-byte FILE records with fixups, resident
/// $STANDARD_INFORMATION / $FILE_NAME, and $DATA size (resident or
/// non-resident). Edge cases (attribute lists, $FN in an external record) are
/// skipped gracefully rather than guessed.
/// </summary>
public class MftParser : IRawArtifactParser
{
    public string Name => "mft";
    private const long MaxRecords = 3_000_000;   // safety backstop

    private sealed class Entry
    {
        public long Rec; public bool InUse; public bool IsDir;
        public string? Name; public long ParentRec = -1;
        public string? SiCreated, SiModified, SiAccessed, FnCreated;
        public long LogicalSize;
        public string? FullPath;
    }

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var path = FindMft(sessionDir);
        if (path == null) return 0;

        byte[] data;
        try { data = File.ReadAllBytes(path); }
        catch (Exception ex) { progress?.Invoke($"WARNING: mft read failed: {ex.Message}"); return 0; }
        if (data.Length < 1024 || !Sig(data, 0)) { progress?.Invoke("mft: not a FILE-record stream"); return 0; }

        var recSize = DetectRecordSize(data);
        var bps = 512;                                  // fixup stride; MFT records use 512 strides
        var entries = new Dictionary<long, Entry>();
        long total = data.Length / recSize;
        if (total > MaxRecords) total = MaxRecords;

        for (long i = 0; i < total; i++)
        {
            var off = (int)(i * recSize);
            if (off + recSize > data.Length) break;
            if (!Sig(data, off)) continue;              // skip BAAD/empty
            var rec = new byte[recSize];
            Array.Copy(data, off, rec, 0, recSize);
            try
            {
                ApplyFixup(rec, bps);
                var e = ParseRecord(rec, i);
                if (e?.Name != null) entries[i] = e;
            }
            catch { /* malformed record - skip */ }
        }

        // resolve full paths
        foreach (var e in entries.Values) e.FullPath = ResolvePath(e, entries);

        return Insert(conn, entries.Values, progress);
    }

    private static string? FindMft(string sessionDir)
    {
        var dir = Path.Combine(sessionDir, "raw", "mft");
        if (!Directory.Exists(dir)) return null;
        foreach (var cand in new[] { "$MFT", "MFT", "$Mft" })
        {
            var p = Path.Combine(dir, cand);
            if (File.Exists(p)) return p;
        }
        // any file that begins with the FILE signature
        foreach (var f in Directory.EnumerateFiles(dir))
        {
            try { using var fs = File.OpenRead(f); var b = new byte[4]; if (fs.Read(b, 0, 4) == 4 && b[0] == (byte)'F' && b[1] == (byte)'I' && b[2] == (byte)'L' && b[3] == (byte)'E') return f; }
            catch { }
        }
        return null;
    }

    private static bool Sig(byte[] d, int off) =>
        off + 4 <= d.Length && d[off] == (byte)'F' && d[off + 1] == (byte)'I' && d[off + 2] == (byte)'L' && d[off + 3] == (byte)'E';

    private static int DetectRecordSize(byte[] d)
    {
        // "allocated size of this record" lives at 0x1C of the first record
        var alloc = BitConverter.ToInt32(d, 0x1C);
        return alloc is 512 or 1024 or 2048 or 4096 ? alloc : 1024;
    }

    private static void ApplyFixup(byte[] rec, int bps)
    {
        ushort usaOff = BitConverter.ToUInt16(rec, 4);
        ushort usaCnt = BitConverter.ToUInt16(rec, 6);
        for (var i = 1; i < usaCnt; i++)
        {
            var sectorEnd = i * bps - 2;
            if (sectorEnd + 2 > rec.Length || usaOff + i * 2 + 1 >= rec.Length) break;
            rec[sectorEnd] = rec[usaOff + i * 2];
            rec[sectorEnd + 1] = rec[usaOff + i * 2 + 1];
        }
    }

    private static Entry? ParseRecord(byte[] rec, long recNum)
    {
        var flags = BitConverter.ToUInt16(rec, 0x16);
        var e = new Entry { Rec = recNum, InUse = (flags & 0x01) != 0, IsDir = (flags & 0x02) != 0 };

        int off = BitConverter.ToUInt16(rec, 0x14);
        var bestNameNs = -1;                            // prefer Win32(1)/Win32&DOS(3) over DOS(2)/POSIX(0)
        while (off + 8 <= rec.Length)
        {
            var type = BitConverter.ToUInt32(rec, off);
            if (type == 0xFFFFFFFF) break;
            var len = BitConverter.ToInt32(rec, off + 4);
            if (len <= 0 || off + len > rec.Length) break;
            var resident = rec[off + 8] == 0;

            if (type == 0x10 && resident)               // $STANDARD_INFORMATION
            {
                var c = off + BitConverter.ToUInt16(rec, off + 0x14);
                e.SiCreated = Ft(rec, c); e.SiModified = Ft(rec, c + 8); e.SiAccessed = Ft(rec, c + 0x18);
            }
            else if (type == 0x30 && resident)          // $FILE_NAME
            {
                var c = off + BitConverter.ToUInt16(rec, off + 0x14);
                if (c + 0x42 <= rec.Length)
                {
                    var parent = BitConverter.ToInt64(rec, c) & 0xFFFFFFFFFFFF;   // low 48 bits
                    var ns = rec[c + 0x41];
                    var nameLen = rec[c + 0x40];
                    if (c + 0x42 + nameLen * 2 <= rec.Length && (ns != 2 || bestNameNs < 0))
                    {
                        if (ns >= bestNameNs)            // keep the best (non-DOS) name
                        {
                            e.Name = System.Text.Encoding.Unicode.GetString(rec, c + 0x42, nameLen * 2);
                            e.ParentRec = parent;
                            e.FnCreated = Ft(rec, c + 8);
                            bestNameNs = ns;
                        }
                    }
                }
            }
            else if (type == 0x80)                      // $DATA (unnamed = primary stream size)
            {
                if (resident) e.LogicalSize = Math.Max(e.LogicalSize, BitConverter.ToUInt32(rec, off + 0x10));
                else if (off + 0x38 <= rec.Length) e.LogicalSize = Math.Max(e.LogicalSize, BitConverter.ToInt64(rec, off + 0x30));
            }
            off += len;
        }
        return e;
    }

    private static string? ResolvePath(Entry e, Dictionary<long, Entry> all)
    {
        var parts = new Stack<string>();
        var cur = e;
        var depth = 0;
        var seen = new HashSet<long>();
        while (cur?.Name != null && depth++ < 256)
        {
            if (cur.Rec == 5) break;                    // root directory
            parts.Push(cur.Name);
            if (!seen.Add(cur.ParentRec) || cur.ParentRec < 0 || !all.TryGetValue(cur.ParentRec, out var parent)) break;
            cur = parent;
        }
        return parts.Count > 0 ? "\\" + string.Join("\\", parts) : (e.Name == "." ? "\\" : e.Name);
    }

    private static string? Ft(byte[] d, int off)
    {
        if (off + 8 > d.Length) return null;
        var ft = BitConverter.ToInt64(d, off);
        if (ft <= 0) return null;
        try { return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-ddTHH:mm:ssZ"); }
        catch { return null; }
    }

    private static int Insert(SqliteConnection conn, IEnumerable<Entry> entries, Action<string>? progress)
    {
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO mft_entries (record_number, in_use, is_directory, file_name, full_path,
                                     parent_record, si_created_utc, si_modified_utc, si_accessed_utc,
                                     fn_created_utc, logical_size)
            VALUES ($rn, $iu, $dir, $fn, $fp, $pr, $sc, $sm, $sa, $fc, $sz)
            """;
        SqliteParameter P(string n) { var p = cmd.CreateParameter(); p.ParameterName = n; cmd.Parameters.Add(p); return p; }
        var pRn = P("$rn"); var pIu = P("$iu"); var pDir = P("$dir"); var pFn = P("$fn"); var pFp = P("$fp");
        var pPr = P("$pr"); var pSc = P("$sc"); var pSm = P("$sm"); var pSa = P("$sa"); var pFc = P("$fc"); var pSz = P("$sz");

        var n = 0;
        foreach (var e in entries)
        {
            pRn.Value = e.Rec; pIu.Value = e.InUse ? 1 : 0; pDir.Value = e.IsDir ? 1 : 0;
            pFn.Value = (object?)e.Name ?? DBNull.Value; pFp.Value = (object?)e.FullPath ?? DBNull.Value;
            pPr.Value = e.ParentRec; pSc.Value = (object?)e.SiCreated ?? DBNull.Value;
            pSm.Value = (object?)e.SiModified ?? DBNull.Value; pSa.Value = (object?)e.SiAccessed ?? DBNull.Value;
            pFc.Value = (object?)e.FnCreated ?? DBNull.Value; pSz.Value = e.LogicalSize;
            cmd.ExecuteNonQuery();
            n++;
        }
        tx.Commit();
        progress?.Invoke($"mft: {n} entries");
        return n;
    }
}
