using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses the NTFS change journal ($UsnJrnl:$J, collected to raw/mft/$UsnJrnl_J)
/// into the usn_journal table: per-change records (create/delete/rename/data)
/// with timestamps. High-signal changes (deletes, renames, executable creates)
/// are also promoted to the timeline.
///
/// Handles USN_RECORD V2 (primary) and V3 (128-bit file refs). The collected
/// stream is the live (non-sparse) journal; leading/embedded zero gaps between
/// records are skipped.
/// </summary>
public class UsnParser : IRawArtifactParser
{
    public string Name => "usn";
    private const int MaxRecords = 3_000_000;       // safety backstop
    private const int MaxTimeline = 100_000;        // cap high-signal timeline rows

    // USN_REASON_* flags
    private static readonly (uint bit, string name)[] Reasons =
    {
        (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"), (0x00000004, "DATA_TRUNCATION"),
        (0x00000010, "NAMED_DATA_OVERWRITE"), (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
        (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"), (0x00000400, "EA_CHANGE"),
        (0x00000800, "SECURITY_CHANGE"), (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
        (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"), (0x00010000, "HARD_LINK_CHANGE"),
        (0x00020000, "COMPRESSION_CHANGE"), (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
        (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"), (0x80000000, "CLOSE"),
    };
    private static readonly string[] ExecExts = { ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".scr", ".sys", ".js", ".hta" };

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var path = FindUsn(sessionDir);
        if (path == null) return 0;
        byte[] d;
        try { d = File.ReadAllBytes(path); }
        catch (Exception ex) { progress?.Invoke($"WARNING: usn read failed: {ex.Message}"); return 0; }

        using var tx = conn.BeginTransaction();
        using var ins = conn.CreateCommand();
        ins.CommandText = """
            INSERT INTO usn_journal (ts_utc, usn, file_ref, parent_ref, file_name, reasons, file_attributes)
            VALUES ($ts, $usn, $fr, $pr, $fn, $rs, $fa)
            """;
        SqliteParameter P(SqliteCommand c, string n) { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
        var pTs = P(ins, "$ts"); var pUsn = P(ins, "$usn"); var pFr = P(ins, "$fr");
        var pPr = P(ins, "$pr"); var pFn = P(ins, "$fn"); var pRs = P(ins, "$rs"); var pFa = P(ins, "$fa");

        using var tl = conn.CreateCommand();
        tl.CommandText = """
            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            VALUES ($ts, 'usn', 'FileSystem', $sum, $det, 'usn_journal', last_insert_rowid())
            """;
        var tTs = P(tl, "$ts"); var tSum = P(tl, "$sum"); var tDet = P(tl, "$det");

        int n = 0, tlCount = 0, pos = 0;
        while (pos + 60 <= d.Length && n < MaxRecords)
        {
            var recLen = BitConverter.ToInt32(d, pos);
            if (recLen == 0) { pos += 8; continue; }                  // zero gap -> advance to next 8-byte slot
            if (recLen < 60 || recLen > 4096 || pos + recLen > d.Length) { pos += 8; continue; }

            var major = BitConverter.ToUInt16(d, pos + 4);
            int usnOff, tsOff, reasonOff, attrOff, nameLenOff, nameOffOff;
            long fileRef, parentRef;
            if (major == 2)
            {
                fileRef = BitConverter.ToInt64(d, pos + 0x08);
                parentRef = BitConverter.ToInt64(d, pos + 0x10);
                usnOff = 0x18; tsOff = 0x20; reasonOff = 0x28; attrOff = 0x34; nameLenOff = 0x38; nameOffOff = 0x3A;
            }
            else if (major == 3)
            {
                fileRef = BitConverter.ToInt64(d, pos + 0x08);        // low 64 bits of the 128-bit ref
                parentRef = BitConverter.ToInt64(d, pos + 0x18);
                usnOff = 0x28; tsOff = 0x30; reasonOff = 0x38; attrOff = 0x44; nameLenOff = 0x48; nameOffOff = 0x4A;
            }
            else { pos += 8; continue; }

            string? tsUtc = null;
            try { var ft = BitConverter.ToInt64(d, pos + tsOff); if (ft > 0) tsUtc = DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-ddTHH:mm:ssZ"); }
            catch { }
            var usn = BitConverter.ToInt64(d, pos + usnOff);
            var reason = BitConverter.ToUInt32(d, pos + reasonOff);
            var attrs = BitConverter.ToUInt32(d, pos + attrOff);
            var nameLen = BitConverter.ToUInt16(d, pos + nameLenOff);
            var nameOff = BitConverter.ToUInt16(d, pos + nameOffOff);
            string name = "";
            if (nameLen > 0 && pos + nameOff + nameLen <= d.Length)
                name = System.Text.Encoding.Unicode.GetString(d, pos + nameOff, nameLen);

            var reasonStr = DecodeReasons(reason);
            pTs.Value = (object?)tsUtc ?? DBNull.Value; pUsn.Value = usn; pFr.Value = fileRef;
            pPr.Value = parentRef; pFn.Value = name; pRs.Value = reasonStr; pFa.Value = (long)attrs;
            ins.ExecuteNonQuery();
            n++;

            // high-signal -> timeline (dated only; bounded)
            if (tsUtc != null && tlCount < MaxTimeline)
            {
                var isDelete = (reason & 0x200) != 0;
                var isRenameOld = (reason & 0x1000) != 0;
                var isExecCreate = (reason & 0x100) != 0 && ExecExts.Any(x => name.ToLowerInvariant().EndsWith(x));
                if (isDelete || isRenameOld || isExecCreate)
                {
                    tTs.Value = tsUtc;
                    tSum.Value = $"{(isDelete ? "File deleted" : isRenameOld ? "File renamed (old name)" : "Executable created")}: {name}";
                    tDet.Value = reasonStr;
                    tl.ExecuteNonQuery();
                    tlCount++;
                }
            }
            pos += recLen;
            if (recLen % 8 != 0) pos += 8 - (recLen % 8);             // 8-byte align
        }
        tx.Commit();
        progress?.Invoke($"usn: {n} records, {tlCount} timeline events");
        return n;
    }

    private static string FindUsn(string sessionDir)
    {
        var dir = Path.Combine(sessionDir, "raw", "mft");
        if (!Directory.Exists(dir)) return null!;
        foreach (var cand in new[] { "$UsnJrnl_J", "$UsnJrnl", "UsnJrnl_J", "$J" })
        {
            var p = Path.Combine(dir, cand);
            if (File.Exists(p)) return p;
        }
        return null!;
    }

    private static string DecodeReasons(uint reason)
    {
        var parts = new List<string>();
        foreach (var (bit, nm) in Reasons) if ((reason & bit) != 0) parts.Add(nm);
        return parts.Count > 0 ? string.Join("|", parts) : $"0x{reason:X}";
    }
}
