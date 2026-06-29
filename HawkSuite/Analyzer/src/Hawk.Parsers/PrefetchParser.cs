using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses raw/prefetch/*.pf (SCCA format, versions 17/23/26/30/31).
/// Win10/11 files are MAM-compressed (Xpress Huffman) — decompressed via
/// ntdll RtlDecompressBufferEx, which exists on every supported analyst OS.
/// Each run timestamp becomes an Execution timeline row.
/// </summary>
public class PrefetchParser : IRawArtifactParser
{
    public string Name => "prefetch";

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var pfDir = Path.Combine(sessionDir, "raw", "prefetch");
        if (!Directory.Exists(pfDir)) return 0;

        using var tx = conn.BeginTransaction();
        using var insert = conn.CreateCommand();
        insert.CommandText = """
            INSERT INTO prefetch (file_name, executable, prefetch_hash, run_count, last_run_utc,
                                  run_times, referenced_files, volume_serial, volume_created_utc, format_version)
            VALUES ($fn, $exe, $hash, $rc, $last, $runs, $refs, $vol, $volts, $ver)
            """;
        var pFn = P(insert, "$fn"); var pExe = P(insert, "$exe"); var pHash = P(insert, "$hash");
        var pRc = P(insert, "$rc"); var pLast = P(insert, "$last"); var pRuns = P(insert, "$runs");
        var pRefs = P(insert, "$refs"); var pVol = P(insert, "$vol"); var pVolTs = P(insert, "$volts");
        var pVer = P(insert, "$ver");

        using var tl = conn.CreateCommand();
        tl.CommandText = """
            INSERT INTO timeline (ts_utc, source, category, summary, detail, artifact_table, artifact_id)
            VALUES ($ts, 'prefetch', 'Execution', $sum, $det, 'prefetch', $id)
            """;
        var tTs = P(tl, "$ts"); var tSum = P(tl, "$sum"); var tDet = P(tl, "$det"); var tId = P(tl, "$id");

        var n = 0;
        foreach (var file in Directory.EnumerateFiles(pfDir, "*.pf").OrderBy(f => f))
        {
            PrefetchRecord rec;
            try
            {
                rec = ParseFile(file);
            }
            catch (Exception ex)
            {
                progress?.Invoke($"WARNING: prefetch {Path.GetFileName(file)}: {ex.Message}");
                continue;
            }

            pFn.Value = Path.GetFileName(file);
            pExe.Value = rec.Executable;
            pHash.Value = rec.Hash;
            pRc.Value = rec.RunCount;
            pLast.Value = (object?)rec.RunTimes.FirstOrDefault() ?? DBNull.Value;
            pRuns.Value = JsonSerializer.Serialize(rec.RunTimes);
            pRefs.Value = JsonSerializer.Serialize(rec.ReferencedFiles);
            pVol.Value = (object?)rec.VolumeSerial ?? DBNull.Value;
            pVolTs.Value = (object?)rec.VolumeCreated ?? DBNull.Value;
            pVer.Value = rec.Version;
            insert.ExecuteNonQuery();
            n++;

            using (var rowId = conn.CreateCommand())
            {
                rowId.CommandText = "SELECT last_insert_rowid()";
                tId.Value = (long)rowId.ExecuteScalar()!;
            }
            foreach (var ts in rec.RunTimes)
            {
                tTs.Value = ts;
                tSum.Value = $"Prefetch: {rec.Executable} executed";
                tDet.Value = $"run count {rec.RunCount}, {Path.GetFileName(file)}";
                tl.ExecuteNonQuery();
            }
        }
        tx.Commit();
        return n;
    }

    private sealed record PrefetchRecord(
        string Executable, string Hash, int Version, int RunCount,
        List<string> RunTimes, List<string> ReferencedFiles,
        string? VolumeSerial, string? VolumeCreated);

    private static PrefetchRecord ParseFile(string path)
    {
        var raw = File.ReadAllBytes(path);
        if (raw.Length < 8) throw new InvalidDataException("file too small");

        // Win10/11: MAM-compressed wrapper
        if (raw[0] == (byte)'M' && raw[1] == (byte)'A' && raw[2] == (byte)'M' && raw[3] == 0x04)
        {
            var decompressedSize = BitConverter.ToInt32(raw, 4);
            if (decompressedSize is <= 0 or > 64 * 1024 * 1024)
                throw new InvalidDataException($"implausible decompressed size {decompressedSize}");
            raw = MamDecompress(raw, 8, decompressedSize);
        }

        if (raw.Length < 0x54 || raw[4] != (byte)'S' || raw[5] != (byte)'C' || raw[6] != (byte)'C' || raw[7] != (byte)'A')
            throw new InvalidDataException("not an SCCA prefetch file");

        var version = BitConverter.ToInt32(raw, 0);
        var executable = Encoding.Unicode.GetString(raw, 0x10, 60).TrimEnd('\0');
        var nul = executable.IndexOf('\0');
        if (nul >= 0) executable = executable[..nul];
        var hash = BitConverter.ToUInt32(raw, 0x4C).ToString("X8");

        // file-information block layout per version
        int runCountOffset, lastRunOffset, lastRunSlots;
        switch (version)
        {
            case 17: lastRunOffset = 0x78; lastRunSlots = 1; runCountOffset = 0x90; break;
            case 23: lastRunOffset = 0x80; lastRunSlots = 1; runCountOffset = 0x98; break;
            case 26: lastRunOffset = 0x80; lastRunSlots = 8; runCountOffset = 0xD0; break;
            case 30:
            case 31:
                lastRunOffset = 0x80; lastRunSlots = 8;
                // two v30 file-information variants; the metrics-array offset
                // (u32 @0x54) marks where file information ends
                var metricsOffset = BitConverter.ToInt32(raw, 0x54);
                runCountOffset = metricsOffset >= 0xD4 ? 0xD0 : 0xC8;
                break;
            default: throw new InvalidDataException($"unsupported SCCA version {version}");
        }

        var runTimes = new List<string>();
        for (var i = 0; i < lastRunSlots; i++)
        {
            var ft = BitConverter.ToInt64(raw, lastRunOffset + i * 8);
            if (ft <= 0) continue;
            try { runTimes.Add(DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-ddTHH:mm:ssZ")); }
            catch (ArgumentOutOfRangeException) { /* corrupt slot */ }
        }
        var runCount = raw.Length > runCountOffset + 4 ? BitConverter.ToInt32(raw, runCountOffset) : 0;
        if (runCount is < 0 or > 1_000_000) runCount = 0;   // implausible → unknown

        // filename-strings section: UTF-16 strings, null-separated
        var refFiles = new List<string>();
        var strOffset = BitConverter.ToInt32(raw, 0x64);
        var strSize = BitConverter.ToInt32(raw, 0x68);
        if (strOffset > 0 && strSize > 0 && strOffset + strSize <= raw.Length)
        {
            var blob = Encoding.Unicode.GetString(raw, strOffset, strSize);
            refFiles.AddRange(blob.Split('\0', StringSplitOptions.RemoveEmptyEntries));
        }

        // first volume: serial + creation time
        string? volSerial = null, volCreated = null;
        var volOffset = BitConverter.ToInt32(raw, 0x6C);
        var volCount = BitConverter.ToInt32(raw, 0x70);
        if (volCount > 0 && volOffset > 0 && volOffset + 0x14 <= raw.Length)
        {
            var volFt = BitConverter.ToInt64(raw, volOffset + 0x08);
            if (volFt > 0)
                try { volCreated = DateTime.FromFileTimeUtc(volFt).ToString("yyyy-MM-ddTHH:mm:ssZ"); }
                catch (ArgumentOutOfRangeException) { }
            volSerial = BitConverter.ToUInt32(raw, volOffset + 0x10).ToString("X8");
        }

        return new PrefetchRecord(executable, hash, version, runCount, runTimes, refFiles, volSerial, volCreated);
    }

    // ---- ntdll Xpress-Huffman decompression (MAM wrapper) -----------------
    private const ushort COMPRESSION_FORMAT_XPRESS_HUFF = 4;

    [DllImport("ntdll.dll")]
    private static extern uint RtlGetCompressionWorkSpaceSize(
        ushort format, out uint bufferWorkSpaceSize, out uint fragmentWorkSpaceSize);

    [DllImport("ntdll.dll")]
    private static extern uint RtlDecompressBufferEx(
        ushort format, byte[] uncompressed, int uncompressedSize,
        byte[] compressed, int compressedSize, out int finalSize, byte[] workSpace);

    private static byte[] MamDecompress(byte[] data, int offset, int decompressedSize)
    {
        var status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF, out var wsSize, out _);
        if (status != 0) throw new InvalidDataException($"RtlGetCompressionWorkSpaceSize NTSTATUS 0x{status:X8}");

        var compressed = new byte[data.Length - offset];
        Buffer.BlockCopy(data, offset, compressed, 0, compressed.Length);
        var output = new byte[decompressedSize];
        var workspace = new byte[wsSize];

        status = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF,
            output, output.Length, compressed, compressed.Length, out var finalSize, workspace);
        if (status != 0) throw new InvalidDataException($"RtlDecompressBufferEx NTSTATUS 0x{status:X8}");
        if (finalSize < output.Length) Array.Resize(ref output, finalSize);
        return output;
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
