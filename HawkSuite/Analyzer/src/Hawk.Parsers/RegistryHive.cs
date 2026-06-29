using System.Text;

namespace Hawk.Parsers;

/// <summary>
/// Minimal read-only parser for offline registry hive files (regf format).
/// Supports what the shimcache/amcache parsers need: key lookup by path,
/// subkey/value enumeration, value data (incl. big-data 'db' cells), and
/// key last-written timestamps. No transaction-log replay — hives copied
/// from VSS are crash-consistent, which is sufficient for these artifacts.
/// </summary>
public sealed class RegistryHive
{
    private readonly byte[] _data;
    private const int HbinBase = 0x1000;          // cell offsets are relative to this

    public RegistryKey Root { get; }

    public RegistryHive(string path)
    {
        _data = File.ReadAllBytes(path);
        if (_data.Length < 0x200 || ReadAscii(0, 4) != "regf")
            throw new InvalidDataException("not a regf hive");
        var rootOffset = BitConverter.ToInt32(_data, 0x24);
        Root = ReadKey(rootOffset);
    }

    /// <summary>Resolves a backslash-separated subpath from the root, or null.</summary>
    public RegistryKey? GetKey(string path)
    {
        var key = Root;
        foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries))
        {
            key = EnumerateSubkeys(key).FirstOrDefault(
                k => string.Equals(k.Name, part, StringComparison.OrdinalIgnoreCase));
            if (key == null) return null;
        }
        return key;
    }

    public IEnumerable<RegistryKey> EnumerateSubkeys(RegistryKey key)
    {
        if (key.SubkeyCount == 0 || key.SubkeyListOffset == -1) yield break;
        foreach (var off in WalkSubkeyList(key.SubkeyListOffset))
        {
            RegistryKey? k = null;
            try { k = ReadKey(off); } catch { /* corrupt cell — skip */ }
            if (k != null) yield return k;
        }
    }

    public IEnumerable<RegistryValue> EnumerateValues(RegistryKey key)
    {
        if (key.ValueCount == 0 || key.ValueListOffset == -1) yield break;
        var listPos = CellData(key.ValueListOffset);
        for (var i = 0; i < key.ValueCount; i++)
        {
            var vkOffset = BitConverter.ToInt32(_data, listPos + i * 4);
            RegistryValue? v = null;
            try { v = ReadValue(vkOffset); } catch { /* corrupt cell — skip */ }
            if (v != null) yield return v;
        }
    }

    public RegistryValue? GetValue(RegistryKey key, string name) =>
        EnumerateValues(key).FirstOrDefault(
            v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase));

    // ---- cell plumbing ------------------------------------------------------

    /// <summary>Absolute offset of a cell's data (skips the 4-byte size field).</summary>
    private int CellData(int cellOffset) => HbinBase + cellOffset + 4;

    private IEnumerable<int> WalkSubkeyList(int listOffset)
    {
        var pos = CellData(listOffset);
        var sig = ReadAscii(pos, 2);
        var count = BitConverter.ToUInt16(_data, pos + 2);
        switch (sig)
        {
            case "lf":   // fast leaf: offset + 4-byte name hint
            case "lh":   // hash leaf: offset + 4-byte hash
                for (var i = 0; i < count; i++)
                    yield return BitConverter.ToInt32(_data, pos + 4 + i * 8);
                break;
            case "li":   // index leaf: offsets only
                for (var i = 0; i < count; i++)
                    yield return BitConverter.ToInt32(_data, pos + 4 + i * 4);
                break;
            case "ri":   // index root: points at other lists
                for (var i = 0; i < count; i++)
                {
                    var sub = BitConverter.ToInt32(_data, pos + 4 + i * 4);
                    foreach (var off in WalkSubkeyList(sub)) yield return off;
                }
                break;
            default:
                yield break;   // unknown list type — treat as empty
        }
    }

    private RegistryKey ReadKey(int cellOffset)
    {
        var pos = CellData(cellOffset);
        if (ReadAscii(pos, 2) != "nk") throw new InvalidDataException($"expected nk cell at 0x{cellOffset:X}");
        var flags = BitConverter.ToUInt16(_data, pos + 0x02);
        var ft = BitConverter.ToInt64(_data, pos + 0x04);
        DateTime? lastWritten = null;
        if (ft > 0)
            try { lastWritten = DateTime.FromFileTimeUtc(ft); } catch (ArgumentOutOfRangeException) { }

        var nameLen = BitConverter.ToUInt16(_data, pos + 0x48);
        var name = (flags & 0x20) != 0     // KEY_COMP_NAME → Latin-1, else UTF-16
            ? Encoding.Latin1.GetString(_data, pos + 0x4C, nameLen)
            : Encoding.Unicode.GetString(_data, pos + 0x4C, nameLen);

        return new RegistryKey(
            Name: name,
            LastWrittenUtc: lastWritten,
            SubkeyCount: BitConverter.ToInt32(_data, pos + 0x14),
            SubkeyListOffset: BitConverter.ToInt32(_data, pos + 0x1C),
            ValueCount: BitConverter.ToInt32(_data, pos + 0x24),
            ValueListOffset: BitConverter.ToInt32(_data, pos + 0x28));
    }

    private RegistryValue ReadValue(int cellOffset)
    {
        var pos = CellData(cellOffset);
        if (ReadAscii(pos, 2) != "vk") throw new InvalidDataException($"expected vk cell at 0x{cellOffset:X}");
        var nameLen = BitConverter.ToUInt16(_data, pos + 0x02);
        var dataSizeRaw = BitConverter.ToUInt32(_data, pos + 0x04);
        var dataOffset = BitConverter.ToInt32(_data, pos + 0x08);
        var type = BitConverter.ToInt32(_data, pos + 0x0C);
        var flags = BitConverter.ToUInt16(_data, pos + 0x10);

        var name = nameLen == 0 ? ""        // default value
            : (flags & 0x1) != 0
                ? Encoding.Latin1.GetString(_data, pos + 0x14, nameLen)
                : Encoding.Unicode.GetString(_data, pos + 0x14, nameLen);

        byte[] data;
        var inline = (dataSizeRaw & 0x80000000) != 0;
        var dataSize = (int)(dataSizeRaw & 0x7FFFFFFF);
        if (inline)
        {
            // data lives in the 4 offset bytes themselves
            data = new byte[Math.Min(dataSize, 4)];
            Buffer.BlockCopy(_data, pos + 0x08, data, 0, data.Length);
        }
        else if (dataSize > 16344)
        {
            data = ReadBigData(dataOffset, dataSize);
        }
        else
        {
            data = new byte[dataSize];
            Buffer.BlockCopy(_data, CellData(dataOffset), data, 0, dataSize);
        }
        return new RegistryValue(name, type, data);
    }

    /// <summary>'db' big-data cells: data split across 16344-byte segments.</summary>
    private byte[] ReadBigData(int dbOffset, int totalSize)
    {
        var pos = CellData(dbOffset);
        if (ReadAscii(pos, 2) != "db")
        {
            // some hives store >16344 directly anyway — fall back to direct read
            var direct = new byte[totalSize];
            Buffer.BlockCopy(_data, pos, direct, 0, totalSize);
            return direct;
        }
        var segCount = BitConverter.ToUInt16(_data, pos + 2);
        var listPos = CellData(BitConverter.ToInt32(_data, pos + 4));
        var result = new byte[totalSize];
        var written = 0;
        for (var i = 0; i < segCount && written < totalSize; i++)
        {
            var segPos = CellData(BitConverter.ToInt32(_data, listPos + i * 4));
            var chunk = Math.Min(16344, totalSize - written);
            Buffer.BlockCopy(_data, segPos, result, written, chunk);
            written += chunk;
        }
        return result;
    }

    private string ReadAscii(int offset, int len) => Encoding.ASCII.GetString(_data, offset, len);
}

public sealed record RegistryKey(
    string Name, DateTime? LastWrittenUtc,
    int SubkeyCount, int SubkeyListOffset,
    int ValueCount, int ValueListOffset);

public sealed record RegistryValue(string Name, int Type, byte[] Data)
{
    public string? AsString() => Type switch
    {
        1 or 2 => DecodeSz(),                               // REG_SZ / REG_EXPAND_SZ
        4 when Data.Length >= 4 => BitConverter.ToUInt32(Data, 0).ToString(),
        11 when Data.Length >= 8 => BitConverter.ToUInt64(Data, 0).ToString(),
        _ => null
    };

    public uint? AsDword() => Type == 4 && Data.Length >= 4 ? BitConverter.ToUInt32(Data, 0) : null;

    private string DecodeSz()
    {
        var s = Encoding.Unicode.GetString(Data);
        var nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }
}
