using System.Buffers.Binary;

namespace Hawk.Core;

/// <summary>
/// Bloom filter keyed on MD5 hex strings (NSRL whitelist). Same technique as
/// Redline's DefaultWhitelist.bloom, clean-room implementation.
///
/// Because the keys are themselves MD5 digests (uniformly distributed), the
/// k index functions are derived directly from the digest bytes via
/// Kirsch-Mitzenmacher double hashing: g_i = h1 + i*h2 (mod m). No re-hashing
/// of the key is needed, which keeps lookups allocation-free and O(k).
/// </summary>
public sealed class BloomFilter
{
    private const string Magic = "HWKBLM01";

    private readonly ulong[] _words;

    public long BitCount { get; }
    public int HashCount { get; }
    public long ItemCount { get; private set; }

    private BloomFilter(long bitCount, int hashCount, long itemCount, ulong[] words)
    {
        BitCount = bitCount; HashCount = hashCount; ItemCount = itemCount; _words = words;
    }

    /// <summary>Sizes the filter for <paramref name="expectedItems"/> at the target false-positive rate.</summary>
    public static BloomFilter Create(long expectedItems, double falsePositiveRate = 1e-4)
    {
        if (expectedItems < 1) expectedItems = 1;
        var ln2 = Math.Log(2);
        var bits = (long)Math.Ceiling(-expectedItems * Math.Log(falsePositiveRate) / (ln2 * ln2));
        bits = Math.Max(64, (bits + 63) / 64 * 64);                 // round up to whole words
        var k = Math.Max(1, (int)Math.Round(bits / (double)expectedItems * ln2));
        return new BloomFilter(bits, k, 0, new ulong[bits / 64]);
    }

    public void Add(string md5Hex)
    {
        if (!TryDeriveHashes(md5Hex, out var h1, out var h2)) return;
        for (var i = 0; i < HashCount; i++)
        {
            var bit = (long)((h1 + (ulong)i * h2) % (ulong)BitCount);
            _words[bit >> 6] |= 1UL << (int)(bit & 63);
        }
        ItemCount++;
    }

    /// <summary>False positives possible at the configured rate; false negatives never.</summary>
    public bool MightContain(string md5Hex)
    {
        if (!TryDeriveHashes(md5Hex, out var h1, out var h2)) return false;
        for (var i = 0; i < HashCount; i++)
        {
            var bit = (long)((h1 + (ulong)i * h2) % (ulong)BitCount);
            if ((_words[bit >> 6] & (1UL << (int)(bit & 63))) == 0) return false;
        }
        return true;
    }

    /// <summary>h1/h2 come straight from the digest bytes; key must be 32 hex chars.</summary>
    private static bool TryDeriveHashes(string md5Hex, out ulong h1, out ulong h2)
    {
        h1 = 0; h2 = 0;
        if (md5Hex is not { Length: 32 }) return false;
        Span<byte> digest = stackalloc byte[16];
        for (var i = 0; i < 16; i++)
        {
            var hi = HexVal(md5Hex[i * 2]); var lo = HexVal(md5Hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            digest[i] = (byte)((hi << 4) | lo);
        }
        h1 = BinaryPrimitives.ReadUInt64LittleEndian(digest);
        h2 = BinaryPrimitives.ReadUInt64LittleEndian(digest[8..]) | 1; // odd → full cycle mod m
        return true;
    }

    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1
    };

    // ------------------------------ persistence ------------------------------

    public void Save(string path)
    {
        using var fs = File.Create(path);
        using var w = new BinaryWriter(fs);
        w.Write(System.Text.Encoding.ASCII.GetBytes(Magic));
        w.Write(HashCount);
        w.Write(BitCount);
        w.Write(ItemCount);
        foreach (var word in _words) w.Write(word);
    }

    public static BloomFilter Load(string path)
    {
        using var fs = File.OpenRead(path);
        using var r = new BinaryReader(fs);
        var magic = System.Text.Encoding.ASCII.GetString(r.ReadBytes(8));
        if (magic != Magic) throw new InvalidDataException($"{path}: not a Hawk bloom filter (bad magic)");
        var k = r.ReadInt32();
        var bits = r.ReadInt64();
        var items = r.ReadInt64();
        if (k is < 1 or > 64 || bits < 64 || bits % 64 != 0)
            throw new InvalidDataException($"{path}: corrupt bloom filter header");
        var words = new ulong[bits / 64];
        for (var i = 0; i < words.Length; i++) words[i] = r.ReadUInt64();
        return new BloomFilter(bits, k, items, words);
    }
}
