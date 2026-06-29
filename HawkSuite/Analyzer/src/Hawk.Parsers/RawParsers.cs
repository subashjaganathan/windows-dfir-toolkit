using Hawk.Core;

namespace Hawk.Parsers;

/// <summary>All raw-artifact parsers, in import order.</summary>
public static class RawParsers
{
    public static IRawArtifactParser[] All =>
    [
        new EvtxParser(),
        new PrefetchParser(),
        new ShimcacheParser(),
        new AmcacheParser(),
        new MftParser(),
        new UsnParser(),
    ];
}
