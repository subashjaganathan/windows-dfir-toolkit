using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// A parser for raw acquired artifacts (EVTX, prefetch, hives, ...) found in
/// the extracted session's raw/ tree. Implementations live in Hawk.Parsers
/// (net8.0-windows); Hawk.Core stays platform-neutral, so the importer
/// receives parsers by injection rather than referencing them.
/// </summary>
public interface IRawArtifactParser
{
    /// <summary>Short name used in progress messages ("evtx", "prefetch", ...).</summary>
    string Name { get; }

    /// <summary>
    /// Parses raw artifacts under <paramref name="sessionDir"/> (the extracted
    /// .hawk root) into <paramref name="conn"/>. Returns parsed record count.
    /// Must be tolerant: a missing raw/ subtree is a no-op returning 0, and a
    /// single corrupt file must not abort the rest (log and continue).
    /// </summary>
    int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null);
}
