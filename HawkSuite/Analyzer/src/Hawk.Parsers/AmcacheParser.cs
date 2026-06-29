using System.Globalization;
using Hawk.Core;
using Microsoft.Data.Sqlite;

namespace Hawk.Parsers;

/// <summary>
/// Parses Amcache.hve (raw/registry/Amcache.hve): InventoryApplicationFile
/// (Win10/11 application inventory with SHA1) and InventoryDriverBinary
/// (driver inventory with signing status — unsigned drivers are a classic
/// rootkit signal the MRI layer can correlate).
///
/// LinkDate is the PE compile timestamp and key-last-written is inventory
/// sync time — neither is host execution activity, so amcache rows stay out
/// of the timeline. The table powers execution-evidence and hash lookups.
/// </summary>
public class AmcacheParser : IRawArtifactParser
{
    public string Name => "amcache";

    public int Parse(SqliteConnection conn, string sessionDir, Action<string>? progress = null)
    {
        var hivePath = Path.Combine(sessionDir, "raw", "registry", "Amcache.hve");
        if (!File.Exists(hivePath)) return 0;

        RegistryHive hive;
        try { hive = new RegistryHive(hivePath); }
        catch (Exception ex)
        {
            progress?.Invoke($"WARNING: amcache hive unreadable: {ex.Message}");
            return 0;
        }

        using var tx = conn.BeginTransaction();
        using var insert = conn.CreateCommand();
        insert.CommandText = """
            INSERT INTO amcache (entry_type, path, name, publisher, version, sha1, size,
                                 link_date_utc, key_last_written_utc, binary_type, product_name,
                                 driver_signed, driver_company)
            VALUES ($type, $path, $name, $pub, $ver, $sha1, $size, $link, $klw, $bt, $prod, $dsig, $dco)
            """;
        var pType = P(insert, "$type"); var pPath = P(insert, "$path"); var pName = P(insert, "$name");
        var pPub = P(insert, "$pub"); var pVer = P(insert, "$ver"); var pSha1 = P(insert, "$sha1");
        var pSize = P(insert, "$size"); var pLink = P(insert, "$link"); var pKlw = P(insert, "$klw");
        var pBt = P(insert, "$bt"); var pProd = P(insert, "$prod"); var pDsig = P(insert, "$dsig");
        var pDco = P(insert, "$dco");

        var n = 0;

        // ---- InventoryApplicationFile (Win10/11) ----------------------------
        var appFiles = hive.GetKey("Root\\InventoryApplicationFile");
        if (appFiles != null)
        {
            foreach (var key in hive.EnumerateSubkeys(appFiles))
            {
                var vals = hive.EnumerateValues(key).ToDictionary(
                    v => v.Name, v => v, StringComparer.OrdinalIgnoreCase);
                string? V(string name) => vals.TryGetValue(name, out var v) ? v.AsString() : null;

                pType.Value = "application_file";
                pPath.Value = (object?)V("LowerCaseLongPath") ?? DBNull.Value;
                pName.Value = (object?)V("Name") ?? DBNull.Value;
                pPub.Value = (object?)V("Publisher") ?? DBNull.Value;
                pVer.Value = (object?)V("Version") ?? DBNull.Value;
                pSha1.Value = (object?)NormalizeFileId(V("FileId")) ?? DBNull.Value;
                pSize.Value = long.TryParse(V("Size"), out var sz) ? sz : DBNull.Value;
                pLink.Value = (object?)ParseLinkDate(V("LinkDate")) ?? DBNull.Value;
                pKlw.Value = (object?)key.LastWrittenUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? DBNull.Value;
                pBt.Value = (object?)V("BinaryType") ?? DBNull.Value;
                pProd.Value = (object?)V("ProductName") ?? DBNull.Value;
                pDsig.Value = DBNull.Value; pDco.Value = DBNull.Value;
                insert.ExecuteNonQuery();
                n++;
            }
        }

        // ---- InventoryDriverBinary ------------------------------------------
        var drivers = hive.GetKey("Root\\InventoryDriverBinary");
        if (drivers != null)
        {
            foreach (var key in hive.EnumerateSubkeys(drivers))
            {
                var vals = hive.EnumerateValues(key).ToDictionary(
                    v => v.Name, v => v, StringComparer.OrdinalIgnoreCase);
                string? V(string name) => vals.TryGetValue(name, out var v) ? v.AsString() : null;
                uint? D(string name) => vals.TryGetValue(name, out var v) ? v.AsDword() : null;

                pType.Value = "driver_binary";
                // key name IS the lower-case driver path for this inventory
                pPath.Value = key.Name.Length > 0 ? key.Name : (object?)V("DriverName") ?? DBNull.Value;
                pName.Value = (object?)V("Service") ?? DBNull.Value;
                pPub.Value = DBNull.Value;
                pVer.Value = (object?)V("DriverVersion") ?? DBNull.Value;
                pSha1.Value = (object?)NormalizeFileId(V("DriverId")) ?? DBNull.Value;
                pSize.Value = DBNull.Value;
                pLink.Value = (object?)ParseLinkDate(V("DriverTimeStamp")) ?? DBNull.Value;
                pKlw.Value = (object?)key.LastWrittenUtc?.ToString("yyyy-MM-ddTHH:mm:ssZ") ?? DBNull.Value;
                pBt.Value = (object?)V("DriverType") ?? DBNull.Value;
                pProd.Value = (object?)V("Product") ?? DBNull.Value;
                pDsig.Value = D("DriverSigned") is uint ds ? (long)ds : DBNull.Value;
                pDco.Value = (object?)V("DriverCompany") ?? DBNull.Value;
                insert.ExecuteNonQuery();
                n++;
            }
        }

        tx.Commit();
        if (n == 0)
            progress?.Invoke("amcache: no Inventory* keys (pre-1709 'File' format not supported yet)");
        return n;
    }

    /// <summary>Amcache FileId is SHA1 with a 4-zero prefix ("0000&lt;sha1&gt;").</summary>
    private static string? NormalizeFileId(string? fileId)
    {
        if (string.IsNullOrEmpty(fileId)) return null;
        var id = fileId.Trim();
        return id.Length == 44 && id.StartsWith("0000") ? id[4..].ToLowerInvariant() : id.ToLowerInvariant();
    }

    /// <summary>LinkDate "MM/dd/yyyy HH:mm:ss"; DriverTimeStamp is unix epoch seconds.</summary>
    private static string? ParseLinkDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        if (DateTime.TryParseExact(s, "MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            return dt.ToString("yyyy-MM-ddTHH:mm:ssZ");
        if (long.TryParse(s, out var epoch) && epoch is > 0 and < 4102444800)
            return DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
        return null;
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
