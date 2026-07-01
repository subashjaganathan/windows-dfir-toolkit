using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Optional memory-forensics hand-off. Runs Volatility3 (if available) against a
/// captured RAM image and ingests the Redline-parity results into the session:
///   pslist + psscan  -> memory_processes (psscan-only rows = potentially hidden),
///   malfind          -> memory_injections + injected-code findings,
///   netscan          -> memory_netscan.
///
/// Volatility3 is NOT bundled (it needs Python). Detection order: HAWK_VOL env,
/// a `vol` on PATH, else `python -m volatility3`. If none is found it logs a
/// clear note and no-ops - HawkSuite stays dependency-free. Findings are written
/// with their MITRE ATT&CK technique directly (this runs after import scoring).
/// </summary>
public static class MemoryAnalyzer
{
    private static readonly string[] Userwritable =
        [@"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\programdata\", @"\users\"];

    /// <summary>Returns (fileName, argPrefix) for invoking Volatility3, or null if unavailable.</summary>
    public static (string File, string[] Pre)? DetectVol(string? overrideCmd = null)
    {
        static (string, string[])? FromToken(string t) =>
            t.EndsWith(".py", StringComparison.OrdinalIgnoreCase) ? ("python", new[] { t }) : (t, Array.Empty<string>());

        if (!string.IsNullOrWhiteSpace(overrideCmd)) return FromToken(overrideCmd.Trim());
        var env = Environment.GetEnvironmentVariable("HAWK_VOL");
        if (!string.IsNullOrWhiteSpace(env)) return FromToken(env.Trim());

        foreach (var name in new[] { "vol", "vol.exe", "vol.py", "volatility3" })
        {
            var p = OnPath(name);
            if (p != null) return name.EndsWith(".py") ? ("python", new[] { p }) : (p, Array.Empty<string>());
        }
        // python -m volatility3 (only if the module actually imports)
        var py = OnPath("python") ?? OnPath("python3");
        if (py != null && TryRun(py, new[] { "-c", "import volatility3" }, out _)) return (py, new[] { "-m", "volatility3" });
        return null;
    }

    public static int Analyze(SqliteConnection conn, string imagePath, string? volOverride = null, Action<string>? progress = null)
    {
        if (!File.Exists(imagePath)) { progress?.Invoke($"memory: image not found: {imagePath}"); return 0; }
        var vol = DetectVol(volOverride);
        if (vol is null)
        {
            progress?.Invoke("memory: Volatility3 not found (set HAWK_VOL, put `vol` on PATH, or `pip install volatility3`); skipping memory analysis");
            return 0;
        }
        progress?.Invoke($"memory: analyzing {Path.GetFileName(imagePath)} with {vol.Value.File} {string.Join(' ', vol.Value.Pre)} (this takes minutes; first run downloads symbols)");

        var pslist = RunPlugin(vol.Value, imagePath, "windows.pslist", progress);
        var psscan = RunPlugin(vol.Value, imagePath, "windows.psscan", progress);
        var malfind = RunPlugin(vol.Value, imagePath, "windows.malfind", progress);
        var netscan = RunPlugin(vol.Value, imagePath, "windows.netscan", progress);

        var n = IngestProcesses(conn, pslist, psscan, progress)
              + IngestMalfind(conn, malfind, progress)
              + IngestNetscan(conn, netscan, progress);
        progress?.Invoke($"memory: ingested {n} rows");
        return n;
    }

    // ---- ingestion --------------------------------------------------------

    private static int IngestProcesses(SqliteConnection conn, List<Dictionary<string, JsonElement>>? live,
        List<Dictionary<string, JsonElement>>? scan, Action<string>? progress)
    {
        if (live is null && scan is null) return 0;
        var livePids = new HashSet<long>();
        foreach (var r in live ?? new()) { var p = Long(r, "PID"); if (p.HasValue) livePids.Add(p.Value); }
        var scanPids = new HashSet<long>();
        foreach (var r in scan ?? new()) { var p = Long(r, "PID"); if (p.HasValue) scanPids.Add(p.Value); }

        var all = new Dictionary<long, (string? name, long? ppid, string? create, string? exit, bool inLive, bool inScan)>();
        void Merge(List<Dictionary<string, JsonElement>>? rows, bool isLive, bool isScan)
        {
            foreach (var r in rows ?? new())
            {
                var pid = Long(r, "PID"); if (!pid.HasValue) continue;
                all.TryGetValue(pid.Value, out var cur);
                all[pid.Value] = (cur.name ?? Str(r, "ImageFileName") ?? Str(r, "Name"),
                    cur.ppid ?? Long(r, "PPID"), cur.create ?? Str(r, "CreateTime"),
                    cur.exit ?? Str(r, "ExitTime"), cur.inLive || isLive, cur.inScan || isScan);
            }
        }
        Merge(live, true, false); Merge(scan, false, true);

        var findings = new List<(string, string, string, string, string?)>();
        using (var tx = conn.BeginTransaction())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO memory_processes (pid,ppid,name,create_utc,exit_utc,source) VALUES ($pid,$ppid,$n,$c,$e,$s)";
            var pPid = P(cmd, "$pid"); var pPpid = P(cmd, "$ppid"); var pN = P(cmd, "$n");
            var pC = P(cmd, "$c"); var pE = P(cmd, "$e"); var pS = P(cmd, "$s");
            foreach (var kv in all)
            {
                var (name, ppid, create, exit, inLive, inScan) = kv.Value;
                var src = inLive && inScan ? "both" : inLive ? "pslist" : "psscan";
                pPid.Value = kv.Key; pPpid.Value = (object?)ppid ?? DBNull.Value; pN.Value = (object?)name ?? DBNull.Value;
                pC.Value = (object?)create ?? DBNull.Value; pE.Value = (object?)exit ?? DBNull.Value; pS.Value = src;
                cmd.ExecuteNonQuery();
                // psscan-only (not in the pslist linked list) = classic DKOM hiding
                if (inScan && !inLive)
                    findings.Add(("memory-hidden-process", "high",
                        $"Process visible only to pool scan (possible DKOM hiding): {name ?? "?"} (PID {kv.Key})",
                        "present in windows.psscan but absent from windows.pslist", create));
            }
            tx.Commit();
        }
        InsertFindings(conn, findings, "memory_processes", "T1014 | Rootkit (DKOM process hiding)");
        return all.Count;
    }

    private static int IngestMalfind(SqliteConnection conn, List<Dictionary<string, JsonElement>>? rows, Action<string>? progress)
    {
        if (rows is null) return 0;
        var findings = new List<(string, string, string, string, string?)>();
        using (var tx = conn.BeginTransaction())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "INSERT INTO memory_injections (pid,process,protection,tag,vpn_start,vpn_end,has_pe) VALUES ($pid,$p,$pr,$t,$s,$e,$pe)";
            var pPid = P(cmd, "$pid"); var pP = P(cmd, "$p"); var pPr = P(cmd, "$pr");
            var pT = P(cmd, "$t"); var pS = P(cmd, "$s"); var pE = P(cmd, "$e"); var pPe = P(cmd, "$pe");
            foreach (var r in rows)
            {
                var pid = Long(r, "PID"); var proc = Str(r, "Process");
                var prot = Str(r, "Protection"); var tag = Str(r, "Tag");
                var disasm = Str(r, "Disasm") ?? ""; var hex = Str(r, "Hexdump") ?? "";
                var hasPe = hex.Contains("4d 5a") || hex.StartsWith("MZ") || disasm.Length > 0;
                pPid.Value = (object?)pid ?? DBNull.Value; pP.Value = (object?)proc ?? DBNull.Value;
                pPr.Value = (object?)prot ?? DBNull.Value; pT.Value = (object?)tag ?? DBNull.Value;
                pS.Value = (object?)Str(r, "Start VPN") ?? DBNull.Value; pE.Value = (object?)Str(r, "End VPN") ?? DBNull.Value;
                pPe.Value = hasPe ? 1 : 0;
                cmd.ExecuteNonQuery();
                findings.Add(("memory-injected-code", "critical",
                    $"Injected/hollowed code in process {proc ?? "?"} (PID {pid})",
                    $"malfind region protection={prot}; tag={tag}{(hasPe ? "; PE header present" : "")}", null));
            }
            tx.Commit();
        }
        InsertFindings(conn, findings, "memory_injections", "T1055 | Process Injection");
        return rows.Count;
    }

    private static int IngestNetscan(SqliteConnection conn, List<Dictionary<string, JsonElement>>? rows, Action<string>? progress)
    {
        if (rows is null) return 0;
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO memory_netscan (proto,local_addr,local_port,foreign_addr,foreign_port,state,pid,owner,created_utc) VALUES ($p,$la,$lp,$fa,$fp,$st,$pid,$o,$c)";
        var pP = P(cmd, "$p"); var pLa = P(cmd, "$la"); var pLp = P(cmd, "$lp"); var pFa = P(cmd, "$fa");
        var pFp = P(cmd, "$fp"); var pSt = P(cmd, "$st"); var pPid = P(cmd, "$pid"); var pO = P(cmd, "$o"); var pC = P(cmd, "$c");
        foreach (var r in rows)
        {
            pP.Value = (object?)Str(r, "Proto") ?? DBNull.Value;
            pLa.Value = (object?)Str(r, "LocalAddr") ?? DBNull.Value; pLp.Value = (object?)Long(r, "LocalPort") ?? DBNull.Value;
            pFa.Value = (object?)Str(r, "ForeignAddr") ?? DBNull.Value; pFp.Value = (object?)Long(r, "ForeignPort") ?? DBNull.Value;
            pSt.Value = (object?)Str(r, "State") ?? DBNull.Value; pPid.Value = (object?)Long(r, "PID") ?? DBNull.Value;
            pO.Value = (object?)Str(r, "Owner") ?? DBNull.Value; pC.Value = (object?)Str(r, "Created") ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return rows.Count;
    }

    // ---- volatility invocation + json -------------------------------------

    private static List<Dictionary<string, JsonElement>>? RunPlugin((string File, string[] Pre) vol, string image, string plugin, Action<string>? progress)
    {
        try
        {
            var args = new List<string>(vol.Pre) { "-q", "-r", "json", "-f", image, plugin };
            if (!TryRun(vol.File, args.ToArray(), out var stdout, 3_600_000) || string.IsNullOrWhiteSpace(stdout))
            { progress?.Invoke($"memory: {plugin} produced no output (skipped)"); return null; }
            var doc = JsonDocument.Parse(stdout);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            var rows = new List<Dictionary<string, JsonElement>>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.ValueKind != JsonValueKind.Object) continue;
                var d = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in el.EnumerateObject()) if (prop.Name != "__children") d[prop.Name] = prop.Value.Clone();
                rows.Add(d);
            }
            progress?.Invoke($"memory: {plugin} -> {rows.Count} rows");
            return rows;
        }
        catch (Exception ex) { progress?.Invoke($"memory: {plugin} failed: {ex.Message}"); return null; }
    }

    private static bool TryRun(string file, string[] args, out string stdout, int timeoutMs = 15000)
    {
        stdout = "";
        try
        {
            var psi = new ProcessStartInfo { FileName = file, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in args) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi);
            if (p is null) return false;
            var so = p.StandardOutput.ReadToEndAsync();
            _ = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(true); } catch { } return false; }
            stdout = so.GetAwaiter().GetResult();
            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    private static string? OnPath(string name)
    {
        var paths = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator);
        foreach (var dir in paths)
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            try { var f = Path.Combine(dir, name); if (File.Exists(f)) return f; } catch { }
        }
        return null;
    }

    // ---- helpers ----------------------------------------------------------

    private static string? Str(Dictionary<string, JsonElement> r, string k)
    {
        if (!r.TryGetValue(k, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.ToString(),
            JsonValueKind.Null => null,
            _ => v.ToString()
        };
    }

    private static long? Long(Dictionary<string, JsonElement> r, string k)
    {
        if (!r.TryGetValue(k, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l)) return l;
        if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out var s)) return s;
        return null;
    }

    private static void InsertFindings(SqliteConnection conn,
        List<(string rule, string sev, string sum, string det, string? ts)> rows, string table, string technique)
    {
        if (rows.Count == 0) return;
        using var tx = conn.BeginTransaction();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO findings (rule,severity,summary,detail,ts_utc,technique,artifact_table) VALUES ($r,$s,$su,$d,$ts,$tech,$tbl)";
        var pr = P(cmd, "$r"); var ps = P(cmd, "$s"); var psu = P(cmd, "$su");
        var pd = P(cmd, "$d"); var pts = P(cmd, "$ts"); var ptech = P(cmd, "$tech"); var ptbl = P(cmd, "$tbl");
        ptech.Value = technique; ptbl.Value = table;
        foreach (var (rule, sev, sum, det, ts) in rows)
        {
            pr.Value = rule; ps.Value = sev; psu.Value = sum; pd.Value = (object?)det ?? DBNull.Value; pts.Value = (object?)ts ?? DBNull.Value;
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}
