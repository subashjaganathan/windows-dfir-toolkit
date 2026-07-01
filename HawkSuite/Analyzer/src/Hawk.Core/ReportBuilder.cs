using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Generates a self-contained HTML incident report from a SCORED session db.
///
/// Design contract (the v1 toolkit's report was the user's main complaint):
///  - Reports only what the analysis layer actually concluded. Trusted/zero-
///    score items are summarized as counts, never listed as "findings".
///  - Every number is derived from the db at render time — no hard-coded totals.
///  - Analyst tags are authoritative: a 'benign' tag suppresses an item from the
///    findings section; a 'confirmed' tag promotes it regardless of score.
///  - Unknown timestamps render as [UNKNOWN], never as collection time.
///  - No external assets, no scripts: one portable .html the analyst can archive.
/// </summary>
public static class ReportBuilder
{
    public static string Build(SqliteConnection conn, string? outputPath = null)
    {
        var info = AnalysisService.GetSessionInfo(conn);
        var host = info.GetValueOrDefault("hostname") as string ?? "unknown-host";
        var caseNo = info.GetValueOrDefault("caseNumber") as string ?? "";
        outputPath ??= Path.Combine(Directory.GetCurrentDirectory(),
            $"HawkReport_{Sanitize(caseNo)}_{Sanitize(host)}.html");

        IReadOnlyList<dynamic> procs = AnalysisService.GetWorklist(conn, onlyScored: true);
        IReadOnlyList<dynamic> pers = AnalysisService.GetPersistenceWorklist(conn)
            .Where(r => Get<int>(r, "score") > 0).Cast<dynamic>().ToList();
        IReadOnlyList<dynamic> findings = AnalysisService.GetFindings(conn);
        IReadOnlyList<dynamic> evidence = AnalysisService.GetExecutionEvidence(conn);
        var iocs = GetIocHits(conn);

        // tags
        var confirmed = CountTag(conn, "confirmed");
        var benign = new HashSet<(string, long)>(GetTagged(conn, "benign"));

        var sb = new StringBuilder(1 << 18);
        Head(sb, host, caseNo);
        Summary(sb, conn, info, procs, pers, findings, iocs, confirmed);
        FindingsSection(sb, findings, iocs);
        ProcessSection(sb, procs, benign);
        PersistenceSection(sb, pers, benign);
        EvidenceSection(sb, evidence);
        TimelineSection(sb, conn);
        HostSection(sb, info);
        CustodySection(sb, conn, info);
        Foot(sb);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        File.WriteAllText(outputPath, sb.ToString(), new UTF8Encoding(false));
        return outputPath;
    }

    // ----------------------------------------------------------------- summary
    private static void Summary(StringBuilder sb, SqliteConnection conn,
        Dictionary<string, object?> info, IReadOnlyList<dynamic> procs, IReadOnlyList<dynamic> pers,
        IReadOnlyList<dynamic> findings, List<(string, string, string, string?)> iocs, int confirmed)
    {
        int crit = findings.Count(f => Get<string>(f, "severity") == "critical")
                 + procs.Count(p => Get<string>(p, "band") == "critical")
                 + pers.Count(p => Get<string>(p, "band") == "critical");
        int high = findings.Count(f => Get<string>(f, "severity") == "high")
                 + procs.Count(p => Get<string>(p, "band") == "high")
                 + pers.Count(p => Get<string>(p, "band") == "high");

        // Overall posture is driven by the strongest signal present.
        var (verdict, vClass) =
            confirmed > 0 || crit > 0 ? ("Critical activity identified", "critical") :
            high > 0 || iocs.Count > 0 ? ("Suspicious activity requires review", "high") :
            (procs.Count + pers.Count + findings.Count) > 0 ? ("Low-confidence items to review", "medium") :
            ("No scored findings — clean within collected scope", "trusted");

        long evtCount = ScalarLong(conn, "SELECT COUNT(*) FROM event_logs");
        long tlCount = ScalarLong(conn, "SELECT COUNT(*) FROM timeline");

        sb.Append($"""
            <section class="card">
              <h2>Executive Summary</h2>
              <div class="verdict v-{vClass}">{Enc(verdict)}</div>
              <div class="grid">
                <div class="metric"><span class="num c-critical">{crit}</span><span>Critical</span></div>
                <div class="metric"><span class="num c-high">{high}</span><span>High</span></div>
                <div class="metric"><span class="num">{confirmed}</span><span>Analyst-confirmed</span></div>
                <div class="metric"><span class="num">{iocs.Count}</span><span>IOC matches</span></div>
                <div class="metric"><span class="num">{procs.Count}</span><span>Scored processes</span></div>
                <div class="metric"><span class="num">{pers.Count}</span><span>Scored persistence</span></div>
                <div class="metric"><span class="num">{findings.Count}</span><span>Event findings</span></div>
                <div class="metric"><span class="num">{evtCount:N0}</span><span>Events parsed</span></div>
                <div class="metric"><span class="num">{tlCount:N0}</span><span>Timeline rows</span></div>
              </div>
              <p class="note">Scope note: these conclusions cover only the artifacts collected in this
              session. Items the analyzer trusted (signed/known-good binaries, expected system processes)
              are intentionally excluded from the findings below to avoid the false-positive noise of
              raw collection. Counts above are computed from the session database at render time.</p>
            </section>
            """);
    }

    // ---------------------------------------------------------------- findings
    private static void FindingsSection(StringBuilder sb, IReadOnlyList<dynamic> findings,
        List<(string rule, string sev, string detail, string? ts)> iocs)
    {
        sb.Append("<section class=\"card\"><h2>Findings</h2>");
        if (findings.Count == 0 && iocs.Count == 0)
        {
            sb.Append("<p class=\"empty\">No event-rule findings or IOC matches in scope.</p></section>");
            return;
        }
        sb.Append("<table><thead><tr><th>Severity</th><th>Rule</th><th>MITRE ATT&amp;CK</th><th>Time (UTC)</th><th>Detail</th></tr></thead><tbody>");
        foreach (var f in findings)
            Row(sb, Get<string>(f, "severity"), Get<string>(f, "rule"), Get<string>(f, "technique"),
                Get<string>(f, "tsUtc"), Get<string>(f, "summary"), Get<string>(f, "detail"));
        foreach (var (rule, sev, detail, ts) in iocs)
            Row(sb, sev, rule, "T1071 | Application Layer Protocol", ts, detail, null);
        sb.Append("</tbody></table></section>");

        static void Row(StringBuilder sb, string? sev, string? rule, string? technique, string? ts, string? summary, string? detail)
        {
            var s = (sev ?? "low").ToLowerInvariant();
            sb.Append($"<tr><td><span class=\"badge b-{s}\">{Enc(sev)}</span></td>"
                + $"<td>{Enc(rule)}</td><td class=\"mono small\">{Enc(technique) ?? "<i>-</i>"}</td>"
                + $"<td class=\"mono\">{Enc(ts) ?? "<i>[UNKNOWN]</i>"}</td>"
                + $"<td>{Enc(summary)}{(string.IsNullOrEmpty(detail) ? "" : $"<div class=\"sub\">{Enc(detail)}</div>")}</td></tr>");
        }
    }

    // --------------------------------------------------------------- processes
    private static void ProcessSection(StringBuilder sb, IReadOnlyList<dynamic> procs, HashSet<(string, long)> benign)
    {
        sb.Append("<section class=\"card\"><h2>Scored Processes</h2>");
        var shown = procs.Where(p => !benign.Contains(("processes", Get<long>(p, "id")))).ToList();
        if (shown.Count == 0) { sb.Append("<p class=\"empty\">No scored processes (all trusted or tagged benign).</p></section>"); return; }
        sb.Append("<table><thead><tr><th>MRI</th><th>Process</th><th>PID</th><th>User</th><th>Path</th><th>Signature</th><th>Matched rules</th></tr></thead><tbody>");
        foreach (var p in shown)
        {
            sb.Append($"<tr><td><span class=\"badge b-{Get<string>(p, "band")}\">{Get<int>(p, "score")}</span></td>"
                + $"<td>{Enc(Get<string>(p, "name"))}{TagMark(p)}</td><td class=\"mono\">{Get<long?>(p, "pid")}</td>"
                + $"<td>{Enc(Get<string>(p, "user"))}</td>"
                + $"<td class=\"mono small\">{Enc(Get<string>(p, "path")) ?? "<i class='c-critical'>[no disk backing]</i>"}</td>"
                + $"<td>{Enc(Get<string>(p, "signatureStatus"))}</td>"
                + $"<td class=\"small\">{Rules(Get<string>(p, "matchedRules"))}</td></tr>");
        }
        sb.Append("</tbody></table></section>");
    }

    private static void PersistenceSection(StringBuilder sb, IReadOnlyList<dynamic> pers, HashSet<(string, long)> benign)
    {
        sb.Append("<section class=\"card\"><h2>Scored Persistence</h2>");
        var shown = pers.Where(p => !benign.Contains((Get<string>(p, "table")!, Get<long>(p, "id")))).ToList();
        if (shown.Count == 0) { sb.Append("<p class=\"empty\">No scored persistence items.</p></section>"); return; }
        sb.Append("<table><thead><tr><th>MRI</th><th>Type</th><th>Name</th><th>Command / Target</th><th>Matched rules</th></tr></thead><tbody>");
        foreach (var p in shown)
            sb.Append($"<tr><td><span class=\"badge b-{Get<string>(p, "band")}\">{Get<int>(p, "score")}</span></td>"
                + $"<td>{Enc(Get<string>(p, "table"))}</td><td>{Enc(Get<string>(p, "name"))}{TagMark(p)}</td>"
                + $"<td class=\"mono small\">{Enc(Get<string>(p, "detail"))}</td>"
                + $"<td class=\"small\">{Rules(Get<string>(p, "matchedRules"))}</td></tr>");
        sb.Append("</tbody></table></section>");
    }

    private static void EvidenceSection(StringBuilder sb, IReadOnlyList<dynamic> evidence)
    {
        if (evidence.Count == 0) return;
        sb.Append("<section class=\"card\"><h2>Execution Evidence</h2>"
            + "<p class=\"note\">Prefetch run times are execution evidence. Shimcache/Amcache timestamps are "
            + "file metadata (presence), NOT execution times — labeled accordingly.</p>"
            + "<table><thead><tr><th>Source</th><th>File / Executable</th><th>Timestamp (UTC)</th><th>Detail</th></tr></thead><tbody>");
        foreach (var e in evidence.Take(500))
            sb.Append($"<tr><td>{Enc(Get<string>(e, "source"))}</td><td class=\"mono small\">{Enc(Get<string>(e, "name"))}</td>"
                + $"<td class=\"mono\">{Enc(Get<string>(e, "tsUtc")) ?? "<i>[UNKNOWN]</i>"}</td>"
                + $"<td class=\"small\">{Enc(Get<string>(e, "detail"))}</td></tr>");
        sb.Append("</tbody></table></section>");
    }

    private static void TimelineSection(StringBuilder sb, SqliteConnection conn)
    {
        // Only the high-signal categories — the full timeline lives in the GUI.
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT ts_utc, category, summary FROM timeline
            WHERE ts_utc IS NOT NULL
              AND category IN ('DefenseEvasion','Malware','Persistence','CredentialAccess','LateralMovement','AccountManagement')
            ORDER BY ts_utc DESC LIMIT 200
            """;
        var rows = new List<(string ts, string cat, string sum)>();
        using (var r = cmd.ExecuteReader())
            while (r.Read()) rows.Add((r.GetString(0), r.IsDBNull(1) ? "" : r.GetString(1), r.IsDBNull(2) ? "" : r.GetString(2)));
        if (rows.Count == 0) return;
        sb.Append("<section class=\"card\"><h2>Key Timeline (high-signal categories)</h2>"
            + "<table><thead><tr><th>Time (UTC)</th><th>Category</th><th>Event</th></tr></thead><tbody>");
        foreach (var (ts, cat, sum) in rows)
            sb.Append($"<tr><td class=\"mono\">{Enc(ts)}</td><td>{Enc(cat)}</td><td class=\"small\">{Enc(sum)}</td></tr>");
        sb.Append("</tbody></table></section>");
    }

    private static void HostSection(StringBuilder sb, Dictionary<string, object?> info)
    {
        sb.Append("<section class=\"card\"><h2>Host Information</h2><div class=\"kv\">");
        void Kv(string k, object? v) { if (v != null) sb.Append($"<div class=\"k\">{Enc(k)}</div><div class=\"v\">{Enc(v.ToString())}</div>"); }
        Kv("Hostname", info.GetValueOrDefault("hostname"));
        Kv("Role", info.GetValueOrDefault("role"));
        Kv("OS", info.GetValueOrDefault("os"));
        Kv("Collection preset", info.GetValueOrDefault("preset"));
        Kv("Collected (UTC)", info.GetValueOrDefault("collectedUtc"));
        Kv("Investigator", info.GetValueOrDefault("investigator"));
        sb.Append("</div></section>");
    }

    private static void CustodySection(StringBuilder sb, SqliteConnection conn, Dictionary<string, object?> info)
    {
        sb.Append("<section class=\"card\"><h2>Chain of Custody</h2><div class=\"kv\">");
        void Kv(string k, string? v) { sb.Append($"<div class=\"k\">{Enc(k)}</div><div class=\"v mono\">{Enc(v) ?? "—"}</div>"); }
        Kv("Case number", info.GetValueOrDefault("caseNumber") as string);
        Kv("Report generated (UTC)", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        Kv("Analyzer", "Hawk Analyzer");
        sb.Append("</div><p class=\"note\">Session integrity is sealed by the per-file SHA256 manifest (hashes.json) "
            + "inside the .hawk container and the container's own .sha256 sidecar produced at collection time. "
            + "This report is a derived view; the .hawk session remains the authoritative evidence.</p></section>");
    }

    // ------------------------------------------------------------------ IOC
    /// <summary>IOC-match findings already in the findings table (rule LIKE 'ioc-%').</summary>
    private static List<(string rule, string sev, string detail, string? ts)> GetIocHits(SqliteConnection conn)
    {
        var list = new List<(string, string, string, string?)>();
        if (!TableExists(conn, "findings")) return list;
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT rule, severity, summary, detail, ts_utc FROM findings WHERE rule LIKE 'ioc-%'";
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add((r.GetString(0), r.GetString(1),
                r.GetString(2) + (r.IsDBNull(3) ? "" : " — " + r.GetString(3)),
                r.IsDBNull(4) ? null : r.GetString(4)));
        return list;
    }

    // --------------------------------------------------------------- helpers
    private static readonly JsonSerializerOptions J = new();

    private static string Rules(string? matchedJson)
    {
        if (string.IsNullOrEmpty(matchedJson)) return "";
        try
        {
            var parts = new List<string>();
            foreach (var e in JsonDocument.Parse(matchedJson).RootElement.EnumerateArray())
                parts.Add($"{Enc(e.GetProperty("rule").GetString())} <b>+{e.GetProperty("points").GetInt32()}</b>");
            return string.Join("<br>", parts);
        }
        catch { return ""; }
    }

    private static string TagMark(dynamic row)
    {
        var tag = Get<string>(row, "tag");
        return string.IsNullOrEmpty(tag) ? "" : $" <span class=\"tag tag-{Enc(tag)}\">{Enc(tag)}</span>";
    }

    private static IEnumerable<(string, long)> GetTagged(SqliteConnection conn, string tag)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT artifact_table, artifact_id FROM tags WHERE tag = $t";
        cmd.Parameters.AddWithValue("$t", tag);
        using var r = cmd.ExecuteReader();
        while (r.Read()) yield return (r.GetString(0), r.GetInt64(1));
    }

    private static int CountTag(SqliteConnection conn, string tag)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM tags WHERE tag = $t";
        cmd.Parameters.AddWithValue("$t", tag);
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    private static bool TableExists(SqliteConnection conn, string name)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$n";
        cmd.Parameters.AddWithValue("$n", name);
        return cmd.ExecuteScalar() != null;
    }

    private static long ScalarLong(SqliteConnection conn, string sql)
    {
        try { using var c = conn.CreateCommand(); c.CommandText = sql; return Convert.ToInt64(c.ExecuteScalar()); }
        catch { return 0; }
    }

    private static T Get<T>(dynamic row, string key)
    {
        var d = (IDictionary<string, object?>)row;
        var v = d.TryGetValue(key, out var val) ? val : null;
        if (v == null) return default!;
        if (typeof(T) == typeof(int)) return (T)(object)Convert.ToInt32(v);
        if (typeof(T) == typeof(long)) return (T)(object)Convert.ToInt64(v);
        return (T)v;
    }

    private static string? Enc(string? s) => s == null ? null : WebUtility.HtmlEncode(s);
    private static string Sanitize(string s) => string.Concat(s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));

    // --------------------------------------------------------------- chrome
    private static void Head(StringBuilder sb, string host, string caseNo) => sb.Append($$"""
        <!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
        <title>Hawk IR Report — {{Enc(host)}}</title>
        <style>
          :root{--bg:#0f1320;--card:#161c2c;--line:#2a3450;--txt:#dbe2f0;--dim:#8b95ad;--accent:#4da3ff;
                --trusted:#2e7d32;--low:#7e8aa3;--medium:#c79214;--high:#e2620a;--critical:#d23030;}
          *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
            font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding:0 0 60px}
          header{background:#13182a;border-bottom:1px solid var(--line);padding:22px 36px}
          header h1{margin:0;font-size:22px;letter-spacing:1px}header h1 span{color:var(--accent)}
          header .meta{color:var(--dim);font-size:13px;margin-top:6px}
          main{max-width:1180px;margin:0 auto;padding:24px 28px}
          .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px 24px;margin:18px 0}
          .card h2{margin:0 0 14px;font-size:17px;color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:8px}
          .verdict{font-size:18px;font-weight:600;padding:10px 16px;border-radius:8px;margin-bottom:16px;display:inline-block}
          .v-critical{background:rgba(210,48,48,.15);color:#ff7a7a;border:1px solid var(--critical)}
          .v-high{background:rgba(226,98,10,.15);color:#ffac6b;border:1px solid var(--high)}
          .v-medium{background:rgba(199,146,20,.15);color:#ffd470;border:1px solid var(--medium)}
          .v-trusted{background:rgba(46,125,50,.15);color:#84d98a;border:1px solid var(--trusted)}
          .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;margin:10px 0}
          .metric{background:#1d2538;border:1px solid var(--line);border-radius:8px;padding:12px;text-align:center}
          .metric .num{display:block;font-size:26px;font-weight:700}.metric span:last-child{color:var(--dim);font-size:12px}
          table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
          th{text-align:left;color:var(--dim);font-weight:600;border-bottom:1px solid var(--line);padding:8px 10px}
          td{border-bottom:1px solid #1b2336;padding:7px 10px;vertical-align:top}
          .mono{font-family:Consolas,monospace}.small{font-size:12px}.sub{color:var(--dim);font-size:12px;margin-top:3px;word-break:break-all}
          .badge{display:inline-block;min-width:32px;text-align:center;padding:2px 8px;border-radius:9px;color:#fff;font-weight:600;font-size:12px}
          .b-trusted{background:var(--trusted)}.b-low{background:var(--low)}.b-medium{background:var(--medium);color:#1a1a1a}
          .b-high{background:var(--high)}.b-critical{background:var(--critical)}
          .c-critical{color:#ff7a7a}.c-high{color:#ffac6b}
          .tag{font-size:11px;padding:1px 7px;border-radius:7px;margin-left:6px}
          .tag-confirmed{background:var(--critical)}.tag-suspicious{background:var(--medium);color:#1a1a1a}.tag-benign{background:var(--trusted)}
          .kv{display:grid;grid-template-columns:200px 1fr;gap:6px 16px}.kv .k{color:var(--dim)}.kv .v{word-break:break-all}
          .note{color:var(--dim);font-size:12.5px;margin:12px 0 0;border-left:3px solid var(--line);padding-left:12px}
          .empty{color:var(--dim);font-style:italic}
          footer{max-width:1180px;margin:20px auto 0;padding:0 28px;color:var(--dim);font-size:12px}
        </style></head><body>
        <header><h1>HAWK <span>IR REPORT</span></h1>
          <div class="meta">Host: <b>{{Enc(host)}}</b> &nbsp;•&nbsp; Case: <b>{{Enc(caseNo)}}</b>
          &nbsp;•&nbsp; Generated {{DateTime.UtcNow:yyyy-MM-dd HH:mm}} UTC</div></header><main>
        """);

    private static void Foot(StringBuilder sb) => sb.Append("""
        </main><footer>Generated by Hawk Analyzer. This report is a derived view of the sealed .hawk
        session; conclusions are scoped to collected artifacts. Trusted/known-good items are excluded
        from findings by design to minimize false positives.</footer></body></html>
        """);
}
