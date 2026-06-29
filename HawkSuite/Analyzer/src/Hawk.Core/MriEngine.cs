using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Hawk.Core;

/// <summary>
/// Malware Risk Index engine. Trust ladder first (NSRL → baseline → signer →
/// expected-process conformance), scoring rules only for what remains.
/// Clean-room reimplementation of the Redline MRI concept.
/// </summary>
public class MriEngine
{
    private readonly JsonElement _cfg;
    private readonly HashSet<string> _trustedSigners;
    private readonly Dictionary<string, JsonElement> _expectedProcs;
    private readonly HashSet<string> _svchostGroups;
    private readonly IWhitelist _whitelist;

    public MriEngine(string mriConfigPath, IWhitelist whitelist)
    {
        _cfg = JsonDocument.Parse(File.ReadAllText(mriConfigPath)).RootElement.Clone();
        _whitelist = whitelist;
        _trustedSigners = _cfg.GetProperty("trustedSigners").EnumerateArray()
            .Select(e => e.GetString()!.ToLowerInvariant()).ToHashSet();
        _expectedProcs = _cfg.GetProperty("expectedSystemProcesses").EnumerateArray()
            .ToDictionary(e => e.GetProperty("name").GetString()!.ToLowerInvariant(), e => e.Clone());
        _svchostGroups = _cfg.GetProperty("knownSvchostGroups").EnumerateArray()
            .Select(e => e.GetString()!.ToLowerInvariant()).ToHashSet();
    }

    public void ScoreProcesses(SqliteConnection conn, string hostRole)
    {
        var modifiers = LoadRoleModifiers(hostRole);
        using var read = conn.CreateCommand();
        read.CommandText = "SELECT id, name, path, command_line, user, md5, signature_status, signer, parent_name FROM processes";
        var rows = new List<(long id, string? name, string? path, string? cl, string? user, string? md5, string? sig, string? signer, string? parent)>();
        using (var r = read.ExecuteReader())
            while (r.Read())
                rows.Add((r.GetInt64(0), S(r,1), S(r,2), S(r,3), S(r,4), S(r,5), S(r,6), S(r,7), S(r,8)));

        using var tx = conn.BeginTransaction();
        using var write = conn.CreateCommand();
        write.CommandText = """
            INSERT OR REPLACE INTO mri_scores (artifact_table, artifact_id, score, band, trust_verdict, matched_rules)
            VALUES ('processes', $id, $score, $band, $verdict, $rules)
            """;
        var pId = P(write, "$id"); var pScore = P(write, "$score");
        var pBand = P(write, "$band"); var pVerdict = P(write, "$verdict"); var pRules = P(write, "$rules");

        foreach (var row in rows)
        {
            var (verdict, score, matched) = Evaluate(row, modifiers);
            pId.Value = row.id; pScore.Value = score; pBand.Value = Band(score, verdict);
            pVerdict.Value = verdict; pRules.Value = JsonSerializer.Serialize(matched);
            write.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private (string verdict, int score, List<object> matched)
        Evaluate((long id, string? name, string? path, string? cl, string? user, string? md5, string? sig, string? signer, string? parent) p,
                 Dictionary<string, double> modifiers)
    {
        var matched = new List<object>();

        // ---- Trust ladder, step 0: known-bad always wins -------------------
        if (p.md5 != null && _whitelist.IsKnownBad(p.md5))
            return ("MALICIOUS", 100, [new { rule = "known-bad-hash", points = 100 }]);

        // Binary-identity trust: suppresses IDENTITY rules only. Behavioral
        // rules below run regardless — a validly signed powershell.exe with an
        // -enc payload is still an -enc payload (signer trust is about the
        // file, not the invocation).
        var binaryTrusted =
            (p.md5 != null && _whitelist.IsKnownGood(p.md5)) ||
            (p.sig == "Valid" && p.signer != null &&
             _trustedSigners.Any(ts => p.signer.ToLowerInvariant().Contains(ts)));

        var name = (p.name ?? "").ToLowerInvariant();
        var path = (p.path ?? "").ToLowerInvariant();
        var score = 0.0;
        void Hit(string rule, int points)
        {
            var mod = modifiers.GetValueOrDefault(rule, 1.0);
            score += points * mod;
            matched.Add(new { rule, points = (int)(points * mod) });
        }

        // ---- IDENTITY rules (skipped for trusted binaries) ------------------
        if (!binaryTrusted)
        {
            if (_expectedProcs.TryGetValue(name, out var exp))
            {
                var okPaths = exp.GetProperty("paths").EnumerateArray().Select(e => e.GetString()!.ToLowerInvariant());
                if (path.Length > 0 && !okPaths.Any(path.Contains)) Hit("system-process-wrong-path", 40);

                if (exp.TryGetProperty("users", out var users) && p.user != null)
                {
                    var u = p.user.ToLowerInvariant();
                    if (!users.EnumerateArray().Any(e => u.Contains(e.GetString()!.ToLowerInvariant())))
                    {
                        // svchost user-mode service groups are legitimate exceptions
                        var userModeOk = name == "svchost.exe" && IsUserModeServiceGroup(p.cl);
                        if (!userModeOk) Hit("system-process-wrong-user", 30);
                    }
                }
                if (exp.TryGetProperty("parents", out var parents) && p.parent != null)
                {
                    var par = p.parent.ToLowerInvariant();
                    if (!parents.EnumerateArray().Any(e => par == e.GetString()!.ToLowerInvariant()))
                        Hit("system-process-wrong-parent", 35);
                }
                if (name == "svchost.exe" && !KnownSvchostGroup(p.cl))
                    Hit("svchost-unknown-group", 25);
            }

            if (TrustedSignerInvalid(p.sig, p.signer))
                Hit("masquerading-signer", 25);

            var userWritable = new[] { @"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\perflogs\" };
            if (p.sig is "NotSigned" or "Unknown" && userWritable.Any(path.Contains))
                Hit("unsigned-in-user-writable", 20);
            else if (p.sig == "NotSigned" && path.Length > 0)
                Hit("unsigned-not-whitelisted", 8);   // deliberately low — old toolkit's main FP source
        }

        // ---- BEHAVIORAL rules (always evaluated) -----------------------------
        var cl = (p.cl ?? "").ToLowerInvariant();
        if (name is "powershell.exe" or "pwsh.exe" &&
            (cl.Contains(" -enc") || cl.Contains(" -e ") || cl.Contains("iex(") || cl.Contains("downloadstring")))
            Hit("encoded-powershell", 25);

        var officeParents = new[] { "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe" };
        if ((name is "cmd.exe" or "powershell.exe" or "wscript.exe" or "cscript.exe") &&
            officeParents.Contains((p.parent ?? "").ToLowerInvariant()))
            Hit("started-by-shell-from-office", 35);

        // LOLBAS: only WITH suspicious arguments (bare execution scores zero by design)
        if ((name == "certutil.exe" && (cl.Contains("-urlcache") || cl.Contains("-decode"))) ||
            (name == "mshta.exe" && cl.Contains("http")) ||
            (name == "regsvr32.exe" && cl.Contains("/i:http")) ||
            (name == "rundll32.exe" && cl.Contains("javascript:")))
            Hit("lolbas-suspicious-args", 25);

        var final = Math.Min(100, (int)score);
        if (final > 0) return ("SCORED", final, matched);
        return (binaryTrusted ? "TRUSTED" : "NEUTRAL", 0, matched);
    }

    // ===================== persistence artifact scoring =====================

    /// <summary>Scores all persistence artifact tables with the same trust ladder.</summary>
    public void ScorePersistence(SqliteConnection conn, string hostRole)
    {
        var modifiers = LoadRoleModifiers(hostRole);
        ScoreBinaryBacked(conn, modifiers, "services",
            "SELECT id, path_name, binary_path, md5, signature_status, signer, service_dll_md5, service_dll_sig_status, service_dll_signer FROM services",
            ServiceRules);
        ScoreBinaryBacked(conn, modifiers, "registry_runkeys",
            "SELECT id, command, binary_path, md5, signature_status, signer, NULL, NULL, NULL FROM registry_runkeys",
            CommandRules);
        ScoreBinaryBacked(conn, modifiers, "scheduled_tasks",
            "SELECT id, execute || ' ' || COALESCE(arguments,''), binary_path, md5, signature_status, signer, NULL, NULL, NULL FROM scheduled_tasks",
            CommandRules);
        ScoreBinaryBacked(conn, modifiers, "startup_folder",
            "SELECT id, COALESCE(target, item_path) || ' ' || COALESCE(target_arguments,''), COALESCE(target, item_path), md5, signature_status, signer, NULL, NULL, NULL FROM startup_folder",
            CommandRules);
        ScoreWmi(conn, modifiers);
    }

    private delegate void ExtraRules(
        (string? command, string? binaryPath, string? dllMd5, string? dllSig, string? dllSigner) row,
        Action<string, int> hit);

    private void ScoreBinaryBacked(SqliteConnection conn, Dictionary<string, double> modifiers,
        string table, string selectSql, ExtraRules extraRules)
    {
        var rows = new List<(long id, string? cmd, string? bin, string? md5, string? sig, string? signer, string? dllMd5, string? dllSig, string? dllSigner)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = selectSql;
            using var r = read.ExecuteReader();
            while (r.Read())
                rows.Add((r.GetInt64(0), S(r,1), S(r,2), S(r,3), S(r,4), S(r,5), S(r,6), S(r,7), S(r,8)));
        }

        using var tx = conn.BeginTransaction();
        using var write = conn.CreateCommand();
        write.CommandText = """
            INSERT OR REPLACE INTO mri_scores (artifact_table, artifact_id, score, band, trust_verdict, matched_rules)
            VALUES ($t, $id, $score, $band, $verdict, $rules)
            """;
        var pT = P(write, "$t"); var pId = P(write, "$id"); var pScore = P(write, "$score");
        var pBand = P(write, "$band"); var pVerdict = P(write, "$verdict"); var pRules = P(write, "$rules");
        pT.Value = table;

        foreach (var row in rows)
        {
            var matched = new List<object>();
            var score = 0.0;
            string verdict;
            void Hit(string rule, int points)
            {
                var mod = modifiers.GetValueOrDefault(rule, 1.0);
                score += points * mod;
                matched.Add(new { rule, points = (int)(points * mod) });
            }

            // ---- trust ladder, step 0: known-bad always wins ----
            if (row.md5 != null && _whitelist.IsKnownBad(row.md5))
                { verdict = "MALICIOUS"; score = 100; matched.Add(new { rule = "known-bad-hash", points = 100 }); }
            else
            {
                // Binary-identity trust suppresses identity rules only.
                // Behavioral command-string rules ALWAYS run: a run key invoking
                // a signed powershell.exe with -enc is still malicious persistence.
                var binaryTrusted =
                    ((row.md5 != null && _whitelist.IsKnownGood(row.md5)) || TrustedValidSigner(row.sig, row.signer)) &&
                    (row.dllMd5 == null || _whitelist.IsKnownGood(row.dllMd5) || TrustedValidSigner(row.dllSig, row.dllSigner));

                if (!binaryTrusted)
                {
                    // ---- identity rules ----
                    var path = (row.bin ?? "").ToLowerInvariant();
                    var userWritable = new[] { @"\temp\", @"\appdata\", @"\downloads\", @"\public\", @"$recycle.bin", @"\perflogs\" };
                    if (row.sig is "NotSigned" or "Unknown" && userWritable.Any(path.Contains) && path.Length > 0)
                        Hit("persistence-unsigned-user-writable", 25);
                    if (TrustedSignerInvalid(row.sig, row.signer))
                        Hit("masquerading-signer", 25);
                    if (row.dllMd5 != null && row.dllSig is "NotSigned" or "Invalid" && !_whitelist.IsKnownGood(row.dllMd5))
                        Hit("unsigned-not-whitelisted", 8);
                }

                // ---- behavioral rules (always) ----
                extraRules((row.cmd, row.bin, row.dllMd5, row.dllSig, row.dllSigner), Hit);
                verdict = score > 0 ? "SCORED" : (binaryTrusted ? "TRUSTED" : "NEUTRAL");
            }

            pId.Value = row.id; pScore.Value = Math.Min(100, (int)score);
            pBand.Value = Band(Math.Min(100, (int)score), verdict);
            pVerdict.Value = verdict; pRules.Value = JsonSerializer.Serialize(matched);
            write.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>Service-specific rules (on top of the common binary rules).</summary>
    private void ServiceRules(
        (string? command, string? binaryPath, string? dllMd5, string? dllSig, string? dllSigner) row,
        Action<string, int> hit)
    {
        var raw = row.command ?? "";   // services pass path_name as command
        var lower = raw.ToLowerInvariant();

        // unquoted path containing spaces before the executable
        if (!raw.StartsWith('"') && raw.Contains(' '))
        {
            var exeIdx = lower.IndexOf(".exe", StringComparison.Ordinal);
            if (exeIdx > 0 && raw[..exeIdx].Contains(' '))
                hit("unquoted-service-path", 15);
        }
        if (lower.Contains("cmd.exe /c") || lower.Contains("cmd /c") ||
            lower.Contains("powershell") || lower.Contains("wscript") || lower.Contains("mshta"))
            hit("service-runs-shell", 30);
        CommandRules(row, hit);
    }

    /// <summary>Command-string rules shared by run keys, tasks, startup items, services.</summary>
    private void CommandRules(
        (string? command, string? binaryPath, string? dllMd5, string? dllSig, string? dllSigner) row,
        Action<string, int> hit)
    {
        var cl = (row.command ?? "").ToLowerInvariant();
        if (cl.Contains(" -enc") || cl.Contains(" -e ") || cl.Contains("iex(") ||
            cl.Contains("downloadstring") || cl.Contains("frombase64string"))
            hit("encoded-powershell", 25);
        if ((cl.Contains("certutil") && (cl.Contains("-urlcache") || cl.Contains("-decode"))) ||
            (cl.Contains("mshta") && cl.Contains("http")) ||
            (cl.Contains("regsvr32") && cl.Contains("/i:http")) ||
            (cl.Contains("rundll32") && cl.Contains("javascript:")))
            hit("lolbas-suspicious-args", 25);
        // command references an .exe but the collector could not resolve a file
        if (row.binaryPath == null && cl.Contains(".exe"))
            hit("persistence-target-missing", 10);
    }

    private void ScoreWmi(SqliteConnection conn, Dictionary<string, double> modifiers)
    {
        var rows = new List<(long id, string? objType)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT id, object_type FROM wmi_persistence";
            using var r = read.ExecuteReader();
            while (r.Read()) rows.Add((r.GetInt64(0), S(r, 1)));
        }

        using var tx = conn.BeginTransaction();
        using var write = conn.CreateCommand();
        write.CommandText = """
            INSERT OR REPLACE INTO mri_scores (artifact_table, artifact_id, score, band, trust_verdict, matched_rules)
            VALUES ('wmi_persistence', $id, $score, $band, $verdict, $rules)
            """;
        var pId = P(write, "$id"); var pScore = P(write, "$score");
        var pBand = P(write, "$band"); var pVerdict = P(write, "$verdict"); var pRules = P(write, "$rules");

        foreach (var (id, objType) in rows)
        {
            var (rule, pts) = objType switch
            {
                "CommandLineEventConsumer"  => ("wmi-commandline-consumer", 35),
                "ActiveScriptEventConsumer" => ("wmi-activescript-consumer", 45),
                _ => ((string?)null, 0)   // filters and bindings: context, not findings
            };
            var mod = rule == null ? 1.0 : modifiers.GetValueOrDefault(rule, 1.0);
            var score = (int)(pts * mod);
            pId.Value = id; pScore.Value = score;
            pBand.Value = Band(score, score > 0 ? "SCORED" : "NEUTRAL");
            pVerdict.Value = score > 0 ? "SCORED" : "NEUTRAL";
            pRules.Value = rule == null ? "[]" : JsonSerializer.Serialize(new[] { new { rule, points = score } });
            write.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private bool TrustedValidSigner(string? sig, string? signer) =>
        sig == "Valid" && signer != null &&
        _trustedSigners.Any(ts => signer.ToLowerInvariant().Contains(ts));

    private bool TrustedSignerInvalid(string? sig, string? signer) =>
        sig == "Invalid" && signer != null &&
        _trustedSigners.Any(ts => signer.ToLowerInvariant().Contains(ts));

    private bool KnownSvchostGroup(string? commandLine)
    {
        var g = ExtractSvchostGroup(commandLine);
        return g == null || _svchostGroups.Contains(g);
    }

    private bool IsUserModeServiceGroup(string? commandLine)
    {
        var g = ExtractSvchostGroup(commandLine);
        if (g == null) return false;
        return _cfg.GetProperty("userModeServiceGroups").EnumerateArray()
            .Any(e => e.GetString()!.ToLowerInvariant() == g);
    }

    private static string? ExtractSvchostGroup(string? commandLine)
    {
        if (commandLine == null) return null;
        var m = System.Text.RegularExpressions.Regex.Match(commandLine, @"-k\s+([\w]+)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
    }

    private Dictionary<string, double> LoadRoleModifiers(string role)
    {
        var d = new Dictionary<string, double>();
        if (_cfg.GetProperty("roleModifiers").TryGetProperty(role, out var mods))
            foreach (var m in mods.EnumerateObject())
                if (m.Value.ValueKind == JsonValueKind.Number) d[m.Name] = m.Value.GetDouble();
        return d;
    }

    private static string Band(int score, string verdict) => verdict switch
    {
        "TRUSTED" => "trusted",
        "MALICIOUS" => "critical",
        _ => score switch { 0 => "trusted", <= 19 => "low", <= 39 => "medium", <= 69 => "high", _ => "critical" }
    };

    private static string? S(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);
    private static SqliteParameter P(SqliteCommand c, string n)
    { var p = c.CreateParameter(); p.ParameterName = n; c.Parameters.Add(p); return p; }
}

/// <summary>Whitelist abstraction — Phase 2 adds the NSRL bloom filter + org baseline.</summary>
public interface IWhitelist
{
    bool IsKnownGood(string md5);
    bool IsKnownBad(string md5);
}

/// <summary>Placeholder until the NSRL bloom filter is built (hawk whitelist build).</summary>
public class EmptyWhitelist : IWhitelist
{
    public bool IsKnownGood(string md5) => false;
    public bool IsKnownBad(string md5) => false;
}
