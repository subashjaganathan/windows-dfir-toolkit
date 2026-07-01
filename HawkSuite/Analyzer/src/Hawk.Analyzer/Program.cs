using System.Runtime.InteropServices;
using System.Text.Json;
using Hawk.Core;

namespace Hawk.Analyzer;

internal static class Program
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    [STAThread]
    private static int Main(string[] args)
    {
        // `hawk <file.hawk|hawk.db>` → GUI preloaded (double-click association)
        if (args.Length == 1 && File.Exists(args[0]) &&
            (args[0].EndsWith(".hawk", StringComparison.OrdinalIgnoreCase) ||
             args[0].EndsWith(".db", StringComparison.OrdinalIgnoreCase)))
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm(args[0]));
            return 0;
        }

        if (args.Length > 0)
        {
            AttachConsole(-1); // reuse the launching console for CLI mode
            return RunCli(args);
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    // ----------------------------- CLI mode ---------------------------------
    private static int RunCli(string[] args)
    {
        switch (args[0].ToLowerInvariant())
        {
            case "import":
            {
                if (args.Length < 2) { Usage(); return 1; }
                Console.WriteLine($"\n[*] Importing session: {args[1]}");
                var dbPath = AnalysisService.ImportAndScore(args[1],
                    msg => Console.WriteLine($"    {msg}"), Parsers.RawParsers.All);
                Console.WriteLine($"[+] Session database: {dbPath}");
                return 0;
            }
            case "findings":
            {
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                foreach (var row in AnalysisService.GetFindings(conn))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["severity"],-9} {d["tsUtc"] ?? "[UNKNOWN]",-22} {d["rule"]}");
                    Console.WriteLine($"          {d["summary"]}");
                    if (d["detail"] != null) Console.WriteLine($"          {d["detail"]}");
                }
                return 0;
            }
            case "events":
            {
                // hawk events <hawk.db> [channel] [eventId]
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                var channel = args.Length > 2 ? args[2] : null;
                long? eid = args.Length > 3 && long.TryParse(args[3], out var e) ? e : null;
                foreach (var row in AnalysisService.GetEvents(conn, channel, eid, limit: 200))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["tsUtc"],-22} {d["eventId"],6}  {d["channel"]}");
                    Console.WriteLine($"          {d["summary"]}");
                }
                return 0;
            }
            case "worklist":
            {
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                foreach (var row in AnalysisService.GetWorklist(conn, onlyScored: true))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["score"],4}  {d["band"],-8} {d["pid"],6}  {d["name"]}");
                    Console.WriteLine($"      path : {d["path"] ?? "[no disk backing]"}");
                    foreach (var rule in JsonDocument.Parse((string)d["matchedRules"]!).RootElement.EnumerateArray())
                        Console.WriteLine($"      rule : {rule.GetProperty("rule").GetString()} (+{rule.GetProperty("points").GetInt32()})");
                }
                return 0;
            }
            case "persistence":
            {
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                foreach (var row in AnalysisService.GetPersistenceWorklist(conn))
                {
                    var d = (IDictionary<string, object?>)row;
                    if ((int)d["score"]! == 0) continue;
                    Console.WriteLine($"{d["score"],4}  {d["band"],-8} {d["table"],-18} {d["name"]}");
                    Console.WriteLine($"      cmd  : {d["detail"]}");
                    foreach (var rule in JsonDocument.Parse((string)d["matchedRules"]!).RootElement.EnumerateArray())
                        Console.WriteLine($"      rule : {rule.GetProperty("rule").GetString()} (+{rule.GetProperty("points").GetInt32()})");
                }
                return 0;
            }
            case "report":
            {
                // hawk report <hawk.db|session.hawk> [-o file.html]
                var (inputs, output) = SplitOutputArg(args.Skip(1));
                if (inputs.Count != 1) { Usage(); return 1; }
                var dbPath = inputs[0].EndsWith(".hawk", StringComparison.OrdinalIgnoreCase)
                    ? AnalysisService.ImportAndScore(inputs[0], m => Console.WriteLine($"    {m}"), Parsers.RawParsers.All)
                    : inputs[0];
                using var conn = Db.Open(dbPath);
                var path = ReportBuilder.Build(conn, output);
                Console.WriteLine($"[+] Report written: {path}");
                return 0;
            }
            case "evidence":
            {
                // hawk evidence <hawk.db> — prefetch/shimcache/amcache rollup
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                foreach (var row in AnalysisService.GetExecutionEvidence(conn))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["tsUtc"] ?? "[UNKNOWN]",-22} {d["source"],-24} {d["name"]}");
                    Console.WriteLine($"          {d["detail"]}");
                }
                return 0;
            }
            case "usn":
            {
                // hawk usn <hawk.db> [filter]
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                var filter = args.Length > 2 ? args[2] : null;
                foreach (var row in AnalysisService.GetUsnRecords(conn, filter, 1000))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["tsUtc"] ?? "[UNKNOWN]",-22} {d["fileName"],-40} {d["reasons"]}");
                }
                return 0;
            }
            case "srum":
            {
                // hawk srum <hawk.db> [filter] — per-app resource + network usage, top volume first
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                var filter = args.Length > 2 ? args[2] : null;
                foreach (var row in AnalysisService.GetSrum(conn, filter, 1000))
                {
                    var d = (IDictionary<string, object?>)row;
                    var sent = d["bytesSent"] as long?; var recv = d["bytesRecvd"] as long?;
                    var vol = (sent.HasValue || recv.HasValue) ? $"  sent={sent ?? 0} recvd={recv ?? 0}" : "";
                    Console.WriteLine($"{d["tsUtc"] ?? "[UNKNOWN]",-22} {d["provider"],-13} {d["app"]}{vol}");
                }
                return 0;
            }
            case "mft":
            {
                // hawk mft <hawk.db> [filter] [--deleted]
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                var filter = args.Skip(2).FirstOrDefault(a => !a.StartsWith("--"));
                var deletedOnly = args.Contains("--deleted");
                foreach (var row in AnalysisService.GetMftEntries(conn, filter, deletedOnly, 1000))
                {
                    var d = (IDictionary<string, object?>)row;
                    var state = (bool)d["inUse"]! ? " " : "X";   // X = deleted
                    Console.WriteLine($"[{state}] {d["siModifiedUtc"] ?? "[UNKNOWN]",-22} {d["fullPath"] ?? d["fileName"]}");
                }
                return 0;
            }
            case "timeline":
            {
                if (args.Length < 2) { Usage(); return 1; }
                using var conn = Db.Open(args[1]);
                foreach (var row in AnalysisService.GetTimeline(conn,
                    args.Length > 2 ? args[2] : null, args.Length > 3 ? args[3] : null))
                {
                    var d = (IDictionary<string, object?>)row;
                    Console.WriteLine($"{d["tsUtc"],-22} {d["category"],-14} {d["summary"]}");
                }
                return 0;
            }
            case "whitelist" when args.Length >= 3 && args[1].Equals("build", StringComparison.OrdinalIgnoreCase):
            {
                // hawk whitelist build <nsrl-input>... [-o <dir>]
                var (inputs, output) = SplitOutputArg(args.Skip(2));
                output ??= AnalysisService.FindConfigDir("Whitelist")
                    ?? Path.Combine(AppContext.BaseDirectory, "Configuration", "Whitelist");
                try
                {
                    Console.WriteLine($"\n[*] Building NSRL whitelist → {output}");
                    var (count, path) = WhitelistBuilder.Build(inputs, output, progress: m => Console.WriteLine($"    {m}"));
                    Console.WriteLine($"[+] {count:N0} hashes indexed: {path}");
                    Console.WriteLine("    Every future `hawk import` now suppresses NSRL-known binaries.");
                    return 0;
                }
                catch (Exception ex) { Console.WriteLine($"[!] {ex.Message}"); return 1; }
            }
            case "baseline" when args.Length >= 3 && args[1].Equals("create", StringComparison.OrdinalIgnoreCase):
            {
                // hawk baseline create <session.hawk|hawk.db> [-o <file>]
                var (inputs, output) = SplitOutputArg(args.Skip(2));
                if (inputs.Count != 1) { Usage(); return 1; }
                output ??= Path.Combine(
                    AnalysisService.FindConfigDir("Whitelist")
                        ?? Path.Combine(AppContext.BaseDirectory, "Configuration", "Whitelist"),
                    "org-baseline.json");
                try
                {
                    Console.WriteLine("\n[*] Building org baseline from gold-image session");
                    Console.WriteLine("    WARNING: only use a session from a KNOWN-CLEAN reference host.");
                    var (count, path) = BaselineBuilder.Create(inputs[0], output, m => Console.WriteLine($"    {m}"));
                    Console.WriteLine($"[+] {count:N0} binaries baselined: {path}");
                    return 0;
                }
                catch (Exception ex) { Console.WriteLine($"[!] {ex.Message}"); return 1; }
            }
            default:
                Usage();
                return 1;
        }
    }

    /// <summary>Splits trailing `-o <path>` from a positional argument list.</summary>
    private static (List<string> inputs, string? output) SplitOutputArg(IEnumerable<string> args)
    {
        var inputs = new List<string>();
        string? output = null;
        var list = args.ToList();
        for (var i = 0; i < list.Count; i++)
        {
            if (list[i] is "-o" or "--output")
            {
                if (i + 1 < list.Count) output = list[++i];
            }
            else inputs.Add(list[i]);
        }
        return (inputs, output);
    }

    private static void Usage() => Console.WriteLine("""

        Hawk Analyzer v0.4
        usage:
          hawk                                      launch the analysis GUI
          hawk import <session.hawk>                import session (incl. EVTX/prefetch/shimcache/
                                                    amcache raw parsing), build hawk.db, run MRI
          hawk worklist <hawk.db>                   print MRI-ranked process worklist
          hawk persistence <hawk.db>                print MRI-ranked persistence worklist
          hawk findings <hawk.db>                   print event-rule findings (sprays, log clears...)
          hawk events <hawk.db> [channel] [eid]     print parsed event-log rows
          hawk evidence <hawk.db>                   print execution evidence (prefetch/shim/amcache)
          hawk mft <hawk.db> [filter] [--deleted]   query $MFT (file inventory; --deleted = deleted only)
          hawk usn <hawk.db> [filter]               query $UsnJrnl change journal (create/delete/rename)
          hawk srum <hawk.db> [filter]              query SRUM per-app resource + network usage (top volume first)
          hawk report <hawk.db|session> [-o f.html] generate a self-contained HTML incident report
          hawk timeline <hawk.db> [from] [to]       print timeline (ISO-8601 UTC bounds)
          hawk whitelist build <nsrl>... [-o dir]   build nsrl.bloom from NSRL RDS
                                                    (RDSv3 .db | NSRLFile.txt | md5-per-line .txt)
          hawk baseline create <session> [-o file]  build org-baseline.json from a
                                                    KNOWN-CLEAN gold-image session
        """);
}
