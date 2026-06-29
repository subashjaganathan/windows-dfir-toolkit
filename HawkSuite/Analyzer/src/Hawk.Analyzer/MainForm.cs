using System.Reflection;
using System.Text.Json;
using Hawk.Core;
using Microsoft.Data.Sqlite;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Hawk.Analyzer;

/// <summary>
/// Hawk Analyzer main window — a WebView2-hosted UI in a desktop shell,
/// the same architecture Redline used (XulRunner/Gecko in a window).
/// </summary>
public class MainForm : Form
{
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill };
    private SqliteConnection? _db;
    private string? _dbPath;
    private readonly string? _preload;

    public MainForm(string? preload = null)
    {
        _preload = preload;
        Text = "Hawk Analyzer";
        Width = 1380; Height = 860;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = System.Drawing.Color.FromArgb(16, 20, 28);
        Controls.Add(_web);
        Load += async (_, _) => await InitWebView();
        FormClosed += (_, _) => _db?.Dispose();
    }

    private async Task InitWebView()
    {
        var userData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HawkSuite", "WebView2");
        var env = await CoreWebView2Environment.CreateAsync(null, userData);
        await _web.EnsureCoreWebView2Async(env);
        _web.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        _web.CoreWebView2.Settings.IsStatusBarEnabled = false;
        _web.CoreWebView2.WebMessageReceived += OnWebMessage;
        _web.CoreWebView2.NavigationCompleted += async (_, _) =>
        {
            if (_preload == null) return;
            try
            {
                var dbPath = _preload.EndsWith(".hawk", StringComparison.OrdinalIgnoreCase)
                    ? await Task.Run(() => AnalysisService.ImportAndScore(_preload,
                        msg => Reply("progress", msg, null), Parsers.RawParsers.All))
                    : _preload;
                SwitchDb(dbPath);
                Reply("autoload", new { dbPath }, null);
            }
            catch (Exception ex) { Reply("progress", "preload failed: " + ex.Message, null); }
        };
        _web.CoreWebView2.NavigateToString(LoadUiHtml());
    }

    private static string LoadUiHtml()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().First(n => n.EndsWith("index.html"));
        using var s = asm.GetManifestResourceStream(name)!;
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    // ------------------------- JS <-> C# bridge -------------------------------
    private async void OnWebMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string reqId = "";
        try
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            var root = doc.RootElement;
            var cmd = root.GetProperty("cmd").GetString()!;
            reqId = root.GetProperty("reqId").GetString() ?? "";

            object? data = cmd switch
            {
                "pickAndImport" => await PickAndImport(),
                "openAnalysis"  => OpenAnalysis(),
                "sessionInfo"   => RequireDb(c => (object)AnalysisService.GetSessionInfo(c)),
                "worklist"      => RequireDb(c => (object)AnalysisService.GetWorklist(c)),
                "persistence"   => RequireDb(c => (object)AnalysisService.GetPersistenceWorklist(c)),
                "network"       => RequireDb(c => (object)AnalysisService.GetNetwork(c)),
                "timeline"      => RequireDb(c => (object)AnalysisService.GetTimeline(c,
                                       root.TryGetProperty("fromUtc", out var f) ? f.GetString() : null,
                                       root.TryGetProperty("toUtc", out var to) ? to.GetString() : null)),
                "findings"      => RequireDb(c => (object)AnalysisService.GetFindings(c)),
                "events"        => RequireDb(c => (object)AnalysisService.GetEvents(c,
                                       root.TryGetProperty("channel", out var ch) ? ch.GetString() : null,
                                       root.TryGetProperty("eventId", out var eid) && eid.ValueKind == JsonValueKind.Number ? eid.GetInt64() : null,
                                       root.TryGetProperty("contains", out var q) ? q.GetString() : null)),
                "eventDetail"   => RequireDb(c => (object?)AnalysisService.GetEventDetail(c,
                                       root.GetProperty("id").GetInt64()) ?? new Dictionary<string, object?>()),
                "execEvidence"  => RequireDb(c => (object)AnalysisService.GetExecutionEvidence(c)),
                "report"        => GenerateReport(),
                "setTag"        => RequireDb(c =>
                                   {
                                       AnalysisService.SetTag(c,
                                           root.TryGetProperty("table", out var tb) ? tb.GetString() ?? "processes" : "processes",
                                           root.GetProperty("id").GetInt64(),
                                           root.TryGetProperty("tag", out var t) ? t.GetString() : null,
                                           root.TryGetProperty("note", out var n) ? n.GetString() : null);
                                       return (object)true;
                                   }),
                _ => throw new InvalidOperationException($"unknown cmd {cmd}")
            };
            Reply(reqId, data, null);
        }
        catch (Exception ex)
        {
            Reply(reqId, null, ex.Message);
        }
    }

    private void Reply(string reqId, object? data, string? error)
    {
        var json = JsonSerializer.Serialize(new { reqId, data, error });
        if (InvokeRequired) BeginInvoke(() => _web.CoreWebView2.PostWebMessageAsJson(json));
        else _web.CoreWebView2.PostWebMessageAsJson(json);
    }

    private object? RequireDb(Func<SqliteConnection, object> fn)
    {
        if (_db == null) throw new InvalidOperationException("No session open");
        return fn(_db);
    }

    private async Task<object?> PickAndImport()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Import Hawk session",
            Filter = "Hawk session (*.hawk)|*.hawk|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return null;

        var hawkFile = dlg.FileName;
        var dbPath = await Task.Run(() => AnalysisService.ImportAndScore(hawkFile,
            msg => Reply("progress", msg, null), Parsers.RawParsers.All));
        SwitchDb(dbPath);
        return new { dbPath };
    }

    private object? OpenAnalysis()
    {
        using var dlg = new OpenFileDialog
        {
            Title = "Open existing analysis",
            Filter = "Hawk analysis db (hawk.db)|hawk.db|SQLite db (*.db)|*.db"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return null;
        SwitchDb(dlg.FileName);
        return new { dbPath = dlg.FileName };
    }

    private object? GenerateReport()
    {
        if (_db == null) throw new InvalidOperationException("No session open");
        using var dlg = new SaveFileDialog
        {
            Title = "Save HTML incident report",
            Filter = "HTML report (*.html)|*.html",
            FileName = $"HawkReport_{Path.GetFileName(Path.GetDirectoryName(_dbPath))}.html"
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return null;
        var path = ReportBuilder.Build(_db, dlg.FileName);
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true }); }
        catch { /* opening in browser is best-effort */ }
        return new { path };
    }

    private void SwitchDb(string dbPath)
    {
        _db?.Dispose();
        _db = Db.Open(dbPath);
        _dbPath = dbPath;
        Text = $"Hawk Analyzer — {Path.GetFileName(Path.GetDirectoryName(dbPath))}";
    }
}
