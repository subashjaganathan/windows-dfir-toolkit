// Windows DFIR Toolkit - self-extracting launcher stub.
// Compiled by Build-Exe.ps1 with the whole toolkit embedded as a zip resource ("toolkit.zip").
// At runtime it: self-elevates (UAC), extracts the toolkit to a fresh working directory, and
// runs Run_IR_Collection.ps1. This preserves the toolkit's modular Scripts\ folder structure
// (unlike flat self-extractors) and keeps collection deterministic - the launcher only unpacks
// and invokes; it makes no collection decisions.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;

// Embedded file metadata (shown in the exe's Details tab) - identifies it as a forensic tool.
[assembly: AssemblyTitle("Hawk Windows Collector")]
[assembly: AssemblyProduct("Hawk Windows Collector")]
[assembly: AssemblyCompany("Windows DFIR Toolkit")]
[assembly: AssemblyDescription("Forensically sound Windows incident-response evidence collector")]
[assembly: AssemblyCopyright("MIT License")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyVersion("1.0.0.0")]

static class DfirLauncher
{
    static bool IsAdmin()
    {
        try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    static int Main(string[] args)
    {
        string joined = string.Join(" ", args);

        // Re-launch elevated if not already Administrator (collection needs admin for full coverage).
        if (!IsAdmin())
        {
            try
            {
                var psi = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName)
                {
                    Arguments = joined,
                    Verb = "runas",
                    UseShellExecute = true
                };
                Process.Start(psi);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Administrator elevation was declined or failed: " + ex.Message);
                Console.Error.WriteLine("    Right-click the executable and choose 'Run as administrator'.");
                return 1;
            }
        }

        // Extract the embedded toolkit to a fresh working directory.
        string work = Path.Combine(Path.GetTempPath(), "DFIR_Toolkit_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
        Directory.CreateDirectory(work);
        string zipPath = Path.Combine(work, "_toolkit.zip");
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using (var s = asm.GetManifestResourceStream("toolkit.zip"))
            {
                if (s == null) { Console.Error.WriteLine("[!] Embedded toolkit resource not found."); return 2; }
                using (var f = File.Create(zipPath)) { s.CopyTo(f); }
            }
            ZipFile.ExtractToDirectory(zipPath, work);
            File.Delete(zipPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[!] Failed to extract toolkit: " + ex.Message);
            return 3;
        }

        // Locate the orchestrator (root of the extracted tree, or one level down if the zip nested it).
        string runner = Path.Combine(work, "Run_IR_Collection.ps1");
        if (!File.Exists(runner))
        {
            foreach (var d in Directory.GetDirectories(work))
            {
                string cand = Path.Combine(d, "Run_IR_Collection.ps1");
                if (File.Exists(cand)) { runner = cand; break; }
            }
        }
        if (!File.Exists(runner))
        {
            Console.Error.WriteLine("[!] Run_IR_Collection.ps1 not found in the extracted package.");
            return 4;
        }

        Console.WriteLine("========================================================");
        Console.WriteLine("   Hawk Windows Collector - forensic evidence collection");
        Console.WriteLine("========================================================");
        Console.WriteLine("[*] Extracted to: " + work);
        Console.WriteLine("[*] Launching collection (elevated, ExecutionPolicy Bypass)...");

        var run = new ProcessStartInfo("powershell.exe",
            "-NoProfile -ExecutionPolicy Bypass -File \"" + runner + "\" " + joined)
        {
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(runner)
        };
        try
        {
            var proc = Process.Start(run);
            proc.WaitForExit();
            return proc.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[!] Failed to launch collection: " + ex.Message);
            return 5;
        }
    }
}
