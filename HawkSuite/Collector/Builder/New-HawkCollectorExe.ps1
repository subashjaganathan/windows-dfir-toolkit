<#
.SYNOPSIS
    Wraps a built Hawk Collector package folder into a SINGLE self-extracting
    executable (HawkCollector.exe) for deployment to isolated / quarantined
    hosts. No internet and no third-party tools required: it compiles a tiny
    .NET launcher with the in-box C# compiler (csc.exe) and embeds the whole
    package (modules, runtime, config, and any staged Tools\ like go-winpmem)
    as a resource.

    The produced .exe:
      - requests Administrator at launch (UAC prompt; no "run as admin" needed),
      - extracts the package to a temp folder,
      - runs the collector, writing the .hawk next to the .exe (e.g. the USB),
        falling back to %SystemDrive%\HawkOutput then %TEMP% if not writable,
      - cleans up the temp folder afterwards.

.EXAMPLE
    .\New-HawkCollectorExe.ps1 -PackageRoot C:\Users\me\HawkCollector -OutputExe C:\Users\me\HawkCollector.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [Parameter(Mandatory)][string]$OutputExe
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path (Join-Path $PackageRoot 'Runtime\Collector.ps1'))) {
    throw "PackageRoot does not look like a built collector (missing Runtime\Collector.ps1): $PackageRoot"
}

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
if (-not (Test-Path $csc)) { throw "In-box C# compiler not found (csc.exe). .NET Framework 4.x is required to build the .exe." }
$fwDir   = Split-Path $csc
$zipAsm  = Join-Path $fwDir 'System.IO.Compression.FileSystem.dll'
$zipAsm2 = Join-Path $fwDir 'System.IO.Compression.dll'

Write-Host "[*] Building self-extracting HawkCollector.exe" -ForegroundColor Cyan

$build = Join-Path $env:TEMP ("hawkexe_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $build | Out-Null
try {
    # --- Stage a clean copy of the package (exclude stray outputs) -----------
    $stage = Join-Path $build 'pkg'
    Copy-Item -LiteralPath $PackageRoot -Destination $stage -Recurse -Force
    Get-ChildItem $stage -Recurse -Include '*.hawk','*.hawk.sha256' -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    # --- Zip the staged package (structure preserved) ------------------------
    $payload = Join-Path $build 'payload.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $payload,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Host ("[+] Package payload: {0:N1} MB" -f ((Get-Item $payload).Length / 1MB))

    # --- Manifest: request Administrator at launch ---------------------------
    $manifest = Join-Path $build 'app.manifest'
@'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
'@ | Out-File $manifest -Encoding utf8

    # --- C# launcher source --------------------------------------------------
    $src = Join-Path $build 'HawkLauncher.cs'
@'
using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.IO.Compression;

class HawkLauncher {
    static int Main() {
        Console.Title = "Hawk Collector";
        Console.WriteLine("=== Hawk Collector (self-extracting, offline-capable) ===");
        string tmp = Path.Combine(Path.GetTempPath(), "HawkCollector_" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(tmp);
        try {
            string zipPath = Path.Combine(tmp, "payload.zip");
            using (Stream rs = Assembly.GetExecutingAssembly().GetManifestResourceStream("HawkCollector.payload")) {
                if (rs == null) { Console.WriteLine("[!] Embedded payload missing."); return 2; }
                using (FileStream fs = File.Create(zipPath)) { rs.CopyTo(fs); }
            }
            Console.WriteLine("[*] Extracting collector...");
            string pkg = Path.Combine(tmp, "pkg");
            ZipFile.ExtractToDirectory(zipPath, pkg);
            try { File.Delete(zipPath); } catch {}

            string collector = Path.Combine(pkg, "Runtime", "Collector.ps1");
            if (!File.Exists(collector)) { Console.WriteLine("[!] Collector.ps1 not found after extract."); return 3; }

            string outDir = ChooseOutputDir();
            Console.WriteLine("[*] Output (.hawk) will be written to: " + outDir);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + collector + "\" -PackageRoot \"" + pkg + "\" -OutputDir \"" + outDir + "\"";
            psi.UseShellExecute = false;
            Process p = Process.Start(psi);
            p.WaitForExit();
            Console.WriteLine();
            Console.WriteLine("[+] Collection finished. Look for the .hawk in: " + outDir);
            return p.ExitCode;
        }
        catch (Exception ex) { Console.WriteLine("[!] Error: " + ex.Message); return 1; }
        finally {
            try { Directory.Delete(tmp, true); } catch {}
            Console.WriteLine("Press any key to close...");
            try { Console.ReadKey(); } catch {}
        }
    }

    static string ChooseOutputDir() {
        try { string d = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); if (IsWritable(d)) return d; } catch {}
        try {
            string sd = Environment.GetEnvironmentVariable("SystemDrive"); if (string.IsNullOrEmpty(sd)) sd = "C:";
            string ho = Path.Combine(sd + "\\", "HawkOutput"); Directory.CreateDirectory(ho); if (IsWritable(ho)) return ho;
        } catch {}
        return Path.GetTempPath();
    }
    static bool IsWritable(string dir) {
        try { string t = Path.Combine(dir, ".hwk_" + Guid.NewGuid().ToString("N").Substring(0, 6)); File.WriteAllText(t, "x"); File.Delete(t); return true; }
        catch { return false; }
    }
}
'@ | Out-File $src -Encoding utf8

    # --- Compile -------------------------------------------------------------
    New-Item -ItemType Directory -Force (Split-Path $OutputExe) | Out-Null
    $args = @(
        '/nologo', '/target:exe', '/platform:anycpu',
        "/win32manifest:$manifest",
        "/reference:$zipAsm2", "/reference:$zipAsm",
        "/resource:$payload,HawkCollector.payload",
        "/out:$OutputExe",
        $src
    )
    & $csc @args
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputExe)) { throw "csc.exe compilation failed (exit $LASTEXITCODE)" }

    Write-Host ("[+] Built: {0} ({1:N1} MB)" -f $OutputExe, ((Get-Item $OutputExe).Length / 1MB)) -ForegroundColor Green
    Write-Host "    Copy this single file to the target. Double-click (it prompts for Admin)."
    Write-Host "    The .hawk lands beside the .exe, or in %SystemDrive%\HawkOutput if the exe's folder is read-only."
}
finally {
    Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue
}
