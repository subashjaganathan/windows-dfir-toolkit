#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a single self-extracting Windows DFIR Toolkit executable.

.DESCRIPTION
    Packages the entire toolkit (Run_IR_Collection.ps1 + Scripts\ + Tools\ + IOCs\ + docs) into
    a zip, embeds it as a resource inside a small C# launcher (Build\Launcher.cs), and compiles
    a standalone .exe with the .NET Framework C# compiler (csc.exe, present on all Windows).

    The resulting exe self-elevates (UAC), extracts the toolkit to a fresh temp working folder,
    and runs the orchestrator. The launcher only unpacks and invokes - it makes no collection
    decisions, so collection stays deterministic and forensically sound.

    The .exe is a BUILD ARTIFACT (dist\) and is intentionally NOT committed to the repo; attach
    it to a GitHub Release instead. Sign it (signtool) before distribution to avoid AV noise.

.PARAMETER SignThumbprint
    Optional Authenticode certificate thumbprint. If supplied, the exe is signed via signtool.

.EXAMPLE
    .\Build\Build-Exe.ps1
    .\Build\Build-Exe.ps1 -SignThumbprint A1B2C3...
#>
param(
    [string]$OutputName = "WindowsDFIRToolkit.exe",
    [string]$SignThumbprint = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$DistDir  = Join-Path $RepoRoot "dist"
$StageDir = Join-Path $env:TEMP ("dfir_build_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
$ZipPath  = Join-Path $StageDir "toolkit.zip"
$ExePath  = Join-Path $DistDir $OutputName
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir  -Force | Out-Null

Write-Host "[*] Repo root : $RepoRoot" -ForegroundColor Cyan
Write-Host "[*] Staging   : $StageDir" -ForegroundColor Cyan

# 1. Stage the toolkit content (exclude repo/dev cruft and the build output itself).
$Include = @("Run_IR_Collection.ps1","Scripts","Tools","IOCs","README.md","LICENSE","DFIR_TOOLKIT_REFERENCE.txt")
$PkgDir  = Join-Path $StageDir "pkg"
New-Item -ItemType Directory -Path $PkgDir -Force | Out-Null
foreach ($item in $Include) {
    $src = Join-Path $RepoRoot $item
    if (Test-Path $src) { Copy-Item $src -Destination $PkgDir -Recurse -Force }
}

# 2. Zip the staged content (contents at the zip root -> extracts flat with Scripts\ preserved).
Write-Host "[*] Compressing toolkit..." -ForegroundColor Cyan
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path (Join-Path $PkgDir "*") -DestinationPath $ZipPath -Force
$ZipMB = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
Write-Host "[*] toolkit.zip = $ZipMB MB" -ForegroundColor Cyan

# 3. Compile the launcher with the embedded zip resource.
$Csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $Csc)) { $Csc = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
if (-not (Test-Path $Csc)) { throw "csc.exe (.NET Framework C# compiler) not found." }
$Launcher = Join-Path $PSScriptRoot "Launcher.cs"
if (-not (Test-Path $Launcher)) { throw "Launcher.cs not found at $Launcher" }

Write-Host "[*] Compiling with csc.exe..." -ForegroundColor Cyan
if (Test-Path $ExePath) { Remove-Item $ExePath -Force }
$cscArgs = @(
    "/nologo","/target:exe","/platform:anycpu","/optimize+",
    "/reference:System.IO.Compression.FileSystem.dll",
    "/resource:$ZipPath,toolkit.zip",
    "/out:$ExePath",
    $Launcher
)
& $Csc @cscArgs
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ExePath)) { throw "Compilation failed (csc exit $LASTEXITCODE)." }

# 4. Optional code signing.
if ($SignThumbprint) {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
    if ($SignTool) {
        Write-Host "[*] Signing with cert $SignThumbprint..." -ForegroundColor Cyan
        & $SignTool.FullName sign /sha1 $SignThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $ExePath
    } else { Write-Warning "[!] signtool.exe not found - skipping signing." }
}

# 5. Hash the artifact.
$ExeMB   = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
$ExeHash = (Get-FileHash $ExePath -Algorithm SHA256).Hash
"$ExeHash  $OutputName" | Out-File "$ExePath.sha256" -Encoding ASCII
Remove-Item $StageDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Built: $ExePath ($ExeMB MB)" -ForegroundColor Green
Write-Host "[+] SHA256: $ExeHash" -ForegroundColor Green
Write-Host "[+] Attach this exe to a GitHub Release (do not commit it to the repo tree)." -ForegroundColor Cyan
if (-not $SignThumbprint) { Write-Host "[!] Unsigned - sign before distribution to minimize AV false positives." -ForegroundColor Yellow }
