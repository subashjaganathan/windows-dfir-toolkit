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
    [string]$OutputName = "HawkWindowsCollector.exe",
    [string]$SignThumbprint = "",   # Authenticode cert thumbprint in Cert:\CurrentUser\My (real cert)
    [switch]$NoSign                  # skip signing entirely
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

# 4. Code signing. Uses a real cert if -SignThumbprint is given; otherwise auto-generates a
#    self-signed code-signing cert so the exe is always Authenticode-signed. NOTE: a self-signed
#    signature proves integrity but is NOT trusted on other machines until the cert is added to
#    Trusted Publishers - re-sign with a CA-issued cert for external distribution.
$SignStatus = "unsigned"
if (-not $NoSign) {
    try {
        $cert = $null
        if ($SignThumbprint) {
            $cert = Get-Item "Cert:\CurrentUser\My\$SignThumbprint" -ErrorAction SilentlyContinue
            if (-not $cert) { $cert = Get-Item "Cert:\LocalMachine\My\$SignThumbprint" -ErrorAction SilentlyContinue }
            if (-not $cert) { throw "certificate $SignThumbprint not found in CurrentUser\My or LocalMachine\My" }
        } else {
            # Publisher identity for the signature (shown as the publisher once the cert is trusted).
            $subject = "CN=DFIR-Hawk, O=DFIR-Hawk"
            $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
            if (-not $cert) {
                Write-Host "[*] Generating self-signed code-signing certificate..." -ForegroundColor Cyan
                $cert = New-SelfSignedCertificate -Subject $subject -Type CodeSigningCert `
                    -CertStoreLocation Cert:\CurrentUser\My -KeyUsage DigitalSignature `
                    -KeyLength 2048 -NotAfter (Get-Date).AddYears(5) -ErrorAction Stop
            }
        }
        Write-Host "[*] Signing with $($cert.Subject) [$($cert.Thumbprint)]..." -ForegroundColor Cyan
        $sig = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm SHA256 `
            -TimestampServer "http://timestamp.digicert.com" -ErrorAction Stop
        $SignStatus = "$($sig.Status) (signer: $($cert.Subject))"
        Write-Host "[+] Signature: $($sig.Status)" -ForegroundColor Green
    } catch {
        Write-Warning "[!] Signing failed: $_"
        $SignStatus = "sign-failed"
    }
}

# 5. Hash the artifact.
$ExeMB   = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
$ExeHash = (Get-FileHash $ExePath -Algorithm SHA256).Hash
"$ExeHash  $OutputName" | Out-File "$ExePath.sha256" -Encoding ASCII
Remove-Item $StageDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Built: $ExePath ($ExeMB MB)" -ForegroundColor Green
Write-Host "[+] SHA256: $ExeHash" -ForegroundColor Green
Write-Host "[+] Signature: $SignStatus" -ForegroundColor Green
Write-Host "[+] Attach this exe to a GitHub Release (do not commit it to the repo tree)." -ForegroundColor Cyan
if (-not $SignThumbprint -and -not $NoSign) {
    Write-Host "[!] Signed with a SELF-SIGNED cert (integrity only). Re-sign with a CA-issued" -ForegroundColor Yellow
    Write-Host "    code-signing certificate (-SignThumbprint) before external distribution." -ForegroundColor Yellow
}
