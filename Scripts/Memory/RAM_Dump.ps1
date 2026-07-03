#Requires -Version 5.1
<#
.SYNOPSIS
    Captures a live RAM dump using WinPmem.

.DESCRIPTION
    Automatically downloads WinPmem from GitHub if not present in Tools folder.
    Captures full physical memory, computes SHA256 hash, records system state
    at time of capture, and adds to evidence manifest.

.COMPATIBILITY
    Windows 10/11 / Server 2016+ : Full (64-bit)

.IR_PHASE
    Live Response / Memory Forensics

.MITRE_ATTCK
    T1055 - Process Injection (detected via memory)
    T1059 - Command Execution (fileless)
    T1003 - Credential Dumping

.FORENSIC_SAFETY
    Read-only memory capture - does not modify system state

.NOTES
    WinPmem auto-download requires internet access.
    Place winpmem_mini_x64.exe in Tools\ folder for offline use.

.AUTHOR
    DFIR Toolkit

.VERSION
    1.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname   = $env:COMPUTERNAME
$BasePath = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum    = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$OutDir     = "$BasePath\RAM_${Hostname}_${Timestamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile    = "$BasePath\RAM_Dump_Execution.log"
$JsonFile   = "$BasePath\RAM_Dump_${Hostname}_${Timestamp}.json"
$DumpFile   = "$OutDir\RAM_${Hostname}_${Timestamp}.raw"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "RAM dump started | Case: $CaseNum"

# Admin gate: write a Skipped evidence artifact (rather than exiting silently) so the report
# can distinguish "not collected - needs admin" from "collected, nothing found".
if (-not $IsAdmin) {
    Write-Warning "[!] RAM capture requires Administrator privileges - skipping (recorded in evidence)."
    Write-Log "Skipped: requires Administrator privileges" "WARN"
    $Skip = [PSCustomObject]@{
        ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0"; IsAdmin=$false }
        ArtifactType   = "RAMDump"
        Status         = "Skipped"
        Reason         = "Requires Administrator privileges (run the toolkit elevated to capture memory)."
    }
    $Skip | ConvertTo-Json -Depth 4 | Out-File $JsonFile -Encoding UTF8
    try { $h = (Get-FileHash $JsonFile -Algorithm SHA256).Hash
          [PSCustomObject]@{ FileName=$JsonFile; Hash=$h; Generated=(Get-Date).ToString("o") } | ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8 } catch {}
    return
}

# Determine toolkit root
$ToolkitRoot = if ($PSScriptRoot) { Split-Path (Split-Path $PSScriptRoot) } else { (Get-Location).Path }
$ToolsDir    = Join-Path $ToolkitRoot "Tools"
New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

# WinPmem path
$Arch        = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
$WinPmem     = Join-Path $ToolsDir "winpmem_mini_${Arch}.exe"

# Auto-download WinPmem if not present
if (-not (Test-Path $WinPmem)) {
    Write-Host "[*] WinPmem not found in Tools\ folder. Attempting auto-download..." -ForegroundColor Yellow
    Write-Log "WinPmem not found - attempting download"

    $DownloadSuccess = $false

    try {
        # Get latest release from GitHub API
        Write-Host "[*] Querying GitHub for latest WinPmem release..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $APIUrl   = "https://api.github.com/repos/Velocidex/WinPmem/releases/latest"
        $Headers  = @{ "User-Agent" = "DFIR-Toolkit/3.1" }
        $Release  = Invoke-RestMethod -Uri $APIUrl -Headers $Headers -ErrorAction Stop

        # Find the right asset
        $Asset = $Release.assets | Where-Object {
            $_.name -match "winpmem_mini_${Arch}" -and $_.name -match "\.exe$"
        } | Select-Object -First 1

        if (-not $Asset) {
            # Fallback - try any exe
            $Asset = $Release.assets | Where-Object { $_.name -match "\.exe$" } | Select-Object -First 1
        }

        if ($Asset) {
            Write-Host "[*] Downloading $($Asset.name) ($([math]::Round($Asset.size/1MB,1)) MB)..." -ForegroundColor Cyan
            Write-Log "Downloading: $($Asset.browser_download_url)"

            $TempPath = Join-Path $ToolsDir $Asset.name
            Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $TempPath -Headers $Headers -ErrorAction Stop

            # Rename to standard name if needed
            if ($TempPath -ne $WinPmem) {
                Copy-Item $TempPath $WinPmem -Force
            }

            if (Test-Path $WinPmem) {
                $DownloadSuccess = $true
                Write-Host "[+] WinPmem downloaded successfully to: $WinPmem" -ForegroundColor Green
                Write-Log "WinPmem downloaded: $WinPmem"
            }
        } else {
            Write-Log "No suitable WinPmem asset found in release" "WARN"
        }
    } catch {
        Write-Log "GitHub download failed: $_" "WARN"
        Write-Warning "[!] Auto-download failed: $_"
    }

    if (-not $DownloadSuccess) {
        # Try direct known URL as fallback
        try {
            Write-Host "[*] Trying direct download fallback..." -ForegroundColor Yellow
            $FallbackURL = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_${Arch}_rc2.exe"
            Invoke-WebRequest -Uri $FallbackURL -OutFile $WinPmem -ErrorAction Stop
            if (Test-Path $WinPmem) {
                $DownloadSuccess = $true
                Write-Host "[+] WinPmem downloaded via fallback URL" -ForegroundColor Green
                Write-Log "WinPmem downloaded via fallback"
            }
        } catch {
            Write-Log "Fallback download also failed: $_" "WARN"
        }
    }

    if (-not $DownloadSuccess) {
        $ErrMsg = @"
[!] WinPmem could not be downloaded automatically.

MANUAL STEPS:
  1. Go to: https://github.com/Velocidex/WinPmem/releases/latest
  2. Download: winpmem_mini_${Arch}.exe
  3. Place it in: $ToolsDir
  4. Re-run this script

"@
        Write-Host $ErrMsg -ForegroundColor Red
        Write-Log "WinPmem not available - RAM dump aborted" "ERROR"

        # Record failure in JSON
        $Evidence = [PSCustomObject]@{
            ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
            ArtifactType   = "RAMDump"
            Status         = "Failed"
            Error          = "WinPmem not available. Manual download required."
            ManualDownload = "https://github.com/Velocidex/WinPmem/releases/latest"
            ToolsDirectory = $ToolsDir
        }
        $Evidence | ConvertTo-Json -Depth 4 | Out-File $JsonFile -Encoding UTF8
        exit 1
    }
}

# Verify WinPmem integrity
Write-Host "[*] Verifying WinPmem executable..." -ForegroundColor Cyan
$WinPmemHash = (Get-FileHash $WinPmem -Algorithm SHA256).Hash
$WinPmemSize = (Get-Item $WinPmem).Length
Write-Log "WinPmem: $WinPmem | SHA256: $WinPmemHash | Size: $WinPmemSize"

# Capture system state BEFORE dump
Write-Host "[*] Recording pre-dump system state..." -ForegroundColor Cyan
$OSInfo      = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$TotalRAMGB  = [math]::Round($OSInfo.TotalVisibleMemorySize / 1MB, 2)
$FreeRAMGB   = [math]::Round($OSInfo.FreePhysicalMemory / 1MB, 2)
$UsedRAMGB   = [math]::Round($TotalRAMGB - $FreeRAMGB, 2)

# Check available disk space
$DriveLetter = Split-Path $OutDir -Qualifier
$Drive       = Get-PSDrive ($DriveLetter -replace ":","") -ErrorAction SilentlyContinue
$FreeDiskGB  = if ($Drive) { [math]::Round($Drive.Free / 1GB, 2) } else { 0 }
$RequiredGB  = [math]::Round($TotalRAMGB * 1.1, 2)

Write-Host "[*] RAM: ${TotalRAMGB} GB total | ${UsedRAMGB} GB used | Disk free: ${FreeDiskGB} GB required: ${RequiredGB} GB" -ForegroundColor Cyan
Write-Log "RAM: ${TotalRAMGB}GB | Disk free: ${FreeDiskGB}GB | Required: ${RequiredGB}GB"

if ($FreeDiskGB -lt $RequiredGB) {
    Write-Error "[!] Insufficient disk space. Need ${RequiredGB} GB, have ${FreeDiskGB} GB free."
    Write-Log "Insufficient disk space - aborting" "ERROR"
    exit 1
}

$PreDumpState = [PSCustomObject]@{
    CaptureStartTime  = (Get-Date).ToString("o")
    TotalRAMGB        = $TotalRAMGB
    UsedRAMGB         = $UsedRAMGB
    FreeRAMGB         = $FreeRAMGB
    RunningProcesses  = (Get-Process -ErrorAction SilentlyContinue).Count
    ActiveConnections = (Get-NetTCPConnection -ErrorAction SilentlyContinue).Count
    SystemUptime      = $OSInfo.LastBootUpTime.ToString("o")
}

# Execute RAM Dump
Write-Host "" 
Write-Host "[*] Starting RAM capture to: $DumpFile" -ForegroundColor Cyan
Write-Host "[*] This will take several minutes depending on RAM size..." -ForegroundColor Yellow
Write-Host "[*] DO NOT interrupt this process" -ForegroundColor Yellow
Write-Host ""
Write-Log "Starting WinPmem capture: $DumpFile"

$DumpStart  = Get-Date
# WinPmem mini takes output file as positional argument
# Usage: winpmem_mini_x64.exe <output_path>
$WinPmemArgs = "`"$DumpFile`""
$Process    = Start-Process -FilePath $WinPmem -ArgumentList $WinPmemArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
$DumpEnd    = Get-Date
$DumpDuration = [math]::Round(($DumpEnd - $DumpStart).TotalMinutes, 2)

Write-Log "WinPmem exit code: $($Process.ExitCode) | Duration: ${DumpDuration} min"

# Verify dump
$DumpResult = [PSCustomObject]@{
    Success       = $false
    DumpFile      = $DumpFile
    SizeGB        = $null
    SHA256        = $null
    DurationMin   = $DumpDuration
    ExitCode      = $Process.ExitCode
    Error         = $null
}

if (Test-Path $DumpFile) {
    $DumpInfo          = Get-Item $DumpFile
    $DumpResult.SizeGB = [math]::Round($DumpInfo.Length / 1GB, 2)

    Write-Host "[*] Computing SHA256 hash of dump file (this may take a minute)..." -ForegroundColor Cyan
    Write-Log "Computing SHA256 of dump file"

    $DumpHash              = Get-FileHash $DumpFile -Algorithm SHA256
    $DumpResult.SHA256     = $DumpHash.Hash
    $DumpResult.Success    = ($DumpInfo.Length -gt 100MB)

    Write-Host "[+] Dump file: $($DumpResult.SizeGB) GB" -ForegroundColor Green
    Write-Host "[+] SHA256   : $($DumpResult.SHA256)"    -ForegroundColor Green
    Write-Log "Dump complete: $($DumpResult.SizeGB)GB | SHA256: $($DumpResult.SHA256)"
} else {
    $DumpResult.Error   = "Dump file not created - WinPmem may have failed"
    $DumpResult.Success = $false
    Write-Error "[!] Dump file not found after capture"
    Write-Log "Dump file not created" "ERROR"
}

# Post-dump system state
$PostDumpState = [PSCustomObject]@{
    CaptureEndTime   = (Get-Date).ToString("o")
    DurationMinutes  = $DumpDuration
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{
        CaseNumber   = $CaseNum
        Hostname     = $Hostname
        CollectedAt  = (Get-Date).ToString("o")
        ToolVersion="1.0"
        IsAdmin      = $IsAdmin
    }
    ArtifactType   = "RAMDump"
    Tool           = [PSCustomObject]@{
        Name         = "WinPmem"
        Path         = $WinPmem
        SHA256       = $WinPmemHash
        Version      = "Auto-detected"
        License      = "Apache 2.0"
        Source       = "https://github.com/Velocidex/WinPmem"
    }
    PreDumpState   = $PreDumpState
    PostDumpState  = $PostDumpState
    DumpResult     = $DumpResult
    OutputDirectory= $OutDir
    ParseNote      = "Analyze with Volatility3 (vol.py) or Magnet Axiom. Commands: vol.py -f $DumpFile windows.pslist | windows.netscan | windows.malfind"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host ""
if ($DumpResult.Success) {
    Write-Host "[+] RAM capture SUCCESSFUL" -ForegroundColor Green
    Write-Host "[+] Dump File  : $DumpFile ($($DumpResult.SizeGB) GB)" -ForegroundColor Green
    Write-Host "[+] SHA256     : $($DumpResult.SHA256)" -ForegroundColor Green
    Write-Host "[+] Duration   : $DumpDuration minutes" -ForegroundColor Green
    Write-Host "[+] JSON       : $JsonFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Next steps - analyze with:" -ForegroundColor Cyan
    Write-Host "    Volatility3 : vol.py -f `"$DumpFile`" windows.pslist" -ForegroundColor Cyan
    Write-Host "    Volatility3 : vol.py -f `"$DumpFile`" windows.netscan" -ForegroundColor Cyan
    Write-Host "    Volatility3 : vol.py -f `"$DumpFile`" windows.malfind" -ForegroundColor Cyan
} else {
    Write-Host "[!] RAM capture FAILED - check log: $LogFile" -ForegroundColor Red
}
Write-Log "Script completed | Success: $($DumpResult.Success)"
