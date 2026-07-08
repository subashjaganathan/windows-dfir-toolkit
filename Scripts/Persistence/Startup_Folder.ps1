<#
.SYNOPSIS
    Collects startup folder executables and shortcuts for persistence detection.

.DESCRIPTION
    Enumerates user and system startup folders and extracts file details,
    including shortcut targets and file hashes, to identify malicious
    persistence.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1547.001 - Startup Folder
    T1036    - Masquerading
    T1059    - Command-Line / PowerShell

.FORENSIC_SAFETY
    Read-only, forensic-safe

.OUTPUT
    JSON evidence file + SHA256 hash
    Execution log

.AUTHOR
    DFIR Toolkit

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =========================
# Environment / Paths
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$LogFile   = "$BasePath\StartupFolder_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Startup folder collection started"
Write-Log "Administrator privileges: $IsAdmin"

# =========================
# Startup Folder Paths
# FIX: Added all user startup paths dynamically so multi-user systems are covered
# =========================
$StartupPaths = [System.Collections.Generic.List[string]]::new()

# Current user
$StartupPaths.Add("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")
# All users / system-wide
$StartupPaths.Add("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")

# FIX: Enumerate other user profiles' startup folders when running as admin
if ($IsAdmin) {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $UserStartup = "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if ((Test-Path $UserStartup) -and $StartupPaths -notcontains $UserStartup) {
            $StartupPaths.Add($UserStartup)
        }
    }
}

Write-Host "[*] Collecting Startup Folder items from $($StartupPaths.Count) paths..." -ForegroundColor Cyan
Write-Log "Enumerating $($StartupPaths.Count) startup folder paths"

$StartupData = [System.Collections.Generic.List[PSCustomObject]]::new()
$WshShell    = New-Object -ComObject WScript.Shell

foreach ($Path in $StartupPaths) {
    if (-not (Test-Path $Path)) {
        Write-Log "Path not found: $Path"
        continue
    }

    Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {

        $TargetPath  = $null
        $LnkArgs     = $null
        $FileHashVal = $null

        # Resolve shortcut target
        if ($_.Extension -eq ".lnk") {
            try {
                $Shortcut   = $WshShell.CreateShortcut($_.FullName)
                $TargetPath = $Shortcut.TargetPath
                $LnkArgs    = $Shortcut.Arguments
            } catch {
                $TargetPath = "Unable to resolve shortcut"
            }
        }

        # Hash executable files directly (not .lnk)   FIX: v1.0 skipped hashing entirely
        if ($_.Extension -ne ".lnk" -and $_.Length -gt 0) {
            try {
                $FileHashVal = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch {
                $FileHashVal = "Hash Failed"
            }
        }

        $StartupData.Add([PSCustomObject]@{
            Hostname          = $Hostname
            CollectionTime    = ([DateTime]::UtcNow).ToString("o")
            StartupPath       = $Path
            FileName          = $_.Name
            FullPath          = $_.FullName
            TargetPath        = $TargetPath
            LnkArguments      = $LnkArgs           # FIX: added shortcut arguments
            FileExtension     = $_.Extension
            FileSizeBytes     = $_.Length
            SHA256            = $FileHashVal        # FIX: added file hash
            CreationTimeUtc   = $_.CreationTimeUtc.ToString("o")
            LastWriteTimeUtc  = $_.LastWriteTimeUtc.ToString("o")
        })
    }
}

Write-Log "Startup folder items collected: $($StartupData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Startup_Folder_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType = "StartupFolder"
    Hostname     = $Hostname
    CollectedAt  = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    EntryCount   = $StartupData.Count
    Data         = $StartupData
}

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Startup folder data exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

[PSCustomObject]@{
    FileName  = $JsonFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = ([DateTime]::UtcNow).ToString("o")
} | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Startup folder collection completed ($($StartupData.Count) entries)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
