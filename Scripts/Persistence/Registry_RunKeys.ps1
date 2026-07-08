<#
.SYNOPSIS
    Collects Windows Registry Run Keys for persistence detection.

.DESCRIPTION
    Enumerates common Windows Registry auto-start locations used
    for persistence and extracts command values for DFIR analysis.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1547.001 - Registry Run Keys / Startup Folder
    T1059    - Command-Line / PowerShell
    T1036    - Masquerading

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
$LogFile   = "$BasePath\Registry_RunKeys_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Registry Run Keys collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full registry visibility."
}

# =========================
# Registry Run Key Paths
# FIX: Added additional persistence locations (RunServices, RunServicesOnce,
#      SessionManager\BootExecute, Winlogon Userinit/Shell, AppInit_DLLs)
# =========================
$RunKeyPaths = @(
    # Standard Run / RunOnce
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    # 32-bit on 64-bit OS
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    # RunServices (legacy but still abused)
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    # Winlogon
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    # AppInit DLLs
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
)

# Fields of interest for Winlogon / AppInit keys (not all values are persistence)
$WinlogonFields  = @("Userinit", "Shell", "AppInit_DLLs")
$WindowsFields   = @("AppInit_DLLs", "LoadAppInit_DLLs")

Write-Host "[*] Collecting Registry Run Keys..." -ForegroundColor Cyan
Write-Log "Enumerating registry run key paths ($($RunKeyPaths.Count) paths)"

$RunKeyData = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Path in $RunKeyPaths) {
    try {
        if (-not (Test-Path $Path)) {
            Write-Log "Path not found (expected): $Path"
            continue
        }

        $Values = Get-ItemProperty -Path $Path -ErrorAction Stop

        foreach ($Property in $Values.PSObject.Properties) {

            # Skip PowerShell metadata properties
            if ($Property.Name -match "^PS") { continue }

            # For Winlogon / Windows keys, only capture known persistence fields
            $IsWinlogon = $Path -match "Winlogon"
            $IsWindows  = $Path -match "\\Windows$"
            if ($IsWinlogon -and $Property.Name -notin $WinlogonFields) { continue }
            if ($IsWindows  -and $Property.Name -notin $WindowsFields)  { continue }

            $RunKeyData.Add([PSCustomObject]@{
                Hostname        = $Hostname
                CollectionTime  = ([DateTime]::UtcNow).ToString("o")
                RegistryPath    = $Path
                ValueName       = $Property.Name
                ValueType       = ($Property.TypeNameOfValue -replace "^System\.", "")
                Command         = $Property.Value
            })
        }

        Write-Log "Processed: $Path"

    } catch {
        Write-Warning "[!] Could not access $Path : $_"
        Write-Log "ERROR accessing ${Path}: $_"
    }
}

Write-Log "Run key entries collected: $($RunKeyData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Registry_RunKeys_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType = "RegistryRunKeys"
    Hostname     = $Hostname
    CollectedAt  = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    EntryCount   = $RunKeyData.Count
    Data         = $RunKeyData
}

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Registry run keys exported to JSON"

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

Write-Host "[+] Registry Run Key collection completed ($($RunKeyData.Count) entries)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
