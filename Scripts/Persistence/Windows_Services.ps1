<#
.SYNOPSIS
    Collects Windows service information for persistence detection.

.DESCRIPTION
    Enumerates Windows services and extracts binary paths, run-as
    accounts, start types, service states, and digital signatures
    to identify malicious persistence and privilege abuse.

.IR_PHASE
    Persistence / Investigation

.MITRE_ATTCK
    T1543.003 - Windows Service
    T1036    - Masquerading
    T1059    - Command-Line / PowerShell
    T1106    - Native API

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

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# =========================
# Environment / Paths
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$LogFile   = "$BasePath\Services_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Windows service collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full service visibility."
}

# =========================
# Service Collection
# =========================
Write-Host "[*] Collecting Windows services..." -ForegroundColor Cyan
Write-Log "Enumerating Windows services via Win32_Service"

$Services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

$ServiceData = foreach ($Service in $Services) {

    # FIX: v1.0 did not validate or hash service binaries
    # Extract executable path (strip quotes and arguments from PathName)
    $BinaryPath = $Service.PathName
    $ExePath    = $null
    $SigStatus  = "Unknown"
    $FileHash   = $null

    if ($BinaryPath) {
        # Handle quoted paths: "C:\path\to\svc.exe" -args
        if ($BinaryPath -match '^"([^"]+)"') {
            $ExePath = $Matches[1]
        } elseif ($BinaryPath -match '^([^\s]+)') {
            $ExePath = $Matches[1]
        }

        if ($ExePath -and (Test-Path $ExePath -ErrorAction SilentlyContinue)) {
            try {
                $Sig       = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction SilentlyContinue
                $SigStatus = if ($Sig) { $Sig.Status.ToString() } else { "Unknown" }
                $FileHash  = (Get-FileHash -Path $ExePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } catch {
                $SigStatus = "Hash/Sig Failed"
            }
        } else {
            $SigStatus = "Binary Not Found"
        }
    }

    [PSCustomObject]@{
        Hostname         = $Hostname
        CollectionTime   = (Get-Date).ToString("o")
        ServiceName      = $Service.Name
        DisplayName      = $Service.DisplayName
        Description      = $Service.Description
        State            = $Service.State
        StartMode        = $Service.StartMode
        RunAsAccount     = $Service.StartName
        BinaryPath       = $BinaryPath
        ExecutablePath   = $ExePath                    # FIX: parsed clean exe path
        SHA256           = $FileHash                   # FIX: added file hash
        SignatureStatus  = $SigStatus                  # FIX: added signature check
        ProcessId        = $Service.ProcessId          # FIX: added live PID for running services
        DelayedAutoStart = $Service.DelayedAutoStart
    }
}

Write-Log "Services collected: $($ServiceData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Windows_Services_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ArtifactType = "WindowsServices"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion="1.0"
    ServiceCount = $ServiceData.Count
    Data         = $ServiceData
}

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Service data exported to JSON"

# =========================
# Evidence Integrity
# =========================
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

[PSCustomObject]@{
    FileName  = $JsonFile
    Algorithm = $Hash.Algorithm
    Hash      = $Hash.Hash
    Generated = (Get-Date).ToString("o")
} | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA256 hash generated"

Write-Host "[+] Windows service collection completed ($($ServiceData.Count) services)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
