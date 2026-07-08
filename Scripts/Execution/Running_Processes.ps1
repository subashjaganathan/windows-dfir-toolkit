<#
.SYNOPSIS
    Collects running process details and validates digital signatures.

.DESCRIPTION
    Enumerates running processes, captures executable metadata,
    digital signature status, parent process, command-line arguments,
    and file hash to assist DFIR investigations in identifying
    suspicious or malicious activity.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1055 - Process Injection
    T1036 - Masquerading
    T1106 - Native API Abuse

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
$LogFile   = "$BasePath\Running_Processes_Execution.log"
$JsonFile  = "$BasePath\Running_Processes_${Hostname}_${Timestamp}.json"
$HashFile  = "$JsonFile.hash.json"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Script execution started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Script is NOT running as Administrator. Some processes may not be accessible."
    Write-Log "WARNING: Not running as Administrator"
}

# =========================
# Pre-build WMI process table for CommandLine + ParentPID
# FIX: Get-Process does not expose CommandLine or ParentProcessId;
#      Win32_Process via CIM is required and much faster as a single call.
# =========================
Write-Host "[*] Loading WMI process table..." -ForegroundColor Cyan
Write-Log "Loading Win32_Process via CIM"

$WmiProcesses = @{}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    $WmiProcesses[$_.ProcessId] = $_
}

# =========================
# Process Collection
# =========================
Write-Host "[*] Collecting running processes..." -ForegroundColor Cyan
Write-Log "Enumerating running processes"

$ProcessData = foreach ($Process in Get-Process -ErrorAction SilentlyContinue) {

    $ExePath   = $null
    $SigStatus = "Unknown"
    $FileHash  = $null
    $WmiProc   = $WmiProcesses[$Process.Id]

    try {
        $ExePath = $Process.MainModule.FileName
        if ($ExePath -and (Test-Path $ExePath)) {
            $Signature = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction SilentlyContinue
            $FileHash  = (Get-FileHash -Path $ExePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $SigStatus = if ($Signature) { $Signature.Status.ToString() } else { "Unknown" }
        } else {
            $SigStatus = "Executable Not Found"
        }
    } catch {
        $ExePath   = "Access Denied"
        $SigStatus = "Access Denied"
    }

    [PSCustomObject]@{
        Hostname         = $Hostname
        CollectionTime   = ([DateTime]::UtcNow).ToString("o")
        ProcessName      = $Process.ProcessName
        PID              = $Process.Id
        ParentPID        = if ($WmiProc) { $WmiProc.ParentProcessId } else { $null }  # FIX: added PPID
        ParentName       = if ($WmiProc -and $WmiProcesses[$WmiProc.ParentProcessId]) {
                               $WmiProcesses[$WmiProc.ParentProcessId].Name
                           } else { $null }
        CommandLine      = if ($WmiProc) { $WmiProc.CommandLine } else { $null }       # FIX: added command line
        ExecutablePath   = $ExePath
        SHA256           = $FileHash
        SignatureStatus  = $SigStatus
        SessionId        = $Process.SessionId                                           # FIX: added session context
        StartTime        = if ($Process.StartTime) { $Process.StartTime.ToString("o") } else { $null }
        WorkingSetMB     = [math]::Round($Process.WorkingSet64 / 1MB, 2)
    }
}

Write-Log "Processes collected: $(@($ProcessData).Count)"

# =========================
# Unified Evidence Schema
# =========================
$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType  = "RunningProcesses"
    Hostname      = $Hostname
    CollectedAt   = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    ProcessCount  = @($ProcessData).Count
    Data          = $ProcessData
}

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Process data exported to JSON"

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

Write-Host "[+] Running process collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"              -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"              -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"               -ForegroundColor Green

Write-Log "Script execution completed"
