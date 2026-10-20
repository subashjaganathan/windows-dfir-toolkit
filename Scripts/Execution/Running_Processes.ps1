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
    # [int] key: Win32_Process.ProcessId is UInt32 but Get-Process .Id is Int32, and a hashtable
    # treats [uint32]4 and [int]4 as DIFFERENT keys - every lookup missed, so CommandLine,
    # ParentPID and ParentName were empty for every process.
    $WmiProcesses[[int]$_.ProcessId] = $_
}

# =========================
# Process Collection
# =========================
Write-Host "[*] Collecting running processes..." -ForegroundColor Cyan
Write-Log "Enumerating running processes"

# Hash + signature once per binary (dozens of svchost.exe share one image).
$IdentityCache = @{}
function Get-BinaryIdentity([string]$Path) {
    if (-not $Path) { return $null }
    if ($IdentityCache.ContainsKey($Path)) { return $IdentityCache[$Path] }
    $id = [PSCustomObject]@{ SHA256 = $null; SignatureStatus = "Executable Not Found"; Signer = $null }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try { $id.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $id.SignatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) { $id.Signer = $sig.SignerCertificate.Subject }
        } catch { $id.SignatureStatus = "Unknown" }
    }
    $IdentityCache[$Path] = $id
    $id
}
function ConvertTo-UtcIso($dt) { if ($dt) { ([datetime]$dt).ToUniversalTime().ToString("o") } else { $null } }

$ProcessData = foreach ($Process in Get-Process -ErrorAction SilentlyContinue) {
    $WmiProc = $WmiProcesses[$Process.Id]

    # Protected / PPL processes (lsass, MsMpEng, ...) refuse a module handle even to
    # an admin; Win32_Process still reports the image path, so fall back to it
    # instead of losing path, hash and signature as "Access Denied".
    $ExePath = $null; $PathSource = $null
    try { $ExePath = $Process.MainModule.FileName; if ($ExePath) { $PathSource = "Process.MainModule" } } catch {}
    if (-not $ExePath -and $WmiProc -and $WmiProc.ExecutablePath) { $ExePath = $WmiProc.ExecutablePath; $PathSource = "Win32_Process" }
    $Id = Get-BinaryIdentity $ExePath

    $Owner = $null
    if ($WmiProc) {
        try {
            $o = Invoke-CimMethod -InputObject $WmiProc -MethodName GetOwner -ErrorAction Stop
            if ($o.ReturnValue -eq 0) { $Owner = if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { $o.User } }
        } catch {}
    }
    $Parent = if ($WmiProc) { $WmiProcesses[[int]$WmiProc.ParentProcessId] } else { $null }
    $ProcStart = if ($WmiProc -and $WmiProc.CreationDate) { $WmiProc.CreationDate } else { try { $Process.StartTime } catch { $null } }

    [PSCustomObject]@{
        Hostname         = $Hostname
        CollectionTime   = ([DateTime]::UtcNow).ToString("o")
        ProcessName      = $Process.ProcessName
        PID              = $Process.Id
        ParentPID        = if ($WmiProc) { $WmiProc.ParentProcessId } else { $null }
        ParentName       = if ($Parent) { $Parent.Name } else { $null }
        # PIDs are reused: a parent that STARTED AFTER its child is not the real parent.
        ParentStartTime  = if ($Parent) { ConvertTo-UtcIso $Parent.CreationDate } else { $null }
        ParentIsStale    = [bool]($Parent -and $ProcStart -and $Parent.CreationDate -and ([datetime]$Parent.CreationDate -gt [datetime]$ProcStart))
        CommandLine      = if ($WmiProc) { $WmiProc.CommandLine } else { $null }
        ExecutablePath   = if ($ExePath) { $ExePath } else { $null }
        PathSource       = $PathSource
        SHA256           = if ($Id) { $Id.SHA256 } else { $null }
        SignatureStatus  = if ($Id) { $Id.SignatureStatus } else { "No Image Path" }
        Signer           = if ($Id) { $Id.Signer } else { $null }
        Owner            = $Owner
        SessionId        = $Process.SessionId
        StartTime        = ConvertTo-UtcIso $ProcStart
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
