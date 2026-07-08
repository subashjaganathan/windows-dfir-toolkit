<#
.SYNOPSIS
    Collects active network connections and listening ports.

.DESCRIPTION
    Enumerates active TCP/UDP connections and correlates them with
    process information to identify malicious network activity,
    C2 communication, and unauthorized listeners.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1041  - Exfiltration Over C2 Channel
    T1071  - Application Layer Protocol
    T1571  - Non-Standard Port
    T1105  - Ingress Tool Transfer
    T1021  - Remote Services

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
$LogFile   = "$BasePath\Network_Connections_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Network connection collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full process correlation."
}

# =========================
# Pre-build process lookup table for performance
# FIX: original called Get-Process inside every loop iteration - very slow
# =========================
Write-Host "[*] Building process lookup table..." -ForegroundColor Cyan
Write-Log "Building PID->ProcessName lookup table"

$ProcessMap = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $ProcessMap[$_.Id] = [PSCustomObject]@{
        Name = $_.ProcessName
        Path = try { $_.MainModule.FileName } catch { "Access Denied" }
    }
}

# =========================
# TCP Connection Collection
# =========================
Write-Host "[*] Collecting TCP connections..." -ForegroundColor Cyan
Write-Log "Enumerating TCP connections"

$TcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue

# =========================
# UDP Endpoint Collection   (FIX: v1.0 missed UDP entirely)
# =========================
Write-Host "[*] Collecting UDP endpoints..." -ForegroundColor Cyan
Write-Log "Enumerating UDP endpoints"

$UdpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue

$ConnectionData = @()

foreach ($Conn in $TcpConnections) {
    $Proc = $ProcessMap[$Conn.OwningProcess]
    $ConnectionData += [PSCustomObject]@{
        Hostname       = $Hostname
        CollectionTime = ([DateTime]::UtcNow).ToString("o")
        Protocol       = "TCP"
        ProcessName    = if ($Proc) { $Proc.Name } else { "Unknown" }
        ProcessPath    = if ($Proc) { $Proc.Path } else { "Unknown" }
        PID            = $Conn.OwningProcess
        LocalAddress   = $Conn.LocalAddress
        LocalPort      = $Conn.LocalPort
        RemoteAddress  = $Conn.RemoteAddress
        RemotePort     = $Conn.RemotePort
        State          = $Conn.State
        CreationTime   = if ($Conn.CreationTime) { $Conn.CreationTime.ToString("o") } else { $null }
    }
}

foreach ($Ep in $UdpEndpoints) {
    $Proc = $ProcessMap[$Ep.OwningProcess]
    $ConnectionData += [PSCustomObject]@{
        Hostname       = $Hostname
        CollectionTime = ([DateTime]::UtcNow).ToString("o")
        Protocol       = "UDP"
        ProcessName    = if ($Proc) { $Proc.Name } else { "Unknown" }
        ProcessPath    = if ($Proc) { $Proc.Path } else { "Unknown" }
        PID            = $Ep.OwningProcess
        LocalAddress   = $Ep.LocalAddress
        LocalPort      = $Ep.LocalPort
        RemoteAddress  = $null
        RemotePort     = $null
        State          = "Stateless"
        CreationTime   = if ($Ep.CreationTime) { $Ep.CreationTime.ToString("o") } else { $null }
    }
}

Write-Log "Connections collected: $($ConnectionData.Count) (TCP + UDP)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Network_Connections_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType    = "NetworkConnections"
    Hostname        = $Hostname
    CollectedAt     = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    ConnectionCount = $ConnectionData.Count
    Data            = $ConnectionData
}

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Network connection data exported to JSON"

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

Write-Host "[+] Network connection collection completed" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"                -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"                -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"                 -ForegroundColor Green

Write-Log "Script execution completed"
