<#
.SYNOPSIS
    Collects IPv4 ARP cache entries for DFIR investigations.

.DESCRIPTION
    Retrieves ARP neighbor information using native PowerShell cmdlets
    and maps network interfaces to identify suspicious devices, rogue
    gateways, and potential ARP spoofing or MITM activity.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1557.002 - ARP Cache Poisoning
    T1040    - Network Sniffing

.FORENSIC_SAFETY
    Read-only, forensic-safe (does not modify system state)

.OUTPUT
    JSON evidence file + SHA256 hash file stored in C:\IR_Collection\

.AUTHOR
    DFIR Toolkit

.VERSION
    1.1
#>

Set-StrictMode -Off
$ErrorActionPreference = "Stop"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }

# =========================
# Privilege Awareness
# =========================
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Warning "[!] Script is NOT running as Administrator. Output may be incomplete."
}

# =========================
# Environment / Paths
# =========================
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$LogFile   = "$BasePath\ARP_Entries_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "ARP cache collection started"
Write-Log "Administrator privileges: $IsAdmin"

$JsonFile = "$BasePath\ARP_Entries_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

Write-Host "[*] Collecting ARP cache entries..." -ForegroundColor Cyan
Write-Log "Enumerating ARP neighbor table"

try {
    # Retrieve network adapters for interface mapping
    $Adapters = Get-NetAdapter -ErrorAction Stop |
        Select-Object ifIndex, Name, MacAddress, Status

    # Retrieve IPv4 ARP entries
    $ArpEntries = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop

    $Results = foreach ($Entry in $ArpEntries) {

        $Adapter = $Adapters | Where-Object { $_.ifIndex -eq $Entry.InterfaceIndex }

        [PSCustomObject]@{
            Hostname        = $Hostname
            CollectionTime  = ([DateTime]::UtcNow).ToString("o")
            IPAddress       = $Entry.IPAddress
            MACAddress      = $Entry.LinkLayerAddress
            Interface       = $Adapter.Name
            InterfaceIndex  = $Entry.InterfaceIndex
            AdapterStatus   = $Adapter.Status          # FIX: added adapter link state
            State           = $Entry.State
            CacheType       = if ($Entry.IsPermanent -eq $true) { "Static" } else { "Dynamic" }
            IsRouter        = $Entry.IsRouter
        }
    }

    # =========================
    # Unified Evidence Schema   (FIX: was missing envelope in v1.0)
    # =========================
    $Evidence = [PSCustomObject]@{
        ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType = "ARPEntries"
        Hostname     = $Hostname
        CollectedAt  = ([DateTime]::UtcNow).ToString("o")
        ToolVersion=$Global:DFIR_ToolVersion
        EntryCount   = @($Results).Count
        Data         = $Results
    }

    $Evidence | ConvertTo-Json -Depth 5 |
        Out-File -FilePath $JsonFile -Encoding UTF8

    Write-Log "ARP data exported to JSON ($(@($Results).Count) entries)"

    # =========================
    # Evidence Integrity (SHA256)
    # =========================
    $Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256

    [PSCustomObject]@{
        FileName  = $JsonFile
        Algorithm = $Hash.Algorithm
        Hash      = $Hash.Hash
        Generated = ([DateTime]::UtcNow).ToString("o")
    } | ConvertTo-Json | Out-File -FilePath $HashFile -Encoding UTF8

    Write-Log "SHA256 hash generated"

    Write-Host "[+] ARP data successfully collected"  -ForegroundColor Green
    Write-Host "[+] JSON Output  : $JsonFile"          -ForegroundColor Green
    Write-Host "[+] Hash Output  : $HashFile"          -ForegroundColor Green
    Write-Host "[+] Execution Log: $LogFile"           -ForegroundColor Green

} catch {
    $Msg = "[!] Failed to collect ARP entries: $_"
    Write-Error $Msg
    Write-Log   $Msg
}

Write-Log "Script execution completed"
