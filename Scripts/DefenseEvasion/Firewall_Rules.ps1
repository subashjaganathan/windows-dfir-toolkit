<#
.SYNOPSIS
    Collects Windows Firewall rules for DFIR investigations.

.DESCRIPTION
    Enumerates inbound and outbound firewall rules to identify
    defense evasion, C2 enablement, and unauthorized network access.

.IR_PHASE
    Defense Evasion / Live Response

.MITRE_ATTCK
    T1562.004 - Disable or Modify Firewall
    T1105    - Ingress Tool Transfer
    T1071    - Application Layer Protocol
    T1046    - Network Service Scanning

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
$LogFile   = "$BasePath\Firewall_Rules_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "Firewall rule collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full firewall rule visibility."
}

# =========================
# Firewall Profile State    (FIX: v1.0 did not capture profile-level on/off state)
# =========================
Write-Host "[*] Collecting firewall profile states..." -ForegroundColor Cyan
Write-Log "Enumerating firewall profile states"

$ProfileData = Get-NetFirewallProfile -ErrorAction SilentlyContinue |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked

# =========================
# Firewall Rule Collection
# FIX: Calling Get-NetFirewall*Filter inside a foreach loop is extremely slow
#      Pre-build hashtables indexed by InstanceID for O(1) lookup instead.
# =========================
Write-Host "[*] Pre-loading firewall filter tables..." -ForegroundColor Cyan
Write-Log "Loading port/app/address filter tables"

$PortFilters = @{}
Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $PortFilters[$_.InstanceID] = $_
}

$AppFilters = @{}
Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $AppFilters[$_.InstanceID] = $_
}

$AddrFilters = @{}
Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $AddrFilters[$_.InstanceID] = $_
}

Write-Host "[*] Collecting firewall rules..." -ForegroundColor Cyan
Write-Log "Enumerating firewall rules"

$Rules = Get-NetFirewallRule -ErrorAction SilentlyContinue

$RuleData = foreach ($Rule in $Rules) {

    $Id         = $Rule.InstanceID
    $PortFilter = $PortFilters[$Id]
    $AppFilter  = $AppFilters[$Id]
    $AddrFilter = $AddrFilters[$Id]

    [PSCustomObject]@{
        Hostname       = $Hostname
        CollectionTime = ([DateTime]::UtcNow).ToString("o")
        RuleName       = $Rule.DisplayName
        RuleID         = $Rule.Name               # FIX: added unique rule ID
        Direction      = $Rule.Direction
        Action         = $Rule.Action
        Enabled        = $Rule.Enabled
        Profile        = $Rule.Profile
        Protocol       = $PortFilter.Protocol
        Program        = $AppFilter.Program
        LocalPort      = $PortFilter.LocalPort
        RemotePort     = $PortFilter.RemotePort
        LocalAddress   = $AddrFilter.LocalAddress
        RemoteAddress  = $AddrFilter.RemoteAddress
        Group          = $Rule.Group              # FIX: added rule group for context
    }
}

Write-Log "Firewall rules collected: $($RuleData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\Firewall_Rules_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType   = "FirewallRules"
    Hostname       = $Hostname
    CollectedAt    = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    ProfileState   = $ProfileData          # FIX: included profile state in output
    RuleCount      = $RuleData.Count
    Data           = $RuleData
}

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "Firewall rules exported to JSON"

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

Write-Host "[+] Firewall rule collection completed"  -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"             -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"             -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"              -ForegroundColor Green

Write-Log "Script execution completed"
