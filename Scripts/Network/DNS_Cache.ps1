<#
.SYNOPSIS
    Collects DNS resolver cache entries for DFIR investigations.

.DESCRIPTION
    Enumerates the local Windows DNS client cache to identify
    suspicious domain queries associated with malware, C2,
    and data exfiltration activity.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1071.004 - DNS
    T1041    - Exfiltration Over C2 Channel
    T1568    - Dynamic Resolution
    T1105    - Ingress Tool Transfer

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
$LogFile   = "$BasePath\DNS_Cache_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "DNS cache collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges recommended for full DNS cache visibility."
}

# =========================
# DNS Cache Collection
# =========================
Write-Host "[*] Collecting DNS cache entries..." -ForegroundColor Cyan
Write-Log "Enumerating DNS resolver cache"

$DnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue

# FIX: Wrap in @() so .Count works when result is $null or single object
$DnsData = @(foreach ($Entry in $DnsCache) {
    [PSCustomObject]@{
        Hostname       = $Hostname
        CollectionTime = (Get-Date).ToString("o")
        EntryName      = $Entry.Entry
        RecordType     = $Entry.Type
        Data           = $Entry.Data
        Status         = $Entry.Status
        TimeToLive     = $Entry.TimeToLive
        DataLength     = $Entry.DataLength   # FIX: added for richer analysis
    }
})

Write-Log "DNS entries collected: $($DnsData.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\DNS_Cache_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ArtifactType = "DNSCache"
    Hostname     = $Hostname
    CollectedAt  = (Get-Date).ToString("o")
    ToolVersion="1.0"
    EntryCount   = $DnsData.Count
    Data         = $DnsData
}

$Evidence | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "DNS cache exported to JSON"

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

Write-Host "[+] DNS cache collection completed"  -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"         -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"         -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"          -ForegroundColor Green

Write-Log "Script execution completed"
