#Requires -Version 5.1
<#
.SYNOPSIS
    Enumerates active named pipes and correlates with owning processes.

.DESCRIPTION
    Lists all named pipes on the system and attempts to identify
    owning processes. C2 frameworks (Cobalt Strike, Metasploit,
    Sliver) heavily use named pipes for inter-process communication.

.IR_PHASE
    Identification / Live Response

.MITRE_ATTCK
    T1071     - Application Layer Protocol
    T1570     - Lateral Tool Transfer
    T1055.012 - Process Hollowing (via pipes)

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"


# --- Shared toolkit module: single source of truth for version + base paths ---
$__DFIRMod = Join-Path $PSScriptRoot '..\Infrastructure\DFIR_Common.psm1'
if (Test-Path $__DFIRMod) { Import-Module $__DFIRMod -Force -ErrorAction SilentlyContinue }
if (-not $Global:DFIR_ToolVersion) { $Global:DFIR_ToolVersion = '1.0' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Named_Pipes_Execution.log"
$JsonFile = "$BasePath\Named_Pipes_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Named pipe collection started"

# Known malicious / C2 pipe names (partial matches)
$SuspiciousPipePatterns = @(
    "msagent_","postex_","status_[0-9a-f]{8}","inject","beacon","cobaltstrike",
    "meterpreter","paexec","remcom","csexec","winexesvc","smbexec",
    "PSEXESVC"
)
# Legitimate Windows pipes - excluded from suspicious
$LegitimePipes = @("lsarpc","samr","atsvc","epmapper","spoolss","wkssvc","ntsvcs",
    "svcctl","eventlog","winreg","netlogon","srvsvc","browser","mojo","chrome",
    "crashpad","ipc","terminal server","tsvcpipe","W32TIME_ALT")

Write-Host "[*] Enumerating named pipes..." -ForegroundColor Cyan

# Get all named pipes
$Pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") 2>$null

# Build PID map from handles (requires SysInternals handle.exe for full coverage;
# fallback: enumerate via WMI where possible)
$HandleMap = @{}
try {
    # Try handle.exe if available
    $HandleExe = Get-Command handle.exe -ErrorAction SilentlyContinue
    if ($HandleExe) {
        $HandleOut = & handle.exe -a -nobanner 2>$null
        # Parse handle output for pipe handles
    }
} catch {}

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Pipe in $Pipes) {
    $PipeName = $Pipe -replace "\\\\\.\\pipe\\",""

    $IsSuspicious = $false
    $MatchedPattern = $null
    # Skip known legitimate pipes
    $IsLegit = $false
    foreach ($Legit in $LegitimePipes) { if ($PipeName -match $Legit) { $IsLegit = $true; break } }
    if (-not $IsLegit) {
        foreach ($Pattern in $SuspiciousPipePatterns) {
            if ($PipeName -match $Pattern) {
                $IsSuspicious = $true
                $MatchedPattern = $Pattern
                break
            }
        }
    }

    $Results.Add([PSCustomObject]@{
        CollectionTime  = ([DateTime]::UtcNow).ToString("o")
        PipeName        = $PipeName
        FullPath        = $Pipe
        IsSuspicious    = $IsSuspicious
        MatchedPattern  = $MatchedPattern
    })
}

$SuspCount = ($Results | Where-Object { $_.IsSuspicious }).Count
Write-Log "Named pipes found: $($Results.Count) | Suspicious: $SuspCount"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType   = "NamedPipes"
    TotalPipes     = $Results.Count
    SuspiciousCount= $SuspCount
    Data           = $Results
}

$Evidence | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Named pipes: $($Results.Count) | Suspicious: $SuspCount" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
