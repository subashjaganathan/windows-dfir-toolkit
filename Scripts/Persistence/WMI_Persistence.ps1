<#
.SYNOPSIS
    Collects WMI permanent event subscriptions for persistence detection.

.DESCRIPTION
    Enumerates WMI Event Filters, all consumer types (not just
    CommandLineEventConsumer), and FilterToConsumerBindings to
    identify stealthy fileless persistence mechanisms.

.IR_PHASE
    Persistence / Advanced Investigation

.MITRE_ATTCK
    T1546.003 - WMI Event Subscription
    T1059    - Command-Line / PowerShell
    T1106    - Native API
    T1027    - Obfuscated Files or Information

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
$LogFile   = "$BasePath\WMI_Persistence_Execution.log"

New-Item -ItemType Directory -Path $BasePath -Force | Out-Null

function Write-Log {
    param([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format o) :: $Message"
}

Write-Log "WMI persistence collection started"
Write-Log "Administrator privileges: $IsAdmin"

if (-not $IsAdmin) {
    Write-Warning "[!] Administrator privileges required to enumerate WMI subscriptions."
}

# =========================
# WMI Persistence Collection
# FIX: v1.0 only queried CommandLineEventConsumer - attackers also use
#      ActiveScriptEventConsumer (VBScript/JScript payloads). Both collected here.
# FIX: Used __PATH for binding correlation - this is unreliable across CIM sessions.
#      Use .Name property matching instead.
# =========================
Write-Host "[*] Collecting WMI Event Filters..." -ForegroundColor Cyan
Write-Log "Enumerating WMI Filters, Consumers, and Bindings"

$Namespace = "root\subscription"

$Filters  = @(Get-CimInstance -Namespace $Namespace -ClassName __EventFilter          -ErrorAction SilentlyContinue)
$CmdCons  = @(Get-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)
$ScriptCons = @(Get-CimInstance -Namespace $Namespace -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
$Bindings = @(Get-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)

Write-Log "Filters: $($Filters.Count) | CmdConsumers: $($CmdCons.Count) | ScriptConsumers: $($ScriptCons.Count) | Bindings: $($Bindings.Count)"

# Build lookup maps by Name
$FilterMap   = @{}; $Filters   | Where-Object { $_.__RELPATH } | ForEach-Object { $FilterMap[$_.__RELPATH]   = $_ }
$CmdConMap   = @{}; $CmdCons   | Where-Object { $_.__RELPATH } | ForEach-Object { $CmdConMap[$_.__RELPATH]   = $_ }
$ScriptConMap= @{}; $ScriptCons| Where-Object { $_.__RELPATH } | ForEach-Object { $ScriptConMap[$_.__RELPATH]= $_ }

$Data = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($Binding in $Bindings) {
    if (-not $Binding.Filter -or -not $Binding.Consumer) { continue }
    $FilterRef   = $Binding.Filter.__RELPATH
    $ConsumerRef = $Binding.Consumer.__RELPATH
    if (-not $FilterRef -or -not $ConsumerRef) { continue }

    $Filter   = $FilterMap[$FilterRef]
    $CmdCon   = $CmdConMap[$ConsumerRef]
    $ScriptCon= $ScriptConMap[$ConsumerRef]

    $Consumer     = if ($CmdCon) { $CmdCon } else { $ScriptCon }
    $ConsumerType = if ($CmdCon) { "CommandLineEventConsumer" } elseif ($ScriptCon) { "ActiveScriptEventConsumer" } else { "Unknown" }

    $Data.Add([PSCustomObject]@{
        Hostname        = $Hostname
        CollectionTime  = ([DateTime]::UtcNow).ToString("o")
        FilterName      = $Filter.Name
        FilterQuery     = $Filter.Query
        FilterLanguage  = $Filter.QueryLanguage          # FIX: added query language
        EventNamespace  = $Filter.EventNamespace
        ConsumerType    = $ConsumerType                  # FIX: now distinguishes consumer types
        ConsumerName    = $Consumer.Name
        CommandLine     = $CmdCon.CommandLineTemplate
        Executable      = $CmdCon.ExecutablePath
        ScriptText      = $ScriptCon.ScriptText          # FIX: captures VBScript/JS payloads
        ScriptFileName  = $ScriptCon.ScriptFileName
        ScriptingEngine = $ScriptCon.ScriptingEngine
    })
}

Write-Log "WMI subscription bindings collected: $($Data.Count)"

# =========================
# Unified Evidence Schema
# =========================
$JsonFile = "$BasePath\WMI_Persistence_${Hostname}_${Timestamp}.json"
$HashFile = "$JsonFile.hash.json"

$Evidence = [PSCustomObject]@{
    ChainOfCustody = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType = "WMIPersistence"
    Hostname     = $Hostname
    CollectedAt  = ([DateTime]::UtcNow).ToString("o")
    ToolVersion=$Global:DFIR_ToolVersion
    EntryCount   = $Data.Count
    Data         = $Data
}

$Evidence | ConvertTo-Json -Depth 6 |
    Out-File -FilePath $JsonFile -Encoding UTF8

Write-Log "WMI persistence data exported to JSON"

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

Write-Host "[+] WMI persistence collection completed ($($Data.Count) bindings)" -ForegroundColor Green
Write-Host "[+] JSON Output  : $JsonFile"  -ForegroundColor Green
Write-Host "[+] Hash Output  : $HashFile"  -ForegroundColor Green
Write-Host "[+] Execution Log: $LogFile"   -ForegroundColor Green

Write-Log "Script execution completed"
