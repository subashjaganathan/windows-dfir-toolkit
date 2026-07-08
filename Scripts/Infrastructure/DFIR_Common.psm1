#Requires -Version 5.1
<#
.SYNOPSIS
    DFIR Toolkit - Shared Helper Module

.DESCRIPTION
    Common functions used by all DFIR collection scripts:
    privilege checking, logging, evidence envelope creation,
    SHA256 hashing, chain-of-custody stamping, and output helpers.

.AUTHOR
    Subash J

.VERSION
    2.0
#>

# -- Global Evidence Base Path --------------------------------------------------
# Honor DFIR_OUTPUT (set by the orchestrator's -OutputPath) so shared paths match per-script paths.
$Global:DFIR_BasePath    = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$Global:DFIR_CaseNumber  = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Global:DFIR_Investigator = if ($env:DFIR_INV) { $env:DFIR_INV } else { $env:USERNAME }
# Authoritative toolkit version - single source of truth. Scripts read $Global:DFIR_ToolVersion.
$Global:DFIR_ToolVersion = "1.0"

# -- Privilege Check ------------------------------------------------------------
function Test-AdminPrivilege {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-AdminPrivilege {
    if (-not (Test-AdminPrivilege)) {
        # throw (not exit): scripts are dot-invoked by the orchestrator, which wraps each in
        # try/catch. exit would terminate the whole session and abort the entire collection.
        throw "This script requires Administrator privileges."
    }
}

# -- Directory Init -------------------------------------------------------------
function Initialize-EvidenceDirectory {
    param([string]$SubPath = "")
    $Path = if ($SubPath) { Join-Path $Global:DFIR_BasePath $SubPath } else { $Global:DFIR_BasePath }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    return $Path
}

# -- Logging --------------------------------------------------------------------
function Write-DFIRLog {
    param(
        [string]$LogFile,
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")][string]$Level = "INFO"
    )
    $Entry = "$(Get-Date -Format o) [$Level] :: $Message"
    Add-Content -Path $LogFile -Value $Entry
    if ($Level -eq "WARN")  { Write-Warning $Message }
    if ($Level -eq "ERROR") { Write-Error   $Message }
}

# -- Chain of Custody Header ----------------------------------------------------
function New-ChainOfCustody {
    param([string]$ArtifactType, [string]$ScriptName)

    # NTP sync status
    $W32Status = (w32tm /query /status 2>&1) -join " "
    $NtpSource = if ($W32Status -match "Source:\s+(.+?)[\r\n]") { $Matches[1].Trim() } else { "Unknown" }
    $NtpOffset = if ($W32Status -match "Phase Offset:\s+(.+?)[\r\n]") { $Matches[1].Trim() } else { "Unknown" }

    return [PSCustomObject]@{
        CaseNumber      = $Global:DFIR_CaseNumber
        Investigator    = $Global:DFIR_Investigator
        Hostname        = $env:COMPUTERNAME
        Domain          = $env:USERDOMAIN
        CollectedAt     = ([DateTime]::UtcNow).ToString("o")
        CollectedAtUTC  = ([DateTime]::UtcNow).ToString("o")
        TimeZone        = [System.TimeZoneInfo]::Local.Id
        NTPSource       = $NtpSource
        NTPOffset       = $NtpOffset
        ArtifactType    = $ArtifactType
        ScriptName      = $ScriptName
        ToolVersion     = $Global:DFIR_ToolVersion
        OSVersion       = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        IsAdmin         = (Test-AdminPrivilege)
    }
}

# -- Evidence Envelope ----------------------------------------------------------
function New-EvidenceEnvelope {
    param(
        [string]$ArtifactType,
        [string]$ScriptName,
        [object]$Data,
        [hashtable]$ExtraFields = @{}
    )
    $CoC = New-ChainOfCustody -ArtifactType $ArtifactType -ScriptName $ScriptName

    $Envelope = [ordered]@{
        ChainOfCustody = $CoC
        ArtifactType   = $ArtifactType
        EntryCount     = if ($Data -is [System.Collections.ICollection]) { $Data.Count } else { 1 }
        Data           = $Data
    }
    foreach ($Key in $ExtraFields.Keys) { $Envelope[$Key] = $ExtraFields[$Key] }
    return [PSCustomObject]$Envelope
}

# -- Write + Hash ---------------------------------------------------------------
function Export-EvidenceFile {
    param(
        [object]$Evidence,
        [string]$JsonFile,
        [string]$LogFile
    )
    $Evidence | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Encoding UTF8

    $Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
    $HashInfo = [PSCustomObject]@{
        FileName  = $JsonFile
        Algorithm = $Hash.Algorithm
        Hash      = $Hash.Hash
        Generated = (Get-Date).ToString("o")
        CaseNumber= $Global:DFIR_CaseNumber
    }
    $HashInfo | ConvertTo-Json | Out-File -FilePath "$JsonFile.hash.json" -Encoding UTF8

    if ($LogFile) { Write-DFIRLog -LogFile $LogFile -Message "Exported: $JsonFile (SHA256: $($Hash.Hash))" }
    return $Hash.Hash
}

# -- Standard output paths ------------------------------------------------------
function Get-OutputPaths {
    param([string]$ArtifactName)
    $Ts       = Get-Date -Format "yyyyMMdd_HHmmss"
    $Host_    = $env:COMPUTERNAME
    $Base     = $Global:DFIR_BasePath
    return @{
        JsonFile = "$Base\${ArtifactName}_${Host_}_${Ts}.json"
        LogFile  = "$Base\${ArtifactName}_Execution.log"
        HashFile = "$Base\${ArtifactName}_${Host_}_${Ts}.json.hash.json"
    }
}

Export-ModuleMember -Function *
