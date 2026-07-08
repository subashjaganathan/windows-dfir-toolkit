#Requires -Version 5.1
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
$LogFile  = "$BasePath\AV_EDR_Execution.log"
$JsonFile = "$BasePath\AV_EDR_Status_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "AV/EDR status collection started | Case: $CaseNum"

# Registered AV/Firewall/AS products via WMI SecurityCenter2
Write-Host "[*] Collecting registered security products..." -ForegroundColor Cyan
$AVProducts = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $AVList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($AV in $AVList) {
        $State = $AV.productState
        $Enabled  = ($State -band 0x1000) -ne 0
        $UpToDate = ($State -band 0x0010) -eq 0
        $AVProducts.Add([PSCustomObject]@{
            ProductName      = $AV.displayName
            ProductType      = "AntiVirus"
            ProductState     = $State
            RealTimeEnabled  = $Enabled
            DefinitionsUpToDate = $UpToDate
            PathToExe        = $AV.pathToSignedProductExe
            PathToReporting  = $AV.pathToSignedReportingExe
            Timestamp        = $AV.timestamp
        })
    }
} catch { Write-Log "AV SecurityCenter2 query failed: $_" "WARN" }

try {
    $ASList = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiSpywareProduct -ErrorAction SilentlyContinue
    foreach ($AS in $ASList) {
        $State    = $AS.productState
        $Enabled  = ($State -band 0x1000) -ne 0
        $UpToDate = ($State -band 0x0010) -eq 0
        $AVProducts.Add([PSCustomObject]@{
            ProductName      = $AS.displayName
            ProductType      = "AntiSpyware"
            ProductState     = $State
            RealTimeEnabled  = $Enabled
            DefinitionsUpToDate = $UpToDate
            PathToExe        = $AS.pathToSignedProductExe
        })
    }
} catch {}
Write-Log "Security products registered: $($AVProducts.Count)"

# Windows Defender detailed status
Write-Host "[*] Collecting Windows Defender detailed status..." -ForegroundColor Cyan
$DefenderStatus = [PSCustomObject]@{}
try {
    $MPStatus   = Get-MpComputerStatus -ErrorAction Stop
    $DefenderStatus = [PSCustomObject]@{
        AMEngineVersion          = $MPStatus.AMEngineVersion
        AMProductVersion         = $MPStatus.AMProductVersion
        AMServiceEnabled         = $MPStatus.AMServiceEnabled
        AMServiceVersion         = $MPStatus.AMServiceVersion
        AntispywareEnabled       = $MPStatus.AntispywareEnabled
        AntispywareSignatureAge  = $MPStatus.AntispywareSignatureAge
        AntispywareSignatureVersion = $MPStatus.AntispywareSignatureVersion
        AntivirusEnabled         = $MPStatus.AntivirusEnabled
        AntivirusSignatureAge    = $MPStatus.AntivirusSignatureAge
        AntivirusSignatureVersion= $MPStatus.AntivirusSignatureVersion
        BehaviorMonitorEnabled   = $MPStatus.BehaviorMonitorEnabled
        IoavProtectionEnabled    = $MPStatus.IoavProtectionEnabled
        IsTamperProtected        = $MPStatus.IsTamperProtected
        NISEnabled               = $MPStatus.NISEnabled
        OnAccessProtectionEnabled= $MPStatus.OnAccessProtectionEnabled
        RealTimeProtectionEnabled= $MPStatus.RealTimeProtectionEnabled
        LastFullScanEndTime      = if ($MPStatus.FullScanEndTime) { $MPStatus.FullScanEndTime.ToString("o") } else { $null }
        LastQuickScanEndTime     = if ($MPStatus.QuickScanEndTime) { $MPStatus.QuickScanEndTime.ToString("o") } else { $null }
        DefenderSignatureAge     = $MPStatus.AntivirusSignatureAge
        SignaturesOutdated       = ($MPStatus.AntivirusSignatureAge -gt 7)
    }
    Write-Log "Defender: Enabled=$($MPStatus.AntivirusEnabled) SigAge=$($MPStatus.AntivirusSignatureAge)days TamperProtected=$($MPStatus.IsTamperProtected)"
} catch { Write-Log "Defender status failed: $_" "WARN" }

# Defender quarantine items
Write-Host "[*] Collecting Defender quarantine items..." -ForegroundColor Cyan
$QuarantineItems = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
    foreach ($T in $Threats) {
        $ThreatInfo = Get-MpThreat -ThreatID $T.ThreatID -ErrorAction SilentlyContinue
        $QuarantineItems.Add([PSCustomObject]@{
            ThreatID         = $T.ThreatID
            ThreatName       = $ThreatInfo.ThreatName
            SeverityID       = $ThreatInfo.SeverityID
            CategoryID       = $ThreatInfo.CategoryID
            ActionSuccess    = $T.ActionSuccess
            DetectionTime    = if ($T.InitialDetectionTime) { $T.InitialDetectionTime.ToString("o") } else { $null }
            RemediationTime  = if ($T.RemediationTime) { $T.RemediationTime.ToString("o") } else { $null }
            Resources        = $T.Resources
        })
    }
    Write-Log "Quarantine/detection items: $($QuarantineItems.Count)"
} catch { Write-Log "Threat detection query failed: $_" "WARN" }

# Defender exclusions
Write-Host "[*] Collecting Defender exclusions..." -ForegroundColor Cyan
$DefenderExclusions = [PSCustomObject]@{}
try {
    $Prefs = Get-MpPreference -ErrorAction Stop
    $DefenderExclusions = [PSCustomObject]@{
        ExclusionPath        = $Prefs.ExclusionPath
        ExclusionExtension   = $Prefs.ExclusionExtension
        ExclusionProcess     = $Prefs.ExclusionProcess
        ExclusionIPAddress   = $Prefs.ExclusionIpAddress
        DisableRealtimeMonitoring = $Prefs.DisableRealtimeMonitoring
        DisableBehaviorMonitoring = $Prefs.DisableBehaviorMonitoring
        DisableBlockAtFirstSeen   = $Prefs.DisableBlockAtFirstSeen
        TotalExclusions      = ($Prefs.ExclusionPath.Count + $Prefs.ExclusionProcess.Count + $Prefs.ExclusionExtension.Count)
        SuspiciousExclusions = @($Prefs.ExclusionPath | Where-Object { $_ -match "TEMP|AppData|Downloads|Desktop|Startup" })
    }
} catch { Write-Log "Exclusion query failed: $_" "WARN" }

# Known EDR products running as services
Write-Host "[*] Detecting EDR/Security agent services..." -ForegroundColor Cyan
$EDRPatterns = @{
    "CrowdStrike Falcon"    = @("CSFalconService","CsFalconContainer")
    "SentinelOne"           = @("SentinelAgent","SentinelStaticEngine")
    "Carbon Black"          = @("CbDefense","CbDefenseSensor","carbonblack")
    "Microsoft Defender ATP"= @("Sense","WdNisSvc","WinDefend")
    "Symantec SEP"          = @("SepMasterService","ccSvcHst")
    "McAfee/Trellix"        = @("mfewc","McAfeeFramework","mfemms")
    "Cylance"               = @("CylanceSvc")
    "Sophos"                = @("SophosAgent","SAVService","Sophos MCS Agent")
    "Trend Micro"           = @("TmCCSF","ntrtscan","TmPfw")
    "ESET"                  = @("ekrn","EHttpSrv")
    "Kaspersky"             = @("AVP","klnagent")
    "Malwarebytes"          = @("MBAMService","MBAMProtection")
    "Palo Alto Cortex"      = @("cyserver","traps_agent")
    "Elastic Agent"         = @("Elastic Agent","elastic-agent")
    "Velociraptor"          = @("Velociraptor")
}

$DetectedEDR = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($Product in $EDRPatterns.Keys) {
    foreach ($SvcName in $EDRPatterns[$Product]) {
        $Svc = Get-Service $SvcName -ErrorAction SilentlyContinue
        if ($Svc) {
            $DetectedEDR.Add([PSCustomObject]@{
                Product     = $Product
                ServiceName = $Svc.Name
                Status      = $Svc.Status.ToString()
                StartType   = $Svc.StartType.ToString()
                Running     = ($Svc.Status -eq "Running")
            })
            Write-Log "EDR detected: $Product ($SvcName) - $($Svc.Status)"
            break
        }
    }
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType        = "AV_EDR_Status"
    RegisteredProducts  = $AVProducts
    WindowsDefender     = $DefenderStatus
    DefenderExclusions  = $DefenderExclusions
    QuarantineItems     = $QuarantineItems
    DetectedEDRAgents   = $DetectedEDR
    Summary = [PSCustomObject]@{
        TotalSecurityProducts = $AVProducts.Count
        EDRAgentsDetected     = $DetectedEDR.Count
        QuarantineCount       = $QuarantineItems.Count
        DefenderEnabled       = $DefenderStatus.AntivirusEnabled
        TamperProtected       = $DefenderStatus.IsTamperProtected
        SignaturesOutdated    = $DefenderStatus.SignaturesOutdated
        SuspiciousExclusions  = if ($DefenderExclusions.SuspiciousExclusions) { $DefenderExclusions.SuspiciousExclusions.Count } else { 0 }
    }
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] AV/EDR status collected | Products: $($AVProducts.Count) | EDR Agents: $($DetectedEDR.Count) | Quarantine: $($QuarantineItems.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
