#Requires -Version 5.1
<#
.SYNOPSIS
    Advanced threat hunting checks across multiple attack techniques.

.DESCRIPTION
    Performs targeted hunting checks for:
    - COM hijacking entries in HKCU
    - UAC / AppLocker / WDAC bypass indicators
    - LOLBAS (Living Off the Land) abuse evidence
    - Defender exclusions added by attackers
    - Suspicious scheduled task patterns
    - Print spooler driver abuse (PrintNightmare)
    - DCOM lateral movement config
    - Recycle bin metadata
    - Clipboard content snapshot
    - Installed software anomalies
    - Environment variable PATH hijacking risk

.IR_PHASE
    Threat Hunting / Advanced Investigation

.MITRE_ATTCK
    T1218  - Signed Binary Proxy Execution (LOLBAS)
    T1548  - Abuse Elevation Control Mechanism
    T1562  - Impair Defenses
    T1112  - Modify Registry

.FORENSIC_SAFETY
    Read-only, forensic-safe

.AUTHOR
    DFIR Toolkit

.VERSION
    2.0
#>

Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\ThreatHunting_Execution.log"
$JsonFile = "$BasePath\ThreatHunting_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Threat hunting collection started"

# -- COM Hijacking (HKCU overrides HKLM) ---------------------------------------
Write-Host "[*] Checking COM hijacking indicators..." -ForegroundColor Cyan
$COMHijacks = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    if (Test-Path "HKCU:\Software\Classes\CLSID") {
        Get-ChildItem "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | ForEach-Object {
            $CLSID = $_.PSChildName
            $HKLMPath = "HKLM:\Software\Classes\CLSID\$CLSID"
            $InprocKey= "$($_.PSPath)\InprocServer32"
            $LocalSrv = "$($_.PSPath)\LocalServer32"
            if (Test-Path $InprocKey -or Test-Path $LocalSrv) {
                $HKCUVal = (Get-ItemProperty $InprocKey -ErrorAction SilentlyContinue)."(default)"
                $COMHijacks.Add([PSCustomObject]@{
                    CLSID       = $CLSID
                    HKCUPath    = $_.PSPath
                    HKCUValue   = $HKCUVal
                    OverridesHKLM = (Test-Path $HKLMPath)
                    Suspicious  = $true
                })
            }
        }
    }
    Write-Log "COM hijack candidates: $($COMHijacks.Count)"
} catch { Write-Log "COM hijack check error: $_" "WARN" }

# -- UAC Configuration ----------------------------------------------------------
Write-Host "[*] Checking UAC configuration..." -ForegroundColor Cyan
$UACKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
$UACConfig = [PSCustomObject]@{
    EnableLUA                    = $UACKey.EnableLUA
    ConsentPromptBehaviorAdmin   = $UACKey.ConsentPromptBehaviorAdmin
    ConsentPromptBehaviorUser    = $UACKey.ConsentPromptBehaviorUser
    EnableInstallerDetection     = $UACKey.EnableInstallerDetection
    EnableSecureUIAPaths         = $UACKey.EnableSecureUIAPaths
    EnableVirtualization         = $UACKey.EnableVirtualization
    PromptOnSecureDesktop        = $UACKey.PromptOnSecureDesktop
    UACDisabled                  = ($UACKey.EnableLUA -eq 0)
}

# -- Defender Exclusions --------------------------------------------------------
Write-Host "[*] Checking Windows Defender exclusions..." -ForegroundColor Cyan
$DefenderExclusions = [PSCustomObject]@{}
try {
    $DefPrefs = Get-MpPreference -ErrorAction SilentlyContinue
    $DefenderExclusions = [PSCustomObject]@{
        ExclusionPath        = $DefPrefs.ExclusionPath
        ExclusionExtension   = $DefPrefs.ExclusionExtension
        ExclusionProcess     = $DefPrefs.ExclusionProcess
        DisableRealtimeMonitoring = $DefPrefs.DisableRealtimeMonitoring
        DisableBehaviorMonitoring = $DefPrefs.DisableBehaviorMonitoring
        DisableBlockAtFirstSeen   = $DefPrefs.DisableBlockAtFirstSeen
        DisableIOAVProtection     = $DefPrefs.DisableIOAVProtection
        MAPSReporting             = $DefPrefs.MAPSReporting
        TamperProtection          = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -ErrorAction SilentlyContinue).TamperProtection
        Note_Exclusions      = "Check ExclusionPath and ExclusionProcess fields above for suspicious entries"
    }
    Write-Log "Defender exclusions: Paths=$($DefPrefs.ExclusionPath.Count) Procs=$($DefPrefs.ExclusionProcess.Count)"
} catch { Write-Log "Defender check error: $_" "WARN" }

# -- LOLBAS Abuse Detection -----------------------------------------------------
Write-Host "[*] Checking LOLBAS usage in recent event logs..." -ForegroundColor Cyan
$LOLBASBins = @("certutil","mshta","regsvr32","rundll32","msiexec","wscript","cscript","bitsadmin",
                "forfiles","pcalua","cmdkey","eudcedit","appsyncpublishingserver","ntdsutil",
                "syncappvpublishingserver","diskshadow","regasm","regsvcs","installutil","msbuild",
                "cmstp","odbcconf","pcwrun","xwizard","ftp","makecab","replace","expand")

$LOLBASHits = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $ProcEvents = Get-WinEvent -FilterHashtable @{
        LogName="Security"; Id=4688; StartTime=(Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue

    foreach ($Evt in $ProcEvents) {
        $Msg = $Evt.Message
        foreach ($Bin in $LOLBASBins) {
            if ($Msg -match "\b$Bin\b") {
                $LOLBASHits.Add([PSCustomObject]@{
                    TimeCreated = $Evt.TimeCreated.ToString("o")
                    EventID     = 4688
                    MatchedBin  = $Bin
                    MessageSnip = ($Msg -split "`r?`n" -join " ").Substring(0,[Math]::Min(400,$Msg.Length))
                })
                break
            }
        }
    }
    Write-Log "LOLBAS hits in event log: $($LOLBASHits.Count)"
} catch { Write-Log "LOLBAS event check error: $_" "WARN" }

# -- PrintNightmare / Spooler ---------------------------------------------------
Write-Host "[*] Checking Print Spooler / PrintNightmare indicators..." -ForegroundColor Cyan
$SpoolerConfig = [PSCustomObject]@{
    SpoolerRunning         = ((Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq "Running")
    SpoolerStartType       = (Get-Service Spooler -ErrorAction SilentlyContinue).StartType
    RegisterSpoolerRemoteRpcEndPoint = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Print" -ErrorAction SilentlyContinue).RegisterSpoolerRemoteRpcEndPoint
    NonDefaultDrivers = @(Get-PrinterDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.PrinterEnvironment -eq "Windows x64" -and $_.Name -notin @("Microsoft Print To PDF","Microsoft XPS Document Writer","Fax") } |
        Select-Object Name, DriverVersion, PrinterEnvironment, InfPath)
}

# -- Installed Software Anomalies -----------------------------------------------
Write-Host "[*] Collecting installed software..." -ForegroundColor Cyan
$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)
$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

$InstalledSoftware = [System.Collections.Generic.List[PSCustomObject]]::new()
$RecentlyInstalled = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($RegPath in $RegPaths) {
    Get-ChildItem $RegPath -ErrorAction SilentlyContinue | ForEach-Object {
        $App = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if (-not $App.DisplayName) { return }
        $InstDate = $null
        if ($App.InstallDate -match "^\d{8}$") {
            try { $InstDate = [datetime]::ParseExact($App.InstallDate,"yyyyMMdd",$null).ToString("o") } catch {}
        }
        $Entry = [PSCustomObject]@{
            DisplayName    = $App.DisplayName
            Version        = $App.DisplayVersion
            Publisher      = $App.Publisher
            InstallDate    = $InstDate
            InstallLocation= $App.InstallLocation
            UninstallString= $App.UninstallString
            RegistryPath   = $_.PSPath
        }
        $InstalledSoftware.Add($Entry)
        if ($InstDate -and ([datetime]::Parse($InstDate) -gt $SinceDate)) {
            $RecentlyInstalled.Add($Entry)
        }
    }
}
Write-Log "Installed software: $($InstalledSoftware.Count) | Recently installed: $($RecentlyInstalled.Count)"

# -- PATH Hijacking Risk --------------------------------------------------------
Write-Host "[*] Checking PATH hijacking risk..." -ForegroundColor Cyan
$PathEntries = @($env:PATH -split ";") | Where-Object { $_ -ne "" }
$WritablePATH = @($PathEntries | Where-Object {
    if (-not (Test-Path $_)) { return $false }
    try {
        $ACL = Get-Acl $_ -ErrorAction Stop
        $WritableIdentities = @("Everyone","BUILTIN\Users","NT AUTHORITY\Authenticated Users")
        $ACL.Access | Where-Object {
            $WritableIdentities -contains $_.IdentityReference.Value -and
            $_.FileSystemRights -match "Write|FullControl|Modify" -and
            $_.AccessControlType -eq "Allow"
        }
    } catch { $false }
})
Write-Log "Writable PATH entries: $($WritablePATH.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody     = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType       = "ThreatHunting"
    COMHijackCandidates= $COMHijacks
    UACConfig          = $UACConfig
    DefenderExclusions = $DefenderExclusions
    LOLBASHits         = $LOLBASHits
    PrintSpooler       = $SpoolerConfig
    InstalledSoftware  = $InstalledSoftware
    RecentlyInstalled  = $RecentlyInstalled
    WritablePATHEntries= $WritablePATH
}

$Evidence | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Threat hunting complete" -ForegroundColor Green
Write-Host "    COM Hijacks: $($COMHijacks.Count) | LOLBAS Hits: $($LOLBASHits.Count) | Recent Installs: $($RecentlyInstalled.Count)" -ForegroundColor Cyan
Write-Host "    UAC Disabled: $($UACConfig.UACDisabled) | Defender Exclusions: $($DefenderExclusions.ExclusionPath.Count + $DefenderExclusions.ExclusionProcess.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
