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
            # Parenthesise each Test-Path: '-or' is not a Test-Path parameter, so the
            # unparenthesised form bound '-or'/the second path as arguments to the first call.
            if ((Test-Path $InprocKey) -or (Test-Path $LocalSrv)) {
                $HKCUVal = (Get-ItemProperty $InprocKey -ErrorAction SilentlyContinue)."(default)"
                if (-not $HKCUVal) { $HKCUVal = (Get-ItemProperty $LocalSrv -ErrorAction SilentlyContinue)."(default)" }
                $OverridesHKLM = Test-Path $HKLMPath

                # Resolve the server binary: expand env vars, strip quotes/arguments.
                $ServerPath = $HKCUVal
                if ($ServerPath) {
                    $ServerPath = [Environment]::ExpandEnvironmentVariables([string]$ServerPath)
                    if ($ServerPath -match '^"([^"]+)"') { $ServerPath = $Matches[1] }
                    elseif ($ServerPath -match '^([^\s,]+\.(dll|exe|ocx))') { $ServerPath = $Matches[1] }
                    $ServerPath = $ServerPath.Trim('"').Trim()
                }
                $InSystemLoc = $false
                if ($ServerPath) {
                    $InSystemLoc = ($ServerPath -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') -or
                                   ($ServerPath -match '(?i)\\Program Files( \(x86\))?\\')
                }

                # COM hijacking is only meaningful when an HKCU CLSID OVERRIDES an existing
                # HKLM CLSID and the server binary is NOT in a trusted system location.
                # Benign per-user COM registration (Office, browsers, .NET) is extremely common,
                # so only record genuine candidates to keep the report free of false positives.
                if ($OverridesHKLM -and -not $InSystemLoc) {
                    $COMHijacks.Add([PSCustomObject]@{
                        CLSID            = $CLSID
                        HKCUPath         = $_.PSPath
                        HKCUValue        = $HKCUVal
                        ServerPath       = $ServerPath
                        OverridesHKLM    = $OverridesHKLM
                        InSystemLocation = $InSystemLoc
                        Suspicious       = $true
                    })
                }
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
# A LOLBAS binary name appearing in an event is NOT suspicious by itself: these
# binaries run constantly during normal servicing, installs and dev builds. We flag
# only when (a) a known abuse ARGUMENT pattern is present on the command line, or
# (b) a LOLBAS binary executes from OUTSIDE a trusted system directory. We pull
# process-creation events from Security/4688 and, when present, Sysmon/1 (which
# always carries the command line even when 4688 cmdline auditing is off).
Write-Host "[*] Checking LOLBAS abuse in recent process-creation events..." -ForegroundColor Cyan
$LOLBASBins = @("certutil","mshta","regsvr32","rundll32","msiexec","wscript","cscript","bitsadmin",
                "forfiles","cmdkey","appsyncpublishingserver","ntdsutil","mavinject",
                "syncappvpublishingserver","diskshadow","regasm","regsvcs","installutil","msbuild",
                "cmstp","odbcconf","xwizard")

# High-signal abuse argument patterns (evidence of proxy execution / download).
$LOLBASAbuse = @(
    'certutil(\.exe)?\b.*(-urlcache|-decode|-encode|-f\s+-split|-verifyctl)',
    'regsvr32(\.exe)?\b.*(/i:http|scrobj\.dll|/u\s+/n\s+/i:)',
    'rundll32(\.exe)?\b.*(javascript:|vbscript:|,Control_RunDLL\s+http|url\.dll,|shell32\.dll,ShellExec)',
    'mshta(\.exe)?\b.*(http|https|javascript:|vbscript:)',
    'bitsadmin(\.exe)?\b.*(/transfer|/addfile|/create)',
    'msiexec(\.exe)?\b.*(/q\S*\s+\S*http|/i\s+http|/y\s)',
    '(wscript|cscript)(\.exe)?\b.*\.(vbs|js|jse|vbe|wsf|wsh)\b',
    'msbuild(\.exe)?\b.*\.(xml|csproj|targets|proj)\b',
    'installutil(\.exe)?\b.*/logfile=.*/logtoconsole=false',
    'cmstp(\.exe)?\b.*(/s|/ni).*\.inf',
    'odbcconf(\.exe)?\b.*(/a\b|regsvr)',
    'mavinject(\.exe)?\b.*/injectrunning',
    'forfiles(\.exe)?\b.*/c\s+"?cmd',
    'diskshadow(\.exe)?\b.*/s\b',
    'xwizard(\.exe)?\b.*RunWizard'
)

$LOLBASHits = [System.Collections.Generic.List[PSCustomObject]]::new()

# Is 4688 command-line auditing enabled? Without it, argument-based detection is blind.
$CmdLineAuditing = $false
try {
    $CmdLineAuditing = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1)
} catch {}

# Build a unified list of {Time, Image, CommandLine, Source} process-creation records.
$ExecRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=4688; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue | ForEach-Object {
        $Msg = $_.Message
        $img = if ($Msg -match 'New Process Name:\s*(.+)')      { $Matches[1].Trim() } else { $null }
        $cmd = if ($Msg -match 'Process Command Line:\s*(.+)')  { $Matches[1].Trim() } else { $null }
        if ($img) { $ExecRecords.Add([PSCustomObject]@{ Time=$_.TimeCreated; Image=$img; CommandLine=$cmd; Source="Security/4688" }) }
    }
} catch { Write-Log "4688 query error: $_" "WARN" }
try {
    Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-Sysmon/Operational"; Id=1; StartTime=(Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue | ForEach-Object {
        $Msg = $_.Message
        $img = if ($Msg -match 'Image:\s*(.+)')       { $Matches[1].Trim() } else { $null }
        $cmd = if ($Msg -match 'CommandLine:\s*(.+)')  { $Matches[1].Trim() } else { $null }
        if ($img) { $ExecRecords.Add([PSCustomObject]@{ Time=$_.TimeCreated; Image=$img; CommandLine=$cmd; Source="Sysmon/1" }) }
    }
} catch {}

foreach ($rec in $ExecRecords) {
    $base = try { [System.IO.Path]::GetFileNameWithoutExtension($rec.Image).ToLower() } catch { $null }
    if (-not $base -or ($LOLBASBins -notcontains $base)) { continue }

    $inSystem = $rec.Image -match '(?i)\\Windows\\(System32|SysWOW64)\\'
    $abusePat = $null
    if ($rec.CommandLine) {
        foreach ($pat in $LOLBASAbuse) { if ($rec.CommandLine -match $pat) { $abusePat = $pat; break } }
    }

    # Flag only on a matched abuse pattern, or a LOLBAS binary run from a non-system path.
    if ($abusePat -or -not $inSystem) {
        $snip = if ($rec.CommandLine) { $rec.CommandLine } else { $rec.Image }
        $snip = ($snip -split "`r?`n") -join " "
        $LOLBASHits.Add([PSCustomObject]@{
            TimeCreated = $rec.Time.ToString("o")
            Source      = $rec.Source
            MatchedBin  = $base
            Image       = $rec.Image
            Confidence  = if ($abusePat) { "High" } else { "Medium" }
            Reason      = if ($abusePat) { "abuse-argument pattern" } else { "LOLBAS binary from non-system path" }
            CommandLine = $snip.Substring(0,[Math]::Min(500,$snip.Length))
        })
    }
}
if (-not $CmdLineAuditing -and ($ExecRecords | Where-Object { $_.Source -eq "Sysmon/1" }).Count -eq 0) {
    Write-Log "4688 command-line auditing is DISABLED and no Sysmon present - LOLBAS argument detection is blind (absence of hits does not mean clean)" "WARN"
}
Write-Log "LOLBAS abuse hits: $($LOLBASHits.Count) (cmdline auditing: $CmdLineAuditing, process events: $($ExecRecords.Count))"

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
    LOLBASDetection    = [PSCustomObject]@{
        CommandLineAuditingEnabled = $CmdLineAuditing
        ProcessEventsExamined      = $ExecRecords.Count
        Note = if (-not $CmdLineAuditing -and ($ExecRecords | Where-Object { $_.Source -eq 'Sysmon/1' }).Count -eq 0) {
            "Command-line auditing is disabled and Sysmon is absent; argument-based LOLBAS detection is blind. Zero hits does not indicate a clean host."
        } else { "Process-creation telemetry available." }
    }
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
