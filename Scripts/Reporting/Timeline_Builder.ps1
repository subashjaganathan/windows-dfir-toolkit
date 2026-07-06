#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname     = $env:COMPUTERNAME
$BasePath     = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum      = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
$Investigator = if ($env:DFIR_INV)  { $env:DFIR_INV  } else { $env:USERNAME }
$ReportDir    = "$BasePath\Timeline_${Timestamp}"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
$LogFile  = "$BasePath\Timeline_Execution.log"
$JsonFile = "$BasePath\Timeline_${Hostname}_${Timestamp}.json"
$CSVFile  = "$ReportDir\Timeline_${Hostname}_${Timestamp}.csv"
$HTMLFile = "$ReportDir\Timeline_${Hostname}_${Timestamp}.html"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Timeline builder started | Case: $CaseNum"

# Helper: safely get CollectedAt from any evidence file
function Get-COC {
    param($Data)
    try {
        if ($Data.ChainOfCustody -and $Data.ChainOfCustody.CollectedAt) {
            return $Data.ChainOfCustody.CollectedAt.ToString()
        }
        if ($Data.CollectedAt) { return $Data.CollectedAt.ToString() }
    } catch {}
    return (Get-Date).ToString("o")
}

Write-Host "[*] Loading all evidence artifacts..." -ForegroundColor Cyan

$EvidenceFiles = @(Get-ChildItem $BasePath -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch "\.hash\.json$|Manifest|Timeline|Report|IOC" })

Write-Host "[*] Found $($EvidenceFiles.Count) evidence files" -ForegroundColor Cyan

$Timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Event {
    param(
        $Time,
        [string]$Source,
        [string]$Category,
        [string]$Description,
        [string]$User = "",
        [string]$HostVal = "",
        [string]$Detail = "",
        [string]$Severity = "INFO"
    )
    if (-not $Time) { return }
    $TimeStr = "$Time"
    if ($TimeStr -eq "" -or $TimeStr -eq "null" -or $TimeStr -match "^0001|^1/1/0001") { return }

    # Normalise every event time to UTC so a mixed-source timeline sorts correctly and the
    # "UTC" column/label is truthful (producers emit a mix of UTC and local timestamps).
    $DT = $null
    if ($Time -is [datetime]) {
        $DT = if ($Time.Kind -eq [System.DateTimeKind]::Utc) { $Time } else { $Time.ToUniversalTime() }
    } elseif ($Time -is [datetimeoffset]) {
        $DT = $Time.UtcDateTime
    } else {
        # ISO 8601 with offset (e.g. "2026-05-28T21:12:01.123+05:30") -> convert to UTC.
        if (-not $DT) { try { $DT = [datetimeoffset]::Parse($TimeStr, [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime } catch {} }
        if (-not $DT) { try { $DT = [datetime]::Parse($TimeStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch {} }
        if (-not $DT) { try { $DT = ([datetime]::Parse($TimeStr)).ToUniversalTime() } catch {} }
    }
    if ($null -eq $DT) { return }
    if ($DT.Year -lt 2000 -or $DT.Year -gt 2100) { return }

    $DetailTrim = ""
    if ($Detail -and $Detail.Length -gt 0) { $DetailTrim = $Detail.Substring(0,[Math]::Min(200,$Detail.Length)) }
    $HostFinal = if ($HostVal) { $HostVal } else { $script:Hostname }

    $script:Timeline.Add([PSCustomObject]@{
        DateTime    = $DT.ToString("o")
        DateTimeUTC = $DT.ToString("yyyy-MM-dd HH:mm:ss")
        Source      = $Source
        Category    = $Category
        Severity    = $Severity
        Description = $Description
        User        = $User
        Hostname    = $HostFinal
        Detail      = $DetailTrim
    })
}

foreach ($F in $EvidenceFiles) {
    try {
        $Raw = Get-Content $F.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $Raw) { continue }
        $Data = $Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $Data) { continue }
        $AT = $Data.ArtifactType
        if (-not $AT) { continue }

        $Pre = $Timeline.Count
        Write-Host "  [*] Processing $AT..." -ForegroundColor Cyan

        switch ($AT) {

            #  Security Event Log 
            "SecurityEventLog" {
                $Col = (Get-COC $Data)
                $EventArray = if ($Data.Data) { $Data.Data } elseif ($Data.Events) { $Data.Events } else { @() }
                foreach ($E in $EventArray) {
                    if (-not $E) { continue }
                    $T = $Col
                    try { if ($E.TimeCreated -and $E.TimeCreated.ToString() -ne "") { $T = $E.TimeCreated.ToString() } } catch {}
                    $Msg = ""
                    try { if ($E.Message) { $Msg = $E.Message.ToString().Substring(0,[Math]::Min(150,$E.Message.ToString().Length)) } } catch {}
                    $EID = 0
                    try { $EID = [int]$E.EventID } catch {}
                    $Sev = if ($EID -in @(4625,4648,4720,4728,4732,4756,4768,4769,4776)) { "HIGH" } else { "INFO" }
                    Add-Event $T "SecurityLog" "Authentication" "EventID $EID : $($E.EventType)" "" "$($E.Computer)" $Msg $Sev
                }
            }

            #  System/App Event Log 
            "SystemApplicationEventLog" {
                if ($Data.EventGroups) {
                    $Data.EventGroups.PSObject.Properties | ForEach-Object {
                        foreach ($E in $_.Value) {
                            $Msg = if ($E.Message) { $E.Message.Substring(0,[Math]::Min(100,$E.Message.Length)) } else { "" }
                            Add-Event $E.TimeCreated "SystemLog" "System" "EventID $($E.EventID): $Msg" "" $E.Computer "" "INFO"
                        }
                    }
                }
            }

            #  PowerShell Event Log 
            "PowerShellEventLog" {
                foreach ($S in $Data.ScriptBlockEvents) {
                    if ($S.IsSuspicious) {
                        $ST = if ($S.ScriptText) { $S.ScriptText.Substring(0,[Math]::Min(200,$S.ScriptText.Length)) } else { "" }
                        Add-Event $S.TimeCreated "PowerShellLog" "SuspiciousExecution" "Suspicious PS: $($S.SuspiciousIndicators -join ', ')" $S.UserSID "" $ST "HIGH"
                    }
                }
                foreach ($E in $Data.LegacyEvents) {
                    Add-Event $E.TimeCreated "PowerShellLog" "Execution" "PS Legacy Event $($E.EventID)" "" "" "" "INFO"
                }
            }

            #  Logon Sessions 
            "Logon_Sessions_Deep" {
                foreach ($L in $Data.LogonEvents) {
                    if ($L.IsSuspicious) {
                        $Sev = "HIGH"
                        Add-Event $L.TimeCreated "LogonSessions" "Authentication" "Suspicious logon: $($L.LogonTypeName) from $($L.SourceIP)" $L.TargetUser "" $L.AuthPackage $Sev
                    }
                }
                foreach ($F2 in $Data.FailedLogons) {
                    Add-Event $F2.TimeCreated "FailedLogon" "Authentication" "Failed logon from $($F2.SourceIP): $($F2.FailureReason)" $F2.TargetUser "" "" "MEDIUM"
                }
                foreach ($B in $Data.BruteForceIPs) {
                    Add-Event (Get-COC $Data) "BruteForce" "Authentication" "Brute force: $($B.FailCount) attempts from $($B.SourceIP)" "" "" "" "CRITICAL"
                }
            }

            #  Running Processes 
            "RunningProcesses" {
                $ProcArray = if ($Data.Data) { $Data.Data } else { @() }
                foreach ($P in $ProcArray) {
                    if (-not $P) { continue }
                    try {
                        if ($P.StartTime) {
                            $Sev = if ($P.IsSuspicious) { "HIGH" } else { "INFO" }
                            Add-Event $P.StartTime.ToString() "RunningProcesses" "ProcessExecution" "$( if($P.IsSuspicious){'SUSPICIOUS: '} )$($P.ProcessName) PID:$($P.PID)" "$($P.Owner)" "" "$($P.ExecutablePath)" $Sev
                        }
                    } catch {}
                }
            }

            #  Scheduled Tasks 
            "ScheduledTasks" {
                $TaskArray = if ($Data.Data) { $Data.Data } else { @() }
                foreach ($T in $TaskArray) {
                    if (-not $T) { continue }
                    try {
                        if ($T.LastRunTime -and $T.LastRunTime.ToString() -ne "") {
                            $Sev = if ($T.IsSuspicious) { "HIGH" } else { "INFO" }
                            Add-Event $T.LastRunTime.ToString() "ScheduledTasks" "Execution" "Task: $($T.TaskName)" "$($T.RunAsUser)" "" "$($T.Command) $($T.Arguments)" $Sev
                        }
                    } catch {}
                }
            }
            "ScheduledTaskXML" {
                foreach ($T in $Data.AllTasks) {
                    if ($T.LastRunTime -and $T.IsSuspicious) {
                        Add-Event $T.LastRunTime "ScheduledTaskXML" "Persistence" "Suspicious task: $($T.TaskName) - $($T.SuspiciousReasons)" $T.RunAs "" $T.TaskPath "HIGH"
                    }
                }
            }

            #  Windows Services 
            "WindowsServices" {
                $SvcArray = if ($Data.Data) { $Data.Data } else { @() }
                $ColAT = try { (Get-COC $Data).ToString() } catch { (Get-Date).ToString("o") }
                foreach ($S in $SvcArray) {
                    if (-not $S) { continue }
                    try {
                        if ($S.IsSuspicious) {
                            Add-Event $ColAT "WindowsServices" "Persistence" "Suspicious service: $($S.ServiceName) | $($S.BinaryPath)" "$($S.RunAsAccount)" "" "$($S.BinaryPath)" "HIGH"
                        }
                    } catch {}
                }
            }

            #  Registry 
            "RegistryRunKeys" {
                $RegArray = if ($Data.Data) { $Data.Data } else { @() }
                $ColAT = try { (Get-COC $Data).ToString() } catch { (Get-Date).ToString("o") }
                foreach ($R in $RegArray) {
                    if (-not $R) { continue }
                    try {
                        $Sev = if ($R.IsSuspicious) { "HIGH" } else { "INFO" }
                        Add-Event $ColAT "RegistryRunKeys" "Persistence" "Run key: $($R.Name) = $($R.Value)" "" "" "$($R.KeyPath)" $Sev
                    } catch {}
                }
            }
            "RegistryExecutionArtifacts" {
                foreach ($B in $Data.BAMEntries) {
                    if ($B.LastExecuted) { Add-Event $B.LastExecuted "BAM" "Execution" "BAM execution: $($B.ExePath)" $B.UserSID "" "" "INFO" }
                }
                foreach ($U in $Data.UserAssist) {
                    if ($U.LastRun) { Add-Event $U.LastRun "UserAssist" "UserActivity" "UserAssist: $($U.ProgramName)" "" "" "" "INFO" }
                }
            }
            "Registry_Deep_Persistence" {
                # Producer emits PersistenceFindings[] with Category/RegistryKey/Value/RiskLevel.
                foreach ($F2 in $Data.PersistenceFindings) {
                    $Sev = if ($F2.RiskLevel -eq "CRITICAL") { "CRITICAL" } elseif ($F2.RiskLevel -eq "HIGH") { "HIGH" } else { "INFO" }
                    Add-Event (Get-COC $Data) "DeepPersistence" "Persistence" "$($F2.RiskLevel): $($F2.Category) - $($F2.RegistryKey)" "" "" "$($F2.Value)" $Sev
                }
            }
            "WMIPersistence" {
                # Producer emits Data[] (not EventBindings) with FilterName/ConsumerName.
                foreach ($B in $Data.Data) {
                    Add-Event (Get-COC $Data) "WMI" "Persistence" "WMI binding: $($B.FilterName) -> $($B.ConsumerName)" "" "" "$($B.ConsumerType)" "HIGH"
                }
            }
            "StartupFolder" {
                foreach ($S in $Data.Data) {
                    Add-Event $S.CreationTime "StartupFolder" "Persistence" "Startup item: $($S.Name)" "" "" $S.FullPath "MEDIUM"
                }
            }
            "GPO_Cache_Scripts" {
                foreach ($S in $Data.SuspiciousScripts) {
                    Add-Event $S.CreationTime "GPO" "Persistence" "Suspicious GPO script: $($S.ScriptName)" "" "" $S.FullPath "HIGH"
                }
            }

            #  File System 
            "FileSystemArtifacts" {
                foreach ($F2 in $Data.RecentLNKFiles) {
                    if ($F2.LastWriteTime) { Add-Event $F2.LastWriteTime "LNKFiles" "UserActivity" "File accessed: $($F2.TargetPath)" $F2.User "" $F2.LNKPath "INFO" }
                }
                foreach ($F2 in $Data.SuspiciousDrops) {
                    if ($F2.CreationTime) { Add-Event $F2.CreationTime "SuspiciousDrops" "FileSystem" "Suspicious file: $($F2.FileName)" "" "" $F2.Path "HIGH" }
                }
            }
            "Backup_VSS_Deep" {
                foreach ($E in $Data.VSSDeletionCommands) {
                    Add-Event $E.TimeCreated "VSS_Deletion" "Impact" "VSS deletion: $($E.CommandLine)" $E.SubjectUser "" "" "CRITICAL"
                }
                foreach ($S in $Data.ShadowCopies) {
                    Add-Event $S.CreationDate "ShadowCopy" "Backup" "Shadow copy: $($S.VolumeName)" "" "" $S.ID "INFO"
                }
            }
            "AppX_UWP_Apps" {
                foreach ($A in $Data.SuspiciousPackages) {
                    Add-Event (Get-COC $Data) "AppX" "Execution" "Suspicious AppX: $($A.Name)" "" "" $A.InstallLocation "MEDIUM"
                }
            }

            #  USB and Devices 
            "USB_Device_Driver_WER" {
                foreach ($U in $Data.USBDevices) {
                    if ($U.LastArrival) { Add-Event $U.LastArrival "USB" "DeviceConnection" "USB: $($U.FriendlyName)" "" "" $U.SerialNumber "INFO" }
                }
                foreach ($W in $Data.WERCrashReports) {
                    if ($W.CreationTime) { Add-Event $W.CreationTime "WERCrash" "ApplicationCrash" "Crash: $($W.AppName) v$($W.AppVersion)" "" "" $W.ReportPath "MEDIUM" }
                }
            }

            #  Network 
            "NetworkConnections" {
                foreach ($C in $Data.SuspiciousConnections) {
                    Add-Event (Get-COC $Data) "NetConnections" "C2Detection" "Suspicious connection: $($C.RemoteAddress):$($C.RemotePort) PID:$($C.OwningPID)" "" "" $C.ProcessPath "HIGH"
                }
            }
            "DNSCache" {
                foreach ($D2 in $Data.SuspiciousDomains) {
                    Add-Event (Get-COC $Data) "DNS" "C2Detection" "Suspicious DNS: $($D2.Name) -> $($D2.Data)" "" "" "" "HIGH"
                }
            }
            "Network_Advanced" {
                foreach ($R in $Data.RDPHistory) {
                    Add-Event (Get-COC $Data) "RDP_History" "LateralMovement" "RDP connection: $($R.ServerName)" "" "" "" "INFO"
                }
            }
            "NetworkPacketCapture" {
                if ($Data.CaptureStart) {
                    Add-Event $Data.CaptureStart "NetCapture" "Collection" "Network capture: $($Data.CaptureDurationSec)s ETL $($Data.ETLSizeMB)MB" "" "" "" "INFO"
                }
            }
            "LateralMovement" {
                # Producer's SMB session objects use ClientName/ClientUser (Get-SmbSession has no IP).
                foreach ($S in $Data.SMBSessions) {
                    Add-Event (Get-COC $Data) "SMBSessions" "LateralMovement" "SMB session: $($S.ClientName) user $($S.ClientUser)" "$($S.ClientUser)" "" "" "INFO"
                }
                # PSExecArtifacts is a single object of named indicators, not an array. Emit an
                # event only for indicators that are actually present.
                $PX = $Data.PSExecArtifacts
                if ($PX) {
                    if ($PX.PSEXESVCService) { Add-Event (Get-COC $Data) "PSExec" "LateralMovement" "PsExec service present (PSEXESVC)" "" "" "$($PX.PSEXESVCService)" "HIGH" }
                    if ($PX.PSEXEPipeExists) { Add-Event (Get-COC $Data) "PSExec" "LateralMovement" "PsExec named pipe present (\\.\pipe\PSEXESVC)" "" "" "" "HIGH" }
                    if ($PX.PAExecService)   { Add-Event (Get-COC $Data) "PSExec" "LateralMovement" "PAExec service present: $($PX.PAExecService)" "" "" "" "HIGH" }
                    if ($PX.RemComService)   { Add-Event (Get-COC $Data) "PSExec" "LateralMovement" "RemCom service present" "" "" "$($PX.RemComService)" "HIGH" }
                    if ($PX.SmbExecService)  { Add-Event (Get-COC $Data) "PSExec" "LateralMovement" "smbexec service present" "" "" "$($PX.SmbExecService)" "HIGH" }
                }
            }

            #  Credentials 
            "CredentialArtifacts" {
                foreach ($C in $Data.CredentialManager) {
                    Add-Event (Get-COC $Data) "CredMgr" "CredentialAccess" "Stored credential: $($C.TargetName)" $C.UserName "" $C.Type "INFO"
                }
            }
            "LSA_Secrets_Metadata" {
                foreach ($K in $Data.LSASecretKeys) {
                    if ($K.IsSuspicious) {
                        Add-Event (Get-COC $Data) "LSA_Secrets" "CredentialAccess" "Suspicious LSA key: $($K.SecretName)" "" "" $K.SuspiciousReason "HIGH"
                    }
                }
            }
            "Kerberoasting_Evidence" {
                foreach ($K in $Data.KerberoastCandidates) {
                    Add-Event $K.TimeCreated "Kerberoasting" "CredentialAccess" "RC4 TGS: $($K.ServiceName) by $($K.RequestedBy) from $($K.ClientAddress)" $K.RequestedBy "" "" "HIGH"
                }
                foreach ($A in $Data.ASREPRoastingCandidates) {
                    Add-Event $A.TimeCreated "ASREP_Roasting" "CredentialAccess" "AS-REP roastable: $($A.AccountName)" $A.AccountName "" "" "HIGH"
                }
                foreach ($B in $Data.BurstRequests) {
                    Add-Event $B.FirstSeen "Kerberoast_Burst" "CredentialAccess" "Burst Kerberoasting: $($B.RC4RequestCount) requests from $($B.ClientAddress)" "" "" "" "CRITICAL"
                }
            }
            "DCSync_Detection" {
                foreach ($D2 in $Data.DCSyncCandidates) {
                    Add-Event $D2.TimeCreated "DCSync" "CredentialAccess" "DCSync: $($D2.SubjectAccount) accessed replication rights" $D2.SubjectAccount "" $D2.Note "CRITICAL"
                }
                foreach ($P in $Data.PSToolSignatures) {
                    Add-Event $P.TimeCreated "DCSync_PS" "CredentialAccess" "DCSync PS tool detected" "" "" $P.ScriptText "CRITICAL"
                }
            }

            #  Defense Evasion 
            "AV_EDR_Status" {
                foreach ($P in $Data.RegisteredProducts) {
                    if ($P.ProductState -and $P.ProductState -match "disabled|off|266240|397568") {
                        Add-Event (Get-COC $Data) "AV_Status" "DefenseEvasion" "AV disabled: $($P.DisplayName)" "" "" "" "HIGH"
                    }
                }
            }
            "Defender_Scan_History" {
                foreach ($T in $Data.ThreatHistory) {
                    if ($T.InitialDetectionTime) {
                        $Sev = if ($T.Severity -in @("High","Severe")) { "HIGH" } else { "MEDIUM" }
                        Add-Event $T.InitialDetectionTime "DefenderDetect" "Malware" "Defender: $($T.ThreatName) [$($T.Severity)] ActionSuccess:$($T.ActionSuccess)" "" "" ($T.Resources -join ",") $Sev
                    }
                }
                foreach ($E in $Data.DefenderEvents) {
                    if ($E.EventID -in @(5001,5010,5012,2002)) {
                        Add-Event $E.TimeCreated "DefenderDisabled" "DefenseEvasion" "Defender disabled: Event $($E.EventID)" "" "" "" "CRITICAL"
                    }
                }
            }
            "FirewallRules" {
                foreach ($R in $Data.SuspiciousRules) {
                    Add-Event (Get-COC $Data) "FirewallRule" "DefenseEvasion" "Suspicious FW rule: $($R.DisplayName) $($R.Direction) $($R.Action)" "" "" "" "MEDIUM"
                }
            }
            "AntiForensics" {
                # Log-clearing events carry their own real timestamp; other findings use collection time.
                foreach ($C in $Data.LogClearing) {
                    Add-Event $C.TimeCreated "AntiForensics" "DefenseEvasion" "Event log cleared: $($C.Log) (Event $($C.EventID))" "$($C.ClearedBy)" "" "" "CRITICAL"
                }
                foreach ($F2 in $Data.Findings) {
                    if ($F2.Category -eq "LogClearing") { continue }   # already emitted above with real time
                    $sev = if ($F2.Severity -in @("CRITICAL","HIGH","MEDIUM")) { $F2.Severity } else { "INFO" }
                    $t = if ($F2.TimeCreated) { $F2.TimeCreated } else { (Get-COC $Data) }
                    Add-Event $t "AntiForensics" "DefenseEvasion" "$($F2.Title)" "" "" "$($F2.Detail)" $sev
                }
            }
            "ThreatHunting" {
                # LOLBAS hits now carry CommandLine/MatchedBin/Confidence; COM candidates live in
                # COMHijackCandidates with HKCUPath/ServerPath.
                foreach ($H in $Data.LOLBASHits) {
                    $sev = if ($H.Confidence -eq "High") { "HIGH" } else { "MEDIUM" }
                    Add-Event $H.TimeCreated "LOLBAS" "DefenseEvasion" "LOLBAS $($H.MatchedBin): $($H.CommandLine)" "" "" "$($H.Reason)" $sev
                }
                foreach ($C in $Data.COMHijackCandidates) {
                    Add-Event (Get-COC $Data) "COM_Hijack" "Persistence" "COM hijack: $($C.CLSID)" "" "" "$($C.ServerPath)" "HIGH"
                }
            }
            "IIS_WebShell_Detection" {
                foreach ($S in $Data.SuspectedShells) {
                    Add-Event $S.LastModified "WebShell" "InitialAccess" "Web shell ($($S.SignatureCount) sigs): $($S.FileName)" "" "" $S.FullPath "CRITICAL"
                }
                foreach ($R in $Data.SuspiciousRequests) {
                    Add-Event (Get-COC $Data) "WebShellAccess" "InitialAccess" "Suspicious web request from $($R.ClientIP): $($R.RequestURI)" "" "" "" "HIGH"
                }
            }

            #  Cloud and Modern 
            "CloudServiceArtifacts" {
                if ($Data.SuspiciousArtifacts) {
                    foreach ($C in $Data.SuspiciousArtifacts) {
                        Add-Event (Get-COC $Data) "Cloud" "Exfiltration" "Cloud: $($C.Name)" "" "" $C.Path "MEDIUM"
                    }
                }
            }
            "WSL_HyperV_Virtualization" {
                if ($Data.WSLInstalled) {
                    Add-Event (Get-COC $Data) "WSL" "Execution" "WSL installed - potential AV evasion vector" "" "" "" "MEDIUM"
                }
            }
            "WindowsHello_ModernAuth" {
                Add-Event (Get-COC $Data) "WindowsHello" "Authentication" "Hello enrolled users: $($Data.UsersEnrolled)" "" "" "" "INFO"
            }
            "Office365_Exchange" {
                if ($Data.BECRiskCount -gt 0) {
                    Add-Event (Get-COC $Data) "BEC_Risk" "Exfiltration" "BEC risk: $($Data.BECRiskIndicators -join '; ')" "" "" "" "HIGH"
                }
            }
            "Email_Office_Artifacts" {
                foreach ($F2 in $Data.MacroEnabledFiles) {
                    if ($F2.LastModified) { Add-Event $F2.LastModified "MacroFile" "Execution" "Macro file: $($F2.FileName)" "" "" $F2.FullPath "MEDIUM" }
                }
            }

            #  Active Directory 
            "ActiveDirectory_DomainArtifacts" {
                Add-Event (Get-COC $Data) "ActiveDirectory" "Discovery" "AD: $($Data.DomainControllers.Count) DCs found | Domain: $($Data.DomainName)" "" "" "" "INFO"
            }
            "LAPS_Status" {
                foreach ($R in $Data.RiskFindings) {
                    Add-Event (Get-COC $Data) "LAPS" "PrivilegeEscalation" "LAPS risk: $R" "" "" "" "MEDIUM"
                }
            }

            #  System 
            "SystemInformation" {
                Add-Event (Get-COC $Data) "SystemInfo" "Collection" "System: $($Data.Data.OSName) | Uptime since: $($Data.Data.LastBootTime)" "" "" "" "INFO"
            }
            "PatchLevel" {
                if ($Data.CriticalPending -gt 0) {
                    Add-Event (Get-COC $Data) "PatchLevel" "Vulnerability" "$($Data.CriticalPending) critical patches missing" "" "" "" "HIGH"
                }
                foreach ($H in $Data.Hotfixes | Select-Object -First 10) {
                    if ($H.InstalledOn -and $H.InstalledOn -ne "") {
                        try {
                            [datetime]::Parse($H.InstalledOn) | Out-Null
                            Add-Event $H.InstalledOn "WindowsUpdate" "SystemChange" "Hotfix: $($H.HotFixID) - $($H.Description)" $H.InstalledBy "" "" "INFO"
                        } catch {}
                    }
                }
            }
            "CertificateStore" {
                foreach ($C in $Data.SuspiciousCerts) {
                    Add-Event (Get-COC $Data) "Certificate" "DefenseEvasion" "Suspicious cert: $($C.Subject)" "" "" $C.Thumbprint "HIGH"
                }
            }
            "TPM_SecureBoot_BitLocker" {
                Add-Event (Get-COC $Data) "TPM_SecureBoot" "Collection" "TPM: $($Data.TPM.TpmPresent) | SecureBoot: $($Data.SecureBoot.SecureBootEnabled) | BitLocker: $($Data.BitLockerVolumes.Count) vols" "" "" "" "INFO"
            }

            #  Memory 
            "RAMDump" {
                if ($Data.PreDumpState.CaptureStartTime) {
                    Add-Event $Data.PreDumpState.CaptureStartTime "RAMDump" "Collection" "RAM capture: $($Data.DumpResult.SizeGB) GB | SHA256: $($Data.DumpResult.SHA256)" "" "" $Data.DumpResult.DumpFile "INFO"
                }
            }
            "LoadedDLLs" {
                foreach ($D2 in $Data.SuspiciousDLLs) {
                    Add-Event (Get-COC $Data) "LoadedDLLs" "DefenseEvasion" "Suspicious DLL: $($D2.ModuleName) in $($D2.ProcessName)" "" "" $D2.FileName "HIGH"
                }
            }
            "NamedPipes" {
                foreach ($P in $Data.SuspiciousPipes) {
                    Add-Event (Get-COC $Data) "NamedPipes" "C2Detection" "C2 pipe: $($P.PipeName)" "" "" $P.DetectionReason "HIGH"
                }
            }

            #  Application 
            "SQL_Server_Artifacts" {
                foreach ($E in $Data.SuspiciousLogEntries) {
                    Add-Event (Get-COC $Data) "SQL_Server" "Execution" "SQL suspicious: $($E.MatchedKeyword)" "" "" $E.LogEntry "HIGH"
                }
            }
            "PS_Transcript_Collection" {
                foreach ($T in $Data.SuspiciousTranscripts) {
                    Add-Event $T.CreationTime "PSTranscript" "Execution" "Suspicious transcript: $($T.FileName) - $($T.SuspiciousReasons)" $T.UserName "" "" "HIGH"
                }
            }
            "ExecutionHistory" {
                Add-Event (Get-COC $Data) "SRUM" "Collection" "SRUM execution history collected" "" "" "" "INFO"
            }
            "NTDS_Location" {
                if ($Data.DCRole.IsDomainController) {
                    Add-Event (Get-COC $Data) "NTDS" "Collection" "DC detected | NTDS: $($Data.NTDSDatabase.Found) | Size: $($Data.NTDSDatabase.NTDSSizeGB)GB" "" "" $Data.NTDSDatabase.NTDSPath "INFO"
                }
            }
            "RawEventLogExport" {
                Add-Event (Get-COC $Data) "EVTX_Export" "Collection" "EVTX export: $($Data.ExportedCount) logs to $($Data.OutputDirectory)" "" "" "" "INFO"
            }
            "AutorunsPersistenceSummary" {
                foreach ($A in $Data.PersistenceEntries) {
                    if ($A.IsSuspicious) {
                        Add-Event (Get-COC $Data) "Autoruns" "Persistence" "Persistence: $($A.Location) = $($A.Value)" "" "" $A.Category "HIGH"
                    }
                }
            }

            # AI Attack Detection
            "AI_Attack_Detection" {
                $ColAT = Get-COC $Data
                foreach ($F2 in $Data.Findings) {
                    if (-not $F2) { continue }
                    try {
                        $Sev = if ($F2.Severity -eq "CRITICAL") { "CRITICAL" } elseif ($F2.Severity -eq "HIGH") { "HIGH" } else { "MEDIUM" }
                        Add-Event $ColAT "AI_Attack" $F2.Category "$($F2.Severity): $($F2.Title)" "" "" "$($F2.Detail)" $Sev
                    } catch {}
                }
                foreach ($P in $Data.AIProcesses) {
                    if (-not $P) { continue }
                    # 'if' is a statement, not an expression - it cannot be passed inline as an
                    # argument. Assign to a local first.
                    $pt = if ($P.StartTime) { $P.StartTime } else { $ColAT }
                    try { Add-Event $pt "AI_Tool" "Execution" "LLM tool running: $($P.ProcessName) PID:$($P.PID)" "" "" "$($P.Path)" "HIGH" } catch {}
                }
            }

            #  Fallback for any unhandled artifact 
            default {
                $COC = (Get-COC $Data)
                if ($COC) {
                    Add-Event $COC $AT "Collection" "Artifact collected: $AT" "" "" "" "INFO"
                }
            }
        }

        $Added = $Timeline.Count - $Pre
        if ($Added -gt 0) {
            Write-Host "    [+] Added $Added events" -ForegroundColor Green
        }

    } catch {
        Write-Log "Error processing $($F.Name): $_" "WARN"
    }
}

$Sorted = @($Timeline | Sort-Object DateTime)
Write-Host ""
Write-Host "[+] Total timeline events: $($Sorted.Count)" -ForegroundColor $(if($Sorted.Count -gt 0){"Green"}else{"Yellow"})
Write-Log "Timeline events: $($Sorted.Count)"

#  HTML REPORT 
Write-Host "[*] Generating HTML timeline..." -ForegroundColor Cyan

$SevColors = @{
    "CRITICAL" = "dc2626"
    "HIGH"     = "ea580c"
    "MEDIUM"   = "d97706"
    "LOW"      = "65a30d"
    "INFO"     = "3b82f6"
}
$CatColors = @{
    "Authentication"="3b82f6"; "ProcessExecution"="10b981"; "C2Detection"="7c3aed"
    "Persistence"="f59e0b"; "CredentialAccess"="ec4899"; "DefenseEvasion"="6b7280"
    "LateralMovement"="0ea5e9"; "Exfiltration"="f97316"; "Execution"="22c55e"
    "Malware"="dc2626"; "UserActivity"="84cc16"; "NetworkActivity"="06b6d4"
    "InitialAccess"="ef4444"; "Impact"="991b1b"; "Discovery"="78716c"
    "Collection"="94a3b8"; "SystemChange"="eab308"; "Backup"="22d3ee"
    "DeviceConnection"="14b8a6"; "FileSystem"="64748b"; "ApplicationCrash"="f43f5e"
    "SuspiciousExecution"="b91c1c"; "PrivilegeEscalation"="f87171"; "Vulnerability"="fbbf24"
}

# HTML-encode evidence-derived strings so attacker-controlled artifact content (command
# lines, script text, paths) cannot break the table or inject markup into the analyst's browser.
function HtmlEnc { param($s) if ($null -eq $s) { return "" } [System.Net.WebUtility]::HtmlEncode([string]$s) }

$EventRows = foreach ($E in $Sorted) {
    $SC = if ($SevColors[$E.Severity]) { $SevColors[$E.Severity] } else { "94a3b8" }
    $CC = if ($CatColors[$E.Category]) { $CatColors[$E.Category] } else { "64748b" }
    "<tr>
        <td style='white-space:nowrap;font-family:monospace;font-size:11px;padding:6px 10px'>$($E.DateTimeUTC)</td>
        <td style='padding:6px 10px'><span style='background:#$SC;color:white;padding:1px 6px;border-radius:10px;font-size:9px;font-weight:600'>$(HtmlEnc $E.Severity)</span></td>
        <td style='padding:6px 10px'><span style='background:#$CC;color:white;padding:1px 6px;border-radius:3px;font-size:10px'>$(HtmlEnc $E.Category)</span></td>
        <td style='font-size:11px;padding:6px 10px'>$(HtmlEnc $E.Source)</td>
        <td style='font-size:11px;padding:6px 10px'>$(HtmlEnc $E.Description)</td>
        <td style='font-size:11px;padding:6px 10px;color:#4b5563'>$(HtmlEnc $E.User)</td>
        <td style='font-size:10px;padding:6px 10px;color:#9ca3af;max-width:200px;overflow:hidden'>$(HtmlEnc $E.Detail)</td>
    </tr>"
}

# Stats
$CritCount = @($Sorted | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$HighCount = @($Sorted | Where-Object { $_.Severity -eq "HIGH" }).Count
$TopCats   = @($Sorted | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 5)
$TopSources= @($Sorted | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 5)
$FirstEvent= if ($Sorted.Count -gt 0) { $Sorted[0].DateTimeUTC } else { "N/A" }
$LastEvent = if ($Sorted.Count -gt 0) { $Sorted[-1].DateTimeUTC } else { "N/A" }

$TopCatRows = ($TopCats | ForEach-Object { "<tr><td style='padding:4px 10px;font-size:12px'>$($_.Name)</td><td style='padding:4px 10px;font-size:12px;font-weight:600'>$($_.Count)</td></tr>" }) -join ""

$HTML = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>DFIR Timeline - $Hostname - $CaseNum</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc}
.header{background:linear-gradient(135deg,#1e3a5f,#1d4ed8);color:white;padding:20px 30px}
.header h1{font-size:20px;font-weight:700}
.header p{font-size:12px;opacity:.8;margin-top:4px}
.stats{display:flex;gap:12px;padding:16px 30px;background:white;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}
.stat{background:#f1f5f9;padding:10px 16px;border-radius:6px;text-align:center;min-width:90px}
.stat strong{display:block;font-size:22px;font-weight:700}
.stat span{font-size:10px;color:#64748b}
.toolbar{padding:10px 30px;background:white;border-bottom:1px solid #e2e8f0;display:flex;gap:10px;flex-wrap:wrap}
.toolbar input{padding:6px 12px;border:1px solid #d1d5db;border-radius:4px;font-size:12px;flex:1;min-width:200px}
.toolbar select{padding:6px 10px;border:1px solid #d1d5db;border-radius:4px;font-size:12px}
.table-wrap{overflow-x:auto;padding:0 15px 30px}
table{width:100%;border-collapse:collapse}
th{background:#1e3a5f;color:white;padding:8px 10px;text-align:left;font-size:11px;position:sticky;top:0;z-index:1}
tr:nth-child(even){background:#f9fafb}
tr:hover{background:#eff6ff!important}
td{border-bottom:1px solid #f1f5f9;vertical-align:top}
.summary{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 30px}
.summary-card{background:white;border-radius:8px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.07)}
.summary-card h3{font-size:13px;font-weight:600;color:#1e3a5f;margin-bottom:10px}
.summary-card table{font-size:12px}
</style>
</head><body>
<div class="header">
<h1>DFIR Forensic Timeline</h1>
<p>Case: $(HtmlEnc $CaseNum) | Host: $(HtmlEnc $Hostname) | Investigator: $(HtmlEnc $Investigator) | Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC</p>
</div>
<div class="stats">
<div class="stat"><strong>$($Sorted.Count)</strong><span>Total Events</span></div>
<div class="stat"><strong style="color:#dc2626">$CritCount</strong><span>Critical</span></div>
<div class="stat"><strong style="color:#ea580c">$HighCount</strong><span>High</span></div>
<div class="stat"><strong>$($EvidenceFiles.Count)</strong><span>Artifacts</span></div>
<div class="stat"><strong style="font-size:13px">$FirstEvent</strong><span>First Event</span></div>
<div class="stat"><strong style="font-size:13px">$LastEvent</strong><span>Last Event</span></div>
</div>
<div class="summary">
<div class="summary-card"><h3>Top Event Categories</h3><table>$TopCatRows</table></div>
<div class="summary-card"><h3>Evidence Sources</h3><table>$(($TopSources | ForEach-Object {"<tr><td style='padding:4px 10px;font-size:12px'>$($_.Name)</td><td style='padding:4px 10px;font-size:12px;font-weight:600'>$($_.Count)</td></tr>"}) -join "")</table></div>
</div>
<div class="toolbar">
<input type="text" id="search" placeholder="Search timeline (IP, process name, username, event...)" oninput="filterTable()">
<select id="sevFilter" onchange="filterTable()">
<option value="">All Severities</option>
<option value="CRITICAL">CRITICAL</option>
<option value="HIGH">HIGH</option>
<option value="MEDIUM">MEDIUM</option>
<option value="INFO">INFO</option>
</select>
<select id="catFilter" onchange="filterTable()">
<option value="">All Categories</option>
$(($Sorted | Select-Object -ExpandProperty Category -Unique | Sort-Object | ForEach-Object { "<option value='$(HtmlEnc $_)'>$(HtmlEnc $_)</option>" }) -join "")
</select>
</div>
<div class="table-wrap">
<table id="tbl">
<thead><tr><th>Date/Time UTC</th><th>Severity</th><th>Category</th><th>Source</th><th>Description</th><th>User</th><th>Detail</th></tr></thead>
<tbody id="tbody">$($EventRows -join "")</tbody>
</table>
</div>
<script>
function filterTable() {
    var q = document.getElementById('search').value.toLowerCase();
    var sev = document.getElementById('sevFilter').value;
    var cat = document.getElementById('catFilter').value;
    var rows = document.getElementById('tbody').rows;
    var vis = 0;
    for (var r of rows) {
        var txt = r.textContent.toLowerCase();
        var sevOk = !sev || r.cells[1].textContent.includes(sev);
        var catOk = !cat || r.cells[2].textContent.includes(cat);
        var show = txt.includes(q) && sevOk && catOk;
        r.style.display = show ? '' : 'none';
        if (show) vis++;
    }
}
</script>
</body></html>
"@

$HTML | Out-File $HTMLFile -Encoding UTF8 -Force
$Sorted | Export-Csv $CSVFile -NoTypeInformation -Encoding UTF8

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType    = "ForensicTimeline"
    TotalEvents     = $Sorted.Count
    CriticalEvents  = $CritCount
    HighEvents      = $HighCount
    HTMLReport      = $HTMLFile
    CSVExport       = $CSVFile
    TopCategories   = @($Sorted | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [PSCustomObject]@{ Category=$_.Name; Count=$_.Count } })
    TopSources      = @($Sorted | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [PSCustomObject]@{ Source=$_.Name; Count=$_.Count } })
}
$Evidence | ConvertTo-Json -Depth 5 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Timeline complete | Events: $($Sorted.Count) | Critical: $CritCount | High: $HighCount" -ForegroundColor Green
Write-Host "[+] HTML: $HTMLFile" -ForegroundColor Green
Write-Host "[+] CSV : $CSVFile" -ForegroundColor Green
Write-Log "Completed | Events: $($Sorted.Count) Critical: $CritCount High: $HighCount"
