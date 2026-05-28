#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\DCSync_Execution.log"
$JsonFile = "$BasePath\DCSync_Detection_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "DCSync detection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

$IsDC      = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType -eq 2
$IsDomain  = (Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue).PartOfDomain
Write-Log "IsDC: $IsDC | IsDomain: $IsDomain"

if (-not $IsDomain) {
    Write-Host "[!] Machine is not domain-joined. DCSync detection limited to local event log analysis." -ForegroundColor Yellow
    Write-Log "Non-domain machine - limited DCSync detection available"
}

# Event 4662 - Object access with replication rights
# DCSync = access to DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
Write-Host "[*] Collecting replication access events (4662)..." -ForegroundColor Cyan
$ReplicationEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$DCSyncCandidates  = [System.Collections.Generic.List[PSCustomObject]]::new()

# DCSync GUID identifiers
$ReplicationGUIDs = @{
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Synchronize"
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Manage-Topology"
    "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
}

try {
    $Filter  = @{ LogName="Security"; Id=4662; StartTime=$SinceDate }
    $Events  = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    Write-Host "[*] Processing $($Events.Count) object access events (4662)..." -ForegroundColor Cyan

    foreach ($E in $Events) {
        $Msg        = $E.Message
        $SubjectUser= if ($Msg -match "Subject:[\s\S]*?Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $SubjectDom = if ($Msg -match "Subject:[\s\S]*?Account Domain:\s*(\S+)") { $Matches[1] } else { $null }
        $ObjectDN   = if ($Msg -match "Object Name:\s*(.+?)(\r|\n)") { $Matches[1].Trim() } else { $null }
        $AccProps   = if ($Msg -match "Properties:\s*([\s\S]*?)(?=Additional|$)") { $Matches[1] } else { "" }
        $AccessMask = if ($Msg -match "Access Mask:\s*(\S+)") { $Matches[1] } else { $null }

        # Check for replication GUIDs in access properties
        $MatchedGUIDs = @()
        foreach ($GUID in $ReplicationGUIDs.Keys) {
            if ($AccProps -match $GUID -or $Msg -match $GUID) {
                $MatchedGUIDs += $ReplicationGUIDs[$GUID]
            }
        }

        # Skip computer accounts and MSOL/AAD sync accounts (legitimate replication)
        $IsLegitimate = ($SubjectUser -match "\$$" -or $SubjectUser -match "^MSOL_|^AADConnect|^AAD_|^AzureAD" -or $SubjectUser -match "^krbtgt")

        if ($MatchedGUIDs.Count -gt 0) {
            $ReplicationEvent = [PSCustomObject]@{
                TimeCreated      = $E.TimeCreated.ToString("o")
                EventID          = $E.Id
                SubjectAccount   = "$SubjectDom\$SubjectUser"
                ObjectDN         = $ObjectDN
                AccessMask       = $AccessMask
                MatchedGUIDs     = $MatchedGUIDs
                IsLegitimate     = $IsLegitimate
                RiskLevel        = if ($IsLegitimate) { "LOW" } else { "CRITICAL" }
                Note             = if ($IsLegitimate) { "Legitimate replication account" } else { "Non-DC account with replication access - potential DCSync" }
            }
            $ReplicationEvents.Add($ReplicationEvent)
            if (-not $IsLegitimate) { $DCSyncCandidates.Add($ReplicationEvent) }
        }
    }
    Write-Log "4662 events: $($Events.Count) | Replication events: $($ReplicationEvents.Count) | DCSync candidates: $($DCSyncCandidates.Count)"
} catch { Write-Log "4662 event query failed: $_" "WARN" }

# Event 4742/4738 - Computer/User account changes (post-DCSync persistence)
Write-Host "[*] Checking for post-DCSync account changes..." -ForegroundColor Cyan
$PostDCSyncChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter2 = @{ LogName="Security"; Id=@(4738,4742,4720,4728,4732,4756); StartTime=$SinceDate }
    $ChgEvents = @(Get-WinEvent -FilterHashtable $Filter2 -ErrorAction SilentlyContinue)
    foreach ($E in $ChgEvents) {
        $Msg      = $E.Message
        $Target   = if ($Msg -match "Target Account:[\s\S]*?Account Name:\s*(\S+)") { $Matches[1] } elseif ($Msg -match "Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $SubjUser = if ($Msg -match "Subject:[\s\S]*?Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $PostDCSyncChanges.Add([PSCustomObject]@{
            TimeCreated  = $E.TimeCreated.ToString("o")
            EventID      = $E.Id
            EventType    = switch ($E.Id) { 4720{"Account Created"} 4738{"Account Changed"} 4742{"Computer Changed"} 4728{"Added to Global Group"} 4732{"Added to Local Group"} 4756{"Added to Universal Group"} default{"Unknown"} }
            TargetAccount= $Target
            PerformedBy  = $SubjUser
        })
    }
    Write-Log "Post-DCSync account change events: $($PostDCSyncChanges.Count)"
} catch { Write-Log "Account change events failed: $_" "WARN" }

# Mimikatz DCSync pattern in PowerShell event log
Write-Host "[*] Scanning PowerShell logs for DCSync tool signatures..." -ForegroundColor Cyan
$PSToolSignatures = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $PSFilter = @{ LogName="Microsoft-Windows-PowerShell/Operational"; Id=4104; StartTime=$SinceDate }
    $PSEvents = @(Get-WinEvent -FilterHashtable $PSFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "dcsync|Invoke-Mimikatz|lsadump::dcsync|Get-DomainUser.*SPN|DCSync|Replication" })
    foreach ($E in $PSEvents) {
        $PSToolSignatures.Add([PSCustomObject]@{
            TimeCreated = $E.TimeCreated.ToString("o")
            EventID     = $E.Id
            ScriptText  = ($E.Message -replace "\r?\n"," ").Substring(0,[Math]::Min(300,$E.Message.Length))
            RiskLevel   = "CRITICAL"
        })
    }
    Write-Log "DCSync PS signatures: $($PSToolSignatures.Count)"
} catch { Write-Log "PS log scan failed: $_" "WARN" }

# AD Replication permissions check (if AD module available)
Write-Host "[*] Checking AD replication permissions..." -ForegroundColor Cyan
$ReplicationPermissions = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    if ((Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) -and $IsDomain) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $DomainDN = (Get-ADDomain -ErrorAction SilentlyContinue).DistinguishedName
        if ($DomainDN) {
            $ACL = Get-ACL "AD:\$DomainDN" -ErrorAction SilentlyContinue
            if ($ACL) {
                $ACL.Access | Where-Object {
                    $_.ObjectType -in @(
                        [guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
                        [guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
                    ) -and $_.AccessControlType -eq "Allow"
                } | ForEach-Object {
                    $Principal = $_.IdentityReference.ToString()
                    $IsExpected = ($Principal -match "Domain Controllers|Enterprise Domain Controllers|Administrators|SYSTEM|ENTERPRISE")
                    $ReplicationPermissions.Add([PSCustomObject]@{
                        Principal       = $Principal
                        AccessType      = $_.AccessControlType.ToString()
                        Rights          = $_.ActiveDirectoryRights.ToString()
                        ObjectType      = $_.ObjectType.ToString()
                        RightName       = if ($ReplicationGUIDs[$_.ObjectType.ToString()]) { $ReplicationGUIDs[$_.ObjectType.ToString()] } else { "Unknown" }
                        IsExpected      = $IsExpected
                        RiskLevel       = if ($IsExpected) { "LOW" } else { "CRITICAL" }
                    })
                }
                Write-Log "Replication permissions found: $($ReplicationPermissions.Count)"
            }
        }
    } else {
        Write-Log "AD module not available or not domain-joined" "WARN"
    }
} catch { Write-Log "AD ACL check failed: $_" "WARN" }

$UnexpectedPerms  = @($ReplicationPermissions | Where-Object { -not $_.IsExpected }).Count
$TotalRisk = $DCSyncCandidates.Count + $PSToolSignatures.Count + $UnexpectedPerms
Write-Log "DCSync candidates: $($DCSyncCandidates.Count) | PS signatures: $($PSToolSignatures.Count) | Unexpected perms: $UnexpectedPerms"

$Evidence = [PSCustomObject]@{
    ChainOfCustody            = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType              = "DCSync_Detection"
    IsDomainController        = $IsDC
    IsDomainJoined            = $IsDomain
    TotalRiskIndicators       = $TotalRisk
    ReplicationEventCount     = $ReplicationEvents.Count
    DCSyncCandidateCount      = $DCSyncCandidates.Count
    UnexpectedPermCount       = $UnexpectedPerms
    PSToolSignatureCount      = $PSToolSignatures.Count
    DCSyncCandidates          = $DCSyncCandidates
    AllReplicationEvents      = $ReplicationEvents
    PostDCSyncAccountChanges  = $PostDCSyncChanges
    PSToolSignatures          = $PSToolSignatures
    ReplicationPermissions    = $ReplicationPermissions
    MITREReference            = "T1003.006 - OS Credential Dumping: DCSync"
    ForensicNote              = "DCSync allows non-DC accounts to replicate domain credentials. Requires DS-Replication-Get-Changes-All permission."
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

$RiskColor = if ($TotalRisk -gt 0) { "Red" } else { "Green" }
Write-Host "[+] DCSync detection complete | Candidates: $($DCSyncCandidates.Count) | PS Signatures: $($PSToolSignatures.Count) | Unexpected Perms: $UnexpectedPerms" -ForegroundColor $RiskColor
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
