#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Kerberoasting_Execution.log"
$JsonFile = "$BasePath\Kerberoasting_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Kerberoasting evidence collection started | Case: $CaseNum"

$DaysBack  = if ($env:DFIR_DAYS) { [int]$env:DFIR_DAYS } else { 30 }
$SinceDate = (Get-Date).AddDays(-$DaysBack)

# Check domain membership
$IsDomain = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
Write-Log "Domain joined: $IsDomain"

# Event 4769 - Kerberos TGS requests (Kerberoasting indicator)
Write-Host "[*] Collecting Kerberos TGS request events (4769)..." -ForegroundColor Cyan
$TGSEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$KerberoastCandidates = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $Filter = @{ LogName="Security"; Id=4769; StartTime=$SinceDate }
    $Events  = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    Write-Host "[*] Processing $($Events.Count) TGS events..." -ForegroundColor Cyan

    foreach ($E in $Events) {
        $Msg         = $E.Message
        $ServiceName = if ($Msg -match "Service Name:\s*(\S+)") { $Matches[1] } else { $null }
        $ServiceID   = if ($Msg -match "Service ID:\s*(\S+)") { $Matches[1] } else { $null }
        $AccountName = if ($Msg -match "Account Name:\s*(\S+)@") { $Matches[1] } else { $null }
        $ClientAddr  = if ($Msg -match "Client Address:\s*::ffff:(\S+)") { $Matches[1] } elseif ($Msg -match "Client Address:\s*(\S+)") { $Matches[1] } else { $null }
        $TicketEnc   = if ($Msg -match "Ticket Encryption Type:\s*(\S+)") { $Matches[1] } else { $null }
        $FailCode    = if ($Msg -match "Failure Code:\s*(\S+)") { $Matches[1] } else { $null }

        # RC4 (0x17) encryption = Kerberoasting indicator
        $IsRC4       = ($TicketEnc -eq "0x17")
        # Skip computer accounts and krbtgt
        $IsUserAcct  = ($ServiceName -and $ServiceName -notmatch "krbtgt|\$$" -and $ServiceID -notmatch "\$$")

        if ($IsRC4 -and $IsUserAcct -and $FailCode -eq "0x0") {
            $KerberoastCandidates.Add([PSCustomObject]@{
                TimeCreated     = $E.TimeCreated.ToString("o")
                ServiceName     = $ServiceName
                ServiceID       = $ServiceID
                RequestedBy     = $AccountName
                ClientAddress   = $ClientAddr
                EncryptionType  = $TicketEnc
                EncryptionName  = "RC4-HMAC (Kerberoastable)"
                RiskLevel       = "HIGH"
                Note            = "RC4 TGS for non-computer account - strong Kerberoasting indicator"
            })
        }

        $TGSEvents.Add([PSCustomObject]@{
            TimeCreated    = $E.TimeCreated.ToString("o")
            ServiceName    = $ServiceName
            AccountName    = $AccountName
            ClientAddress  = $ClientAddr
            EncryptionType = $TicketEnc
            FailureCode    = $FailCode
            IsRC4          = $IsRC4
            IsUserAccount  = $IsUserAcct
        })
    }
    Write-Log "TGS events: $($TGSEvents.Count) | Kerberoast candidates: $($KerberoastCandidates.Count)"
} catch { Write-Log "TGS event query failed: $_" "WARN" }

# Volume-based detection - multiple TGS requests from same source = Kerberoasting tool
Write-Host "[*] Analyzing TGS request patterns..." -ForegroundColor Cyan
$BurstRequests = [System.Collections.Generic.List[PSCustomObject]]::new()
$RC4Events     = @($TGSEvents | Where-Object { $_.IsRC4 -and $_.IsUserAccount })
if ($RC4Events.Count -gt 0) {
    $RC4Events | Group-Object ClientAddress | Where-Object { $_.Count -ge 5 } | ForEach-Object {
        $BurstRequests.Add([PSCustomObject]@{
            ClientAddress  = $_.Name
            RC4RequestCount= $_.Count
            FirstSeen      = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastSeen       = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
            Services       = @($_.Group | Select-Object -ExpandProperty ServiceName -Unique)
            RiskLevel      = "CRITICAL"
            Note           = "High-volume RC4 TGS requests from single source - Kerberoasting tool signature"
        })
    }
}

# SPN enumeration from local Kerberos ticket cache
Write-Host "[*] Enumerating SPNs from local Kerberos cache..." -ForegroundColor Cyan
$SPNData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $KListOut = (klist tickets 2>&1) -join "`n"
    if ($KListOut -notmatch "No tickets") {
        $Tickets = $KListOut -split "#\d+"
        foreach ($T in $Tickets) {
            if ($T -match "Server:\s*(\S+)") {
                $ServerName = $Matches[1]
                $EncType    = if ($T -match "EncryptionType:\s*(.+?)(\r|\n)") { $Matches[1].Trim() } else { $null }
                $EndTime    = if ($T -match "EndTime:\s*(.+?)(\r|\n)") { $Matches[1].Trim() } else { $null }
                $SPNData.Add([PSCustomObject]@{
                    ServerSPN      = $ServerName
                    EncryptionType = $EncType
                    EndTime        = $EndTime
                    IsRC4          = ($EncType -match "RC4|ARCFOUR|0x17")
                })
            }
        }
    }
    Write-Log "Local Kerberos tickets: $($SPNData.Count)"
} catch { Write-Log "klist failed: $_" "WARN" }

# AS-REP Roasting check - event 4768 with no pre-auth
Write-Host "[*] Checking for AS-REP Roasting indicators (4768)..." -ForegroundColor Cyan
$ASREPEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter2  = @{ LogName="Security"; Id=4768; StartTime=$SinceDate }
    $ASEvents = @(Get-WinEvent -FilterHashtable $Filter2 -ErrorAction SilentlyContinue)
    foreach ($E in $ASEvents) {
        $Msg      = $E.Message
        $PreAuth  = if ($Msg -match "Pre-Authentication Type:\s*(\S+)") { $Matches[1] } else { $null }
        $AcctName = if ($Msg -match "Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $EncType  = if ($Msg -match "Ticket Encryption Type:\s*(\S+)") { $Matches[1] } else { $null }
        $ClientIP = if ($Msg -match "Client Address:\s*::ffff:(\S+)") { $Matches[1] } elseif ($Msg -match "Client Address:\s*(\S+)") { $Matches[1] } else { $null }
        # Pre-auth type 0 = no pre-authentication required = AS-REP Roastable
        if ($PreAuth -eq "0") {
            $ASREPEvents.Add([PSCustomObject]@{
                TimeCreated    = $E.TimeCreated.ToString("o")
                AccountName    = $AcctName
                ClientAddress  = $ClientIP
                EncryptionType = $EncType
                PreAuthType    = $PreAuth
                RiskLevel      = "HIGH"
                Note           = "AS-REP Roastable account - no pre-authentication required"
            })
        }
    }
    Write-Log "AS-REP Roasting candidates: $($ASREPEvents.Count)"
} catch { Write-Log "4768 event query failed: $_" "WARN" }

# AD module SPN enumeration (if available)
Write-Host "[*] Attempting SPN enumeration via AD module..." -ForegroundColor Cyan
$ADSPNAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $SPNUsers = @(Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
            -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate,Enabled `
            -ErrorAction SilentlyContinue)
        foreach ($U in $SPNUsers) {
            $PasswordAge = if ($U.PasswordLastSet) { [math]::Round(((Get-Date) - $U.PasswordLastSet).TotalDays) } else { $null }
            $ADSPNAccounts.Add([PSCustomObject]@{
                SamAccountName    = $U.SamAccountName
                Enabled           = $U.Enabled
                SPNs              = $U.ServicePrincipalName
                PasswordLastSet   = if ($U.PasswordLastSet) { $U.PasswordLastSet.ToString("o") } else { $null }
                PasswordAgeDays   = $PasswordAge
                LastLogon         = if ($U.LastLogonDate) { $U.LastLogonDate.ToString("o") } else { $null }
                IsHighRisk        = ($PasswordAge -gt 365 -or $null -eq $PasswordAge)
            })
        }
        Write-Log "AD SPN accounts: $($ADSPNAccounts.Count)"
    } else {
        Write-Log "ActiveDirectory module not available - skipping AD SPN enumeration" "WARN"
        Write-Host "[!] AD module not available - SPN enumeration limited to event log analysis" -ForegroundColor Yellow
    }
} catch { Write-Log "AD SPN enumeration failed: $_" "WARN" }

$TotalRisk = $KerberoastCandidates.Count + $BurstRequests.Count + $ASREPEvents.Count
Write-Log "Kerberoast candidates: $($KerberoastCandidates.Count) | Burst: $($BurstRequests.Count) | ASREP: $($ASREPEvents.Count) | AD SPNs: $($ADSPNAccounts.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody          = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType            = "Kerberoasting_Evidence"
    IsDomainJoined          = $IsDomain
    TGSEventCount           = $TGSEvents.Count
    KerberoastCandidateCount= $KerberoastCandidates.Count
    BurstRequestCount       = $BurstRequests.Count
    ASREPRoastCount         = $ASREPEvents.Count
    ADSPNAccountCount       = $ADSPNAccounts.Count
    TotalRiskIndicators     = $TotalRisk
    KerberoastCandidates    = $KerberoastCandidates
    BurstRequests           = $BurstRequests
    ASREPRoastingCandidates = $ASREPEvents
    LocalKerberosTickets    = $SPNData
    ADSPNAccounts           = $ADSPNAccounts
    MITREReference          = "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Kerberoasting evidence collected | TGS Events: $($TGSEvents.Count) | Candidates: $($KerberoastCandidates.Count) | Burst: $($BurstRequests.Count) | ASREP: $($ASREPEvents.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
