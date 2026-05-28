#Requires -Version 5.1
<#
.SYNOPSIS
    Collects credential-related artifacts for DFIR investigations.

.DESCRIPTION
    Enumerates Windows Credential Manager vaults, Kerberos ticket cache,
    LSASS protection state, SAM/LSA protection settings, DPAPI master key
    locations, and credential-related registry settings.

.IR_PHASE
    Credential Access / Privilege Escalation

.MITRE_ATTCK
    T1003     - OS Credential Dumping
    T1555.004 - Windows Credential Manager
    T1558     - Steal or Forge Kerberos Tickets
    T1552     - Unsecured Credentials

.FORENSIC_SAFETY
    Read-only - does NOT dump credentials or hashes

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
$LogFile  = "$BasePath\Credential_Artifacts_Execution.log"
$JsonFile = "$BasePath\Credential_Artifacts_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Credential artifact collection started"

# -- Windows Credential Manager -------------------------------------------------
Write-Host "[*] Enumerating Windows Credential Manager..." -ForegroundColor Cyan
$CredMgrData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    # Use cmdkey to list stored credentials (metadata only, no passwords)
    $CmdkeyOut = (cmdkey /list 2>&1) -join "`n"
    $Entries = $CmdkeyOut -split "(?=Target:)" | Where-Object { $_ -match "Target:" }
    foreach ($Entry in $Entries) {
        $Target = if ($Entry -match "Target:\s*(.+)") { $Matches[1].Trim() } else { "Unknown" }
        $Type   = if ($Entry -match "Type:\s*(.+)")   { $Matches[1].Trim() } else { "Unknown" }
        $User   = if ($Entry -match "User:\s*(.+)")   { $Matches[1].Trim() } else { "Unknown" }
        $CredMgrData.Add([PSCustomObject]@{
            Target = $Target; Type = $Type; User = $User
            Note   = "Password not collected - metadata only"
        })
    }
    Write-Log "Credential Manager entries: $($CredMgrData.Count)"
} catch { Write-Log "Credential Manager error: $_" "WARN" }

# -- Kerberos Tickets ------------------------------------------------------------
Write-Host "[*] Enumerating Kerberos tickets..." -ForegroundColor Cyan
$KerbData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $KlistOut = (klist 2>&1)
    $TicketBlocks = ($KlistOut -join "`n") -split "(?=#\d+>)" | Where-Object { $_ -match "Client:" }
    foreach ($Block in $TicketBlocks) {
        $KerbData.Add([PSCustomObject]@{
            Client      = if ($Block -match "Client:\s*(.+)") { $Matches[1].Trim() } else { $null }
            Server      = if ($Block -match "Server:\s*(.+)") { $Matches[1].Trim() } else { $null }
            KerbTicket  = if ($Block -match "KerbTicket Encryption Type:\s*(.+)") { $Matches[1].Trim() } else { $null }
            TicketFlags = if ($Block -match "Ticket Flags\s*(.+)") { $Matches[1].Trim() } else { $null }
            StartTime   = if ($Block -match "Start Time:\s*(.+)") { $Matches[1].Trim() } else { $null }
            EndTime     = if ($Block -match "End Time:\s*(.+)")   { $Matches[1].Trim() } else { $null }
            RenewTime   = if ($Block -match "Renew Time:\s*(.+)") { $Matches[1].Trim() } else { $null }
        })
    }
    Write-Log "Kerberos tickets: $($KerbData.Count)"
} catch { Write-Log "Kerberos error: $_" "WARN" }

# -- LSASS Protection ----------------------------------------------------------
Write-Host "[*] Checking LSASS protection settings..." -ForegroundColor Cyan
$LSASSProtection = [PSCustomObject]@{
    RunAsPPL          = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL
    LsaCfgFlags       = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags
    DisableRestrictedAdmin = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).DisableRestrictedAdmin
    TokenLeakDetectDelaySecs = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).TokenLeakDetectDelaySecs
    NoLMHash          = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).NoLMHash
    LmCompatibilityLevel = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    # Check if credential guard is enabled
    CredentialGuard   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    WDigestEnabled    = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential
    Note_WDigest      = "If WDigestEnabled=1, plaintext credentials stored in LSASS memory (critical finding)"
}
Write-Log "LSASS protection settings collected"

# -- LSA Authentication Packages -----------------------------------------------
Write-Host "[*] Checking LSA authentication packages..." -ForegroundColor Cyan
$LSAKey = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
$LSAConfig = [PSCustomObject]@{
    AuthenticationPackages     = $LSAKey.Authentication_Packages
    SecurityPackages           = $LSAKey.Security_Packages
    NotificationPackages       = $LSAKey.Notification_Packages
    LimitBlankPasswordUse      = $LSAKey.LimitBlankPasswordUse
    Note = "Non-standard packages here indicate potential credential theft backdoor"
}

# -- DPAPI Master Keys ---------------------------------------------------------
Write-Host "[*] Locating DPAPI master key files..." -ForegroundColor Cyan
$DPAPIKeys = [System.Collections.Generic.List[PSCustomObject]]::new()
$DPAPIPaths = @(
    "$env:APPDATA\Microsoft\Protect",
    "C:\Windows\System32\Microsoft\Protect",
    "C:\Windows\SysWOW64\Microsoft\Protect"
)
foreach ($DPath in $DPAPIPaths) {
    if (Test-Path $DPath) {
        Get-ChildItem $DPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $DPAPIKeys.Add([PSCustomObject]@{
                Path          = $_.FullName
                LastWriteTime = $_.LastWriteTimeUtc.ToString("o")
                SizeBytes     = $_.Length
            })
        }
    }
}
Write-Log "DPAPI key files: $($DPAPIKeys.Count)"

# -- Autologon Credentials -----------------------------------------------------
Write-Host "[*] Checking autologon configuration..." -ForegroundColor Cyan
$WinlogonKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
$AutoLogon = [PSCustomObject]@{
    AutoAdminLogon    = $WinlogonKey.AutoAdminLogon
    DefaultUserName   = $WinlogonKey.DefaultUserName
    DefaultDomainName = $WinlogonKey.DefaultDomainName
    DefaultPassword   = if ($WinlogonKey.DefaultPassword) { "[PRESENT - CLEARTEXT]" } else { $null }
    Note              = if ($WinlogonKey.DefaultPassword) { "CRITICAL: Autologon password stored in plaintext registry" } else { "No autologon password found" }
}
Write-Log "Autologon check complete"

$Evidence = [PSCustomObject]@{
    ChainOfCustody    = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType      = "CredentialArtifacts"
    LSASSProtection   = $LSASSProtection
    LSAConfig         = $LSAConfig
    AutoLogon         = $AutoLogon
    CredentialManager = $CredMgrData
    KerberosTickets   = $KerbData
    DPAPIKeyFiles     = $DPAPIKeys
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Credential artifacts collected | CredMgr: $($CredMgrData.Count) | Kerberos: $($KerbData.Count) | DPAPI Keys: $($DPAPIKeys.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
