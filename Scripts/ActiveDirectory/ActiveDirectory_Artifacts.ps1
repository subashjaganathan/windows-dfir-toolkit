#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Active Directory artifacts from domain-joined machines.

.DESCRIPTION
    Enumerates domain membership details, applied GPOs, domain
    trusts, domain user sessions, Kerberos configuration, LDAP
    settings, and domain controller connectivity. Runs on any
    domain-joined Windows machine without requiring AD module.

.COMPATIBILITY
    Windows 10 1607+  : Full (domain-joined)
    Windows 11        : Full (domain-joined)
    Server 2016+      : Full
    Standalone        : Partial (domain queries will fail gracefully)

.IR_PHASE
    Privilege Escalation / Lateral Movement / Investigation

.MITRE_ATTCK
    T1484 - Domain Policy Modification
    T1069 - Permission Groups Discovery
    T1087 - Account Discovery
    T1135 - Network Share Discovery

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
$LogFile  = "$BasePath\ActiveDirectory_Execution.log"
$JsonFile = "$BasePath\ActiveDirectory_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Active Directory artifact collection started | Case: $CaseNum"

# -- Domain Membership Check ---------------------------------------------------
Write-Host "[*] Checking domain membership..." -ForegroundColor Cyan
$CS = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$IsDomainJoined = $CS.PartOfDomain
$DomainName     = $CS.Domain

$DomainInfo = [PSCustomObject]@{
    IsDomainJoined    = $IsDomainJoined
    DomainName        = $DomainName
    DomainRole        = switch ($CS.DomainRole) {
        0 {"StandaloneWorkstation"} 1 {"MemberWorkstation"} 2 {"StandaloneServer"}
        3 {"MemberServer"} 4 {"BackupDomainController"} 5 {"PrimaryDomainController"}
        default {"Unknown"}
    }
    LoggedOnUser      = $env:USERNAME
    LoggedOnDomain    = $env:USERDOMAIN
}
Write-Log "Domain joined: $IsDomainJoined | Domain: $DomainName"

if (-not $IsDomainJoined) {
    Write-Warning "[!] Machine is not domain-joined. AD artifact collection will be limited."
    Write-Log "Not domain-joined - skipping most AD checks" "WARN"
}

# -- Domain Controller Info ----------------------------------------------------
Write-Host "[*] Locating domain controllers..." -ForegroundColor Cyan
$DCInfo = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $NLTest = (nltest /dclist:$DomainName 2>&1) -join "`n"
    $DCLines = $NLTest -split "`n" | Where-Object { $_ -match "\\\\" }
    foreach ($DCLine in $DCLines) {
        $DCName = $DCLine.Trim() -replace "\\\\",""
        if ($DCName) {
            $DCInfo.Add([PSCustomObject]@{
                DCName    = $DCName
                Domain    = $DomainName
                Reachable = (Test-Connection $DCName -Count 1 -Quiet -ErrorAction SilentlyContinue)
            })
        }
    }
    Write-Log "Domain controllers found: $($DCInfo.Count)"
} catch {
    Write-Log "DC enumeration failed: $_" "WARN"
}

# -- Applied Group Policies ----------------------------------------------------
Write-Host "[*] Collecting applied Group Policy information..." -ForegroundColor Cyan
$GPOData = [PSCustomObject]@{}
try {
    $GPResult = (gpresult /r /scope computer 2>&1) -join "`n"
    $GPOData = [PSCustomObject]@{
        RawOutput        = ($GPResult -split "`n" | Select-Object -First 100) -join "`n"
        AppliedGPOs      = @($GPResult -split "`n" | Where-Object { $_ -match "^\s{4}\w" -and $_ -notmatch "^---" } | ForEach-Object { $_.Trim() })
        LastApplied      = if ($GPResult -match "Last time Group Policy was applied:\s*(.+)") { $Matches[1].Trim() } else { $null }
        AppliedFromDC    = if ($GPResult -match "Group Policy was applied from:\s*(.+)") { $Matches[1].Trim() } else { $null }
    }
    Write-Log "GPO data collected"
} catch {
    $GPOData = [PSCustomObject]@{ Error = "gpresult failed: $_" }
    Write-Log "GPO collection failed: $_" "WARN"
}

# -- Domain User Sessions -------------------------------------------------------
Write-Host "[*] Collecting domain user sessions..." -ForegroundColor Cyan
$DomainSessions = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $LogonEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4624
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue | Select-Object -First 200

    foreach ($Evt in $LogonEvents) {
        $Msg = $Evt.Message
        $LogonType = if ($Msg -match "Logon Type:\s*(\d+)") { $Matches[1] } else { $null }
        $UserName  = if ($Msg -match "Account Name:\s*(\S+)") { $Matches[1] } else { $null }
        $UserDomain= if ($Msg -match "Account Domain:\s*(\S+)") { $Matches[1] } else { $null }

        if ($UserDomain -and $UserDomain -ne $Hostname -and $UserDomain -ne "NT AUTHORITY" -and $UserDomain -ne "Window Manager") {
            $DomainSessions.Add([PSCustomObject]@{
                TimeCreated = $Evt.TimeCreated.ToString("o")
                UserName    = $UserName
                UserDomain  = $UserDomain
                LogonType   = switch ($LogonType) {
                    "2" {"Interactive"} "3" {"Network"} "4" {"Batch"} "5" {"Service"}
                    "7" {"Unlock"} "8" {"NetworkCleartext"} "9" {"NewCredentials"}
                    "10" {"RemoteInteractive"} "11" {"CachedInteractive"} default {"Type $LogonType"}
                }
            })
        }
    }
    Write-Log "Domain sessions found: $($DomainSessions.Count)"
} catch {
    Write-Log "Domain session collection failed: $_" "WARN"
}

# -- Kerberos Configuration ----------------------------------------------------
Write-Host "[*] Collecting Kerberos configuration..." -ForegroundColor Cyan
$KerbConfig = [PSCustomObject]@{
    KerberosMaxTokenSize   = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -ErrorAction SilentlyContinue).MaxTokenSize
    KerbMaxPacketSize      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -ErrorAction SilentlyContinue).MaxPacketSize
    DomainKerberosEncTypes = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -ErrorAction SilentlyContinue).SupportedEncryptionTypes
    KerberosLogLevel       = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos" -ErrorAction SilentlyContinue).LogLevel
    KlistOutput            = (klist 2>&1) -join "`n"
    KlistTgtOutput         = (klist tgt 2>&1) -join "`n"
}
Write-Log "Kerberos config collected"

# -- LDAP / Domain Trust Settings ----------------------------------------------
Write-Host "[*] Checking LDAP and domain trust settings..." -ForegroundColor Cyan
$LDAPConfig = [PSCustomObject]@{
    LDAPClientSigning      = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -ErrorAction SilentlyContinue).LDAPClientIntegrity
    LDAPChannelBinding     = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -ErrorAction SilentlyContinue).LdapClientTlsRequirements
    DomainTrusts           = ((nltest /domain_trusts 2>&1) -join "`n")
    SiteName               = ((nltest /server:$DomainName /dsgetsite 2>&1) -join " ").Trim()
}
Write-Log "LDAP config collected"

# -- Cached Domain Credentials -------------------------------------------------
Write-Host "[*] Checking cached domain credential settings..." -ForegroundColor Cyan
$CachedCreds = [PSCustomObject]@{
    CachedLogonsCount    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue).CachedLogonsCount
    NoDomainController   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue).CachePrimaryDomain
    Note                 = "CachedLogonsCount defines how many domain credentials are cached locally for offline logon"
}
Write-Log "Cached credentials setting: $($CachedCreds.CachedLogonsCount)"

# -- DNS Suffix Search List ----------------------------------------------------
Write-Host "[*] Collecting DNS configuration..." -ForegroundColor Cyan
$DNSConfig = [PSCustomObject]@{
    SearchList         = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).SearchList
    DomainName         = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).Domain
    NVDomainName       = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).NV_Domain
    DNSSuffix          = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ErrorAction SilentlyContinue).DNSDomain
    RegisteredAdapters = @(Get-DnsClient -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress)
}
Write-Log "DNS config collected"

$Evidence = [PSCustomObject]@{
    ChainOfCustody  = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsAdmin=$IsAdmin }
    ArtifactType    = "ActiveDirectory_DomainArtifacts"
    Compatibility   = "Windows 10/11 domain-joined / Server 2016+"
    DomainInfo      = $DomainInfo
    DomainControllers = $DCInfo
    GroupPolicy     = $GPOData
    DomainSessions  = $DomainSessions
    KerberosConfig  = $KerbConfig
    LDAPConfig      = $LDAPConfig
    CachedCredentials = $CachedCreds
    DNSConfig       = $DNSConfig
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Active Directory artifacts collected" -ForegroundColor Green
Write-Host "    DCs: $($DCInfo.Count) | Domain Sessions: $($DomainSessions.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
