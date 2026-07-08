#Requires -Version 5.1
<#
.SYNOPSIS
    Collects Windows Hello, PIN, biometric, and modern auth artifacts.

.DESCRIPTION
    Enumerates Windows Hello for Business configuration, PIN
    authentication setup, biometric enrollment status, Microsoft
    account linkage, Azure AD join status, and Passport/NGC
    key container artifacts. Critical for Windows 10/11 identity
    and credential investigation.

.COMPATIBILITY
    Windows 10 1607+  : Full
    Windows 11        : Full
    Server 2016+      : Partial (Hello for Business only)

.IR_PHASE
    Credential Access / Identity Investigation

.MITRE_ATTCK
    T1078.004 - Valid Accounts: Cloud Accounts
    T1556     - Modify Authentication Process
    T1539     - Steal Web Session Cookie

.FORENSIC_SAFETY
    Read-only, forensic-safe. No credentials extracted.

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
$LogFile  = "$BasePath\WindowsHello_Execution.log"
function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
$JsonFile = "$BasePath\WindowsHello_${Hostname}_${Timestamp}.json"

Write-Log "Windows Hello collection started | Case: $CaseNum"

# -- OS Detection --------------------------------------------------------------
$OSInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = $OSInfo.Caption
$IsServer  = $OSCaption -match "Server"
Write-Log ("OS: " + $OSCaption + " | IsServer: " + $IsServer)

# -- Azure AD / Domain Join Status ---------------------------------------------
Write-Host "[*] Collecting domain and Azure AD join status..." -ForegroundColor Cyan
$JoinStatus = [PSCustomObject]@{}
try {
    $DSRegOut = (dsregcmd /status 2>&1) -join "`n"
    $JoinStatus = [PSCustomObject]@{
        AzureADJoined         = ($DSRegOut -match "AzureAdJoined\s*:\s*YES")
        DomainJoined          = ($DSRegOut -match "DomainJoined\s*:\s*YES")
        WorkplaceJoined       = ($DSRegOut -match "WorkplaceJoined\s*:\s*YES")
        AzureTenantId         = if ($DSRegOut -match "TenantId\s*:\s*(\S+)") { $Matches[1] } else { $null }
        AzureTenantName       = if ($DSRegOut -match "TenantName\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        DeviceId              = if ($DSRegOut -match "DeviceId\s*:\s*(\S+)") { $Matches[1] } else { $null }
        DeviceAuthStatus      = if ($DSRegOut -match "Device Auth Status\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        HelloForBusinessStatus= if ($DSRegOut -match "Hello for Business\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        NgcPrerequisiteCheck  = if ($DSRegOut -match "NgcPrerequisiteCheck\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        SSO                   = ($DSRegOut -match "SSO State\s*:\s*AzureAdPrt : YES")
        RawOutput             = ($DSRegOut -split "`n" | Select-Object -First 80) -join "`n"
    }
    Write-Log "Join Status: AAD=$($JoinStatus.AzureADJoined) Domain=$($JoinStatus.DomainJoined)"
} catch {
    $JoinStatus = [PSCustomObject]@{ Error = "dsregcmd failed: $_" }
    Write-Log "dsregcmd failed: $_" "WARN"
}

# -- Windows Hello NGC Key Containers ------------------------------------------
Write-Host "[*] Enumerating Windows Hello NGC key containers..." -ForegroundColor Cyan
$NGCKeys = [System.Collections.Generic.List[PSCustomObject]]::new()
$NGCPaths = @(
    "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys",
    "C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Crypto\Keys"
)
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $NGCPath = "$($_.FullName)\AppData\Local\Microsoft\Ngc"
    if (Test-Path $NGCPath) {
        Get-ChildItem $NGCPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $NGCKeys.Add([PSCustomObject]@{
                UserProfile   = (Split-Path $_.FullName -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Parent | Split-Path -Leaf)
                Path          = $_.FullName
                Name          = $_.Name
                SizeBytes     = $_.Length
                LastWriteTime = $_.LastWriteTimeUtc.ToString("o")
                CreationTime  = $_.CreationTimeUtc.ToString("o")
                IsDirectory   = $_.PSIsContainer
            })
        }
    }
}
Write-Log "NGC key container items: $($NGCKeys.Count)"

# -- Per-User Hello Enrollment Status ------------------------------------------
Write-Host "[*] Checking per-user Hello enrollment..." -ForegroundColor Cyan
$HelloEnrollment = [System.Collections.Generic.List[PSCustomObject]]::new()
Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $UserName = $_.Name
    $NgcPath  = "$($_.FullName)\AppData\Local\Microsoft\Ngc"
    $PinPath  = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin"

    $HasNGC   = Test-Path $NgcPath -ErrorAction SilentlyContinue
    $NgcCount = if ($HasNGC) { (Get-ChildItem $NgcPath -Recurse -ErrorAction SilentlyContinue).Count } else { 0 }

    $HelloEnrollment.Add([PSCustomObject]@{
        UserName          = $UserName
        NGCFolderExists   = $HasNGC
        NGCItemCount      = $NgcCount
        PINConfigured     = $HasNGC -and ($NgcCount -gt 0)
        ProfilePath       = $_.FullName
        LastWriteTime     = if ($HasNGC) { (Get-Item $NgcPath -ErrorAction SilentlyContinue).LastWriteTimeUtc.ToString("o") } else { $null }
    })
}
Write-Log "Hello enrollment checked for $($HelloEnrollment.Count) users"

# -- Biometric Service Status ---------------------------------------------------
Write-Host "[*] Checking Windows Biometric Service..." -ForegroundColor Cyan
$BiometricData = [PSCustomObject]@{}
try {
    $WBF = Get-Service WbioSrvc -ErrorAction Stop
    $BiometricData = [PSCustomObject]@{
        ServiceStatus    = $WBF.Status.ToString()
        StartType        = $WBF.StartType.ToString()
        BiometricDevices = @(Get-PnpDevice -Class Biometric -ErrorAction SilentlyContinue |
            Select-Object FriendlyName, Status, DeviceID, Manufacturer)
        FaceAuthEnabled  = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -ErrorAction SilentlyContinue).EnhancedAntiSpoofing
        FingerprintEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -ErrorAction SilentlyContinue).Enabled
    }
    Write-Log "Biometric service: $($WBF.Status)"
} catch {
    $BiometricData = [PSCustomObject]@{ Error = "Biometric service query failed: $_" }
    Write-Log "Biometric service query failed: $_" "WARN"
}

# -- Microsoft Account (MSA) Linkage -------------------------------------------
Write-Host "[*] Checking Microsoft Account linkage..." -ForegroundColor Cyan
$MSAData = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $MSAKey = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
    if (Test-Path $MSAKey) {
        Get-ChildItem $MSAKey -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($Props.IdentityName) {
                    $MSAData.Add([PSCustomObject]@{
                        IdentityName  = $Props.IdentityName
                        GivenName     = $Props.GivenName
                        DisplayName   = $Props.DisplayName
                        ProviderID    = $Props.ProviderID
                    })
                }
            }
        }
    }
    Write-Log "MSA accounts found: $($MSAData.Count)"
} catch {
    Write-Log "MSA query failed: $_" "WARN"
}

# -- Server-Specific: Service Accounts and gMSA (Server OS only) --------------
$ServiceAccountData = [PSCustomObject]@{ Collected = $false }
if ($IsServer) {
    Write-Host "[*] Server OS - collecting service account artifacts..." -ForegroundColor Cyan
    # Local service accounts used by services (potential persistence via service accounts)
    $ServiceAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartName -notmatch "^(LocalSystem|NT AUTHORITY|NT SERVICE)" -and $_.StartName } |
        ForEach-Object {
            $ServiceAccounts.Add([PSCustomObject]@{
                ServiceName = $_.Name
                DisplayName = $_.DisplayName
                StartName   = $_.StartName
                State       = $_.State
                StartMode   = $_.StartMode
                Note        = "Non-default service account - verify this is expected"
            })
        }

    # Group Managed Service Accounts (gMSA) via registry
    $gMSAPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions"
    $gMSAData = @(Get-ChildItem $gMSAPath -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    })

    # IIS Application Pool identities
    $AppPools = [System.Collections.Generic.List[PSCustomObject]]::new()
    $AppCmdPath = "C:\Windows\System32\inetsrvppcmd.exe"
    if (Test-Path $AppCmdPath) {
        try {
            $APList = (& $AppCmdPath list apppool /processModel.userName:* 2>&1)
            foreach ($AP in $APList) {
                if ($AP -match 'APPPOOL "(.+?)"') {
                    $AppPools.Add([PSCustomObject]@{ AppPool = $Matches[1]; RawLine = $AP.ToString() })
                }
            }
        } catch {}
    }

    $ServiceAccountData = [PSCustomObject]@{
        Collected            = $true
        NonDefaultServices   = $ServiceAccounts
        IISAppPools          = $AppPools
        Note                 = "Service accounts with non-default identities are high-value targets for privilege escalation"
    }
    Write-Log ("Service accounts with non-default identity: " + $ServiceAccounts.Count)
}

# -- Credential Provider Configuration -----------------------------------------
Write-Host "[*] Checking credential providers..." -ForegroundColor Cyan
$CredProviders = [System.Collections.Generic.List[PSCustomObject]]::new()
$CPKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
if (Test-Path $CPKey) {
    Get-ChildItem $CPKey -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $CredProviders.Add([PSCustomObject]@{
            CLSID       = $_.PSChildName
            Name        = $Props."(default)"
            Disabled    = (Get-ItemProperty "$($_.PSPath)" -Name Disabled -ErrorAction SilentlyContinue).Disabled
        })
    }
}
Write-Log "Credential providers: $($CredProviders.Count)"

# -- Windows 11 Specific: Enhanced Phishing Protection -------------------------
Write-Host "[*] Checking Enhanced Phishing Protection (Win11)..." -ForegroundColor Cyan
$PhishingProtection = [PSCustomObject]@{
    ServiceEnabled       = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" -ErrorAction SilentlyContinue).SmartScreenEnabled
    NotifyMalicious      = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).EnableSmartScreen
    NotifyPasswordReuse  = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -ErrorAction SilentlyContinue).TamperProtection
    Note                 = "Enhanced Phishing Protection requires Windows 11 22H2+"
}

$Evidence = [PSCustomObject]@{
    ChainOfCustody        = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion; IsAdmin=$IsAdmin }
    ArtifactType          = "WindowsHello_ModernAuth"
    Compatibility         = "Windows 10 1607+ / Windows 11 / Server 2016+ (partial)"
    DomainAndAADJoin      = $JoinStatus
    HelloEnrollmentByUser = $HelloEnrollment
    NGCKeyContainers      = $NGCKeys
    BiometricService      = $BiometricData
    MicrosoftAccounts     = $MSAData
    CredentialProviders   = $CredProviders
    PhishingProtection    = $PhishingProtection
    ServiceAccounts       = $ServiceAccountData
    OSMode                = if ($IsServer) { "Server OS - biometrics replaced with service account analysis" } else { "Workstation OS - Full Hello/biometric collection" }
}

$Evidence | ConvertTo-Json -Depth 7 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Windows Hello artifacts collected" -ForegroundColor Green
Write-Host "    Users enrolled: $($HelloEnrollment.Count) | NGC Keys: $($NGCKeys.Count) | MSA Accounts: $($MSAData.Count)" -ForegroundColor Cyan
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
