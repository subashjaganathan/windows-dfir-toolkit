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
$LogFile  = "$BasePath\LAPS_Status_Execution.log"
$JsonFile = "$BasePath\LAPS_Status_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "LAPS status collection started | Case: $CaseNum"

# LAPS installation detection
Write-Host "[*] Checking LAPS installation..." -ForegroundColor Cyan
$LAPSInstalled  = $false
$LAPSVersion    = $null
$LAPSType       = $null

# Check for Windows LAPS (built-in Win Server 2019+ / Win 11 22H2+)
$WindowsLAPS    = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS" -ErrorAction SilentlyContinue
if ($WindowsLAPS) {
    $LAPSInstalled = $true
    $LAPSType      = "Windows LAPS (Built-in)"
    $LAPSVersion   = $WindowsLAPS.Version
    Write-Log "Windows LAPS (built-in) detected"
}

# Check for legacy LAPS CSE (AdmPwd.dll)
$LegacyLAPS = @(Get-Item "C:\Program Files\LAPS\CSE\AdmPwd.dll" -ErrorAction SilentlyContinue)
if (-not $LAPSInstalled -and $LegacyLAPS) {
    $LAPSInstalled = $true
    $LAPSType      = "Legacy LAPS (AdmPwd)"
    $LAPSVersion   = $LegacyLAPS[0].VersionInfo.FileVersion
    Write-Log "Legacy LAPS CSE detected: $($LAPSVersion)"
}

# Check via installed software
if (-not $LAPSInstalled) {
    $LAPSSoftware = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "LAPS|Local Administrator Password" })
    if ($LAPSSoftware) {
        $LAPSInstalled = $true
        $LAPSType      = "LAPS (via installer) - $($LAPSSoftware[0].DisplayName)"
        $LAPSVersion   = $LAPSSoftware[0].DisplayVersion
        Write-Log "LAPS found via installed software: $($LAPSSoftware[0].DisplayName)"
    }
}

Write-Log "LAPS installed: $LAPSInstalled | Type: $LAPSType | Version: $LAPSVersion"

# LAPS policy configuration
Write-Host "[*] Collecting LAPS policy configuration..." -ForegroundColor Cyan
$LAPSPolicy = [PSCustomObject]@{ Configured = $false }
try {
    $LAPSPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    if (-not (Test-Path $LAPSPolicyKey)) {
        $LAPSPolicyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"
    }
    if (Test-Path $LAPSPolicyKey) {
        $Props = Get-ItemProperty $LAPSPolicyKey -ErrorAction SilentlyContinue
        $LAPSPolicy = [PSCustomObject]@{
            Configured           = $true
            RegistryKey          = $LAPSPolicyKey
            AdmPwdEnabled        = $Props.AdmPwdEnabled
            PasswordComplexity   = $Props.PasswordComplexity
            PasswordLength       = $Props.PasswordLength
            PasswordAgeDays      = $Props.PasswordAgeDays
            BackupDirectory      = $Props.BackupDirectory
            ADPasswordEncryption = $Props.ADPasswordEncryptionEnabled
            PasswordExpirationProtectionEnabled = $Props.PasswordExpirationProtectionEnabled
        }
        Write-Log "LAPS policy found: Enabled=$($Props.AdmPwdEnabled) | Length=$($Props.PasswordLength) | AgeDays=$($Props.PasswordAgeDays)"
    }
} catch { Write-Log "LAPS policy read failed: $_" "WARN" }

# Local admin account status
Write-Host "[*] Checking local Administrator account status..." -ForegroundColor Cyan
$LocalAdminStatus = [PSCustomObject]@{}
try {
    $AdminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($AdminAccount) {
        $LocalAdminStatus = [PSCustomObject]@{
            Enabled          = $AdminAccount.Enabled
            LastLogon        = if ($AdminAccount.LastLogon) { $AdminAccount.LastLogon.ToString("o") } else { $null }
            PasswordLastSet  = if ($AdminAccount.PasswordLastSet) { $AdminAccount.PasswordLastSet.ToString("o") } else { $null }
            PasswordExpires  = $AdminAccount.PasswordExpires
            PasswordRequired = $AdminAccount.PasswordRequired
            SID              = $AdminAccount.SID.ToString()
            PasswordAgeDays  = if ($AdminAccount.PasswordLastSet) { [math]::Round(((Get-Date) - $AdminAccount.PasswordLastSet).TotalDays) } else { $null }
            IsPasswordOld    = if ($AdminAccount.PasswordLastSet) { ((Get-Date) - $AdminAccount.PasswordLastSet).TotalDays -gt 90 } else { $true }
        }
        Write-Log "Local admin: Enabled=$($AdminAccount.Enabled) | PasswordAge=$($LocalAdminStatus.PasswordAgeDays) days"
    }
} catch { Write-Log "Local admin query failed: $_" "WARN" }

# Risk assessment
$RiskFindings = @()
if (-not $LAPSInstalled)                          { $RiskFindings += "LAPS not installed - shared local admin password risk" }
if ($LAPSInstalled -and -not $LAPSPolicy.Configured){ $RiskFindings += "LAPS installed but not configured via policy" }
if ($LocalAdminStatus.Enabled -and $LocalAdminStatus.IsPasswordOld) { $RiskFindings += "Local Administrator enabled with password older than 90 days" }
if (-not $LocalAdminStatus.Enabled)               { $RiskFindings += "Built-in Administrator disabled - verify alternate admin account" }

Write-Log "Risk findings: $($RiskFindings.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody     = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType       = "LAPS_Status"
    LAPSInstalled      = $LAPSInstalled
    LAPSType           = $LAPSType
    LAPSVersion        = $LAPSVersion
    LAPSPolicy         = $LAPSPolicy
    LocalAdminStatus   = $LocalAdminStatus
    RiskFindings       = $RiskFindings
    RiskCount          = $RiskFindings.Count
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

$RiskColor = if ($RiskFindings.Count -gt 0) { "Yellow" } else { "Green" }
Write-Host "[+] LAPS status collected | Installed: $LAPSInstalled | Type: $LAPSType | Risk Findings: $($RiskFindings.Count)" -ForegroundColor $RiskColor
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
