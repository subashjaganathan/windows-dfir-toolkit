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
$LogFile  = "$BasePath\LSA_Secrets_Execution.log"
$JsonFile = "$BasePath\LSA_Secrets_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "LSA Secrets metadata collection started | Case: $CaseNum"

# LSA Secret key names (metadata only - no values)
Write-Host "[*] Collecting LSA Secrets key metadata..." -ForegroundColor Cyan
$LSASecretKeys = [System.Collections.Generic.List[PSCustomObject]]::new()
$LSAKeyPath    = "HKLM:\SECURITY\Policy\Secrets"

try {
    if (Test-Path $LSAKeyPath) {
        Get-ChildItem $LSAKeyPath -ErrorAction SilentlyContinue | ForEach-Object {
            $KeyName    = $_.PSChildName
            $IsService  = $KeyName -match "^_SC_"
            $ServiceName= if ($IsService) { $KeyName -replace "^_SC_","" } else { $null }
            $IsSuspicious = $false
            $SuspReason   = @()

            # Flag unusual LSA secret names
            if ($KeyName -notmatch "^_SC_|^DPAPI|^NL|^RasDialParams|^DefaultPassword|^ASPNET|^SAC|^SAI") {
                $IsSuspicious = $true
                $SuspReason  += "Non-standard LSA secret name"
            }
            if ($KeyName -match "hack|malware|payload|shell|beacon|cobalt|meterp") {
                $IsSuspicious = $true
                $SuspReason  += "Suspicious naming pattern"
            }

            $LSASecretKeys.Add([PSCustomObject]@{
                SecretName       = $KeyName
                IsServiceSecret  = $IsService
                ServiceName      = $ServiceName
                IsSuspicious     = $IsSuspicious
                SuspiciousReason = ($SuspReason -join "; ")
                Note             = "Value not extracted - metadata only. Use impacket/secretsdump for full extraction offline."
            })
        }
        Write-Log "LSA secret keys found: $($LSASecretKeys.Count)"
    } else {
        Write-Log "LSA Secrets key not accessible (requires SYSTEM)" "WARN"
        Write-Host "[!] LSA Secrets key requires SYSTEM privileges - recording key path only" -ForegroundColor Yellow
    }
} catch { Write-Log "LSA Secrets access failed: $_" "WARN" }

# Cached domain credentials count
Write-Host "[*] Checking cached domain credential count..." -ForegroundColor Cyan
$CachedCreds = [PSCustomObject]@{ Count = $null; RegistryPath = $null }
try {
    $NLPath = "HKLM:\SECURITY\Cache"
    if (Test-Path $NLPath) {
        $NLItems = @(Get-ChildItem $NLPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "^NL\$\d+" })
        $CachedCreds = [PSCustomObject]@{
            Count        = $NLItems.Count
            RegistryPath = $NLPath
            Note         = "NL cache entries represent cached domain logon hashes"
        }
        Write-Log "Cached domain credentials: $($NLItems.Count)"
    }
} catch { Write-Log "Cache credential count failed: $_" "WARN" }

# LSA protection state
Write-Host "[*] Checking LSA protection and configuration..." -ForegroundColor Cyan
$LSAConfig = [PSCustomObject]@{}
try {
    $LSAKey  = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    $LSAConfig = [PSCustomObject]@{
        RunAsPPL              = $LSAKey.RunAsPPL
        LsaCfgFlags           = $LSAKey.LsaCfgFlags
        DisableDomainCreds    = $LSAKey.disabledomaincreds
        EveryoneIncludesAnon  = $LSAKey.everyoneincludesanonymous
        ForceGuest            = $LSAKey.forceguest
        LimitBlankPasswordUse = $LSAKey.limitblankpassworduse
        NoLMHash              = $LSAKey.nolmhash
        RestrictAnonymous     = $LSAKey.restrictanonymous
        RestrictAnonymousSAM  = $LSAKey.restrictanonymoussam
        SecureBoot            = $LSAKey.SecureBoot
        AuthenticationPackages= $LSAKey."Authentication Packages"
        NotificationPackages  = $LSAKey."Notification Packages"
        SecurityPackages      = $LSAKey."Security Packages"
    }
    Write-Log "LSA config collected | PPL=$($LSAKey.RunAsPPL) | NoLMHash=$($LSAKey.nolmhash)"
} catch { Write-Log "LSA config failed: $_" "WARN" }

# Service accounts using LSA secrets
Write-Host "[*] Mapping service accounts to LSA secrets..." -ForegroundColor Cyan
$ServiceSecretMap = [System.Collections.Generic.List[PSCustomObject]]::new()
$ServicesWithCreds = @(Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.StartName -and $_.StartName -notmatch "LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE" })

foreach ($Svc in $ServicesWithCreds) {
    $HasLSASecret = $LSASecretKeys | Where-Object { $_.ServiceName -eq $Svc.Name }
    $ServiceSecretMap.Add([PSCustomObject]@{
        ServiceName    = $Svc.Name
        DisplayName    = $Svc.DisplayName
        StartAccount   = $Svc.StartName
        State          = $Svc.State
        HasLSASecret   = ($null -ne $HasLSASecret)
        LSASecretKey   = if ($HasLSASecret) { $HasLSASecret.SecretName } else { $null }
    })
}
Write-Log "Services with non-default accounts: $($ServiceSecretMap.Count)"

$SuspLSA = ($LSASecretKeys | Where-Object { $_.IsSuspicious }).Count
$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType        = "LSA_Secrets_Metadata"
    LSASecretKeyCount   = $LSASecretKeys.Count
    SuspiciousKeyCount  = $SuspLSA
    CachedDomainCreds   = $CachedCreds
    LSAConfig           = $LSAConfig
    LSASecretKeys       = $LSASecretKeys
    ServiceAccountMap   = $ServiceSecretMap
    ForensicNote        = "Values intentionally not extracted. For offline extraction use: impacket-secretsdump -system SYSTEM -security SECURITY LOCAL"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] LSA Secrets metadata collected | Keys: $($LSASecretKeys.Count) | Cached creds: $($CachedCreds.Count) | Suspicious: $SuspLSA" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
