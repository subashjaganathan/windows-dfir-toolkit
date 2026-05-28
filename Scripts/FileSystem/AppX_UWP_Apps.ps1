#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\AppX_UWP_Execution.log"
$JsonFile = "$BasePath\AppX_UWP_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "AppX/UWP collection started | Case: $CaseNum"

# All installed AppX packages (all users)
Write-Host "[*] Collecting AppX package inventory (all users)..." -ForegroundColor Cyan
$AllPackages = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuspiciousPackages = [System.Collections.Generic.List[PSCustomObject]]::new()

# Known legitimate publisher prefixes
$LegitPublishers = @("CN=Microsoft","CN=Apple","CN=Google","CN=Mozilla","CN=Adobe",
    "CN=Spotify","CN=Slack","CN=Zoom","CN=Amazon","CN=Dropbox","CN=NVIDIA")

try {
    $Packages = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
    foreach ($Pkg in $Packages) {
        $IsLegit = $false
        foreach ($LP in $LegitPublishers) {
            if ($Pkg.Publisher -match [regex]::Escape($LP.Replace("CN=",""))) { $IsLegit = $true; break }
        }

        # Sideloaded = not from store (no StoreId or SignatureKind = Developer/None)
        $IsSideloaded = $false
        $SigKind = $null
        try {
            $SigKind     = $Pkg.SignatureKind.ToString()
            $IsSideloaded= ($SigKind -eq "Developer" -or $SigKind -eq "None")
        } catch {}

        $PkgObj = [PSCustomObject]@{
            Name             = $Pkg.Name
            PackageFullName  = $Pkg.PackageFullName
            Version          = $Pkg.Version.ToString()
            Publisher        = $Pkg.Publisher
            Architecture     = $Pkg.Architecture.ToString()
            InstallLocation  = $Pkg.InstallLocation
            IsFramework      = $Pkg.IsFramework
            IsDevelopment    = $IsSideloaded
            SignatureKind    = $SigKind
            PackageUserInfo  = @($Pkg.PackageUserInformation | ForEach-Object { $_.UserSecurityId })
            IsKnownPublisher = $IsLegit
            IsSuspicious     = ($IsSideloaded -and -not $IsLegit)
        }
        $AllPackages.Add($PkgObj)
        if ($PkgObj.IsSuspicious) { $SuspiciousPackages.Add($PkgObj) }
    }
    Write-Log "AppX packages: $($AllPackages.Count) | Sideloaded suspicious: $($SuspiciousPackages.Count)"
} catch { Write-Log "AppX package query failed: $_" "WARN" }

# Provisioned packages (installed for all new users)
Write-Host "[*] Collecting provisioned AppX packages..." -ForegroundColor Cyan
$ProvisionedPackages = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
    foreach ($PP in $Provisioned) {
        $ProvisionedPackages.Add([PSCustomObject]@{
            DisplayName     = $PP.DisplayName
            PackageName     = $PP.PackageName
            Version         = $PP.Version
            Architecture    = $PP.Architecture
            PublisherId     = $PP.PublisherId
        })
    }
    Write-Log "Provisioned packages: $($ProvisionedPackages.Count)"
} catch { Write-Log "Provisioned packages query failed: $_" "WARN" }

# AppX installation events from event log
Write-Host "[*] Collecting AppX installation events..." -ForegroundColor Cyan
$AppXEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $Filter = @{ LogName="Microsoft-Windows-AppXDeployment/Operational"; Id=@(400,701); MaxEvents=200 }
    $Events = @(Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue)
    foreach ($E in $Events) {
        $AppXEvents.Add([PSCustomObject]@{
            TimeCreated = $E.TimeCreated.ToString("o")
            EventID     = $E.Id
            Message     = $E.Message -replace "\r?\n"," "
        })
    }
    Write-Log "AppX events: $($AppXEvents.Count)"
} catch { Write-Log "AppX events query failed: $_" "WARN" }

# Developer mode status
Write-Host "[*] Checking developer mode status..." -ForegroundColor Cyan
$DevModeKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
$DevMode     = [PSCustomObject]@{ Enabled = $false }
if (Test-Path $DevModeKey) {
    $Props = Get-ItemProperty $DevModeKey -ErrorAction SilentlyContinue
    $DevMode = [PSCustomObject]@{
        Enabled              = ($Props.AllowDevelopmentWithoutDevLicense -eq 1)
        AllowAllTrustedApps  = ($Props.AllowAllTrustedApps -eq 1)
    }
}
Write-Log "Developer mode: $($DevMode.Enabled)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody      = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType        = "AppX_UWP_Apps"
    TotalPackages       = $AllPackages.Count
    SuspiciousCount     = $SuspiciousPackages.Count
    ProvisionedCount    = $ProvisionedPackages.Count
    DeveloperModeEnabled= $DevMode.Enabled
    DeveloperMode       = $DevMode
    SuspiciousPackages  = $SuspiciousPackages
    AllPackages         = $AllPackages
    ProvisionedPackages = $ProvisionedPackages
    AppXEvents          = $AppXEvents
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File $JsonFile -Encoding UTF8
$Hash = Get-FileHash $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] AppX/UWP collection complete | Total: $($AllPackages.Count) | Suspicious: $($SuspiciousPackages.Count) | DevMode: $($DevMode.Enabled)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
