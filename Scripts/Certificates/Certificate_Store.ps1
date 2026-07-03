#Requires -Version 5.1
Set-StrictMode -Off
$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Hostname  = $env:COMPUTERNAME
$BasePath  = if ($env:DFIR_OUTPUT) { $env:DFIR_OUTPUT } else { "C:\IR_Collection" }
$CaseNum   = if ($env:DFIR_CASE) { $env:DFIR_CASE } else { "CASE-$(Get-Date -Format yyyyMMdd)" }
New-Item -ItemType Directory -Path $BasePath -Force | Out-Null
$LogFile  = "$BasePath\Certificates_Execution.log"
$JsonFile = "$BasePath\Certificate_Store_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Certificate store collection started | Case: $CaseNum"

# A root is only genuinely "rogue" when it is NOT part of the Microsoft Trusted Root
# Program (the AuthRoot CTL) and was not deployed by enterprise policy. A hardcoded name
# allowlist can never be complete and mislabels legitimate public CAs (SSL.com, Starfield,
# Go Daddy, emSign, ...) as rogue. Instead we build the authoritative trusted set from the
# CTL/GPO thumbprints Windows itself records, and flag only roots absent from it.
$TrustedRootThumbs = @{}
foreach ($k in @(
    "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates",          # CTL auto-update program roots
    "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates",          # enterprise-deployed roots
    "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates",     # GPO-deployed roots
    "HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates")) {
    try { if (Test-Path $k) { foreach ($n in (Get-ChildItem $k -ErrorAction SilentlyContinue).PSChildName) { $TrustedRootThumbs[$n.ToUpperInvariant()] = $true } } } catch {}
}

function Get-CertData {
    param([string]$StoreLocation, [string]$StoreName)
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $Store.Open("ReadOnly")
        foreach ($Cert in $Store.Certificates) {
            $DaysTillExpiry = ($Cert.NotAfter - (Get-Date)).TotalDays
            $Results.Add([PSCustomObject]@{
                StoreLocation    = $StoreLocation
                StoreName        = $StoreName
                Subject          = $Cert.Subject
                Issuer           = $Cert.Issuer
                Thumbprint       = $Cert.Thumbprint
                SerialNumber     = $Cert.SerialNumber
                NotBefore        = $Cert.NotBefore.ToString("o")
                NotAfter         = $Cert.NotAfter.ToString("o")
                DaysTillExpiry   = [math]::Round($DaysTillExpiry)
                HasPrivateKey    = $Cert.HasPrivateKey
                SignatureAlg     = $Cert.SignatureAlgorithm.FriendlyName
                IsExpired        = ($Cert.NotAfter -lt (Get-Date))
                # Suspicious only if a self-signed Root-store cert is absent from the
                # Microsoft/enterprise trusted-root set - i.e. installed out-of-band.
                IsSuspicious     = ($Cert.Subject -eq $Cert.Issuer -and $StoreName -eq "Root" -and
                            -not $script:TrustedRootThumbs.ContainsKey($Cert.Thumbprint.ToUpperInvariant()))
            })
        }
        $Store.Close()
    } catch {}
    return $Results
}

Write-Host "[*] Collecting certificate stores..." -ForegroundColor Cyan
$AllCerts = [System.Collections.Generic.List[PSCustomObject]]::new()
$Stores   = @(
    @{ Loc="LocalMachine"; Name="Root" }
    @{ Loc="LocalMachine"; Name="CA" }
    @{ Loc="LocalMachine"; Name="My" }
    @{ Loc="LocalMachine"; Name="TrustedPeople" }
    @{ Loc="LocalMachine"; Name="TrustedPublisher" }
    @{ Loc="LocalMachine"; Name="Disallowed" }
    @{ Loc="CurrentUser";  Name="Root" }
    @{ Loc="CurrentUser";  Name="CA" }
    @{ Loc="CurrentUser";  Name="My" }
    @{ Loc="CurrentUser";  Name="TrustedPeople" }
)

foreach ($S in $Stores) {
    $Certs = Get-CertData $S.Loc $S.Name
    foreach ($C in $Certs) { $AllCerts.Add($C) }
}

$SuspiciousCerts = @($AllCerts | Where-Object { $_.IsSuspicious })
$ExpiredWithKey  = @($AllCerts | Where-Object { $_.IsExpired -and $_.HasPrivateKey })
$RogueRoots      = @($AllCerts | Where-Object { $_.StoreName -eq "Root" -and $_.IsSuspicious } | Sort-Object Thumbprint -Unique)

Write-Log "Certificates: Total=$($AllCerts.Count) Suspicious=$($SuspiciousCerts.Count) RogueRoots=$($RogueRoots.Count)"

# CTL (Certificate Trust List)
Write-Host "[*] Checking Certificate Trust Lists..." -ForegroundColor Cyan
$CTLData = (certutil -verifyCTL AuthRootWU 2>&1) -join "`n"

$Evidence = [PSCustomObject]@{
    ChainOfCustody   = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=(Get-Date).ToString("o"); ToolVersion="1.0" }
    ArtifactType     = "CertificateStore"
    TotalCerts       = $AllCerts.Count
    SuspiciousCount  = $SuspiciousCerts.Count
    RogueRootCount   = $RogueRoots.Count
    SuspiciousCerts  = $SuspiciousCerts
    RogueRootCerts   = $RogueRoots
    ExpiredWithKey   = $ExpiredWithKey
    AllCertificates  = $AllCerts
    CTLCheck         = ($CTLData -split "`n" | Select-Object -First 20) -join "`n"
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=(Get-Date).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Certificate store collected | Total: $($AllCerts.Count) | Suspicious: $($SuspiciousCerts.Count) | Rogue Roots: $($RogueRoots.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
