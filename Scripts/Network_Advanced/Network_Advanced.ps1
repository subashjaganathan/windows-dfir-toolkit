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
$LogFile  = "$BasePath\Network_Advanced_Execution.log"
$JsonFile = "$BasePath\Network_Advanced_${Hostname}_${Timestamp}.json"

function Write-Log { param([string]$M,[string]$L="INFO") Add-Content $LogFile "$(Get-Date -Format o) [$L] :: $M" }
Write-Log "Advanced network artifact collection started | Case: $CaseNum"

# Wireless network profiles
Write-Host "[*] Collecting WiFi profiles..." -ForegroundColor Cyan
$WiFiProfiles = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $NetshOut = (netsh wlan show profiles 2>&1) -join "`n"
    $ProfileNames = [regex]::Matches($NetshOut, "All User Profile\s*:\s*(.+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
    foreach ($Profile in $ProfileNames) {
        $Detail = (netsh wlan show profile name="$Profile" key=clear 2>&1) -join "`n"
        $WiFiProfiles.Add([PSCustomObject]@{
            SSID           = $Profile
            AuthType       = if ($Detail -match "Authentication\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
            Encryption     = if ($Detail -match "Cipher\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
            KeyContent     = if ($Detail -match "Key Content\s*:\s*(.+)") { "[PRESENT]" } else { "Not stored in cleartext" }
            ConnectionMode = if ($Detail -match "Connection mode\s*:\s*(.+)") { $Matches[1].Trim() } else { $null }
        })
    }
    Write-Log "WiFi profiles: $($WiFiProfiles.Count)"
} catch { Write-Log "WiFi collection failed: $_" "WARN" }

# RDP saved connections and bitmap cache
Write-Host "[*] Collecting RDP history..." -ForegroundColor Cyan
$RDPHistory = [System.Collections.Generic.List[PSCustomObject]]::new()
$RDPKey = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Servers"
if (Test-Path $RDPKey) {
    Get-ChildItem $RDPKey -ErrorAction SilentlyContinue | ForEach-Object {
        $Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $RDPHistory.Add([PSCustomObject]@{
            ServerName   = $_.PSChildName
            UsernameHint = $Props.UsernameHint
        })
    }
}
$RDPMRUKey = "HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default"
if (Test-Path $RDPMRUKey) {
    $RDPMRUProps = Get-ItemProperty $RDPMRUKey -ErrorAction SilentlyContinue
    $RDPMRUProps.PSObject.Properties | Where-Object { $_.Name -match "^MRU" } | ForEach-Object {
        $RDPHistory.Add([PSCustomObject]@{ ServerName=$_.Value; Source="MRU" })
    }
}

# RDP bitmap cache
$RDPCachePaths = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    "$($_.FullName)\AppData\Local\Microsoft\Terminal Server Client\Cache"
})
$RDPCacheFiles = @($RDPCachePaths | Where-Object { Test-Path $_ } | ForEach-Object {
    Get-ChildItem $_ -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{ File=$_.Name; Path=$_.FullName; SizeBytes=$_.Length; LastModified=$_.LastWriteTimeUtc.ToString("o") }
    }
})
Write-Log "RDP history: $($RDPHistory.Count) | RDP Cache files: $($RDPCacheFiles.Count)"

# Proxy settings
Write-Host "[*] Collecting proxy configuration..." -ForegroundColor Cyan
$ProxySettings = [PSCustomObject]@{
    WinHTTP      = ((netsh winhttp show proxy 2>&1) -join " ")
    IEProxy      = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
                     Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL
    SystemProxy  = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
                     Select-Object ProxySettingsPerUser, ProxyEnable, ProxyServer
    WPADEnabled  = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue).AutoDetect
}

# DNS cache with suspicious domain detection
Write-Host "[*] Collecting DNS cache with enrichment..." -ForegroundColor Cyan
$DomainCache = @(Get-DnsClientCache -ErrorAction SilentlyContinue)
$SuspiciousDomains = @($DomainCache | Where-Object {
    $_.Entry -match "\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}" -or  # IP as domain
    $_.Entry -match "\.onion$" -or                            # Tor
    $_.Entry.Length -gt 50 -or                               # Abnormally long
    $_.Entry -match "[a-z0-9]{20,}\.(com|net|org|info)$"   # DGA-like
})

# Network adapter config including WPAD
$AdapterDetails = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    $Config = Get-NetIPConfiguration -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name         = $_.Name
        Status       = $_.Status
        MACAddress   = $_.MacAddress
        LinkSpeed    = $_.LinkSpeed
        IPv4         = ($Config.IPv4Address.IPAddress -join ", ")
        IPv6         = ($Config.IPv6Address.IPAddress -join ", ")
        Gateway      = ($Config.IPv4DefaultGateway.NextHop -join ", ")
        DNS          = ($Config.DNSServer.ServerAddresses -join ", ")
        DNSSuffix    = $Config.NetProfile.Name
    }
})

# Clipboard history (Win10 1809+)
Write-Host "[*] Checking clipboard history..." -ForegroundColor Cyan
$ClipboardData = [PSCustomObject]@{ Note = "Clipboard history requires direct UI access - check C:\Users\*\AppData\Local\Microsoft\Windows\Clipboard" }
$ClipPaths = @(Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    "$($_.FullName)\AppData\Local\Microsoft\Windows\Clipboard"
} | Where-Object { Test-Path $_ })
if ($ClipPaths) {
    $ClipFiles = @($ClipPaths | ForEach-Object { Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue })
    $ClipboardData = [PSCustomObject]@{
        ClipboardPaths = $ClipPaths
        FileCount      = $ClipFiles.Count
        Files          = @($ClipFiles | Select-Object Name, LastWriteTime, Length)
        Note           = "Clipboard DB files found - use SQLite browser for content analysis"
    }
}

Write-Log "WiFi: $($WiFiProfiles.Count) | RDP: $($RDPHistory.Count) | Suspicious DNS: $($SuspiciousDomains.Count)"

$Evidence = [PSCustomObject]@{
    ChainOfCustody    = [PSCustomObject]@{ CaseNumber=$CaseNum; Hostname=$Hostname; CollectedAt=([DateTime]::UtcNow).ToString("o"); ToolVersion=$Global:DFIR_ToolVersion }
    ArtifactType      = "Network_Advanced"
    WiFiProfiles      = $WiFiProfiles
    RDPHistory        = $RDPHistory
    RDPBitmapCache    = $RDPCacheFiles
    ProxySettings     = $ProxySettings
    SuspiciousDNS     = $SuspiciousDomains
    AllDNSEntries     = $DomainCache.Count
    AdapterDetails    = $AdapterDetails
    ClipboardHistory  = $ClipboardData
}

$Evidence | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8
$Hash = Get-FileHash -Path $JsonFile -Algorithm SHA256
[PSCustomObject]@{ FileName=$JsonFile; Hash=$Hash.Hash; Generated=([DateTime]::UtcNow).ToString("o") } |
    ConvertTo-Json | Out-File "$JsonFile.hash.json" -Encoding UTF8

Write-Host "[+] Advanced network artifacts collected | WiFi: $($WiFiProfiles.Count) | RDP History: $($RDPHistory.Count) | Suspicious DNS: $($SuspiciousDomains.Count)" -ForegroundColor Green
Write-Host "[+] JSON: $JsonFile" -ForegroundColor Green
Write-Log "Completed"
